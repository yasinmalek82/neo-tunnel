package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

const telegramAPI = "https://api.telegram.org"
const finalCaption = "گزارش نهایی پایلوت NEO | سوئد"
const telegramStateFile = "telegram.json"

var reportPilotID = regexp.MustCompile(`^[a-f0-9]{32}$`)
var jobID = regexp.MustCompile(`^[a-f0-9]{32}-(final|daily-[0-9]{8})$`)
var botToken = regexp.MustCompile(`^[0-9]{5,20}:[A-Za-z0-9_-]{30,100}$`)

type telegramConfig struct {
	Token        string    `json:"token"`
	ChatID       int64     `json:"chat_id"`
	Offset       int64     `json:"offset"`
	PairingHash  string    `json:"pairing_hash,omitempty"`
	PairingUntil time.Time `json:"pairing_until,omitempty"`
}

func pairingDigest(code string) string {
	digest := sha256.Sum256([]byte(code))
	return hex.EncodeToString(digest[:])
}

func (c *telegramConfig) accept(chat int64, kind, text string, now time.Time) string {
	if kind != "private" || chat <= 0 {
		return ""
	}
	args := strings.Fields(text)
	if c.ChatID == 0 {
		if len(args) == 2 && args[0] == "/start" && now.Before(c.PairingUntil) &&
			subtle.ConstantTimeCompare([]byte(c.PairingHash), []byte(pairingDigest(args[1]))) == 1 {
			c.ChatID = chat
			c.PairingHash = ""
			c.PairingUntil = time.Time{}
			return "pair"
		}
		return ""
	}
	if c.ChatID != chat || len(args) != 1 {
		return ""
	}
	switch args[0] {
	case "/status", "/today", "/report":
		return args[0][1:]
	}
	return ""
}

func receiveReport(dir string, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.NotFound(w, r)
		return
	}
	if _, err := os.Stat(filepath.Join(dir, telegramStateFile)); err != nil {
		http.NotFound(w, r)
		return
	}
	if r.URL.Path == "/v1/reports/probe" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.URL.Path == reportSnapshotPath {
		var data reportSnapshot
		if err := decodeJSON(http.MaxBytesReader(w, r.Body, 8192), &data); err != nil || data.At.IsZero() {
			http.Error(w, "Invalid report snapshot", http.StatusBadRequest)
			return
		}
		if err := atomicJSON(filepath.Join(dir, "report-state.json"), data); err != nil {
			http.Error(w, "Cannot save report", 500)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/v1/reports/jobs/")
	if !jobID.MatchString(id) {
		http.NotFound(w, r)
		return
	}
	// This authenticated operation may transfer the final compressed archive.
	deadline := time.Now().Add(65 * time.Second)
	responder := http.NewResponseController(w)
	_ = responder.SetReadDeadline(deadline)
	_ = responder.SetWriteDeadline(deadline)
	if err := saveJob(dir, id, r.Body); err != nil {
		http.Error(w, "Cannot queue report", http.StatusInsufficientStorage)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func saveJob(dir, id string, body io.Reader) error {
	unlock, err := lock(filepath.Join(dir, "report-lock"))
	if err != nil {
		return err
	}
	defer unlock()
	path := filepath.Join(dir, "job-"+id)
	for _, existing := range []string{path, filepath.Join(dir, "sent-"+id)} {
		if _, err := os.Stat(existing); err == nil {
			return nil
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	maxSize := int64(4096)
	if strings.HasSuffix(id, "-final") {
		maxSize = reportMax
	}
	files, _ := filepath.Glob(filepath.Join(dir, "job-*"))
	var occupied int64
	for _, name := range files {
		if info, err := os.Stat(name); err == nil {
			occupied += info.Size()
		}
	}
	if len(files) >= 64 || occupied+maxSize > 96<<20 {
		return errors.New("report queue is full")
	}
	dst, err := os.CreateTemp(dir, ".report-in-")
	if err != nil {
		return err
	}
	defer os.Remove(dst.Name())
	defer dst.Close()
	n, err := io.Copy(dst, io.LimitReader(body, maxSize+1))
	if err != nil {
		return err
	}
	if n == 0 || n > maxSize {
		return errors.New("report exceeds the allowed size")
	}
	if err := dst.Sync(); err != nil {
		return err
	}
	if err := dst.Close(); err != nil {
		return err
	}
	return os.Rename(dst.Name(), path)
}

type telegramClient struct {
	base   string
	token  string
	client *http.Client
}

type telegramResponse struct {
	OK         bool            `json:"ok"`
	Code       int             `json:"error_code"`
	Result     json.RawMessage `json:"result"`
	Parameters struct {
		RetryAfter int `json:"retry_after"`
	} `json:"parameters"`
}

type telegramError struct{ code, retryAfter int }

func (e telegramError) Error() string {
	return fmt.Sprintf("Telegram request returned code %d", e.code)
}

func (c telegramClient) request(ctx context.Context, method, contentType string, body io.Reader, size int64, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/bot"+c.token+"/"+method, body)
	if err != nil {
		return errors.New("invalid Telegram request")
	}
	req.Header.Set("Content-Type", contentType)
	req.ContentLength = size
	res, err := c.client.Do(req)
	if err != nil {
		return errors.New("Telegram connection failed")
	}
	defer res.Body.Close()
	var response telegramResponse
	if err := json.NewDecoder(io.LimitReader(res.Body, 256<<10)).Decode(&response); err != nil {
		return telegramError{code: res.StatusCode}
	}
	if !response.OK || res.StatusCode != http.StatusOK {
		code := response.Code
		if code == 0 {
			code = res.StatusCode
		}
		return telegramError{code, response.Parameters.RetryAfter}
	}
	if dst != nil {
		if err := json.Unmarshal(response.Result, dst); err != nil {
			return errors.New("invalid Telegram result")
		}
	}
	return nil
}

func (c telegramClient) call(ctx context.Context, method string, data, dst any) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return c.request(ctx, method, "application/json", bytes.NewReader(b), int64(len(b)), dst)
}

func (c telegramClient) message(ctx context.Context, chat int64, text string) error {
	return c.call(ctx, "sendMessage", map[string]any{"chat_id": chat, "text": text}, nil)
}

func (c telegramClient) document(ctx context.Context, chat int64, path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	st, err := file.Stat()
	if err != nil {
		return err
	}
	if st.Size() < 1 || st.Size() > reportMax {
		return errors.New("Telegram report size exceeded")
	}
	var buf bytes.Buffer
	form := multipart.NewWriter(&buf)
	if err := form.WriteField("chat_id", fmt.Sprint(chat)); err != nil {
		return err
	}
	if err := form.WriteField("caption", finalCaption); err != nil {
		return err
	}
	if _, err := form.CreateFormFile("document", "neo-sweden-pilot.tar.gz"); err != nil {
		return err
	}
	header := bytes.Clone(buf.Bytes())
	buf.Reset()
	if err := form.Close(); err != nil {
		return err
	}
	body := io.MultiReader(bytes.NewReader(header), file, bytes.NewReader(buf.Bytes()))
	return c.request(ctx, "sendDocument", form.FormDataContentType(), body, int64(len(header)+buf.Len())+st.Size(), nil)
}

type telegramUpdate struct {
	ID      int64 `json:"update_id"`
	Message struct {
		Text string `json:"text"`
		Chat struct {
			ID   int64  `json:"id"`
			Type string `json:"type"`
		} `json:"chat"`
	} `json:"message"`
}

func sendQueuedReport(ctx context.Context, dir string, chat int64, client telegramClient) error {
	files, err := filepath.Glob(filepath.Join(dir, "job-*"))
	if err != nil {
		return err
	}
	for _, path := range files {
		id := strings.TrimPrefix(filepath.Base(path), "job-")
		if !jobID.MatchString(id) {
			continue
		}
		marker := filepath.Join(dir, "sent-"+id)
		final := strings.HasSuffix(id, "-final")
		if _, err := os.Stat(marker); os.IsNotExist(err) {
			if final {
				err = client.document(ctx, chat, path)
			} else {
				var data []byte
				data, err = os.ReadFile(path)
				if err == nil {
					err = client.message(ctx, chat, string(data))
				}
			}
			if err != nil {
				return err
			}
			if err := atomicWrite(marker, []byte("sent\n"), 0600); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		if final {
			return os.Rename(path, filepath.Join(dir, "last-report.tar.gz"))
		}
		return os.Remove(path)
	}
	return nil
}

func replyToCommand(ctx context.Context, dir string, c telegramConfig, client telegramClient, command string) error {
	if command == "pair" {
		return client.message(ctx, c.ChatID, "گزارش‌گیر NEO سوئد فعال شد. /status /today /report")
	}
	if command == "report" {
		path := filepath.Join(dir, "last-report.tar.gz")
		if _, err := os.Stat(path); err == nil {
			return client.document(ctx, c.ChatID, path)
		}
		return client.message(ctx, c.ChatID, "گزارش نهایی هنوز به سوئد نرسیده است.")
	}
	var snapshot reportSnapshot
	if readJSON(filepath.Join(dir, "report-state.json"), &snapshot) != nil {
		return client.message(ctx, c.ChatID, "هنوز داده‌ای از ایران نرسیده است.")
	}
	reply := snapshot.Status
	if command == "today" {
		reply = snapshot.Today
	}
	loc, _ := time.LoadLocation("Asia/Tehran")
	if loc == nil {
		loc = time.UTC
	}
	reply += "\nزمان آخرین داده: " + snapshot.At.In(loc).Format("2006-01-02 15:04") + " (تهران)"
	if time.Since(snapshot.At) > 2*time.Minute {
		reply += "\nداده تازه نیست."
	}
	return client.message(ctx, c.ChatID, reply)
}

func botLoop(ctx context.Context, dir string, client telegramClient) error {
	unlock, err := lock(filepath.Join(dir, "telegram-lock"))
	if err != nil {
		return err
	}
	defer unlock()
	path := filepath.Join(dir, telegramStateFile)
	var cfg telegramConfig
	if err := readJSON(path, &cfg); err != nil {
		return err
	}
	if !botToken.MatchString(cfg.Token) {
		return errors.New("invalid Telegram bot token")
	}
	client.token = cfg.Token
	var nextDelivery time.Time
	for ctx.Err() == nil {
		if cfg.ChatID != 0 && !time.Now().Before(nextDelivery) {
			if err := sendQueuedReport(ctx, dir, cfg.ChatID, client); err != nil && ctx.Err() == nil {
				fmt.Fprintln(os.Stderr, err)
				nextDelivery = time.Now().Add(telegramBackoff(err))
			}
		}
		var updates []telegramUpdate
		err := client.call(ctx, "getUpdates", map[string]any{"timeout": 15, "limit": 20, "allowed_updates": []string{"message"}, "offset": cfg.Offset}, &updates)
		if err != nil {
			if ctx.Err() == nil {
				fmt.Fprintln(os.Stderr, err)
			}
			if wait(ctx, telegramBackoff(err)) != nil {
				break
			}
			continue
		}
		for _, update := range updates {
			if update.ID < cfg.Offset {
				continue
			}
			command := cfg.accept(update.Message.Chat.ID, update.Message.Chat.Type, update.Message.Text, time.Now())
			cfg.Offset = update.ID + 1
			if err := atomicJSON(path, cfg); err != nil {
				return err
			}
			if command != "" {
				if err := replyToCommand(ctx, dir, cfg, client, command); err != nil && ctx.Err() == nil {
					fmt.Fprintln(os.Stderr, err)
				}
			}
		}
		// Bound retries even if a proxy returns empty polls immediately.
		if len(updates) == 0 && wait(ctx, time.Second) != nil {
			break
		}
	}
	return nil
}

func telegramBackoff(err error) time.Duration {
	var apiErr telegramError
	if errors.As(err, &apiErr) && apiErr.retryAfter > 0 {
		return time.Duration(apiErr.retryAfter) * time.Second
	}
	return 15 * time.Second
}

func setupTelegram(ctx context.Context, in *bufio.Reader, action string) error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("Telegram setup requires sudo on the Sweden host")
	}
	role, err := installedRole()
	if err != nil {
		return err
	}
	if role != "foreign" {
		return errors.New("configure Telegram on the joined Sweden host")
	}
	var agent AgentConfig
	if err := readJSON(configHome+"/agent.json", &agent); err != nil {
		return err
	}
	path := filepath.Join(agent.StateDir, telegramStateFile)
	if action == "status" {
		var cfg telegramConfig
		if err := readJSON(path, &cfg); err != nil {
			return err
		}
		fmt.Printf("Telegram paired: %t\n", cfg.ChatID != 0)
		return nil
	}
	if action != "setup" {
		return errors.New("usage: neo-tunnel telegram setup|status")
	}
	if unlock, err := lock(adminHome); err == nil {
		defer unlock()
	} else {
		return err
	}
	if err := tool(ctx, "systemctl", "is-active", "--quiet", "neo-agent.service"); err != nil {
		return errors.New("start the Sweden agent before configuring Telegram")
	}
	fmt.Print("Dedicated Telegram bot token (input hidden): ")
	hide := exec.Command("stty", "-echo")
	hide.Stdin = os.Stdin
	if err := hide.Run(); err != nil {
		return errors.New("Telegram setup requires an interactive terminal")
	}
	raw, err := in.ReadString('\n')
	restore := exec.Command("stty", "echo")
	restore.Stdin = os.Stdin
	_ = restore.Run()
	fmt.Println()
	if err != nil {
		return err
	}
	token := strings.TrimSpace(raw)
	if !botToken.MatchString(token) {
		return errors.New("invalid Telegram bot token")
	}
	client := telegramClient{base: telegramAPI, token: token, client: &http.Client{Timeout: 12 * time.Second, CheckRedirect: noRedirect}}
	var me struct {
		Username string `json:"username"`
	}
	if err := client.call(ctx, "getMe", struct{}{}, &me); err != nil {
		return err
	}
	var webhook struct {
		URL string `json:"url"`
	}
	if err := client.call(ctx, "getWebhookInfo", struct{}{}, &webhook); err != nil {
		return err
	}
	if webhook.URL != "" {
		return errors.New("use a dedicated bot without a webhook")
	}
	code := randomToken()[:24]
	cfg := telegramConfig{Token: token, PairingHash: pairingDigest(code), PairingUntil: time.Now().Add(15 * time.Minute)}
	// Stop the old worker before replacing credentials to prevent a stale poll
	// from overwriting the pairing record. The agent and tunnel stay running.
	if err := tool(ctx, "systemctl", "stop", "neo-telegram.service"); err != nil {
		return err
	}
	if err := configFile(agent.StateDir, telegramStateFile, jsonBytes(cfg)); err != nil {
		return err
	}
	if err := enableUnits(ctx, "neo-telegram.service"); err != nil {
		return err
	}
	fmt.Printf("Open @%s in a private Telegram chat and send /start %s within 15 minutes.\n", asciiConsole(me.Username), code)
	return nil
}
