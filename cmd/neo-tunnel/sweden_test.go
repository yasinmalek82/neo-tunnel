package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestUDPEdgeForwardsWithAnIsolatedSocketPerClient(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	edge, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer edge.Close()
	peers := make(chan string, 2)
	go func() {
		var buf [32]byte
		for i := 0; i < 2; i++ {
			n, addr, e := server.ReadFromUDP(buf[:])
			if e != nil {
				return
			}
			peers <- addr.String()
			_, _ = server.WriteToUDP(buf[:n], addr)
		}
	}()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	relay := make(chan error, 1)
	go func() { relay <- relayUDP(ctx, edge, server.LocalAddr().(*net.UDPAddr), 4, time.Second) }()
	for _, value := range []string{"one", "two"} {
		conn, e := net.DialUDP("udp4", nil, edge.LocalAddr().(*net.UDPAddr))
		if e != nil {
			t.Fatal(e)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		if _, e = conn.Write([]byte(value)); e != nil {
			t.Fatal(e)
		}
		var out [3]byte
		if n, e := conn.Read(out[:]); e != nil || string(out[:n]) != value {
			t.Fatalf("reply %q, error %v", out[:n], e)
		}
	}
	if <-peers == <-peers {
		t.Fatal("clients shared an upstream socket")
	}
	cancel()
	if err := <-relay; err != nil {
		t.Fatal(err)
	}
}

func TestAvailabilityDoesNotCountAGapAsAnOutage(t *testing.T) {
	from := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	sample := func(seconds int, state string) availabilitySample {
		return availabilitySample{At: from.Add(time.Duration(seconds) * time.Second), Primary: state, TCP: state, UDP: state}
	}
	samples := []availabilitySample{sample(0, "up"), sample(5, "down"), sample(10, "down"), sample(15, "up"),
		sample(45, "down"), sample(50, "up"), sample(55, "up")}
	stats := summarizeAvailability(samples, from, from.Add(55*time.Second))
	if stats.TCP.Interruptions != 1 || stats.TCP.Recoveries != 2 || stats.TCP.DownSeconds != 15 || stats.TCP.KnownSeconds != 25 {
		t.Fatalf("unexpected TCP stats: %+v", stats.TCP)
	}
}

func TestTelegramPairingOnlyAllowsPrivateOwner(t *testing.T) {
	now := time.Now()
	config := telegramConfig{PairingHash: pairingDigest("example"), PairingUntil: now.Add(time.Minute)}
	if accepted := config.accept(12, "group", "/start example", now); accepted != "" || config.ChatID != 0 {
		t.Fatal("paired a group")
	}
	if accepted := config.accept(12, "private", "/start example", now); accepted != "pair" || config.ChatID != 12 {
		t.Fatal("private setup failed")
	}
	if config.accept(13, "private", "/report", now) != "" || config.accept(13, "private", "/start example", now) != "" {
		t.Fatal("foreign chat authorized")
	}
	if config.accept(12, "private", "/today", now) != "today" {
		t.Fatal("owner command denied")
	}
}

func TestTelegramReportsQueueOfflineAndDeduplicateAfterRestart(t *testing.T) {
	iran, foreign := t.TempDir(), t.TempDir()
	if err := atomicJSON(filepath.Join(foreign, telegramStateFile), telegramConfig{}); err != nil {
		t.Fatal(err)
	}
	loc, err := time.LoadLocation("Asia/Tehran")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 17, 22, 0, 0, 0, loc)
	p := Pilot{ID: newID(), Start: now.Add(-2 * time.Hour), End: now.Add(-5 * time.Minute)}
	if err := atomicJSON(pilotPath(iran), p); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(iran, "pilot-report.tar.gz"), []byte("test archive"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filepath.Join(iran, "pilot-report.tar.gz"), now, now); err != nil {
		t.Fatal(err)
	}
	var online atomic.Bool
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !online.Load() {
			w.WriteHeader(503)
			return
		}
		receiveReport(foreign, w, r)
	}))
	defer agent.Close()
	makeController := func() controller {
		return controller{config: Config{Peer: agent.URL, StateDir: iran}, api: agent.Client()}
	}
	c := makeController()
	if err := c.reportOnce(t.Context(), now, loc); err != nil {
		t.Fatal(err)
	}
	pending, _ := filepath.Glob(filepath.Join(iran, "job-*"))
	if len(pending) != 2 {
		t.Fatalf("queued %d items while offline", len(pending))
	}
	online.Store(true)
	c = makeController()
	for i := 0; i < 3; i++ {
		if err := c.reportOnce(t.Context(), now, loc); err != nil {
			t.Fatal(err)
		}
	}
	pending, _ = filepath.Glob(filepath.Join(iran, "job-*"))
	if len(pending) != 0 {
		t.Fatal("Iran queue did not drain")
	}
	received, _ := filepath.Glob(filepath.Join(foreign, "job-*"))
	if len(received) != 2 {
		t.Fatalf("received %d jobs", len(received))
	}
	var messages, documents atomic.Int32
	telegram := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/sendMessage"):
			var data struct {
				ChatID int64  `json:"chat_id"`
				Text   string `json:"text"`
			}
			if err := json.NewDecoder(r.Body).Decode(&data); err != nil || data.ChatID != 42 || !strings.Contains(data.Text, "نامعلوم") {
				t.Error("unexpected Telegram summary")
			}
			messages.Add(1)
		case strings.HasSuffix(r.URL.Path, "/sendDocument"):
			if err := r.ParseMultipartForm(8192); err != nil || r.FormValue("chat_id") != "42" {
				t.Error("unexpected Telegram document form")
			}
			file, fh, err := r.FormFile("document")
			if err != nil || fh.Filename != "neo-sweden-pilot.tar.gz" {
				t.Error("missing final report")
			} else {
				file.Close()
			}
			documents.Add(1)
		default:
			t.Error("unexpected request")
		}
		fmt.Fprint(w, `{"ok":true,"result":{}}`)
	}))
	defer telegram.Close()
	client := telegramClient{base: telegram.URL, token: "fixture", client: telegram.Client()}
	for i := 0; i < 4; i++ {
		if err := sendQueuedReport(t.Context(), foreign, 42, client); err != nil {
			t.Fatal(err)
		}
	}
	if messages.Load() != 1 || documents.Load() != 1 {
		t.Fatalf("Telegram delivered %d summaries and %d documents", messages.Load(), documents.Load())
	}
	for _, path := range received {
		id := strings.TrimPrefix(filepath.Base(path), "job-")
		if err := saveJob(foreign, id, strings.NewReader("duplicate")); err != nil {
			t.Fatal(err)
		}
	}
	if err := sendQueuedReport(t.Context(), foreign, 42, client); err != nil {
		t.Fatal(err)
	}
	if messages.Load() != 1 || documents.Load() != 1 {
		t.Fatal("resending received reports caused duplicate Telegram deliveries")
	}
	if _, err := os.Stat(filepath.Join(foreign, "last-report.tar.gz")); err != nil {
		t.Fatal(err)
	}
}
