package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"strconv"
	"strings"
	"time"
)

type Health struct {
	Sessions  int    `json:"sessions"`
	Detail    string `json:"detail,omitempty"`
	State     string `json:"state"`
	Check     string `json:"check"`
	CheckMS   *int   `json:"check_ms"`
	DownCount int    `json:"down_count"`
}

type controller struct {
	config Config
	digest string
	api    *http.Client
	probe  *http.Client
}

func (c *controller) agentCall(ctx context.Context, host, path string, request *agentRequest, output any) error {
	err := c.callAgent(ctx, host, path, request, output)
	if err != nil && host == c.config.Peer && c.config.PeerFallback != "" {
		return c.callAgent(ctx, c.config.PeerFallback, path, request, output)
	}
	return err
}

func (c *controller) callAgent(ctx context.Context, host, path string, request *agentRequest, output any) error {
	method := http.MethodGet
	var body io.Reader
	if request != nil {
		method = http.MethodPost
		payload, err := json.Marshal(request)
		if err != nil {
			return err
		}
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(host, "/")+path, body)
	if err != nil {
		return err
	}
	reply, err := c.api.Do(req)
	if err != nil {
		return err
	}
	defer reply.Body.Close()
	if reply.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(reply.Body, 1024))
		return fmt.Errorf("%s: HTTP %d %s", host, reply.StatusCode, strings.TrimSpace(string(raw)))
	}
	return decodeJSON(io.LimitReader(reply.Body, 16384), output)
}

func (c *controller) resourcePair(ctx context.Context) [2]*Reading {
	var result [2]*Reading
	now := time.Now()
	for i, host := range [2]string{c.config.Iran, c.config.Peer} {
		var r *Reading
		if c.agentCall(ctx, host, "/v1/resources", nil, &r) == nil && fresh(now, r) {
			result[i] = r
		}
	}
	return result
}

func (c *controller) operate(ctx context.Context, req agentRequest) error {
	var result error
	for _, host := range [2]string{c.config.Iran, c.config.Peer} {
		err := c.agentCall(ctx, host, "/v1/operation", &req, &struct{}{})
		result = errors.Join(result, err)
	}
	return result
}

func (c *controller) runtime(ctx context.Context, command string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", c.config.HAProxySocket)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return "", err
	}
	if _, err := io.WriteString(conn, command+"\n"); err != nil {
		return "", err
	}
	if err := conn.(*net.UnixConn).CloseWrite(); err != nil {
		return "", err
	}
	raw, err := io.ReadAll(io.LimitReader(conn, 1<<20))
	return strings.TrimSpace(string(raw)), err
}

func parseHealth(raw string, profiles map[string]Profile) (map[string]Health, error) {
	r := csv.NewReader(strings.NewReader(strings.TrimPrefix(raw, "# ")))
	r.FieldsPerRecord = -1
	columns, err := r.Read()
	if err != nil {
		return nil, err
	}
	keys := map[string]int{}
	for i, k := range columns {
		keys[k] = i
	}
	for _, name := range []string{"pxname", "svname", "status", "check_status", "check_duration", "chkdown"} {
		if _, ok := keys[name]; !ok {
			return nil, fmt.Errorf("HAProxy statistic %s missing", name)
		}
	}
	out := make(map[string]Health)
	for {
		row, err := r.Read()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if len(row) < len(columns)-1 {
			return nil, errors.New("truncated HAProxy statistics")
		}
		get := func(k string) string {
			if i := keys[k]; i < len(row) {
				return row[i]
			}
			return ""
		}
		id := get("pxname")
		if _, ok := profiles[id]; !ok || get("svname") != "via_"+id {
			continue
		}
		h := Health{State: get("status"), Check: get("check_status"), Detail: optional("last_chk", keys, row)}
		h.Sessions, _ = strconv.Atoi(optional("scur", keys, row))
		if n, err := strconv.Atoi(get("check_duration")); err == nil {
			h.CheckMS = ptr(n)
		}
		h.DownCount, _ = strconv.Atoi(get("chkdown"))
		out[id] = h
	}
}

func optional(name string, keys map[string]int, row []string) string {
	if i, ok := keys[name]; ok && i < len(row) {
		return row[i]
	}
	return ""
}

func (c *controller) health(ctx context.Context) (map[string]Health, error) {
	raw, err := c.runtime(ctx, "show stat")
	if err != nil {
		return nil, err
	}
	return parseHealth(raw, c.config.Profiles)
}

func (c *controller) route(ctx context.Context, id string) error {
	if _, ok := c.config.Profiles[id]; !ok {
		return errors.New("unknown route")
	}
	response, err := c.runtime(ctx, "set map "+c.config.MapFile+" preference "+id)
	if err != nil {
		return err
	}
	if response != "" {
		return fmt.Errorf("HAProxy rejected preference: %s", response)
	}
	return atomicWrite(c.config.MapFile, []byte("preference "+id+"\n"), 0640)
}

func (h Health) ready() bool { return h.State == "UP" || strings.HasPrefix(h.State, "UP ") }

func (c *controller) service(ctx context.Context, id string) error {
	profile := c.config.Profiles[id]
	if profile.AppTCP != "" {
		conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", profile.AppTCP)
		if err == nil {
			conn.Close()
		}
		return err
	}
	if profile.AppURL == "" {
		return errors.New("application response check unavailable")
	}
	_, err := c.measure(ctx, profile.AppURL, []byte(profile.AppBody), nil)
	return err
}

type timing struct{ Total, Connect, FirstByte time.Duration }

func (c *controller) measure(ctx context.Context, url string, expected, payload []byte) (timing, error) {
	ctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	start := time.Now()
	var connectStart time.Time
	var result timing
	trace := &httptrace.ClientTrace{
		ConnectStart: func(string, string) { connectStart = time.Now() },
		ConnectDone: func(_, _ string, err error) {
			if err == nil {
				result.Connect = time.Since(connectStart)
			}
		},
		GotFirstResponseByte: func() { result.FirstByte = time.Since(start) },
	}
	ctx = httptrace.WithClientTrace(ctx, trace)
	method := http.MethodGet
	if payload != nil {
		method = http.MethodPost
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(payload))
	if err != nil {
		return result, err
	}
	res, err := c.probe.Do(req)
	if err != nil {
		return result, err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, int64(len(expected)+1)))
	result.Total = time.Since(start)
	if err != nil {
		return result, err
	}
	if res.StatusCode != http.StatusOK || !bytes.Equal(data, expected) {
		return result, errors.New("unexpected application response")
	}
	return result, nil
}

func wait(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func readyProbeURL(p Profile, path string) string { return "http://" + p.Canary + path }

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout() || errors.Is(err, context.DeadlineExceeded)
}

func loadConfig(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err == nil && len(buf) > 1<<20 {
		return nil, errors.New("controller config too large")
	}
	return buf, err
}
