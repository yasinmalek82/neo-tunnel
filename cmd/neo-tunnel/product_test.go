package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEnrollmentTokenExpiresAndIsConsumedOnce(t *testing.T) {
	now := time.Now()
	token := "test-token"
	grant := enrollmentGrant{Digest: fmt.Sprintf("%x", sha256.Sum256([]byte(token))), Expires: now.Add(time.Minute)}
	if err := grant.consume("wrong", now); err == nil {
		t.Fatal("accepted wrong token")
	}
	if err := grant.consume(token, now); err != nil {
		t.Fatal(err)
	}
	if err := grant.consume(token, now); err == nil {
		t.Fatal("accepted consumed token")
	}
	expired := enrollmentGrant{Digest: grant.Digest, Expires: now}
	if err := expired.consume(token, now); err == nil {
		t.Fatal("accepted expired token")
	}
}

func TestPilotPersistsAndClosesAfterSevenDays(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)
	pilot, err := startPilot(dir, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := recordPilot(dir, now.Add(time.Minute), dashboardSnapshot{Iran: &Reading{CPU: .84, At: now.Add(time.Minute), SustainedPressure: true}}); err != nil {
		t.Fatal(err)
	}
	summary, err := readPilotSummary(dir, now.Add(8*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if summary.Pilot.ID != pilot.ID || summary.Active || summary.ObservedMinutes != 1 || summary.IranMinutes != 1 || summary.PeerMinutes != 0 || summary.IranPressureMinutes != 1 {
		t.Fatalf("unexpected summary: %+v", summary)
	}
}

func TestShareableMinuteHasOnlyAllowlistedFields(t *testing.T) {
	r := Reading{At: time.Now(), CPU: .5, Profiles: map[string]GroupReading{"secret-private-host": {}}}
	value := safeMinute(time.Now(), dashboardSnapshot{Iran: &r, Selected: "secret-private-id", Health: map[string]Health{"primary": {State: "DOWN", Detail: "private IP 192.0.2.1"}}})
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("secret")) || bytes.Contains(raw, []byte("192.0.2.1")) {
		t.Fatalf("export leaked input: %s", raw)
	}
}

func TestDashboardRejectsNonLoopbackHostAndMutation(t *testing.T) {
	h := dashboardHandler(t.TempDir())
	for _, tc := range []struct {
		method, host string
		code         int
	}{
		{"GET", "127.0.0.1:8787", 200}, {"GET", "evil.example", 403}, {"POST", "localhost:8787", 405},
	} {
		r := httptest.NewRequest(tc.method, "http://"+tc.host+"/", nil)
		result := httptest.NewRecorder()
		h.ServeHTTP(result, r)
		if result.Code != tc.code {
			t.Errorf("%s %s: got %d want %d", tc.method, tc.host, result.Code, tc.code)
		}
		if tc.code == 200 && (!strings.Contains(result.Body.String(), `dir="rtl"`) || !strings.Contains(result.Body.String(), "نامعلوم")) {
			t.Fatal("missing RTL unavailable state")
		}
	}
}

func TestASCIIConsoleEscapesExternalCharacters(t *testing.T) {
	if got := asciiConsole("Error خطا\n"); got != "Error \\u062e\\u0637\\u0627\n" {
		t.Fatalf("console output %q", got)
	}
}

func TestEnrollmentEndpointIssuesAndConsumesCredentials(t *testing.T) {
	admin, site := t.TempDir(), t.TempDir()
	for _, ca := range []string{"frp-ca", "management-ca"} {
		if err := makeCA(admin, ca); err != nil {
			t.Fatal(err)
		}
	}
	if err := atomicJSON(filepath.Join(admin, "site.json"), siteSettings{Host: "iran.example.net", Bind: "127.0.0.1", Port: 16443, AppPort: 14443}); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(site, "secrets"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"primary.token", "standby.token"} {
		if err := os.WriteFile(filepath.Join(site, "secrets", name), []byte("fixture\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	token := randomToken()
	path := filepath.Join(admin, "grant.json")
	makeGrant := func(at time.Time) {
		t.Helper()
		if err := atomicJSON(path, enrollmentGrant{Digest: fmt.Sprintf("%x", sha256.Sum256([]byte(token))), Expires: at}); err != nil {
			t.Fatal(err)
		}
	}
	csr, _, err := makeCSR()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(enrollmentRequest{FRP: csr, Agent: csr})
	if err != nil {
		t.Fatal(err)
	}
	handler := enrollmentHandler(admin, site)
	request := func(payload []byte) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest("POST", "https://iran.example.net/join", bytes.NewReader(payload))
		req.Header.Set("Authorization", "Bearer "+token)
		result := httptest.NewRecorder()
		handler.ServeHTTP(result, req)
		return result
	}
	makeGrant(time.Now().Add(-time.Minute))
	if got := request(payload).Code; got != 401 {
		t.Fatalf("expired token returned %d", got)
	}
	makeGrant(time.Now().Add(time.Minute))
	if got := request(nil).Code; got != 400 {
		t.Fatalf("malformed request returned %d", got)
	}
	first := request(payload)
	if first.Code != 200 {
		t.Fatalf("first enrollment returned %d: %s", first.Code, first.Body.String())
	}
	var out enrollmentReply
	if err := json.Unmarshal(first.Body.Bytes(), &out); err != nil || out.Primary != "fixture" || len(out.Agent) == 0 {
		t.Fatal("missing enrolled credentials")
	}
	if got := request(payload).Code; got != 401 {
		t.Fatalf("replay returned %d", got)
	}
}
