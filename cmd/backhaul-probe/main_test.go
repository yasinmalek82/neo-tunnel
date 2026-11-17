package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCanaryHandler(t *testing.T) {
	for _, test := range []struct {
		method string
		path   string
		status int
		body   string
	}{
		{http.MethodGet, "/readyz", http.StatusOK, "backhaul-ready-v1\n"},
		{http.MethodPost, "/readyz", http.StatusMethodNotAllowed, ""},
		{http.MethodGet, "/anywhere", http.StatusNotFound, ""},
	} {
		t.Run(test.method+test.path, func(t *testing.T) {
			response := httptest.NewRecorder()
			canaryHandler(response, httptest.NewRequest(test.method, test.path, nil))
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d", response.Code, test.status)
			}
			if test.body != "" && response.Body.String() != test.body {
				t.Fatalf("body = %q, want %q", response.Body.String(), test.body)
			}
		})
	}
}

func TestUDPReplyRequiresAnExactChallenge(t *testing.T) {
	challenge := []byte("BHP1abcdefghijklmnop")
	want := []byte("BHA1abcdefghijklmnop")
	if got := udpReply(challenge); !bytes.Equal(got, want) {
		t.Fatalf("reply = %q, want %q", got, want)
	}
	if !bytes.Equal(challenge, []byte("BHP1abcdefghijklmnop")) {
		t.Fatalf("challenge modified in place: %q", challenge)
	}
	for _, invalid := range [][]byte{want, challenge[:len(challenge)-1], append(challenge, 'x')} {
		if got := udpReply(invalid); got != nil {
			t.Fatalf("unexpected response to %q: %q", invalid, got)
		}
	}
}

func TestLoopbackAddress(t *testing.T) {
	for _, test := range []struct {
		addr  string
		valid bool
	}{
		{"127.0.0.1:17102", true}, {"[::1]:17102", true},
		{"0.0.0.0:17102", false}, {"192.0.2.1:17102", false},
		{"127.0.0.1:0", false}, {"127.0.0.1:65536", false},
		{"localhost:17102", false}, {"127.0.0.1:17102/path", false},
	} {
		if err := validateAddress(test.addr); (err == nil) != test.valid {
			t.Errorf("validateAddress(%q) = %v, want success %t", test.addr, err, test.valid)
		}
	}
}

func TestReportUsesSuccessesForTailLatency(t *testing.T) {
	out := summarize("udp", "127.0.0.1:17102", 5,
		[]time.Duration{2 * time.Millisecond, 12 * time.Millisecond, 3 * time.Millisecond})
	if out.Sent != 5 || out.Received != 3 || out.TimeoutsOrErrors != 2 ||
		out.P95MS == nil || *out.P95MS != 12 {
		t.Fatalf("unexpected report: %#v", out)
	}
	noReplies := summarize("tcp", "127.0.0.1:17102", 3, nil)
	if noReplies.P95MS != nil || noReplies.Received != 0 || noReplies.TimeoutsOrErrors != 3 {
		t.Fatalf("unexpected report for failed checks: %#v", noReplies)
	}
}

func TestCalibrationEchoIsBounded(t *testing.T) {
	handler := http.HandlerFunc(canaryHandler)
	for _, test := range []struct {
		size int
		code int
	}{
		{1024, http.StatusOK},
		{(256 << 10) + 1, http.StatusRequestEntityTooLarge},
	} {
		payload := bytes.Repeat([]byte("x"), test.size)
		req := httptest.NewRequest(http.MethodPost, "/transfer", bytes.NewReader(payload))
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != test.code {
			t.Fatalf("size %d returned %d, want %d", test.size, res.Code, test.code)
		}
		if test.code == http.StatusOK && !bytes.Equal(res.Body.Bytes(), payload) {
			t.Fatal("response changed the calibration data")
		}
	}
}
