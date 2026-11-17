package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"
)

const (
	maxEcho   = 256 << 10
	readyPath = "/readyz"
	readyBody = "backhaul-ready-v1\n"
	udpAsk    = "BHP1"
	udpAck    = "BHA1"
	udpSize   = len(udpAsk) + 16
)

type report struct {
	Transport        string   `json:"transport"`
	Address          string   `json:"address"`
	Sent             int      `json:"sent"`
	Received         int      `json:"received"`
	TimeoutsOrErrors int      `json:"timeouts_or_errors"`
	P95MS            *float64 `json:"p95_ms"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err := run(ctx, os.Args[1:])
	if err != nil && !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: backhaul-probe serve|check [flags]")
	}
	switch args[0] {
	case "serve":
		flags := flag.NewFlagSet("serve", flag.ContinueOnError)
		addr := flags.String("listen", "127.0.0.1:18080", "loopback TCP/UDP address")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("serve takes flags only")
		}
		if err := validateAddress(*addr); err != nil {
			return err
		}
		return serve(ctx, *addr)
	case "check":
		return check(ctx, args[1:])
	default:
		return errors.New("usage: backhaul-probe serve|check [flags]")
	}
}

func validateAddress(addr string) error {
	address, err := netip.ParseAddrPort(addr)
	if err != nil || !address.Addr().IsLoopback() || address.Addr().Zone() != "" || address.Port() == 0 {
		return fmt.Errorf("expected a numeric loopback address with a port, got %q", addr)
	}
	return nil
}

func canaryHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/transfer" {
		transfer(w, r)
		return
	}
	if r.URL.Path != readyPath {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, readyBody)
}

func transfer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.ContentLength < 1 || r.ContentLength > maxEcho {
		http.Error(w, "invalid transfer size", http.StatusRequestEntityTooLarge)
		return
	}
	payload, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxEcho))
	if err != nil || int64(len(payload)) != r.ContentLength {
		http.Error(w, "incomplete transfer", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(payload)
}

func udpReply(packet []byte) []byte {
	if len(packet) != udpSize || string(packet[:len(udpAsk)]) != udpAsk {
		return nil
	}
	reply := make([]byte, udpSize)
	copy(reply, udpAck)
	copy(reply[len(udpAck):], packet[len(udpAsk):])
	return reply
}

func serve(ctx context.Context, addr string) error {
	tcp, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer tcp.Close()
	udp, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	defer udp.Close()
	server := &http.Server{
		Handler:           http.HandlerFunc(canaryHandler),
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       2 * time.Second,
		WriteTimeout:      2 * time.Second,
		IdleTimeout:       3 * time.Second,
		MaxHeaderBytes:    4096,
	}
	results := make(chan error, 2)
	go func() { results <- server.Serve(tcp) }()
	go func() {
		var buffer [udpSize + 1]byte
		for {
			n, peer, err := udp.ReadFrom(buffer[:])
			if err != nil {
				results <- err
				return
			}
			if response := udpReply(buffer[:n]); response != nil {
				_, _ = udp.WriteTo(response, peer)
			}
		}
	}()

	select {
	case err := <-results:
		_ = server.Close()
		return err
	case <-ctx.Done():
		_ = udp.Close()
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			_ = server.Close()
			return err
		}
		return nil
	}
}

func check(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("check", flag.ContinueOnError)
	tcp := flags.String("tcp", "", "forwarded TCP canary address on loopback")
	udp := flags.String("udp", "", "forwarded UDP canary address on loopback")
	count := flags.Int("n", 5, "samples per protocol (1-100)")
	timeout := flags.Duration("timeout", 1200*time.Millisecond, "timeout per sample (up to 5s)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || (*tcp == "" && *udp == "") {
		return errors.New("check requires -tcp and/or -udp loopback address")
	}
	if *count < 1 || *count > 100 || *timeout <= 0 || *timeout > 5*time.Second {
		return errors.New("use 1-100 samples and a positive timeout up to 5s")
	}

	client := &http.Client{
		Transport:     &http.Transport{DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       *timeout,
	}
	probes := []struct {
		protocol string
		address  string
		request  func() error
	}{
		{"tcp", *tcp, func() error { return checkTCP(ctx, client, *tcp) }},
		{"udp", *udp, func() error { return checkUDP(*udp, *timeout) }},
	}
	for _, probe := range probes {
		if probe.address != "" {
			if err := validateAddress(probe.address); err != nil {
				return err
			}
		}
	}

	encoder := json.NewEncoder(os.Stdout)
	ok := true
	for _, probe := range probes {
		if probe.address == "" {
			continue
		}
		var completed []time.Duration
		for i := 0; i < *count; i++ {
			if err := ctx.Err(); err != nil {
				return err
			}
			start := time.Now()
			if err := probe.request(); err == nil {
				completed = append(completed, time.Since(start))
			}
		}
		if err := encoder.Encode(summarize(probe.protocol, probe.address, *count, completed)); err != nil {
			return err
		}
		ok = ok && len(completed) == *count
	}
	if !ok {
		return errors.New("one or more canary samples did not return the expected response")
	}
	return nil
}

func checkTCP(ctx context.Context, client *http.Client, addr string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+readyPath, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, int64(len(readyBody)+1)))
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK || string(body) != readyBody {
		return errors.New("unexpected TCP canary response")
	}
	return nil
}

func checkUDP(addr string, timeout time.Duration) error {
	var packet [udpSize]byte
	copy(packet[:], udpAsk)
	if _, err := rand.Read(packet[len(udpAsk):]); err != nil {
		return err
	}
	deadline := time.Now().Add(timeout)
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	if _, err := conn.Write(packet[:]); err != nil {
		return err
	}
	var reply [udpSize + 1]byte
	n, err := conn.Read(reply[:])
	if err != nil {
		return err
	}
	copy(packet[:], udpAck)
	if !bytes.Equal(reply[:n], packet[:]) {
		return errors.New("unexpected UDP canary response")
	}
	return nil
}

func summarize(protocol, address string, sent int, successful []time.Duration) report {
	result := report{Transport: protocol, Address: address, Sent: sent,
		Received: len(successful), TimeoutsOrErrors: sent - len(successful)}
	if len(successful) != 0 {
		slices.Sort(successful)
		rank := (95*len(successful) + 99) / 100
		ms := float64(successful[rank-1]) / float64(time.Millisecond)
		result.P95MS = &ms
	}
	return result
}
