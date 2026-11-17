package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const cadence = 5 * time.Second
const baselineWindow = 15 * time.Minute

type agent struct {
	config         AgentConfig
	mu             sync.Mutex
	history        []Reading
	pressuredSince time.Time
	oomUntil       time.Time
	lease          lease
}

type lease struct {
	ID    string    `json:"id"`
	Until time.Time `json:"until"`
}

type agentRequest struct {
	ID      string `json:"id"`
	Profile string `json:"profile,omitempty"`
	Action  string `json:"action"`
}

func newID() string {
	var entropy [16]byte
	rand.Read(entropy[:])
	return hex.EncodeToString(entropy[:])
}

func (a *agent) observe(r Reading) Reading {
	a.mu.Lock()
	defer a.mu.Unlock()
	if pressure(&r) {
		if a.pressuredSince.IsZero() {
			a.pressuredSince = r.At
		}
		r.SustainedPressure = r.At.Sub(a.pressuredSince) >= 30*time.Second
	} else {
		a.pressuredSince = time.Time{}
	}
	if r.OOM {
		a.oomUntil = r.At.Add(30 * time.Second)
	}
	r.OOM = r.At.Before(a.oomUntil)

	cut := r.At.Add(-baselineWindow)
	for len(a.history) > 1 && a.history[1].At.Before(cut) {
		a.history = a.history[1:]
	}
	if len(a.history) > 0 && r.At.Sub(a.history[len(a.history)-1].At) > 2*cadence {
		a.history = nil
	}
	a.history = append(a.history, r)
	r.BaselineReady = r.At.Sub(a.history[0].At) >= baselineWindow
	if r.BaselineReady {
		for _, v := range a.history {
			r.BaselineCPU += v.CPU
			r.BaselineAvailable += v.Available
		}
		r.BaselineCPU /= float64(len(a.history))
		r.BaselineAvailable /= float64(len(a.history))
	}
	a.history[len(a.history)-1] = r
	return r
}

func (a *agent) latest() *Reading {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.history) == 0 {
		return nil
	}
	return ptr(a.history[len(a.history)-1])
}

func (a *agent) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.URL.Path == "/v1/resources" && r.Method == http.MethodGet:
		_ = json.NewEncoder(w).Encode(a.latest())
	case r.URL.Path == "/v1/operation" && r.Method == http.MethodPost:
		var request agentRequest
		if err := decodeJSON(http.MaxBytesReader(w, r.Body, 1024), &request); err != nil || len(request.ID) != 32 {
			http.Error(w, "invalid operation", 400)
			return
		}
		if err := a.operate(r.Context(), request); err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		_ = json.NewEncoder(w).Encode(struct{}{})
	default:
		http.NotFound(w, r)
	}
}

func (a *agent) operate(ctx context.Context, r agentRequest) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	occupied := now.Before(a.lease.Until)
	if occupied && a.lease.ID != r.ID {
		return errors.New("host operation already in progress")
	}
	path := filepath.Join(a.config.StateDir, "lease.json")
	switch r.Action {
	case "claim":
		next := lease{ID: r.ID, Until: now.Add(40 * time.Second)}
		if err := atomicJSON(path, next); err != nil {
			return err
		}
		a.lease = next
	case "release":
		if !occupied {
			return nil
		}
		if err := atomicJSON(path, lease{}); err != nil {
			return err
		}
		a.lease = lease{}
	case "start", "stop":
		if !occupied {
			return errors.New("operation lease expired")
		}
		unit, ok := a.config.Units[r.Profile]
		if !ok {
			return errors.New("experiment not configured on this host")
		}
		ctx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
		defer cancel()
		if err := exec.CommandContext(ctx, "/usr/bin/systemctl", "--no-block", r.Action, unit).Run(); err != nil {
			return fmt.Errorf("systemctl %s %s: %w", r.Action, unit, err)
		}
	default:
		return errors.New("unknown operation")
	}
	return nil
}

type minuteSummary struct {
	Minute         time.Time `json:"minute"`
	Samples        int       `json:"samples"`
	MeanCPU        float64   `json:"mean_host_cpu_fraction"`
	MinAvailable   float64   `json:"min_host_memory_available_fraction"`
	PeakWorkingSet uint64    `json:"peak_tool_working_set_bytes"`
	ToolCPUSeconds float64   `json:"tool_cpu_seconds"`
	Pressure       bool      `json:"pressure"`
	firstCPU       float64
}

func appendRecord(path string, record any, limit int64) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() >= limit {
		return errors.New("log size cap reached")
	}
	return json.NewEncoder(f).Encode(record)
}

func prune(dir, prefix string, after time.Time, layout string) {
	paths, _ := filepath.Glob(filepath.Join(dir, prefix+"-*.jsonl"))
	for _, path := range paths {
		label := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(path), prefix+"-"), ".jsonl")
		if stamp, err := time.Parse(layout, label); err == nil && stamp.Before(after) {
			_ = os.Remove(path)
		}
	}
}

func (a *agent) collect(ctx context.Context) {
	sample := sampler{config: a.config}
	ticker := time.NewTicker(cadence)
	defer ticker.Stop()
	var summary minuteSummary
	for {
		r, err := sample.sample()
		if err == nil {
			v := a.observe(*r)
			hour := v.At.Truncate(time.Hour)
			if err := appendRecord(filepath.Join(a.config.StateDir, "detail-"+hour.Format("2006010215")+".jsonl"), v, 2<<20); err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
			minute := v.At.Truncate(time.Minute)
			if summary.Minute != minute {
				if summary.Samples > 0 {
					summary.MeanCPU /= float64(summary.Samples)
					path := filepath.Join(a.config.StateDir, "minute-"+summary.Minute.Format("20060102")+".jsonl")
					if err := appendRecord(path, summary, 2<<20); err != nil {
						fmt.Fprintln(os.Stderr, err)
					}
				}
				prune(a.config.StateDir, "detail", hour.Add(-23*time.Hour), "2006010215")
				prune(a.config.StateDir, "minute", minute.Truncate(24*time.Hour).Add(-6*24*time.Hour), "20060102")
				summary = minuteSummary{Minute: minute, MinAvailable: 1, firstCPU: v.ToolCPU}
			}
			summary.Samples++
			summary.MeanCPU += v.CPU
			summary.MinAvailable = min(summary.MinAvailable, v.Available)
			summary.PeakWorkingSet = max(summary.PeakWorkingSet, v.WorkingSet)
			summary.ToolCPUSeconds = max(0, v.ToolCPU-summary.firstCPU)
			summary.Pressure = summary.Pressure || v.OOM || v.MemoryPressure || v.SustainedPressure
		} else {
			fmt.Fprintln(os.Stderr, err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func serveAgent(ctx context.Context, config AgentConfig) error {
	if err := config.validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(config.StateDir, 0700); err != nil {
		return err
	}
	unlock, err := lock(config.StateDir)
	if err != nil {
		return err
	}
	defer unlock()
	tlsConfig, err := config.Identity.tls(true)
	if err != nil {
		return err
	}
	a := agent{config: config}
	if err := readJSON(filepath.Join(config.StateDir, "lease.json"), &a.lease); err != nil && !os.IsNotExist(err) {
		return err
	}
	l, err := net.Listen("tcp", config.Listen)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	collectorDone := make(chan struct{})
	go func() { defer close(collectorDone); a.collect(ctx) }()
	server := http.Server{TLSConfig: tlsConfig, Handler: http.HandlerFunc(a.handle), ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout: 4 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 4096}
	results := make(chan error, 1)
	go func() { results <- server.ServeTLS(l, "", "") }()
	select {
	case err := <-results:
		cancel()
		<-collectorDone
		return err
	case <-ctx.Done():
		_ = server.Close()
		<-collectorDone
		return nil
	}
}
