package main

import (
	"bufio"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func snapshot(now time.Time) Reading {
	return Reading{At: now, CPU: .25, Available: .6, WorkingSet: 16 << 20, ToolCPU: 150, BaselineReady: true}
}

func TestCalibrationGateRejectsUnknownOrPressuredHost(t *testing.T) {
	now := time.Now()
	local, remote := snapshot(now), snapshot(now)
	for _, test := range []struct {
		name   string
		change func(*Reading)
	}{
		{"stale", func(r *Reading) { r.At = now.Add(-31 * time.Second) }},
		{"cpu", func(r *Reading) { r.CPU = .80 }},
		{"memory", func(r *Reading) { r.Available = .20 }},
		{"oom", func(r *Reading) { r.OOM = true }},
		{"short baseline", func(r *Reading) { r.BaselineReady = false }},
	} {
		t.Run(test.name, func(t *testing.T) {
			peer := remote
			test.change(&peer)
			if err := admit(now, &local, &peer); err == nil {
				t.Fatal("unsafe calibration admitted")
			}
		})
	}
	if err := admit(now, &local, &remote); err != nil {
		t.Fatal(err)
	}
	if err := admit(now, &local, nil); err == nil {
		t.Fatal("missing peer admitted")
	}
}

func TestCostRequiresUsefulTransfer(t *testing.T) {
	before, after := snapshot(time.Now()), snapshot(time.Now())
	after.ToolCPU += 2
	if cost(before, after, 0).CPUPerGiB != nil {
		t.Fatal("no useful data must remain unknown")
	}
	got := cost(before, after, 64<<20).CPUPerGiB
	if got == nil || math.Abs(*got-32) > .0001 {
		t.Fatalf("CPU cost = %v, want 32 CPU-seconds/GiB", got)
	}
}

func TestChoiceRequiresEnoughQualityEvidence(t *testing.T) {
	base := Result{Samples: 60, Success: 60, P95MS: 100, TotalCPUPerGiB: ptr(35.)}
	candidate := Result{Samples: 60, Success: 60, P95MS: 109, TotalCPUPerGiB: ptr(25.)}
	if !prefer(base, candidate) {
		t.Fatal("lower CPU cost with equivalent quality was rejected")
	}
	for _, bad := range []Result{
		{Samples: 59, Success: 59, P95MS: 95, TotalCPUPerGiB: ptr(25.)},
		{Samples: 60, Success: 60, P95MS: 111, TotalCPUPerGiB: ptr(25.)},
		{Samples: 60, Success: 60, P95MS: 102, Outages: 1, TotalCPUPerGiB: ptr(25.)},
		{Samples: 60, Success: 60, P95MS: 102, Uncertain: true, TotalCPUPerGiB: ptr(25.)},
	} {
		if prefer(base, bad) {
			t.Errorf("selected insufficient or worse evidence: %+v", bad)
		}
	}
}

func TestRecoveryRestoresPreferenceAfterInterruptedSwitch(t *testing.T) {
	ctx := t.Context()
	dir, err := os.MkdirTemp("/tmp", "neo-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "edge.sock")
	conn, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	commands := make(chan string, 1)
	go func() {
		client, err := conn.Accept()
		if err != nil {
			return
		}
		defer client.Close()
		line, _ := bufio.NewReader(client).ReadString('\n')
		commands <- line
	}()
	config := Config{StateDir: dir, HAProxySocket: socket, MapFile: filepath.Join(dir, "route.map"),
		Profiles: map[string]Profile{"primary": {}, "standby": {}}}
	c := controller{config: config, api: &http.Client{}}
	s := State{Active: Version{Profile: "primary", ID: "v1"}, Pending: &Operation{ID: newID(), Kind: "apply", Stage: "switching", Target: "standby"}}
	if err := c.save(s); err != nil {
		t.Fatal(err)
	}
	if err := c.recover(ctx, &s); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-commands:
		want := "set map " + config.MapFile + " preference primary\n"
		if got != want {
			t.Fatalf("runtime command=%q, want %q", got, want)
		}
	case <-time.After(time.Second):
		t.Fatal("runtime preference was not recovered")
	}
	data, err := os.ReadFile(config.MapFile)
	if err != nil || string(data) != "preference primary\n" {
		t.Fatalf("persisted preference %q, error=%v", data, err)
	}
	onDisk, err := c.state()
	if err != nil || onDisk.Active.ID != "v1" || onDisk.Pending != nil {
		t.Fatalf("persisted state %+v, error=%v", onDisk, err)
	}
}

func TestHostPressureRequiresThirtySeconds(t *testing.T) {
	a := agent{}
	at := time.Now()
	for i := 0; i < 8; i++ {
		next := snapshot(at.Add(time.Duration(i) * 5 * time.Second))
		next.CPU = .85
		got := a.observe(next)
		if got.SustainedPressure != (i >= 6) {
			t.Fatalf("at %ds pressure=%v", i*5, got.SustainedPressure)
		}
	}
	recovered := a.observe(snapshot(at.Add(40 * time.Second)))
	if recovered.SustainedPressure {
		t.Fatal("pressure did not clear")
	}
}

func TestOperationLeaseSurvivesRestartAndRejectsConcurrentChange(t *testing.T) {
	config := AgentConfig{StateDir: t.TempDir()}
	initial := agent{config: config}
	ctx := t.Context()
	first := agentRequest{ID: newID(), Action: "claim"}
	if err := initial.operate(ctx, first); err != nil {
		t.Fatal(err)
	}
	restarted := agent{config: config}
	if err := readJSON(filepath.Join(config.StateDir, "lease.json"), &restarted.lease); err != nil {
		t.Fatal(err)
	}
	second := agentRequest{ID: newID(), Action: "claim"}
	if err := restarted.operate(ctx, second); err == nil {
		t.Fatal("second operation bypassed the lease")
	}
	if err := restarted.operate(ctx, first); err != nil {
		t.Fatal("same operation could not retry:", err)
	}
}

func TestAutomaticPreferenceNeedsFiveMinutesOfRepeatedEvidence(t *testing.T) {
	now := time.Now()
	state := State{Active: Version{ID: "v1", Activated: now.Add(-time.Hour)}}
	base := Result{Samples: 60, Success: 60, P95MS: 100}
	better := Result{Samples: 60, Success: 60, P95MS: 50}
	newer := Proposal{ID: "new", Base: "v1", Target: "standby", Created: now, Eligible: true, Baseline: base, Candidate: better}
	older := newer
	older.ID = "old"
	older.Created = now.Add(-4 * time.Minute)
	if eligibleAutomatic(now, state, []Proposal{newer, older}) != nil {
		t.Fatal("selected a route with only four minutes of evidence")
	}
	older.Created = now.Add(-5 * time.Minute)
	if chosen := eligibleAutomatic(now, state, []Proposal{older, newer}); chosen == nil || chosen.ID != "new" {
		t.Fatalf("eligible repeated evidence was ignored: %+v", chosen)
	}
	state.Active.Activated = now.Add(-4 * time.Minute)
	if eligibleAutomatic(now, state, []Proposal{older, newer}) != nil {
		t.Fatal("cooldown did not prevent a repeated switch")
	}
}
