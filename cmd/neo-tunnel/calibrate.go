package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"time"
)

type trial struct {
	Result
	latency     []time.Duration
	loaded      []time.Duration
	connect     []time.Duration
	firstByte   []time.Duration
	lastFail    time.Time
	minHeadroom [2]float64
	invalidCPU  [2]bool
	invalidWire [2]bool
}

func (t *trial) observe(v timing, err error, useful int64, at time.Time) {
	t.Samples++
	t.AttemptedUseful += useful
	if err != nil {
		if isTimeout(err) {
			t.Timeouts++
		} else {
			t.Errors++
		}
		if t.lastFail.IsZero() {
			t.Outages++
			t.lastFail = at
		}
		return
	}
	t.Success++
	t.Useful += useful
	if useful > 0 {
		t.loaded = append(t.loaded, v.Total)
		t.LoadSuccess++
	}
	t.latency = append(t.latency, v.Total)
	t.connect = append(t.connect, v.Connect)
	t.firstByte = append(t.firstByte, v.FirstByte)
	t.finishOutage(at)
}

func (t *trial) finishOutage(at time.Time) {
	if !t.lastFail.IsZero() {
		t.OutageSeconds += at.Sub(t.lastFail).Seconds()
		t.lastFail = time.Time{}
	}
}

func p95(values []time.Duration) float64 {
	if len(values) == 0 {
		return 0
	}
	slices.Sort(values)
	i := (len(values)*95+99)/100 - 1
	return float64(values[i]) / float64(time.Millisecond)
}

func (t *trial) summarize() Result {
	t.P95MS = p95(t.latency)
	if len(t.loaded) > 0 {
		t.LoadP95MS = ptr(p95(t.loaded))
	}
	t.ConnectP95MS = p95(t.connect)
	t.FirstByteP95MS = p95(t.firstByte)
	if t.Iran.CPUPerGiB != nil && t.Peer.CPUPerGiB != nil {
		t.TotalCPUPerGiB = ptr(*t.Iran.CPUPerGiB + *t.Peer.CPUPerGiB)
	}
	t.LimitingHost = "iran"
	if t.minHeadroom[1] < t.minHeadroom[0] {
		t.LimitingHost = "peer"
	}
	return t.Result
}

func (t *trial) resources(before, after [2]*Reading, useful int64) {
	if before[0] == nil || before[1] == nil || after[0] == nil || after[1] == nil {
		return
	}
	for i, entry := range []*Cost{&t.Iran, &t.Peer} {
		v := cost(*before[i], *after[i], useful)
		entry.CPUSeconds += v.CPUSeconds
		entry.PeakWorkingSet = max(entry.PeakWorkingSet, v.PeakWorkingSet)
		if v.ExtraBytes == nil {
			t.invalidWire[i] = true
		}
		if after[i].ToolCPU < before[i].ToolCPU {
			t.invalidCPU[i] = true
		}
		if !t.invalidWire[i] {
			if entry.ExtraBytes == nil {
				entry.ExtraBytes = ptr(uint64(0))
			}
			*entry.ExtraBytes += *v.ExtraBytes
		} else {
			entry.ExtraBytes = nil
		}
		if t.Useful > 0 && !t.invalidCPU[i] {
			entry.CPUPerGiB = ptr(entry.CPUSeconds * (1 << 30) / float64(t.Useful))
		} else {
			entry.CPUPerGiB = nil
		}
	}
}

func sizes(index int) int {
	switch {
	case index < 10:
		return 0
	case index < 30:
		return 1024
	case index < 45:
		return 16 << 10
	default:
		return 256 << 10
	}
}

func shifted(r *Reading) bool {
	return r != nil && (r.CPU > r.BaselineCPU+.25 || r.Available < r.BaselineAvailable-.15)
}

func (c *controller) batch(ctx context.Context, op Operation, t *trial, startIndex, endIndex int, quota *int64, active string) error {
	start := time.Now()
	defer func() { t.DurationSeconds += time.Since(start).Seconds(); t.finishOutage(time.Now()) }()
	snapshot := c.resourcePair(ctx)
	if err := guard(time.Now(), snapshot[0], snapshot[1], false); err != nil {
		return err
	}
	current := snapshot
	var refreshed, sampled time.Time
	priorUseful := t.Useful
	// Only this batch's successfully completed transfers are used for its overhead.
	defer func() { t.resources(snapshot, current, t.Useful-priorUseful) }()
	for i := startIndex; i < endIndex; i++ {
		if err := wait(ctx, time.Until(start.Add(time.Duration(i-startIndex)*1600*time.Millisecond))); err != nil {
			return err
		}
		if time.Since(refreshed) >= 15*time.Second {
			if err := c.operate(ctx, agentRequest{ID: op.ID, Action: "claim"}); err != nil {
				return err
			}
			refreshed = time.Now()
		}
		if time.Since(sampled) >= cadence {
			current = c.resourcePair(ctx)
			if err := guard(time.Now(), current[0], current[1], false); err != nil {
				return err
			}
			for j, r := range current {
				if shifted(r) {
					return fmt.Errorf("host %d: load changed from its baseline", j+1)
				}
				target := &t.Iran
				if j == 1 {
					target = &t.Peer
				}
				target.PeakWorkingSet = max(target.PeakWorkingSet, r.WorkingSet)
				headroom := min(1-r.CPU, r.Available)
				t.minHeadroom[j] = min(t.minHeadroom[j], headroom)
			}
			health, err := c.health(ctx)
			if err != nil {
				return err
			}
			if !health[active].ready() || c.service(ctx, active) != nil {
				return errors.New("active path or its application lost readiness")
			}
			sampled = time.Now()
		}
		p := c.config.Profiles[t.Profile]
		n := sizes(i)
		path := "/readyz"
		expected := []byte("backhaul-ready-v1\n")
		var payload []byte
		if n > 0 {
			reserved := int64(n) * 2
			if reserved > *quota {
				return errors.New("calibration data budget exhausted")
			}
			*quota -= reserved
			payload = make([]byte, n)
			rand.Read(payload)
			expected = payload
			path = "/transfer"
		}
		at := time.Now()
		d, err := c.measure(ctx, readyProbeURL(p, path), expected, payload)
		t.observe(d, err, int64(n)*2, at)
	}
	finished := time.Now()
	for current[0].At.Before(finished) || current[1].At.Before(finished) {
		if err := wait(ctx, time.Second); err != nil {
			return err
		}
		current = c.resourcePair(ctx)
		if err := guard(time.Now(), current[0], current[1], false); err != nil {
			return err
		}
	}
	return nil
}

func (c *controller) calibration(ctx context.Context, state *State, target string) (proposal Proposal, err error) {
	c.pruneHistory()
	if target == "" {
		for id, p := range c.config.Profiles {
			if id != state.Active.Profile && id != state.Parked && !p.Staged {
				target = id
			}
		}
	}
	p, ok := c.config.Profiles[target]
	if !ok || target == state.Active.Profile || target == state.Parked || (p.Staged && (p.Replaces != state.Active.Profile || state.Retiring != "")) {
		return Proposal{}, errors.New("choose a distinct, configured profile")
	}
	reading := c.resourcePair(ctx)
	if err := admit(time.Now(), reading[0], reading[1]); err != nil {
		return Proposal{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, maxRun)
	defer cancel()
	op := Operation{ID: newID(), Kind: "calibrate", Target: target, Started: time.Now(), Stage: "preparing"}
	state.Pending = &op
	if err := c.save(*state); err != nil {
		return Proposal{}, err
	}
	defer func() {
		finish, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		err = errors.Join(err, c.recover(finish, state))
	}()
	if err := c.operate(ctx, agentRequest{ID: op.ID, Action: "claim"}); err != nil {
		return Proposal{}, err
	}
	if err := c.prepare(ctx, op, p.Staged); err != nil {
		return Proposal{}, err
	}
	if err := c.service(ctx, state.Active.Profile); err != nil {
		return Proposal{}, err
	}
	if err := c.service(ctx, target); err != nil {
		return Proposal{}, err
	}
	base := trial{Result: Result{Profile: state.Active.Profile}, minHeadroom: [2]float64{1, 1}}
	comparison := trial{Result: Result{Profile: target}, minHeadroom: [2]float64{1, 1}}
	remaining := int64(maxUseful)
	for _, window := range []struct {
		trial      *trial
		start, end int
	}{{&base, 0, 30}, {&comparison, 0, 60}, {&base, 30, 60}} {
		if err := c.batch(ctx, op, window.trial, window.start, window.end, &remaining, state.Active.Profile); err != nil {
			window.trial.Uncertain = true
			window.trial.Reason = err.Error()
			break
		}
	}
	if err := c.service(ctx, target); err != nil {
		comparison.Uncertain = true
		comparison.Reason = err.Error()
	}
	proposal = Proposal{ID: op.ID, Config: c.digest, Base: state.Active.ID, Target: target, Setting: p.Experiment,
		Created: time.Now().UTC(), Baseline: base.summarize(), Candidate: comparison.summarize()}
	proposal.Eligible = prefer(proposal.Baseline, proposal.Candidate)
	return proposal, atomicJSON(filepath.Join(c.config.StateDir, "proposal-"+proposal.ID+".json"), proposal)
}
