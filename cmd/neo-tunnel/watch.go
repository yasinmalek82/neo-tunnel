package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

func pressureFromChange(before, after *Reading) bool {
	if before == nil || after == nil || (!after.SustainedPressure && !after.OOM && !after.MemoryPressure) {
		return false
	}
	return after.ToolCPUFraction > before.ToolCPUFraction+.10 || after.WorkingSet > before.WorkingSet+(32<<20)
}

func (c *controller) observeChange(ctx context.Context, s *State) error {
	window := s.Observation
	now := time.Now()
	if now.After(window.Until) {
		s.Observation = nil
		return c.save(*s)
	}
	pair := c.resourcePair(ctx)
	if !pressureFromChange(window.Before[0], pair[0]) && !pressureFromChange(window.Before[1], pair[1]) {
		return nil
	}
	health, err := c.health(ctx)
	if err != nil {
		return err
	}
	if s.Previous == nil || !health[s.Previous.Profile].ready() {
		return errors.New("resource pressure after change; previous path is unavailable")
	}
	return c.rollback(ctx, s)
}

func eligibleAutomatic(now time.Time, s State, proposals []Proposal) *Proposal {
	if now.Sub(s.Active.Activated) < 5*time.Minute {
		return nil
	}
	slices.SortFunc(proposals, func(a, b Proposal) int { return b.Created.Compare(a.Created) })
	if len(proposals) < 2 {
		return nil
	}
	first := proposals[0]
	if !first.Eligible || !prefer(first.Baseline, first.Candidate) || first.Base != s.Active.ID {
		return nil
	}
	for _, p := range proposals[1:] {
		if p.Base != first.Base || p.Target != first.Target || !p.Eligible || !prefer(p.Baseline, p.Candidate) {
			break
		}
		if now.Sub(p.Created) > 30*time.Minute {
			break
		}
		if first.Created.Sub(p.Created) >= 5*time.Minute {
			return &first
		}
	}
	return nil
}

func (c *controller) evaluatePreference(ctx context.Context, s *State) error {
	if !c.config.AutoPrefer || s.Observation != nil {
		return nil
	}
	paths, err := filepath.Glob(filepath.Join(c.config.StateDir, "proposal-*.json"))
	if err != nil {
		return err
	}
	now := time.Now()
	var evidence []Proposal
	for _, path := range paths {
		id := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(path), "proposal-"), ".json")
		p, err := c.readProposal(id)
		profile, ok := c.config.Profiles[p.Target]
		if err == nil && ok && !profile.Staged && !c.config.Profiles[s.Active.Profile].Staged && p.Target != s.Parked && p.Base == s.Active.ID &&
			!p.Created.After(now) && now.Sub(p.Created) < 30*time.Minute {
			evidence = append(evidence, p)
		}
	}
	p := eligibleAutomatic(now, *s, evidence)
	if p == nil {
		return nil
	}
	return c.switchRoute(ctx, s, p.Target, p.ID, "automatic")
}

func (c *controller) maintain(ctx context.Context, s *State) error {
	if s.Pending != nil {
		recovery, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		return c.recover(recovery, s)
	}
	if s.Observation != nil {
		return c.observeChange(ctx, s)
	}
	if s.Retiring != "" {
		return c.retire(ctx, s)
	}
	return c.evaluatePreference(ctx, s)
}

func (c *controller) pruneHistory() {
	files, _ := filepath.Glob(filepath.Join(c.config.StateDir, "proposal-*.json"))
	now := time.Now()
	for _, f := range files {
		if info, err := os.Stat(f); err == nil && now.Sub(info.ModTime()) > 7*24*time.Hour {
			_ = os.Remove(f)
		}
	}
}

type PathEvent struct {
	At             time.Time         `json:"at"`
	Paths          map[string]Health `json:"paths"`
	ConcurrentDown bool              `json:"concurrent_down"`
	Confidence     string            `json:"confidence"`
}

func (c *controller) recordPathChanges(health map[string]Health, last *map[string]bool) error {
	next := make(map[string]bool)
	numDown := 0
	numKnown := 0
	different := false
	for id, p := range c.config.Profiles {
		if p.Staged {
			continue
		}
		h, ok := health[id]
		if !ok {
			continue
		}
		numKnown++
		next[id] = h.ready()
		if h.State == "DOWN" && h.Check != "" && h.Check != "INI" {
			numDown++
		}
		old, known := (*last)[id]
		if !known || old != next[id] {
			different = true
		}
	}
	if !different || numKnown != 2 {
		return nil
	}
	if err := os.MkdirAll(c.config.StateDir, 0700); err != nil {
		return err
	}
	now := time.Now().UTC()
	prune(c.config.StateDir, "paths", now.Truncate(24*time.Hour).Add(-6*24*time.Hour), "20060102")
	path := filepath.Join(c.config.StateDir, "paths-"+now.Format("20060102")+".jsonl")
	if err := appendRecord(path, PathEvent{At: now, Paths: health, ConcurrentDown: numDown == 2, Confidence: "active_health_check"}, 2<<20); err != nil {
		return err
	}
	*last = next
	return nil
}

func (c *controller) concurrentDownEvents() int {
	paths, _ := filepath.Glob(filepath.Join(c.config.StateDir, "paths-*.jsonl"))
	total := 0
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		decoder := json.NewDecoder(io.LimitReader(f, 2<<20))
		for {
			var event PathEvent
			if decoder.Decode(&event) != nil {
				break
			}
			if event.ConcurrentDown {
				total++
			}
		}
		_ = f.Close()
	}
	return total
}
