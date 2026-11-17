package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func (c *controller) statePath() string  { return filepath.Join(c.config.StateDir, "state.json") }
func (c *controller) save(s State) error { return atomicJSON(c.statePath(), s) }

func (c *controller) state() (State, error) {
	var s State
	err := readJSON(c.statePath(), &s)
	if os.IsNotExist(err) {
		return State{Active: Version{Profile: c.config.Initial, ID: "initial"}}, nil
	}
	if _, ok := c.config.Profiles[s.Active.Profile]; err == nil && !ok {
		return State{}, errors.New("active profile missing from controller configuration")
	}
	return s, err
}

func (c *controller) prepare(ctx context.Context, op Operation, provision bool) error {
	p := c.config.Profiles[op.Target]
	if provision {
		if err := c.operate(ctx, agentRequest{ID: op.ID, Profile: op.Target, Action: "start"}); err != nil {
			return err
		}
		reply, err := c.runtime(ctx, "set server "+op.Target+"/via_"+op.Target+" state ready")
		if err != nil {
			return err
		}
		if reply != "" {
			return fmt.Errorf("HAProxy rejected readiness: %s", reply)
		}
	}
	nextClaim := time.Now().Add(12 * time.Second)
	for {
		if time.Now().After(nextClaim) {
			if err := c.operate(ctx, agentRequest{ID: op.ID, Action: "claim"}); err != nil {
				return err
			}
			nextClaim = time.Now().Add(12 * time.Second)
		}
		pair := c.resourcePair(ctx)
		if err := guard(time.Now(), pair[0], pair[1], false); err != nil && op.Kind != "rollback" {
			return err
		}
		health, err := c.health(ctx)
		if err != nil {
			return err
		}
		if health[op.Target].ready() {
			break
		}
		if err := wait(ctx, 2*time.Second); err != nil {
			return err
		}
	}
	if _, err := c.measure(ctx, readyProbeURL(p, "/readyz"), []byte("backhaul-ready-v1\n"), nil); err != nil {
		return err
	}
	return c.service(ctx, op.Target)
}

func (c *controller) recover(ctx context.Context, s *State) error {
	op := s.Pending
	if op == nil {
		return nil
	}
	if op.Kind == "retire" {
		return c.finishRetirement(ctx, s, *op)
	}
	if op.Stage == "switching" {
		if err := c.route(ctx, s.Active.Profile); err != nil {
			return fmt.Errorf("restore active preference: %w", err)
		}
	}
	if (c.config.Profiles[op.Target].Staged || s.Parked == op.Target) && s.Active.Profile != op.Target {
		if op.Target == s.Retiring {
			s.Pending = nil
			s.LastOutcome = op.Kind + " failed; existing sessions retained"
			_ = c.operate(ctx, agentRequest{ID: op.ID, Action: "release"})
			return c.save(*s)
		}
		if err := c.operate(ctx, agentRequest{ID: op.ID, Action: "claim"}); err != nil {
			return err
		}
		if err := c.operate(ctx, agentRequest{ID: op.ID, Profile: op.Target, Action: "stop"}); err != nil {
			return err
		}
	}
	// The lease also expires independently if a host cannot be contacted.
	_ = c.operate(ctx, agentRequest{ID: op.ID, Action: "release"})
	s.Pending = nil
	s.LastOutcome = op.Kind + " finished without switching"
	if err := c.save(*s); err != nil {
		s.Pending = op
		return err
	}
	return nil
}

func (c *controller) readProposal(id string) (Proposal, error) {
	var p Proposal
	if raw, err := hex.DecodeString(id); err != nil || len(raw) != 16 {
		return p, errors.New("invalid proposal ID")
	}
	err := readJSON(filepath.Join(c.config.StateDir, "proposal-"+id+".json"), &p)
	if err != nil {
		return p, err
	}
	if p.ID != id || p.Config != c.digest {
		return p, errors.New("proposal has a different configuration; run calibrate again")
	}
	return p, nil
}

func (c *controller) apply(ctx context.Context, s *State, id string) error {
	p, err := c.readProposal(id)
	if err != nil {
		return err
	}
	if s.Active.ID == id {
		return nil
	}
	if p.Base != s.Active.ID || time.Since(p.Created) > 24*time.Hour {
		return errors.New("proposal evidence is stale; run calibrate again against the current version")
	}
	if !p.Eligible || !prefer(p.Baseline, p.Candidate) {
		return errors.New("proposal has insufficient evidence for application")
	}
	return c.switchRoute(ctx, s, p.Target, id, "apply")
}

func (c *controller) rollback(ctx context.Context, s *State) error {
	if s.Previous == nil {
		return errors.New("no previous version to restore")
	}
	return c.switchRoute(ctx, s, s.Previous.Profile, newID(), "rollback")
}

func (c *controller) switchRoute(ctx context.Context, s *State, target, version, kind string) (err error) {
	targetProfile, ok := c.config.Profiles[target]
	if !ok || target == s.Active.Profile || (targetProfile.Staged && targetProfile.Replaces != s.Active.Profile) {
		return errors.New("invalid target profile")
	}
	if kind != "rollback" && time.Since(s.Active.Activated) < 5*time.Minute {
		return errors.New("wait five minutes after the previous change")
	}
	ctx, cancel := context.WithTimeout(ctx, 80*time.Second)
	defer cancel()
	pair := c.resourcePair(ctx)
	if kind != "rollback" {
		if err := admit(time.Now(), pair[0], pair[1]); err != nil {
			return err
		}
	}
	op := Operation{ID: newID(), Stage: "preparing", Target: target, Kind: kind, Started: time.Now().UTC()}
	s.Pending = &op
	if err := c.save(*s); err != nil {
		return err
	}
	defer func() {
		finish, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		if err != nil {
			err = errors.Join(err, c.recover(finish, s))
			return
		}
		_ = c.operate(finish, agentRequest{ID: op.ID, Action: "release"})
	}()
	if err = c.operate(ctx, agentRequest{ID: op.ID, Action: "claim"}); err != nil {
		return err
	}
	provision := targetProfile.Staged || s.Parked == target
	if err = c.prepare(ctx, op, provision); err != nil {
		return err
	}

	op.Stage = "switching"
	if err = c.save(*s); err != nil {
		return err
	}
	if err = c.route(ctx, target); err != nil {
		return err
	}
	prior := s.Active
	next := *s
	next.Active = Version{Profile: target, ID: version, Activated: time.Now().UTC()}
	next.Previous = &prior
	next.Observation = nil
	if kind == "apply" || kind == "automatic" {
		next.Observation = &Observation{Before: pair, Until: next.Active.Activated.Add(5 * time.Minute)}
	}
	if s.Parked == target {
		next.Parked = ""
	}
	next.Retiring = ""
	switch {
	case targetProfile.Staged:
		next.Retiring = prior.Profile
	case c.config.Profiles[prior.Profile].Staged:
		next.Retiring = prior.Profile
	}
	if next.Retiring != "" {
		next.DrainAfter = next.Active.Activated.Add(5 * time.Minute)
	} else {
		next.DrainAfter = time.Time{}
	}
	next.Pending = nil
	next.LastOutcome = kind + " committed"
	if err = c.save(next); err != nil {
		// fsync can fail after the atomic rename. Read the resulting state before deciding how to recover.
		onDisk, readErr := c.state()
		if readErr == nil && onDisk.Active.ID == version && onDisk.Pending == nil {
			*s = onDisk
		}
		return err
	}
	*s = next
	return nil
}

func (c *controller) retire(ctx context.Context, s *State) error {
	if time.Now().Before(s.DrainAfter) {
		return nil
	}
	health, err := c.health(ctx)
	if err != nil {
		return err
	}
	standby := c.readyReserve(*s, health)
	old, known := health[s.Retiring]
	if !standby || !health[s.Active.Profile].ready() || !known || old.Sessions > 0 {
		return nil
	}
	op := Operation{ID: newID(), Kind: "retire", Stage: "draining", Target: s.Retiring, Started: time.Now().UTC()}
	s.Pending = &op
	if err := c.save(*s); err != nil {
		return err
	}
	return c.finishRetirement(ctx, s, op)
}

func (c *controller) readyReserve(s State, health map[string]Health) bool {
	for id, p := range c.config.Profiles {
		if !p.Staged && id != s.Active.Profile && id != s.Retiring && id != s.Parked && health[id].ready() {
			return true
		}
	}
	return false
}

func (c *controller) finishRetirement(ctx context.Context, s *State, op Operation) error {
	if err := c.operate(ctx, agentRequest{ID: op.ID, Action: "claim"}); err != nil {
		return err
	}
	old := op.Target
	health, err := c.health(ctx)
	if err != nil {
		return err
	}
	if !health[s.Active.Profile].ready() || !c.readyReserve(*s, health) {
		// At least one of the two remaining paths is unavailable. Restore the old route as an option.
		if err := c.operate(ctx, agentRequest{ID: op.ID, Profile: old, Action: "start"}); err != nil {
			return err
		}
		reply, err := c.runtime(ctx, "set server "+old+"/via_"+old+" state ready")
		if err != nil {
			return err
		}
		if reply != "" {
			return fmt.Errorf("HAProxy could not cancel drain: %s", reply)
		}
		s.Pending = nil
		_ = c.operate(ctx, agentRequest{ID: op.ID, Action: "release"})
		return c.save(*s)
	}
	if health[old].State != "DRAIN" {
		reply, err := c.runtime(ctx, "set server "+old+"/via_"+old+" state drain")
		if err != nil {
			return err
		}
		if reply != "" {
			return fmt.Errorf("HAProxy rejected drain: %s", reply)
		}
	}
	health, err = c.health(ctx)
	if err != nil {
		return err
	}
	h, ok := health[old]
	if !ok || h.Sessions > 0 {
		return nil
	}
	if err := c.operate(ctx, agentRequest{ID: op.ID, Profile: old, Action: "stop"}); err != nil {
		return err
	}
	if !c.config.Profiles[old].Staged {
		s.Parked = old
	}
	s.Pending = nil
	s.Retiring = ""
	s.DrainAfter = time.Time{}
	s.LastOutcome = "previous path drained"
	if err := c.save(*s); err != nil {
		return err
	}
	_ = c.operate(ctx, agentRequest{ID: op.ID, Action: "release"})
	return nil
}
