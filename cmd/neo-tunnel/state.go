package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

type Version struct {
	Profile   string    `json:"profile"`
	ID        string    `json:"id"`
	Activated time.Time `json:"activated"`
}

type Operation struct {
	ID      string    `json:"id"`
	Kind    string    `json:"kind"`
	Stage   string    `json:"stage"`
	Target  string    `json:"target"`
	Started time.Time `json:"started"`
}

type State struct {
	Retiring    string       `json:"retiring,omitempty"`
	Parked      string       `json:"parked,omitempty"`
	DrainAfter  time.Time    `json:"drain_after,omitempty"`
	Observation *Observation `json:"observation,omitempty"`
	Active      Version      `json:"active"`
	Previous    *Version     `json:"previous"`
	Pending     *Operation   `json:"pending,omitempty"`
	LastOutcome string       `json:"last_outcome,omitempty"`
}

type Observation struct {
	Before [2]*Reading `json:"before"`
	Until  time.Time   `json:"until"`
}

type Proposal struct {
	ID        string    `json:"id"`
	Config    string    `json:"config_sha256"`
	Base      string    `json:"base_version"`
	Target    string    `json:"target"`
	Setting   string    `json:"setting"`
	Created   time.Time `json:"created"`
	Baseline  Result    `json:"baseline"`
	Candidate Result    `json:"candidate"`
	Eligible  bool      `json:"eligible"`
}

func atomicJSON(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(path, append(raw, '\n'), 0600)
}

func atomicWrite(path string, data []byte, permissions os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".neo-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(permissions); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	parent, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}

func lock(dir string) (func(), error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "operation.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("an operation is already running: %w", err)
	}
	return func() { _ = f.Close() }, nil
}
