package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const pilotDuration = 7 * 24 * time.Hour
const maxPilotBytes = 32 << 20

type Pilot struct {
	AutoDisabled bool      `json:"auto_disabled,omitempty"`
	ID           string    `json:"id"`
	Start        time.Time `json:"start"`
	End          time.Time `json:"end"`
}

type pilotResources struct {
	CPU        float64  `json:"host_cpu_fraction"`
	Available  float64  `json:"host_memory_available_fraction"`
	ToolCPU    *float64 `json:"tool_cpu_seconds_per_second"`
	WorkingSet uint64   `json:"tool_working_set_bytes"`
	Pressure   bool     `json:"pressure"`
	OOM        bool     `json:"oom"`
}

type pilotMinute struct {
	At         time.Time       `json:"at"`
	Primary    *bool           `json:"primary_ready"`
	Standby    *bool           `json:"standby_ready"`
	Iran       *pilotResources `json:"iran"`
	Peer       *pilotResources `json:"peer"`
	LastOutage *time.Time      `json:"last_outage,omitempty"`
}

type pilotCutover struct {
	ID string    `json:"pilot_id"`
	At time.Time `json:"at"`
}

type pilotSummary struct {
	CutoverAt           *time.Time           `json:"cutover_at,omitempty"`
	Availability        *availabilityMetrics `json:"availability,omitempty"`
	Pilot               Pilot                `json:"pilot"`
	Active              bool                 `json:"active"`
	ExpectedMinutes     int                  `json:"expected_minutes"`
	ObservedMinutes     int                  `json:"observed_minutes"`
	HealthMinutes       int                  `json:"health_minutes"`
	UnreadyMinutes      int                  `json:"unready_minutes"`
	IranMinutes         int                  `json:"iran_minutes"`
	PeerMinutes         int                  `json:"peer_minutes"`
	IranPressureMinutes int                  `json:"iran_pressure_minutes"`
	PeerPressureMinutes int                  `json:"peer_pressure_minutes"`
	LastOutage          *time.Time           `json:"last_outage,omitempty"`
	CustomerSuccess     *float64             `json:"customer_success"`
	WireOverhead        *uint64              `json:"wire_overhead_bytes"`
}

func pilotPath(dir string) string         { return filepath.Join(dir, "pilot.json") }
func dataPath(dir string, p Pilot) string { return filepath.Join(dir, "pilot-"+p.ID+".jsonl") }
func startPilot(dir string, now time.Time) (Pilot, error) {
	p := Pilot{ID: newID(), Start: now.UTC(), End: now.UTC().Add(pilotDuration)}
	var prior Pilot
	err := readJSON(pilotPath(dir), &prior)
	if err == nil && now.Before(prior.End) {
		return Pilot{}, errors.New("a pilot is already running")
	}
	if err != nil && !os.IsNotExist(err) {
		return Pilot{}, err
	}
	if err := atomicJSON(pilotPath(dir), p); err != nil {
		return Pilot{}, err
	}
	// The previous period can be preserved by exporting it before starting a new one.
	files, _ := filepath.Glob(filepath.Join(dir, "pilot-*.jsonl"))
	for _, name := range files {
		if name != dataPath(dir, p) {
			_ = os.Remove(name)
		}
	}
	return p, nil
}

func safeMinute(now time.Time, s dashboardSnapshot) pilotMinute {
	m := pilotMinute{At: now.UTC().Truncate(time.Minute), LastOutage: s.LastOutage}
	for id, dst := range map[string]**bool{"primary": &m.Primary, "standby": &m.Standby} {
		if h, ok := s.Health[id]; ok && h.State != "" && h.Check != "INI" {
			*dst = ptr(h.ready())
		}
	}
	resources := func(r *Reading) *pilotResources {
		if !fresh(now, r) {
			return nil
		}
		return &pilotResources{CPU: r.CPU, Available: r.Available, ToolCPU: r.ToolCPUPerSecond, WorkingSet: r.WorkingSet,
			Pressure: r.SustainedPressure || r.MemoryPressure || r.OOM, OOM: r.OOM}
	}
	m.Iran = resources(s.Iran)
	m.Peer = resources(s.Peer)
	return m
}

func recordPilot(dir string, now time.Time, s dashboardSnapshot) error {
	var p Pilot
	if err := readJSON(pilotPath(dir), &p); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if now.Before(p.Start) || !now.Before(p.End) {
		return nil
	}
	return appendRecord(dataPath(dir, p), safeMinute(now, s), maxPilotBytes)
}

func pilotMinutes(dir string, p Pilot, visit func(pilotMinute)) error {
	f, err := os.Open(dataPath(dir, p))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	dec := json.NewDecoder(io.LimitReader(f, maxPilotBytes))
	var previous time.Time
	for {
		var m pilotMinute
		err := dec.Decode(&m)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil
		}
		if err != nil {
			return err
		}
		if !m.At.After(previous) || m.At.Before(p.Start.Truncate(time.Minute)) || !m.At.Before(p.End) {
			continue
		}
		previous = m.At
		visit(m)
	}
}

func readPilotSummary(dir string, now time.Time) (pilotSummary, error) {
	var s pilotSummary
	if err := readJSON(pilotPath(dir), &s.Pilot); err != nil {
		return s, err
	}
	if s.Pilot.ID == "" {
		return s, nil
	}
	var cutover pilotCutover
	if readJSON(filepath.Join(dir, "pilot-cutover.json"), &cutover) == nil && cutover.ID == s.Pilot.ID {
		s.CutoverAt = ptr(cutover.At)
	}
	s.Active = now.Before(s.Pilot.End)
	end := minTime(now, s.Pilot.End)
	s.ExpectedMinutes = max(0, int(end.Sub(s.Pilot.Start)/time.Minute))
	err := pilotMinutes(dir, s.Pilot, func(m pilotMinute) {
		s.ObservedMinutes++
		if m.Primary != nil && m.Standby != nil {
			s.HealthMinutes++
			if !*m.Primary && !*m.Standby {
				s.UnreadyMinutes++
			}
		}
		if m.LastOutage != nil && !m.LastOutage.Before(s.Pilot.Start) {
			s.LastOutage = m.LastOutage
		}
		if m.Iran != nil {
			s.IranMinutes++
			if m.Iran.Pressure {
				s.IranPressureMinutes++
			}
		}
		if m.Peer != nil {
			s.PeerMinutes++
			if m.Peer.Pressure {
				s.PeerPressureMinutes++
			}
		}
	})
	return s, err
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func pilotAnalysis(s pilotSummary) string {
	switch {
	case s.IranPressureMinutes > 0 || s.PeerPressureMinutes > 0:
		return "Check background CPU and memory load on the affected host before running a capacity test."
	case s.UnreadyMinutes > 0:
		return "Compare the recorded outage windows with application and network incidents."
	case s.ExpectedMinutes == 0 || s.PeerMinutes < s.ExpectedMinutes*9/10 || s.IranMinutes < s.ExpectedMinutes*9/10:
		return "Check telemetry coverage before comparing the hosts."
	default:
		return "Review the passive evidence and run a guarded calibration if a capacity comparison is needed."
	}
}

func exportPilot(dir string, now time.Time) (string, error) {
	s, err := readPilotSummary(dir, now)
	if err != nil {
		return "", err
	}
	if s.Pilot.ID == "" {
		return "", errors.New("no pilot data to export")
	}
	metrics, err := readAvailability(dir, s.Pilot.Start, minTime(now, s.Pilot.End))
	if err != nil {
		return "", err
	}
	s.Availability = &metrics
	target := filepath.Join(dir, "pilot-report.tar.gz")
	file, err := os.CreateTemp(dir, ".report-")
	if err != nil {
		return "", err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	zip := gzip.NewWriter(file)
	archive := tar.NewWriter(zip)
	write := func(name string, content []byte) error {
		if err := archive.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(content))}); err != nil {
			return err
		}
		_, err := archive.Write(content)
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return "", err
	}
	if err := write("summary.json", data); err != nil {
		return "", err
	}
	md := fmt.Sprintf("# NEO Tunnel pilot\n\nPeriod started %s.\n\n- Observed %d of %d elapsed minutes\n- Both path states known in %d minutes\n- Both fixed paths unready in %d sampled minutes\n- Iran resource coverage %d minutes, pressure %d minutes\n- Foreign resource coverage %d minutes, pressure %d minutes\n- Customer success and wire overhead unknown\n\n%s\n",
		s.Pilot.Start.Format(time.RFC3339), s.ObservedMinutes, s.ExpectedMinutes, s.HealthMinutes, s.UnreadyMinutes, s.IranMinutes, s.IranPressureMinutes, s.PeerMinutes, s.PeerPressureMinutes, pilotAnalysis(s))
	if s.CutoverAt != nil {
		md += "\nCustomer cutover: " + s.CutoverAt.Format(time.RFC3339) + "\n"
	}
	md += fmt.Sprintf("\n- TCP: %d interruptions, %d recoveries, %d seconds down, %d seconds observed\n- UDP path: %d interruptions, %d recoveries, %d seconds down, %d seconds observed\n",
		metrics.TCP.Interruptions, metrics.TCP.Recoveries, metrics.TCP.DownSeconds, metrics.TCP.KnownSeconds,
		metrics.UDP.Interruptions, metrics.UDP.Recoveries, metrics.UDP.DownSeconds, metrics.UDP.KnownSeconds)
	if err := write("report.md", []byte(md)); err != nil {
		return "", err
	}
	// Re-encode an explicit schema even if the source files were extended later.
	var minutes []byte
	if err := pilotMinutes(dir, s.Pilot, func(m pilotMinute) {
		if b, e := json.Marshal(m); e == nil {
			minutes = append(minutes, b...)
			minutes = append(minutes, '\n')
		}
	}); err != nil {
		return "", err
	}
	if err := write("minutes.jsonl", minutes); err != nil {
		return "", err
	}
	if err := archive.Close(); err != nil {
		return "", err
	}
	if err := zip.Close(); err != nil {
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(file.Name(), target); err != nil {
		return "", err
	}
	return target, nil
}

func runPilot(dir, action string, useJSON bool) error {
	now := time.Now().UTC()
	unlock, err := lock(filepath.Join(dir, "pilot-lock"))
	if err != nil {
		return err
	}
	defer unlock()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if action == "start" {
		p, err := startPilot(dir, now)
		if err != nil {
			return err
		}
		_ = os.Remove(filepath.Join(dir, "pilot-report.tar.gz"))
		if useJSON {
			return json.NewEncoder(os.Stdout).Encode(p)
		}
		fmt.Printf("Pilot started. Ends %s UTC.\n", p.End.Format("2006-01-02 15:04"))
		return nil
	}
	if action == "stop" {
		var p Pilot
		if err := readJSON(pilotPath(dir), &p); err != nil && !os.IsNotExist(err) {
			return err
		}
		if !p.AutoDisabled || now.Before(p.End) {
			p.AutoDisabled = true
			if now.Before(p.End) {
				p.End = now
			}
			if err := atomicJSON(pilotPath(dir), p); err != nil {
				return err
			}
		}
	}
	if action == "mark-cutover" {
		var p Pilot
		if err := readJSON(pilotPath(dir), &p); err != nil {
			return err
		}
		if p.ID == "" || !now.Before(p.End) {
			return errors.New("an active pilot is required to mark cutover")
		}
		path := filepath.Join(dir, "pilot-cutover.json")
		var previous pilotCutover
		if readJSON(path, &previous) == nil && previous.ID == p.ID {
			fmt.Printf("Customer cutover already recorded at %s.\n", previous.At.Format(time.RFC3339))
			return nil
		}
		if err := atomicJSON(path, pilotCutover{ID: p.ID, At: now}); err != nil {
			return err
		}
		fmt.Printf("Customer cutover recorded at %s.\n", now.Format(time.RFC3339))
		return nil
	}
	if action == "export" {
		path, err := exportPilot(dir, now)
		if err != nil {
			return err
		}
		if useJSON {
			return json.NewEncoder(os.Stdout).Encode(map[string]string{"path": path})
		}
		fmt.Println(path)
		return nil
	}
	if action != "status" && action != "stop" {
		return errors.New("usage: neo-tunnel pilot start|status|stop|export|mark-cutover")
	}
	s, err := readPilotSummary(dir, now)
	if err != nil {
		return err
	}
	if useJSON {
		return json.NewEncoder(os.Stdout).Encode(s)
	}
	if s.Pilot.AutoDisabled {
		fmt.Println("Automatic pilot start is disabled.")
	}
	fmt.Printf("Pilot active: %t. Samples: %d/%d minutes. Iran: %d. Foreign: %d.\n", s.Active, s.ObservedMinutes, s.ExpectedMinutes, s.IranMinutes, s.PeerMinutes)
	return nil
}

func (c *controller) updateDashboard(ctx context.Context, prior dashboardSnapshot, health map[string]Health, at time.Time) (dashboardSnapshot, error) {
	s, err := c.state()
	if err != nil {
		return prior, err
	}
	next := dashboardSnapshot{At: at, Health: health, Preferred: s.Active.Profile, Iran: prior.Iran, Peer: prior.Peer, LastOutage: prior.LastOutage, LastRecovery: prior.LastRecovery}
	if health[next.Preferred].ready() {
		next.Selected = next.Preferred
	}
	for _, id := range []string{"primary", "standby"} {
		if health[id].ready() && id != next.Preferred && id != s.Parked {
			if next.Selected == "" {
				next.Selected = id
			} else {
				next.Standby = id
			}
		}
	}
	if next.Selected == "" && prior.Selected != "" && len(health) > 0 {
		next.LastOutage = ptr(at)
	}
	if next.Selected != "" && prior.Selected == "" && prior.LastOutage != nil {
		next.LastRecovery = ptr(at)
	}
	pair := c.resourcePair(ctx)
	next.Iran, next.Peer = pair[0], pair[1]
	minuteChanged := !at.Truncate(time.Minute).Equal(prior.At.Truncate(time.Minute))
	if err := updatePilot(c.config.StateDir, at, next, minuteChanged); err != nil {
		return prior, err
	}
	return next, atomicJSON(filepath.Join(c.config.StateDir, "dashboard.json"), next)
}

func updatePilot(dir string, at time.Time, snapshot dashboardSnapshot, minuteChanged bool) error {
	unlock, err := lock(filepath.Join(dir, "pilot-lock"))
	if err != nil {
		// A CLI operation may be updating or exporting the current pilot.
		return nil
	}
	defer unlock()
	// An existing state file also records completion and an explicit opt-out.
	if snapshot.Selected != "" {
		if _, err := os.Stat(pilotPath(dir)); os.IsNotExist(err) {
			if _, err := startPilot(dir, at); err != nil {
				return err
			}
			minuteChanged = true
		} else if err != nil {
			return err
		}
	}
	if !minuteChanged {
		return nil
	}
	if err := completePilot(dir, at); err != nil {
		return err
	}
	return recordPilot(dir, at, snapshot)
}

func completePilot(dir string, now time.Time) error {
	var p Pilot
	if err := readJSON(pilotPath(dir), &p); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if p.ID == "" || now.Before(p.End) {
		return nil
	}
	info, err := os.Stat(filepath.Join(dir, "pilot-report.tar.gz"))
	if err == nil && !p.End.After(info.ModTime()) {
		return nil
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	_, err = exportPilot(dir, now)
	return err
}
