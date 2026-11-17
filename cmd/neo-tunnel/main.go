package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Status struct {
	Standby              string            `json:"standby,omitempty"`
	StandbyBasis         string            `json:"standby_basis"`
	ConcurrentDownEvents int               `json:"concurrent_down_events_7d"`
	State                State             `json:"state"`
	Health               map[string]Health `json:"path_health"`
	HealthError          string            `json:"path_health_error,omitempty"`
	Applications         map[string]*bool  `json:"application_ready"`
	Iran                 *Reading          `json:"iran"`
	Peer                 *Reading          `json:"peer"`
	ISPExperience        *bool             `json:"isp_experience"`
}

func (c *controller) status(ctx context.Context, s State) Status {
	result := Status{State: s, Applications: map[string]*bool{}}
	h, err := c.health(ctx)
	result.Health = h
	for id, p := range c.config.Profiles {
		if id != s.Active.Profile && !p.Staged && h[id].ready() {
			result.Standby = id
			break
		}
	}
	a, b := c.config.Profiles[s.Active.Profile], c.config.Profiles[result.Standby]
	if result.Standby != "" {
		if a.Provider != "" && b.Provider != "" && a.Provider != b.Provider {
			result.StandbyBasis = "initial_provider_diversity"
		}
		if result.StandbyBasis == "" && a.Carrier != b.Carrier {
			result.StandbyBasis = "initial_carrier_diversity"
		}
		if result.StandbyBasis == "" {
			result.StandbyBasis = "configured_pair"
		}
	}
	result.ConcurrentDownEvents = c.concurrentDownEvents()
	if err != nil {
		result.HealthError = err.Error()
	}
	for id, p := range c.config.Profiles {
		result.Applications[id] = nil
		if (p.AppURL != "" || p.AppTCP != "") && h[id].ready() {
			result.Applications[id] = ptr(c.service(ctx, id) == nil)
		}
	}
	pair := c.resourcePair(ctx)
	result.Iran, result.Peer = pair[0], pair[1]
	return result
}

func label(v *bool) string {
	if v == nil {
		return "Unknown"
	}
	if *v {
		return "Ready"
	}
	return "Failed"
}

func printStatus(s Status) {
	fmt.Printf("Preferred path: %s | Version: %s\n", s.State.Active.Profile, s.State.Active.ID)
	if s.State.Pending != nil {
		fmt.Printf("Pending operation: %s | Stage: %s\n", s.State.Pending.Kind, s.State.Pending.Stage)
	}
	keys := make([]string, 0, len(s.Applications))
	for id := range s.Applications {
		keys = append(keys, id)
	}
	sort.Strings(keys)
	for _, id := range keys {
		health := "Unknown"
		if v, ok := s.Health[id]; ok {
			health = label(ptr(v.ready()))
		}
		fmt.Printf("Path %s | Carrier: %s | Destination: %s\n", id, health, label(s.Applications[id]))
	}
	for _, host := range []struct {
		name string
		r    *Reading
	}{{"Iran", s.Iran}, {"Foreign", s.Peer}} {
		if host.r == nil {
			fmt.Printf("%s resources: unknown\n", host.name)
			continue
		}
		r := host.r
		fmt.Printf("%s resources | Host CPU %.1f%% | Available memory %.1f%% | Tool memory %.1f MiB\n", host.name, r.CPU*100, r.Available*100, float64(r.WorkingSet)/(1<<20))
	}
	if s.Standby != "" {
		fmt.Printf("Ready standby: %s | Concurrent outage events: %d\n", s.Standby, s.ConcurrentDownEvents)
	}
	fmt.Println("Customer network experience: unknown")
}

func printCost(name string, c Cost) {
	cpu, wire := "Unknown", "Unknown"
	if c.CPUPerGiB != nil {
		cpu = fmt.Sprintf("%.2f CPU-s/GiB", *c.CPUPerGiB)
	}
	if c.ExtraBytes != nil {
		wire = fmt.Sprintf("%d bytes", *c.ExtraBytes)
	}
	fmt.Printf("  %s | %s | Peak RAM %.1f MiB | Wire overhead %s\n", name, cpu, float64(c.PeakWorkingSet)/(1<<20), wire)
}

func printProposal(p Proposal) {
	fmt.Printf("Proposal: %s | Base version: %s | Path: %s\n", p.ID, p.Base, p.Target)
	if p.Eligible {
		fmt.Println("Evidence supports this proposal.")
	} else {
		fmt.Println("Insufficient evidence to apply this proposal.")
	}
	for _, r := range []Result{p.Baseline, p.Candidate} {
		fmt.Printf("Path %s | Successful %d/%d | p95 %.1f ms | Outages %d (%.1fs) | Timeouts %d | Errors %d\n",
			r.Profile, r.Success, r.Samples, r.P95MS, r.Outages, r.OutageSeconds, r.Timeouts, r.Errors)
		if r.LoadP95MS != nil {
			fmt.Printf("  Loaded p95 %.1f ms | %d successful samples\n", *r.LoadP95MS, r.LoadSuccess)
		}
		printCost("Iran", r.Iran)
		printCost("Foreign", r.Peer)
		if r.TotalCPUPerGiB != nil {
			fmt.Printf("  Total CPU %.2f CPU-s/GiB | Limiting host: %s\n", *r.TotalCPUPerGiB, r.LimitingHost)
		}
		if r.Reason != "" {
			fmt.Printf("  Observed reason: %s\n", asciiConsole(r.Reason))
		}
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "neo-tunnel [status|first-check|telegram|pilot|dashboard|setup-iran|issue-link|join|ingress|enable-udp|calibrate [profile]|apply <proposal-id>|rollback|watch|agent] [--config FILE] [--json]")
}

func run(ctx context.Context, args []string) error {
	configPath := ""
	useJSON := false
	var position []string
	for len(args) > 0 {
		switch args[0] {
		case "-h", "--help", "help":
			usage()
			return nil
		case "--json":
			useJSON = true
		case "--config":
			args = args[1:]
			if len(args) == 0 {
				return errors.New("missing config filename")
			}
			configPath = args[0]
		default:
			if strings.HasPrefix(args[0], "-") {
				return fmt.Errorf("unknown option %s", args[0])
			}
			position = append(position, args[0])
		}
		args = args[1:]
	}
	if len(position) == 0 {
		return terminalMenu(ctx)
	}
	command := position[0]
	extra := position[1:]
	if command == "pilot" || command == "dashboard" {
		if configPath == "" && runtime.GOOS == "linux" && os.Geteuid() == 0 {
			return runAsOperator(ctx, command, extra, useJSON)
		}
		if configPath == "" {
			configPath = "/etc/neo-tunnel/controller.json"
		}
		var config Config
		if err := readJSON(configPath, &config); err != nil {
			return err
		}
		if !filepath.IsAbs(config.StateDir) {
			return errors.New("invalid state directory")
		}
		if command == "dashboard" && len(extra) == 0 {
			return serveDashboard(ctx, config.StateDir)
		}
		if command == "pilot" && len(extra) == 1 {
			return runPilot(config.StateDir, extra[0], useJSON)
		}
		return errors.New("invalid pilot or dashboard arguments")
	}
	if command == "telegram" && len(extra) == 1 {
		return setupTelegram(ctx, bufio.NewReader(os.Stdin), extra[0])
	}
	if command == "telegram-worker" && len(extra) == 0 {
		if configPath == "" {
			configPath = configHome + "/agent.json"
		}
		var cfg AgentConfig
		if err := readJSON(configPath, &cfg); err != nil {
			return err
		}
		return botLoop(ctx, cfg.StateDir, telegramClient{base: telegramAPI, client: &http.Client{Timeout: 85 * time.Second, CheckRedirect: noRedirect}})
	}
	if command == "udp-edge" && len(extra) == 0 {
		if configPath == "" {
			configPath = configHome + "/udp.json"
		}
		var settings udpSettings
		if err := readJSON(configPath, &settings); err != nil {
			return err
		}
		return serveUDP(ctx, settings)
	}
	switch command {
	case "setup-iran", "join", "issue-link", "enroll-serve", "ingress", "enable-udp":
		return runSetup(ctx, command, extra)
	}
	if (command == "apply" && len(extra) != 1) || (command == "calibrate" && len(extra) > 1) ||
		(command != "apply" && command != "calibrate" && len(extra) != 0) {
		usage()
		return flag.ErrHelp
	}
	if configPath == "" && runtime.GOOS == "linux" && os.Geteuid() == 0 && command != "agent" {
		return runAsOperator(ctx, command, extra, useJSON)
	}
	if configPath == "" {
		name := "controller.json"
		if command == "agent" {
			name = "agent.json"
		}
		configPath = filepath.Join("/etc/neo-tunnel", name)
	}
	if command == "agent" {
		var config AgentConfig
		if err := readJSON(configPath, &config); err != nil {
			return err
		}
		return serveAgent(ctx, config)
	}
	switch command {
	case "status", "first-check", "report-worker", "calibrate", "apply", "rollback", "watch":
	default:
		usage()
		return flag.ErrHelp
	}
	var config Config
	raw, err := loadConfig(configPath)
	if err != nil {
		return err
	}
	if err := decodeJSON(bytes.NewReader(raw), &config); err != nil {
		return err
	}
	if err := config.validate(); err != nil {
		return err
	}
	api, err := agentClient(config.Identity)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(raw)
	c := controller{config: config, digest: hex.EncodeToString(hash[:]), api: api,
		probe: &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, CheckRedirect: noRedirect}}
	out := func(v any) error { return json.NewEncoder(os.Stdout).Encode(v) }
	switch command {
	case "watch":
		return c.watch(ctx)
	case "first-check":
		return c.firstCheck(ctx)
	case "report-worker":
		return c.reportLoop(ctx)
	}
	if command != "status" {
		unlock, err := lock(config.StateDir)
		if err != nil {
			return err
		}
		defer unlock()
	}
	s, err := c.state()
	if err != nil {
		return err
	}
	if command != "status" {
		finish, cancel := context.WithTimeout(ctx, 20*time.Second)
		err = c.recover(finish, &s)
		cancel()
		if err != nil {
			return err
		}
		if s.Pending != nil {
			return errors.New("previous operation is still draining established sessions")
		}
	}
	switch command {
	case "status":
		s := c.status(ctx, s)
		if useJSON {
			return out(s)
		}
		printStatus(s)
	case "calibrate":
		target := ""
		if len(extra) == 1 {
			target = extra[0]
		}
		p, err := c.calibration(ctx, &s, target)
		if p.ID != "" {
			if useJSON {
				err = errors.Join(err, out(p))
			} else {
				printProposal(p)
			}
		}
		return err
	case "apply":
		if err := c.apply(ctx, &s, extra[0]); err != nil {
			return err
		}
	case "rollback":
		if err := c.rollback(ctx, &s); err != nil {
			return err
		}
	}
	if command == "apply" || command == "rollback" {
		if useJSON {
			return out(s)
		}
		fmt.Printf("Active version: %s | Path: %s\n", s.Active.ID, s.Active.Profile)
	}
	return nil
}

func (c *controller) watch(ctx context.Context) error {
	var last map[string]bool
	var snapshot dashboardSnapshot
	var udp string
	var sampledUDP time.Time
	var observationDay time.Time
	session := newID()[:8]
	_ = readJSON(filepath.Join(c.config.StateDir, "dashboard.json"), &snapshot)
	for ctx.Err() == nil {
		health, err := c.health(ctx)
		if err == nil {
			err = c.recordPathChanges(health, &last)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, asciiConsole(err.Error()))
		}
		now := time.Now().UTC()

		if now.Sub(snapshot.At) >= 15*time.Second || health[snapshot.Selected].ready() != (snapshot.Selected != "") {
			if next, err := c.updateDashboard(ctx, snapshot, health, now); err == nil {
				snapshot = next
			} else {
				fmt.Fprintln(os.Stderr, asciiConsole(err.Error()))
			}
		}
		var pilot Pilot
		if readJSON(pilotPath(c.config.StateDir), &pilot) == nil && pilot.ID != "" && !now.Before(pilot.Start) && now.Before(pilot.End) {
			if c.config.UDP && now.Sub(sampledUDP) >= 20*time.Second {
				udp = udpStatus(c.config)
				sampledUDP = now
			}
			day := now.Truncate(24 * time.Hour)
			if day != observationDay {
				prune(c.config.StateDir, "availability", day.Add(-7*24*time.Hour), "20060102")
				observationDay = day
			}
			sample := sampleAvailability(now, health, udp)
			sample.Session = session
			if err := recordAvailability(c.config.StateDir, sample); err != nil {
				fmt.Fprintln(os.Stderr, asciiConsole(err.Error()))
			}
		}

		if unlock, err := lock(c.config.StateDir); err == nil {
			func() {
				defer unlock()
				s, err := c.state()
				if err == nil {
					err = c.maintain(ctx, &s)
				}
				if err != nil {
					fmt.Fprintln(os.Stderr, asciiConsole(err.Error()))
				}
			}()
		}
		if wait(ctx, cadence) != nil {
			break
		}
	}
	return nil
}

func asciiConsole(value string) string {
	var b strings.Builder
	for _, r := range value {
		switch {
		case r == '\n' || r == '\t' || (r >= 32 && r < 127):
			b.WriteRune(r)
		default:
			quoted := strconv.QuoteToASCII(string(r))
			b.WriteString(quoted[1 : len(quoted)-1])
		}
	}
	return b.String()
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(os.Stderr, asciiConsole(err.Error()))
		}
		os.Exit(1)
	}
}
