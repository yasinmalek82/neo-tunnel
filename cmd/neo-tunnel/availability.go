package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"neo-tunnel/internal/canary"
)

const observationGap = 3 * cadence
const availabilityCap = 3 << 20

type availabilitySample struct {
	Session string    `json:"session,omitempty"`
	At      time.Time `json:"at"`
	Primary string    `json:"primary,omitempty"`
	Standby string    `json:"standby,omitempty"`
	TCP     string    `json:"tcp,omitempty"`
	UDP     string    `json:"udp,omitempty"`
}

type pathMetrics struct {
	Interruptions int `json:"interruptions"`
	Recoveries    int `json:"recoveries"`
	DownSeconds   int `json:"down_seconds"`
	KnownSeconds  int `json:"known_seconds"`
}

type availabilityMetrics struct {
	Primary pathMetrics `json:"primary"`
	Standby pathMetrics `json:"standby"`
	TCP     pathMetrics `json:"tcp"`
	UDP     pathMetrics `json:"udp"`
}

func healthValue(h Health) string {
	if h.Check == "" || h.Check == "INI" {
		return ""
	}
	if h.ready() {
		return "up"
	}
	if h.State == "DOWN" {
		return "down"
	}
	return ""
}

func sampleAvailability(at time.Time, h map[string]Health, udp string) availabilitySample {
	s := availabilitySample{At: at, Primary: healthValue(h["primary"]), Standby: healthValue(h["standby"]), UDP: udp}
	switch {
	case s.Primary == "up" || s.Standby == "up":
		s.TCP = "up"
	case s.Primary == "down" && s.Standby == "down":
		s.TCP = "down"
	}
	return s
}

func summarizeAvailability(samples []availabilitySample, from, to time.Time) availabilityMetrics {
	var m availabilityMetrics
	for i := 1; i < len(samples); i++ {
		prev, next := samples[i-1], samples[i]
		if next.Session != prev.Session || !next.At.After(prev.At) || next.At.Sub(prev.At) > observationGap {
			continue
		}
		left, right := prev.At, next.At
		if left.Before(from) {
			left = from
		}
		if right.After(to) {
			right = to
		}
		seconds := max(0, int(right.Sub(left).Seconds()))
		within := !next.At.Before(from) && next.At.Before(to)
		for _, v := range []struct {
			before, after string
			result        *pathMetrics
		}{
			{prev.Primary, next.Primary, &m.Primary}, {prev.Standby, next.Standby, &m.Standby},
			{prev.TCP, next.TCP, &m.TCP}, {prev.UDP, next.UDP, &m.UDP},
		} {
			// A missing observation on either side leaves this entire interval uncovered.
			if v.before == "" || v.after == "" {
				continue
			}
			v.result.KnownSeconds += seconds
			if v.before == "down" {
				v.result.DownSeconds += seconds
			}
			if within && v.before == "up" && v.after == "down" {
				v.result.Interruptions++
			}
			if within && v.before == "down" && v.after == "up" {
				v.result.Recoveries++
			}
		}
	}
	return m
}

func availabilityPath(dir string, at time.Time) string {
	return filepath.Join(dir, "availability-"+at.UTC().Format("20060102")+".jsonl")
}

func readAvailability(dir string, from, to time.Time) (availabilityMetrics, error) {
	var samples []availabilitySample
	start := from.UTC().Add(-observationGap).Truncate(24 * time.Hour)
	for day := start; !day.After(to); day = day.Add(24 * time.Hour) {
		file, err := os.Open(availabilityPath(dir, day))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return availabilityMetrics{}, err
		}
		decoder := json.NewDecoder(io.LimitReader(file, availabilityCap+4096))
		for {
			var sample availabilitySample
			if err := decoder.Decode(&sample); err != nil {
				if err == io.EOF || err == io.ErrUnexpectedEOF {
					break
				}
				_ = file.Close()
				return availabilityMetrics{}, err
			}
			if !sample.At.Before(from.Add(-observationGap)) && !sample.At.After(to.Add(observationGap)) {
				samples = append(samples, sample)
			}
		}
		_ = file.Close()
	}
	return summarizeAvailability(samples, from, to), nil
}

func recordAvailability(dir string, s availabilitySample) error {
	return appendRecord(availabilityPath(dir, s.At), s, availabilityCap)
}

func udpStatus(config Config) string {
	if !config.UDP {
		return ""
	}
	p, ok := config.Profiles["primary"]
	if !ok || !loopback(p.Canary) {
		return ""
	}
	if canary.CheckUDP(p.Canary, 700*time.Millisecond) == nil {
		return "up"
	}
	return "down"
}

func (c *controller) firstCheck(ctx context.Context) error {
	paths, err := c.health(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("Primary TCP/TLS readiness: %s\n", label(ptr(paths["primary"].ready())))
	fmt.Printf("Standby QUIC readiness: %s\n", label(ptr(paths["standby"].ready())))
	pair := c.resourcePair(ctx)
	fmt.Printf("Iran / Sweden telemetry: %s / %s\n", label(ptr(pair[0] != nil)), label(ptr(pair[1] != nil)))
	udp := udpStatus(c.config)
	if c.config.UDP {
		fmt.Printf("Primary UDP round trip: %s\n", label(ptr(udp == "up")))
	} else {
		fmt.Println("UDP customer ingress: off")
	}
	fmt.Println("Verify TCP and UDP application responses on the temporary customer port before cutover.")
	if !paths["primary"].ready() || !paths["standby"].ready() || pair[0] == nil || pair[1] == nil || c.config.UDP && udp != "up" {
		return fmt.Errorf("one or more first-connection checks are pending or failed")
	}
	return nil
}
