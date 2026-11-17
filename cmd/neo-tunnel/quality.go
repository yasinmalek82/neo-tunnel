package main

import (
	"fmt"
	"math"
	"time"
)

const (
	maxUseful = 64 << 20
	maxRun    = 5 * time.Minute
	maxAge    = 30 * time.Second
)

type GroupReading struct {
	CPUSeconds   float64  `json:"cpu_seconds"`
	CPUPerSecond *float64 `json:"cpu_seconds_per_second"`
	WorkingSet   uint64   `json:"working_set_bytes"`
}

type Reading struct {
	Profiles          map[string]GroupReading `json:"profile_resources,omitempty"`
	ToolCPUPerSecond  *float64                `json:"tool_cpu_seconds_per_second"`
	ToolCPUFraction   float64                 `json:"tool_cpu_fraction_of_effective_capacity"`
	At                time.Time               `json:"at"`
	CPU               float64                 `json:"host_cpu_fraction"`
	Available         float64                 `json:"host_memory_available_fraction"`
	EffectiveCPU      float64                 `json:"effective_cpu"`
	Steal             float64                 `json:"cpu_steal_fraction"`
	SwapBytes         uint64                  `json:"swap_used_bytes"`
	OpenFiles         uint64                  `json:"open_files"`
	FileLimit         uint64                  `json:"file_limit"`
	Sockets           uint64                  `json:"sockets"`
	ToolCPU           float64                 `json:"tool_cpu_seconds"`
	WorkingSet        uint64                  `json:"tool_working_set_bytes"`
	WireBytes         *uint64                 `json:"dedicated_interface_bytes"`
	OOM               bool                    `json:"oom_observed"`
	MemoryPressure    bool                    `json:"memory_pressure"`
	SustainedPressure bool                    `json:"sustained_pressure"`
	BaselineReady     bool                    `json:"baseline_ready"`
	BaselineCPU       float64                 `json:"baseline_cpu_mean"`
	BaselineAvailable float64                 `json:"baseline_available_mean"`
}

type Cost struct {
	CPUSeconds     float64  `json:"cpu_seconds"`
	CPUPerGiB      *float64 `json:"cpu_seconds_per_gib"`
	PeakWorkingSet uint64   `json:"peak_working_set_bytes"`
	ExtraBytes     *uint64  `json:"extra_bytes"`
}

type Result struct {
	LoadP95MS       *float64 `json:"p95_under_load_ms"`
	LoadSuccess     int      `json:"loaded_successes"`
	AttemptedUseful int64    `json:"max_useful_bytes_attempted"`
	Profile         string   `json:"profile"`
	Samples         int      `json:"samples"`
	Success         int      `json:"success"`
	Timeouts        int      `json:"timeouts"`
	Errors          int      `json:"errors"`
	Outages         int      `json:"outages"`
	OutageSeconds   float64  `json:"outage_seconds"`
	P95MS           float64  `json:"p95_ms"`
	ConnectP95MS    float64  `json:"connect_p95_ms"`
	FirstByteP95MS  float64  `json:"first_byte_p95_ms"`
	Useful          int64    `json:"useful_bytes"`
	DurationSeconds float64  `json:"duration_seconds"`
	Iran            Cost     `json:"iran"`
	Peer            Cost     `json:"peer"`
	LimitingHost    string   `json:"limiting_host"`
	TotalCPUPerGiB  *float64 `json:"total_cpu_seconds_per_gib"`
	Uncertain       bool     `json:"uncertain"`
	Reason          string   `json:"reason,omitempty"`
}

func ptr[T any](v T) *T { return &v }

func fresh(now time.Time, r *Reading) bool {
	return r != nil && now.Sub(r.At) <= maxAge && r.At.Sub(now) <= 5*time.Second
}

func pressure(r *Reading) bool {
	return r.CPU >= .80 || r.ToolCPUFraction >= .80 || r.Available <= .20
}

func guard(now time.Time, iran, peer *Reading, starting bool) error {
	for _, host := range []struct {
		name string
		r    *Reading
	}{{"iran", iran}, {"peer", peer}} {
		r := host.r
		switch {
		case !fresh(now, r):
			return fmt.Errorf("%s: resource data unavailable or stale", host.name)
		case r.OOM || r.MemoryPressure || r.SustainedPressure:
			return fmt.Errorf("%s: resource pressure", host.name)
		case starting && (!r.BaselineReady || pressure(r) || r.BaselineCPU >= .80 || (r.BaselineAvailable > 0 && r.BaselineAvailable <= .20)):
			return fmt.Errorf("%s: insufficient headroom or baseline", host.name)
		}
	}
	return nil
}

func admit(now time.Time, iran, peer *Reading) error { return guard(now, iran, peer, true) }

func cost(before, after Reading, useful int64) Cost {
	out := Cost{CPUSeconds: math.Max(0, after.ToolCPU-before.ToolCPU), PeakWorkingSet: max(before.WorkingSet, after.WorkingSet)}
	if useful <= 0 {
		return out
	}
	if after.ToolCPU >= before.ToolCPU {
		out.CPUPerGiB = ptr(out.CPUSeconds * (1 << 30) / float64(useful))
	}
	if before.WireBytes != nil && after.WireBytes != nil && *after.WireBytes >= *before.WireBytes && *after.WireBytes-*before.WireBytes >= uint64(useful) {
		out.ExtraBytes = ptr(*after.WireBytes - *before.WireBytes - uint64(useful))
	}
	return out
}

func prefer(base, candidate Result) bool {
	if base.Uncertain || candidate.Uncertain || base.Samples < 60 || candidate.Samples < 60 ||
		candidate.Success == 0 || base.Success == 0 || candidate.Outages > base.Outages || candidate.OutageSeconds > base.OutageSeconds {
		return false
	}
	baseP95, candidateP95 := base.P95MS, candidate.P95MS
	if base.LoadP95MS != nil && candidate.LoadP95MS != nil {
		baseP95, candidateP95 = *base.LoadP95MS, *candidate.LoadP95MS
	}
	delta := float64(candidate.Success)/float64(candidate.Samples) - float64(base.Success)/float64(base.Samples)
	if delta < -.01 || candidateP95 > baseP95*1.10 {
		return false
	}
	if delta > .01 || candidateP95 < baseP95*.90 {
		return true
	}
	if base.TotalCPUPerGiB == nil || candidate.TotalCPUPerGiB == nil {
		return false
	}
	if candidate.Iran.PeakWorkingSet > base.Iran.PeakWorkingSet || candidate.Peer.PeakWorkingSet > base.Peer.PeakWorkingSet {
		return false
	}
	for _, pair := range [][2]*uint64{{base.Iran.ExtraBytes, candidate.Iran.ExtraBytes}, {base.Peer.ExtraBytes, candidate.Peer.ExtraBytes}} {
		if pair[0] != nil && pair[1] != nil && *pair[1] > *pair[0] {
			return false
		}
	}
	return *candidate.TotalCPUPerGiB < *base.TotalCPUPerGiB ||
		(*candidate.TotalCPUPerGiB == *base.TotalCPUPerGiB &&
			(candidate.Iran.PeakWorkingSet < base.Iran.PeakWorkingSet || candidate.Peer.PeakWorkingSet < base.Peer.PeakWorkingSet))
}
