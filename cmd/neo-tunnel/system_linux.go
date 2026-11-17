//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type sampler struct {
	previousProfiles map[string]GroupReading
	config           AgentConfig
	previous         [8]uint64
	previousOOM      uint64
	previousSeconds  float64
	previousAt       time.Time
	started          bool
}

func fields(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	return strings.Fields(string(data)), err
}

func kernelValues(path string) (map[string]uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	result := map[string]uint64{}
	for _, line := range strings.Split(string(data), "\n") {
		items := strings.Fields(line)
		if len(items) >= 2 {
			value, err := strconv.ParseUint(items[1], 10, 64)
			if err == nil {
				result[strings.TrimSuffix(items[0], ":")] = value
			}
		}
	}
	return result, nil
}

func single(path string) (uint64, error) {
	values, err := fields(path)
	if err != nil {
		return 0, err
	}
	if len(values) != 1 {
		return 0, fmt.Errorf("invalid value in %s", path)
	}
	return strconv.ParseUint(values[0], 10, 64)
}

func (s *sampler) sample() (*Reading, error) {
	stats, err := fields("/proc/stat")
	if err != nil {
		return nil, err
	}
	if len(stats) < 9 || stats[0] != "cpu" {
		return nil, errors.New("aggregate CPU counters unavailable")
	}
	var ticks [8]uint64
	for i := range ticks {
		ticks[i], err = strconv.ParseUint(stats[i+1], 10, 64)
		if err != nil {
			return nil, err
		}
	}
	hostStart := s.previous
	s.previous = ticks
	if hostStart == [8]uint64{} {
		return nil, errors.New("waiting for second CPU sample")
	}
	var total, busy, steal uint64
	for i, n := range ticks {
		if n < hostStart[i] {
			continue
		}
		delta := n - hostStart[i]
		total += delta
		if i != 3 && i != 4 && i != 7 {
			busy += delta
		}
		if i == 7 {
			steal = delta
		}
	}
	if total == 0 {
		return nil, errors.New("CPU counters have not advanced")
	}
	mem, err := kernelValues("/proc/meminfo")
	if err != nil {
		return nil, err
	}
	if mem["MemTotal"] == 0 {
		return nil, errors.New("MemTotal unavailable")
	}
	group := s.config.ToolCgroup
	cpu, err := kernelValues(filepath.Join(group, "cpu.stat"))
	if err != nil {
		return nil, err
	}
	memory, err := single(filepath.Join(group, "memory.current"))
	if err != nil {
		return nil, err
	}
	memoryStat, err := kernelValues(filepath.Join(group, "memory.stat"))
	if err != nil {
		return nil, err
	}
	events, err := kernelValues(filepath.Join(group, "memory.events"))
	if err != nil {
		return nil, err
	}
	var oomCount = events["oom"]
	vm, err := kernelValues("/proc/vmstat")
	if err != nil {
		return nil, err
	}
	oomCount += vm["oom_kill"]
	pressureFields, err := fields("/proc/pressure/memory")
	if err != nil {
		return nil, err
	}
	var severe bool
	for i, v := range pressureFields {
		if v == "full" && i+1 < len(pressureFields) {
			avg, err := strconv.ParseFloat(strings.TrimPrefix(pressureFields[i+1], "avg10="), 64)
			if err != nil {
				return nil, err
			}
			severe = avg >= 5
		}
	}
	effective := float64(runtime.NumCPU())
	for parent := group; parent != "/"; parent = filepath.Dir(parent) {
		quota, err := fields(filepath.Join(parent, "cpu.max"))
		if err == nil && len(quota) == 2 && quota[0] != "max" {
			q, qErr := strconv.ParseFloat(quota[0], 64)
			period, pErr := strconv.ParseFloat(quota[1], 64)
			if qErr == nil && pErr == nil && period > 0 {
				effective = min(effective, q/period)
			}
		}
	}
	files, err := fields("/proc/sys/fs/file-nr")
	if err != nil {
		return nil, err
	}
	if len(files) != 3 {
		return nil, errors.New("invalid file-nr")
	}
	openFiles, err := strconv.ParseUint(files[0], 10, 64)
	if err != nil {
		return nil, err
	}
	limit, err := strconv.ParseUint(files[2], 10, 64)
	if err != nil {
		return nil, err
	}
	var socketCount uint64
	socketFields, err := fields("/proc/net/sockstat")
	if err != nil {
		return nil, err
	}
	if len(socketFields) >= 3 && socketFields[0] == "sockets:" {
		socketCount, err = strconv.ParseUint(socketFields[2], 10, 64)
		if err != nil {
			return nil, err
		}
	}
	r := &Reading{At: time.Now().UTC(), CPU: float64(busy) / float64(total),
		EffectiveCPU: effective, Available: float64(mem["MemAvailable"]) / float64(mem["MemTotal"]),
		Steal: float64(steal) / float64(total), SwapBytes: (mem["SwapTotal"] - min(mem["SwapTotal"], mem["SwapFree"])) * 1024,
		OpenFiles: openFiles, FileLimit: limit, Sockets: socketCount, ToolCPU: float64(cpu["usage_usec"]) / 1e6,
		WorkingSet: memory - min(memory, memoryStat["inactive_file"]), OOM: s.started && oomCount > s.previousOOM, MemoryPressure: severe}
	if s.started && r.ToolCPU >= s.previousSeconds && r.EffectiveCPU > 0 {
		rate := (r.ToolCPU - s.previousSeconds) / r.At.Sub(s.previousAt).Seconds()
		r.ToolCPUPerSecond = ptr(rate)
		r.ToolCPUFraction = rate / r.EffectiveCPU
	}
	if len(s.config.ProfileCgroups) > 0 {
		r.Profiles = make(map[string]GroupReading)
		for id, dir := range s.config.ProfileCgroups {
			cpu, err := kernelValues(filepath.Join(dir, "cpu.stat"))
			if err != nil {
				continue
			}
			current, err := single(filepath.Join(dir, "memory.current"))
			if err != nil {
				continue
			}
			cache, err := kernelValues(filepath.Join(dir, "memory.stat"))
			if err != nil {
				continue
			}
			group := GroupReading{CPUSeconds: float64(cpu["usage_usec"]) / 1e6, WorkingSet: current - min(current, cache["inactive_file"])}
			if prev, ok := s.previousProfiles[id]; ok && group.CPUSeconds >= prev.CPUSeconds {
				group.CPUPerSecond = ptr((group.CPUSeconds - prev.CPUSeconds) / r.At.Sub(s.previousAt).Seconds())
			}
			r.Profiles[id] = group
		}
		s.previousProfiles = r.Profiles
	}
	s.previousAt = r.At
	s.previousSeconds = r.ToolCPU
	s.previousOOM = oomCount
	s.started = true
	if name := s.config.WireInterface; name != "" {
		base := filepath.Join("/sys/class/net", name, "statistics")
		rx, rxErr := single(filepath.Join(base, "rx_bytes"))
		tx, txErr := single(filepath.Join(base, "tx_bytes"))
		if rxErr == nil && txErr == nil {
			r.WireBytes = ptr(rx + tx)
		}
	}
	return r, nil
}
