package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	_ "time/tzdata"
)

const reportMax = 33 << 20 // The pilot archive is bounded below Telegram's upload limit.
const reportSnapshotPath = "/v1/reports/state"

type reportSnapshot struct {
	At     time.Time `json:"at"`
	Status string    `json:"status"`
	Today  string    `json:"today"`
}

func lastReportCutoff(now time.Time, loc *time.Location) time.Time {
	local := now.In(loc)
	cut := time.Date(local.Year(), local.Month(), local.Day(), 21, 0, 0, 0, loc)
	if now.Before(cut) {
		cut = cut.AddDate(0, 0, -1)
	}
	return cut
}

func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

type resourceWindow struct {
	Iran, Peer, IranPressure, PeerPressure int
}

func formatWindow(dir string, p Pilot, start, end time.Time, loc *time.Location) (string, error) {
	metrics, err := readAvailability(dir, start, end)
	if err != nil {
		return "", err
	}
	var usage resourceWindow
	err = pilotMinutes(dir, p, func(m pilotMinute) {
		if m.At.Before(start.Truncate(time.Minute)) || !m.At.Before(end) {
			return
		}
		if m.Iran != nil {
			usage.Iran++
			if m.Iran.Pressure {
				usage.IranPressure++
			}
		}
		if m.Peer != nil {
			usage.Peer++
			if m.Peer.Pressure {
				usage.PeerPressure++
			}
		}
	})
	if err != nil {
		return "", err
	}
	elapsed := max(0, int(end.Sub(start).Seconds()))
	var b strings.Builder
	fmt.Fprintf(&b, "پایش سوئد | %s تا %s (تهران)\n", start.In(loc).Format("01-02 15:04"), end.In(loc).Format("01-02 15:04"))
	for _, v := range []struct {
		name string
		m    pathMetrics
	}{
		{"مسیر اصلی TCP/TLS", metrics.Primary}, {"پشتیبان QUIC", metrics.Standby},
		{"آمادگی ورودی TCP", metrics.TCP}, {"پایش مسیر UDP", metrics.UDP},
	} {
		fmt.Fprintf(&b, "%s: %d قطع، %d بازیابی، %s قطعی، %s نامعلوم\n",
			v.name, v.m.Interruptions, v.m.Recoveries, reportDuration(v.m.DownSeconds), reportDuration(max(0, elapsed-v.m.KnownSeconds)))
	}
	fmt.Fprintf(&b, "پوشش منابع و فشار | ایران %d / %d دقیقه، سوئد %d / %d دقیقه\nقطع‌ها بر اساس نمونه‌های سلامت مسیر محاسبه شده‌اند.", usage.Iran, usage.IranPressure, usage.Peer, usage.PeerPressure)
	return b.String(), nil
}

func reportDuration(seconds int) string {
	return fmt.Sprintf("%d:%02d:%02d", seconds/3600, (seconds/60)%60, seconds%60)
}

func reportState(dir string, now time.Time, p Pilot, loc *time.Location) (reportSnapshot, error) {
	s := reportSnapshot{At: now, Status: "وضعیت مسیر نامعلوم است.", Today: "دورهٔ پایلوت در دسترس نیست."}
	var dashboard dashboardSnapshot
	if readJSON(filepath.Join(dir, "dashboard.json"), &dashboard) == nil {
		s.At = dashboard.At
		if !dashboard.At.IsZero() && now.Sub(dashboard.At) < 90*time.Second {
			routes := map[string]string{"primary": "TCP/TLS", "standby": "QUIC", "naive": "NaiveProxy"}
			if routes[dashboard.Selected] != "" {
				s.Status = "مسیر آماده: " + routes[dashboard.Selected]
			} else if len(dashboard.Health) > 0 {
				s.Status = "مسیر آماده پیدا نشد."
			}
		}
	}
	if p.ID != "" {
		end := minTime(now, p.End)
		from := later(p.Start, lastReportCutoff(now, loc))
		if !from.Before(end) {
			from = later(p.Start, lastReportCutoff(end, loc))
		}
		if from.Before(end) {
			window, err := formatWindow(dir, p, from, end, loc)
			if err != nil {
				return s, err
			}
			s.Today = window
		}
	}
	return s, nil
}

func (c *controller) relayReport(ctx context.Context, path string, body func() (io.ReadCloser, error), length int64) int {
	client := *c.api
	client.Timeout = 70 * time.Second
	for _, host := range []string{c.config.Peer, c.config.PeerFallback} {
		if host == "" {
			continue
		}
		stream, err := body()
		if err != nil {
			return 0
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, strings.TrimRight(host, "/")+path, stream)
		if err != nil {
			_ = stream.Close()
			return 0
		}
		req.ContentLength = length
		reply, err := client.Do(req)
		if err != nil {
			_ = stream.Close()
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(reply.Body, 4096))
		_ = reply.Body.Close()
		if reply.StatusCode == http.StatusNoContent || reply.StatusCode == http.StatusNotFound {
			return reply.StatusCode
		}
	}
	return 0
}

func (c *controller) relayBytes(ctx context.Context, path string, data []byte) int {
	return c.relayReport(ctx, path, func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil }, int64(len(data)))
}

func (c *controller) reportLoop(ctx context.Context) error {
	loc, err := time.LoadLocation("Asia/Tehran")
	if err != nil {
		return err
	}
	for ctx.Err() == nil {
		if err := c.reportOnce(ctx, time.Now().UTC(), loc); err != nil {
			fmt.Fprintln(os.Stderr, asciiConsole(err.Error()))
		}
		if wait(ctx, time.Minute) != nil {
			break
		}
	}
	return nil
}

func (c *controller) reportOnce(ctx context.Context, now time.Time, loc *time.Location) error {
	dir := c.config.StateDir
	var p Pilot
	if err := readJSON(pilotPath(dir), &p); err != nil && !os.IsNotExist(err) {
		return err
	}
	if p.ID != "" {
		if !reportPilotID.MatchString(p.ID) {
			return errors.New("invalid pilot state")
		}
		if err := queuePilotReports(dir, now, p, loc); err != nil {
			return err
		}
	}
	// Keep queued daily and final reports on Iran until the foreign agent
	// confirms persistence, regardless of Telegram connectivity.
	if c.relayBytes(ctx, "/v1/reports/probe", nil) != http.StatusNoContent {
		return nil
	}
	s, err := reportState(dir, now, p, loc)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if c.relayBytes(ctx, reportSnapshotPath, raw) != http.StatusNoContent {
		return nil
	}
	return c.flushReports(ctx)
}

func pendingReport(dir, id string) (bool, error) {
	for _, prefix := range []string{"sent-", "job-"} {
		if _, err := os.Stat(filepath.Join(dir, prefix+id)); err == nil {
			return false, nil
		} else if !os.IsNotExist(err) {
			return false, err
		}
	}
	return true, nil
}

func queuePilotReports(dir string, now time.Time, p Pilot, loc *time.Location) error {
	first := lastReportCutoff(p.Start, loc).AddDate(0, 0, 1)
	for cutoff := first; !cutoff.After(minTime(now, p.End)); cutoff = cutoff.AddDate(0, 0, 1) {
		id := p.ID + "-daily-" + cutoff.Format("20060102")
		needed, err := pendingReport(dir, id)
		if err != nil {
			return err
		}
		if !needed {
			continue
		}
		window, err := formatWindow(dir, p, later(p.Start, cutoff.AddDate(0, 0, -1)), cutoff, loc)
		if err != nil {
			return err
		}
		if err := saveJob(dir, id, strings.NewReader(window)); err != nil {
			return err
		}
	}
	if now.Before(p.End) {
		return nil
	}
	id := p.ID + "-final"
	needed, err := pendingReport(dir, id)
	if err != nil || !needed {
		return err
	}

	unlock, err := lock(filepath.Join(dir, "pilot-lock"))
	if err != nil {
		return nil
	} // A concurrent export can finish on the next cycle.
	defer unlock()
	var current Pilot
	if err := readJSON(pilotPath(dir), &current); err != nil {
		return err
	}
	if p.ID != current.ID || !p.End.Equal(current.End) {
		return nil
	}
	archive := filepath.Join(dir, "pilot-report.tar.gz")
	info, err := os.Stat(archive)
	if os.IsNotExist(err) || err == nil && info.ModTime().Before(p.End) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Size() < 1 || info.Size() > reportMax {
		return errors.New("final pilot archive is outside the transfer limit")
	}
	file, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer file.Close()
	return saveJob(dir, id, file)
}

func (c *controller) flushReports(ctx context.Context) error {
	dir := c.config.StateDir
	files, err := filepath.Glob(filepath.Join(dir, "job-*"))
	if err != nil {
		return err
	}
	// One delivery per cycle bounds traffic when a long outage has queued
	// multiple reports. The agent and ingress run independently.
	for _, path := range files {
		id := strings.TrimPrefix(filepath.Base(path), "job-")
		if !jobID.MatchString(id) {
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		if c.relayReport(ctx, "/v1/reports/jobs/"+id, func() (io.ReadCloser, error) { return os.Open(path) }, info.Size()) != http.StatusNoContent {
			return nil
		}
		if err := atomicWrite(filepath.Join(dir, "sent-"+id), []byte("queued\n"), 0600); err != nil {
			return err
		}
		return os.Remove(path)
	}
	return nil
}
