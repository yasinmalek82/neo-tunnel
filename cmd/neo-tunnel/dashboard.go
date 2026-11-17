package main

import (
	"context"
	_ "embed"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

//go:embed dashboard.html
var dashboardHTML string
var dashboardTemplate = template.Must(template.New("dashboard").Parse(dashboardHTML))

type dashboardSnapshot struct {
	At           time.Time         `json:"at"`
	Preferred    string            `json:"preferred"`
	Selected     string            `json:"selected"`
	Standby      string            `json:"standby"`
	Health       map[string]Health `json:"health"`
	Iran         *Reading          `json:"iran"`
	Peer         *Reading          `json:"peer"`
	LastOutage   *time.Time        `json:"last_outage"`
	LastRecovery *time.Time        `json:"last_recovery"`
}

func dashboardHandler(dir string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		if host != "127.0.0.1" && host != "localhost" && host != "::1" && host != "[::1]" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'")
		if r.URL.Path == "/report" {
			w.Header().Set("Content-Disposition", `attachment; filename="neo-tunnel-pilot.tar.gz"`)
			http.ServeFile(w, r, filepath.Join(dir, "pilot-report.tar.gz"))
			return
		}
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		now := time.Now().UTC()
		var snapshot dashboardSnapshot
		_ = readJSON(filepath.Join(dir, "dashboard.json"), &snapshot)
		routeName := func(id string) string {
			switch id {
			case "primary":
				return "TCP/TLS"
			case "standby":
				return "QUIC"
			case "naive":
				return "NaiveProxy"
			}
			return "نامعلوم"
		}
		view := struct {
			Route, Standby, Updated, Outage, Recovery, Analysis, Pilot string
			Hosts                                                      [2]struct{ Name, CPU, Memory, Tool, Status string }
			Report                                                     bool
		}{Route: "نامعلوم", Standby: "نامعلوم", Updated: "نامعلوم", Outage: "رخدادی ثبت نشده", Recovery: "رخدادی ثبت نشده", Pilot: "دوره‌ای شروع نشده", Analysis: "هنوز دادهٔ کافی برای تشخیص وضعیت نداریم."}
		if !snapshot.At.IsZero() && now.Sub(snapshot.At) <= 90*time.Second {
			view.Route = routeName(snapshot.Selected)
			view.Standby = routeName(snapshot.Standby)
			if len(snapshot.Health) > 0 && snapshot.Selected == "" {
				view.Route = "هیچ مسیر آماده‌ای شناسایی نشد"
			}
			if h, ok := snapshot.Health[snapshot.Preferred]; ok && !h.ready() && snapshot.Standby == "" {
				view.Standby = "مسیر آمادهٔ دیگری شناسایی نشد"
			}
			view.Updated = snapshot.At.Format("15:04:05 UTC")
			if snapshot.Selected != "" {
				view.Analysis = "پایش تانل، یک مسیر آماده برای اتصال‌های جدید شناسایی کرده است."
			}
		}
		if snapshot.LastOutage != nil {
			view.Outage = snapshot.LastOutage.Format("2006-01-02 15:04 UTC")
		}
		if snapshot.LastRecovery != nil {
			view.Recovery = snapshot.LastRecovery.Format("2006-01-02 15:04 UTC")
		}
		for i, v := range []*Reading{snapshot.Iran, snapshot.Peer} {
			h := &view.Hosts[i]
			h.Name = [2]string{"ایران", "خارج"}[i]
			h.CPU, h.Memory, h.Tool, h.Status = "نامعلوم", "نامعلوم", "نامعلوم", "دادهٔ تازه در دسترس نیست"
			if !fresh(now, v) {
				continue
			}
			h.CPU = fmt.Sprintf("%.0f%%", v.CPU*100)
			h.Memory = fmt.Sprintf("%.0f%%", v.Available*100)
			h.Tool = fmt.Sprintf("%.1f MiB", float64(v.WorkingSet)/(1<<20))
			h.Status = "عادی"
			if v.MemoryPressure || v.SustainedPressure || v.OOM {
				h.Status = "فشار منابع ثبت شده"
				view.Analysis = "فشار منابع در دست‌کم یک میزبان مشاهده شده است. علت اختلال مسیر به بررسی جداگانه نیاز دارد."
			}
		}
		var p Pilot
		if readJSON(pilotPath(dir), &p) == nil {
			if p.AutoDisabled {
				view.Pilot = "پایلوت خودکار غیرفعال است"
			} else if now.Before(p.End) {
				view.Pilot = "در حال جمع‌آوری تا " + p.End.Format("2006-01-02 15:04 UTC")
			} else {
				view.Pilot = "دوره پایان یافته است"
			}
		}
		_, err = os.Stat(filepath.Join(dir, "pilot-report.tar.gz"))
		view.Report = err == nil
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = dashboardTemplate.Execute(w, view)
	})
}

func serveDashboard(ctx context.Context, dir string) error {
	l, err := net.Listen("tcp4", "127.0.0.1:8787")
	if err != nil {
		return err
	}
	defer l.Close()
	server := http.Server{Handler: dashboardHandler(dir), ReadHeaderTimeout: 3 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 4096}
	stop := context.AfterFunc(ctx, func() { _ = server.Close() })
	defer stop()
	err = server.Serve(l)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}
