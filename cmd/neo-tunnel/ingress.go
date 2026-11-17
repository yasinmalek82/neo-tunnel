package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Operators free the former BackPack listener only after the temporary-port
// checks pass. This command edits only NEO's managed listener files.
func changeIngress(ctx context.Context, portArg, scope string, requireReady bool) error {
	role, err := installedRole()
	if err != nil {
		return err
	}
	if role != "iran" {
		return errors.New("change the customer ingress on the Iran host")
	}
	var before siteSettings
	siteFile := filepath.Join(adminHome, "site.json")
	if err := readJSON(siteFile, &before); err != nil {
		return err
	}
	port, err := strconv.Atoi(portArg)
	if err != nil {
		return errors.New("customer port must be an integer")
	}
	next := before
	next.Port = port
	switch scope {
	case "public":
		next.Bind = "0.0.0.0"
	case "local":
		next.Bind = "127.0.0.1"
	default:
		return errors.New("ingress scope must be public or local")
	}
	if err := next.validate(); err != nil {
		return err
	}
	if next == before {
		return nil
	}
	if next.Port != before.Port {
		udp := []string{}
		if next.UDP {
			udp = append(udp, udpConfig(next).Listen)
		}
		if err := ensurePorts([]string{udpConfig(next).Listen}, udp); err != nil {
			return err
		}
	}
	// The readiness checks do not require shutting down either customer port.
	if requireReady {
		if err := run(ctx, []string{"first-check"}); err != nil {
			return err
		}
	}
	haPath := filepath.Join(configHome, "haproxy.cfg")
	beforeHA, err := os.ReadFile(haPath)
	if err != nil {
		return err
	}
	oldBind := "    bind " + net.JoinHostPort(before.Bind, strconv.Itoa(before.Port)) + "\n"
	if strings.Count(string(beforeHA), oldBind) != 1 {
		return errors.New("managed HAProxy bind did not match the installed listener")
	}
	updated := []byte(strings.Replace(string(beforeHA), oldBind, "    bind "+udpConfig(next).Listen+"\n", 1))
	staged, err := os.CreateTemp(adminHome, "ingress-")
	if err != nil {
		return err
	}
	defer os.Remove(staged.Name())
	if _, err = staged.Write(updated); err != nil {
		_ = staged.Close()
		return err
	}
	if err := staged.Close(); err != nil {
		return err
	}
	if err := tool(ctx, "/usr/local/libexec/neo-tunnel/haproxy", "-c", "-f", staged.Name()); err != nil {
		return err
	}

	write := func(settings siteSettings, ha []byte) error {
		if err := configFile(configHome, "haproxy.cfg", ha); err != nil {
			return err
		}
		if settings.UDP {
			if err := configFile(configHome, "udp.json", jsonBytes(udpConfig(settings))); err != nil {
				return err
			}
		}
		return atomicJSON(siteFile, settings)
	}
	units := []string{"neo-haproxy.service"}
	if next.UDP {
		units = append(units, "neo-udp.service")
	}
	restart := func(ctx context.Context) error {
		if err := tool(ctx, "systemctl", append([]string{"restart"}, units...)...); err != nil {
			return err
		}
		if err := wait(ctx, time.Second); err != nil {
			return err
		}
		for _, u := range units {
			if err := tool(ctx, "systemctl", "is-active", "--quiet", u); err != nil {
				return err
			}
		}
		return nil
	}
	commit := func() error {
		if err := write(next, updated); err != nil {
			return err
		}
		return restart(ctx)
	}
	if requireReady {
		if err := atomicJSON(filepath.Join(adminHome, "ingress-previous.json"), before); err != nil {
			return err
		}
	}
	if err := commit(); err != nil {
		restore, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return errors.Join(err, write(before, beforeHA), restart(restore))
	}
	fmt.Printf("NEO ingress is now %s. Verify actual TCP and UDP application replies.\n", udpConfig(next).Listen)
	return nil
}

func enableInstalledUDP(ctx context.Context) error {
	role, err := installedRole()
	if err != nil {
		return err
	}
	if role != "iran" {
		return errors.New("enable customer UDP on the Iran host")
	}
	siteFile := filepath.Join(adminHome, "site.json")
	var site siteSettings
	if err := readJSON(siteFile, &site); err != nil {
		return err
	}
	if site.UDP {
		return enableUnits(ctx, "neo-udp.service")
	}
	if err := ensurePorts(nil, []string{udpConfig(site).Listen}); err != nil {
		return err
	}
	name := "controller.json"
	configPath := filepath.Join(configHome, name)
	raw, err := loadConfig(configPath)
	if err != nil {
		return err
	}
	var cfg Config
	if err := readJSON(configPath, &cfg); err != nil {
		return err
	}
	cfg.UDP = true
	if err := configFile(configHome, "udp.json", jsonBytes(udpConfig(site))); err != nil {
		return err
	}
	if err := enableUnits(ctx, "neo-udp.service"); err != nil {
		return err
	}
	defer func() {
		// State is committed only once the watcher has been restarted below.
		if !site.UDP {
			restore, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			_ = tool(restore, "systemctl", "disable", "--now", "neo-udp.service")
		}
	}()
	if err := configFile(configHome, name, jsonBytes(cfg)); err != nil {
		return err
	}
	restoreConfig := func(e error) error {
		restore, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return errors.Join(e, configFile(configHome, name, raw), tool(restore, "systemctl", "restart", "neo-watch.service", "neo-report.service"))
	}
	if err := tool(ctx, "systemctl", "restart", "neo-watch.service", "neo-report.service"); err != nil {
		return restoreConfig(err)
	}
	next := site
	next.UDP = true
	if err := atomicJSON(siteFile, next); err != nil {
		return restoreConfig(err)
	}
	site = next
	fmt.Printf("UDP ingress enabled on %s using the primary path.\n", udpConfig(site).Listen)
	return nil
}
