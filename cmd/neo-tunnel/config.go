package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type Identity struct {
	Cert string `json:"cert"`
	Key  string `json:"key"`
	CA   string `json:"ca"`
}

type AgentConfig struct {
	ProfileCgroups map[string]string `json:"profile_cgroups"`
	Listen         string            `json:"listen"`
	StateDir       string            `json:"state_dir"`
	Identity       Identity          `json:"identity"`
	ToolCgroup     string            `json:"tool_cgroup"`
	WireInterface  string            `json:"wire_interface"`
	Units          map[string]string `json:"units"`
}

type Profile struct {
	AppTCP   string `json:"app_tcp,omitempty"`
	Replaces string `json:"replaces,omitempty"`
	Revision string `json:"revision"`
	Provider string `json:"provider,omitempty"`
	Canary   string `json:"canary"`
	AppURL   string `json:"app_url"`
	AppBody  string `json:"app_body"`
	Carrier  string `json:"carrier"`
	// Experiment describes the single setting that differs from its base profile.
	Experiment string `json:"experiment"`
	Staged     bool   `json:"staged"`
}

type Config struct {
	PeerFallback  string             `json:"peer_fallback,omitempty"`
	AutoPrefer    bool               `json:"auto_prefer"`
	StateDir      string             `json:"state_dir"`
	Iran          string             `json:"iran_agent"`
	Peer          string             `json:"peer_agent"`
	Identity      Identity           `json:"identity"`
	HAProxySocket string             `json:"haproxy_socket"`
	MapFile       string             `json:"map_file"`
	Initial       string             `json:"initial"`
	Profiles      map[string]Profile `json:"profiles"`
}

var identifier = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,47}$`)
var unitName = regexp.MustCompile(`^neo-[a-z0-9_-]{1,40}(@[a-z0-9_-]{1,40})?\.service$`)

func readJSON(path string, dst any) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return decodeJSON(io.LimitReader(file, 4<<20), dst)
}

func decodeJSON(body io.Reader, dst any) error {
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("expected exactly one JSON value")
	}
	return nil
}

func (id Identity) tls(server bool) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(id.Cert, id.Key)
	if err != nil {
		return nil, err
	}
	pem, err := os.ReadFile(id.CA)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("invalid management CA")
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
	if server {
		config.ClientAuth = tls.RequireAndVerifyClientCert
		config.ClientCAs = roots
	} else {
		config.RootCAs = roots
	}
	return config, nil
}

func agentClient(id Identity) (*http.Client, error) {
	tlsConfig, err := id.tls(false)
	if err != nil {
		return nil, err
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}, Timeout: 3 * time.Second, CheckRedirect: noRedirect}, nil
}

func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func loopback(addr string) bool {
	a, err := netip.ParseAddrPort(addr)
	return err == nil && a.Addr().IsLoopback() && a.Addr().Zone() == "" && a.Port() != 0
}

func parsedURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return nil, fmt.Errorf("invalid URL %q", raw)
	}
	return u, nil
}

func (c Config) validate() error {
	if !filepath.IsAbs(c.StateDir) || !filepath.IsAbs(c.HAProxySocket) || !filepath.IsAbs(c.MapFile) ||
		regexp.MustCompile(`[\s;]`).MatchString(c.MapFile) {
		return errors.New("invalid state, socket or map path")
	}
	addresses := []string{c.Iran, c.Peer}
	if c.PeerFallback != "" {
		addresses = append(addresses, c.PeerFallback)
	}
	for _, address := range addresses {
		u, err := parsedURL(address)
		if err != nil || u.Scheme != "https" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
			return errors.New("management endpoints must be HTTPS origins")
		}
	}
	if c.Iran == c.Peer {
		return errors.New("different host agents are required")
	}
	initial, ok := c.Profiles[c.Initial]
	if !ok || initial.Staged || len(c.Profiles) < 2 {
		return errors.New("need an initial profile and a standby")
	}
	staged := 0
	for id, p := range c.Profiles {
		if !identifier.MatchString(id) || !loopback(p.Canary) || p.Carrier == "" {
			return fmt.Errorf("invalid profile %q", id)
		}
		if p.Staged {
			base, exists := c.Profiles[p.Replaces]
			if p.Experiment == "" || !exists || base.Staged || p.Replaces == id {
				return fmt.Errorf("profile %q needs a permanent base and a single experiment setting", id)
			}
			staged++
		}
		if p.AppTCP != "" && (!loopback(p.AppTCP) || p.AppURL != "") {
			return errors.New("invalid TCP application check")
		}
		if p.AppURL != "" {
			u, err := parsedURL(p.AppURL)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || !loopback(u.Host) ||
				len(p.AppBody) == 0 || len(p.AppBody) > 4096 {
				return fmt.Errorf("invalid application check for %q", id)
			}
		}
	}
	if staged > 1 || len(c.Profiles)-staged != 2 {
		return errors.New("declare two permanent profiles and at most one experiment")
	}
	return nil
}

func (c AgentConfig) validate() error {
	if !filepath.IsAbs(c.StateDir) || !filepath.IsAbs(c.ToolCgroup) {
		return errors.New("absolute state and cgroup paths required")
	}
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return err
	}
	if c.WireInterface != "" && !regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`).MatchString(c.WireInterface) {
		return errors.New("invalid wire interface")
	}
	for profile, group := range c.ProfileCgroups {
		base := filepath.Clean(c.ToolCgroup)
		if !identifier.MatchString(profile) || !strings.HasPrefix(filepath.Clean(group), base+"/") {
			return errors.New("profile cgroups must be descendants of the tool cgroup")
		}
	}
	for profile, unit := range c.Units {
		if !identifier.MatchString(profile) || !unitName.MatchString(unit) {
			return errors.New("invalid experiment unit mapping")
		}
	}
	return nil
}
