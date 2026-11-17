package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const configHome = "/etc/neo-tunnel"
const adminHome = "/var/lib/neo-tunnel-admin"
const templateHome = "/usr/local/share/neo-tunnel"
const releaseVersion = "v0.2.1"
const releaseURL = "https://github.com/yasinmalek82/neo-tunnel/releases/download/" + releaseVersion

func runSetup(ctx context.Context, command string, args []string) error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("installation commands require Linux and root")
	}
	if err := os.MkdirAll(adminHome, 0700); err != nil {
		return err
	}
	if command == "enroll-serve" {
		return serveEnrollment(ctx, adminHome, configHome)
	}
	unlock, err := lock(adminHome)
	if err != nil {
		return err
	}
	defer unlock()
	switch command {
	case "setup-iran":
		in := bufio.NewReader(os.Stdin)
		if len(args) == 0 {
			return iranWizard(ctx, in)
		}
		return errors.New("use setup-iran through the interactive menu")
	case "issue-link":
		if len(args) != 0 {
			return errors.New("issue-link takes no arguments")
		}
		return issueLink(ctx)
	case "join":
		if len(args) != 0 {
			return errors.New("join reads the setup link from standard input")
		}
		role, err := installedRole()
		if err != nil {
			return err
		}
		if role != "" && role != "foreign" {
			return errors.New("this host is already configured as Iran")
		}
		var pending pendingJoin
		path := filepath.Join(adminHome, "foreign-join.json")
		if err := readJSON(path, &pending); err != nil && !os.IsNotExist(err) {
			return err
		}
		if role == "" && pending.Reply.Site.Host == "" {
			raw, err := io.ReadAll(io.LimitReader(os.Stdin, 4096))
			if err != nil {
				return err
			}
			pending, err = prepareJoin(ctx, string(raw))
			if err != nil {
				return err
			}
			if err := atomicJSON(path, pending); err != nil {
				return err
			}
		}
		if err := installForeign(ctx, pending); err != nil {
			return err
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		printJoinResult(ctx)
		return nil
	}
	return errors.New("unknown installation command")
}

func terminalMenu(ctx context.Context) error {
	info, err := os.Stdin.Stat()
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeCharDevice == 0 {
		usage()
		return errors.New("interactive menu requires a terminal")
	}
	in := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("\nNEO Tunnel\n1. Set up Iran\n2. Join foreign server\n3. Manage tunnel\n4. Pilot report\n5. Open dashboard\n0. Exit\n")
		choice, err := ask(in, "Select an option", "")
		if errors.Is(err, io.EOF) || choice == "0" {
			return nil
		}
		if err != nil {
			return err
		}
		switch choice {
		case "1":
			if runtime.GOOS != "linux" || os.Geteuid() != 0 {
				err = errors.New("run this option with sudo on Linux")
				break
			}
			unlock, lockErr := lock(adminHome)
			if lockErr != nil {
				err = lockErr
				break
			}
			err = iranWizard(ctx, in)
			unlock()
		case "2":
			fmt.Println("Run the one-line installation command printed on Iran, or paste the setup link here.")
			var input string
			fmt.Print("Setup link (input hidden): ")
			hide := exec.Command("stty", "-echo")
			hide.Stdin = os.Stdin
			if e := hide.Run(); e != nil {
				err = e
				break
			}
			input, err = in.ReadString('\n')
			echo := exec.Command("stty", "echo")
			echo.Stdin = os.Stdin
			_ = echo.Run()
			fmt.Println()
			if err != nil {
				break
			}
			child := exec.CommandContext(ctx, os.Args[0], "join")
			child.Stdin = strings.NewReader(input)
			child.Stdout, child.Stderr = os.Stdout, os.Stderr
			err = child.Run()
		case "3":
			fmt.Println("1. Status\n2. Calibrate\n3. Apply proposal\n4. Roll back\n5. Show enrollment command")
			var sub string
			sub, err = ask(in, "Select an action", "1")
			commands := map[string]string{"1": "status", "2": "calibrate", "3": "apply", "4": "rollback", "5": "issue-link"}
			if err != nil || commands[sub] == "" {
				break
			}
			args := []string{commands[sub]}
			if sub == "3" {
				id, e := ask(in, "Proposal ID", "")
				if e != nil {
					err = e
					break
				}
				args = append(args, id)
			}
			err = run(ctx, args)
		case "4":
			fmt.Println("1. Start seven-day pilot\n2. Status\n3. Stop pilot and disable automatic start\n4. Export report")
			var sub string
			sub, err = ask(in, "Select an action", "2")
			actions := map[string]string{"1": "start", "2": "status", "3": "stop", "4": "export"}
			if err != nil || actions[sub] == "" {
				break
			}
			err = run(ctx, []string{"pilot", actions[sub]})
		case "5":
			var site siteSettings
			err = readJSON(filepath.Join(adminHome, "site.json"), &site)
			if err == nil {
				fmt.Printf("On your computer: ssh -N -L 8787:127.0.0.1:8787 USER@%s\nOpen http://127.0.0.1:8787/\n", site.Host)
			}
		default:
			fmt.Println("Choose a number from the menu.")
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, asciiConsole(err.Error()))
		}
	}
}

func ask(in *bufio.Reader, label, def string) (string, error) {
	if def != "" {
		fmt.Printf("%s [%s]: ", label, def)
	} else {
		fmt.Printf("%s: ", label)
	}
	value, err := in.ReadString('\n')
	if err != nil {
		return "", err
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return def, nil
	}
	return value, nil
}

var setupHost = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)

func (s siteSettings) validate() error {
	if !setupHost.MatchString(s.Host) || strings.HasSuffix(s.Host, ".") {
		return errors.New("enter an IPv4 address or DNS name for Iran")
	}
	if s.Bind != "127.0.0.1" && s.Bind != "0.0.0.0" {
		return errors.New("invalid frontend bind address")
	}
	if s.Port < 1024 || s.Port > 65535 || s.AppPort < 1 || s.AppPort > 65535 {
		return errors.New("port out of range")
	}
	internal := map[int]bool{8787: true, 17000: true, 17003: true, 17005: true, 17010: true, 17011: true, 17013: true, 17101: true, 17102: true, 17104: true, 17111: true, 17112: true, 17114: true, 18443: true}
	if internal[s.Port] || s.AppPort == 18080 || s.AppPort == 18443 {
		return errors.New("the selected port is reserved by NEO Tunnel")
	}
	return nil
}

func iranWizard(ctx context.Context, in *bufio.Reader) error {
	var saved siteSettings
	if err := readJSON(filepath.Join(adminHome, "site.json"), &saved); err == nil {
		fmt.Println("Iran configuration already exists.")
		if err := installIran(ctx, saved); err != nil {
			return err
		}
		return issueLink(ctx)
	} else if !os.IsNotExist(err) {
		return err
	}
	host, err := ask(in, "Iran IPv4 address or DNS name", "")
	if err != nil {
		return err
	}
	public, err := ask(in, "Expose the customer port on all IPv4 interfaces? (yes/no)", "no")
	if err != nil {
		return err
	}
	if public != "yes" && public != "no" {
		return errors.New("enter yes or no")
	}
	port, err := ask(in, "Iran customer TCP port", "16443")
	if err != nil {
		return err
	}
	app, err := ask(in, "Foreign application loopback port", "14443")
	if err != nil {
		return err
	}
	p, e1 := strconv.Atoi(port)
	a, e2 := strconv.Atoi(app)
	if e1 != nil || e2 != nil {
		return errors.New("ports must be integers")
	}
	site := siteSettings{Host: host, Bind: "127.0.0.1", Port: p, AppPort: a}
	if public == "yes" {
		site.Bind = "0.0.0.0"
	}
	if err := site.validate(); err != nil {
		return err
	}
	fmt.Printf("Iran: %s | Listener: %s:%d | Foreign app: 127.0.0.1:%d | TCP/TLS + QUIC\n", site.Host, site.Bind, site.Port, site.AppPort)
	ok, err := ask(in, "Create tunnel? (yes/no)", "no")
	if err != nil || ok != "yes" {
		return err
	}
	if err := installIran(ctx, site); err != nil {
		return err
	}
	return issueLink(ctx)
}

func tool(ctx context.Context, binary string, args ...string) error {
	cmd := exec.CommandContext(ctx, binary, args...)
	data, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", filepath.Base(binary), err, strings.TrimSpace(asciiConsole(string(data))))
	}
	return nil
}

func configFile(dir, name string, data []byte) error {
	p := filepath.Join(dir, name)
	mode := os.FileMode(0640)
	if err := atomicWrite(p, data, mode); err != nil {
		return err
	}
	group, err := user.LookupGroup("neo")
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		return err
	}
	return os.Chown(p, 0, gid)
}

func installTree(dst string, files map[string][]byte) error {
	for _, dir := range []string{dst, filepath.Join(dst, "secrets"), filepath.Join(dst, "runtime")} {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return err
		}
		if err := os.Chmod(dir, 0750); err != nil {
			return err
		}
		group, err := user.LookupGroup("neo")
		if err != nil {
			return err
		}
		gid, _ := strconv.Atoi(group.Gid)
		if dir == filepath.Join(dst, "runtime") {
			u, err := user.Lookup("neo")
			if err != nil {
				return err
			}
			uid, _ := strconv.Atoi(u.Uid)
			if err := os.Chown(dir, uid, gid); err != nil {
				return err
			}
		} else if err := os.Chown(dir, 0, gid); err != nil {
			return err
		}
	}
	for name, bytes := range files {
		if err := configFile(dst, name, bytes); err != nil {
			return err
		}
	}
	return nil
}

func jsonBytes(value any) []byte {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		panic(err)
	}
	return b
}

func makeCA(dir, name string) error {
	certPath, keyPath := filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")
	if _, err := os.Stat(certPath); err == nil {
		_, _, _, err := loadCA(dir, name)
		return err
	} else if !os.IsNotExist(err) {
		return err
	}
	key, private, err := keyPair()
	if err != nil {
		return err
	}
	cert, _, err := certificate("NEO "+name, nil, key, &key.PublicKey, "", 0, 5*365*24*time.Hour, true)
	if err != nil {
		return err
	}
	if err := atomicWrite(keyPath, private, 0600); err != nil {
		return err
	}
	return atomicWrite(certPath, cert, 0600)
}

func leaf(dir, ca, host string, usage x509.ExtKeyUsage) ([]byte, []byte, error) {
	_, issuer, signer, err := loadCA(dir, ca)
	if err != nil {
		return nil, nil, err
	}
	key, private, err := keyPair()
	if err != nil {
		return nil, nil, err
	}
	pem, _, err := certificate("NEO "+ca, issuer, signer, &key.PublicKey, host, usage, 365*24*time.Hour, false)
	return pem, private, err
}

func randomToken() string {
	var b [32]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func installedRole() (string, error) {
	b, err := os.ReadFile(filepath.Join(configHome, "setup.role"))
	if os.IsNotExist(err) {
		if _, dirErr := os.Stat(configHome); dirErr == nil {
			return "", errors.New("existing manual configuration found; use a clean test server")
		}
		return "", nil
	}
	return strings.TrimSpace(string(b)), err
}

func ensurePorts(addresses []string, udp []string) error {
	for _, addr := range addresses {
		l, err := net.Listen("tcp4", addr)
		if err != nil {
			return fmt.Errorf("TCP port unavailable at %s: %w", addr, err)
		}
		l.Close()
	}
	for _, addr := range udp {
		l, err := net.ListenPacket("udp4", addr)
		if err != nil {
			return fmt.Errorf("UDP port unavailable at %s: %w", addr, err)
		}
		l.Close()
	}
	return nil
}

func renderFRP(dir string, site siteSettings, iran bool) (map[string][]byte, error) {
	role := "frpc"
	if iran {
		role = "frps"
	}
	files := map[string][]byte{}
	for i, name := range []string{"primary", "standby"} {
		port := 17104 + 10*i
		filename := role + "-" + name + ".toml"
		raw, err := os.ReadFile(filepath.Join(dir, filename))
		if err != nil {
			return nil, err
		}
		config := string(raw)
		if iran {
			config = strings.Replace(config, `bindAddr = "127.0.0.1"`, `bindAddr = "0.0.0.0"`, 1)
			config = strings.Replace(config, "allowPorts = [{", fmt.Sprintf("allowPorts = [{ single = %d }, {", port), 1)
			config = strings.Replace(config, "maxPortsPerClient = 4", "maxPortsPerClient = 5", 1)
		} else {
			config = strings.ReplaceAll(config, "iran.example.net", site.Host)
			config = strings.ReplaceAll(config, "localPort = 14443", "localPort = "+strconv.Itoa(site.AppPort))
			config += fmt.Sprintf("\n[[proxies]]\nname = \"management\"\ntype = \"tcp\"\nlocalIP = \"127.0.0.1\"\nlocalPort = 18443\nremotePort = %d\n", port)
		}
		files[filename] = []byte(config)
	}
	return files, nil
}

func defaultAgent() AgentConfig {
	return AgentConfig{Listen: "127.0.0.1:18443", StateDir: "/var/lib/neo-tunnel/agent", ToolCgroup: "/sys/fs/cgroup/neo.slice",
		Identity: Identity{Cert: configHome + "/secrets/agent.crt", Key: configHome + "/secrets/agent.key", CA: configHome + "/secrets/management-ca.crt"},
	}
}

func installRole(files map[string][]byte, role string) error {
	stage, err := os.MkdirTemp(filepath.Dir(configHome), ".neo-stage-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	if err := os.Chmod(stage, 0750); err != nil {
		return err
	}
	files["setup.role"] = []byte(role + "\n")
	if err := installTree(stage, files); err != nil {
		return err
	}
	return os.Rename(stage, configHome)
}

func installIran(ctx context.Context, site siteSettings) error {
	if err := site.validate(); err != nil {
		return err
	}
	role, err := installedRole()
	if err != nil {
		return err
	}
	if role != "" && role != "iran" {
		return errors.New("this host is already configured as Foreign")
	}
	if role == "" {
		if err := ensurePorts([]string{net.JoinHostPort(site.Bind, strconv.Itoa(site.Port)), "0.0.0.0:17000", "0.0.0.0:17010", "127.0.0.1:17003", "127.0.0.1:17013", "127.0.0.1:17101", "127.0.0.1:17102", "127.0.0.1:17104", "127.0.0.1:17111", "127.0.0.1:17112", "127.0.0.1:17114", "127.0.0.1:18443", "127.0.0.1:8787"}, []string{"0.0.0.0:17011", "127.0.0.1:17101", "127.0.0.1:17102", "127.0.0.1:17111", "127.0.0.1:17112"}); err != nil {
			return err
		}
		files, err := renderFRP(templateHome, site, true)
		if err != nil {
			return err
		}
		for _, ca := range []string{"frp-ca", "management-ca"} {
			if err := makeCA(adminHome, ca); err != nil {
				return err
			}
			chain, _, _, err := loadCA(adminHome, ca)
			if err != nil {
				return err
			}
			key := "management-ca"
			if ca == "frp-ca" {
				key = "ca"
			}
			files["secrets/"+key+".crt"] = chain
		}
		for _, item := range []struct {
			name, ca, host string
			usage          x509.ExtKeyUsage
		}{
			{"iran", "frp-ca", site.Host, x509.ExtKeyUsageServerAuth},
			{"agent", "management-ca", "127.0.0.1", x509.ExtKeyUsageServerAuth},
			{"controller", "management-ca", "", x509.ExtKeyUsageClientAuth},
		} {
			cert, key, err := leaf(adminHome, item.ca, item.host, item.usage)
			if err != nil {
				return err
			}
			files["secrets/"+item.name+".crt"], files["secrets/"+item.name+".key"] = cert, key
		}
		files["secrets/primary.token"] = []byte(randomToken() + "\n")
		files["secrets/standby.token"] = []byte(randomToken() + "\n")
		raw, err := os.ReadFile(filepath.Join(templateHome, "haproxy.cfg"))
		if err != nil {
			return err
		}
		ha := strings.Replace(string(raw), "bind 127.0.0.1:16443", fmt.Sprintf("bind %s:%d", site.Bind, site.Port), 1)
		// The default wizard supports an arbitrary TCP service. The separate canary still checks the carrier.
		for _, line := range strings.Split(ha, "\n") {
			if strings.Contains(line, "/healthz") {
				ha = strings.ReplaceAll(ha, line+"\n    tcp-check expect string \"HTTP/1.0 200 OK\"\n", "")
			}
		}
		files["haproxy.cfg"] = []byte(ha)
		files["runtime/route.map"] = []byte("preference primary\n")
		files["agent.json"] = jsonBytes(defaultAgent())
		config := Config{StateDir: "/var/lib/neo-tunnel/controller", Iran: "https://127.0.0.1:18443", Peer: "https://127.0.0.1:17104", PeerFallback: "https://127.0.0.1:17114",
			Identity:      Identity{Cert: configHome + "/secrets/controller.crt", Key: configHome + "/secrets/controller.key", CA: configHome + "/secrets/management-ca.crt"},
			HAProxySocket: "/run/neo-tunnel/haproxy.sock", MapFile: configHome + "/runtime/route.map", Initial: "primary", AutoPrefer: true,
			Profiles: map[string]Profile{
				"primary": {Carrier: "tcp/tls", Revision: releaseVersion, Canary: "127.0.0.1:17102", AppTCP: "127.0.0.1:17101"},
				"standby": {Carrier: "quic", Revision: releaseVersion, Canary: "127.0.0.1:17112", AppTCP: "127.0.0.1:17111"},
			},
		}
		if err := config.validate(); err != nil {
			return err
		}
		files["controller.json"] = jsonBytes(config)
		if err := installRole(files, "iran"); err != nil {
			return err
		}
	}
	if err := atomicJSON(filepath.Join(adminHome, "site.json"), site); err != nil {
		return err
	}
	return enableUnits(ctx, "neo-frp@frps-primary.service", "neo-frp@frps-standby.service", "neo-agent.service", "neo-haproxy.service", "neo-watch.service", "neo-dashboard.service")
}

func issueLink(ctx context.Context) error {
	var site siteSettings
	if err := readJSON(filepath.Join(adminHome, "site.json"), &site); err != nil {
		return err
	}
	_ = tool(ctx, "systemctl", "stop", "neo-enrollment.service")
	if err := ensurePorts([]string{"0.0.0.0:" + enrollmentPort}, nil); err != nil {
		return err
	}
	key, private, err := keyPair()
	if err != nil {
		return err
	}
	// Self-signed short-lived leaf. The setup link carries its public-key fingerprint.
	cert, leaf, err := certificate("NEO Enrollment", nil, key, &key.PublicKey, site.Host, x509.ExtKeyUsageServerAuth, 20*time.Minute, true)
	if err != nil {
		return err
	}
	if err := atomicWrite(filepath.Join(adminHome, "enrollment.crt"), cert, 0600); err != nil {
		return err
	}
	if err := atomicWrite(filepath.Join(adminHome, "enrollment.key"), private, 0600); err != nil {
		return err
	}
	token := randomToken()
	digest := sha256.Sum256([]byte(token))
	g := enrollmentGrant{Digest: hex.EncodeToString(digest[:]), Expires: time.Now().UTC().Add(enrollmentLife)}
	if err := atomicJSON(filepath.Join(adminHome, "grant.json"), g); err != nil {
		return err
	}
	if err := tool(ctx, "systemd-run", "--quiet", "--collect", "--unit=neo-enrollment", "--property=RuntimeMaxSec=16min", "/usr/local/bin/neo-tunnel", "enroll-serve"); err != nil {
		return err
	}
	pin := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	link := url.URL{Scheme: "neo-tunnel", Host: net.JoinHostPort(site.Host, enrollmentPort), Path: "/join", RawQuery: url.Values{"pin": {hex.EncodeToString(pin[:])}, "token": {token}}.Encode()}
	fmt.Println("Allow TCP 17000 and 17005 and UDP 17011 from the Foreign host. Port 17005 is temporary.")
	fmt.Println("Run this one-time command on the Foreign server within 15 minutes. Keep it private.")
	fmt.Printf("tmp=$(mktemp) && curl -fsSL '%s/install.sh' -o \"$tmp\" && printf '%%s\\n' '%s' | { if [ \"$(id -u)\" -eq 0 ]; then bash \"$tmp\" --join-stdin; else sudo bash \"$tmp\" --join-stdin; fi; }\n", releaseURL, link.String())
	return nil
}

type pendingJoin struct {
	Reply    enrollmentReply `json:"reply"`
	FRPKey   []byte          `json:"frp_private_key"`
	AgentKey []byte          `json:"agent_private_key"`
}

func makeCSR() ([]byte, []byte, error) {
	key, pem, err := keyPair()
	if err != nil {
		return nil, nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	return csr, pem, err
}

func prepareJoin(ctx context.Context, link string) (pendingJoin, error) {
	frp, frpKey, err := makeCSR()
	if err != nil {
		return pendingJoin{}, err
	}
	agent, agentKey, err := makeCSR()
	if err != nil {
		return pendingJoin{}, err
	}
	reply, err := enroll(ctx, link, enrollmentRequest{FRP: frp, Agent: agent})
	if err != nil {
		return pendingJoin{}, err
	}
	if err := reply.Site.validate(); err != nil {
		return pendingJoin{}, err
	}
	return pendingJoin{Reply: reply, FRPKey: frpKey, AgentKey: agentKey}, nil
}

func installForeign(ctx context.Context, p pendingJoin) error {
	role, err := installedRole()
	if err != nil {
		return err
	}
	if role != "" && role != "foreign" {
		return errors.New("this host is already configured as Iran")
	}
	if role == "" {
		if err := ensurePorts([]string{"127.0.0.1:18080", "127.0.0.1:18443"}, []string{"127.0.0.1:18080"}); err != nil {
			return err
		}
		if conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", p.Reply.Site.AppPort)); err == nil {
			conn.Close()
		} else {
			fmt.Println("The destination TCP port is currently closed. Start your destination service before testing customer traffic.")
		}
		files, err := renderFRP(templateHome, p.Reply.Site, false)
		if err != nil {
			return err
		}
		files["secrets/ca.crt"] = p.Reply.FRPCA
		files["secrets/management-ca.crt"] = p.Reply.AgentCA
		files["secrets/primary.token"] = []byte(p.Reply.Primary + "\n")
		files["secrets/standby.token"] = []byte(p.Reply.Standby + "\n")
		for _, id := range []string{"primary", "standby"} {
			files["secrets/"+id+"-client.crt"], files["secrets/"+id+"-client.key"] = p.Reply.FRP, p.FRPKey
		}
		files["secrets/agent.crt"], files["secrets/agent.key"] = p.Reply.Agent, p.AgentKey
		files["agent.json"] = jsonBytes(defaultAgent())
		if err := installRole(files, "foreign"); err != nil {
			return err
		}
	}
	return enableUnits(ctx, "neo-probe.service", "neo-agent.service", "neo-frp@frpc-primary.service", "neo-frp@frpc-standby.service")
}

func enableUnits(ctx context.Context, units ...string) error {
	var started []string
	for _, unit := range units {
		wasActive := exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", unit).Run() == nil
		if !wasActive {
			started = append(started, unit)
		}
		if err := tool(ctx, "systemctl", "enable", "--now", unit); err != nil {
			rollback, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			return errors.Join(err, tool(rollback, "systemctl", append([]string{"disable", "--now"}, started...)...))
		}
	}
	return nil
}

func runAsOperator(ctx context.Context, command string, extra []string, useJSON bool) error {
	args := []string{"-u", "neo", "--", os.Args[0], command}
	args = append(args, extra...)
	if useJSON {
		args = append(args, "--json")
	}
	cmd := exec.CommandContext(ctx, "runuser", args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

func printJoinResult(ctx context.Context) {
	pending := map[string]bool{"primary": true, "standby": true}
	deadline := time.Now().Add(12 * time.Second)
	for len(pending) > 0 && time.Now().Before(deadline) && ctx.Err() == nil {
		for lane := range pending {
			unit := "neo-frp@frpc-" + lane + ".service"
			id, err := exec.CommandContext(ctx, "systemctl", "show", "-p", "InvocationID", "--value", unit).Output()
			if err != nil {
				continue
			}
			invocation := strings.TrimSpace(string(id))
			if raw, err := hex.DecodeString(invocation); err != nil || len(raw) != 16 {
				continue
			}
			logs, err := exec.CommandContext(ctx, "journalctl", "--no-pager", "--lines=80", "-o", "cat", "_SYSTEMD_INVOCATION_ID="+invocation).Output()
			if err == nil && strings.Contains(string(logs), "[canary-tcp] start proxy success") && strings.Contains(string(logs), "[management] start proxy success") {
				delete(pending, lane)
			}
		}
		if len(pending) > 0 && wait(ctx, time.Second) != nil {
			break
		}
	}
	for _, lane := range []string{"primary", "standby"} {
		outcome := "registered with Iran"
		if pending[lane] {
			outcome = "registration pending; check Status on Iran"
		}
		fmt.Printf("%s: %s\n", lane, outcome)
	}
}
