package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const enrollmentPort = "17005"
const enrollmentLife = 15 * time.Minute

type enrollmentGrant struct {
	Digest  string    `json:"digest"`
	Expires time.Time `json:"expires"`
	Used    bool      `json:"used"`
}

func (g *enrollmentGrant) consume(token string, now time.Time) error {
	if g.Used || !now.Before(g.Expires) {
		return errors.New("enrollment link expired or already used")
	}
	digest := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare([]byte(g.Digest), []byte(hex.EncodeToString(digest[:]))) != 1 {
		return errors.New("invalid enrollment token")
	}
	g.Used = true
	return nil
}

type siteSettings struct {
	UDP     bool   `json:"udp,omitempty"`
	Host    string `json:"host"`
	Bind    string `json:"bind"`
	Port    int    `json:"port"`
	AppPort int    `json:"app_port"`
}

type enrollmentRequest struct {
	FRP   []byte `json:"frp_csr"`
	Agent []byte `json:"agent_csr"`
}

type enrollmentReply struct {
	Site    siteSettings `json:"site"`
	FRP     []byte       `json:"frp_cert"`
	FRPCA   []byte       `json:"frp_ca"`
	Agent   []byte       `json:"agent_cert"`
	AgentCA []byte       `json:"management_ca"`
	Primary string       `json:"primary_token"`
	Standby string       `json:"standby_token"`
}

func keyPair() (*ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

func certificate(subject string, issuer *x509.Certificate, signer *ecdsa.PrivateKey, public *ecdsa.PublicKey, host string, usage x509.ExtKeyUsage, ttl time.Duration, ca bool) ([]byte, *x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: subject}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(ttl),
		IsCA: ca, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature}
	if ca {
		cert.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		cert.MaxPathLenZero = true
		issuer = cert
	} else {
		cert.ExtKeyUsage = []x509.ExtKeyUsage{usage}
	}
	if ip := net.ParseIP(host); ip != nil {
		cert.IPAddresses = []net.IP{ip}
	} else if host != "" {
		cert.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, issuer, public, signer)
	if err != nil {
		return nil, nil, err
	}
	actual, err := x509.ParseCertificate(der)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), actual, err
}

func loadCA(dir, name string) ([]byte, *x509.Certificate, *ecdsa.PrivateKey, error) {
	chain, err := os.ReadFile(filepath.Join(dir, name+".crt"))
	if err != nil {
		return nil, nil, nil, err
	}
	key, err := tls.LoadX509KeyPair(filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key"))
	if err != nil {
		return nil, nil, nil, err
	}
	signer, ok := key.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, nil, errors.New("invalid CA key type")
	}
	cert, err := x509.ParseCertificate(key.Certificate[0])
	return chain, cert, signer, err
}

func signEnrollment(dir, name string, csr []byte, host string, usage x509.ExtKeyUsage) ([]byte, []byte, error) {
	req, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		return nil, nil, err
	}
	if err := req.CheckSignature(); err != nil {
		return nil, nil, err
	}
	public, ok := req.PublicKey.(*ecdsa.PublicKey)
	if !ok || public.Curve != elliptic.P256() {
		return nil, nil, errors.New("enrollment requires P-256 keys")
	}
	ca, issuer, signer, err := loadCA(dir, name)
	if err != nil {
		return nil, nil, err
	}
	leaf, _, err := certificate("NEO Foreign", issuer, signer, public, host, usage, 365*24*time.Hour, false)
	return leaf, ca, err
}

func enrollmentHandler(admin, config string) http.Handler {
	var mutex sync.Mutex
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/join" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		mutex.Lock()
		defer mutex.Unlock()
		path := filepath.Join(admin, "grant.json")
		var g enrollmentGrant
		if readJSON(path, &g) != nil || g.consume(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), time.Now()) != nil {
			http.Error(w, "Enrollment link is invalid, expired, or already used", http.StatusUnauthorized)
			return
		}
		var in enrollmentRequest
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&in) != nil || decoder.Decode(new(any)) != io.EOF {
			http.Error(w, "Invalid enrollment request", http.StatusBadRequest)
			return
		}
		var out enrollmentReply
		var err error
		out.FRP, out.FRPCA, err = signEnrollment(admin, "frp-ca", in.FRP, "", x509.ExtKeyUsageClientAuth)
		if err != nil {
			http.Error(w, "Cannot issue credentials", http.StatusBadRequest)
			return
		}
		out.Agent, out.AgentCA, err = signEnrollment(admin, "management-ca", in.Agent, "127.0.0.1", x509.ExtKeyUsageServerAuth)
		if err != nil {
			http.Error(w, "Cannot issue credentials", http.StatusBadRequest)
			return
		}
		if readJSON(filepath.Join(admin, "site.json"), &out.Site) != nil {
			http.Error(w, "Iran configuration is unavailable", 500)
			return
		}
		for name, dst := range map[string]*string{"primary.token": &out.Primary, "standby.token": &out.Standby} {
			value, err := os.ReadFile(filepath.Join(config, "secrets", name))
			if err != nil {
				http.Error(w, "Iran configuration is unavailable", 500)
				return
			}
			*dst = strings.TrimSpace(string(value))
		}
		// Persist consumption before sending any credential.
		if atomicJSON(path, g) != nil {
			http.Error(w, "Cannot store enrollment state", 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(out)
	})
}

func serveEnrollment(ctx context.Context, admin, config string) error {
	key, err := tls.LoadX509KeyPair(filepath.Join(admin, "enrollment.crt"), filepath.Join(admin, "enrollment.key"))
	if err != nil {
		return err
	}
	var site siteSettings
	if err := readJSON(filepath.Join(admin, "site.json"), &site); err != nil {
		return err
	}
	var grant enrollmentGrant
	if err := readJSON(filepath.Join(admin, "grant.json"), &grant); err != nil {
		return err
	}
	if time.Until(grant.Expires) <= 0 {
		return errors.New("enrollment link expired")
	}
	ctx, cancel := context.WithDeadline(ctx, grant.Expires)
	defer cancel()
	listener, err := net.Listen("tcp", net.JoinHostPort("0.0.0.0", enrollmentPort))
	if err != nil {
		return err
	}
	server := http.Server{Handler: enrollmentHandler(admin, config), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{key}},
		ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 6 * time.Second, WriteTimeout: 6 * time.Second, MaxHeaderBytes: 4096}
	stop := context.AfterFunc(ctx, func() { _ = server.Close() })
	defer stop()
	err = server.ServeTLS(listener, "", "")
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func enroll(ctx context.Context, link string, req enrollmentRequest) (enrollmentReply, error) {
	var out enrollmentReply
	u, err := url.Parse(strings.TrimSpace(link))
	if err != nil || u.Scheme != "neo-tunnel" || u.User != nil || u.Fragment != "" || u.Path != "/join" || u.Hostname() == "" || u.Port() != enrollmentPort {
		return out, errors.New("invalid setup link")
	}
	q := u.Query()
	pin, err := hex.DecodeString(q.Get("pin"))
	token, tokenErr := hex.DecodeString(q.Get("token"))
	if err != nil || len(pin) != 32 || tokenErr != nil || len(token) != 32 {
		return out, errors.New("invalid enrollment token or fingerprint")
	}
	u.Scheme = "https"
	u.RawQuery = ""
	payload, err := json.Marshal(req)
	if err != nil {
		return out, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(payload))
	if err != nil {
		return out, err
	}
	request.Header.Set("Authorization", "Bearer "+q.Get("token"))
	request.Header.Set("Content-Type", "application/json")
	client := http.Client{Timeout: 8 * time.Second, CheckRedirect: noRedirect, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("missing enrollment certificate")
			}
			cert := state.PeerCertificates[0]
			sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
			if subtle.ConstantTimeCompare(sum[:], pin) != 1 || time.Now().Before(cert.NotBefore) || time.Now().After(cert.NotAfter) {
				return errors.New("enrollment certificate does not match the link")
			}
			return cert.VerifyHostname(u.Hostname())
		}},
	}}
	resp, err := client.Do(request)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("enrollment was rejected (HTTP %d); request a new link", resp.StatusCode)
	}
	if err := decodeJSON(io.LimitReader(resp.Body, 32768), &out); err != nil {
		return out, errors.New("invalid enrollment reply")
	}
	if out.Site.Host != u.Hostname() {
		return out, errors.New("enrollment reply selected a different Iran host")
	}
	return out, nil
}
