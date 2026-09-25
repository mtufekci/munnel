package client

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/mtufekci/munnel/internal/mux"
)

// Default control ports: plaintext and TLS.
const (
	DefaultControlPort    = "7001"
	DefaultControlTLSPort = "7002"
)

// DefaultInspectAddr keeps the inspector on loopback: it can replay requests
// against the local app, so it must not be reachable from the network.
const DefaultInspectAddr = "127.0.0.1:4040"

// Config holds client settings.
type Config struct {
	LocalPort   int    // local service port, e.g. 3000
	LocalHost   string // default "127.0.0.1"
	ServerAddr  string // control server "host:port", e.g. "tunnels.example.com:7001"
	Subdomain   string // requested subdomain; "" = server picks
	Token       string // auth token for protected servers
	Protect     bool   // opt the tunnel into forward-auth (viewers must log in)
	Inspect     bool   // run the web inspector
	InspectAddr string // inspector listen addr, default "127.0.0.1:4040"
	MaxBody     int64  // per-request body cap in bytes (matches server side)

	// TLS dials the server's TLS control port (default port 7002) and
	// verifies its certificate against the system roots (or RootCAs).
	TLS bool
	// ServerCertSHA256 pins the server's leaf certificate: hex SHA-256 of its
	// DER bytes (colons allowed). With a pin the exact certificate must match
	// and the CA chain is not consulted, so a self-signed server works too.
	// A Let's Encrypt certificate changes at every renewal (~60 days), and so
	// does its pin. Requires TLS.
	ServerCertSHA256 string
	// RootCAs replaces the system roots for TLS verification (tests, private
	// CAs). Nil means the system roots.
	RootCAs *x509.CertPool

	// PingInterval / IdleTimeout tune tunnel liveness (mux defaults when zero).
	PingInterval time.Duration
	IdleTimeout  time.Duration

	pin []byte // decoded ServerCertSHA256
}

// Validate checks the config and fills defaults.
func (c *Config) Validate() error {
	if c.LocalPort <= 0 || c.LocalPort > 65535 {
		return fmt.Errorf("invalid local port %d", c.LocalPort)
	}
	if c.LocalHost == "" {
		c.LocalHost = "127.0.0.1"
	}
	if c.ServerAddr == "" {
		return fmt.Errorf("no server address (use --server host:7001)")
	}
	if !strings.Contains(c.ServerAddr, ":") {
		port := DefaultControlPort
		if c.TLS {
			port = DefaultControlTLSPort
		}
		c.ServerAddr += ":" + port
	}
	if c.ServerCertSHA256 != "" {
		if !c.TLS {
			return errors.New("--server-cert-sha256 needs --tls")
		}
		pin, err := hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(c.ServerCertSHA256), ":", ""))
		if err != nil || len(pin) != sha256.Size {
			return errors.New("--server-cert-sha256 must be 64 hex characters (SHA-256 of the certificate DER)")
		}
		c.pin = pin
	}
	if c.InspectAddr == "" {
		c.InspectAddr = DefaultInspectAddr
	}
	if c.MaxBody <= 0 {
		c.MaxBody = 32 << 20
	}
	return nil
}

// tlsConfig builds the client TLS settings for the control connection.
func (c *Config) tlsConfig() *tls.Config {
	host, _, err := net.SplitHostPort(c.ServerAddr)
	if err != nil {
		host = c.ServerAddr
	}
	tc := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, RootCAs: c.RootCAs}
	if len(c.pin) > 0 {
		pin := c.pin
		// The pin names one exact certificate, a stricter check than any CA
		// chain, so chain verification is replaced rather than stacked (which
		// also lets a self-signed server be pinned). VerifyConnection runs on
		// every handshake, resumed ones included.
		tc.InsecureSkipVerify = true
		tc.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("server sent no certificate")
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(sum[:], pin) != 1 {
				return fmt.Errorf("server certificate sha256 %x does not match the pinned %x", sum, pin)
			}
			return nil
		}
	}
	return tc
}

// tuneSession applies the liveness settings to a new session.
func (c *Config) tuneSession(s *mux.Session) {
	s.PingInterval = c.PingInterval
	s.IdleTimeout = c.IdleTimeout
}
