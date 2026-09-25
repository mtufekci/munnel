// Package integration: TLS control port and reserved names.
//
// The TLS listener runs beside the plaintext one; a client with --tls must
// verify the server (system roots, a private CA, or an exact certificate
// pin) and refuse anything else. Reserved names are claimable only by their
// listed signed tokens, only over TLS, and self-service enrollment never
// mints a token for one.
package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mtufekci/munnel/internal/client"
	"github.com/mtufekci/munnel/internal/server"
	"github.com/mtufekci/munnel/internal/token"
)

// selfSignedCert returns a certificate for 127.0.0.1/localhost that is its
// own CA, so tests can trust it through a private root pool.
func selfSignedCert(t *testing.T) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "munnel test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, leaf
}

// startServerConfig starts a server from cfg, filling loopback test defaults.
func startServerConfig(t *testing.T, cfg server.Config) *server.Server {
	t.Helper()
	if cfg.Domain == "" {
		cfg.Domain = "localhost"
	}
	if cfg.ControlAddr == "" {
		cfg.ControlAddr = "127.0.0.1:0"
	}
	if cfg.ProxyAddr == "" {
		cfg.ProxyAddr = "127.0.0.1:0"
	}
	if cfg.PublicScheme == "" {
		cfg.PublicScheme = "http"
	}
	srv, err := server.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Bind(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go srv.ListenAndServe(ctx)
	t.Cleanup(cancel)
	return srv
}

// tryConnect runs a tunnel with cfg until the server accepts or refuses it.
// An accepted tunnel keeps running until the test ends.
func tryConnect(t *testing.T, cfg client.Config) (ok bool, sub, msg string) {
	t.Helper()
	tun, err := client.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go tun.Run(ctx)
	deadline := time.After(5 * time.Second)
	for {
		select {
		case e := <-tun.Events():
			switch e.Kind {
			case client.EventConnected:
				t.Cleanup(cancel)
				return true, tun.Status().Subdomain, ""
			case client.EventDisconnected:
				cancel()
				return false, "", e.Message
			}
		case <-deadline:
			cancel()
			t.Fatal("client neither connected nor was refused in time")
		}
	}
}

func TestTLS_ControlPort(t *testing.T) {
	cert, leaf := selfSignedCert(t)
	srv := startServerConfig(t, server.Config{
		ControlTLSAddr: "127.0.0.1:0",
		ControlTLS:     &tls.Config{Certificates: []tls.Certificate{cert}},
	})
	if srv.ControlTLSListener() == nil {
		t.Fatal("TLS control listener not started")
	}
	tlsAddr := srv.ControlTLSListener().Addr().String()
	local := localOK()
	defer local.Close()
	port := serverPort(t, local.URL)

	sum := sha256.Sum256(leaf.Raw)
	pin := hex.EncodeToString(sum[:])
	wrong := sum
	wrong[0] ^= 0xff
	roots := x509.NewCertPool()
	roots.AddCert(leaf)

	cases := []struct {
		name    string
		tune    func(*client.Config)
		wantOK  bool
		wantMsg string
	}{
		{"pinned certificate", func(c *client.Config) { c.ServerCertSHA256 = pin }, true, ""},
		{"wrong pin refused", func(c *client.Config) { c.ServerCertSHA256 = hex.EncodeToString(wrong[:]) }, false, "does not match the pinned"},
		{"unknown CA refused by the system roots", func(c *client.Config) {}, false, "certificate"},
		{"trusted CA with hostname check", func(c *client.Config) { c.RootCAs = roots }, true, ""},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sub := "tls" + string(rune('a'+i))
			cfg := client.Config{LocalPort: port, ServerAddr: tlsAddr, Subdomain: sub, TLS: true}
			tc.tune(&cfg)
			ok, got, msg := tryConnect(t, cfg)
			if ok != tc.wantOK {
				t.Fatalf("connected=%v (%s), want %v", ok, msg, tc.wantOK)
			}
			if !ok {
				if !strings.Contains(msg, tc.wantMsg) {
					t.Fatalf("refusal %q should mention %q", msg, tc.wantMsg)
				}
				return
			}
			if got != sub {
				t.Fatalf("subdomain = %q, want %q", got, sub)
			}
			code, _, body := doPublic(t, srv, sub, "GET", "/", nil, nil)
			if code != 200 || string(body) != "ok" {
				t.Fatalf("request over the TLS tunnel: %d %q", code, body)
			}
		})
	}

	// A plaintext client on the TLS port fails the handshake instead of
	// talking cleartext to it.
	ok, _, _ := tryConnect(t, client.Config{LocalPort: port, ServerAddr: tlsAddr, Subdomain: "plain-on-tls"})
	if ok {
		t.Fatal("plaintext client connected to the TLS port")
	}
}

func TestReserved_OnlyItsTokenOverTLS(t *testing.T) {
	key := []byte("reserved-integration-key")
	hopTok, _ := token.Mint(key, "hop", 8760*time.Hour)
	squatter, _ := token.Mint(key, "hop", time.Hour) // same sub claim, not listed
	unscoped, _ := token.Mint(key, "", time.Hour)

	reservedFile := filepath.Join(t.TempDir(), "reserved")
	os.WriteFile(reservedFile, []byte("# name tokenID[,tokenID]\nhop "+token.IDOf(hopTok)+"\n"), 0o600)
	auth, err := server.NewAuthenticatorWith(server.AuthOptions{
		Tokens:       "static-token",
		SigningKey:   key,
		ReservedFile: reservedFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	cert, leaf := selfSignedCert(t)
	srv := startServerConfig(t, server.Config{
		Auth:           auth,
		EnrollPassword: "enrollpw",
		ControlTLSAddr: "127.0.0.1:0",
		ControlTLS:     &tls.Config{Certificates: []tls.Certificate{cert}},
	})
	plainAddr := srv.ControlListener().Addr().String()
	tlsAddr := srv.ControlTLSListener().Addr().String()
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	local := localOK()
	defer local.Close()
	port := serverPort(t, local.URL)

	overTLS := func(tok, sub string) client.Config {
		return client.Config{LocalPort: port, ServerAddr: tlsAddr, TLS: true, RootCAs: roots, Token: tok, Subdomain: sub}
	}
	refusals := []struct {
		name    string
		cfg     client.Config
		wantMsg string
	}{
		{"its own token over plaintext", client.Config{LocalPort: port, ServerAddr: plainAddr, Token: hopTok}, "TLS"},
		{"another token scoped to the name", overTLS(squatter, ""), "reserved"},
		{"unscoped signed token asking for it", overTLS(unscoped, "hop"), "reserved"},
		{"static token asking for it", overTLS("static-token", "hop"), "reserved"},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			if ok, sub, msg := tryConnect(t, tc.cfg); ok {
				t.Fatalf("claimed %q, want refusal", sub)
			} else if !strings.Contains(msg, tc.wantMsg) {
				t.Fatalf("refusal %q should mention %q", msg, tc.wantMsg)
			}
		})
	}

	// Enrollment never mints a token for a reserved name (any spelling).
	for _, sub := range []string{"hop", "HOP", " hop "} {
		status, out := postToken(t, srv, sub, "enrollpw", "")
		if status != http.StatusForbidden || out["token"] != nil {
			t.Fatalf("enroll %q: status %d out %v, want 403 and no token", sub, status, out)
		}
	}
	if status, _ := postToken(t, srv, "hop2", "enrollpw", ""); status != http.StatusOK {
		t.Fatalf("unreserved enrollment broke: %d", status)
	}

	// The listed token over TLS gets the name, and traffic flows.
	ok, sub, msg := tryConnect(t, overTLS(hopTok, ""))
	if !ok || sub != "hop" {
		t.Fatalf("reserved owner over TLS: ok=%v sub=%q msg=%q", ok, sub, msg)
	}
	if code, _, body := doPublic(t, srv, "hop", "GET", "/", nil, nil); code != 200 || string(body) != "ok" {
		t.Fatalf("reserved tunnel: %d %q", code, body)
	}

	// Unreserved names are unaffected on the plaintext port.
	if ok, _, msg := tryConnect(t, client.Config{LocalPort: port, ServerAddr: plainAddr, Token: unscoped, Subdomain: "free"}); !ok {
		t.Fatalf("unreserved name over plaintext refused: %s", msg)
	}
}

// countWriter counts server log lines that contain match.
type countWriter struct {
	match string
	n     atomic.Int32
}

func (w *countWriter) Write(p []byte) (int, error) {
	if strings.Contains(string(p), w.match) {
		w.n.Add(1)
	}
	return len(p), nil
}

// TestReserved_PlaintextRefusalNotRetried: the server can refuse a reserved
// name over plaintext only after the hello, token included, has arrived. A
// client pointed at the plaintext port must then stay down instead of
// resending that token in the clear on every reconnect.
func TestReserved_PlaintextRefusalNotRetried(t *testing.T) {
	key := []byte("reserved-integration-key")
	hopTok, _ := token.Mint(key, "hop", time.Hour)
	auth, err := server.NewAuthenticatorWith(server.AuthOptions{
		SigningKey: key,
		Reserved:   "hop " + token.IDOf(hopTok),
	})
	if err != nil {
		t.Fatal(err)
	}
	attempts := &countWriter{match: "reserved for TLS"}
	srv := startServerConfig(t, server.Config{Auth: auth, Logger: log.New(attempts, "", 0)})
	local := localOK()
	defer local.Close()

	tun, err := client.New(client.Config{LocalPort: serverPort(t, local.URL),
		ServerAddr: srv.ControlListener().Addr().String(), Token: hopTok})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ran := make(chan struct{})
	go func() { tun.Run(ctx); close(ran) }()

	var refusal string
	deadline := time.After(5 * time.Second)
	for refusal == "" {
		select {
		case e := <-tun.Events():
			switch e.Kind {
			case client.EventConnected:
				t.Fatal("reserved name granted over plaintext")
			case client.EventDisconnected:
				refusal = e.Message
			}
		case <-deadline:
			t.Fatal("client neither connected nor was refused in time")
		}
	}
	if !strings.Contains(refusal, "reserved for TLS") || !strings.Contains(refusal, "not retrying") {
		t.Fatalf("refusal %q should say the name needs TLS and that the client stopped", refusal)
	}

	// The first reconnect would come after one second of backoff.
	quiet := time.After(1500 * time.Millisecond)
	for waiting := true; waiting; {
		select {
		case e := <-tun.Events():
			if e.Kind == client.EventConnecting || e.Kind == client.EventReconnecting {
				t.Fatalf("client retried after a TLS-required refusal: %s", e.Message)
			}
		case <-quiet:
			waiting = false
		}
	}
	if n := attempts.n.Load(); n != 1 {
		t.Fatalf("server received the token over plaintext %d times, want 1", n)
	}

	cancel()
	select {
	case <-ran:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}
