// Package integration: signed, scoped token auth regression tests.
//
// These drive the real server+client handshake with HMAC-signed tokens
// (package token): a scoped token must bind to its subdomain, a wrong
// subdomain must be rejected, a revoked token must be rejected, a tampered
// token must be rejected, and static tokens must still work alongside signed
// ones (backward compatibility).
package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mtufekci/munnel/internal/client"
	"github.com/mtufekci/munnel/internal/server"
	"github.com/mtufekci/munnel/internal/token"
)

// startServerWithAuth stands up a server with the given auth options.
func startServerWithAuth(t *testing.T, opts server.AuthOptions) *server.Server {
	t.Helper()
	auth, err := server.NewAuthenticatorWith(opts)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := server.New(server.Config{
		Domain:       "localhost",
		ControlAddr:  "127.0.0.1:0",
		ProxyAddr:    "127.0.0.1:0",
		PublicScheme: "http",
		Auth:         auth,
	})
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

// connectSigned attempts a tunnel connection and reports whether the server
// accepted it. On success it returns the assigned subdomain; on rejection the
// server's error message.
func connectSigned(t *testing.T, srv *server.Server, port int, sub, tok string) (ok bool, subdomain, msg string) {
	t.Helper()
	tun, err := client.New(client.Config{
		LocalPort:  port,
		ServerAddr: srv.ControlListener().Addr().String(),
		Subdomain:  sub,
		Token:      tok,
		Inspect:    false,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tun.Run(ctx)
	deadline := time.After(5 * time.Second)
	for {
		select {
		case e := <-tun.Events():
			switch e.Kind {
			case client.EventConnected:
				return true, tun.Status().Subdomain, ""
			case client.EventDisconnected:
				return false, "", e.Message
			}
		case <-deadline:
			t.Fatal("client did not connect or get rejected in time")
		}
	}
}

func localOK() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
}

// TestSignedToken_ScopedSubdomain: a token signed for "alice" must connect on
// the alice subdomain and be rejected for any other.
func TestSignedToken_ScopedSubdomain(t *testing.T) {
	key := []byte("integration-signing-key")
	local := localOK()
	defer local.Close()
	srv := startServerWithAuth(t, server.AuthOptions{SigningKey: key})

	tok, _ := token.Mint(key, "alice", time.Hour)

	// No explicit sub requested → the token's claim is used.
	if ok, sub, msg := connectSigned(t, srv, serverPort(t, local.URL), "", tok); !ok {
		t.Fatalf("scoped token rejected: %s", msg)
	} else if sub != "alice" {
		t.Fatalf("subdomain: want alice, got %q", sub)
	}

	// Explicit matching sub → ok.
	if ok, _, msg := connectSigned(t, srv, serverPort(t, local.URL), "alice", tok); !ok {
		t.Fatalf("matching sub rejected: %s", msg)
	}

	// Wrong sub → the token's claim overrides the request (scoping enforced
	// by assignment, consistent with static reserved tokens): the client gets
	// "alice", never "bob".
	if ok, sub, msg := connectSigned(t, srv, serverPort(t, local.URL), "bob", tok); !ok {
		t.Fatalf("scoped token rejected on mismatched request: %s", msg)
	} else if sub != "alice" {
		t.Fatalf("scoped token should override to alice, got %q", sub)
	}
}

// TestSignedToken_AnySubdomain: a token with no sub claim may claim any free
// subdomain (the server still validates the name).
func TestSignedToken_AnySubdomain(t *testing.T) {
	key := []byte("k")
	local := localOK()
	defer local.Close()
	srv := startServerWithAuth(t, server.AuthOptions{SigningKey: key})

	tok, _ := token.Mint(key, "", time.Hour)
	if ok, sub, msg := connectSigned(t, srv, serverPort(t, local.URL), "freepick", tok); !ok {
		t.Fatalf("no-claim token rejected: %s", msg)
	} else if sub != "freepick" {
		t.Fatalf("subdomain: want freepick, got %q", sub)
	}
}

// TestSignedToken_Revoked: a token whose ID is in the revoked file is rejected
// even though its signature and expiry are valid.
func TestSignedToken_Revoked(t *testing.T) {
	key := []byte("k")
	local := localOK()
	defer local.Close()

	tok, _ := token.Mint(key, "alice", time.Hour)
	id := token.IDOf(tok)

	revokedPath := filepath.Join(t.TempDir(), "revoked")
	if err := os.WriteFile(revokedPath, []byte("# revoked\n"+id+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := startServerWithAuth(t, server.AuthOptions{SigningKey: key, RevokedFile: revokedPath})

	if ok, _, msg := connectSigned(t, srv, serverPort(t, local.URL), "alice", tok); ok {
		t.Fatal("revoked token was accepted")
	} else if !strings.Contains(msg, "revoke") {
		t.Fatalf("rejection should mention revocation, got %q", msg)
	}
}

// TestSignedToken_Tampered: a token with a corrupted signature is rejected.
func TestSignedToken_Tampered(t *testing.T) {
	key := []byte("k")
	local := localOK()
	defer local.Close()
	srv := startServerWithAuth(t, server.AuthOptions{SigningKey: key})

	tok, _ := token.Mint(key, "alice", time.Hour)
	body := tok[len(token.Prefix):]
	dot := strings.IndexByte(body, '.')
	sig := body[dot+1:]
	// Flip the first signature char: the last one's low bits are base64
	// padding the decoder ignores, so changing it left ~5% of tokens valid.
	alt := byte('A')
	if sig[0] == 'A' {
		alt = 'B'
	}
	tampered := token.Prefix + body[:dot+1] + string(alt) + sig[1:]

	if ok, _, _ := connectSigned(t, srv, serverPort(t, local.URL), "alice", tampered); ok {
		t.Fatal("tampered token was accepted")
	}
}

// TestSignedToken_StaticCoexists: signed and static tokens work side by side,
// and the server is NOT open when either is configured.
func TestSignedToken_StaticCoexists(t *testing.T) {
	key := []byte("k")
	local := localOK()
	defer local.Close()
	srv := startServerWithAuth(t, server.AuthOptions{SigningKey: key, Tokens: "statictok"})

	// Signed token works.
	stok, _ := token.Mint(key, "alice", time.Hour)
	if ok, _, msg := connectSigned(t, srv, serverPort(t, local.URL), "alice", stok); !ok {
		t.Fatalf("signed token rejected on mixed server: %s", msg)
	}

	// Static token works (no reservation → any free sub).
	if ok, _, msg := connectSigned(t, srv, serverPort(t, local.URL), "statik", "statictok"); !ok {
		t.Fatalf("static token rejected on mixed server: %s", msg)
	}

	// No token → rejected (not open mode).
	if ok, _, _ := connectSigned(t, srv, serverPort(t, local.URL), "nope", ""); ok {
		t.Fatal("connected without a token on a server with auth configured")
	}
}
