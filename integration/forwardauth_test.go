// Package integration: forward-auth (zero-trust) regression tests.
//
// A protected tunnel requires a viewer session before requests reach the local
// service. These verify: unprotected tunnels are unaffected on an FA-enabled
// server; a protected tunnel redirects unauthenticated viewers to the login
// flow; the stub login flow issues a cookie that grants access and injects
// X-Authenticated-User; a spoofed identity header is stripped; and a signed
// token with prot:true mandates protection without the client --protect flag.
package integration

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mtufekci/munnel/internal/client"
	"github.com/mtufekci/munnel/internal/forwardauth"
	"github.com/mtufekci/munnel/internal/server"
	"github.com/mtufekci/munnel/internal/token"
)

// startServerWithFA stands up a server with forward-auth enabled (open auth).
func startServerWithFA(t *testing.T, fa *forwardauth.Manager) *server.Server {
	t.Helper()
	auth, err := server.NewAuthenticator("", "")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := server.New(server.Config{
		Domain:       "localhost",
		ControlAddr:  "127.0.0.1:0",
		ProxyAddr:    "127.0.0.1:0",
		PublicScheme: "http",
		Auth:         auth,
		FA:           fa,
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

// connectT connects a tunnel (protect controls the --protect opt-in) and
// blocks until connected.
func connectT(t *testing.T, srv *server.Server, port int, sub string, protect bool) *client.Tunnel {
	t.Helper()
	tun, err := client.New(client.Config{
		LocalPort:   port,
		ServerAddr:  srv.ControlListener().Addr().String(),
		Subdomain:   sub,
		Protect:     protect,
		Inspect:     false,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go tun.Run(ctx)
	deadline := time.After(5 * time.Second)
	for {
		select {
		case e := <-tun.Events():
			if e.Kind == client.EventConnected {
				return tun
			}
			if e.Kind == client.EventDisconnected {
				t.Fatalf("tunnel rejected: %s", e.Message)
			}
		case <-deadline:
			t.Fatal("tunnel did not connect in time")
		}
	}
}

// pubRequest builds a request to the proxy with the subdomain Host header.
func pubRequest(t *testing.T, srv *server.Server, sub, method, path string, body io.Reader) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, "http://"+srv.ProxyListener().Addr().String()+path, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = sub + ".localhost"
	return req
}

// noRedirectClient returns a client that does not follow redirects.
func noRedirectClient() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

// echoUser is a local service that echoes the X-Authenticated-User header so
// the test can verify munnel injected it.
func echoUser() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "user=%s", r.Header.Get(forwardauth.UserHeader))
	}))
}

// TestForwardAuth_UnprotectedTunnelUnaffected: on an FA-enabled server, a
// tunnel that did NOT opt into --protect passes requests straight through.
func TestForwardAuth_UnprotectedTunnelUnaffected(t *testing.T) {
	fa := forwardauth.NewManager([]byte("k"), forwardauth.StubProvider{}, time.Hour)
	srv := startServerWithFA(t, fa)
	local := echoUser()
	defer local.Close()

	connectT(t, srv, serverPort(t, local.URL), "plain", false)

	code, _, body := doPublic(t, srv, "plain", "GET", "/", nil, nil)
	if code != 200 {
		t.Fatalf("unprotected tunnel: want 200, got %d", code)
	}
	if string(body) != "user=" {
		t.Fatalf("unprotected tunnel should see no user header, got %q", body)
	}
}

// TestForwardAuth_ProtectedRedirects: a protected tunnel with no session
// cookie redirects the viewer to the login flow (302 → /__munnel/login).
func TestForwardAuth_ProtectedRedirects(t *testing.T) {
	fa := forwardauth.NewManager([]byte("k"), forwardauth.StubProvider{}, time.Hour)
	srv := startServerWithFA(t, fa)
	local := echoUser()
	defer local.Close()

	connectT(t, srv, serverPort(t, local.URL), "prot", true)

	req := pubRequest(t, srv, "prot", "GET", "/secret", nil)
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("want 302 redirect, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/__munnel/login") {
		t.Fatalf("redirect should go to /__munnel/login, got %q", loc)
	}
	if !strings.Contains(loc, "return=%2Fsecret") {
		t.Fatalf("redirect should carry the return path, got %q", loc)
	}
}

// TestForwardAuth_LoginFlow: the full stub flow — POST to /__munnel/auth sets
// a cookie, the redirect to / carries it, and the local service sees the
// injected X-Authenticated-User.
func TestForwardAuth_LoginFlow(t *testing.T) {
	fa := forwardauth.NewManager([]byte("k"), forwardauth.StubProvider{}, time.Hour)
	srv := startServerWithFA(t, fa)
	local := echoUser()
	defer local.Close()

	connectT(t, srv, serverPort(t, local.URL), "flow", true)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	c := &http.Client{Jar: jar, Timeout: 5 * time.Second}

	form := url.Values{"user": {"alice@example.com"}, "return": {"/"}}
	req := pubRequest(t, srv, "flow", "POST", "/__munnel/auth", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.Do(req) // follows the 302 to /, carrying the session cookie
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("post-login request: want 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "user=alice@example.com" {
		t.Fatalf("local service should see the injected user, got %q", body)
	}
}

// TestForwardAuth_SpoofedHeaderStripped: a viewer who sets
// X-Authenticated-User on an unprotected tunnel cannot inject an identity —
// munnel strips it before proxying.
func TestForwardAuth_SpoofedHeaderStripped(t *testing.T) {
	fa := forwardauth.NewManager([]byte("k"), forwardauth.StubProvider{}, time.Hour)
	srv := startServerWithFA(t, fa)
	local := echoUser()
	defer local.Close()

	connectT(t, srv, serverPort(t, local.URL), "spoof", false)

	code, _, body := doPublic(t, srv, "spoof", "GET", "/", nil, http.Header{
		"X-Authenticated-User": {"attacker@example.com"},
	})
	if code != 200 {
		t.Fatalf("want 200, got %d", code)
	}
	if string(body) != "user=" {
		t.Fatalf("spoofed identity header should be stripped, got %q", body)
	}
}

// TestForwardAuth_TokenProtClaim: a signed token with prot:true mandates
// protection — the tunnel is protected even though the client did not pass
// --protect.
func TestForwardAuth_TokenProtClaim(t *testing.T) {
	key := []byte("fa-signing-key")
	fa := forwardauth.NewManager([]byte("session-key"), forwardauth.StubProvider{}, time.Hour)

	auth, err := server.NewAuthenticatorWith(server.AuthOptions{SigningKey: key})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := server.New(server.Config{
		Domain: "localhost", ControlAddr: "127.0.0.1:0", ProxyAddr: "127.0.0.1:0",
		PublicScheme: "http", Auth: auth, FA: fa,
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

	local := echoUser()
	defer local.Close()

	protTok, _ := token.MintWith(key, token.MintOpts{Sub: "claimed", TTL: time.Hour, Prot: true})
	tun, err := client.New(client.Config{
		LocalPort: serverPort(t, local.URL), ServerAddr: srv.ControlListener().Addr().String(),
		Subdomain: "claimed", Token: protTok, Protect: false, Inspect: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	runCtx, runCancel := context.WithCancel(context.Background())
	t.Cleanup(runCancel)
	go tun.Run(runCtx)
	deadline := time.After(5 * time.Second)
	for {
		select {
		case e := <-tun.Events():
			if e.Kind == client.EventConnected {
				goto connected
			}
			if e.Kind == client.EventDisconnected {
				t.Fatalf("prot-claim tunnel rejected: %s", e.Message)
			}
		case <-deadline:
			t.Fatal("prot-claim tunnel did not connect")
		}
	}
connected:
	// No cookie → must redirect (protection is mandated by the token).
	req := pubRequest(t, srv, "claimed", "GET", "/", nil)
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("prot-claim tunnel should redirect without a session, got %d", resp.StatusCode)
	}
}