// Package integration: extra base domains (--extra-domains).
//
// One tunnel namespace serves every configured base domain: the client that
// holds "foo" is reached at foo.<domain> and foo.<extra>. An extra domain's
// apex and www. belong to its owner and are never served or certified, and a
// name with no live tunnel is refused on an extra domain exactly as on the
// primary one.
package integration

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mtufekci/munnel/internal/client"
	"github.com/mtufekci/munnel/internal/proto"
	"github.com/mtufekci/munnel/internal/server"
)

// getHost sends GET / to the proxy with the given Host header.
func getHost(t *testing.T, srv *server.Server, host string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://"+srv.ProxyListener().Addr().String()+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = host
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestExtraDomains_RoutesToSameTunnel(t *testing.T) {
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "local saw "+r.Header.Get("X-Forwarded-Host"))
	}))
	defer local.Close()

	srv := startServerConfig(t, server.Config{
		Domain:       "tunnels.example.test",
		ExtraDomains: []string{"extra.test"},
		AskAddr:      "127.0.0.1:0",
	})
	tun, err := client.New(client.Config{
		LocalPort:  serverPort(t, local.URL),
		ServerAddr: srv.ControlListener().Addr().String(),
		Subdomain:  "foo",
		Inspect:    false,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tun.Run(ctx)
	deadline := time.After(5 * time.Second)
connecting:
	for {
		select {
		case e := <-tun.Events():
			switch e.Kind {
			case client.EventConnected:
				break connecting
			case client.EventDisconnected:
				t.Fatalf("tunnel rejected: %s", e.Message)
			}
		case <-deadline:
			t.Fatal("tunnel did not connect in time")
		}
	}
	// The URL reported to the client stays on the primary domain.
	if got := tun.Status().PublicURL; !strings.Contains(got, "foo.tunnels.example.test") {
		t.Errorf("public URL = %q, want it on the primary domain", got)
	}

	// Same tunnel on both domains; the local service sees the host asked for.
	for _, host := range []string{"foo.extra.test", "FOO.Extra.Test.", "foo.tunnels.example.test"} {
		code, body := getHost(t, srv, host)
		if code != http.StatusOK || body != "local saw "+host {
			t.Errorf("Host %q: %d (local service reached: %v), want 200 from the local service", host, code, strings.HasPrefix(body, "local saw"))
		}
	}

	// A name with no live tunnel is refused the same way on both domains.
	primaryCode, _ := getHost(t, srv, "ghost.tunnels.example.test")
	extraCode, extraBody := getHost(t, srv, "ghost.extra.test")
	if primaryCode != http.StatusBadGateway || extraCode != primaryCode {
		t.Errorf("ghost: primary %d, extra %d, want both %d", primaryCode, extraCode, http.StatusBadGateway)
	}
	if !strings.Contains(extraBody, "ghost.extra.test") {
		t.Errorf("offline page names the wrong host: %s", extraBody)
	}

	// The extra apex and www. never reach a tunnel, and are not certified.
	for _, host := range []string{"extra.test", "www.extra.test"} {
		if code, body := getHost(t, srv, host); code != http.StatusNotFound || strings.Contains(body, "local saw") {
			t.Errorf("Host %q: %d, want 404 unknown host", host, code)
		}
	}
	for domain, want := range map[string]int{
		"foo.extra.test":           http.StatusOK,
		"foo.tunnels.example.test": http.StatusOK,
		"tunnels.example.test":     http.StatusOK,
		"ghost.extra.test":         http.StatusForbidden,
		"extra.test":               http.StatusForbidden,
		"www.extra.test":           http.StatusForbidden,
		"a.foo.extra.test":         http.StatusForbidden,
		"foo.other.test":           http.StatusForbidden,
	} {
		if got := askStatus(t, srv, domain); got != want {
			t.Errorf("ask %q = %d, want %d", domain, got, want)
		}
	}

	// Disconnect: the extra name stops qualifying for a certificate too.
	cancel()
	waitFor(t, 3*time.Second, "tunnel unregistered", func() bool { return srv.Registry().Get("foo") == nil })
	if got := askStatus(t, srv, "foo.extra.test"); got != http.StatusForbidden {
		t.Errorf("ask after disconnect = %d, want %d", got, http.StatusForbidden)
	}
}

// TestExtraDomains_SuffixOverlap: with extra "example.test" below the primary
// "tunnels.example.test", the primary apex stays the landing page and is
// never read as tunnel "tunnels" of the extra domain, even while a client
// holds "tunnels".
func TestExtraDomains_SuffixOverlap(t *testing.T) {
	srv := startServerConfig(t, server.Config{
		Domain:       "tunnels.example.test",
		ExtraDomains: []string{"example.test"},
		AskAddr:      "127.0.0.1:0",
	})
	conn, ack := rawHandshake(t, srv.ControlListener().Addr().String(), proto.Hello{Subdomain: "tunnels"})
	if !ack.OK || ack.Subdomain != "tunnels" {
		t.Fatalf("handshake: %+v", ack)
	}
	defer conn.Close()

	code, body := getHost(t, srv, "tunnels.example.test")
	if code != http.StatusOK || !strings.Contains(body, "your localhost, on the public internet") {
		t.Errorf("primary apex: %d, want the landing page", code)
	}
	if code, _ := getHost(t, srv, "example.test"); code != http.StatusNotFound {
		t.Errorf("extra apex: %d, want 404", code)
	}
	if got := askStatus(t, srv, "example.test"); got != http.StatusForbidden {
		t.Errorf("ask extra apex = %d, want 403", got)
	}
}

// TestExtraDomains_InvalidConfigRefused: the server does not start with a
// bad extra-domain list.
func TestExtraDomains_InvalidConfigRefused(t *testing.T) {
	for _, extras := range [][]string{
		{"tunnels.example.test"}, // same as primary
		{"a.test", "a.test"},
		{"Extra.Test"},
		{"localhost"},
		{"*.extra.test"},
	} {
		if _, err := server.New(server.Config{Domain: "tunnels.example.test", ExtraDomains: extras}); err == nil {
			t.Errorf("New accepted extra domains %q", extras)
		}
	}
}
