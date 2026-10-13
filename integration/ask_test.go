// Package integration: Caddy's on-demand TLS permission check.
//
// Caddy asks before obtaining a certificate for any *.<domain> name. Only the
// apex and a subdomain with a connected tunnel may get one; approving every
// name under the domain lets anyone make the server request certificates for
// made-up names and burn the domain's ACME rate limit.
package integration

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/mtufekci/munnel/internal/proto"
	"github.com/mtufekci/munnel/internal/server"
)

// askStatus queries the server's ask endpoint for domain.
func askStatus(t *testing.T, srv *server.Server, domain string) int {
	t.Helper()
	resp, err := http.Get("http://" + srv.AskListener().Addr().String() + "/check?domain=" + url.QueryEscape(domain))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestAsk_OnlyApexAndLiveTunnels(t *testing.T) {
	srv := startServerConfig(t, server.Config{
		Domain:  "tunnels.example.com",
		AskAddr: "127.0.0.1:0",
	})
	if srv.AskListener() == nil {
		t.Fatal("ask listener not started")
	}
	conn, ack := rawHandshake(t, srv.ControlListener().Addr().String(), proto.Hello{Subdomain: "live"})
	if !ack.OK || ack.Subdomain != "live" {
		t.Fatalf("handshake: %+v", ack)
	}

	for _, tc := range []struct {
		domain string
		want   int
	}{
		{"tunnels.example.com", http.StatusOK},
		{"www.tunnels.example.com", http.StatusOK},
		{"live.tunnels.example.com", http.StatusOK},
		{"LIVE.tunnels.example.com", http.StatusOK}, // Caddy may pass any case
		{"nobody.tunnels.example.com", http.StatusForbidden},
		{"a.live.tunnels.example.com", http.StatusForbidden},
		{"live.example.com", http.StatusForbidden},
		{"live.tunnels.example.com.evil.test", http.StatusForbidden},
		{"evil.test", http.StatusForbidden},
		{"", http.StatusForbidden},
	} {
		if got := askStatus(t, srv, tc.domain); got != tc.want {
			t.Errorf("ask %q = %d, want %d", tc.domain, got, tc.want)
		}
	}

	// The name stops qualifying the moment its tunnel goes away.
	conn.Close()
	waitFor(t, 3*time.Second, "tunnel unregistered", func() bool { return srv.Registry().Get("live") == nil })
	if got := askStatus(t, srv, "live.tunnels.example.com"); got != http.StatusForbidden {
		t.Errorf("ask after disconnect = %d, want %d", got, http.StatusForbidden)
	}
}

func TestAsk_OffByDefault(t *testing.T) {
	srv := startServerConfig(t, server.Config{})
	if srv.AskListener() != nil {
		t.Fatal("ask listener started without AskAddr")
	}
}
