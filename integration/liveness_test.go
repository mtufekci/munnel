// Package integration: liveness and disconnect propagation.
//
// A tunnel whose client vanished without closing the socket (laptop asleep,
// NAT dropped) must be noticed and its name freed; the same token
// reconnecting must get its name back at once; a public viewer who leaves an
// SSE stream must close the stream on the developer's machine too; and a
// local app that never answers must produce a 504, not a hung request.
package integration

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mtufekci/munnel/internal/client"
	"github.com/mtufekci/munnel/internal/proto"
	"github.com/mtufekci/munnel/internal/server"
	"github.com/mtufekci/munnel/internal/token"
)

// rawHandshake completes the control handshake by hand and returns the live
// socket without running a mux session on it: to the server this is a
// client that went silent (it never reads, never answers pings).
func rawHandshake(t *testing.T, addr string, hello proto.Hello) (net.Conn, proto.Ack) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	hello.Type, hello.Version = proto.TypeHello, proto.ControlVersion
	if err := proto.WriteMessage(conn, hello); err != nil {
		t.Fatal(err)
	}
	var ack proto.Ack
	if err := proto.ReadMessage(bufio.NewReader(conn), &ack); err != nil {
		t.Fatal(err)
	}
	return conn, ack
}

// waitFor polls cond until it holds or the timeout passes.
func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %s", timeout, what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestLiveness_DeadPeerDetected(t *testing.T) {
	srv := startServerConfig(t, server.Config{
		MuxPingInterval: 50 * time.Millisecond,
		MuxIdleTimeout:  300 * time.Millisecond,
	})
	_, ack := rawHandshake(t, srv.ControlListener().Addr().String(), proto.Hello{Subdomain: "sleepy"})
	if !ack.OK || ack.Subdomain != "sleepy" {
		t.Fatalf("handshake: %+v", ack)
	}
	if srv.Registry().Get("sleepy") == nil {
		t.Fatal("tunnel not registered")
	}
	waitFor(t, 3*time.Second, "the silent session to be dropped", func() bool {
		return srv.Registry().Get("sleepy") == nil
	})

	// The name is free again.
	local := localOK()
	defer local.Close()
	if ok, _, msg := tryConnect(t, client.Config{LocalPort: serverPort(t, local.URL),
		ServerAddr: srv.ControlListener().Addr().String(), Subdomain: "sleepy"}); !ok {
		t.Fatalf("name not freed after the dead peer was dropped: %s", msg)
	}
}

// TestLiveness_IdleTunnelStaysUp: a healthy tunnel with no traffic survives
// many idle timeouts, because pings and pongs count as traffic both ways.
func TestLiveness_IdleTunnelStaysUp(t *testing.T) {
	srv := startServerConfig(t, server.Config{
		MuxPingInterval: 50 * time.Millisecond,
		MuxIdleTimeout:  300 * time.Millisecond,
	})
	local := localOK()
	defer local.Close()
	ok, _, msg := tryConnect(t, client.Config{
		LocalPort: serverPort(t, local.URL), ServerAddr: srv.ControlListener().Addr().String(),
		Subdomain: "idle", PingInterval: 50 * time.Millisecond, IdleTimeout: 300 * time.Millisecond,
	})
	if !ok {
		t.Fatal(msg)
	}
	first := srv.Registry().Get("idle")
	time.Sleep(1200 * time.Millisecond) // four idle timeouts
	if cur := srv.Registry().Get("idle"); cur == nil || cur.Session != first.Session {
		t.Fatal("healthy idle tunnel was dropped or reconnected")
	}
	if code, _, _ := doPublic(t, srv, "idle", "GET", "/", nil, nil); code != 200 {
		t.Fatalf("idle tunnel: %d", code)
	}
}

func TestLiveness_SameTokenTakesOverStaleSession(t *testing.T) {
	key := []byte("takeover-key")
	auth, err := server.NewAuthenticatorWith(server.AuthOptions{SigningKey: key})
	if err != nil {
		t.Fatal(err)
	}
	// Default 45s idle timeout; the session is stale after 1.5 ping intervals.
	srv := startServerConfig(t, server.Config{Auth: auth, MuxPingInterval: 100 * time.Millisecond})
	addr := srv.ControlListener().Addr().String()
	tok, _ := token.Mint(key, "hop", time.Hour)

	stale, ack := rawHandshake(t, addr, proto.Hello{Token: tok})
	if !ack.OK || ack.Subdomain != "hop" {
		t.Fatalf("handshake: %+v", ack)
	}
	waitFor(t, 3*time.Second, "the silent session to miss a heartbeat", func() bool {
		c := srv.Registry().Get("hop")
		return c != nil && c.Session.Stale()
	})

	local := localOK()
	defer local.Close()
	port := serverPort(t, local.URL)

	// Another token scoped to the same name is still refused: takeover is
	// only for the token that holds the name.
	other, _ := token.Mint(key, "hop", time.Hour)
	if ok, sub, msg := tryConnect(t, client.Config{LocalPort: port, ServerAddr: addr, Token: other}); ok {
		t.Fatalf("a different token took %q", sub)
	} else if !strings.Contains(msg, "in use") {
		t.Fatalf("unexpected refusal: %q", msg)
	}

	// The same token reconnecting gets the name at once, long before the
	// stale session would time out.
	start := time.Now()
	ok, sub, msg := tryConnect(t, client.Config{LocalPort: port, ServerAddr: addr, Token: tok})
	if !ok || sub != "hop" {
		t.Fatalf("same-token reconnect: ok=%v sub=%q msg=%q", ok, sub, msg)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("takeover took %s", time.Since(start))
	}

	// The server closed the stale session's socket.
	stale.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.Copy(io.Discard, stale); err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatal("stale session still open after takeover")
		}
	}
	if code, _, body := doPublic(t, srv, "hop", "GET", "/", nil, nil); code != 200 || string(body) != "ok" {
		t.Fatalf("traffic after takeover: %d %q", code, body)
	}
}

// TestLiveness_SameTokenCannotEvictLiveSession: whoever presents the token
// of a tunnel that is up and answering pings (someone who sniffed it on the
// plaintext control port, say) is refused, however often they retry; only a
// session that has gone quiet can be taken over.
func TestLiveness_SameTokenCannotEvictLiveSession(t *testing.T) {
	key := []byte("takeover-key")
	auth, err := server.NewAuthenticatorWith(server.AuthOptions{SigningKey: key})
	if err != nil {
		t.Fatal(err)
	}
	// Stale would mean 300 ms without a byte; a live peer is never quiet for
	// more than one 200 ms ping interval.
	srv := startServerConfig(t, server.Config{Auth: auth, MuxPingInterval: 200 * time.Millisecond})
	addr := srv.ControlListener().Addr().String()
	tok, _ := token.Mint(key, "hop", time.Hour)

	local := localOK()
	defer local.Close()
	if ok, sub, msg := tryConnect(t, client.Config{LocalPort: serverPort(t, local.URL), ServerAddr: addr,
		Token: tok, PingInterval: 200 * time.Millisecond}); !ok || sub != "hop" {
		t.Fatalf("owner: ok=%v sub=%q msg=%q", ok, sub, msg)
	}
	owner := srv.Registry().Get("hop")

	// Retry across several ping intervals, so an attempt lands at every
	// point of the owner's ping/pong cycle.
	for i := range 8 {
		_, ack := rawHandshake(t, addr, proto.Hello{Token: tok})
		if ack.OK || !strings.Contains(ack.Error, "in use") {
			t.Fatalf("attempt %d with the live owner's token: %+v", i, ack)
		}
		time.Sleep(60 * time.Millisecond)
	}
	if cur := srv.Registry().Get("hop"); cur == nil || cur.Session != owner.Session {
		t.Fatal("the live owner lost its name")
	}
	if code, _, body := doPublic(t, srv, "hop", "GET", "/", nil, nil); code != 200 || string(body) != "ok" {
		t.Fatalf("owner's tunnel after the attempts: %d %q", code, body)
	}
}

func TestProxy_ResponseHeaderTimeout(t *testing.T) {
	released := make(chan struct{})
	testDone := make(chan struct{}) // lets a failing test shut the app down
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/hang": // never answers; ends only when munnel drops the connection
			select {
			case <-r.Context().Done():
				close(released)
			case <-testDone:
			}
		case "/slow-body": // headers at once, body after the header timeout
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			time.Sleep(600 * time.Millisecond)
			io.WriteString(w, "late body")
		}
	}))
	defer local.Close()
	defer close(testDone)
	srv := startServerConfig(t, server.Config{ResponseHeaderTimeout: 300 * time.Millisecond})
	if ok, _, msg := tryConnect(t, client.Config{LocalPort: serverPort(t, local.URL),
		ServerAddr: srv.ControlListener().Addr().String(), Subdomain: "slow"}); !ok {
		t.Fatal(msg)
	}

	start := time.Now()
	code, _, _ := doPublic(t, srv, "slow", "GET", "/hang", nil, nil)
	if code != http.StatusGatewayTimeout {
		t.Fatalf("hanging app: got %d, want 504", code)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("504 took %s", d)
	}
	select {
	case <-released:
	case <-time.After(5 * time.Second):
		t.Fatal("the local request was left hanging after the 504")
	}

	// Only headers are bounded: a body that streams in later still arrives.
	code, _, body := doPublic(t, srv, "slow", "GET", "/slow-body", nil, nil)
	if code != 200 || string(body) != "late body" {
		t.Fatalf("slow body: %d %q", code, body)
	}
}

// TestDisconnect_PublicClientClosesLocalSSE: the app streams one event and
// then waits; only a closed connection ends its handler. When the public
// viewer disconnects, munnel must close the local connection within seconds
// and leave no mux stream behind.
func TestDisconnect_PublicClientClosesLocalSSE(t *testing.T) {
	localClosed := make(chan struct{})
	testDone := make(chan struct{}) // lets a failing test shut the app down
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		io.WriteString(w, "data: hello\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
			close(localClosed)
		case <-testDone:
		}
	}))
	defer local.Close()
	defer close(testDone)
	srv, _ := startServer(t, "")
	if ok, _, msg := tryConnect(t, client.Config{LocalPort: serverPort(t, local.URL),
		ServerAddr: srv.ControlListener().Addr().String(), Subdomain: "sse"}); !ok {
		t.Fatal(msg)
	}

	viewer := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	resp, err := viewer.Do(pubRequest(t, srv, "sse", "GET", "/events", nil))
	if err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(resp.Body).ReadString('\n')
	if err != nil || line != "data: hello\n" {
		t.Fatalf("first event: %q, %v", line, err)
	}
	resp.Body.Close() // the viewer leaves mid-stream (closes the connection)

	select {
	case <-localClosed:
	case <-time.After(5 * time.Second):
		t.Fatal("local SSE connection still open 5s after the viewer left")
	}
	waitFor(t, 3*time.Second, "the mux stream to be released", func() bool {
		c := srv.Registry().Get("sse")
		return c != nil && c.Session.StreamCount() == 0
	})
}
