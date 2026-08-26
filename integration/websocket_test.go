// Package integration: WebSocket tunnel regression test.
//
// A real gorilla/websocket client dials through the munnel server's public
// ingress; the upgrade is hijacked on the server side, piped raw through a
// mux stream, and the client dials the local WS echo server the same way.
// Text + binary frames round-trip in both directions and a clean WS close
// tears the stream down without hanging the tunnel.
//
// Pre-fix, proxyTo returned 501 for any Upgrade request, so the Dial failed
// immediately — this test cannot pass without the hijack+pipe path.
package integration

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// TestWebSocket_TunnelEcho is the core WebSocket regression: a full
// client→server→tunnel→client→local WS round-trip with real frames.
func TestWebSocket_TunnelEcho(t *testing.T) {
	upgrader := websocket.Upgrader{
		// The tunnel rewrites Host to the local addr; don't reject on Origin.
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		for {
			mt, msg, err := c.ReadMessage()
			if err != nil {
				return // peer closed (or errored) — stop echoing
			}
			if err := c.WriteMessage(mt, msg); err != nil {
				return
			}
		}
	}))
	defer local.Close()

	tun, srv, cancel, runDone := startTunnel(t, serverPort(t, local.URL), "ws")
	sub := tun.Status().Subdomain
	proxyAddr := srv.ProxyListener().Addr().String()

	// Dial the tunnel's public URL: TCP goes to the proxy listener, but the
	// Host header is the subdomain so the server routes into the tunnel
	// (mirroring a real browser hitting sub.<domain> over Caddy on 443).
	dialer := &websocket.Dialer{
		NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.Dial("tcp", proxyAddr)
		},
		HandshakeTimeout: 5 * time.Second,
	}
	u := url.URL{Scheme: "ws", Host: sub + ".localhost", Path: "/"}
	wsc, resp, err := dialer.DialContext(context.Background(), u.String(), nil)
	if err != nil {
		t.Fatalf("WS dial through tunnel failed: %v (status=%d)", err, wsStatus(resp))
	}
	defer wsc.Close()

	// Round-trip several text frames — proves both the request (browser→local)
	// and response (local→browser) directions carry WS frames end to end.
	texts := []string{"hello munnel", "second message", "third ✮"}
	for _, msg := range texts {
		if err := wsc.WriteMessage(websocket.TextMessage, []byte(msg)); err != nil {
			t.Fatalf("write %q: %v", msg, err)
		}
		mt, got, err := wsc.ReadMessage()
		if err != nil {
			t.Fatalf("read after %q: %v", msg, err)
		}
		if mt != websocket.TextMessage {
			t.Fatalf("want text frame for %q, got opcode %d", msg, mt)
		}
		if string(got) != msg {
			t.Fatalf("echo mismatch: want %q, got %q", msg, string(got))
		}
	}

	// A binary frame with non-UTF8 bytes — proves the raw pipe isn't
	// mangling content the way a text-only HTTP path would.
	bin := []byte{0, 1, 2, 3, 0xff, 0xfe, 0x00, 0x7f}
	if err := wsc.WriteMessage(websocket.BinaryMessage, bin); err != nil {
		t.Fatalf("write binary: %v", err)
	}
	mt, got, err := wsc.ReadMessage()
	if err != nil {
		t.Fatalf("read binary: %v", err)
	}
	if mt != websocket.BinaryMessage {
		t.Fatalf("want binary frame, got opcode %d", mt)
	}
	if string(got) != string(bin) {
		t.Fatalf("binary echo mismatch: want %d bytes, got %d", len(bin), len(got))
	}

	// Clean close: the client sends a WS close frame; the pipe must tear down
	// on both ends without hanging the tunnel session.
	_ = wsc.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err := wsc.WriteMessage(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, "bye")); err != nil {
		t.Fatalf("write close: %v", err)
	}
	if _, _, err := wsc.ReadMessage(); err == nil {
		t.Fatal("expected a close/error after CloseMessage, got a clean read")
	}

	// The tunnel session itself is unaffected by the WS close — shutting it
	// down now must return cleanly (not hang on a half-open pipe).
	assertRunReturnsAndClosesEvents(t, tun, cancel, runDone, false)
}

func wsStatus(r *http.Response) int {
	if r == nil {
		return 0
	}
	defer r.Body.Close()
	return r.StatusCode
}