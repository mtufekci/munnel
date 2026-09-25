// Package integration: shutdown regression tests for the tunnel client.
//
// These verify the client's Run/Events shutdown contract against a real
// in-process server:
//
//  1. Cancelling ctx while a tunnel is connected (idle) must make Run return
//     and close Events() — not block forever on the live mux session.
//  2. The same must hold with a request stream mid-flight: the ctx watcher in
//     connectOnce closes the socket so sess.Run unblocks independently of any
//     in-flight forwarder goroutine.
//  3. EventShuttingDown is emitted before the channel closes in the normal
//     (not-overloaded) case.
//
// Before the fix, connectOnce had no ctx hook: sess.Run blocked on the live
// socket, Run never reached its ctx.Err() check, Events() was never closed, and
// a non-interactive `for range tun.Events()` hung indefinitely.
package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mtufekci/munnel/internal/client"
	"github.com/mtufekci/munnel/internal/server"
)

// startTunnel stands up a server and one connected client, returning the
// tunnel, the server (for driving public requests), and a cancel func the
// caller uses to trigger shutdown. It blocks until the tunnel is connected.
func startTunnel(t *testing.T, localPort int, sub string) (*client.Tunnel, *server.Server, context.CancelFunc, <-chan error) {
	t.Helper()
	srv, _ := startServer(t, "")
	tun, err := client.New(client.Config{
		LocalPort:  localPort,
		ServerAddr: srv.ControlListener().Addr().String(),
		Subdomain:  sub,
		Inspect:    false,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- tun.Run(ctx) }()

	deadline := time.After(10 * time.Second)
	for {
		select {
		case e := <-tun.Events():
			if e.Kind == client.EventConnected {
				return tun, srv, cancel, runDone
			}
			if e.Kind == client.EventDisconnected {
				t.Fatalf("tunnel disconnected before connecting: %s", e.Message)
			}
		case <-deadline:
			t.Fatal("tunnel did not connect in time")
		}
	}
}

// assertRunReturnsAndClosesEvents cancels ctx and verifies, within a timeout,
// that Run returns with nil and Events() is closed. When expectShutdownEvent is
// true it also requires an EventShuttingDown before the close (safe in the
// low-traffic case where the 256-deep event buffer can't have dropped it).
func assertRunReturnsAndClosesEvents(t *testing.T, tun *client.Tunnel, cancel context.CancelFunc, runDone <-chan error, expectShutdownEvent bool) {
	t.Helper()
	cancel()

	runReturned := false
	eventsClosed := false
	shutdownSeen := false
	deadline := time.After(5 * time.Second)

	// eventsCh is nil'd once closed so the select stops spinning on a closed
	// (always-ready) channel and waits only for runDone.
	eventsCh := tun.Events()

	for !eventsClosed || !runReturned {
		select {
		case e, ok := <-eventsCh:
			if !ok {
				eventsClosed = true
				eventsCh = nil
				continue
			}
			if e.Kind == client.EventShuttingDown {
				shutdownSeen = true
			}
		case err := <-runDone:
			runReturned = true
			if err != nil {
				t.Fatalf("Run returned non-nil error: %v", err)
			}
		case <-deadline:
			t.Fatalf("shutdown timed out: eventsClosed=%v runReturned=%v shutdownSeen=%v",
				eventsClosed, runReturned, shutdownSeen)
		}
	}

	if expectShutdownEvent && !shutdownSeen {
		t.Fatal("Events() closed without an EventShuttingDown first")
	}
}

// TestShutdown_IdleSession is the core regression: a connected, idle tunnel must
// tear down when ctx is cancelled. Pre-fix this hung because sess.Run blocked on
// the live socket with no ctx watcher, so Run never returned and Events() was
// never closed.
func TestShutdown_IdleSession(t *testing.T) {
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer local.Close()

	tun, _, cancel, runDone := startTunnel(t, serverPort(t, local.URL), "idle")
	// No traffic: connect, then cancel. Require the shutdown event too — with
	// no traffic the event buffer cannot have dropped it.
	assertRunReturnsAndClosesEvents(t, tun, cancel, runDone, true)
}

// TestShutdown_MidStream cancels while a request stream is in flight. Run must
// still return promptly: the in-flight forwarder goroutine is independent of
// sess.Run, and closing the socket unblocks the mux read loop without waiting
// for the (still-hanging) local handler to respond.
func TestShutdown_MidStream(t *testing.T) {
	var entered atomic.Int64
	release := make(chan struct{})
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hang" {
			entered.Add(1)
			select {
			case <-release:
				w.Write([]byte("released"))
			case <-time.After(20 * time.Second):
				w.Write([]byte("timeout"))
			}
			return
		}
		w.Write([]byte("ok"))
	}))
	defer local.Close()
	defer close(release)

	tun, srv, cancel, runDone := startTunnel(t, serverPort(t, local.URL), "midstream")
	sub := tun.Status().Subdomain

	// Fire a hanging request through the public proxy so a stream is in flight.
	// Intentionally fire-and-forget: the request will not complete until
	// `release` is closed at teardown.
	go func() {
		doPublic(t, srv, sub, "GET", "/hang", nil, nil)
	}()

	// Wait until the local handler is actually blocking inside /hang.
	deadline := time.After(5 * time.Second)
	for entered.Load() == 0 {
		select {
		case <-time.After(10 * time.Millisecond):
		case <-deadline:
			t.Fatal("hanging request never reached the local handler")
		}
	}

	// Cancel while the stream is mid-flight. Do NOT require EventShuttingDown:
	// the event buffer may hold request events and shutdown emit is
	// best-effort by design; the channel-close contract is what matters.
	assertRunReturnsAndClosesEvents(t, tun, cancel, runDone, false)
}
