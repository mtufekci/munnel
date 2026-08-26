// Package integration spins up a real munnel server, client, and local
// service on loopback and pushes real HTTP traffic through the tunnel.
package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mtufekci/munnel/internal/client"
	"github.com/mtufekci/munnel/internal/inspection"
	"github.com/mtufekci/munnel/internal/server"
)

// stack bundles a running server for one test.
func startServer(t *testing.T, tokens string) (*server.Server, context.CancelFunc) {
	t.Helper()
	auth, err := server.NewAuthenticator(tokens, "")
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
	return srv, cancel
}

// connectClient starts a tunnel client and waits for the connected event.
func connectClient(t *testing.T, srv *server.Server, port int, sub, token string) (*client.Tunnel, *inspection.Store, *inspection.Server, string) {
	t.Helper()
	controlAddr := srv.ControlListener().Addr().String()

	store := inspection.NewStore(0)
	hub := inspection.NewHub()

	tun, err := client.New(client.Config{
		LocalPort:   port,
		ServerAddr:  controlAddr,
		Subdomain:   sub,
		Token:       token,
		Inspect:     true,
		InspectAddr: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatal(err)
	}
	tun.OnRecord = func(rec *inspection.Record) {
		store.Add(rec)
		hub.BroadcastRecord(rec)
	}
	insp := inspection.New(store, hub, tun.Forwarder(), func() any { return tun.Status() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go tun.Run(ctx)

	inspErr := make(chan error, 1)
	go func() { inspErr <- insp.ListenAndServe(ctx, "127.0.0.1:0") }()

	if sub == "" {
		sub = "" // server assigns
	}

	// Wait for connection (or failure).
	timeout := time.After(10 * time.Second)
	for {
		select {
		case e := <-tun.Events():
			switch e.Kind {
			case client.EventConnected:
				st := tun.Status()
				if st.Subdomain == "" {
					t.Fatal("connected with empty subdomain")
				}
				return tun, store, insp, st.Subdomain
			case client.EventDisconnected, client.EventReconnecting:
				return nil, nil, nil, "" // caller inspects tunnel events itself for auth tests
			}
		case <-timeout:
			t.Fatal("client did not connect in time; tunnel events exhausted")
		}
	}
}

func publicURL(srv *server.Server, sub, path string) string {
	return fmt.Sprintf("http://%s%s", srv.ProxyListener().Addr().String(), path)
}

// doPublic performs a request against the proxy with a tunnel Host header.
func doPublic(t *testing.T, srv *server.Server, sub, method, path string, body io.Reader, hdr http.Header) (int, http.Header, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, publicURL(srv, sub, path), body)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = sub + ".localhost"
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, resp.Header, b
}

func TestTunnelRoundTrip(t *testing.T) {
	var hits atomic.Int64
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/json":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"hello":"munnel","path":%q}`, r.URL.Path)
		case "/echo":
			body, _ := io.ReadAll(r.Body)
			w.Header().Set("X-Echoed", "yes")
			w.Header().Set("X-Forwarded-Seen", r.Header.Get("X-Forwarded-Host"))
			w.WriteHeader(201)
			w.Write(body)
		case "/headers":
			json.NewEncoder(w).Encode(map[string]string{
				"xff":  r.Header.Get("X-Forwarded-For"),
				"host": r.Host,
			})
		default:
			w.Write([]byte("root ok"))
		}
	}))
	defer local.Close()
	port := serverPort(t, local.URL)

	srv, _ := startServer(t, "")
	tun, store, insp, sub := connectClient(t, srv, port, "test", "")

	// GET through the tunnel.
	code, _, body := doPublic(t, srv, sub, "GET", "/", nil, nil)
	if code != 200 || string(body) != "root ok" {
		t.Fatalf("GET /: got %d %q", code, body)
	}

	// GET json with query params.
	code, hdr, body := doPublic(t, srv, sub, "GET", "/json?x=1", nil, nil)
	if code != 200 || !strings.Contains(string(body), `"hello":"munnel"`) {
		t.Fatalf("GET /json: got %d %q", code, body)
	}
	if ct := hdr.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("content-type not relayed: %q", ct)
	}

	// POST echo: body integrity through both directions.
	payload := strings.Repeat(`{"event":"payment.succeeded","n":1}`, 500) // ~38 KB
	code, hdr, body = doPublic(t, srv, sub, "POST", "/echo", strings.NewReader(payload), http.Header{"Content-Type": {"application/json"}})
	if code != 201 {
		t.Fatalf("POST /echo: status %d (%q)", code, body)
	}
	if string(body) != payload {
		t.Fatalf("POST /echo: body mismatch (%d bytes)", len(body))
	}
	if hdr.Get("X-Echoed") != "yes" {
		t.Fatal("response header not relayed")
	}
	if hdr.Get("X-Forwarded-Seen") != sub+".localhost" {
		t.Fatalf("X-Forwarded-Host not seen locally: %q", hdr.Get("X-Forwarded-Seen"))
	}

	// Inspector captured all three requests.
	deadline := time.Now().Add(3 * time.Second)
	for store.Size() < 3 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	recs := store.List()
	if len(recs) != 3 {
		t.Fatalf("inspector store size = %d, want 3", len(recs))
	}
	var post *inspection.Record
	for _, r := range recs {
		if r.Method == "POST" {
			post = r
		}
		if r.Status == 0 && !r.Errored {
			t.Fatalf("record missing status: %+v", r)
		}
	}
	if post == nil || post.Status != 201 || string(post.ReqBody) != payload {
		t.Fatalf("POST capture wrong: %+v", post)
	}

	// Inspector HTTP API.
	inspectorAddr := waitInspectorAddr(t, insp)
	_ = inspectorAddr

	// Replay the webhook against localhost.
	before := hits.Load()
	replayReq, _ := http.NewRequest("POST", fmt.Sprintf("http://%s/api/replay/%d", inspectorAddr, post.ID), nil)
	replayResp, err := http.DefaultClient.Do(replayReq)
	if err != nil {
		t.Fatal(err)
	}
	replayBody, _ := io.ReadAll(replayResp.Body)
	replayResp.Body.Close()
	if replayResp.StatusCode != 200 {
		t.Fatalf("replay: %d %s", replayResp.StatusCode, replayBody)
	}
	if got := hits.Load(); got != before+1 {
		t.Fatalf("replay did not hit local service (hits %d → %d)", before, got)
	}
	var replayed inspection.Record
	if err := json.Unmarshal(replayBody, &replayed); err != nil {
		t.Fatal(err)
	}
	if !replayed.Replayed || replayed.Status != 201 {
		t.Fatalf("replay record wrong: %+v", replayed)
	}

	// Tunnel status endpoint reports the connection.
	st := tun.Status()
	if !st.Connected || st.PublicURL == "" || st.Subdomain != sub {
		t.Fatalf("bad status: %+v", st)
	}
}

func TestAutoAssignedSubdomain(t *testing.T) {
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hi"))
	}))
	defer local.Close()
	srv, _ := startServer(t, "")
	_, _, _, sub := connectClient(t, srv, serverPort(t, local.URL), "", "")
	if sub == "" || len(sub) < 4 {
		t.Fatalf("bad assigned subdomain %q", sub)
	}
	code, _, body := doPublic(t, srv, sub, "GET", "/", nil, nil)
	if code != 200 || string(body) != "hi" {
		t.Fatalf("auto-subdomain tunnel: %d %q", code, body)
	}
}

func TestSubdomainCollisionRejected(t *testing.T) {
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("x")) }))
	defer local.Close()
	srv, _ := startServer(t, "")
	connectClient(t, srv, serverPort(t, local.URL), "taken", "")

	// second client requesting the same subdomain must be rejected
	tun2, err := client.New(client.Config{
		LocalPort:   serverPort(t, local.URL),
		ServerAddr:  srv.ControlListener().Addr().String(),
		Subdomain:   "taken",
		Inspect:     false,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tun2.Run(ctx)

	deadline := time.Now().Add(5 * time.Second)
	for {
		select {
		case e := <-tun2.Events():
			if e.Kind == client.EventDisconnected {
				if !strings.Contains(e.Message, "in use") && !strings.Contains(e.Message, "rejected") {
					t.Fatalf("unexpected rejection: %q", e.Message)
				}
				return // pass
			}
			if e.Kind == client.EventConnected {
				t.Fatal("second client connected despite collision")
			}
		case <-time.After(10 * time.Millisecond):
			if time.Now().After(deadline) {
				t.Fatal("no rejection observed")
			}
		}
	}
}

func TestTokenAuth(t *testing.T) {
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("x")) }))
	defer local.Close()
	srv, _ := startServer(t, "goodtoken")

	// no token → rejected
	tunBad, err := client.New(client.Config{
		LocalPort: serverPort(t, local.URL), ServerAddr: srv.ControlListener().Addr().String(), Inspect: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tunBad.Run(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case e := <-tunBad.Events():
			if e.Kind == client.EventDisconnected {
				if !strings.Contains(e.Message, "token") {
					t.Fatalf("expected token rejection, got %q", e.Message)
				}
				goto rejected
			}
			if e.Kind == client.EventConnected {
				t.Fatal("connected without a token on a protected server")
			}
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
	t.Fatal("no auth rejection observed")
rejected:

	// right token → connects
	connectClient(t, srv, serverPort(t, local.URL), "auth-ok", "goodtoken")
}

func TestOfflineTunnelReturns502(t *testing.T) {
	srv, _ := startServer(t, "")
	code, _, _ := doPublic(t, srv, "ghost", "GET", "/", nil, nil)
	if code != http.StatusBadGateway {
		t.Fatalf("offline subdomain: got %d, want 502", code)
	}
}

func TestLandingAndHealthz(t *testing.T) {
	srv, _ := startServer(t, "")
	base := publicURL(srv, "", "")
	resp, err := http.Get(base + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), `"ok":true`) {
		t.Fatalf("healthz: %s", body)
	}
	resp, err = http.Get(base + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "munnel") {
		t.Fatalf("landing page missing branding (%d bytes)", len(body))
	}
}

func serverPort(t *testing.T, url string) int {
	t.Helper()
	var port int
	if _, err := fmt.Sscanf(url[strings.LastIndex(url, ":")+1:], "%d", &port); err != nil {
		t.Fatalf("parse port from %q: %v", url, err)
	}
	return port
}

func waitInspectorAddr(t *testing.T, insp *inspection.Server) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if a := insp.Addr(); a != "" {
			return a
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("inspector did not bind")
	return ""
}
