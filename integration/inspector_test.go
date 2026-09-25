// Package integration: inspector access control.
//
// The inspector holds captured traffic and can replay it against the local
// app, so it refuses any Host but its own loopback address (DNS rebinding),
// any foreign Origin, and any request without the per-launch token. The
// browser gets the token from the printed link once; a cookie carries it
// from then on, including on the websocket feed.
package integration

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"

	"github.com/gorilla/websocket"

	"github.com/mtufekci/munnel/internal/inspection"
)

func startInspector(t *testing.T) (*inspection.Server, string) {
	t.Helper()
	insp := inspection.New(inspection.NewStore(0), inspection.NewHub(), nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go insp.ListenAndServe(ctx, "127.0.0.1:0")
	return insp, waitInspectorAddr(t, insp)
}

func TestInspector_Guard(t *testing.T) {
	insp, addr := startInspector(t)
	_, port, _ := net.SplitHostPort(addr)
	tok := insp.Token()

	cases := []struct {
		name   string
		method string
		path   string
		host   string
		hdr    map[string]string
		want   int
	}{
		{"no token", "GET", "/api/requests", "", nil, http.StatusUnauthorized},
		{"wrong token", "GET", "/api/requests", "", map[string]string{inspection.TokenHeader: "nope"}, http.StatusUnauthorized},
		{"token", "GET", "/api/requests", "", map[string]string{inspection.TokenHeader: tok}, http.StatusOK},
		{"localhost host", "GET", "/api/status", "localhost:" + port, map[string]string{inspection.TokenHeader: tok}, http.StatusOK},
		{"foreign host (DNS rebinding)", "GET", "/api/requests", "evil.example:" + port, map[string]string{inspection.TokenHeader: tok}, http.StatusForbidden},
		{"loopback on another port", "GET", "/api/requests", "127.0.0.1:1", map[string]string{inspection.TokenHeader: tok}, http.StatusForbidden},
		{"replay without token", "POST", "/api/replay/1", "", nil, http.StatusUnauthorized},
		{"replay from a foreign origin", "POST", "/api/replay/1", "", map[string]string{inspection.TokenHeader: tok, "Origin": "http://evil.example"}, http.StatusForbidden},
		{"clear without token", "DELETE", "/api/requests", "", nil, http.StatusUnauthorized},
		{"ui without token", "GET", "/", "", nil, http.StatusUnauthorized},
		{"ui with a wrong launch token", "GET", "/?t=nope", "", nil, http.StatusUnauthorized},
		{"websocket without token", "GET", "/ws", "", nil, http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(tc.method, "http://"+addr+tc.path, nil)
			if tc.host != "" {
				req.Host = tc.host
			}
			for k, v := range tc.hdr {
				req.Header.Set(k, v)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Fatalf("status %d, want %d", resp.StatusCode, tc.want)
			}
		})
	}
}

// TestInspector_BrowserFlow: the printed link sets the cookie and strips the
// token from the address bar; the UI, API and websocket then work with the
// cookie alone.
func TestInspector_BrowserFlow(t *testing.T) {
	insp, addr := startInspector(t)
	link := insp.URLFor(addr)
	if !strings.HasPrefix(link, "http://"+addr+"/?t=") {
		t.Fatalf("launch link %q", link)
	}
	if got := insp.URLFor(":4040"); !strings.HasPrefix(got, "http://127.0.0.1:4040/?t=") {
		t.Fatalf("unspecified host should be shown as loopback, got %q", got)
	}

	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar}
	resp, err := browser.Get(link) // follows the redirect to /
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "<html") {
		t.Fatalf("ui via launch link: %d", resp.StatusCode)
	}
	if strings.Contains(resp.Request.URL.String(), "t=") {
		t.Fatalf("token left in the address bar: %s", resp.Request.URL)
	}
	resp, err = browser.Get("http://" + addr + "/api/requests")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("api with cookie: %d", resp.StatusCode)
	}

	// The websocket feed: same-origin with the cookie is accepted, a foreign
	// origin is refused even with the cookie.
	hdr := http.Header{}
	for _, c := range jar.Cookies(resp.Request.URL) {
		hdr.Add("Cookie", c.Name+"="+c.Value)
	}
	hdr.Set("Origin", "http://"+addr)
	ws, _, err := websocket.DefaultDialer.Dial("ws://"+addr+"/ws", hdr)
	if err != nil {
		t.Fatalf("websocket with cookie: %v", err)
	}
	ws.Close()
	hdr.Set("Origin", "http://evil.example")
	if _, resp, err := websocket.DefaultDialer.Dial("ws://"+addr+"/ws", hdr); err == nil {
		t.Fatal("websocket from a foreign origin accepted")
	} else if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign-origin websocket: %v", err)
	}
}
