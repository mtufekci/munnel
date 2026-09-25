// Package integration: self-service token issuance (POST /__munnel/token).
//
// These drive the real server over HTTP: an enrollment password must gate
// issuance, issued tokens must authenticate the tunnel handshake with their
// sub claim enforced, and a server without the enrollment password (or
// without a signing key) must not issue tokens.
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mtufekci/munnel/internal/server"
	"github.com/mtufekci/munnel/internal/token"
)

// enrollKey is the signing key used by the issuance tests.
var enrollKey = []byte("enroll-test-key")

// startServerWithEnroll stands up a server with a signing key + enrollment
// password (either may be empty to test disabled modes).
func startServerWithEnroll(t *testing.T, enrollPW string, signingKey []byte) *server.Server {
	t.Helper()
	auth, err := server.NewAuthenticatorWith(server.AuthOptions{SigningKey: signingKey})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := server.New(server.Config{
		Domain:         "localhost",
		ControlAddr:    "127.0.0.1:0",
		ProxyAddr:      "127.0.0.1:0",
		PublicScheme:   "http",
		Auth:           auth,
		EnrollPassword: enrollPW,
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

// postToken POSTs an issuance request and decodes the JSON response.
func postToken(t *testing.T, srv *server.Server, sub, password, ttl string) (int, map[string]any) {
	t.Helper()
	body := map[string]string{"sub": sub, "password": password}
	if ttl != "" {
		body["ttl"] = ttl
	}
	b, _ := json.Marshal(body)
	resp, err := http.Post("http://"+srv.ProxyListener().Addr().String()+"/__munnel/token", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return resp.StatusCode, out
}

func TestTokenIssue_Success(t *testing.T) {
	local := localOK()
	defer local.Close()
	srv := startServerWithEnroll(t, "enrollpw", enrollKey)

	status, out := postToken(t, srv, "alice", "enrollpw", "")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (out=%v)", status, out)
	}
	tok, _ := out["token"].(string)
	if tok == "" {
		t.Fatalf("no token in response: %v", out)
	}
	// The token must verify and carry the requested sub claim.
	c, err := token.Parse(enrollKey, tok)
	if err != nil {
		t.Fatalf("issued token does not parse: %v", err)
	}
	if c.Sub != "alice" {
		t.Fatalf("sub = %q, want %q", c.Sub, "alice")
	}
	if c.Exp == 0 {
		t.Fatal("issued token has no expiry")
	}
	if id, _ := out["id"].(string); id == "" || id != c.ID {
		t.Fatalf("response id %v does not match token claim %q", out["id"], c.ID)
	}

	// End to end: the issued token must open a tunnel scoped to its sub.
	port := serverPort(t, local.URL)
	if ok, assigned, msg := connectSigned(t, srv, port, "", tok); !ok {
		t.Fatalf("issued token rejected at handshake: %s", msg)
	} else if assigned != "alice" {
		t.Fatalf("assigned subdomain = %q, want %q", assigned, "alice")
	}
}

func TestTokenIssue_WrongPassword(t *testing.T) {
	srv := startServerWithEnroll(t, "enrollpw", enrollKey)

	status, out := postToken(t, srv, "alice", "wrongpw", "")
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", status)
	}
	if out["token"] != nil {
		t.Fatalf("must not return a token on bad password: %v", out)
	}
}

func TestTokenIssue_Disabled(t *testing.T) {
	// No enrollment password configured → the endpoint must be a 404.
	srv := startServerWithEnroll(t, "", enrollKey)

	status, out := postToken(t, srv, "alice", "whatever", "")
	if status != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", status)
	}
	if out["token"] != nil {
		t.Fatalf("must not return a token when disabled: %v", out)
	}
}

func TestTokenIssue_NoSigningKey(t *testing.T) {
	// Enrollment password set but no signing key → 500, no token.
	srv := startServerWithEnroll(t, "enrollpw", nil)

	status, out := postToken(t, srv, "alice", "enrollpw", "")
	if status != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", status)
	}
	if out["token"] != nil {
		t.Fatalf("must not return a token without a signing key: %v", out)
	}
}

func TestTokenIssue_TTLCap(t *testing.T) {
	srv := startServerWithEnroll(t, "enrollpw", enrollKey)

	// A 10-year TTL request must be capped to 30 days (720h).
	status, out := postToken(t, srv, "alice", "enrollpw", "87600h")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	tok, _ := out["token"].(string)
	c, err := token.Parse(enrollKey, tok)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	maxTTL := 30 * 24 * time.Hour
	life := time.Unix(c.Exp, 0).Sub(time.Now())
	if life > maxTTL+time.Minute {
		t.Fatalf("token lifetime %s exceeds the %s cap", life, maxTTL)
	}
	if exp, _ := out["expires"].(string); exp == "" {
		t.Fatalf("response must include an expires timestamp: %v", out)
	}
}

func TestTokenIssue_InvalidSubdomain(t *testing.T) {
	srv := startServerWithEnroll(t, "enrollpw", enrollKey)

	for _, sub := range []string{"has_underscore", "-leading", "with.dot"} {
		status, _ := postToken(t, srv, sub, "enrollpw", "")
		if status != http.StatusBadRequest {
			t.Fatalf("sub %q: status = %d, want 400", sub, status)
		}
	}

	// "UPPER" is normalized to lowercase before validation, so it succeeds —
	// the dev gets a token scoped to "upper" (same normalization as the
	// handshake and the auth file).
	status, out := postToken(t, srv, "UPPER", "enrollpw", "")
	if status != http.StatusOK {
		t.Fatalf("sub %q: status = %d, want 200 (normalized)", "UPPER", status)
	}
	if got, _ := out["sub"].(string); got != "upper" {
		t.Fatalf("normalized sub = %q, want %q", got, "upper")
	}
}

func TestTokenIssue_EmptySub_Unscoped(t *testing.T) {
	local := localOK()
	defer local.Close()
	srv := startServerWithEnroll(t, "enrollpw", enrollKey)

	status, out := postToken(t, srv, "", "enrollpw", "")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	tok, _ := out["token"].(string)
	c, err := token.Parse(enrollKey, tok)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if c.Sub != "" {
		t.Fatalf("sub = %q, want empty (unscoped)", c.Sub)
	}
	// An unscoped token still tunnels — the server assigns a free subdomain.
	port := serverPort(t, local.URL)
	if ok, _, msg := connectSigned(t, srv, port, "", tok); !ok {
		t.Fatalf("unscoped token rejected at handshake: %s", msg)
	}
}

func TestTokenIssue_TamperedIssuedTokenRejected(t *testing.T) {
	local := localOK()
	defer local.Close()
	srv := startServerWithEnroll(t, "enrollpw", enrollKey)

	_, out := postToken(t, srv, "alice", "enrollpw", "")
	tok, _ := out["token"].(string)
	if tok == "" {
		t.Fatal("no token issued")
	}
	// Flip the first signature char — always changes a decoded byte (the
	// last char's low bits are base64 padding and would be silently ignored).
	body := tok[len(token.Prefix):]
	dot := strings.IndexByte(body, '.')
	sig := body[dot+1:]
	alt := byte('A')
	if sig[0] == 'A' {
		alt = 'B'
	}
	tampered := token.Prefix + body[:dot+1] + string(alt) + sig[1:]

	if ok, _, _ := connectSigned(t, srv, serverPort(t, local.URL), "alice", tampered); ok {
		t.Fatal("tampered issued token was accepted")
	}
}
