package forwardauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSession_SignVerify(t *testing.T) {
	m := NewManager([]byte("k"), StubProvider{}, time.Hour)
	val, err := m.signSession("alice@example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	s, err := m.verifySession(val)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if s.User != "alice@example.com" {
		t.Fatalf("user: want alice@example.com, got %q", s.User)
	}
}

func TestSession_Tampered(t *testing.T) {
	m := NewManager([]byte("k"), StubProvider{}, time.Hour)
	val, _ := m.signSession("alice@example.com", nil)
	// Flip the last char of the signature segment.
	body := val[len(prefix):]
	dot := strings.IndexByte(body, '.')
	last := body[len(body)-1]
	alt := byte('A')
	if last == 'A' {
		alt = 'B'
	}
	tampered := prefix + body[:dot+1] + body[dot+1:len(body)-1] + string(alt)
	if _, err := m.verifySession(tampered); err == nil {
		t.Fatal("tampered session verified")
	}
}

func TestSession_WrongKey(t *testing.T) {
	a := NewManager([]byte("key-a"), StubProvider{}, time.Hour)
	b := NewManager([]byte("key-b"), StubProvider{}, time.Hour)
	val, _ := a.signSession("alice", nil)
	if _, err := b.verifySession(val); err == nil {
		t.Fatal("session signed with key-a verified by key-b")
	}
}

func TestSession_Expired(t *testing.T) {
	m := NewManager([]byte("k"), StubProvider{}, time.Hour)
	// Craft a session already in the past (white-box, package-internal).
	s := Session{User: "alice", Exp: time.Now().Unix() - 1}
	payload, _ := json.Marshal(s)
	val := prefix + b64(payload) + "." + b64(hmacSum(m.key, payload))
	if _, err := m.verifySession(val); err != ErrExpiredSession {
		t.Fatalf("want ErrExpiredSession, got %v", err)
	}
}

func TestAuthorize_NoCookie_Redirects(t *testing.T) {
	m := NewManager([]byte("k"), StubProvider{}, time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/secret", nil)
	rec := httptest.NewRecorder()
	if m.Authorize(rec, req) {
		t.Fatal("Authorize allowed a request with no session")
	}
	if rec.Code != http.StatusFound {
		t.Fatalf("want 302 redirect, got %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, loginPath) {
		t.Fatalf("redirect location: want %s?..., got %q", loginPath, loc)
	}
	if !strings.Contains(loc, "return=%2Fsecret") {
		t.Fatalf("redirect should carry the return path, got %q", loc)
	}
}

func TestAuthorize_ValidCookie_InjectsHeader(t *testing.T) {
	m := NewManager([]byte("k"), StubProvider{}, time.Hour)
	val, _ := m.signSession("alice@example.com", []string{"eng"})
	req := httptest.NewRequest(http.MethodGet, "/secret", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: val})
	rec := httptest.NewRecorder()
	if !m.Authorize(rec, req) {
		t.Fatal("Authorize rejected a valid session")
	}
	if got := req.Header.Get(UserHeader); got != "alice@example.com" {
		t.Fatalf("UserHeader: want alice@example.com, got %q", got)
	}
	if got := req.Header.Get(GroupHeader); got != "eng" {
		t.Fatalf("GroupHeader: want eng, got %q", got)
	}
}

func TestAuthorize_InvalidCookie_Redirects(t *testing.T) {
	m := NewManager([]byte("k"), StubProvider{}, time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/secret", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "s1.garbage.junk"})
	rec := httptest.NewRecorder()
	if m.Authorize(rec, req) {
		t.Fatal("Authorize accepted a garbage session cookie")
	}
	if rec.Code != http.StatusFound {
		t.Fatalf("want 302, got %d", rec.Code)
	}
}

func TestStripIdentityHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(UserHeader, "attacker@example.com")
	req.Header.Set(GroupHeader, "admin")
	StripIdentityHeaders(req)
	if req.Header.Get(UserHeader) != "" {
		t.Fatal("UserHeader not stripped")
	}
	if req.Header.Get(GroupHeader) != "" {
		t.Fatal("GroupHeader not stripped")
	}
}

// TestHandle_LoginFlow exercises the full stub flow end to end: the login
// form renders, the POST to /__munnel/auth sets a cookie and redirects, and
// the cookie then authorizes a protected request.
func TestHandle_LoginFlow(t *testing.T) {
	m := NewManager([]byte("k"), StubProvider{}, time.Hour)

	// 1. GET /__munnel/login renders the form.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, loginPath+"?return=/secret", nil)
	m.Handle(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Sign in") {
		t.Fatalf("login form not rendered: code=%d body=%q", rec.Code, rec.Body.String())
	}

	// 2. POST /__munnel/auth with a user → sets cookie + redirects.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, authPath, strings.NewReader("user=alice@example.com&return=/secret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	m.Handle(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("auth POST: want 302, got %d", rec.Code)
	}
	setCookie := rec.Header().Get("Set-Cookie")
	if !strings.Contains(setCookie, CookieName) {
		t.Fatalf("no session cookie set: %q", setCookie)
	}

	// 3. The cookie authorizes a protected request.
	req = httptest.NewRequest(http.MethodGet, "/secret", nil)
	req.Header.Set("Cookie", setCookie)
	rec = httptest.NewRecorder()
	if !m.Authorize(rec, req) {
		t.Fatal("post-login cookie did not authorize")
	}
	if req.Header.Get(UserHeader) != "alice@example.com" {
		t.Fatalf("UserHeader: want alice@example.com, got %q", req.Header.Get(UserHeader))
	}
}