// Package forwardauth implements munnel's zero-trust access layer.
//
// A protected tunnel requires a viewer to authenticate before the request
// reaches the tunneled local service. On success munnel injects a trusted
// X-Authenticated-User header (which it always strips from incoming requests,
// so a viewer cannot spoof it). The local service trusts that header
// unconditionally — munnel is the auth boundary.
//
// v1 ships a StubProvider (a login form that trusts any submitted user) for
// development and testing. A real OIDC provider (GitHub/Google) is a drop-in
// replacement satisfying the same Provider interface.
package forwardauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// CookieName is the session cookie.
	CookieName = "__munnel_sess"
	// UserHeader is the trusted identity header injected on protected tunnels.
	UserHeader = "X-Authenticated-User"
	// GroupHeader is the optional group/role header.
	GroupHeader = "X-Authenticated-Groups"

	prefix     = "s1."
	loginPath  = "/__munnel/login"
	authPath   = "/__munnel/auth"
	logoutPath = "/__munnel/logout"
)

// Sentinel errors for session verification.
var (
	ErrInvalidSession = errors.New("forwardauth: invalid session")
	ErrExpiredSession = errors.New("forwardauth: expired session")
)

// Session is the signed payload stored in the cookie.
type Session struct {
	User   string   `json:"user"`
	Groups []string `json:"groups,omitempty"`
	Exp    int64    `json:"exp"`
}

// Provider renders the login UI and validates the submitted credentials.
// v1 ships StubProvider (dev/test only — trusts any user). A real OIDC
// provider is a future implementation of this interface.
type Provider interface {
	// RenderLogin writes a login page that POSTs to authPath with `user` and
	// `return` form fields.
	RenderLogin(w http.ResponseWriter, r *http.Request, returnTo string)
	// Authenticate validates a login submission and returns the authenticated
	// user (and optional groups) or an error.
	Authenticate(r *http.Request) (user string, groups []string, err error)
}

// Manager signs/verifies session cookies and drives the login flow.
type Manager struct {
	key      []byte
	provider Provider
	ttl      time.Duration
}

// NewManager builds a Manager. The key signs session cookies; ttl is the
// session lifetime (cookies are HttpOnly + SameSite=Lax; set Secure=true in
// production behind TLS via the Secure field on the cookie the caller
// controls — see SetSessionCookie).
func NewManager(key []byte, provider Provider, ttl time.Duration) *Manager {
	return &Manager{key: key, provider: provider, ttl: ttl}
}

// Enabled reports whether forward-auth is configured (non-nil manager with a
// provider). A nil Manager means protection is disabled server-wide.
func (m *Manager) Enabled() bool { return m != nil && m.provider != nil }

// Authorize checks the request for a valid session on a protected tunnel.
// Returns true (and injects UserHeader) if the request may proceed; false if
// it wrote a redirect to the login flow. The caller MUST strip UserHeader from
// the incoming request before calling, so the header is always munnel-set.
func (m *Manager) Authorize(w http.ResponseWriter, r *http.Request) bool {
	if c, err := r.Cookie(CookieName); err == nil {
		if sess, err := m.verifySession(c.Value); err == nil {
			r.Header.Set(UserHeader, sess.User)
			if len(sess.Groups) > 0 {
				r.Header.Set(GroupHeader, strings.Join(sess.Groups, ","))
			}
			return true
		}
	}
	// No valid session → redirect to the login flow on the same host.
	target := loginPath + "?return=" + url.QueryEscape(r.URL.RequestURI())
	http.Redirect(w, r, target, http.StatusFound)
	return false
}

// Handle routes the /__munnel/* management paths (login form, auth submit,
// logout). These live on the subdomain host so the session cookie is scoped
// to the tunnel's subdomain.
func (m *Manager) Handle(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case loginPath:
		returnTo := r.URL.Query().Get("return")
		m.provider.RenderLogin(w, r, returnTo)
	case authPath:
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		user, groups, err := m.provider.Authenticate(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		m.SetSessionCookie(w, r, user, groups)
		returnTo := r.FormValue("return")
		if returnTo == "" || !strings.HasPrefix(returnTo, "/") {
			returnTo = "/"
		}
		http.Redirect(w, r, returnTo, http.StatusFound)
	case logoutPath:
		m.ClearSessionCookie(w)
		http.Redirect(w, r, "/", http.StatusFound)
	default:
		http.NotFound(w, r)
	}
}

// SetSessionCookie signs a session for user and sets it on the response.
// Secure is set when the request arrived over TLS (behind Caddy) so the
// cookie is only sent over HTTPS in production.
func (m *Manager) SetSessionCookie(w http.ResponseWriter, r *http.Request, user string, groups []string) {
	val, _ := m.signSession(user, groups)
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    val,
		Path:     "/",
		MaxAge:   int(m.ttl.Seconds()),
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearSessionCookie expires the session cookie.
func (m *Manager) ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: "", Path: "/",
		MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

// StripIdentityHeaders removes the trusted identity headers from a request so
// a viewer can never set them — only munnel (after Authorize) may. Call this
// on every proxied request, protected or not.
func StripIdentityHeaders(r *http.Request) {
	r.Header.Del(UserHeader)
	r.Header.Del(GroupHeader)
}

func (m *Manager) signSession(user string, groups []string) (string, error) {
	s := Session{User: user, Groups: groups, Exp: time.Now().Add(m.ttl).Unix()}
	payload, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	return prefix + b64(payload) + "." + b64(hmacSum(m.key, payload)), nil
}

func (m *Manager) verifySession(cookie string) (*Session, error) {
	if !strings.HasPrefix(cookie, prefix) {
		return nil, ErrInvalidSession
	}
	body := cookie[len(prefix):]
	dot := strings.IndexByte(body, '.')
	if dot < 0 {
		return nil, ErrInvalidSession
	}
	payload, err := b64d(body[:dot])
	if err != nil {
		return nil, ErrInvalidSession
	}
	sig, err := b64d(body[dot+1:])
	if err != nil {
		return nil, ErrInvalidSession
	}
	if !hmac.Equal(sig, hmacSum(m.key, payload)) {
		return nil, ErrInvalidSession
	}
	var s Session
	if err := json.Unmarshal(payload, &s); err != nil {
		return nil, ErrInvalidSession
	}
	if time.Now().Unix() > s.Exp {
		return nil, ErrExpiredSession
	}
	return &s, nil
}

// StubProvider is a dev/test-only Provider that trusts any submitted user.
// It must NOT be used in production — there is no password check. Gate it
// behind an explicit opt-in (--auth-stub) on the server.
type StubProvider struct{}

func (StubProvider) RenderLogin(w http.ResponseWriter, r *http.Request, returnTo string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, loginFormTpl, html.EscapeString(authPath), html.EscapeString(returnTo))
}

func (StubProvider) Authenticate(r *http.Request) (string, []string, error) {
	if err := r.ParseForm(); err != nil {
		return "", nil, err
	}
	user := strings.TrimSpace(r.FormValue("user"))
	if user == "" {
		return "", nil, errors.New("no user submitted")
	}
	return user, nil, nil
}

const loginFormTpl = `<!DOCTYPE html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>munnel — sign in</title>
<style>
:root{color-scheme:dark}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0e0c0d;color:#e8e6e3;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.card{padding:2rem;max-width:24rem}
h1{font-size:1.2rem;font-weight:600;color:#c8b6ff;margin:.2rem 0 1rem}
input{font:inherit;padding:.4rem .5rem;background:#1c1917;color:#e8e6e3;border:1px solid #3a3531;border-radius:.3rem;width:100%%;box-sizing:border-box;margin:.3rem 0}
button{font:inherit;padding:.5rem 1rem;background:#c8b6ff;color:#0e0c0d;border:none;border-radius:.3rem;cursor:pointer;margin-top:.5rem}
.hint{color:#a09a92;font-size:.8rem;margin-top:1rem}
</style></head><body><form class="card" method="post" action="%s">
<h1>munnel access</h1>
<input name="user" placeholder="you@example.com" autofocus required>
<input type="hidden" name="return" value="%s">
<button type="submit">Sign in</button>
<div class="hint">stub auth — any user is accepted (dev/test only)</div>
</form></body></html>`

func hmacSum(key, payload []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(payload)
	return m.Sum(nil)
}

func b64(b []byte) string           { return base64.RawURLEncoding.EncodeToString(b) }
func b64d(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
