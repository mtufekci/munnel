package inspection

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// TokenHeader carries the per-launch access token for scripted API calls.
// The browser tab uses a cookie instead (see guard).
const TokenHeader = "X-Munnel-Inspector-Token"

// tokenParam is the query parameter of the launch link (http://…/?t=<token>).
const tokenParam = "t"

// Replayer re-dispatches a captured request to the local service.
// Implemented by client.Forwarder.
type Replayer interface {
	Replay(rec *Record) (*Record, error)
}

// StatusFunc supplies the tunnel status snapshot for /api/status.
type StatusFunc func() any

//go:embed web/index.html
var indexHTML string

// Server is the inspector web app: embedded UI + JSON API + websocket feed.
//
// It holds captured requests (bodies, cookies, auth headers) and can replay
// them against the local app, so every route is guarded (see guard): the
// Host must be the inspector's own loopback address (a DNS-rebinding page
// cannot reach it), and a per-launch random token is required, taken from
// the printed launch link once and then kept in a SameSite=Strict cookie.
type Server struct {
	store    *Store
	hub      *Hub
	replayer Replayer
	status   StatusFunc
	token    string

	http *http.Server
	ln   net.Listener
	mu   sync.RWMutex // guards ln/port/ip across ListenAndServe and handlers
	port string       // bound port
	ip   string       // bound IP when it is a specific non-loopback address
}

// New wires an inspector Server with a fresh random access token.
func New(store *Store, hub *Hub, replayer Replayer, status StatusFunc) *Server {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("inspection: no randomness for the access token: " + err.Error())
	}
	s := &Server{store: store, hub: hub, replayer: replayer, status: status, token: hex.EncodeToString(b[:])}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.serveIndex)
	mux.HandleFunc("GET /api/requests", s.serveList)
	mux.HandleFunc("GET /api/requests/{id}", s.serveOne)
	mux.HandleFunc("POST /api/replay/{id}", s.serveReplay)
	mux.HandleFunc("DELETE /api/requests", s.serveClear)
	mux.HandleFunc("GET /api/status", s.serveStatus)
	mux.HandleFunc("GET /ws", s.hub.ServeWS)
	s.http = &http.Server{Handler: s.guard(mux), ReadHeaderTimeout: 10 * time.Second}
	return s
}

// Token returns the per-launch access token.
func (s *Server) Token() string { return s.token }

// URLFor returns the launch link for an inspector listening on addr: an
// unspecified host (":4040", "0.0.0.0:4040") is shown as 127.0.0.1, and the
// access token rides in the query (the page swaps it for a cookie).
func (s *Server) URLFor(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/?" + tokenParam + "=" + s.token
}

// ListenAndServe binds addr (e.g. "127.0.0.1:4040") and serves until ctx is
// cancelled.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.ln = ln
	if host, port, err := net.SplitHostPort(ln.Addr().String()); err == nil {
		s.port = port
		if ip := net.ParseIP(host); ip != nil && !ip.IsLoopback() && !ip.IsUnspecified() {
			s.ip = ip.String()
		}
	}
	s.mu.Unlock()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		s.http.Shutdown(shutdownCtx)
		ln.Close()
	}()
	return s.http.Serve(ln)
}

// Addr returns the bound address (valid after ListenAndServe starts). Safe to
// call concurrently with ListenAndServe.
func (s *Server) Addr() string {
	s.mu.RLock()
	ln := s.ln
	s.mu.RUnlock()
	if ln == nil {
		return ""
	}
	return ln.Addr().String()
}

// guard admits a request only when its Host (and Origin, if sent) is this
// inspector's own address and it carries the access token. The browser gets
// the token once through the launch link (/?t=…), which sets an HttpOnly,
// SameSite=Strict cookie and redirects to the bare URL so the token leaves the
// address bar; fetch and the websocket then send the cookie on their own.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.allowedHost(r.Host) {
			http.Error(w, "munnel inspector: forbidden host", http.StatusForbidden)
			return
		}
		if o := r.Header.Get("Origin"); o != "" && !s.allowedOrigin(o) {
			http.Error(w, "munnel inspector: forbidden origin", http.StatusForbidden)
			return
		}
		if r.URL.Path == "/" && r.Method == http.MethodGet && r.URL.Query().Has(tokenParam) {
			if !s.validToken(r.URL.Query().Get(tokenParam)) {
				s.denyPage(w)
				return
			}
			http.SetCookie(w, &http.Cookie{
				Name: s.cookieName(), Value: s.token, Path: "/",
				HttpOnly: true, SameSite: http.SameSiteStrictMode,
			})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		if !s.authorized(r) {
			if r.URL.Path == "/" {
				s.denyPage(w)
			} else {
				writeError(w, http.StatusUnauthorized, "missing or wrong inspector token")
			}
			return
		}
		next.ServeHTTP(w, r)
	})
}

// cookieName includes the port: cookies are not port-scoped, and two munnel
// clients on one machine must not overwrite each other's token.
func (s *Server) cookieName() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return "munnel_inspector_" + s.port
}

func (s *Server) validToken(t string) bool {
	return subtle.ConstantTimeCompare([]byte(t), []byte(s.token)) == 1
}

func (s *Server) authorized(r *http.Request) bool {
	if t := r.Header.Get(TokenHeader); t != "" {
		return s.validToken(t)
	}
	c, err := r.Cookie(s.cookieName())
	return err == nil && s.validToken(c.Value)
}

// allowedHost accepts only this inspector's own address: 127.0.0.1, localhost
// or [::1] (or the specific IP it was bound to) with the bound port. A page
// using DNS rebinding reaches the port under a foreign Host and is refused.
func (s *Server) allowedHost(hostport string) bool {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return false
	}
	s.mu.RLock()
	bport, bip := s.port, s.ip
	s.mu.RUnlock()
	if port != bport {
		return false
	}
	switch h := strings.ToLower(host); h {
	case "127.0.0.1", "localhost", "::1":
		return true
	default:
		return bip != "" && h == bip
	}
}

func (s *Server) allowedOrigin(origin string) bool {
	u, err := url.Parse(origin)
	return err == nil && u.Scheme == "http" && u.Path == "" && s.allowedHost(u.Host)
}

func (s *Server) denyPage(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(denyHTML))
}

const denyHTML = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>munnel inspector</title>
<style>:root{color-scheme:dark}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0e0c0d;color:#e8e6e3;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
p{color:#a09a92;max-width:32rem;line-height:1.6}h1{font-size:1.2rem;color:#c8b6ff}</style></head>
<body><div><h1>munnel inspector</h1><p>open the inspector link munnel printed when it started
(it ends in <code>/?t=…</code>). the token changes every time munnel starts.</p></div></body></html>`

func (s *Server) serveIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(indexHTML))
}

func (s *Server) serveList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.store.List())
}

func (s *Server) serveOne(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad id")
		return
	}
	rec := s.store.Get(id)
	if rec == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

func (s *Server) serveReplay(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad id")
		return
	}
	rec := s.store.Get(id)
	if rec == nil {
		writeError(w, http.StatusNotFound, "request no longer in buffer")
		return
	}
	if s.replayer == nil {
		writeError(w, http.StatusServiceUnavailable, "replay unavailable")
		return
	}
	fresh, err := s.replayer.Replay(rec)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	stored := s.store.Add(fresh)
	s.hub.BroadcastRecord(stored)
	writeJSON(w, http.StatusOK, stored)
}

func (s *Server) serveClear(w http.ResponseWriter, r *http.Request) {
	s.store.Clear()
	writeJSON(w, http.StatusOK, map[string]string{"status": "cleared"})
}

func (s *Server) serveStatus(w http.ResponseWriter, r *http.Request) {
	if s.status == nil {
		writeJSON(w, http.StatusOK, map[string]any{"connected": false})
		return
	}
	writeJSON(w, http.StatusOK, s.status())
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "")
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"error": msg, "status": code})
}
