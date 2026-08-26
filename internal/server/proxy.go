package server

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mtufekci/munnel/internal/proto"
)

// Hop-by-hop headers never forwarded over a tunnel.
var hopByHop = map[string]bool{
	"Connection":          true,
	"Proxy-Connection":    true,
	"Keep-Alive":          true,
	"Te":                  true,
	"Trailer":             true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
}

// serveProxyHTTP runs the public ingress until the listener is closed.
func (s *Server) serveProxyHTTP() error {
	srv := &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 15 * time.Second,
		// No Read/Write/IdleTimeout: tunnels carry long-lived streaming
		// responses (SSE, big downloads); the mux layer owns liveness.
	}
	err := srv.Serve(s.proxyLn)
	if err == http.ErrServerClosed || isClosedErr(err) {
		return err
	}
	return err
}

func isClosedErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "closed")
}

// ServeHTTP routes by Host: the bare domain serves the landing page, a
// subdomain is proxied into its tunnel.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := stripPort(r.Host)

	switch {
	case r.URL.Path == "/healthz":
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ok":true,"tunnels":%d}`, s.reg.Count())
		return
	case host == "" || host == s.cfg.Domain || host == "www."+s.cfg.Domain ||
		(host != "" && net.ParseIP(host) != nil) || isAddrHost(host, s.cfg.ProxyAddr):
		s.serveLanding(w, r)
		return
	}

	if !strings.HasSuffix(host, "."+s.cfg.Domain) {
		s.errorPage(w, http.StatusNotFound, "unknown host", fmt.Sprintf("%q is not a subdomain of %s", host, s.cfg.Domain))
		return
	}
	sub := strings.TrimSuffix(host, "."+s.cfg.Domain)
	if !proto.ValidSubdomain(sub) {
		s.errorPage(w, http.StatusNotFound, "unknown host", fmt.Sprintf("%q is not a valid tunnel subdomain", sub))
		return
	}

	c := s.reg.Get(sub)
	if c == nil {
		s.errorPage(w, http.StatusBadGateway, "tunnel offline",
			fmt.Sprintf("no client is connected for %s.%s", sub, s.cfg.Domain))
		return
	}
	s.proxyTo(w, r, c)
}

// proxyTo forwards one public request over the tunnel and relays the response.
func (s *Server) proxyTo(w http.ResponseWriter, r *http.Request, c *Client) {
	// WebSocket / other upgrades are not carried (yet).
	if strings.EqualFold(r.Header.Get("Connection"), "upgrade") || r.Header.Get("Upgrade") != "" {
		s.errorPage(w, http.StatusNotImplemented, "upgrade not supported",
			"WebSocket and other connection upgrades are not supported by munnel yet")
		return
	}

	// Bound the request body (it is replayed through the tunnel framed, and
	// must be length-prefixed for the client side to parse deterministically).
	if r.ContentLength > s.cfg.MaxRequestBody {
		s.errorPage(w, http.StatusRequestEntityTooLarge, "request too large",
			fmt.Sprintf("request body exceeds the %d-byte limit", s.cfg.MaxRequestBody))
		return
	}
	var body []byte
	if r.Body != nil {
		var err error
		body, err = io.ReadAll(io.LimitReader(r.Body, s.cfg.MaxRequestBody+1))
		if err != nil {
			s.errorPage(w, http.StatusBadRequest, "bad request", "failed reading request body")
			return
		}
		if int64(len(body)) > s.cfg.MaxRequestBody {
			s.errorPage(w, http.StatusRequestEntityTooLarge, "request too large",
				fmt.Sprintf("request body exceeds the %d-byte limit", s.cfg.MaxRequestBody))
			return
		}
	}

	meta, _ := json.Marshal(proto.OpenMeta{Host: r.Host, RemoteAddr: r.RemoteAddr})
	st, err := c.Session.OpenStream(meta)
	if err != nil {
		s.errorPage(w, http.StatusBadGateway, "tunnel error", "could not open a stream to the client")
		return
	}

	// Write the request onto the stream in plain HTTP/1.1 wire format.
	out := bufio.NewWriter(st)
	fmt.Fprintf(out, "%s %s HTTP/1.1\r\n", r.Method, r.URL.RequestURI())
	fmt.Fprintf(out, "Host: %s\r\n", r.Host)
	for k, vs := range r.Header {
		if hopByHop[http.CanonicalHeaderKey(k)] {
			continue
		}
		for _, v := range vs {
			fmt.Fprintf(out, "%s: %s\r\n", k, v)
		}
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		fmt.Fprintf(out, "X-Forwarded-For: %s, %s\r\n", xff, remoteIP(r.RemoteAddr))
	} else {
		fmt.Fprintf(out, "X-Forwarded-For: %s\r\n", remoteIP(r.RemoteAddr))
	}
	fmt.Fprintf(out, "X-Forwarded-Host: %s\r\n", r.Host)
	fmt.Fprintf(out, "X-Forwarded-Proto: %s\r\n", s.cfg.PublicScheme)
	if len(body) > 0 || r.ContentLength > 0 || methodHasBody(r.Method) {
		fmt.Fprintf(out, "Content-Length: %d\r\n", len(body))
	}
	out.WriteString("\r\n")
	out.Write(body)
	if err := out.Flush(); err != nil {
		st.Reset()
		return
	}
	_ = st.CloseWrite() // request fully sent; client reads until EOF/body-len

	// Read the response the client relayed back from localhost.
	resp, err := http.ReadResponse(bufio.NewReader(st), r)
	if err != nil {
		s.errorPage(w, http.StatusBadGateway, "tunnel error",
			"the tunnel client closed the stream without a response")
		return
	}
	defer resp.Body.Close()

	dst := w.Header()
	contentLen := int64(-1)
	for k, vs := range resp.Header {
		if hopByHop[http.CanonicalHeaderKey(k)] {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
	if resp.ContentLength >= 0 {
		contentLen = resp.ContentLength
		dst.Set("Content-Length", strconv.FormatInt(contentLen, 10))
	}
	addCORSDebugHeaders(dst)
	w.WriteHeader(resp.StatusCode)

	if r.Method == http.MethodHead {
		return
	}
	flusher, canFlush := w.(http.Flusher)
	buf := make([]byte, 64*1024)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			if canFlush && contentLen < 0 {
				flusher.Flush() // keep SSE/streaming responses flowing
			}
		}
		if rerr != nil {
			return
		}
	}
}

// addCORSDebugHeaders makes error/status pages readable from fetch() during
// local development across origins.
func addCORSDebugHeaders(h http.Header) {
	if h.Get("Access-Control-Allow-Origin") == "" {
		return
	}
	h.Add("Vary", "Origin")
}

// serveLanding serves the embedded landing page on the bare domain.
func (s *Server) serveLanding(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		s.errorPage(w, http.StatusNotFound, "not found", "this is the munnel server landing endpoint")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	io.WriteString(w, landingHTML(s.cfg.Domain, s.cfg.ControlAddr, s.cfg.PublicScheme))
}

// errorPage renders a small dark error document.
func (s *Server) errorPage(w http.ResponseWriter, status int, title, detail string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintf(w, errorPageTpl, status, statusText(status), esc(title), status, esc(detail))
}

func statusText(code int) string {
	if t := http.StatusText(code); t != "" {
		return t
	}
	return "error"
}

func esc(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")
	return r.Replace(s)
}

func stripPort(hostport string) string {
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return strings.ToLower(strings.TrimSuffix(host, "."))
	}
	return strings.ToLower(strings.TrimSuffix(hostport, "."))
}

func remoteIP(remote string) string {
	if ip, _, err := net.SplitHostPort(remote); err == nil {
		return ip
	}
	return remote
}

// isAddrHost treats requests addressed at the listener's own address (e.g.
// "127.0.0.1:8080" typed directly, or "localhost" when domain=localhost) as
// landing-page traffic rather than subdomain lookups.
func isAddrHost(host string, proxyAddr string) bool {
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}
	h, _, err := net.SplitHostPort(proxyAddr)
	if err != nil {
		return false
	}
	h = strings.TrimPrefix(h, "[::]")
	return h != "" && h == host
}

func methodHasBody(m string) bool {
	switch m {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

const errorPageTpl = `<!DOCTYPE html><html lang="en" class="dark"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>%d %s — munnel</title>
<style>
:root{color-scheme:dark}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0e0c0d;color:#e8e6e3;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.card{text-align:center;padding:2rem}
h1{font-size:1.4rem;font-weight:600;margin:.2rem 0;color:#c8b6ff}
p{color:#a09a92;font-size:.9rem;max-width:34rem}
code{background:#1c1917;padding:.1rem .4rem;border-radius:.3rem}
</style></head><body><div class="card">
<h1>%s</h1><p><code>%d</code> · %s</p>
</div></body></html>`
