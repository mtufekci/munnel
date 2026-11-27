package server

import (
	"net/http"
	"strings"
	"time"
)

// serveAsk answers Caddy's on-demand TLS permission check ("ask") until the
// listener is closed. It must stay internal (docker network only): it tells
// whoever asks which tunnels are live.
func (s *Server) serveAsk() error {
	srv := &http.Server{
		Handler:           http.HandlerFunc(s.handleAsk),
		ReadHeaderTimeout: 5 * time.Second,
	}
	return srv.Serve(s.askLn)
}

// handleAsk implements GET /check?domain=<host>: 200 lets Caddy obtain a
// certificate for host, anything else refuses it.
func (s *Server) handleAsk(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/check" {
		http.NotFound(w, r)
		return
	}
	domain := strings.ToLower(r.URL.Query().Get("domain"))
	if !s.certAllowed(domain) {
		http.Error(w, "no live tunnel for "+domain, http.StatusForbidden)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// certAllowed reports whether a certificate may be issued for host: the apex
// (and its www alias, which serves the landing page), or a subdomain of the
// domain or of an extra domain that a client holds right now. Approving
// every name under a domain would let anyone make the server request
// certificates for made-up names and spend the ACME rate limit of the whole
// registered domain. An extra domain's apex and www. are never approved:
// they belong to the domain's owner, not to munnel. host is not stripped of
// a trailing dot (SNI never carries one), so "name." is refused.
func (s *Server) certAllowed(host string) bool {
	if host == s.cfg.Domain || host == "www."+s.cfg.Domain {
		return true
	}
	return s.liveTunnelHost(host)
}
