package server

import (
	"net/http"
	"strings"
	"time"

	"github.com/mtufekci/munnel/internal/proto"
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
// (and its www alias, which serves the landing page), or a subdomain a client
// holds right now. Approving every name under the domain would let anyone
// make the server request certificates for made-up names and spend the ACME
// rate limit of the whole registered domain.
func (s *Server) certAllowed(host string) bool {
	if host == s.cfg.Domain || host == "www."+s.cfg.Domain {
		return true
	}
	sub, ok := strings.CutSuffix(host, "."+s.cfg.Domain)
	return ok && proto.ValidSubdomain(sub) && s.reg.Get(sub) != nil
}
