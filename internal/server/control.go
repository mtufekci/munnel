package server

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/mtufekci/munnel/internal/forwardauth"
	"github.com/mtufekci/munnel/internal/mux"
	"github.com/mtufekci/munnel/internal/proto"
)

// handshakeTimeout bounds the hello/ack exchange before the socket is handed
// to the mux layer.
const handshakeTimeout = 15 * time.Second

// defaultResponseHeaderTimeout bounds how long the proxy waits for a tunnel
// client to relay response headers. Streaming bodies after the headers are
// not affected.
const defaultResponseHeaderTimeout = 60 * time.Second

// errTakenOver ends a stale session whose name was claimed by a reconnect
// that presented the same signed token.
var errTakenOver = errors.New("taken over by a new connection with the same token")

// Config holds server settings.
type Config struct {
	Domain      string // base domain, e.g. "tunnels.example.com"
	ControlAddr string // control + multiplex listener, e.g. ":7001"
	ProxyAddr   string // public HTTP ingress, e.g. ":8080"

	// ControlTLSAddr is the TLS control listener, e.g. ":7002". It runs only
	// when ControlTLS is set too; the plaintext ControlAddr keeps working.
	// Reserved names can be claimed only through this listener.
	ControlTLSAddr string
	ControlTLS     *tls.Config // server certificate for ControlTLSAddr (e.g. CertFile.GetCertificate)

	PublicPort     string // port shown in public URLs (e.g. "443" behind a TLS proxy); "" derives from ProxyAddr
	PublicScheme   string // scheme shown in public URLs ("https" behind Caddy/Cloudflare)
	MaxRequestBody int64  // per-request body cap in bytes
	Auth           *Authenticator
	FA             *forwardauth.Manager // nil = forward-auth disabled server-wide
	EnrollPassword string               // gates self-service token issuance (POST /__munnel/token); "" = disabled
	Logger         *log.Logger

	// ResponseHeaderTimeout: a tunnel client that relays no response headers
	// within this long gets the request answered 504 (default 60s).
	ResponseHeaderTimeout time.Duration
	// MuxPingInterval / MuxIdleTimeout tune tunnel liveness (defaults 15s /
	// 45s, see mux.Session). Tests shorten them.
	MuxPingInterval time.Duration
	MuxIdleTimeout  time.Duration
}

// Server is the munnel tunnel server: control listener + public proxy.
type Server struct {
	cfg Config
	reg *Registry
	log *log.Logger

	controlLn    net.Listener
	controlTLSLn net.Listener // nil when the TLS control listener is off
	proxyLn      net.Listener
}

// New validates config and builds a Server.
func New(cfg Config) (*Server, error) {
	if cfg.Domain == "" {
		cfg.Domain = "localhost"
	}
	if cfg.ControlAddr == "" {
		cfg.ControlAddr = ":7001"
	}
	if cfg.ProxyAddr == "" {
		cfg.ProxyAddr = ":8080"
	}
	if cfg.PublicScheme == "" {
		cfg.PublicScheme = "http"
	}
	if cfg.MaxRequestBody <= 0 {
		cfg.MaxRequestBody = 32 << 20
	}
	if cfg.ResponseHeaderTimeout <= 0 {
		cfg.ResponseHeaderTimeout = defaultResponseHeaderTimeout
	}
	if cfg.Auth == nil {
		a, err := NewAuthenticator("", "")
		if err != nil {
			return nil, err
		}
		cfg.Auth = a
	}
	if cfg.Logger == nil {
		cfg.Logger = log.New(os.Stderr, "", log.LstdFlags)
	}
	return &Server{cfg: cfg, reg: NewRegistry(), log: cfg.Logger}, nil
}

// Registry exposes the live tunnel registry (used by tests/metrics).
func (s *Server) Registry() *Registry { return s.reg }

// ControlListener exposes the bound control listener after ListenAndServe runs
// (useful with ":0" in tests). Nil before the server starts.
func (s *Server) ControlListener() net.Listener { return s.controlLn }

// ProxyListener exposes the bound proxy listener after ListenAndServe runs.
func (s *Server) ProxyListener() net.Listener { return s.proxyLn }

// ControlTLSListener exposes the bound TLS control listener, or nil when TLS
// is not configured.
func (s *Server) ControlTLSListener() net.Listener { return s.controlTLSLn }

func (s *Server) tlsEnabled() bool { return s.cfg.ControlTLS != nil && s.cfg.ControlTLSAddr != "" }

// Bind creates the listeners (synchronously — safe to inspect afterwards,
// which tests rely on). Idempotent. ListenAndServe calls it if needed.
func (s *Server) Bind() error {
	if s.controlLn != nil {
		return nil
	}
	var err error
	s.controlLn, err = net.Listen("tcp", s.cfg.ControlAddr)
	if err != nil {
		return fmt.Errorf("control listen %s: %w", s.cfg.ControlAddr, err)
	}
	if s.tlsEnabled() {
		ln, err := net.Listen("tcp", s.cfg.ControlTLSAddr)
		if err != nil {
			s.controlLn.Close()
			s.controlLn = nil
			return fmt.Errorf("control TLS listen %s: %w", s.cfg.ControlTLSAddr, err)
		}
		tc := s.cfg.ControlTLS.Clone()
		if tc.MinVersion == 0 {
			tc.MinVersion = tls.VersionTLS12
		}
		s.controlTLSLn = tls.NewListener(ln, tc)
	}
	s.proxyLn, err = net.Listen("tcp", s.cfg.ProxyAddr)
	if err != nil {
		s.controlLn.Close()
		s.controlLn = nil
		if s.controlTLSLn != nil {
			s.controlTLSLn.Close()
			s.controlTLSLn = nil
		}
		return fmt.Errorf("proxy listen %s: %w", s.cfg.ProxyAddr, err)
	}
	return nil
}

// ListenAndServe starts the control listener and the public proxy, and blocks
// until ctx is cancelled or a listener fails.
func (s *Server) ListenAndServe(ctx context.Context) error {
	if err := s.Bind(); err != nil {
		return err
	}
	listeners := []net.Listener{s.controlLn, s.proxyLn}
	if s.controlTLSLn != nil {
		listeners = append(listeners, s.controlTLSLn)
	}
	errCh := make(chan error, len(listeners))

	mode := "open (no auth)"
	if !s.cfg.Auth.Open() {
		n := s.cfg.Auth.StaticTokenCount()
		mode = fmt.Sprintf("token auth (%d static token%s", n, plural(n))
		if s.cfg.Auth.SignedEnabled() {
			mode += " + signed tokens"
		}
		mode += ")"
	}
	control := s.controlLn.Addr().String()
	if s.controlTLSLn != nil {
		control += " control-tls=" + s.controlTLSLn.Addr().String()
	}
	if names := s.cfg.Auth.ReservedNames(); len(names) > 0 {
		mode += " reserved=" + strings.Join(names, ",")
	}
	s.log.Printf("munnel-server up — domain=%s control=%s proxy=%s auth=%s",
		s.cfg.Domain, control, s.proxyLn.Addr(), mode)

	go s.acceptLoop(s.controlLn, false, errCh)
	if s.controlTLSLn != nil {
		go s.acceptLoop(s.controlTLSLn, true, errCh)
	}
	go func() { errCh <- s.serveProxyHTTP() }()

	closeAll := func() {
		for _, ln := range listeners {
			ln.Close()
		}
	}
	select {
	case err := <-errCh: // a listener died
		closeAll()
		for range len(listeners) - 1 {
			<-errCh
		}
		return err
	case <-ctx.Done():
		closeAll()
		for range listeners {
			<-errCh
		}
		return nil
	}
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func (s *Server) acceptLoop(ln net.Listener, overTLS bool, errCh chan<- error) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- fmt.Errorf("control accept: %w", err)
			return
		}
		go func() {
			if err := s.handleControlConn(conn, overTLS); err != nil {
				s.log.Printf("control %s: %v", conn.RemoteAddr(), err)
			}
		}()
	}
}

// handleControlConn runs the handshake, registers the tunnel, and pumps the
// mux session until it dies. overTLS reports whether conn came through the
// TLS control listener (the TLS handshake runs on the first read below,
// inside the handshake deadline).
func (s *Server) handleControlConn(conn net.Conn, overTLS bool) error {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))

	br := bufio.NewReader(conn)
	var hello proto.Hello
	if err := proto.ReadMessage(br, &hello); err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	if hello.Type != proto.TypeHello {
		return fmt.Errorf("handshake: expected hello, got %q", hello.Type)
	}
	if hello.Version != proto.ControlVersion {
		return s.reject(conn, fmt.Sprintf("protocol version mismatch (server v%d, client v%d)", proto.ControlVersion, hello.Version))
	}
	if err := s.cfg.Auth.Check(hello.Token); err != nil {
		return s.reject(conn, err.Error())
	}

	sub := proto.NormalizeSubdomain(hello.Subdomain)
	if reserved := s.cfg.Auth.ReservedSubdomain(hello.Token); reserved != "" {
		sub = reserved
	}
	if err := s.cfg.Auth.CheckSubdomain(hello.Token, sub); err != nil {
		return s.reject(conn, err.Error())
	}
	if err := s.cfg.Auth.CheckReserved(hello.Token, sub, overTLS); err != nil {
		code := ""
		if errors.As(err, new(tlsRequiredError)) {
			code = proto.CodeTLSRequired
		}
		return s.rejectCode(conn, err.Error(), code)
	}

	// Forward-auth: a tunnel is protected if the client opted in (--protect)
	// or the signed token mandates it (prot claim). A protected tunnel on a
	// server with no auth provider configured is a misconfiguration — reject
	// rather than silently serve it unauthenticated.
	protected := hello.Protected || s.cfg.Auth.ProtectedByToken(hello.Token)
	if protected && !s.cfg.FA.Enabled() {
		return s.reject(conn, "tunnel protection requested but server has no auth provider configured")
	}

	sess := mux.NewServerSession(conn, br) // br may hold post-JSON bytes
	sess.PingInterval = s.cfg.MuxPingInterval
	sess.IdleTimeout = s.cfg.MuxIdleTimeout
	tokenID := s.cfg.Auth.TokenID(hello.Token)

	// Only a name the server generated may be re-rolled on collision; a
	// requested or token-assigned name must be refused instead, or a scoped
	// token could end up holding a random name.
	generated := sub == ""
	var client, evicted *Client
	for range 100 {
		name := sub
		if generated {
			name = randomSubdomain()
			if s.cfg.Auth.IsReserved(name) {
				continue
			}
		}
		var err error
		client, evicted, err = s.reg.Register(name, sess, conn.RemoteAddr().String(), tokenID)
		if err == nil {
			sub = name
			break
		}
		if err == errSubdomainTaken && generated {
			continue // generated name collided; roll again
		}
		return s.reject(conn, err.Error())
	}
	if client == nil {
		return s.reject(conn, "could not allocate a subdomain")
	}
	client.Protected = protected
	// Unblocks proxy requests waiting on this client; on the error path the
	// session is closed, so they fail fast instead of waiting out a timeout.
	defer client.markReady()
	if evicted != nil {
		s.log.Printf("tunnel %s: stale session taken over by %s (same token %s)", sub, conn.RemoteAddr(), tokenID)
		evicted.Session.CloseWithError(errTakenOver)
	}

	ack := proto.Ack{
		Type:      proto.TypeAck,
		OK:        true,
		Subdomain: sub,
		PublicURL: s.publicURL(sub),
	}
	if err := proto.WriteMessage(conn, ack); err != nil {
		s.reg.Unregister(client)
		sess.Close()
		return fmt.Errorf("ack: %w", err)
	}
	_ = conn.SetDeadline(time.Time{}) // clear handshake deadline
	client.markReady()
	transport := "tcp"
	if overTLS {
		transport = "tls"
	}
	s.log.Printf("tunnel up: %s ← %s (%s)", s.publicURL(sub), conn.RemoteAddr(), transport)

	err := sess.Run() // blocks until disconnect, idle timeout or takeover
	s.reg.Unregister(client)
	s.log.Printf("tunnel down: %s (%v)", sub, err)
	return nil
}

func (s *Server) reject(conn net.Conn, msg string) error { return s.rejectCode(conn, msg, "") }

func (s *Server) rejectCode(conn net.Conn, msg, code string) error {
	ack := proto.Ack{Type: proto.TypeAck, OK: false, Error: msg, Code: code}
	_ = proto.WriteMessage(conn, ack)
	return fmt.Errorf("rejected: %s", msg)
}

func (s *Server) publicURL(sub string) string {
	host := sub + "." + s.cfg.Domain
	if sub == "" {
		host = s.cfg.Domain
	}
	// Port shown in generated URLs: prefer an explicit public port (e.g. "443"
	// when behind a TLS proxy), otherwise derive from the proxy listener.
	port := s.cfg.PublicPort
	if port == "" {
		_, p, err := net.SplitHostPort(s.cfg.ProxyAddr)
		if err == nil {
			port = p
		}
	}
	switch {
	case s.cfg.PublicScheme == "http" && port != "80" && port != "":
		host += ":" + port
	case s.cfg.PublicScheme == "https" && port != "443" && port != "":
		host += ":" + port
	}
	return s.cfg.PublicScheme + "://" + host
}

// randomSubdomain returns a short DNS-safe name, e.g. "f3k9xq".
func randomSubdomain() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	n := binary.BigEndian.Uint32(b[:])
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	out := make([]byte, 6)
	for i := range out {
		out[i] = alphabet[n%36]
		n /= 36
	}
	return string(out)
}
