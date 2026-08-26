package server

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/mtufekci/munnel/internal/forwardauth"
	"github.com/mtufekci/munnel/internal/mux"
	"github.com/mtufekci/munnel/internal/proto"
)

// handshakeTimeout bounds the hello/ack exchange before the socket is handed
// to the mux layer.
const handshakeTimeout = 15 * time.Second

// Config holds server settings.
type Config struct {
	Domain         string // base domain, e.g. "tunnels.example.com"
	ControlAddr    string // control + multiplex listener, e.g. ":7001"
	ProxyAddr      string // public HTTP ingress, e.g. ":8080"
	PublicPort     string // port shown in public URLs (e.g. "443" behind a TLS proxy); "" derives from ProxyAddr
	PublicScheme   string // scheme shown in public URLs ("https" behind Caddy/Cloudflare)
	MaxRequestBody int64  // per-request body cap in bytes
	Auth           *Authenticator
	FA             *forwardauth.Manager // nil = forward-auth disabled server-wide
	Logger         *log.Logger
}

// Server is the munnel tunnel server: control listener + public proxy.
type Server struct {
	cfg Config
	reg *Registry
	log *log.Logger

	controlLn net.Listener
	proxyLn   net.Listener
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

// Bind creates both listeners (synchronously — safe to inspect afterwards,
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
	s.proxyLn, err = net.Listen("tcp", s.cfg.ProxyAddr)
	if err != nil {
		s.controlLn.Close()
		s.controlLn = nil
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
	errCh := make(chan error, 2)

	mode := "open (no auth)"
	if !s.cfg.Auth.Open() {
		n := s.cfg.Auth.StaticTokenCount()
		mode = fmt.Sprintf("token auth (%d static token%s", n, plural(n))
		if s.cfg.Auth.SignedEnabled() {
			mode += " + signed tokens"
		}
		mode += ")"
	}
	s.log.Printf("munnel-server up — domain=%s control=%s proxy=%s auth=%s",
		s.cfg.Domain, s.controlLn.Addr(), s.proxyLn.Addr(), mode)

	go s.acceptLoop(s.controlLn, errCh)
	go func() { errCh <- s.serveProxyHTTP() }()

	select {
	case err := <-errCh: // a listener died
		s.controlLn.Close()
		s.proxyLn.Close()
		<-errCh
		return err
	case <-ctx.Done():
		s.controlLn.Close()
		s.proxyLn.Close()
		<-errCh
		<-errCh
		return nil
	}
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func (s *Server) acceptLoop(ln net.Listener, errCh chan<- error) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- fmt.Errorf("control accept: %w", err)
			return
		}
		go func() {
			if err := s.handleControlConn(conn); err != nil {
				s.log.Printf("control %s: %v", conn.RemoteAddr(), err)
			}
		}()
	}
}

// handleControlConn runs the handshake, registers the tunnel, and pumps the
// mux session until it dies.
func (s *Server) handleControlConn(conn net.Conn) error {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))

	br := bufio.NewReader(conn)
	var hello proto.Hello
	if err := json.NewDecoder(br).Decode(&hello); err != nil {
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

	// Forward-auth: a tunnel is protected if the client opted in (--protect)
	// or the signed token mandates it (prot claim). A protected tunnel on a
	// server with no auth provider configured is a misconfiguration — reject
	// rather than silently serve it unauthenticated.
	protected := hello.Protected || s.cfg.Auth.ProtectedByToken(hello.Token)
	if protected && !s.cfg.FA.Enabled() {
		return s.reject(conn, "tunnel protection requested but server has no auth provider configured")
	}

	sess := mux.NewServerSession(conn, br) // br may hold post-JSON bytes
	client := &Client{}
	for range 100 {
		if sub == "" {
			sub = randomSubdomain()
		}
		var err error
		client, err = s.reg.Register(sub, sess, conn.RemoteAddr().String())
		if err == nil {
			break
		}
		if err == errSubdomainTaken && hello.Subdomain == "" {
			sub = "" // generated name collided; roll again
			continue
		}
		return s.reject(conn, err.Error())
	}
	if client.Session == nil {
		return s.reject(conn, "could not allocate a subdomain")
	}
	client.Protected = protected

	ack := proto.Ack{
		Type:      proto.TypeAck,
		OK:        true,
		Subdomain: sub,
		PublicURL: s.publicURL(sub),
	}
	if err := json.NewEncoder(conn).Encode(ack); err != nil {
		s.reg.Unregister(client)
		return fmt.Errorf("ack: %w", err)
	}
	_ = conn.SetDeadline(time.Time{}) // clear handshake deadline
	s.log.Printf("tunnel up: %s ← %s", s.publicURL(sub), conn.RemoteAddr())

	sess.OnClose = func(err error) {
		s.reg.Unregister(client)
		s.log.Printf("tunnel down: %s (%v)", sub, err)
	}
	sess.Run() // blocks until disconnect
	return nil
}

func (s *Server) reject(conn net.Conn, msg string) error {
	ack := proto.Ack{Type: proto.TypeAck, OK: false, Error: msg}
	_ = json.NewEncoder(conn).Encode(ack)
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
