package client

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mtufekci/munnel/internal/inspection"
	"github.com/mtufekci/munnel/internal/mux"
	"github.com/mtufekci/munnel/internal/proto"
)

// EventKind classifies Tunnel events.
type EventKind string

const (
	EventConnecting   EventKind = "connecting"
	EventConnected    EventKind = "connected"
	EventReconnecting EventKind = "reconnecting"
	EventDisconnected EventKind = "disconnected"
	EventRequest      EventKind = "request"
	EventShuttingDown EventKind = "shutdown"
)

// Event is emitted on status changes and each completed request.
type Event struct {
	Kind      EventKind
	At        time.Time
	PublicURL string
	Subdomain string
	Message   string // error / info detail
	Record    *inspection.Record
}

// Status is a point-in-time snapshot of the tunnel for the inspector UI.
type Status struct {
	Connected   bool      `json:"connected"`
	PublicURL   string    `json:"public_url,omitempty"`
	Subdomain   string    `json:"subdomain,omitempty"`
	Target      string    `json:"target"`
	Server      string    `json:"server"`
	Since       time.Time `json:"since,omitempty"`
	Requests    int64     `json:"requests"`
	LastMessage string    `json:"last_message,omitempty"`
}

// Tunnel manages the persistent control connection to a munnel server,
// reconnecting with backoff on failure.
type Tunnel struct {
	cfg Config
	fwd *Forwarder

	events chan Event

	mu       sync.Mutex
	status   Status
	sess     *mux.Session
	requests atomic.Int64
	closed   bool // guards sends on events after shutdown closes it

	// OnRecord, if set, is invoked for every captured exchange (in addition
	// to the EventRequest emission). Inspector store/hub hook in here.
	OnRecord func(*inspection.Record)
}

// New builds a Tunnel. Run must be called to connect.
func New(cfg Config) (*Tunnel, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	t := &Tunnel{
		cfg:    cfg,
		fwd:    NewForwarder(cfg.LocalHost, cfg.LocalPort, cfg.MaxBody),
		events: make(chan Event, 256),
	}
	t.status.Target = "http://" + t.fwd.LocalAddr()
	t.status.Server = cfg.ServerAddr
	return t, nil
}

// Events returns the event stream. It is closed when Run finishes (after a
// final EventShuttingDown), so `for range tun.Events()` terminates cleanly on
// shutdown — including the non-interactive path in cmd/client.
func (t *Tunnel) Events() <-chan Event { return t.events }

// Forwarder exposes the local dispatcher (inspector uses it for replay).
func (t *Tunnel) Forwarder() *Forwarder { return t.fwd }

// Status returns a snapshot for the inspector's status endpoint.
func (t *Tunnel) Status() Status {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.status
	s.Requests = t.requests.Load()
	return s
}

// Run connects (and reconnects) until ctx is cancelled, then closes the event
// channel via shutdown.
func (t *Tunnel) Run(ctx context.Context) error {
	defer t.shutdown()
	backoff := time.Second
	for {
		t.emit(Event{Kind: EventConnecting, Message: "connecting to " + t.cfg.ServerAddr})
		err := t.connectOnce(ctx)
		if ctx.Err() != nil {
			t.emit(Event{Kind: EventShuttingDown})
			return nil
		}
		t.setStatus(func(s *Status) { s.Connected = false })
		var rej *rejectedError
		if errors.As(err, &rej) && rej.code == proto.CodeTLSRequired {
			// Each retry would resend the token in plaintext to a server
			// that will never accept it there. Stay down, with the reason
			// on screen, until the user quits.
			t.emit(Event{Kind: EventDisconnected, Message: err.Error() + " (not retrying: that would resend the token in plaintext)"})
			<-ctx.Done()
			t.emit(Event{Kind: EventShuttingDown})
			return nil
		}
		t.emit(Event{Kind: EventDisconnected, Message: err.Error()})

		select {
		case <-ctx.Done():
			t.emit(Event{Kind: EventShuttingDown})
			return nil
		case <-time.After(backoff):
		}
		t.emit(Event{Kind: EventReconnecting, Message: fmt.Sprintf("reconnecting (backoff %s)", backoff)})
		if backoff < 10*time.Second {
			backoff *= 2
			if backoff > 10*time.Second {
				backoff = 10 * time.Second
			}
		}
	}
}

// dial connects to the control port: plain TCP, or TLS (handshake included,
// so a bad certificate or pin fails here) when cfg.TLS is set.
func (t *Tunnel) dial(ctx context.Context) (net.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second}
	if !t.cfg.TLS {
		return d.DialContext(ctx, "tcp", t.cfg.ServerAddr)
	}
	td := &tls.Dialer{NetDialer: d, Config: t.cfg.tlsConfig()}
	return td.DialContext(ctx, "tcp", t.cfg.ServerAddr)
}

// connectOnce performs the handshake and pumps one mux session to completion.
func (t *Tunnel) connectOnce(ctx context.Context) error {
	conn, err := t.dial(ctx)
	if err != nil {
		return fmt.Errorf("dial %s: %w", t.cfg.ServerAddr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	// If ctx is cancelled while the session is live, close the socket so
	// sess.Run() returns promptly instead of blocking on a live connection
	// (the mux read loop has no other ctx hook). Without this, cancelling ctx
	// during an active tunnel never propagates to Run.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-done:
		}
	}()

	hello := proto.Hello{
		Type:      proto.TypeHello,
		Version:   proto.ControlVersion,
		Token:     t.cfg.Token,
		Subdomain: t.cfg.Subdomain,
		Protected: t.cfg.Protect,
	}
	if err := proto.WriteMessage(conn, hello); err != nil {
		return fmt.Errorf("handshake write: %w", err)
	}
	br := bufio.NewReader(conn)
	var ack proto.Ack
	if err := proto.ReadMessage(br, &ack); err != nil {
		return fmt.Errorf("handshake read: %w", err)
	}
	if !ack.OK {
		return &rejectedError{msg: ack.Error, code: ack.Code}
	}
	_ = conn.SetDeadline(time.Time{})

	sess := mux.NewClientSession(conn, br)
	t.cfg.tuneSession(sess)
	sess.OnStream = func(st *mux.Stream) {
		go func() {
			rec := t.fwd.Serve(st)
			if rec == nil {
				return
			}
			t.requests.Add(1)
			if t.OnRecord != nil {
				t.OnRecord(rec)
			}
			t.emit(Event{Kind: EventRequest, Record: rec})
		}()
	}

	t.mu.Lock()
	t.sess = sess
	t.status.Connected = true
	t.status.PublicURL = ack.PublicURL
	t.status.Subdomain = ack.Subdomain
	t.status.Since = time.Now()
	t.mu.Unlock()

	t.emit(Event{Kind: EventConnected, PublicURL: ack.PublicURL, Subdomain: ack.Subdomain})

	err = sess.Run()
	t.mu.Lock()
	t.sess = nil
	t.mu.Unlock()
	if err == nil {
		return fmt.Errorf("session ended")
	}
	return err
}

// rejectedError is a refusal in the handshake ack; code is proto.Ack.Code.
type rejectedError struct{ msg, code string }

func (e *rejectedError) Error() string { return "server rejected connection: " + e.msg }

func (t *Tunnel) setStatus(f func(*Status)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	f(&t.status)
}

func (t *Tunnel) emit(e Event) {
	e.At = time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return // shutdown has closed the channel; drop late events
	}
	if e.Message != "" {
		t.status.LastMessage = e.Message
	}
	select {
	case t.events <- e:
	default: // drop if the UI is wedged; tunnels must never block
	}
}

// shutdown closes the event channel so consumers ranging over Events()
// unblock. It is called once when Run returns. emit checks t.closed under the
// same mutex, so in-flight emitters never send on a closed channel — they
// no-op instead. In-flight request handlers finish on their own once the
// session socket closes (see connectOnce's ctx watcher).
func (t *Tunnel) shutdown() {
	t.mu.Lock()
	t.closed = true
	close(t.events)
	t.mu.Unlock()
}
