package server

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/mtufekci/munnel/internal/mux"
)

// Client is one connected tunnel client holding a subdomain.
type Client struct {
	Subdomain   string
	Session     *mux.Session
	RemoteAddr  string
	ConnectedAt time.Time
	Protected   bool   // forward-auth required to view this tunnel
	TokenID     string // signed-token ID that opened it; "" for static/open

	// ready is closed once the handshake ack has been written. The client
	// is registered before the ack (so a taken name can still be refused in
	// it), and a stream opened in that gap would put a mux frame on the wire
	// ahead of the ack line.
	ready     chan struct{}
	readyOnce sync.Once
}

func (c *Client) markReady() { c.readyOnce.Do(func() { close(c.ready) }) }

// waitReady blocks until the handshake finished (true), or ctx ends or a
// few seconds pass (false).
func (c *Client) waitReady(ctx context.Context) bool {
	select {
	case <-c.ready:
		return true
	default:
	}
	t := time.NewTimer(5 * time.Second)
	defer t.Stop()
	select {
	case <-c.ready:
		return true
	case <-ctx.Done():
		return false
	case <-t.C:
		return false
	}
}

// Registry is a thread-safe subdomain → client map.
type Registry struct {
	mu      sync.RWMutex
	clients map[string]*Client

	// OnChange fires after any register/unregister (for server logs).
	OnChange func(c *Client, connected bool)
}

func NewRegistry() *Registry {
	return &Registry{clients: map[string]*Client{}}
}

var errSubdomainTaken = errors.New("subdomain already in use")

// Register claims a subdomain for a session. A name held by a stale session
// (one that has missed a heartbeat, see mux.Session.Stale) that authenticated
// with the same signed-token ID is taken over: the new client replaces it and
// the old one is returned as evicted for the caller to close. A client that
// reconnects after a network drop or a laptop sleep therefore gets its name
// back within a ping interval or two instead of waiting out the idle timeout.
// A holder that still answers pings is never evicted: the token alone proves
// little, since it crosses the plaintext control port in the clear, and a
// sniffer must not be able to take a live tunnel's name. Static and open-mode
// clients (no token ID) never evict.
func (r *Registry) Register(sub string, sess *mux.Session, remote, tokenID string) (c, evicted *Client, err error) {
	r.mu.Lock()
	if cur, exists := r.clients[sub]; exists {
		if tokenID == "" || cur.TokenID != tokenID || !cur.Session.Stale() {
			r.mu.Unlock()
			return nil, nil, errSubdomainTaken
		}
		evicted = cur
	}
	c = &Client{
		Subdomain:   sub,
		Session:     sess,
		RemoteAddr:  remote,
		ConnectedAt: time.Now(),
		TokenID:     tokenID,
		ready:       make(chan struct{}),
	}
	r.clients[sub] = c
	r.mu.Unlock()
	if r.OnChange != nil {
		if evicted != nil {
			r.OnChange(evicted, false)
		}
		r.OnChange(c, true)
	}
	return c, evicted, nil
}

// Unregister releases a subdomain only if it is still held by this session,
// so a reconnect racing a stale unregister can never evict the new session.
func (r *Registry) Unregister(c *Client) {
	r.mu.Lock()
	cur, ok := r.clients[c.Subdomain]
	if !ok || cur.Session != c.Session {
		r.mu.Unlock()
		return
	}
	delete(r.clients, c.Subdomain)
	r.mu.Unlock()
	if r.OnChange != nil {
		r.OnChange(c, false)
	}
}

// Get returns the client holding a subdomain, or nil.
func (r *Registry) Get(sub string) *Client {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.clients[sub]
}

// Count reports how many tunnels are live.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.clients)
}
