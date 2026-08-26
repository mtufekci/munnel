package server

import (
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
	Protected   bool // forward-auth required to view this tunnel
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

// Register claims a subdomain for a session.
func (r *Registry) Register(sub string, sess *mux.Session, remote string) (*Client, error) {
	r.mu.Lock()
	if _, exists := r.clients[sub]; exists {
		r.mu.Unlock()
		return nil, errSubdomainTaken
	}
	c := &Client{
		Subdomain:   sub,
		Session:     sess,
		RemoteAddr:  remote,
		ConnectedAt: time.Now(),
	}
	r.clients[sub] = c
	r.mu.Unlock()
	if r.OnChange != nil {
		r.OnChange(c, true)
	}
	return c, nil
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
