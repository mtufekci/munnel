// Package inspection captures, stores, and replays requests flowing through
// a munnel client, and serves the live web inspector UI.
package inspection

import (
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Record is one captured HTTP exchange, request and response.
type Record struct {
	ID       int64     `json:"id"`
	Time     time.Time `json:"time"`
	Duration int64     `json:"duration_ms"`
	Replayed bool      `json:"replayed"` // produced by a replay, not live traffic
	Errored  bool      `json:"errored"`
	Error    string    `json:"error,omitempty"`

	Method       string      `json:"method"`
	Path         string      `json:"path"`
	ReqHeaders   http.Header `json:"req_headers"`
	ReqBody      string      `json:"req_body"`
	ReqTruncated bool        `json:"req_body_truncated"`

	Status        int         `json:"status"`
	RespHeaders   http.Header `json:"resp_headers"`
	RespBody      string      `json:"resp_body"`
	RespTruncated bool        `json:"resp_body_truncated"`
}

// DefaultCapacity is the ring buffer size of a Store.
const DefaultCapacity = 200

// Store is a fixed-capacity ring buffer of Records, newest last.
type Store struct {
	mu   sync.RWMutex
	buf  []*Record
	cap  int // len(buf) — fixed
	head int // next write index
	n    int // number of live entries
	seq  atomic.Int64
}

func NewStore(capacity int) *Store {
	if capacity <= 0 {
		capacity = DefaultCapacity
	}
	return &Store{buf: make([]*Record, capacity), cap: capacity}
}

// Add assigns an ID, timestamps if unset, and stores the record.
func (s *Store) Add(rec *Record) *Record {
	rec.ID = s.seq.Add(1)
	if rec.Time.IsZero() {
		rec.Time = time.Now()
	}
	s.mu.Lock()
	s.buf[s.head] = rec
	s.head = (s.head + 1) % s.cap
	if s.n < s.cap {
		s.n++
	}
	s.mu.Unlock()
	return rec
}

// List returns stored records, newest first.
func (s *Store) List() []*Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Record, 0, s.n)
	for i := 0; i < s.n; i++ {
		idx := (s.head - 1 - i + s.cap) % s.cap
		out = append(out, s.buf[idx])
	}
	return out
}

// Get returns a record by ID, or nil.
func (s *Store) Get(id int64) *Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := 0; i < s.n; i++ {
		idx := (s.head - 1 - i + s.cap) % s.cap
		if s.buf[idx].ID == id {
			return s.buf[idx]
		}
	}
	return nil
}

// Size returns the number of live entries.
func (s *Store) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.n
}

// Clear drops all stored records (IDs keep increasing).
func (s *Store) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buf = make([]*Record, s.cap)
	s.head = 0
	s.n = 0
}
