package inspection

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const wsWriteDeadline = 5 * time.Second

// Hub fans captured records out to every connected inspector tab.
type Hub struct {
	mu    sync.RWMutex
	conns map[*websocket.Conn]bool
}

func NewHub() *Hub {
	return &Hub{conns: map[*websocket.Conn]bool{}}
}

var upgrader = websocket.Upgrader{
	// Server.guard has already checked Host, Origin (when sent) and the
	// access token before a request reaches ServeWS.
	CheckOrigin: func(r *http.Request) bool { return true },
}

// ServeWS upgrades the connection and forwards broadcasts until it dies.
func (h *Hub) ServeWS(w http.ResponseWriter, r *http.Request) {
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return // upgrade already wrote the error
	}
	h.mu.Lock()
	h.conns[c] = true
	h.mu.Unlock()

	// The hub only writes; we still must read to notice disconnects and
	// answer pings. Discard everything else.
	defer func() {
		h.mu.Lock()
		delete(h.conns, c)
		h.mu.Unlock()
		c.Close()
	}()
	for {
		if _, _, err := c.ReadMessage(); err != nil {
			return
		}
	}
}

// BroadcastRecord sends a {"type":"request",...} event to all clients.
func (h *Hub) BroadcastRecord(rec *Record) {
	h.broadcast(map[string]any{"type": "request", "record": rec})
}

func (h *Hub) broadcast(v any) {
	payload, err := json.Marshal(v)
	if err != nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	dead := []*websocket.Conn{}
	for c := range h.conns {
		_ = c.SetWriteDeadline(time.Now().Add(wsWriteDeadline))
		if err := c.WriteMessage(websocket.TextMessage, payload); err != nil {
			dead = append(dead, c)
		}
	}
	for _, c := range dead {
		delete(h.conns, c)
		c.Close()
	}
}
