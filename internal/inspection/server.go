package inspection

import (
	"context"
	_ "embed"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Replayer re-dispatches a captured request to the local service.
// Implemented by client.Forwarder.
type Replayer interface {
	Replay(rec *Record) (*Record, error)
}

// StatusFunc supplies the tunnel status snapshot for /api/status.
type StatusFunc func() any

//go:embed web/index.html
var indexHTML string

// Server is the inspector web app: embedded UI + JSON API + websocket feed.
type Server struct {
	store    *Store
	hub      *Hub
	replayer Replayer
	status   StatusFunc

	http *http.Server
	ln   net.Listener
	mu   sync.RWMutex // guards ln across ListenAndServe/Addr
}

// New wires an inspector Server.
func New(store *Store, hub *Hub, replayer Replayer, status StatusFunc) *Server {
	s := &Server{store: store, hub: hub, replayer: replayer, status: status}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.serveIndex)
	mux.HandleFunc("GET /api/requests", s.serveList)
	mux.HandleFunc("GET /api/requests/{id}", s.serveOne)
	mux.HandleFunc("POST /api/replay/{id}", s.serveReplay)
	mux.HandleFunc("DELETE /api/requests", s.serveClear)
	mux.HandleFunc("GET /api/status", s.serveStatus)
	mux.HandleFunc("GET /ws", s.hub.ServeWS)
	s.http = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	return s
}

// ListenAndServe binds addr (e.g. ":4040") and serves until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		s.http.Shutdown(shutdownCtx)
		ln.Close()
	}()
	return s.http.Serve(ln)
}

// Addr returns the bound address (valid after ListenAndServe starts). Safe to
// call concurrently with ListenAndServe.
func (s *Server) Addr() string {
	s.mu.RLock()
	ln := s.ln
	s.mu.RUnlock()
	if ln == nil {
		return ""
	}
	return ln.Addr().String()
}

func (s *Server) serveIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(indexHTML))
}

func (s *Server) serveList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.store.List())
}

func (s *Server) serveOne(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad id")
		return
	}
	rec := s.store.Get(id)
	if rec == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

func (s *Server) serveReplay(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad id")
		return
	}
	rec := s.store.Get(id)
	if rec == nil {
		writeError(w, http.StatusNotFound, "request no longer in buffer")
		return
	}
	if s.replayer == nil {
		writeError(w, http.StatusServiceUnavailable, "replay unavailable")
		return
	}
	fresh, err := s.replayer.Replay(rec)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	stored := s.store.Add(fresh)
	s.hub.BroadcastRecord(stored)
	writeJSON(w, http.StatusOK, stored)
}

func (s *Server) serveClear(w http.ResponseWriter, r *http.Request) {
	s.store.Clear()
	writeJSON(w, http.StatusOK, map[string]string{"status": "cleared"})
}

func (s *Server) serveStatus(w http.ResponseWriter, r *http.Request) {
	if s.status == nil {
		writeJSON(w, http.StatusOK, map[string]any{"connected": false})
		return
	}
	writeJSON(w, http.StatusOK, s.status())
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "")
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"error": msg, "status": code})
}
