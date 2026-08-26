package mux

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	pingInterval  = 15 * time.Second
	pingTimestamp = 8
)

// Session multiplexes many Streams over one net.Conn.
//
// Stream IDs use parity to avoid collisions: the side that started as the
// "server" allocates odd IDs, the "client" even IDs. In munnel the tunnel
// server opens all streams (one per incoming public HTTP request), so the
// client side never allocates, but the parity rule keeps the protocol
// symmetric and safe.
type Session struct {
	conn   net.Conn
	r      io.Reader // possibly bufio-buffered view of conn (post-handshake)
	server bool

	wmu sync.Mutex // serializes frame writes

	mu      sync.Mutex
	streams map[uint32]*Stream
	closed  bool

	nextID atomic.Uint32

	// OnStream is invoked (in its own goroutine) for each inbound OPEN frame.
	OnStream func(*Stream)
	// OnClose is invoked exactly once when Run returns.
	OnClose func(error)

	done      chan struct{}
	closeOnce sync.Once
	cbOnce    sync.Once
	closeErr  error
}

// NewServerSession creates the server side of a session (odd stream IDs).
// r must be a reader over conn that preserves any bytes already buffered
// during the control handshake (pass your *bufio.Reader).
func NewServerSession(conn net.Conn, r io.Reader) *Session {
	s := newSession(conn, r, true)
	s.nextID.Store(1)
	return s
}

// NewClientSession creates the client side of a session (even stream IDs).
func NewClientSession(conn net.Conn, r io.Reader) *Session {
	s := newSession(conn, r, false)
	s.nextID.Store(2)
	return s
}

func newSession(conn net.Conn, r io.Reader, server bool) *Session {
	if r == nil {
		r = conn
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
	return &Session{
		conn:    conn,
		r:       r,
		server:  server,
		streams: make(map[uint32]*Stream),
		done:    make(chan struct{}),
	}
}

// IsServer reports whether this is the server side of the session.
func (s *Session) IsServer() bool { return s.server }

// OpenStream allocates a stream ID, sends an OPEN frame with an optional
// metadata blob, and returns the ready stream.
func (s *Session) OpenStream(meta []byte) (*Stream, error) {
	id := s.nextID.Add(2) - 2
	st := newStream(s, id)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, errSessionClosed
	}
	s.streams[id] = st
	s.mu.Unlock()
	if err := s.writeFrame(FrameOpen, id, meta); err != nil {
		s.removeStream(id)
		return nil, err
	}
	return st, nil
}

// Run pumps frames until the connection dies or Close is called. It is
// blocking; callers typically run it in a goroutine.
func (s *Session) Run() error {
	if tc, ok := s.conn.(*net.TCPConn); ok {
		_ = tc.SetReadBuffer(1 << 20)
		_ = tc.SetWriteBuffer(1 << 20)
	}
	stopPing := s.startHeartbeat()
	defer close(stopPing)

	err := s.readLoop()
	s.shutdown(err)
	s.fireOnClose(err)
	return err
}

// Close terminates the session and every open stream.
func (s *Session) Close() {
	s.shutdown(net.ErrClosed)
	s.fireOnClose(net.ErrClosed)
}

func (s *Session) fireOnClose(err error) {
	if s.OnClose != nil {
		s.cbOnce.Do(func() { s.OnClose(err) })
	}
}

// Wait blocks until the session is closed.
func (s *Session) Wait() error {
	<-s.done
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeErr
}

// StreamCount reports the number of live streams.
func (s *Session) StreamCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.streams)
}

func (s *Session) readLoop() error {
	for {
		typ, id, payload, err := readFrame(s.r)
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return err
		}
		switch typ {
		case FrameOpen:
			st := newStream(s, id)
			s.mu.Lock()
			if s.closed {
				s.mu.Unlock()
				continue
			}
			s.streams[id] = st
			s.mu.Unlock()
			if s.OnStream != nil {
				go s.OnStream(st)
			}
		case FrameData:
			if st := s.getStream(id); st != nil {
				st.pushData(payload)
			}
		case FrameClose:
			if st := s.getStream(id); st != nil {
				st.remoteClose()
			}
		case FrameReset:
			if st := s.getStream(id); st != nil {
				st.remoteReset()
			}
		case FramePing:
			_ = s.writeFrame(FramePong, 0, payload)
		case FramePong:
			// Keepalive ack; RTT measurement could hook in here.
		default:
			return fmt.Errorf("mux: unknown frame type %s", frameName(typ))
		}
	}
}

func (s *Session) getStream(id uint32) *Stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.streams[id]
}

func (s *Session) removeStream(id uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.streams, id)
}

func (s *Session) writeFrame(typ byte, id uint32, payload []byte) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return errSessionClosed
	}
	return writeFrame(s.conn, typ, id, payload)
}

func (s *Session) startHeartbeat() chan struct{} {
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(pingInterval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				var ts [pingTimestamp]byte
				binary.BigEndian.PutUint64(ts[:], uint64(time.Now().UnixNano()))
				if err := s.writeFrame(FramePing, 0, ts[:]); err != nil {
					return
				}
			case <-stop:
				return
			case <-s.done:
				return
			}
		}
	}()
	return stop
}

func (s *Session) shutdown(err error) {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.closeErr = err
		streams := make([]*Stream, 0, len(s.streams))
		for _, st := range s.streams {
			streams = append(streams, st)
		}
		s.mu.Unlock()
		for _, st := range streams {
			// Wake any blocked readers/writers with a non-graceful EOF.
			// pushData drops late frames after this via s.sess.done.
			st.markReadDone(errSessionClosed)
		}
		close(s.done)
		_ = s.conn.Close()
	})
}
