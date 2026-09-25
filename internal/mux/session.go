package mux

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DefaultPingInterval is how often each side sends a PING.
	DefaultPingInterval = 15 * time.Second
	// DefaultIdleTimeout closes a session that has received nothing at all
	// (pongs and the peer's own pings included) for this long.
	DefaultIdleTimeout = 45 * time.Second

	pingTimestamp = 8
)

// ErrIdleTimeout ends a session whose peer went silent: not a byte arrived
// within the idle timeout, so the peer is presumed dead (laptop asleep, NAT
// mapping dropped, cable pulled) even though no FIN or RST ever came.
var ErrIdleTimeout = errors.New("mux: peer went silent (idle timeout)")

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

	// PingInterval and IdleTimeout tune liveness; set them before Run. Zero
	// means DefaultPingInterval / DefaultIdleTimeout. Without an idle
	// timeout a peer that vanished without closing the socket would hold the
	// session (and its subdomain) until TCP gave up, which can take hours.
	PingInterval time.Duration
	IdleTimeout  time.Duration

	// lastRecv is when the last byte arrived, as an offset from epoch. The
	// offset comes from the monotonic clock: a wall-clock step (NTP, a VM
	// resume) must neither close every tunnel at once nor delay the
	// detection of a dead one.
	epoch    time.Time
	lastRecv atomic.Int64 // time.Duration since epoch
	stalled  atomic.Bool  // read loop blocked delivering DATA to a slow reader
	pongs    chan []byte  // pong payloads for the heartbeat goroutine to send

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
	if tc := tcpConn(conn); tc != nil {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
	s := &Session{
		conn:    conn,
		server:  server,
		streams: make(map[uint32]*Stream),
		epoch:   time.Now(),
		done:    make(chan struct{}),
		pongs:   make(chan []byte, 1),
	}
	s.r = liveReader{r: r, sess: s}
	return s
}

// liveReader marks the session alive whenever bytes arrive, not only when a
// whole frame has. A DATA frame can be 1 MiB, the sender holds the write lock
// for all of it (no ping gets in between), and on a slow link (a throttled
// hotspot) it may take longer than the idle timeout to arrive.
type liveReader struct {
	r    io.Reader
	sess *Session
}

func (l liveReader) Read(p []byte) (int, error) {
	n, err := l.r.Read(p)
	if n > 0 {
		l.sess.markRecv()
	}
	return n, err
}

// markRecv records that something arrived from the peer just now.
func (s *Session) markRecv() { s.lastRecv.Store(int64(time.Since(s.epoch))) }

// silence is how long nothing has arrived from the peer.
func (s *Session) silence() time.Duration {
	return time.Since(s.epoch) - time.Duration(s.lastRecv.Load())
}

// Stale reports whether the peer has missed a heartbeat: nothing, not even
// part of a frame, has arrived for one and a half ping intervals, although a
// live peer answers every ping within a round trip. A read loop stalled on
// one of our own slow stream readers is never stale: the peer's bytes may be
// waiting unread. The server uses this to let a reconnecting client take its
// name over only from a session that is really gone.
func (s *Session) Stale() bool {
	if s.stalled.Load() {
		return false
	}
	p := s.pingInterval()
	return s.silence() > p+p/2
}

func (s *Session) pingInterval() time.Duration {
	if s.PingInterval > 0 {
		return s.PingInterval
	}
	return DefaultPingInterval
}

// tcpConn finds the TCP socket under conn, unwrapping TLS (tls.Conn exposes
// NetConn), so socket options apply on both control ports.
func tcpConn(conn net.Conn) *net.TCPConn {
	for {
		switch c := conn.(type) {
		case *net.TCPConn:
			return c
		case interface{ NetConn() net.Conn }:
			conn = c.NetConn()
		default:
			return nil
		}
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
	if tc := tcpConn(s.conn); tc != nil {
		_ = tc.SetReadBuffer(1 << 20)
		_ = tc.SetWriteBuffer(1 << 20)
	}
	s.markRecv()
	stopPing := s.startHeartbeat()
	defer close(stopPing)

	err := s.readLoop()
	s.shutdown(err)
	// A deliberate close (idle timeout, CloseWithError) closes the socket, so
	// readLoop only sees "use of closed connection"; report the real reason.
	s.mu.Lock()
	err = s.closeErr
	s.mu.Unlock()
	s.fireOnClose(err)
	return err
}

// Close terminates the session and every open stream.
func (s *Session) Close() { s.CloseWithError(net.ErrClosed) }

// CloseWithError terminates the session like Close; err becomes the error
// Run returns and OnClose receives (first close wins).
func (s *Session) CloseWithError(err error) {
	s.shutdown(err)
	s.fireOnClose(err)
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
				// pushData blocks while the stream's reader is slow. That is
				// our stall, not a silent peer, so the idle watchdog must not
				// count it (see watchdog).
				s.stalled.Store(true)
				st.pushData(payload)
				// Restart the silence clock before clearing stalled, or the
				// watchdog could count the stall itself as silence.
				s.markRecv()
				s.stalled.Store(false)
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
			// The heartbeat goroutine writes the pong: a read loop blocked
			// on a write stops reading, which would starve our own idle
			// check. One pending pong is enough to prove liveness.
			select {
			case s.pongs <- payload:
			default:
			}
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

// startHeartbeat runs two goroutines: a pinger (which also answers pings),
// and a watchdog that closes the session when not a byte has been received
// for IdleTimeout. They are separate because a ping write can block on a dead
// peer's full TCP window; the watchdog never writes, and closing the socket
// unblocks that write.
func (s *Session) startHeartbeat() chan struct{} {
	ping := s.pingInterval()
	idle := s.IdleTimeout
	if idle <= 0 {
		idle = DefaultIdleTimeout
	}
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(ping)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				var ts [pingTimestamp]byte
				binary.BigEndian.PutUint64(ts[:], uint64(time.Now().UnixNano()))
				if err := s.writeFrame(FramePing, 0, ts[:]); err != nil {
					return
				}
			case p := <-s.pongs:
				if err := s.writeFrame(FramePong, 0, p); err != nil {
					return
				}
			case <-stop:
				return
			case <-s.done:
				return
			}
		}
	}()
	go s.watchdog(idle, stop)
	return stop
}

func (s *Session) watchdog(idle time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(max(idle/4, time.Millisecond))
	defer t.Stop()
	for {
		select {
		case <-t.C:
			if s.stalled.Load() {
				continue
			}
			if s.silence() > idle {
				s.CloseWithError(ErrIdleTimeout)
				return
			}
		case <-stop:
			return
		case <-s.done:
			return
		}
	}
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
			st.signalAbort()
		}
		close(s.done)
		_ = s.conn.Close()
	})
}
