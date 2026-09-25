package mux

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// ErrStreamReset is returned when the peer aborts the stream with a RESET frame.
var ErrStreamReset = errors.New("mux: stream reset by peer")

// errSessionClosed is the terminal read error when the owning session dies
// mid-stream. Read surfaces it as io.ErrUnexpectedEOF so HTTP parsers treat
// it as a truncated (not clean) end of body.
var errSessionClosed = errors.New("mux: session closed")

// Stream is one logical full-duplex byte stream multiplexed over a Session.
// It satisfies net.Conn (deadlines are accepted but are no-ops: the owning
// Session owns socket-level keepalives).
//
// Design notes:
//   - chunks is never closed; EOF is signalled by closing eofCh exactly once.
//     This makes "send on closed channel" races impossible.
//   - pushData sends without holding the stream lock, so a full buffer
//     backpressures the session read loop (and thus TCP), never deadlocks
//     against a closer.
//   - Streams assume a single concurrent reader; writers may be concurrent.
type Stream struct {
	id   uint32
	sess *Session

	chunks chan []byte   // inbound DATA payloads, never closed
	eofCh  chan struct{} // closed once, after readErr is published
	cur    []byte        // partially consumed chunk, owned by the reader

	aborted   chan struct{} // closed once the stream is reset or its session dies
	abortOnce sync.Once

	mu        sync.Mutex // guards readErr/readDone/sentClose/reset
	readErr   error
	readDone  bool
	sentClose bool // CLOSE/RESET frame already sent
	reset     bool // aborted locally or by peer; writes must fail

	wmu sync.Mutex // serializes frame emission from Write/CloseWrite

	removeOnce sync.Once
}

func newStream(sess *Session, id uint32) *Stream {
	return &Stream{
		id:      id,
		sess:    sess,
		chunks:  make(chan []byte, 16),
		eofCh:   make(chan struct{}),
		aborted: make(chan struct{}),
	}
}

// Aborted is closed when the stream ends abnormally: a RESET from either side
// or the death of the session. It is never closed by a graceful CLOSE. The
// tunnel client watches it to drop the local request when the public viewer
// goes away (an SSE response would otherwise keep the local connection open).
func (s *Stream) Aborted() <-chan struct{} { return s.aborted }

func (s *Stream) signalAbort() {
	s.abortOnce.Do(func() { close(s.aborted) })
}

// ID returns the stream identifier unique within its session.
func (s *Stream) ID() uint32 { return s.id }

// pushData delivers an inbound DATA payload to the reader. It blocks if the
// per-stream buffer is full — deliberately: that stalls the session read
// loop and lets TCP apply backpressure to the peer. After EOF the payload
// is dropped (a peer sending DATA after CLOSE is violating the protocol).
func (s *Stream) pushData(p []byte) {
	s.mu.Lock()
	done := s.readDone
	s.mu.Unlock()
	if done {
		return
	}
	select {
	case s.chunks <- p:
	case <-s.eofCh: // raced with markReadDone; drop
	case <-s.sess.done:
	}
}

// markReadDone publishes the terminal read state and wakes readers. Only the
// first call has an effect. Reports whether this call won.
func (s *Stream) markReadDone(err error) bool {
	s.mu.Lock()
	if s.readDone {
		s.mu.Unlock()
		return false
	}
	s.readDone = true
	s.readErr = err
	s.mu.Unlock()
	close(s.eofCh) // happens-after the readErr publication above
	return true
}

// remoteClose marks the peer as finished sending: the reader gets EOF after
// buffered data drains.
func (s *Stream) remoteClose() {
	s.markReadDone(io.EOF)
	s.mu.Lock()
	both := s.sentClose
	s.mu.Unlock()
	if both {
		s.remove()
	}
}

// remoteReset aborts the stream immediately in both directions.
func (s *Stream) remoteReset() {
	s.mu.Lock()
	s.reset = true
	s.mu.Unlock()
	s.markReadDone(ErrStreamReset)
	s.signalAbort()
	s.remove()
}

func (s *Stream) remove() {
	s.removeOnce.Do(func() { s.sess.removeStream(s.id) })
}

// Read implements io.Reader. After the peer sends CLOSE and all buffered
// data is consumed, Read returns io.EOF.
func (s *Stream) Read(b []byte) (int, error) {
	for {
		if len(s.cur) > 0 {
			n := copy(b, s.cur)
			s.cur = s.cur[n:]
			return n, nil
		}

		s.mu.Lock()
		done, rerr := s.readDone, s.readErr
		s.mu.Unlock()
		if done {
			// Best-effort drain of anything buffered before EOF was marked.
			select {
			case c := <-s.chunks:
				s.cur = c
				continue
			default:
			}
			switch rerr {
			case nil, io.EOF:
				return 0, io.EOF
			case errSessionClosed:
				return 0, io.ErrUnexpectedEOF
			default:
				return 0, rerr
			}
		}

		select {
		case c := <-s.chunks:
			s.cur = c
		case <-s.eofCh:
			// readDone is visible now; loop handles the terminal state.
		case <-s.sess.done:
			// Session is gone; shutdown marked every stream, so loop.
		}
	}
}

// Write implements io.Writer. Large buffers are chunked into MaxPayload-sized
// frames automatically.
func (s *Stream) Write(b []byte) (int, error) {
	check := func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.reset {
			return ErrStreamReset
		}
		if s.sentClose {
			return net.ErrClosed
		}
		return nil
	}
	if err := check(); err != nil {
		return 0, err
	}

	s.wmu.Lock()
	defer s.wmu.Unlock()

	if err := check(); err != nil {
		return 0, err
	}

	total := 0
	for len(b) > 0 {
		if total > 0 {
			// A reset mid-write (Abort from another goroutine) stops the
			// remaining chunks; the peer would drop them anyway.
			if err := check(); err != nil {
				return total, err
			}
		}
		n := len(b)
		if n > MaxPayload {
			n = MaxPayload
		}
		if err := s.sess.writeFrame(FrameData, s.id, b[:n]); err != nil {
			return total, err
		}
		b = b[n:]
		total += n
	}
	return total, nil
}

// CloseWrite sends a CLOSE frame: the peer's reads will EOF, while this side
// may still read anything already in flight. The stream is unregistered once
// both sides have closed.
func (s *Stream) CloseWrite() error {
	s.mu.Lock()
	if s.sentClose || s.reset {
		s.mu.Unlock()
		return nil
	}
	s.sentClose = true
	peerDone := s.readDone
	s.mu.Unlock()

	s.wmu.Lock()
	err := s.sess.writeFrame(FrameClose, s.id, nil)
	s.wmu.Unlock()
	if peerDone {
		s.remove()
	}
	return err
}

// Reset aborts the stream in both directions immediately. It is Abort; the
// name is kept for existing callers.
func (s *Stream) Reset() error {
	s.Abort()
	return nil
}

// Abort resets the stream in both directions, including after CloseWrite: a
// half-closed stream (request sent, response still streaming) is exactly the
// case a proxy needs to kill when the public client disconnects. It sends a
// RESET unless both sides had already finished cleanly, fails pending and
// future reads and writes on this side, closes Aborted, and unregisters the
// stream. Idempotent and safe to call from any goroutine.
func (s *Stream) Abort() {
	s.mu.Lock()
	if s.reset {
		s.mu.Unlock()
		return
	}
	finished := s.sentClose && s.readDone && s.readErr == io.EOF
	s.reset = true
	s.sentClose = true
	s.mu.Unlock()

	if !finished {
		// Not under s.wmu: a Write blocked on a full socket must not delay the
		// RESET, and the peer drops any DATA that trails it.
		_ = s.sess.writeFrame(FrameReset, s.id, nil)
	}
	s.markReadDone(ErrStreamReset)
	s.signalAbort()
	s.remove()
}

// Close implements io.Closer as an alias for CloseWrite.
func (s *Stream) Close() error { return s.CloseWrite() }

// net.Conn compatibility.

func (s *Stream) LocalAddr() net.Addr              { return s.sess.conn.LocalAddr() }
func (s *Stream) RemoteAddr() net.Addr             { return s.sess.conn.RemoteAddr() }
func (s *Stream) SetDeadline(time.Time) error      { return nil }
func (s *Stream) SetReadDeadline(time.Time) error  { return nil }
func (s *Stream) SetWriteDeadline(time.Time) error { return nil }
