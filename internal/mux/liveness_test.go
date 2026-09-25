package mux

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// pair runs a server and a client session over an in-memory pipe.
func pair(t *testing.T, tune func(server, client *Session)) (server, client *Session, opened chan *Stream) {
	t.Helper()
	c1, c2 := net.Pipe()
	server = NewServerSession(c1, c1)
	client = NewClientSession(c2, c2)
	opened = make(chan *Stream, 16)
	client.OnStream = func(st *Stream) { opened <- st }
	if tune != nil {
		tune(server, client)
	}
	go server.Run()
	go client.Run()
	t.Cleanup(func() { server.Close(); client.Close() })
	return server, client, opened
}

// TestAbortAfterCloseWrite: the proxy half-closes a stream once the request
// is sent, then must still be able to kill it when the public client leaves.
// Reset used to be a no-op after CloseWrite, so the peer never heard of it.
func TestAbortAfterCloseWrite(t *testing.T) {
	server, _, opened := pair(t, nil)

	st, err := server.OpenStream(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	if err := st.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	peer := <-opened
	if _, err := io.ReadAll(peer); err != nil { // request fully received
		t.Fatal(err)
	}
	if _, err := peer.Write([]byte("HTTP/1.1 200 OK\r\n")); err != nil { // response starts streaming
		t.Fatal(err)
	}

	st.Abort()

	select {
	case <-peer.Aborted():
	case <-time.After(2 * time.Second):
		t.Fatal("peer never saw the abort (no RESET sent after CloseWrite)")
	}
	if _, err := peer.Write([]byte("data: more\n\n")); !errors.Is(err, ErrStreamReset) {
		t.Fatalf("peer write after abort: got %v, want ErrStreamReset", err)
	}
	// Local side: reads fail at once instead of waiting for more data.
	if _, err := io.ReadAll(st); !errors.Is(err, ErrStreamReset) {
		t.Fatalf("local read after abort: got %v, want ErrStreamReset", err)
	}
	select {
	case <-st.Aborted():
	default:
		t.Fatal("local Aborted() not closed")
	}
}

// TestAbortedNotClosedOnGracefulClose: Aborted must only fire on abnormal
// ends, or the tunnel client would cancel local requests that finished fine.
func TestAbortedNotClosedOnGracefulClose(t *testing.T) {
	server, _, opened := pair(t, nil)
	st, err := server.OpenStream(nil)
	if err != nil {
		t.Fatal(err)
	}
	st.CloseWrite()
	peer := <-opened
	io.ReadAll(peer)
	peer.CloseWrite()
	if _, err := io.ReadAll(st); err != nil {
		t.Fatal(err)
	}
	st.Abort() // both sides finished: no RESET, nothing aborted remotely
	time.Sleep(50 * time.Millisecond)
	select {
	case <-peer.Aborted():
		t.Fatal("peer aborted after a clean close")
	default:
	}
}

// TestIdleTimeoutClosesSilentPeer: a peer that stops sending anything (no
// frames, no pongs) is declared dead after IdleTimeout.
func TestIdleTimeoutClosesSilentPeer(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()
	go io.Copy(io.Discard, c2) // swallow our pings, never answer

	s := NewServerSession(c1, c1)
	s.PingInterval = 20 * time.Millisecond
	s.IdleTimeout = 150 * time.Millisecond
	done := make(chan error, 1)
	go func() { done <- s.Run() }()

	select {
	case err := <-done:
		if !errors.Is(err, ErrIdleTimeout) {
			t.Fatalf("Run returned %v, want ErrIdleTimeout", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("silent peer not detected")
	}
}

// TestPingsKeepIdleSessionAlive: two live sessions with no traffic stay up
// well past the idle timeout, because pings and pongs count as frames.
func TestPingsKeepIdleSessionAlive(t *testing.T) {
	tune := func(s, c *Session) {
		s.PingInterval, s.IdleTimeout = 20*time.Millisecond, 150*time.Millisecond
		c.PingInterval, c.IdleTimeout = 20*time.Millisecond, 150*time.Millisecond
	}
	server, _, opened := pair(t, tune)
	time.Sleep(600 * time.Millisecond)
	st, err := server.OpenStream(nil)
	if err != nil {
		t.Fatalf("session died while idle: %v", err)
	}
	st.CloseWrite()
	select {
	case <-opened:
	case <-time.After(2 * time.Second):
		t.Fatal("stream never reached the peer")
	}
}

// TestIdleTimeoutIgnoresOwnStall: when our read loop is blocked handing DATA
// to a slow stream reader, the peer's frames queue up unread. That is our
// stall, not a dead peer, and must not close the session.
func TestIdleTimeoutIgnoresOwnStall(t *testing.T) {
	tune := func(s, c *Session) {
		s.PingInterval, s.IdleTimeout = 20*time.Millisecond, 150*time.Millisecond
	}
	server, client, opened := pair(t, tune)
	st, err := server.OpenStream(nil)
	if err != nil {
		t.Fatal(err)
	}
	peer := <-opened

	// 40 frames overflow the 16-chunk stream buffer while nobody reads st.
	payload := bytes.Repeat([]byte("x"), 1024)
	wrote := make(chan error, 1)
	go func() {
		for i := 0; i < 40; i++ {
			if _, err := peer.Write(payload); err != nil {
				wrote <- err
				return
			}
		}
		wrote <- peer.CloseWrite()
	}()

	// Four idle timeouts with the reader stalled. The peer is fine, and must
	// not look stale to a same-token takeover either.
	for end := time.Now().Add(600 * time.Millisecond); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if server.stalled.Load() && server.Stale() {
			t.Fatal("our own stall made a live peer look stale")
		}
	}
	got, err := io.ReadAll(st)
	if err != nil {
		t.Fatalf("session closed during our own stall: %v", err)
	}
	if len(got) != 40*len(payload) {
		t.Fatalf("got %d bytes, want %d", len(got), 40*len(payload))
	}
	if err := <-wrote; err != nil {
		t.Fatal(err)
	}
	_ = client
}

// TestStale: a peer that answers pings is never stale; one that went quiet
// is, once 1.5 ping intervals have passed without a byte from it.
func TestStale(t *testing.T) {
	tune := func(s, c *Session) {
		s.PingInterval, c.PingInterval = 100*time.Millisecond, 100*time.Millisecond
	}
	server, client, _ := pair(t, tune)
	for end := time.Now().Add(500 * time.Millisecond); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if server.Stale() || client.Stale() {
			t.Fatal("a peer answering pings looks stale")
		}
	}

	start := time.Now()
	c1, c2 := net.Pipe()
	defer c2.Close()
	go io.Copy(io.Discard, c2) // swallows our pings, never answers
	quiet := NewServerSession(c1, c1)
	quiet.PingInterval = 100 * time.Millisecond // idle timeout stays at 45 s
	go quiet.Run()
	defer quiet.Close()
	for !quiet.Stale() {
		if time.Since(start) > 3*time.Second {
			t.Fatal("a silent peer never became stale")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if d := time.Since(start); d < 150*time.Millisecond {
		t.Fatalf("stale after %s, before 1.5 ping intervals", d)
	}
}

// slowReader hands out at most chunk bytes per Read and pauses before each
// one: a throttled link (a mobile hotspot, say) on which a single large frame
// takes longer than the idle timeout to arrive.
type slowReader struct {
	r     io.Reader
	chunk int
	pause time.Duration
}

func (s slowReader) Read(p []byte) (int, error) {
	time.Sleep(s.pause)
	if len(p) > s.chunk {
		p = p[:s.chunk]
	}
	return s.r.Read(p)
}

// TestIdleTimeoutSpansSlowFrame: a MaxPayload DATA frame (an upload body)
// that trickles in over several idle timeouts must not end the session. The
// sender holds the write lock for the whole frame, so no ping can get in
// between; the bytes arriving are the only sign of life, and they count.
func TestIdleTimeoutSpansSlowFrame(t *testing.T) {
	c1, c2 := net.Pipe()
	server := NewServerSession(c1, c1)
	// 32 KiB every 20 ms: the 1 MiB frame takes about 0.65 s, more than
	// twice the 300 ms idle timeout.
	client := NewClientSession(c2, slowReader{r: c2, chunk: 32 << 10, pause: 20 * time.Millisecond})
	for _, s := range []*Session{server, client} {
		s.PingInterval, s.IdleTimeout = 50*time.Millisecond, 300*time.Millisecond
	}
	opened := make(chan *Stream, 1)
	client.OnStream = func(st *Stream) { opened <- st }
	clientDone := make(chan error, 1)
	go server.Run()
	go func() { clientDone <- client.Run() }()
	t.Cleanup(func() { server.Close(); client.Close() })

	st, err := server.OpenStream(nil)
	if err != nil {
		t.Fatal(err)
	}
	peer := <-opened
	wrote := make(chan error, 1)
	go func() {
		if _, err := st.Write(bytes.Repeat([]byte("x"), MaxPayload)); err != nil {
			wrote <- err
			return
		}
		wrote <- st.CloseWrite()
	}()

	type result struct {
		n   int
		err error
	}
	read := make(chan result, 1)
	go func() {
		got, err := io.ReadAll(peer)
		read <- result{len(got), err}
	}()
	select {
	case r := <-read:
		if r.err != nil || r.n != MaxPayload {
			t.Fatalf("got %d of %d bytes, err %v", r.n, MaxPayload, r.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("slow frame never arrived")
	}
	if err := <-wrote; err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case err := <-clientDone:
		t.Fatalf("client session ended: %v", err)
	default:
	}
}
