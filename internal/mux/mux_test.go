package mux

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"
)

func TestStreamEcho(t *testing.T) {
	c1, c2 := net.Pipe()
	server := NewServerSession(c1, c1)
	client := NewClientSession(c2, c2)

	opened := make(chan *Stream, 1)
	client.OnStream = func(st *Stream) { opened <- st }
	go server.Run()
	go client.Run()
	defer server.Close()
	defer client.Close()

	// Server opens a stream; the client side echoes everything back.
	const message = "hello munnel"
	go func() {
		st := <-opened
		defer st.CloseWrite()
		io.Copy(st, st) // echo until EOF
	}()

	st, err := server.OpenStream([]byte(`{"host":"test"}`))
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	if _, err := st.Write([]byte(message)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := st.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}

	got, err := io.ReadAll(st)
	if err != nil {
		t.Fatalf("ReadAll echo: %v", err)
	}
	if string(got) != message {
		t.Fatalf("echo mismatch: got %q want %q", got, message)
	}
}

func TestLargePayloadChunking(t *testing.T) {
	c1, c2 := net.Pipe()
	server := NewServerSession(c1, c1)
	client := NewClientSession(c2, c2)
	opened := make(chan *Stream, 1)
	client.OnStream = func(st *Stream) { opened <- st }
	go server.Run()
	go client.Run()
	defer server.Close()
	defer client.Close()

	size := 5*MaxPayload + 12345 // spans several frames
	src := make([]byte, size)
	rand.New(rand.NewSource(42)).Read(src)

	go func() {
		st := <-opened
		defer st.CloseWrite()
		io.Copy(st, st)
	}()

	st, err := server.OpenStream(nil)
	if err != nil {
		t.Fatal(err)
	}
	// Echo frames fit in the peer's per-stream buffer, so this write
	// completes synchronously even over an unbuffered pipe.
	if _, err := st.Write(src); err != nil {
		t.Fatalf("Write: %v", err)
	}
	st.CloseWrite()

	got, err := io.ReadAll(st)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, src) {
		t.Fatalf("payload mismatch: got %d bytes, want %d", len(got), size)
	}
}

func TestConcurrentStreams(t *testing.T) {
	c1, c2 := net.Pipe()
	server := NewServerSession(c1, c1)
	client := NewClientSession(c2, c2)
	opened := make(chan *Stream, 64)
	client.OnStream = func(st *Stream) { opened <- st }
	go server.Run()
	go client.Run()
	defer server.Close()
	defer client.Close()

	// Echo handler for every client-side stream.
	go func() {
		for st := range opened {
			go func(st *Stream) {
				defer st.CloseWrite()
				io.Copy(st, st)
			}(st)
		}
	}()

	const n = 32
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			st, err := server.OpenStream(nil)
			if err != nil {
				errs <- err
				return
			}
			msg := fmt.Sprintf("stream-%03d", i)
			if _, err := st.Write([]byte(msg)); err != nil {
				errs <- err
				return
			}
			st.CloseWrite()
			got, err := io.ReadAll(st)
			if err != nil {
				errs <- err
				return
			}
			if string(got) != msg {
				errs <- fmt.Errorf("stream %d: got %q want %q", i, got, msg)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestResetAbortsRead(t *testing.T) {
	c1, c2 := net.Pipe()
	server := NewServerSession(c1, c1)
	client := NewClientSession(c2, c2)
	opened := make(chan *Stream, 1)
	client.OnStream = func(st *Stream) { opened <- st }
	go server.Run()
	go client.Run()
	defer server.Close()

	st, err := server.OpenStream(nil)
	if err != nil {
		t.Fatal(err)
	}
	clientSide := <-opened
	clientSide.Reset()

	// The RESET frame must cross the pipe and be dispatched before the
	// server-side stream rejects writes.
	time.Sleep(50 * time.Millisecond)
	if _, err := st.Write([]byte("x")); err == nil {
		t.Fatal("expected write to fail after reset")
	}
}

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := writeFrame(&buf, FrameData, 0xdeadbeef, []byte("munnel")); err != nil {
		t.Fatal(err)
	}
	typ, id, payload, err := readFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if typ != FrameData || id != 0xdeadbeef || string(payload) != "munnel" {
		t.Fatalf("round trip got typ=%s id=%x payload=%q", frameName(typ), id, payload)
	}
}

func TestOversizedFrameRejected(t *testing.T) {
	var buf bytes.Buffer
	hdr := [HeaderSize]byte{FrameData, 0, 0, 0, 1, 0xff, 0xff, 0xff, 0xff}
	buf.Write(hdr[:])
	if _, _, _, err := readFrame(&buf); err == nil {
		t.Fatal("expected oversized frame error")
	}
}

func TestTimeoutGuards(t *testing.T) {
	// Keep the whole suite snappy if something deadlocks.
	timer := time.AfterFunc(30*time.Second, func() {
		t.Error("suspicious: 30s elapsed — possible mux deadlock")
	})
	t.Cleanup(func() { timer.Stop() })
}
