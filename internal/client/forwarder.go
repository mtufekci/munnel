package client

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mtufekci/munnel/internal/inspection"
	"github.com/mtufekci/munnel/internal/mux"
)

// captureLimit bounds how much of each body is kept for the inspector
// (the whole body is still proxied verbatim, up to MaxBody).
const captureLimit = 256 * 1024

var hopByHop = map[string]bool{
	"Connection":        true,
	"Keep-Alive":        true,
	"Te":                true,
	"Trailer":           true,
	"Transfer-Encoding": true,
	"Upgrade":           true,
	"Content-Length":    true, // recomputed
}

// Forwarder dispatches tunnel streams to the local service and captures each
// exchange for the inspector. It also replays captured requests.
type Forwarder struct {
	LocalHost string
	LocalPort int
	MaxBody   int64
	rt        *http.Transport
}

// NewForwarder builds a forwarder for http://host:port.
func NewForwarder(host string, port int, maxBody int64) *Forwarder {
	return &Forwarder{
		LocalHost: host,
		LocalPort: port,
		MaxBody:   maxBody,
		rt: &http.Transport{
			Proxy: nil,
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     false, // local HTTP/1.1 only, deterministic framing
			MaxIdleConns:          64,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   0,
			ResponseHeaderTimeout: 0, // SSE/streaming endpoints: no cap
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

// LocalAddr returns "host:port" of the local target.
func (f *Forwarder) LocalAddr() string {
	return net.JoinHostPort(f.LocalHost, strconv.Itoa(f.LocalPort))
}

// Serve handles one stream: read the request off the wire, forward to the
// local service, write the response back, and Return the captured record.
// It owns the stream and closes it.
func (f *Forwarder) Serve(st *mux.Stream) *inspection.Record {
	start := time.Now()
	rec := &inspection.Record{Time: start}

	br := bufio.NewReader(st)
	req, err := http.ReadRequest(br)
	if err != nil {
		rec.Errored = true
		rec.Error = "malformed request from tunnel: " + err.Error()
		writeRawError(st, http.StatusBadRequest, "malformed request")
		_ = st.CloseWrite()
		return rec
	}
	rec.Method = req.Method
	rec.Path = req.URL.RequestURI()
	rec.ReqHeaders = cloneHeader(req.Header)

	// WebSocket / protocol upgrade: the stream becomes a raw bidirectional
	// pipe to the local service. The HTTP request/response framing path below
	// does not apply (no bounded body, no single response).
	if isUpgrade(req) {
		return f.serveWebSocket(st, br, req, rec, start)
	}

	defer st.CloseWrite()

	// Read the request body (bounded). The server always either sets
	// Content-Length or closes the stream when done, so this terminates.
	overlimit := int64(0)
	body, err := readAllLimited(req.Body, f.MaxBody, &overlimit)
	if err != nil {
		rec.Errored = true
		rec.Error = "failed reading request body: " + err.Error()
		writeRawError(st, http.StatusBadRequest, "failed reading request body")
		return rec
	}
	rec.ReqBody, rec.ReqTruncated = truncateForDisplay(body)
	if overlimit > 0 {
		rec.Errored = true
		rec.Error = "request body exceeds limit"
		writeRawError(st, http.StatusRequestEntityTooLarge, "request body too large")
		return rec
	}

	out := f.buildLocalRequest(req, body)
	resp, err := f.rt.RoundTrip(out)
	if err != nil {
		rec.Errored = true
		rec.Error = fmt.Sprintf("local service unreachable (%s): %v", f.LocalAddr(), rootCause(err))
		writeRawError(st, http.StatusBadGateway, "munnel: local service "+f.LocalAddr()+" unreachable")
		rec.Duration = time.Since(start).Milliseconds()
		return rec
	}
	defer resp.Body.Close()

	rec.Status = resp.StatusCode
	rec.RespHeaders = cloneHeader(resp.Header)

	// Tee the response body into the capture buffer while streaming it back
	// over the tunnel, so even streaming responses stay live end-to-end.
	capBuf := &limitedBuffer{limit: captureLimit}
	resp.Body = readCloser{Reader: io.TeeReader(resp.Body, capBuf), Closer: resp.Body}
	werr := resp.Write(st)
	if werr != nil {
		rec.Errored = true
		rec.Error = "tunnel write failed: " + werr.Error()
	}
	rec.RespBody, rec.RespTruncated = capBuf.bytes(), capBuf.truncated
	rec.Duration = time.Since(start).Milliseconds()
	return rec
}

// isUpgrade reports whether req is a protocol-upgrade request (WebSocket, etc.).
func isUpgrade(req *http.Request) bool {
	return strings.EqualFold(req.Header.Get("Connection"), "upgrade") || req.Header.Get("Upgrade") != ""
}

// serveWebSocket dials the local service as a raw TCP connection and pipes it
// bidirectionally against the tunnel stream. The upgrade handshake is re-sent
// verbatim (preserving Upgrade/Connection/Sec-WebSocket-* headers); the Host
// header is rewritten to the local addr so the local service sees the same
// request shape as the HTTP path (the original public host survives in
// X-Forwarded-Host). The inspector gets a 101 record; the WS frames themselves
// are not captured (arbitrary-length, bidirectional).
func (f *Forwarder) serveWebSocket(st *mux.Stream, br *bufio.Reader, req *http.Request, rec *inspection.Record, start time.Time) *inspection.Record {
	local, err := net.DialTimeout("tcp", f.LocalAddr(), 5*time.Second)
	if err != nil {
		rec.Errored = true
		rec.Error = fmt.Sprintf("local service unreachable (%s): %v", f.LocalAddr(), rootCause(err))
		writeRawError(st, http.StatusBadGateway, "munnel: local service "+f.LocalAddr()+" unreachable")
		rec.Duration = time.Since(start).Milliseconds()
		_ = st.CloseWrite()
		return rec
	}
	defer local.Close()

	// Re-send the upgrade request to the local service. http.ReadRequest keeps
	// Host in req.Header, so skip it here and write the local Host explicitly.
	out := bufio.NewWriter(local)
	fmt.Fprintf(out, "%s %s HTTP/1.1\r\n", req.Method, req.URL.RequestURI())
	fmt.Fprintf(out, "Host: %s\r\n", f.LocalAddr())
	for k, vs := range req.Header {
		if strings.EqualFold(k, "Host") {
			continue
		}
		for _, v := range vs {
			fmt.Fprintf(out, "%s: %s\r\n", k, v)
		}
	}
	fmt.Fprintf(out, "X-Forwarded-Host: %s\r\n", req.Host)
	fmt.Fprintf(out, "X-Forwarded-Proto: http\r\n")
	out.WriteString("\r\n")
	if err := out.Flush(); err != nil {
		rec.Errored = true
		rec.Error = "local write failed: " + err.Error()
		rec.Duration = time.Since(start).Milliseconds()
		_ = st.CloseWrite()
		return rec
	}

	// Drain anything the bufio reader pre-buffered past the request headers
	// (pipelined WS frames that arrived with the handshake) onto the local
	// connection before entering the raw pipe.
	if n := br.Buffered(); n > 0 {
		prebuf := make([]byte, n)
		_, _ = io.ReadFull(br, prebuf)
		_, _ = local.Write(prebuf)
	}

	// Record the upgrade for the inspector (frames themselves are not captured).
	rec.Status = http.StatusSwitchingProtocols
	rec.Duration = time.Since(start).Milliseconds()

	// Bidirectional pipe: tunnel stream ↔ local TCP. When either direction
	// ends, close both to unblock the other. Double-close is safe.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(local, st); _ = local.Close(); _ = st.Close() }()
	go func() { defer wg.Done(); _, _ = io.Copy(st, local); _ = st.Close(); _ = local.Close() }()
	wg.Wait()
	return rec
}

// Replay re-dispatches a captured request to the local service and returns
// the fresh exchange as a new record (marked Replayed).
func (f *Forwarder) Replay(src *inspection.Record) (*inspection.Record, error) {
	start := time.Now()
	rec := &inspection.Record{Time: start, Replayed: true, Method: src.Method, Path: src.Path}

	body := []byte(src.ReqBody)
	if src.ReqTruncated {
		return nil, fmt.Errorf("cannot replay: stored request body was truncated (capture limit %d bytes)", captureLimit)
	}
	rec.ReqBody = src.ReqBody

	u := &url.URL{Scheme: "http", Host: f.LocalAddr(), Path: urlPath(src.Path)}
	if q := urlQuery(src.Path); q != "" {
		u.RawQuery = q
	}
	out := &http.Request{
		Method:        src.Method,
		URL:           u,
		Header:        cloneHeader(src.ReqHeaders),
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Host:          f.LocalAddr(),
	}
	out.Header.Del("Host")

	resp, err := f.rt.RoundTrip(out)
	if err != nil {
		rec.Errored = true
		rec.Error = fmt.Sprintf("local service unreachable: %v", rootCause(err))
		rec.Duration = time.Since(start).Milliseconds()
		return rec, nil
	}
	defer resp.Body.Close()

	capBuf := &limitedBuffer{limit: captureLimit}
	_, _ = io.Copy(capBuf, resp.Body)
	rec.Status = resp.StatusCode
	rec.RespHeaders = cloneHeader(resp.Header)
	rec.RespBody, rec.RespTruncated = capBuf.bytes(), capBuf.truncated
	rec.Duration = time.Since(start).Milliseconds()
	return rec, nil
}

func (f *Forwarder) buildLocalRequest(orig *http.Request, body []byte) *http.Request {
	u := &url.URL{
		Scheme:   "http",
		Host:     f.LocalAddr(),
		Path:     orig.URL.Path,
		RawPath:  orig.URL.RawPath,
		RawQuery: orig.URL.RawQuery,
	}
	hdr := http.Header{}
	for k, vs := range orig.Header {
		if hopByHop[http.CanonicalHeaderKey(k)] {
			continue
		}
		hdr[k] = append([]string(nil), vs...)
	}
	out := &http.Request{
		Method:        orig.Method,
		URL:           u,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        hdr,
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Host:          f.LocalAddr(), // local vhosts; original host survives in X-Forwarded-Host
	}
	// Keep the tunnel client out of RFC 7230 ambiguity: a fixed Content-Length
	// always accompanies the buffered body.
	out.Header.Set("Content-Length", strconv.Itoa(len(body)))
	if len(body) == 0 && !methodMayHaveBody(orig.Method) {
		out.Header.Del("Content-Length")
		out.ContentLength = 0
	}
	return out
}

func methodMayHaveBody(m string) bool {
	switch m {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		return true
	}
	return false
}

// readAllLimited reads r fully; extra bytes beyond limit are counted in
// *over instead of being returned.
func readAllLimited(r io.Reader, limit int64, over *int64) ([]byte, error) {
	if r == nil {
		return nil, nil
	}
	var buf bytes.Buffer
	_, err := io.Copy(&buf, io.LimitReader(r, limit))
	if err != nil {
		return nil, err
	}
	// One extra byte determines whether the body exceeded the limit.
	extra := make([]byte, 1)
	n, err := r.Read(extra)
	for err == nil && n > 0 {
		*over += int64(n)
		n, err = r.Read(extra)
	}
	if err != nil && err != io.EOF {
		return buf.Bytes(), err
	}
	return buf.Bytes(), nil
}

// truncateForDisplay keeps the first captureLimit bytes for the inspector.
func truncateForDisplay(b []byte) (string, bool) {
	if len(b) <= captureLimit {
		return string(b), false
	}
	return string(b[:captureLimit]), true
}

type limitedBuffer struct {
	limit     int
	buf       bytes.Buffer
	truncated bool
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	remaining := l.limit - l.buf.Len()
	if remaining > 0 {
		if len(p) > remaining {
			l.buf.Write(p[:remaining])
			l.truncated = true
		} else {
			l.buf.Write(p)
		}
	} else {
		l.truncated = true
	}
	return len(p), nil
}

func (l *limitedBuffer) bytes() string { return l.buf.String() }

func cloneHeader(h http.Header) http.Header {
	if h == nil {
		return http.Header{}
	}
	out := make(http.Header, len(h))
	for k, vs := range h {
		out[k] = append([]string(nil), vs...)
	}
	return out
}

type readCloser struct {
	io.Reader
	io.Closer
}

func rootCause(err error) error {
	for {
		u, ok := err.(interface{ Unwrap() []error })
		if ok {
			errs := u.Unwrap()
			if len(errs) == 0 {
				return err
			}
			err = errs[len(errs)-1]
			continue
		}
		s, ok := err.(interface{ Unwrap() error })
		if !ok {
			return err
		}
		err = s.Unwrap()
	}
}

func urlPath(p string) string {
	if i := strings.IndexByte(p, '?'); i >= 0 {
		return p[:i]
	}
	return p
}

func urlQuery(p string) string {
	if i := strings.IndexByte(p, '?'); i >= 0 {
		return p[i+1:]
	}
	return ""
}

func writeRawError(w io.Writer, status int, msg string) {
	body := msg + "\n"
	resp := &http.Response{
		Status:        strconv.Itoa(status) + " " + http.StatusText(status),
		StatusCode:    status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Header:        http.Header{"Content-Type": {"text/plain; charset=utf-8"}},
	}
	_ = resp.Write(w)
}
