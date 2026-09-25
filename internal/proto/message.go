// Package proto defines munnel's control-plane wire messages.
//
// The control handshake happens on the raw TCP connection before it is handed
// to the mux layer: exactly one JSON-encoded Hello (client → server), then
// one JSON-encoded Ack (server → client), both newline-delimited. After the
// ack the socket switches to binary mux frames exclusively.
package proto

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
)

// ControlVersion is the handshake protocol version. Server and client must
// match on the major version.
const ControlVersion = 1

// Message types.
const (
	TypeHello = "hello"
	TypeAck   = "ack"
)

// Hello is sent by the client immediately after connecting to the server.
type Hello struct {
	Type      string `json:"type"`
	Version   int    `json:"version"`
	Token     string `json:"token,omitempty"`
	Subdomain string `json:"subdomain,omitempty"` // requested; "" = server picks
	Protected bool   `json:"protected,omitempty"` // opt the tunnel into forward-auth
}

// Ack is the server's reply. On failure OK is false and Error is populated.
type Ack struct {
	Type      string `json:"type"`
	OK        bool   `json:"ok"`
	Subdomain string `json:"subdomain,omitempty"`
	PublicURL string `json:"public_url,omitempty"`
	Error     string `json:"error,omitempty"`
	// Code classifies a refusal the client must act on, not just display.
	// Older clients ignore it and older servers never send it.
	Code string `json:"code,omitempty"`
}

// CodeTLSRequired refuses a reserved name over the plaintext control port.
// The client stops reconnecting: every attempt would resend the token in
// the clear to a server that will never accept it there.
const CodeTLSRequired = "tls_required"

// OpenMeta is the JSON payload of a mux FrameOpen, sent by the server when it
// opens a stream for an incoming public request.
type OpenMeta struct {
	Host       string `json:"host"`
	RemoteAddr string `json:"remote_addr"`
}

// WriteMessage writes v as one JSON line (the handshake framing), in a
// single Write so it cannot interleave with anything else on the socket.
func WriteMessage(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// ReadMessage reads exactly one newline-terminated JSON line from br and
// decodes it into v. The same br is then handed to the mux, so it must hold
// precisely the bytes after the newline. A json.Decoder cannot guarantee that:
// it buffers ahead (swallowing early frames) or stops right after the closing
// brace (leaving the '\n' behind, which shifts every later frame by one byte).
// Go 1.27's decoder does the latter for any message of exactly 64, 128, 256…
// bytes. Reading the line ourselves keeps the framing exact.
func ReadMessage(br *bufio.Reader, v any) error {
	line, err := br.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return errors.New("handshake message too long")
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(line, v)
}

var subdomainRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62})$`)

// ValidSubdomain reports whether s is safe to use as a DNS subdomain.
func ValidSubdomain(s string) bool { return subdomainRE.MatchString(s) }

// NormalizeSubdomain lowercases and trims; used before validation.
func NormalizeSubdomain(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
