// Package proto defines munnel's control-plane wire messages.
//
// The control handshake happens on the raw TCP connection before it is handed
// to the mux layer: exactly one JSON-encoded Hello (client → server), then
// one JSON-encoded Ack (server → client), both newline-delimited. After the
// ack the socket switches to binary mux frames exclusively.
package proto

import (
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
}

// OpenMeta is the JSON payload of a mux FrameOpen, sent by the server when it
// opens a stream for an incoming public request.
type OpenMeta struct {
	Host       string `json:"host"`
	RemoteAddr string `json:"remote_addr"`
}

var subdomainRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62})$`)

// ValidSubdomain reports whether s is safe to use as a DNS subdomain.
func ValidSubdomain(s string) bool { return subdomainRE.MatchString(s) }

// NormalizeSubdomain lowercases and trims; used before validation.
func NormalizeSubdomain(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
