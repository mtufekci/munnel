package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/mtufekci/munnel/internal/proto"
)

func errf(format string, args ...any) error { return fmt.Errorf(format, args...) }

var errNoToken = errors.New("server requires a token; reconnect with -t <token>")

// Authenticator validates client tokens and enforces token→subdomain
// reservations from an auth file.
//
// When no tokens are configured at all the server runs in open mode: any
// client may connect (fine for a private/hobby server, unsafe on the public
// internet).
type Authenticator struct {
	tokens   map[string]bool
	reserved map[string]string // token → reserved subdomain
	open     bool
}

// NewAuthenticator builds an Authenticator from a comma-separated token list
// and/or a JSON auth file mapping tokens to reserved subdomains:
//
//	{ "secret-token": "alice", "other-token": "bob" }
func NewAuthenticator(tokensCSV, authFile string) (*Authenticator, error) {
	a := &Authenticator{tokens: map[string]bool{}, reserved: map[string]string{}}
	if tokensCSV != "" {
		for _, t := range strings.Split(tokensCSV, ",") {
			if t = strings.TrimSpace(t); t != "" {
				a.tokens[t] = true
			}
		}
	}
	if authFile != "" {
		b, err := os.ReadFile(authFile)
		if err != nil {
			return nil, errf("auth file: %w", err)
		}
		m := map[string]string{}
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, errf("auth file JSON: %w", err)
		}
		for tok, sub := range m {
			sub = proto.NormalizeSubdomain(sub)
			if !proto.ValidSubdomain(sub) {
				return nil, errf("auth file: invalid reserved subdomain %q", sub)
			}
			a.tokens[tok] = true
			a.reserved[tok] = sub
		}
	}
	a.open = len(a.tokens) == 0
	return a, nil
}

// Open reports whether the server accepts unauthenticated clients.
func (a *Authenticator) Open() bool { return a.open }

// Check validates a client-supplied token.
func (a *Authenticator) Check(token string) error {
	if a.open {
		return nil
	}
	if token == "" {
		return errNoToken
	}
	if !a.tokens[token] {
		return errors.New("invalid token")
	}
	return nil
}

// ReservedSubdomain returns the subdomain bound to a token, if any.
func (a *Authenticator) ReservedSubdomain(token string) string {
	return a.reserved[token]
}

// CheckSubdomain enforces reservation rules for a requested subdomain.
func (a *Authenticator) CheckSubdomain(token, requested string) error {
	if reserved, ok := a.reserved[token]; ok {
		if requested == "" {
			return nil // client takes the reserved name
		}
		if requested != reserved {
			return errf("your token only allows subdomain %q", reserved)
		}
		return nil
	}
	if requested != "" && !proto.ValidSubdomain(requested) {
		return errf("invalid subdomain %q (lowercase letters, digits, hyphens; ≤63 chars)", requested)
	}
	return nil
}
