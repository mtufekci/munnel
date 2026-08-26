package server

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/mtufekci/munnel/internal/proto"
	"github.com/mtufekci/munnel/internal/token"
)

func errf(format string, args ...any) error { return fmt.Errorf(format, args...) }

var errNoToken = errors.New("server requires a token; reconnect with -t <token>")

// Authenticator validates client tokens and enforces token→subdomain rules.
//
// Two token kinds coexist:
//
//  1. Static tokens — opaque strings listed in --auth-tokens or an --auth-file
//     (JSON token→reserved-subdomain). The server holds the full set.
//  2. Signed tokens — HMAC-SHA256-signed credentials (package token) minted
//     with --signing-key. They carry their own subdomain claim and expiry, so
//     the server validates without holding a per-token list. Revocation is by
//     token ID via --revoked-file.
//
// When no tokens AND no signing key are configured the server runs in open
// mode: any client may connect (fine for a private/hobby server, unsafe on
// the public internet).
type Authenticator struct {
	tokens   map[string]bool
	reserved map[string]string // static token → reserved subdomain
	signing  []byte            // HMAC key for signed tokens; nil = disabled
	revoked  map[string]bool   // revoked signed-token IDs
	open     bool
}

// AuthOptions configures an Authenticator.
type AuthOptions struct {
	Tokens      string   // comma-separated static tokens
	AuthFile    string   // JSON file: static token → reserved subdomain
	SigningKey  []byte   // HMAC key for signed tokens (enables them)
	RevokedFile string   // newline-separated revoked signed-token IDs
}

// NewAuthenticator builds an Authenticator from a comma-separated token list
// and/or a JSON auth file. It is the backward-compatible entry point;
// NewAuthenticatorWith covers the signed-token options.
func NewAuthenticator(tokensCSV, authFile string) (*Authenticator, error) {
	return NewAuthenticatorWith(AuthOptions{Tokens: tokensCSV, AuthFile: authFile})
}

// NewAuthenticatorWith builds an Authenticator from the full option set.
func NewAuthenticatorWith(opts AuthOptions) (*Authenticator, error) {
	a := &Authenticator{
		tokens:   map[string]bool{},
		reserved: map[string]string{},
		signing:  opts.SigningKey,
		revoked:  map[string]bool{},
	}
	if opts.Tokens != "" {
		for _, t := range strings.Split(opts.Tokens, ",") {
			if t = strings.TrimSpace(t); t != "" {
				a.tokens[t] = true
			}
		}
	}
	if opts.AuthFile != "" {
		b, err := os.ReadFile(opts.AuthFile)
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
	if opts.RevokedFile != "" {
		ids, err := loadRevokedIDs(opts.RevokedFile)
		if err != nil {
			return nil, errf("revoked file: %w", err)
		}
		a.revoked = ids
	}
	// Open mode only when there is no auth of any kind configured.
	a.open = len(a.tokens) == 0 && len(a.signing) == 0
	return a, nil
}

// Open reports whether the server accepts unauthenticated clients.
func (a *Authenticator) Open() bool { return a.open }

// SignedTokenCount reports how many static tokens are configured, plus one
// for the signing key if set (for the startup log line).
func (a *Authenticator) SignedEnabled() bool { return len(a.signing) > 0 }

// StaticTokenCount returns the number of configured static tokens (for logging).
func (a *Authenticator) StaticTokenCount() int { return len(a.tokens) }

// isSigned reports whether tok is a signed-token string (m1.…). A signed token
// is only meaningful when a signing key is configured.
func (a *Authenticator) isSigned(tok string) bool {
	return len(a.signing) > 0 && strings.HasPrefix(tok, token.Prefix)
}

// Check validates a client-supplied token.
func (a *Authenticator) Check(tok string) error {
	if a.open {
		return nil
	}
	if tok == "" {
		return errNoToken
	}
	if a.isSigned(tok) {
		c, err := token.Parse(a.signing, tok)
		if err != nil {
			return err // malformed / bad-sig / expired
		}
		if a.revoked[c.ID] {
			return errors.New("token revoked")
		}
		return nil
	}
	if !a.tokens[tok] {
		return errors.New("invalid token")
	}
	return nil
}

// ReservedSubdomain returns the subdomain bound to a token, if any. For a
// signed token this is the token's `sub` claim.
func (a *Authenticator) ReservedSubdomain(tok string) string {
	if a.isSigned(tok) {
		if c, err := token.Parse(a.signing, tok); err == nil {
			return c.Sub
		}
		return ""
	}
	return a.reserved[tok]
}

// ProtectedByToken reports whether a signed token mandates forward-auth
// (its `prot` claim). Static tokens never mandate it; the client opts in via
// --protect instead.
func (a *Authenticator) ProtectedByToken(tok string) bool {
	if a.isSigned(tok) {
		if c, err := token.Parse(a.signing, tok); err == nil {
			return c.Prot
		}
	}
	return false
}

// CheckSubdomain enforces reservation rules for a requested subdomain.
func (a *Authenticator) CheckSubdomain(tok, requested string) error {
	if a.isSigned(tok) {
		c, err := token.Parse(a.signing, tok)
		if err != nil {
			return err // already validated in Check; be defensive
		}
		if c.Sub != "" {
			if requested != c.Sub {
				return errf("your token only allows subdomain %q", c.Sub)
			}
			return nil
		}
		// No sub claim → client may claim any free subdomain.
		if requested != "" && !proto.ValidSubdomain(requested) {
			return errf("invalid subdomain %q (lowercase letters, digits, hyphens; ≤63 chars)", requested)
		}
		return nil
	}
	if reserved, ok := a.reserved[tok]; ok {
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

// loadRevokedIDs reads a file of one revoked token ID per line. Blank lines and
// `#` comments are ignored. The file is read once at startup; revoke a token by
// adding its ID (printed by `munnel-server mint`) and restarting.
func loadRevokedIDs(path string) (map[string]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	ids := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ids[line] = true
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return ids, nil
}