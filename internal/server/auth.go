package server

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"unicode"

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
//
// Reserved names (--reserved-file) sit on top of both kinds: a reserved
// subdomain may be claimed only by the signed-token IDs listed for it, and
// only over the TLS control port, so nobody can squat the name while its
// owner is offline and its tunnel never runs over plaintext. The server can
// refuse a plaintext hello only after reading it, token included: a client
// pointed at the plaintext port sends the token in the clear once, then stops
// (proto.CodeTLSRequired) instead of resending it on every reconnect.
type Authenticator struct {
	tokens        map[string]bool
	reserved      map[string]string          // static token → reserved subdomain
	reservedNames map[string]map[string]bool // reserved name → allowed signed-token IDs
	signing       []byte                     // HMAC key for signed tokens; nil = disabled
	revoked       map[string]bool            // revoked signed-token IDs
	open          bool
}

// AuthOptions configures an Authenticator.
type AuthOptions struct {
	Tokens       string // comma-separated static tokens
	AuthFile     string // JSON file: static token → reserved subdomain
	SigningKey   []byte // HMAC key for signed tokens (enables them)
	RevokedFile  string // newline-separated revoked signed-token IDs
	ReservedFile string // reserved names: "name tokenID[,tokenID...]" per line
	Reserved     string // same entries inline, separated by ';' (e.g. $MUNNEL_RESERVED)
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
		tokens:        map[string]bool{},
		reserved:      map[string]string{},
		reservedNames: map[string]map[string]bool{},
		signing:       opts.SigningKey,
		revoked:       map[string]bool{},
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
	if opts.ReservedFile != "" {
		f, err := os.Open(opts.ReservedFile)
		if err != nil {
			return nil, errf("reserved file: %w", err)
		}
		err = parseReserved(f, a.reservedNames)
		f.Close()
		if err != nil {
			return nil, errf("reserved file: %w", err)
		}
	}
	if opts.Reserved != "" {
		entries := strings.ReplaceAll(opts.Reserved, ";", "\n")
		if err := parseReserved(strings.NewReader(entries), a.reservedNames); err != nil {
			return nil, errf("reserved names: %w", err)
		}
	}
	if len(a.reservedNames) > 0 {
		// Reserved names are held by signed-token IDs; without a signing key no
		// token could ever claim them, which is certainly a misconfiguration.
		if len(a.signing) == 0 {
			return nil, errors.New("reserved names need signed tokens: set a signing key")
		}
		for _, sub := range a.reserved {
			if a.reservedNames[sub] != nil {
				return nil, errf("auth file gives reserved name %q to a static token; reserved names belong to signed tokens", sub)
			}
		}
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

// TokenID returns the ID of a valid, unrevoked signed token, or "" for any
// other token (static, malformed, expired). It identifies the holder for
// reserved names and for taking over its own stale session.
func (a *Authenticator) TokenID(tok string) string {
	if !a.isSigned(tok) {
		return ""
	}
	c, err := token.Parse(a.signing, tok)
	if err != nil || a.revoked[c.ID] {
		return ""
	}
	return c.ID
}

// IsReserved reports whether name is a reserved subdomain.
func (a *Authenticator) IsReserved(name string) bool {
	return a.reservedNames[name] != nil
}

// ReservedNames lists the reserved subdomains (for the startup log).
func (a *Authenticator) ReservedNames() []string {
	names := make([]string, 0, len(a.reservedNames))
	for n := range a.reservedNames {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// CheckReserved refuses a reserved name to every token but its listed signed
// tokens, and to those too unless the control connection is TLS. Unreserved
// names always pass.
func (a *Authenticator) CheckReserved(tok, name string, overTLS bool) error {
	ids := a.reservedNames[name]
	if ids == nil {
		return nil
	}
	if id := a.TokenID(tok); id == "" || !ids[id] {
		return errf("subdomain %q is reserved", name)
	}
	if !overTLS {
		return tlsRequiredError{name}
	}
	return nil
}

// tlsRequiredError refuses a reserved name to its own token over plaintext.
// The handshake marks it proto.CodeTLSRequired so the client stops retrying.
type tlsRequiredError struct{ name string }

func (e tlsRequiredError) Error() string {
	return fmt.Sprintf("subdomain %q is reserved for TLS connections: reconnect with --tls to the server's TLS control port", e.name)
}

// parseReserved reads reserved-name entries into into, one per line:
//
//	# comment
//	hop tok_0123456789abcdef
//	staging tok_aaaaaaaaaaaaaaaa,tok_bbbbbbbbbbbbbbbb
//
// The name comes first, then one or more token IDs (as printed by
// `munnel-server mint`); commas, spaces or '=' separate them. Token IDs, not
// tokens: the file is not a secret, and a pasted token is refused.
func parseReserved(r io.Reader, into map[string]map[string]bool) error {
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.FieldsFunc(line, func(r rune) bool { return r == ',' || r == '=' || unicode.IsSpace(r) })
		name := proto.NormalizeSubdomain(fields[0])
		if !proto.ValidSubdomain(name) {
			return errf("line %d: invalid subdomain %q", n, fields[0])
		}
		if len(fields) < 2 {
			return errf("line %d: %q lists no token IDs", n, name)
		}
		ids := into[name]
		if ids == nil {
			ids = map[string]bool{}
			into[name] = ids
		}
		for _, id := range fields[1:] {
			if strings.HasPrefix(id, token.Prefix) {
				return errf("line %d: that is a token, not a token ID (use the tok_… id printed by mint)", n)
			}
			if !strings.HasPrefix(id, "tok_") {
				return errf("line %d: %q is not a token ID (expected tok_…)", n, id)
			}
			ids[id] = true
		}
	}
	return sc.Err()
}

// Mint creates a signed, scoped token using the Authenticator's signing key.
// Returns an error if signed tokens are not enabled (no signing key configured).
// This is the self-service issuance path: the /__munnel/token endpoint calls
// this so a dev can mint their own token with just an enrollment password,
// without ever touching the signing key.
func (a *Authenticator) Mint(opts token.MintOpts) (string, error) {
	if len(a.signing) == 0 {
		return "", errors.New("signed tokens not enabled (no signing key)")
	}
	return token.MintWith(a.signing, opts)
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
