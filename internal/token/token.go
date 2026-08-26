// Package token implements munnel's signed, scoped tunnel tokens.
//
// A signed token is a self-describing credential that binds a client to a
// specific subdomain and an expiry, signed with an HMAC-SHA256 key only the
// server holds. The server validates the signature and expiry at handshake
// time; no central token database is needed. Revocation is by token ID
// (see Authenticator).
//
// Wire format:
//
//	m1.<base64url(payloadJSON)>.<base64url(hmacSHA256(key, payloadJSON))>
//
// payloadJSON encodes Claims. The "m1." prefix lets the server distinguish a
// signed token from a legacy static token (which is an opaque string) without
// trying to parse every value. Static tokens continue to work alongside
// signed ones.
package token

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Prefix marks a signed token. Anything not starting with this is treated as a
// legacy static token by the Authenticator.
const Prefix = "m1."

// Claims is the signed payload of a munnel token.
type Claims struct {
	// Sub is the subdomain this token is allowed to claim. "" means the
	// client may pick any free subdomain (subject to validation).
	Sub string `json:"sub,omitempty"`
	// Exp is the Unix-second expiry. 0 means the token never expires.
	Exp int64 `json:"exp,omitempty"`
	// ID is a unique, random identifier used for revocation. It is safe to
	// expose (it is not a secret — the signature is).
	ID string `json:"id"`
}

// Sentinel errors returned by Parse. Wrapping lets the Authenticator surface
// a precise rejection reason to the client without leaking the key.
var (
	ErrMalformed = errors.New("munnel token: malformed")
	ErrBadSig    = errors.New("munnel token: bad signature")
	ErrExpired   = errors.New("munnel token: expired")
)

// Mint signs and returns a new token for the given subdomain claim and TTL.
// If sub is "" the holder may claim any free subdomain. If ttl <= 0 the token
// never expires (use sparingly).
func Mint(key []byte, sub string, ttl time.Duration) (string, error) {
	if len(key) == 0 {
		return "", errors.New("munnel token: signing key is empty")
	}
	id, err := randomID()
	if err != nil {
		return "", fmt.Errorf("munnel token: generate id: %w", err)
	}
	c := Claims{Sub: sub, ID: id}
	if ttl > 0 {
		c.Exp = time.Now().Add(ttl).Unix()
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("munnel token: marshal: %w", err)
	}
	sig := hmacSum(key, payload)
	return Prefix + b64(payload) + "." + b64(sig), nil
}

// Parse verifies a token's signature and expiry and returns its claims.
// It does NOT check revocation — that is the Authenticator's job (it owns the
// denylist). Revocation aside, a nil error means the token is authentic and
// unexpired.
func Parse(key []byte, tok string) (*Claims, error) {
	if len(key) == 0 {
		return nil, errors.New("munnel token: signing key is empty")
	}
	if !strings.HasPrefix(tok, Prefix) {
		return nil, ErrMalformed
	}
	body := tok[len(Prefix):]
	dot := strings.IndexByte(body, '.')
	if dot < 0 {
		return nil, ErrMalformed
	}
	payload, err := b64d(body[:dot])
	if err != nil {
		return nil, ErrMalformed
	}
	sig, err := b64d(body[dot+1:])
	if err != nil {
		return nil, ErrMalformed
	}
	if !hmac.Equal(sig, hmacSum(key, payload)) {
		return nil, ErrBadSig
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, ErrMalformed
	}
	if c.ID == "" {
		return nil, ErrMalformed
	}
	if c.Exp != 0 && time.Now().Unix() > c.Exp {
		return nil, ErrExpired
	}
	return &c, nil
}

// IDOf extracts a token's ID without verifying the signature, so an operator
// who only has a (possibly revoked or expired) token string can look up its
// ID for the denylist. Returns "" if the token is not a signed token.
func IDOf(tok string) string {
	if !strings.HasPrefix(tok, Prefix) {
		return ""
	}
	body := tok[len(Prefix):]
	dot := strings.IndexByte(body, '.')
	if dot < 0 {
		return ""
	}
	payload, err := b64d(body[:dot])
	if err != nil {
		return ""
	}
	var c Claims
	if json.Unmarshal(payload, &c) != nil {
		return ""
	}
	return c.ID
}

func hmacSum(key, payload []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(payload)
	return m.Sum(nil)
}

func randomID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "tok_" + hex.EncodeToString(b), nil
}

func b64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func b64d(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}