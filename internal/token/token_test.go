package token

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestMintParse_RoundTrip(t *testing.T) {
	key := []byte("super-secret-key")
	tok, err := Mint(key, "alice", 0)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if !strings.HasPrefix(tok, Prefix) {
		t.Fatalf("token missing prefix: %s", tok)
	}
	c, err := Parse(key, tok)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Sub != "alice" {
		t.Fatalf("sub: want alice, got %q", c.Sub)
	}
	if c.ID == "" {
		t.Fatal("ID is empty")
	}
	if c.Exp != 0 {
		t.Fatalf("exp: want 0 (no expiry), got %d", c.Exp)
	}
}

func TestParse_WrongKey(t *testing.T) {
	tok, _ := Mint([]byte("key-a"), "alice", 0)
	if _, err := Parse([]byte("key-b"), tok); err != ErrBadSig {
		t.Fatalf("want ErrBadSig, got %v", err)
	}
}

func TestParse_TamperedPayload(t *testing.T) {
	key := []byte("k")
	tok, _ := Mint(key, "alice", 0)
	// Flip a character in the base64 payload portion — the signature no
	// longer matches (and, if it still decodes, the subdomain differs).
	body := tok[len(Prefix):]
	dot := strings.IndexByte(body, '.')
	if body[dot-1] == 'A' {
		body = body[:dot-1] + "B" + body[dot:]
	} else {
		body = body[:dot-1] + "A" + body[dot:]
	}
	tampered := Prefix + body
	if _, err := Parse(key, tampered); err == nil {
		t.Fatal("Parse accepted a tampered payload")
	}
}

func TestParse_TamperedSignature(t *testing.T) {
	key := []byte("k")
	tok, _ := Mint(key, "alice", 0)
	// Corrupt the signature segment. We flip the FIRST char, not the last:
	// a 32-byte HMAC encodes to 43 base64url chars, and the final char's low
	// 2 bits are padding that Go's decoder ignores — so tampering the last
	// char can leave the decoded bytes (and thus hmac.Equal) unchanged. The
	// first char always maps into the first decoded byte, so any change is
	// observable.
	body := tok[len(Prefix):]
	dot := strings.IndexByte(body, '.')
	sig := body[dot+1:]
	first := sig[0]
	alt := byte('A')
	if first == 'A' {
		alt = 'B'
	}
	body = body[:dot+1] + string(alt) + sig[1:]
	if _, err := Parse(key, Prefix+body); err == nil {
		t.Fatal("Parse accepted a tampered signature")
	}
}

func TestParse_Expired(t *testing.T) {
	key := []byte("k")
	// Expiry is stored at Unix-second granularity, so a sub-second TTL would
	// round to the current second and never trip. Craft a token whose exp is
	// already in the past (this is a white-box test in package token).
	c := Claims{Sub: "alice", ID: "tok_test", Exp: time.Now().Unix() - 1}
	payload, _ := json.Marshal(c)
	tok := Prefix + b64(payload) + "." + b64(hmacSum(key, payload))
	if _, err := Parse(key, tok); err != ErrExpired {
		t.Fatalf("want ErrExpired, got %v", err)
	}
}

func TestParse_NotYetExpired(t *testing.T) {
	key := []byte("k")
	c := Claims{Sub: "alice", ID: "tok_test", Exp: time.Now().Unix() + 3600}
	payload, _ := json.Marshal(c)
	tok := Prefix + b64(payload) + "." + b64(hmacSum(key, payload))
	if _, err := Parse(key, tok); err != nil {
		t.Fatalf("valid future-expiry token should parse: %v", err)
	}
}

func TestParse_Malformed(t *testing.T) {
	cases := []string{
		"",
		"not-a-token",
		"m1.",
		"m1.no-dot-here",
		"m1.!!!.!!!",
		"m1." + base64.RawURLEncoding.EncodeToString([]byte("{not json")) + ".AA",
	}
	for _, tc := range cases {
		if _, err := Parse([]byte("k"), tc); err == nil {
			t.Fatalf("Parse(%q) accepted malformed input", tc)
		}
	}
}

func TestParse_EmptyKey(t *testing.T) {
	if _, err := Parse(nil, "m1.x.y"); err == nil {
		t.Fatal("Parse with empty key should fail")
	}
	if _, err := Mint(nil, "alice", 0); err == nil {
		t.Fatal("Mint with empty key should fail")
	}
}

func TestIDOf(t *testing.T) {
	tok, _ := Mint([]byte("k"), "alice", 0)
	c, _ := Parse([]byte("k"), tok)
	if got := IDOf(tok); got != c.ID {
		t.Fatalf("IDOf: want %q, got %q", c.ID, got)
	}
	if IDOf("legacy-static-token") != "" {
		t.Fatal("IDOf should return empty for a non-signed token")
	}
}

// TestMint_DeterministicIDUniqueness: two mints with the same key+sub must
// produce different IDs (random) and both validate.
func TestMint_IDsAreUnique(t *testing.T) {
	key := []byte("k")
	a, _ := Mint(key, "alice", 0)
	b, _ := Mint(key, "alice", 0)
	if a == b {
		t.Fatal("two mints produced identical tokens (ID not random?)")
	}
	ca, _ := Parse(key, a)
	cb, _ := Parse(key, b)
	if ca.ID == cb.ID {
		t.Fatal("two mints produced identical IDs")
	}
}
