package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mtufekci/munnel/internal/token"
)

func TestParseReserved(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    map[string][]string // name → IDs
		wantErr string
	}{
		{
			name: "lines, comments, separators",
			in: "# reserved names\n\nhop tok_aaaaaaaaaaaaaaaa\n" +
				"staging tok_bbbbbbbbbbbbbbbb,tok_cccccccccccccccc\n" +
				"  Demo = tok_dddddddddddddddd  tok_eeeeeeeeeeeeeeee \n" +
				"hop tok_ffffffffffffffff\n",
			want: map[string][]string{
				"hop":     {"tok_aaaaaaaaaaaaaaaa", "tok_ffffffffffffffff"},
				"staging": {"tok_bbbbbbbbbbbbbbbb", "tok_cccccccccccccccc"},
				"demo":    {"tok_dddddddddddddddd", "tok_eeeeeeeeeeeeeeee"},
			},
		},
		{name: "invalid name", in: "bad_name tok_aaaaaaaaaaaaaaaa\n", wantErr: "invalid subdomain"},
		{name: "no ids", in: "hop\n", wantErr: "lists no token IDs"},
		{name: "a token pasted instead of its id", in: "hop m1.eyJpZCI6InRva18xIn0.sig\n", wantErr: "not a token ID (use"},
		{name: "not an id", in: "hop alice\n", wantErr: "not a token ID"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := map[string]map[string]bool{}
			err := parseReserved(strings.NewReader(tc.in), got)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to mention %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %d names %v, want %d", len(got), got, len(tc.want))
			}
			for name, ids := range tc.want {
				if len(got[name]) != len(ids) {
					t.Fatalf("%s: got %v, want %v", name, got[name], ids)
				}
				for _, id := range ids {
					if !got[name][id] {
						t.Fatalf("%s: missing %s in %v", name, id, got[name])
					}
				}
			}
		})
	}
}

func TestCheckReserved(t *testing.T) {
	key := []byte("reserved-unit-key")
	hopTok, _ := token.Mint(key, "hop", time.Hour)
	otherHop, _ := token.Mint(key, "hop", time.Hour) // same sub claim, different ID
	anyTok, _ := token.Mint(key, "", time.Hour)
	revokedTok, _ := token.Mint(key, "hop", time.Hour)

	dir := t.TempDir()
	revoked := filepath.Join(dir, "revoked")
	os.WriteFile(revoked, []byte(token.IDOf(revokedTok)+"\n"), 0o600)
	a, err := NewAuthenticatorWith(AuthOptions{
		Tokens:      "static-token",
		SigningKey:  key,
		RevokedFile: revoked,
		Reserved:    "hop " + token.IDOf(hopTok) + "," + token.IDOf(revokedTok),
	})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		tok     string
		sub     string
		overTLS bool
		wantErr string // "" = allowed
	}{
		{"listed token over TLS", hopTok, "hop", true, ""},
		{"listed token over plaintext", hopTok, "hop", false, "TLS"},
		{"other token with the same sub claim", otherHop, "hop", true, "is reserved"},
		{"unscoped signed token", anyTok, "hop", true, "is reserved"},
		{"static token", "static-token", "hop", true, "is reserved"},
		{"no token", "", "hop", true, "is reserved"},
		{"listed but revoked", revokedTok, "hop", true, "is reserved"},
		{"unreserved name, plaintext", anyTok, "alice", false, ""},
		{"random name", "static-token", "", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := a.CheckReserved(tc.tok, tc.sub, tc.overTLS)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("want allowed, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
	if !a.IsReserved("hop") || a.IsReserved("alice") {
		t.Fatal("IsReserved wrong")
	}
}

func TestReservedConfigErrors(t *testing.T) {
	dir := t.TempDir()
	authFile := filepath.Join(dir, "auth.json")
	os.WriteFile(authFile, []byte(`{"static-token":"hop"}`), 0o600)

	cases := []struct {
		name    string
		opts    AuthOptions
		wantErr string
	}{
		{"no signing key", AuthOptions{Tokens: "x", Reserved: "hop tok_aaaaaaaaaaaaaaaa"}, "signing key"},
		{"static token reserved to the same name", AuthOptions{AuthFile: authFile, SigningKey: []byte("k"), Reserved: "hop tok_aaaaaaaaaaaaaaaa"}, "static token"},
		{"missing file", AuthOptions{SigningKey: []byte("k"), ReservedFile: filepath.Join(dir, "nope")}, "reserved file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewAuthenticatorWith(tc.opts)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}
