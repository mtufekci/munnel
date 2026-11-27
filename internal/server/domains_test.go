package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// testServer builds a server for primary + extras with the given tunnels
// registered (nil sessions: Registry only dereferences one on collision).
func testServer(t *testing.T, primary string, extras []string, live ...string) *Server {
	t.Helper()
	s, err := New(Config{Domain: primary, ExtraDomains: extras})
	if err != nil {
		t.Fatal(err)
	}
	for _, sub := range live {
		if _, _, err := s.reg.Register(sub, nil, "", ""); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func TestSplitDomainList(t *testing.T) {
	for in, want := range map[string]string{
		"":                         "",
		" , ,":                     "",
		"a.com":                    "a.com",
		" a.com , b.org,":          "a.com|b.org",
		"tufekci.uk,,example.test": "tufekci.uk|example.test",
	} {
		if got := strings.Join(SplitDomainList(in), "|"); got != want {
			t.Errorf("SplitDomainList(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCheckExtraDomains(t *testing.T) {
	ok := [][]string{
		nil,
		{"tufekci.uk"},
		{"a.com", "b.org", "x-1.y2.example.test"},
		{"example.com"},           // suffix of the primary: allowed, most specific wins
		{"t.tunnels.example.com"}, // below the primary: allowed too
	}
	for _, extras := range ok {
		if err := checkExtraDomains("tunnels.example.com", extras); err != nil {
			t.Errorf("%q: unexpected error %v", extras, err)
		}
	}
	type badCase struct {
		extras []string
		want   string // part of the error message
	}
	bad := []badCase{
		{[]string{"Tufekci.uk"}, "must be lower case"},
		{[]string{"tunnels.example.com"}, "same as --domain"},
		{[]string{"a.com", "b.org", "a.com"}, "listed twice"},
	}
	for _, d := range []string{"localhost", "a..com", ".a.com", "a.com.", "-a.com", "a-.com", "a_b.com",
		"a b.com", "*.a.com", "a.com:443", "1.2.3.4", "::1", "https://a.com",
		strings.Repeat("a", 64) + ".com", strings.Repeat("abcdefghi.", 26) + "com"} {
		bad = append(bad, badCase{[]string{d}, "not a valid hostname"})
	}
	for _, tc := range bad {
		err := checkExtraDomains("tunnels.example.com", tc.extras)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: error %v, want one saying %q", tc.extras, err, tc.want)
		}
	}
	// New refuses a bad list too, so the server never starts with one.
	if _, err := New(Config{Domain: "tunnels.example.com", ExtraDomains: []string{"Bad.com"}}); err == nil {
		t.Error("New accepted an upper-case extra domain")
	}
}

func TestTunnelHost(t *testing.T) {
	type want struct {
		sub, base string
		ok        bool
	}
	cases := []struct {
		name    string
		primary string
		extras  []string
		host    string
		want    want
	}{
		// No extras: exactly today's suffix rule.
		{"primary sub", "tunnels.example.com", nil, "foo.tunnels.example.com", want{"foo", "tunnels.example.com", true}},
		{"primary nested", "tunnels.example.com", nil, "a.foo.tunnels.example.com", want{"a.foo", "tunnels.example.com", true}},
		{"no extras: other domain", "tunnels.example.com", nil, "foo.tufekci.uk", want{}},
		{"lookalike suffix", "tunnels.example.com", nil, "foo.eviltunnels.example.com", want{}},

		// One extra.
		{"extra sub", "tunnels.example.com", []string{"tufekci.uk"}, "dgdg.tufekci.uk", want{"dgdg", "tufekci.uk", true}},
		{"primary still", "tunnels.example.com", []string{"tufekci.uk"}, "dgdg.tunnels.example.com", want{"dgdg", "tunnels.example.com", true}},
		{"extra apex", "tunnels.example.com", []string{"tufekci.uk"}, "tufekci.uk", want{}},
		{"extra www", "tunnels.example.com", []string{"tufekci.uk"}, "www.tufekci.uk", want{}},
		{"extra nested", "tunnels.example.com", []string{"tufekci.uk"}, "a.dgdg.tufekci.uk", want{"a.dgdg", "tufekci.uk", true}},
		{"unknown domain", "tunnels.example.com", []string{"tufekci.uk"}, "dgdg.example.org", want{}},
		{"extra lookalike", "tunnels.example.com", []string{"tufekci.uk"}, "dgdg.nottufekci.uk", want{}},

		// Extra is a suffix of the primary: the primary apex is never
		// tunnel "tunnels" of example.com, and its subs stay the primary's.
		{"overlap: primary apex", "tunnels.example.com", []string{"example.com"}, "tunnels.example.com", want{}},
		{"overlap: primary www", "tunnels.example.com", []string{"example.com"}, "www.tunnels.example.com", want{}},
		{"overlap: primary sub", "tunnels.example.com", []string{"example.com"}, "foo.tunnels.example.com", want{"foo", "tunnels.example.com", true}},
		{"overlap: extra sub", "tunnels.example.com", []string{"example.com"}, "foo.example.com", want{"foo", "example.com", true}},
		{"overlap: extra apex", "tunnels.example.com", []string{"example.com"}, "example.com", want{}},

		// Primary is a suffix of an extra: the extra's apex is not tunnel
		// "tunnels" of the primary.
		{"overlap rev: extra apex", "example.com", []string{"tunnels.example.com"}, "tunnels.example.com", want{}},
		{"overlap rev: extra www", "example.com", []string{"tunnels.example.com"}, "www.tunnels.example.com", want{}},
		{"overlap rev: extra sub", "example.com", []string{"tunnels.example.com"}, "foo.tunnels.example.com", want{"foo", "tunnels.example.com", true}},
		{"overlap rev: primary sub", "example.com", []string{"tunnels.example.com"}, "foo.example.com", want{"foo", "example.com", true}},

		// Two extras nested in each other: longest wins regardless of order.
		{"extras nested", "t.test", []string{"example.com", "a.example.com"}, "foo.a.example.com", want{"foo", "a.example.com", true}},
		{"extras nested apex", "t.test", []string{"example.com", "a.example.com"}, "a.example.com", want{}},
	}
	for _, tc := range cases {
		s := testServer(t, tc.primary, tc.extras)
		sub, base, ok := s.tunnelHost(tc.host)
		if got := (want{sub, base, ok}); got != tc.want {
			t.Errorf("%s: tunnelHost(%q) = %+v, want %+v", tc.name, tc.host, got, tc.want)
		}
	}
}

// askCode runs one GET /check?domain= through the ask handler.
func askCode(s *Server, domain string) int {
	rec := httptest.NewRecorder()
	s.handleAsk(rec, httptest.NewRequest(http.MethodGet, "/check?domain="+url.QueryEscape(domain), nil))
	return rec.Code
}

func TestCertAllowed_ExtraDomains(t *testing.T) {
	cases := []struct {
		name    string
		primary string
		extras  []string
		domain  string
		want    int
	}{
		// No extras: today's rule.
		{"no extras: apex", "tunnels.example.com", nil, "tunnels.example.com", 200},
		{"no extras: www", "tunnels.example.com", nil, "www.tunnels.example.com", 200},
		{"no extras: live", "tunnels.example.com", nil, "foo.tunnels.example.com", 200},
		{"no extras: other domain", "tunnels.example.com", nil, "foo.tufekci.uk", 403},

		// One extra.
		{"extra live", "tunnels.example.com", []string{"tufekci.uk"}, "foo.tufekci.uk", 200},
		{"extra live mixed case", "tunnels.example.com", []string{"tufekci.uk"}, "FOO.Tufekci.UK", 200},
		{"extra trailing dot", "tunnels.example.com", []string{"tufekci.uk"}, "foo.tufekci.uk.", 403},
		{"extra not live", "tunnels.example.com", []string{"tufekci.uk"}, "ghost.tufekci.uk", 403},
		{"extra apex", "tunnels.example.com", []string{"tufekci.uk"}, "tufekci.uk", 403},
		{"extra www", "tunnels.example.com", []string{"tufekci.uk"}, "www.tufekci.uk", 403},
		{"extra nested", "tunnels.example.com", []string{"tufekci.uk"}, "a.foo.tufekci.uk", 403},
		{"unknown domain", "tunnels.example.com", []string{"tufekci.uk"}, "foo.example.org", 403},
		{"primary unchanged", "tunnels.example.com", []string{"tufekci.uk"}, "foo.tunnels.example.com", 200},
		{"primary apex unchanged", "tunnels.example.com", []string{"tufekci.uk"}, "tunnels.example.com", 200},

		// Suffix overlap: the primary apex keeps its own rule (approved as
		// the apex, not as tunnel "tunnels"), the extra apex is refused.
		{"overlap: primary apex", "tunnels.example.com", []string{"example.com"}, "tunnels.example.com", 200},
		{"overlap: extra sub", "tunnels.example.com", []string{"example.com"}, "foo.example.com", 200},
		{"overlap: extra apex", "tunnels.example.com", []string{"example.com"}, "example.com", 403},
		{"overlap rev: extra apex", "example.com", []string{"tunnels.example.com"}, "tunnels.example.com", 403},
		{"overlap rev: extra sub", "example.com", []string{"tunnels.example.com"}, "foo.tunnels.example.com", 200},
	}
	for _, tc := range cases {
		// "tunnels" and "www" are live too, so a host misread as that
		// label would be approved.
		s := testServer(t, tc.primary, tc.extras, "foo", "tunnels", "www")
		if got := askCode(s, tc.domain); got != tc.want {
			t.Errorf("%s: ask %q = %d, want %d", tc.name, tc.domain, got, tc.want)
		}
	}
}

// TestServeHTTP_ExtraApexNotServed: an extra domain's apex and www. get the
// unknown-host page, never a tunnel, even when tunnels named like their
// first label are live; offline names on an extra domain name that domain.
func TestServeHTTP_ExtraApexNotServed(t *testing.T) {
	s := testServer(t, "tunnels.example.com", []string{"example.com"}, "tunnels", "www")
	for host, want := range map[string]int{
		"example.com":            http.StatusNotFound,
		"www.example.com":        http.StatusNotFound,
		"WWW.Example.COM.":       http.StatusNotFound,
		"a.ghost.example.com":    http.StatusNotFound,
		"tunnels.example.com":    http.StatusOK, // primary landing page
		"Tunnels.Example.com.":   http.StatusOK,
		"ghost.example.com:8443": http.StatusBadGateway,
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = host
		s.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("GET Host %q = %d, want %d", host, rec.Code, want)
		}
		if want == http.StatusBadGateway && !strings.Contains(rec.Body.String(), "ghost.example.com") {
			t.Errorf("offline page for %q does not name the host it was asked for: %s", host, rec.Body.String())
		}
	}
}
