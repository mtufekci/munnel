package server

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/mtufekci/munnel/internal/proto"
)

// SplitDomainList splits a comma-separated list of domains (the
// --extra-domains flag or $MUNNEL_EXTRA_DOMAINS), trimming spaces and
// dropping empty entries, so "" and a trailing comma both mean none.
func SplitDomainList(s string) []string {
	var out []string
	for _, d := range strings.Split(s, ",") {
		if d = strings.TrimSpace(d); d != "" {
			out = append(out, d)
		}
	}
	return out
}

// checkExtraDomains validates the extra base domains: each one a lower-case
// hostname with at least two labels (not an IP), none repeated, none equal
// to the primary domain. One configured domain may be a suffix of another;
// tunnelHost resolves the overlap.
func checkExtraDomains(primary string, extras []string) error {
	seen := map[string]bool{}
	for _, d := range extras {
		if d != strings.ToLower(d) {
			return fmt.Errorf("extra domain %q: must be lower case", d)
		}
		if !validHostname(d) {
			return fmt.Errorf("extra domain %q: not a valid hostname (lowercase letters, digits, hyphens; at least two labels; no IP addresses)", d)
		}
		if d == strings.ToLower(primary) {
			return fmt.Errorf("extra domain %q: same as --domain", d)
		}
		if seen[d] {
			return fmt.Errorf("extra domain %q: listed twice", d)
		}
		seen[d] = true
	}
	return nil
}

// validHostname reports whether d is a DNS hostname of at least two labels,
// each 1-63 of [a-z0-9-] with no leading or trailing hyphen.
func validHostname(d string) bool {
	if len(d) > 253 || net.ParseIP(d) != nil {
		return false
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

// baseDomains lists the primary domain and the extras, longest first, so the
// most specific base wins when one is a suffix of another.
func baseDomains(primary string, extras []string) []string {
	bases := append([]string{primary}, extras...)
	sort.SliceStable(bases, func(i, j int) bool { return len(bases[i]) > len(bases[j]) })
	return bases
}

// tunnelHost splits a lower-cased host into the tunnel label it addresses
// and the base domain it was addressed under. Every tunnel is reachable
// under every base domain (one shared namespace). ok is false when host is
// not below any base domain, or is the apex or www. of a base domain. The
// primary apex and its www. serve the landing page (callers check them
// first); an extra domain's apex and www. belong to its owner (mail, a
// website) and are never served. An exact apex match beats a suffix match,
// so with extra "example.com" the primary "tunnels.example.com" is never
// tunnel "tunnels". Otherwise the longest base wins. The label is returned
// as found: callers check it with proto.ValidSubdomain, so "a.b.<base>"
// never reaches a tunnel.
func (s *Server) tunnelHost(host string) (sub, base string, ok bool) {
	for _, d := range s.bases {
		if host == d || host == "www."+d {
			return "", "", false
		}
	}
	for _, d := range s.bases {
		if label, found := strings.CutSuffix(host, "."+d); found {
			return label, d, true
		}
	}
	return "", "", false
}

// liveTunnelHost reports whether host names a valid tunnel label under a base
// domain and a client holds that label right now.
func (s *Server) liveTunnelHost(host string) bool {
	sub, _, ok := s.tunnelHost(host)
	return ok && proto.ValidSubdomain(sub) && s.reg.Get(sub) != nil
}
