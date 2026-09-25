package main

import (
	"fmt"
	"testing"
)

// TestApplyDefaults_TLS: tls and server-cert-sha256 follow the same
// precedence as every other setting (env beats config; flags are applied on
// top by run).
func TestApplyDefaults_TLS(t *testing.T) {
	cases := []struct {
		cfg, env       string
		wantTLS        string
		cfgPin, envPin string
		wantPin        string
	}{
		{cfg: "", env: "", wantTLS: ""},
		{cfg: "true", env: "", wantTLS: "true"},
		{cfg: "true", env: "false", wantTLS: "false"},
		{cfg: "", env: "true", wantTLS: "true", cfgPin: "aa", wantPin: "aa"},
		{cfg: "true", wantTLS: "true", cfgPin: "aa", envPin: "bb", wantPin: "bb"},
	}
	for i, c := range cases {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			clearMunnelEnv(t)
			body := ""
			if c.cfg != "" {
				body += "tls=" + c.cfg + "\n"
			}
			if c.cfgPin != "" {
				body += "server-cert-sha256=" + c.cfgPin + "\n"
			}
			writeConfig(t, body)
			if c.env != "" {
				t.Setenv("MUNNEL_TLS", c.env)
			}
			if c.envPin != "" {
				t.Setenv("MUNNEL_SERVER_CERT_SHA256", c.envPin)
			}
			sf := newSF()
			var iset, ival bool
			var mb int
			var mset bool
			applyDefaults(sf, &iset, &ival, &mb, &mset)
			if sf.tls != c.wantTLS {
				t.Errorf("tls = %q, want %q", sf.tls, c.wantTLS)
			}
			if sf.serverCertSHA256 != c.wantPin {
				t.Errorf("pin = %q, want %q", sf.serverCertSHA256, c.wantPin)
			}
		})
	}
}

// TestLogPathDropsQuery: the headless request log must never write query
// strings (OAuth codes, signed-URL signatures) to stdout.
func TestLogPathDropsQuery(t *testing.T) {
	cases := map[string]string{
		"/":                               "/",
		"/auth/callback?code=abc&state=x": "/auth/callback",
		"/files/a.txt?X-Amz-Signature=s":  "/files/a.txt",
		"/plain":                          "/plain",
		"/?":                              "/",
	}
	for in, want := range cases {
		if got := logPath(in); got != want {
			t.Errorf("logPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseBool(t *testing.T) {
	for in, want := range map[string]bool{"": false, "true": true, "false": false, "1": true, "TRUE": true} {
		got, err := parseBool(in)
		if err != nil || got != want {
			t.Errorf("parseBool(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := parseBool("maybe"); err == nil {
		t.Error("parseBool(maybe) should fail")
	}
}
