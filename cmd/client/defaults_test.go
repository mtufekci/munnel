package main

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// writeConfig writes body to a temp file and points MUNNEL_CONFIG at it for the
// duration of the test.
func writeConfig(t *testing.T, body string) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MUNNEL_CONFIG", p)
}

// clearMunnelEnv neutralizes any ambient MUNNEL_* env vars so they can't leak
// into a test's expectations. Every var is set to "" (present-but-empty), which
// applyDefaults treats as "unset" (it skips empty values).
func clearMunnelEnv(t *testing.T) {
	t.Helper()
	for _, e := range envKeys {
		t.Setenv(e.env, "")
	}
}

func newSF() *stringFlags {
	return &stringFlags{server: "localhost:7001", inspectAddr: ":4040", localHost: "127.0.0.1"}
}

// TestLoadConfigFile_ParsesValid verifies comment/blank handling, whitespace
// trimming, key lowercasing, and that malformed lines (no '=') are skipped.
func TestLoadConfigFile_ParsesValid(t *testing.T) {
	body := "# a comment\n\n  # indented comment\nserver = tunnels.example.com:7001 \ntoken=abc123\nInspect-Addr=:4090\nmalformednoequals\n"
	writeConfig(t, body)
	got := loadConfigFile()
	want := map[string]string{
		"server":       "tunnels.example.com:7001",
		"token":        "abc123",
		"inspect-addr": ":4090",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

// TestLoadConfigFile_MissingReturnsNil: an absent file is not an error — the
// caller treats nil as "no config defaults".
func TestLoadConfigFile_MissingReturnsNil(t *testing.T) {
	t.Setenv("MUNNEL_CONFIG", filepath.Join(t.TempDir(), "does-not-exist"))
	if got := loadConfigFile(); got != nil {
		t.Fatalf("expected nil for missing file, got %v", got)
	}
}

// TestApplyDefaults_ConfigOverridesBuiltins: every field set in the config file
// overrides the builtin defaults; fields absent from the file are untouched.
func TestApplyDefaults_ConfigOverridesBuiltins(t *testing.T) {
	clearMunnelEnv(t)
	writeConfig(t, "server=tunnels.example.com:7001\ntoken=secret\nsubdomain=myapp\ninspect-addr=:4090\nlocal-host=0.0.0.0\n")
	sf := newSF()
	var iset, ival bool
	var mb int
	var mset bool
	applyDefaults(sf, &iset, &ival, &mb, &mset)

	if sf.server != "tunnels.example.com:7001" {
		t.Errorf("server = %q, want tunnels.example.com:7001", sf.server)
	}
	if sf.token != "secret" {
		t.Errorf("token = %q, want secret", sf.token)
	}
	if sf.subdomain != "myapp" {
		t.Errorf("subdomain = %q, want myapp", sf.subdomain)
	}
	if sf.inspectAddr != ":4090" {
		t.Errorf("inspectAddr = %q, want :4090", sf.inspectAddr)
	}
	if sf.localHost != "0.0.0.0" {
		t.Errorf("localHost = %q, want 0.0.0.0", sf.localHost)
	}
	if iset || mset || mb != 0 {
		t.Errorf("inspect/maxBody should be unset: iset=%v mset=%v mb=%d", iset, mset, mb)
	}
}

// TestApplyDefaults_EnvOverridesConfig: env vars win over the config file, and
// the config file wins over builtins — the documented precedence.
func TestApplyDefaults_EnvOverridesConfig(t *testing.T) {
	clearMunnelEnv(t)
	writeConfig(t, "server=from-config\ntoken=from-config-token\nsubdomain=cfg\n")
	t.Setenv("MUNNEL_SERVER", "from-env:7001")
	t.Setenv("MUNNEL_TOKEN", "from-env-token")
	sf := newSF()
	var iset, ival bool
	var mb int
	var mset bool
	applyDefaults(sf, &iset, &ival, &mb, &mset)

	if sf.server != "from-env:7001" {
		t.Errorf("server = %q, want from-env:7001 (env must beat config)", sf.server)
	}
	if sf.token != "from-env-token" {
		t.Errorf("token = %q, want from-env-token (env must beat config)", sf.token)
	}
	if sf.subdomain != "cfg" {
		t.Errorf("subdomain = %q, want cfg (config must beat builtin; no env override)", sf.subdomain)
	}
}

// TestApplyDefaults_EmptyValuesIgnored: a config/env value of "" must NOT
// clobber a builtin or existing value — it means "leave as-is".
func TestApplyDefaults_EmptyValuesIgnored(t *testing.T) {
	clearMunnelEnv(t)
	writeConfig(t, "server=\ntoken=\n") // empty config values
	t.Setenv("MUNNEL_SUBDOMAIN", "")    // empty env value
	sf := newSF()
	var iset, ival bool
	var mb int
	var mset bool
	applyDefaults(sf, &iset, &ival, &mb, &mset)

	if sf.server != "localhost:7001" {
		t.Errorf("empty config server should keep builtin; got %q", sf.server)
	}
	if sf.token != "" {
		t.Errorf("token = %q, want \"\" (builtin)", sf.token)
	}
	if sf.subdomain != "" {
		t.Errorf("subdomain = %q, want \"\"", sf.subdomain)
	}
}

// TestApplyDefaults_InspectTriState: inspect is the one field with a non-trivial
// default (on). Any explicit value — config or env — must flip inspectSet so the
// caller knows it was intentional. "true"/"false" (case-insensitive) map
// directly; anything else maps to false. Env beats config.
func TestApplyDefaults_InspectTriState(t *testing.T) {
	cases := []struct {
		cfg     string
		env     string
		wantSet bool
		wantVal bool
	}{
		{"", "", false, false},        // nothing explicit → unset (caller uses builtin "on")
		{"true", "", true, true},      // config true
		{"false", "", true, false},    // config false
		{"FALSE", "", true, false},    // case-insensitive
		{"yes", "", true, false},      // non-"true" → false
		{"", "true", true, true},      // env true
		{"false", "true", true, true}, // env beats config
		{"true", "false", true, false},
	}
	for i, c := range cases {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			clearMunnelEnv(t)
			if c.cfg != "" {
				writeConfig(t, "inspect="+c.cfg+"\n")
			} else {
				writeConfig(t, "")
			}
			if c.env != "" {
				t.Setenv("MUNNEL_INSPECT", c.env)
			}
			sf := newSF()
			var iset, ival bool
			var mb int
			var mset bool
			applyDefaults(sf, &iset, &ival, &mb, &mset)

			if iset != c.wantSet {
				t.Errorf("inspectSet = %v, want %v (cfg=%q env=%q)", iset, c.wantSet, c.cfg, c.env)
			}
			if iset && ival != c.wantVal {
				t.Errorf("inspectVal = %v, want %v (cfg=%q env=%q)", ival, c.wantVal, c.cfg, c.env)
			}
		})
	}
}

// TestApplyDefaults_MaxBody: valid integers set maxBody+maxSet; non-numeric
// values are ignored (no partial/corrupt state).
func TestApplyDefaults_MaxBody(t *testing.T) {
	t.Run("valid_config", func(t *testing.T) {
		clearMunnelEnv(t)
		writeConfig(t, "max-body-mb=64\n")
		sf := newSF()
		var iset, ival bool
		var mb int
		var mset bool
		applyDefaults(sf, &iset, &ival, &mb, &mset)
		if !mset || mb != 64 {
			t.Fatalf("maxBody=%d mset=%v, want 64/true", mb, mset)
		}
	})

	t.Run("invalid_config_ignored", func(t *testing.T) {
		clearMunnelEnv(t)
		writeConfig(t, "max-body-mb=not-a-number\n")
		sf := newSF()
		var iset, ival bool
		var mb int
		var mset bool
		applyDefaults(sf, &iset, &ival, &mb, &mset)
		if mset || mb != 0 {
			t.Fatalf("invalid max-body should be ignored; got mb=%d mset=%v", mb, mset)
		}
	})

	t.Run("env_beats_config", func(t *testing.T) {
		clearMunnelEnv(t)
		writeConfig(t, "max-body-mb=16\n")
		t.Setenv("MUNNEL_MAX_BODY_MB", "128")
		sf := newSF()
		var iset, ival bool
		var mb int
		var mset bool
		applyDefaults(sf, &iset, &ival, &mb, &mset)
		if !mset || mb != 128 {
			t.Fatalf("maxBody=%d mset=%v, want 128/true (env beats config)", mb, mset)
		}
	})
}