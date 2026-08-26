package main

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// envKeys maps environment variables to their config-file key equivalents.
var envKeys = []struct{ env, key string }{
	{"MUNNEL_SERVER", "server"},
	{"MUNNEL_TOKEN", "token"},
	{"MUNNEL_SUBDOMAIN", "subdomain"},
	{"MUNNEL_INSPECT_ADDR", "inspect-addr"},
	{"MUNNEL_LOCAL_HOST", "local-host"},
	{"MUNNEL_MAX_BODY_MB", "max-body-mb"},
	{"MUNNEL_INSPECT", "inspect"},
}

// loadConfigFile reads KEY=VAL defaults from $MUNNEL_CONFIG or ~/.munnel/config.
// Returns nil if the file is absent or unreadable so callers can treat that as
// "no defaults".
func loadConfigFile() map[string]string {
	path := os.Getenv("MUNNEL_CONFIG")
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil
		}
		path = filepath.Join(home, ".munnel", "config")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(strings.ToLower(k))] = strings.TrimSpace(v)
	}
	return out
}

// applyDefaults overlays config-file then env-var defaults onto the flag
// holders. It runs before flag parsing, so any explicit flag still wins.
func applyDefaults(sf *stringFlags, inspectSet *bool, inspectVal *bool, maxBody *int, maxSet *bool) {
	apply := func(m map[string]string) {
		if m == nil {
			return
		}
		if v := m["server"]; v != "" {
			sf.server = v
		}
		if v := m["token"]; v != "" {
			sf.token = v
		}
		if v := m["subdomain"]; v != "" {
			sf.subdomain = v
		}
		if v := m["inspect-addr"]; v != "" {
			sf.inspectAddr = v
		}
		if v := m["local-host"]; v != "" {
			sf.localHost = v
		}
		if v := m["max-body-mb"]; v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				*maxBody = n
				*maxSet = true
			}
		}
		if v := m["inspect"]; v != "" {
			*inspectSet = true
			*inspectVal = strings.EqualFold(v, "true")
		}
	}
	apply(loadConfigFile())

	env := map[string]string{}
	for _, e := range envKeys {
		if v, ok := os.LookupEnv(e.env); ok && v != "" {
			env[e.key] = v
		}
	}
	apply(env)
}