// Command munnel exposes a local port through a munnel server.
//
//	munnel 3000                        expose localhost:3000
//	munnel 3000 -s myapp              claim a subdomain
//	munnel 3000 -t TOKEN --server tunnels.example.com:7001
//	munnel token --sub myapp          acquire a token (saved to ~/.munnel/config)
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/mtufekci/munnel/internal/client"
	"github.com/mtufekci/munnel/internal/inspection"
	"github.com/mtufekci/munnel/internal/tui"
)

var version = "dev"

// stringFlags holds the settings that config file and env vars may default
// (see applyDefaults). tls is tri-state: "" (unset), "true" or "false".
type stringFlags struct {
	subdomain, token, server, inspectAddr, localHost string
	tls, serverCertSHA256                            string
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(argv []string) int {
	// Subcommand: munnel token — self-service token acquisition.
	if len(argv) > 0 && argv[0] == "token" {
		return runToken(argv[1:])
	}

	sf := &stringFlags{server: "localhost:7001", inspectAddr: client.DefaultInspectAddr, localHost: "127.0.0.1"}
	var inspectSet, inspectVal bool
	var maxBodyMB int
	var maxBodySet bool
	var protect bool
	var showVersion bool

	// Defaults from ~/.munnel/config (or $MUNNEL_CONFIG) then MUNNEL_* env vars.
	// Explicit flags below still override these.
	applyDefaults(sf, &inspectSet, &inspectVal, &maxBodyMB, &maxBodySet)

	args := []string{}
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		next := func() string {
			if i+1 < len(argv) {
				i++
				return argv[i]
			}
			return ""
		}
		switch {
		case a == "-s" || a == "--subdomain":
			sf.subdomain = next()
		case strings.HasPrefix(a, "--subdomain="):
			sf.subdomain = strings.TrimPrefix(a, "--subdomain=")
		case a == "-t" || a == "--token":
			sf.token = next()
		case strings.HasPrefix(a, "--token="):
			sf.token = strings.TrimPrefix(a, "--token=")
		case a == "--server":
			sf.server = next()
		case strings.HasPrefix(a, "--server="):
			sf.server = strings.TrimPrefix(a, "--server=")
		case a == "--inspect-addr":
			sf.inspectAddr = next()
		case strings.HasPrefix(a, "--inspect-addr="):
			sf.inspectAddr = strings.TrimPrefix(a, "--inspect-addr=")
		case a == "--local-host":
			sf.localHost = next()
		case strings.HasPrefix(a, "--local-host="):
			sf.localHost = strings.TrimPrefix(a, "--local-host=")
		case a == "--inspect":
			inspectSet = true
			inspectVal = true
		case a == "--inspect=false" || a == "--no-inspect":
			inspectSet = true
			inspectVal = false
		case strings.HasPrefix(a, "--inspect="):
			inspectSet = true
			inspectVal = strings.TrimPrefix(a, "--inspect=") == "true"
		case a == "--max-body-mb":
			maxBodyMB, _ = strconv.Atoi(next())
			maxBodySet = true
		case strings.HasPrefix(a, "--max-body-mb="):
			maxBodyMB, _ = strconv.Atoi(strings.TrimPrefix(a, "--max-body-mb="))
			maxBodySet = true
		case a == "--protect":
			protect = true
		case a == "--tls":
			sf.tls = "true"
		case strings.HasPrefix(a, "--tls="):
			sf.tls = strings.TrimPrefix(a, "--tls=")
		case a == "--server-cert-sha256":
			sf.serverCertSHA256 = next()
		case strings.HasPrefix(a, "--server-cert-sha256="):
			sf.serverCertSHA256 = strings.TrimPrefix(a, "--server-cert-sha256=")
		case a == "--version" || a == "-v":
			showVersion = true
		case a == "-h" || a == "--help":
			usage(os.Stdout)
			return 0
		case strings.HasPrefix(a, "-"):
			fmt.Fprintf(os.Stderr, "unknown flag: %s\n", a)
			usage(os.Stderr)
			return 2
		default:
			args = append(args, a)
		}
	}

	if showVersion {
		fmt.Printf("munnel %s\n", version)
		return 0
	}
	if len(args) != 1 {
		usage(os.Stderr)
		return 2
	}

	port, err := strconv.Atoi(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid port %q\n", args[0])
		return 2
	}

	// Inspection defaults to on; an explicit value from config/env/flags
	// (inspectSet) overrides the default.
	inspectOn := true
	if inspectSet {
		inspectOn = inspectVal
	}

	tlsOn, err := parseBool(sf.tls)
	if err != nil {
		fmt.Fprintf(os.Stderr, "munnel: --tls: %v\n", err)
		return 2
	}

	cfg := client.Config{
		LocalPort:        port,
		LocalHost:        sf.localHost,
		ServerAddr:       sf.server,
		Subdomain:        sf.subdomain,
		Token:            sf.token,
		Protect:          protect,
		Inspect:          inspectOn,
		InspectAddr:      sf.inspectAddr,
		MaxBody:          32 << 20,
		TLS:              tlsOn,
		ServerCertSHA256: sf.serverCertSHA256,
	}
	if maxBodySet && maxBodyMB > 0 {
		cfg.MaxBody = int64(maxBodyMB) << 20
	}
	if cfg.InspectAddr == "" {
		cfg.InspectAddr = client.DefaultInspectAddr
	}

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "munnel: %v\n", err)
		return 2
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	store := inspection.NewStore(0)
	hub := inspection.NewHub()

	tun, err := client.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "munnel: %v\n", err)
		return 2
	}
	tun.OnRecord = func(rec *inspection.Record) {
		store.Add(rec)
		hub.BroadcastRecord(rec)
	}

	inspectURL := ""
	if cfg.Inspect {
		insp := inspection.New(store, hub, tun.Forwarder(), func() any { return tun.Status() })
		go func() {
			if err := insp.ListenAndServe(ctx, cfg.InspectAddr); err != nil && ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "inspector: %v\n", err)
			}
		}()
		// The link carries the inspector's per-launch token; opening it once
		// sets a cookie for the tab.
		inspectURL = insp.URLFor(cfg.InspectAddr)
	}

	go tun.Run(ctx)

	if term.IsTerminal(int(os.Stdout.Fd())) {
		err := tui.Run(tun.Events(), tui.Opts{
			ServerAddr:   cfg.ServerAddr,
			InspectorURL: inspectURL,
			Target:       "http://" + tun.Forwarder().LocalAddr(),
		}, cancel)
		cancel()
		if err != nil {
			fmt.Fprintf(os.Stderr, "tui: %v\n", err)
			return 1
		}
		return 0
	}

	// Non-interactive mode: plain log lines (CI, scripts, piping output).
	fmt.Printf("munnel %s — forwarding http://%s (server %s)\n", version, tun.Forwarder().LocalAddr(), cfg.ServerAddr)
	if inspectURL != "" {
		fmt.Printf("inspector: %s\n", inspectURL)
	}
	for e := range tun.Events() {
		switch e.Kind {
		case client.EventConnected:
			fmt.Printf("\n✓ tunnel live  %s\n\n", e.PublicURL)
		case client.EventDisconnected:
			fmt.Printf("✗ disconnected: %s\n", e.Message)
		case client.EventReconnecting:
			fmt.Printf("… %s\n", e.Message)
		case client.EventRequest:
			if r := e.Record; r != nil {
				status := strconv.Itoa(r.Status)
				if r.Errored {
					status = "ERR"
				}
				fmt.Printf("%-7s %-40s %s %4dms\n", r.Method, logPath(r.Path), status, r.Duration)
			}
		case client.EventShuttingDown:
			fmt.Println("shutdown")
			return 0
		}
	}
	<-ctx.Done()
	return 0
}

// logPath drops the query string from a request path for the headless log:
// stdout often ends up in files, and queries carry secrets (OAuth ?code=,
// signed-URL signatures, API keys). The inspector still shows full paths.
func logPath(p string) string {
	if i := strings.IndexByte(p, '?'); i >= 0 {
		return p[:i]
	}
	return p
}

// parseBool reads a tri-state flag value: "" means unset (false).
func parseBool(v string) (bool, error) {
	if v == "" {
		return false, nil
	}
	return strconv.ParseBool(v)
}

// runToken implements `munnel token`: acquires a signed, scoped token from
// the server's self-service issuance endpoint (POST /__munnel/token) and
// writes it to ~/.munnel/config so every later `munnel <port>` picks it up
// automatically. The enrollment password gates issuance; it is prompted for
// (no echo) and never stored.
func runToken(args []string) int {
	fs := flag.NewFlagSet("munnel token", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	sub := fs.String("sub", "", "subdomain to scope the token to (empty = any free subdomain)")
	ttl := fs.String("ttl", "168h", "token lifetime (e.g. 24h, 168h, 720h); server caps at 720h")
	password := fs.String("password", "", "enrollment password (or $MUNNEL_ENROLL_PASSWORD; prompted if unset)")
	server := fs.String("server", "", "control server address (default: config file or localhost:7001)")
	serverURL := fs.String("server-url", "", "proxy base URL for token issuance (default: derived from --server)")
	showHelp := fs.Bool("help", false, "show help")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showHelp {
		tokenUsage(os.Stdout)
		return 0
	}

	// Defaults from config file (server address), then env (password).
	if *server == "" {
		if m := loadConfigFile(); m != nil {
			*server = m["server"]
		}
	}
	if *server == "" {
		*server = "localhost:7001"
	}
	pw := *password
	if pw == "" {
		pw = os.Getenv("MUNNEL_ENROLL_PASSWORD")
	}
	if pw == "" {
		fmt.Fprintf(os.Stderr, "enrollment password for %s: ", *server)
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "munnel token: read password: %v\n", err)
			return 2
		}
		pw = string(b)
	}
	if pw == "" {
		fmt.Fprintln(os.Stderr, "munnel token: enrollment password required")
		return 2
	}

	proxyURL := *serverURL
	if proxyURL == "" {
		proxyURL = deriveProxyURL(*server)
	}

	reqBody, _ := json.Marshal(map[string]string{
		"sub":      *sub,
		"password": pw,
		"ttl":      *ttl,
	})
	resp, err := http.Post(strings.TrimSuffix(proxyURL, "/")+"/__munnel/token", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		fmt.Fprintf(os.Stderr, "munnel token: %v\n", err)
		return 1
	}
	defer resp.Body.Close()
	var out struct {
		Token   string `json:"token"`
		ID      string `json:"id"`
		Sub     string `json:"sub"`
		Expires string `json:"expires"`
		Error   string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		fmt.Fprintf(os.Stderr, "munnel token: unexpected server response (HTTP %d)\n", resp.StatusCode)
		return 1
	}
	if out.Error != "" {
		fmt.Fprintf(os.Stderr, "munnel token: %s (HTTP %d)\n", out.Error, resp.StatusCode)
		return 1
	}
	if out.Token == "" {
		fmt.Fprintf(os.Stderr, "munnel token: server returned no token (HTTP %d)\n", resp.StatusCode)
		return 1
	}

	if err := updateConfigToken(out.Token); err != nil {
		fmt.Fprintf(os.Stderr, "munnel token: write config: %v\n", err)
		return 1
	}

	fmt.Printf("✓ token acquired (id %s)\n", out.ID)
	if out.Sub != "" {
		fmt.Printf("  subdomain: %s\n", out.Sub)
	} else {
		fmt.Println("  subdomain: any (unscoped)")
	}
	if out.Expires != "" {
		fmt.Printf("  expires:   %s\n", out.Expires)
	} else {
		fmt.Println("  expires:   never")
	}
	fmt.Println("  saved to:  ~/.munnel/config")
	fmt.Println("\nready:  munnel 3000 -s " + map[bool]string{true: out.Sub, false: "myapp"}[out.Sub != ""])
	return 0
}

// deriveProxyURL maps the control address (host:7001) to the proxy base URL.
// A managed server is behind Caddy on 443, so the public domain gets https;
// a localhost server is reached directly on :8080.
func deriveProxyURL(serverAddr string) string {
	host := serverAddr
	if h, _, err := net.SplitHostPort(serverAddr); err == nil {
		host = h
	}
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return "http://localhost:8080"
	default:
		return "https://" + host
	}
}

// updateConfigToken rewrites ~/.munnel/config (or $MUNNEL_CONFIG) with the
// new token, preserving all other lines. The file is written with mode 600.
func updateConfigToken(tok string) error {
	path := os.Getenv("MUNNEL_CONFIG")
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		path = filepath.Join(home, ".munnel", "config")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}

	existing, _ := os.ReadFile(path)
	var lines []string
	replaced := false
	for _, line := range strings.Split(string(existing), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			if k, _, ok := strings.Cut(trimmed, "="); ok && strings.EqualFold(strings.TrimSpace(k), "token") {
				if !replaced {
					lines = append(lines, "token="+tok)
					replaced = true
				}
				continue // drop duplicate token lines
			}
		}
		lines = append(lines, line)
	}
	if !replaced {
		lines = append(lines, "token="+tok)
	}
	out := strings.Join(lines, "\n")
	// Ensure a single trailing newline.
	out = strings.TrimRight(out, "\n") + "\n"
	return os.WriteFile(path, []byte(out), 0o600)
}

func tokenUsage(w *os.File) {
	fmt.Fprint(w, `munnel token — acquire a tunnel token (self-service)

usage:
  munnel token --sub <name> [flags]

flags:
  --sub <name>         subdomain to scope the token to (empty = any free subdomain)
  --ttl <duration>     token lifetime (default "168h"; server caps at 720h)
  --password <pw>      enrollment password (or MUNNEL_ENROLL_PASSWORD; prompted if unset)
  --server <host:port> control server address (default from ~/.munnel/config)
  --server-url <url>   proxy base URL (default: https://<server-host>, or http://localhost:8080)
  -h, --help           show this help

the acquired token is saved to ~/.munnel/config and used automatically by
`+"`munnel <port>`"+`. when it expires, re-run this command.

examples:
  munnel token --sub alice          # token scoped to alice.<domain>
  munnel token                      # token for any free subdomain
`)
}

func usage(w *os.File) {
	fmt.Fprint(w, `munnel — expose localhost to the public internet

usage:
  munnel <port> [flags]
  munnel token --sub <name>   acquire a token (saved to ~/.munnel/config)

flags:
  -s, --subdomain <name>    request a specific subdomain
  -t, --token <token>       auth token for protected servers
      --server <host:port>  control server address          (default "localhost:7001", port 7001 assumed; 7002 with --tls)
      --tls                 connect to the server's TLS control port (verifies the certificate)
      --server-cert-sha256 <hex>  pin the server certificate (SHA-256 of its DER); needs --tls
      --local-host <host>   local service host              (default "127.0.0.1")
      --inspect             run the web inspector           (default true)
      --inspect-addr <addr> inspector listen address        (default "127.0.0.1:4040")
      --max-body-mb <n>     max request body in megabytes   (default 32)
      --protect             require viewer login (forward-auth) on this tunnel
  -v, --version             print version
  -h, --help                show this help

defaults:
  every flag above can be set in ~/.munnel/config (KEY=VAL, one per line) or
  via MUNNEL_* env vars (MUNNEL_SERVER, MUNNEL_TOKEN, MUNNEL_SUBDOMAIN,
  MUNNEL_INSPECT_ADDR, MUNNEL_LOCAL_HOST, MUNNEL_MAX_BODY_MB, MUNNEL_INSPECT,
  MUNNEL_TLS, MUNNEL_SERVER_CERT_SHA256).
  precedence: flag > env > config file > builtin default.

examples:
  munnel 3000                       # random subdomain, defaults from config
  munnel 3000 -s myapp              # claim myapp.<domain>
  munnel 8080 -s myapp -t token --server tunnels.example.com:7001
  munnel 3000 -s myapp --tls --server tunnels.example.com:7002
`)
}
