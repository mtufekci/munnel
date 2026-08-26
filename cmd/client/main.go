// Command munnel exposes a local port through a munnel server.
//
//	munnel 3000                        expose localhost:3000
//	munnel 3000 -s myapp              claim a subdomain
//	munnel 3000 -t TOKEN --server tunnels.example.com:7001
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/mtufekci/munnel/internal/client"
	"github.com/mtufekci/munnel/internal/inspection"
	"github.com/mtufekci/munnel/internal/tui"
)

var version = "dev"

type stringFlags struct{ subdomain, token, server, inspectAddr, localHost string }

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(argv []string) int {
	sf := &stringFlags{server: "localhost:7001", inspectAddr: ":4040", localHost: "127.0.0.1"}
	var inspectSet, inspectVal bool
	var maxBodyMB int
	var maxBodySet bool
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

	cfg := client.Config{
		LocalPort:   port,
		LocalHost:   sf.localHost,
		ServerAddr:  sf.server,
		Subdomain:   sf.subdomain,
		Token:       sf.token,
		Inspect:     inspectOn,
		InspectAddr: sf.inspectAddr,
		MaxBody:     32 << 20,
	}
	if maxBodySet && maxBodyMB > 0 {
		cfg.MaxBody = int64(maxBodyMB) << 20
	}
	if cfg.InspectAddr == "" {
		cfg.InspectAddr = ":4040"
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
		display := cfg.InspectAddr
		switch {
		case strings.HasPrefix(display, ":"):
			display = "127.0.0.1" + display
		case strings.HasPrefix(display, "0.0.0.0:"):
			display = "127.0.0.1:" + strings.TrimPrefix(display, "0.0.0.0:")
		}
		inspectURL = "http://" + display
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
				fmt.Printf("%-7s %-40s %s %4dms\n", r.Method, r.Path, status, r.Duration)
			}
		case client.EventShuttingDown:
			fmt.Println("shutdown")
			return 0
		}
	}
	<-ctx.Done()
	return 0
}

func usage(w *os.File) {
	fmt.Fprint(w, `munnel — expose localhost to the public internet

usage:
  munnel <port> [flags]

flags:
  -s, --subdomain <name>    request a specific subdomain
  -t, --token <token>       auth token for protected servers
      --server <host:port>  control server address          (default "localhost:7001", port 7001 assumed)
      --local-host <host>   local service host              (default "127.0.0.1")
      --inspect             run the web inspector           (default true)
      --inspect-addr <addr> inspector listen address        (default ":4040")
      --max-body-mb <n>     max request body in megabytes   (default 32)
  -v, --version             print version
  -h, --help                show this help

defaults:
  every flag above can be set in ~/.munnel/config (KEY=VAL, one per line) or
  via MUNNEL_* env vars (MUNNEL_SERVER, MUNNEL_TOKEN, MUNNEL_SUBDOMAIN,
  MUNNEL_INSPECT_ADDR, MUNNEL_LOCAL_HOST, MUNNEL_MAX_BODY_MB, MUNNEL_INSPECT).
  precedence: flag > env > config file > builtin default.

examples:
  munnel 3000                       # random subdomain, defaults from config
  munnel 3000 -s myapp              # claim myapp.<domain>
  munnel 8080 -s myapp -t token --server tunnels.example.com:7001
`)
}
