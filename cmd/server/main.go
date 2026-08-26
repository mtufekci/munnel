// Command munnel-server is the public tunnel endpoint: it accepts client
// control connections on one port and public HTTP traffic on another,
// routing subdomains into their tunnels.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/mtufekci/munnel/internal/server"
)

var version = "dev"

func main() {
	os.Exit(run())
}

func run() int {
	fs := flag.NewFlagSet("munnel-server", flag.ExitOnError)
	fs.SetOutput(os.Stderr)
	domain := fs.String("domain", "localhost", "base domain for tunnel routing")
	controlAddr := fs.String("control-addr", ":7001", "listen address for control/multiplexing")
	proxyAddr := fs.String("proxy-addr", ":8080", "listen address for public HTTP ingress")
	authTokens := fs.String("auth-tokens", "", "comma-separated list of valid client tokens")
	authFile := fs.String("auth-file", "", "JSON file mapping tokens to reserved subdomains")
	scheme := fs.String("public-scheme", "http", "scheme in generated URLs (use \"https\" behind a TLS proxy like Caddy)")
	publicPort := fs.String("public-port", "", "port in generated URLs (defaults to the proxy port; set \"443\" behind a TLS proxy)")
	maxBodyMB := fs.Int("max-body-mb", 32, "max request body in megabytes")
	showVersion := fs.Bool("version", false, "print version")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `munnel-server — self-hosted tunnel server

usage:
  munnel-server [flags]

`)
		fs.PrintDefaults()
	}
	_ = fs.Parse(os.Args[1:])

	if *showVersion {
		fmt.Printf("munnel-server %s\n", version)
		return 0
	}
	if *scheme != "http" && *scheme != "https" {
		fmt.Fprintln(os.Stderr, "--public-scheme must be http or https")
		return 2
	}

	auth, err := server.NewAuthenticator(*authTokens, *authFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "munnel-server: %v\n", err)
		return 2
	}

	srv, err := server.New(server.Config{
		Domain:         *domain,
		ControlAddr:    *controlAddr,
		ProxyAddr:      *proxyAddr,
		PublicPort:     *publicPort,
		PublicScheme:   *scheme,
		MaxRequestBody: int64(*maxBodyMB) << 20,
		Auth:           auth,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "munnel-server: %v\n", err)
		return 2
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := srv.ListenAndServe(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "munnel-server: %v\n", err)
		return 1
	}
	return 0
}
