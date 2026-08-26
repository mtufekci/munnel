// Command munnel-server is the public tunnel endpoint: it accepts client
// control connections on one port and public HTTP traffic on another,
// routing subdomains into their tunnels.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/mtufekci/munnel/internal/server"
	"github.com/mtufekci/munnel/internal/token"
)

var version = "dev"

func main() {
	os.Exit(run())
}

func run() int {
	// Subcommand: munnel-server mint — mint a signed, scoped token.
	if len(os.Args) > 1 && os.Args[1] == "mint" {
		return runMint(os.Args[2:])
	}

	fs := flag.NewFlagSet("munnel-server", flag.ExitOnError)
	fs.SetOutput(os.Stderr)
	domain := fs.String("domain", "localhost", "base domain for tunnel routing")
	controlAddr := fs.String("control-addr", ":7001", "listen address for control/multiplexing")
	proxyAddr := fs.String("proxy-addr", ":8080", "listen address for public HTTP ingress")
	authTokens := fs.String("auth-tokens", "", "comma-separated list of valid static client tokens")
	authFile := fs.String("auth-file", "", "JSON file mapping tokens to reserved subdomains")
	signingKeyFile := fs.String("signing-key-file", "", "file containing the HMAC key for signed, scoped tokens (or $MUNNEL_SIGNING_KEY)")
	revokedFile := fs.String("revoked-file", "", "file of revoked signed-token IDs (one per line); reload requires restart")
	scheme := fs.String("public-scheme", "http", "scheme in generated URLs (use \"https\" behind a TLS proxy like Caddy)")
	publicPort := fs.String("public-port", "", "port in generated URLs (defaults to the proxy port; set \"443\" behind a TLS proxy)")
	maxBodyMB := fs.Int("max-body-mb", 32, "max request body in megabytes")
	showVersion := fs.Bool("version", false, "print version")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `munnel-server — self-hosted tunnel server

usage:
  munnel-server [flags]
  munnel-server mint --sub <name> [--ttl 24h] [--key-file <path>]

flags:
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

	signingKey, err := loadSigningKey(*signingKeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "munnel-server: %v\n", err)
		return 2
	}

	auth, err := server.NewAuthenticatorWith(server.AuthOptions{
		Tokens:      *authTokens,
		AuthFile:    *authFile,
		SigningKey:  signingKey,
		RevokedFile: *revokedFile,
	})
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

// loadSigningKey resolves the HMAC key from --signing-key-file or
// $MUNNEL_SIGNING_KEY. Returns nil (signed tokens disabled) if neither is set.
func loadSigningKey(path string) ([]byte, error) {
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("signing key file: %w", err)
		}
		k := strings.TrimSpace(string(b))
		if k == "" {
			return nil, errors.New("signing key file is empty")
		}
		return []byte(k), nil
	}
	if v := strings.TrimSpace(os.Getenv("MUNNEL_SIGNING_KEY")); v != "" {
		return []byte(v), nil
	}
	return nil, nil
}

// runMint implements `munnel-server mint`: signs a scoped token and prints it
// (plus its ID, for the revoke list) to stdout.
func runMint(args []string) int {
	fs := flag.NewFlagSet("munnel-server mint", flag.ExitOnError)
	fs.SetOutput(os.Stderr)
	sub := fs.String("sub", "", "subdomain this token is scoped to (empty = any free subdomain)")
	ttl := fs.Duration("ttl", 0, "token lifetime (e.g. 24h, 7d); 0 = never expires")
	keyFile := fs.String("key-file", "", "file containing the HMAC signing key (or $MUNNEL_SIGNING_KEY)")
	_ = fs.Parse(args)

	key, err := loadSigningKey(*keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mint: %v\n", err)
		return 2
	}
	if key == nil {
		fmt.Fprintln(os.Stderr, "mint: no signing key — pass --key-file <path> or set $MUNNEL_SIGNING_KEY")
		return 2
	}

	tok, err := token.Mint(key, *sub, *ttl)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mint: %v\n", err)
		return 1
	}
	id := token.IDOf(tok)
	fmt.Printf("token: %s\n", id)
	fmt.Println(tok)
	if *ttl > 0 {
		fmt.Printf("expires: %s\n", time.Now().Add(*ttl).UTC().Format(time.RFC3339))
	} else {
		fmt.Println("expires: never")
	}
	fmt.Println("\nTo revoke, add the token id above to --revoked-file and restart.")
	return 0
}