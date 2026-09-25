// Command munnel-server is the public tunnel endpoint: it accepts client
// control connections on one port and public HTTP traffic on another,
// routing subdomains into their tunnels.
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/mtufekci/munnel/internal/forwardauth"
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
	controlAddr := fs.String("control-addr", ":7001", "listen address for control/multiplexing (plaintext)")
	controlTLSAddr := fs.String("control-tls-addr", ":7002", "listen address for the TLS control port (runs only with --tls-cert-file/--tls-key-file)")
	tlsCertFile := fs.String("tls-cert-file", "", "PEM certificate for the TLS control port (e.g. Caddy's certificate for --domain); reloaded when it changes")
	tlsKeyFile := fs.String("tls-key-file", "", "PEM private key for --tls-cert-file")
	proxyAddr := fs.String("proxy-addr", ":8080", "listen address for public HTTP ingress")
	authTokens := fs.String("auth-tokens", "", "comma-separated list of valid static client tokens")
	authFile := fs.String("auth-file", "", "JSON file mapping tokens to reserved subdomains")
	signingKeyFile := fs.String("signing-key-file", "", "file containing the HMAC key for signed, scoped tokens (or $MUNNEL_SIGNING_KEY)")
	revokedFile := fs.String("revoked-file", "", "file of revoked signed-token IDs (one per line); reload requires restart")
	reservedFile := fs.String("reserved-file", "", "file of reserved names, one \"name tokenID[,tokenID...]\" per line (or $MUNNEL_RESERVED, entries separated by ';'); reserved names are claimable only by those signed tokens and only over TLS; reload requires restart")
	authStub := fs.Bool("auth-stub", false, "enable the stub forward-auth provider (dev/test only — trusts any user; do NOT use in production)")
	sessionKeyFile := fs.String("session-key-file", "", "file with the HMAC key for forward-auth session cookies (or $MUNNEL_SESSION_KEY; ephemeral if unset with --auth-stub)")
	enrollPassword := fs.String("enroll-password", "", "password gating self-service token issuance via POST /__munnel/token (or $MUNNEL_ENROLL_PASSWORD)")
	scheme := fs.String("public-scheme", "http", "scheme in generated URLs (use \"https\" behind a TLS proxy like Caddy)")
	publicPort := fs.String("public-port", "", "port in generated URLs (defaults to the proxy port; set \"443\" behind a TLS proxy)")
	maxBodyMB := fs.Int("max-body-mb", 32, "max request body in megabytes")
	showVersion := fs.Bool("version", false, "print version")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `munnel-server — self-hosted tunnel server

usage:
  munnel-server [flags]
  munnel-server mint --sub <name> [--ttl 24h] [--key-file <path>] [--protect]

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

	// Reserved names: --reserved-file wins, else $MUNNEL_RESERVED (handy in a
	// docker .env, which redeploys preserve).
	reservedInline := ""
	if *reservedFile == "" {
		reservedInline = strings.TrimSpace(os.Getenv("MUNNEL_RESERVED"))
	}
	auth, err := server.NewAuthenticatorWith(server.AuthOptions{
		Tokens:       *authTokens,
		AuthFile:     *authFile,
		SigningKey:   signingKey,
		RevokedFile:  *revokedFile,
		ReservedFile: *reservedFile,
		Reserved:     reservedInline,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "munnel-server: %v\n", err)
		return 2
	}

	// TLS control port: on when a certificate is configured. A certificate
	// that cannot be loaded yet (Caddy may still be obtaining it) is only a
	// warning; the listener retries on every handshake.
	var controlTLS *tls.Config
	switch {
	case (*tlsCertFile == "") != (*tlsKeyFile == ""):
		fmt.Fprintln(os.Stderr, "munnel-server: --tls-cert-file and --tls-key-file go together")
		return 2
	case *tlsCertFile != "" && *controlTLSAddr != "":
		cf, err := server.NewCertFile(*tlsCertFile, *tlsKeyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: control TLS certificate not loaded yet (%v); TLS handshakes fail until it is\n", err)
		}
		controlTLS = &tls.Config{GetCertificate: cf.GetCertificate, MinVersion: tls.VersionTLS12}
	}

	// Forward-auth: only the stub provider is wired here (dev/test). A real
	// OIDC provider is a future flag; the forwardauth.Manager is left nil
	// (disabled) unless --auth-stub is set.
	var fa *forwardauth.Manager
	if *authStub {
		sessKey, err := loadSessionKey(*sessionKeyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "munnel-server: %v\n", err)
			return 2
		}
		fa = forwardauth.NewManager(sessKey, forwardauth.StubProvider{}, 7*24*time.Hour)
		fmt.Fprintln(os.Stderr, "warning: --auth-stub trusts any submitted user — dev/test only, not for production")
	}

	// Self-service token issuance: --enroll-password flag wins, else env.
	enrollPW := *enrollPassword
	if enrollPW == "" {
		enrollPW = strings.TrimSpace(os.Getenv("MUNNEL_ENROLL_PASSWORD"))
	}

	srv, err := server.New(server.Config{
		Domain:         *domain,
		ControlAddr:    *controlAddr,
		ControlTLSAddr: *controlTLSAddr,
		ControlTLS:     controlTLS,
		ProxyAddr:      *proxyAddr,
		PublicPort:     *publicPort,
		PublicScheme:   *scheme,
		MaxRequestBody: int64(*maxBodyMB) << 20,
		Auth:           auth,
		FA:             fa,
		EnrollPassword: enrollPW,
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

// loadSessionKey resolves the forward-auth session key from --session-key-file
// or $MUNNEL_SESSION_KEY. If neither is set it generates an ephemeral key (so
// --auth-stub works out of the box for dev), with the caveat that sessions do
// not survive a restart.
func loadSessionKey(path string) ([]byte, error) {
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("session key file: %w", err)
		}
		k := strings.TrimSpace(string(b))
		if k == "" {
			return nil, errors.New("session key file is empty")
		}
		return []byte(k), nil
	}
	if v := strings.TrimSpace(os.Getenv("MUNNEL_SESSION_KEY")); v != "" {
		return []byte(v), nil
	}
	// Ephemeral key: fine for dev/test, but sessions are lost on restart.
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("generate session key: %w", err)
	}
	fmt.Fprintln(os.Stderr, "warning: no --session-key-file set; using an ephemeral session key (sessions will not survive restart)")
	return []byte(hex.EncodeToString(b)), nil
}

// runMint implements `munnel-server mint`: signs a scoped token and prints it
// (plus its ID, for the revoke list) to stdout.
func runMint(args []string) int {
	fs := flag.NewFlagSet("munnel-server mint", flag.ExitOnError)
	fs.SetOutput(os.Stderr)
	sub := fs.String("sub", "", "subdomain this token is scoped to (empty = any free subdomain)")
	ttl := fs.Duration("ttl", 0, "token lifetime (e.g. 24h, 7d); 0 = never expires")
	prot := fs.Bool("protect", false, "mandate forward-auth on the tunnel this token opens")
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

	tok, err := token.MintWith(key, token.MintOpts{Sub: *sub, TTL: *ttl, Prot: *prot})
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
	if *prot {
		fmt.Println("protect: forward-auth mandated on this tunnel")
	}
	fmt.Println("\nTo revoke, add the token id above to --revoked-file and restart.")
	if *sub != "" {
		fmt.Printf("To reserve %q for this token only (TLS only), add \"%s %s\" to --reserved-file and restart.\n", *sub, *sub, id)
	}
	return 0
}
