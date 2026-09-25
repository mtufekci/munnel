# AGENTS.md — orientation for AI agents working on munnel

> Read this first. It tells you how the codebase is laid out, how to build/test/run
> it, where things live, and the conventions to follow. If you're about to change
> something, the section you need is probably already here.

## TL;DR

munnel is a self-hosted ngrok-like tunneling engine. A **client** running on a
developer's machine dials a **server** in the cloud; the server maps a public
subdomain (`https://myapp.tunnels.example.com`) to the client's local port
(`localhost:3000`). A custom 9-byte-binary multiplexer carries HTTP traffic and
control frames over a single TCP socket. Caddy fronts the server with TLS.

```
browser → Caddy :443 (TLS) → munnel-server :8080 (ingress) ─ mux ─ :7001 (or TLS :7002) → client → localhost:3000
                                                                    │
                              Caddy on-demand TLS ← ask http://ask:8080/check ← approve.py (token gate)
```

## Build, test, run

Go 1.25+. No local Go? Everything below also works through Docker.

```sh
# Build (client + server)
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/munnel ./cmd/client
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/munnel-server ./cmd/server

# Tests — ALWAYS with -race. cgo is required for -race.
go test -race ./...

# Run a server locally (dev)
go run ./cmd/server --domain localhost --public-port 443

# Run a client locally (dev)
go run ./cmd/client 3000 -s myapp --server localhost:7001
```

If you have Docker but no Go toolchain, use the alpine image (the `-race`
suite needs `gcc` + `musl-dev`):

```sh
docker run --rm -v "$PWD":/src -w /src golang:1.25-alpine sh -c \
  'apk add --no-cache gcc musl-dev && go test -race ./...'
```

The one-command dev setup for end users is `install-dev.sh` (builds the client,
writes `~/.munnel/config`). Operators deploy the server with the scripts under
`deploy/` — see [deploy/README.md](deploy/README.md).

## Repository map

```
cmd/
  client/         # munnel CLI (the tunnel client devs run)
    main.go       # flag parsing, default loading, event loop, signal handling
    defaults.go   # ~/.munnel/config + MUNNEL_* env defaults (flag > env > config > builtin)
    defaults_test.go
  server/         # munnel-server CLI
    main.go       # flags, config, wires ingress+mux+approval
internal/
  client/
    tunnel.go     # Tunnel: connect/Run/Events; ctx-watcher shutdown; mutex-guarded emit
  server/
    control.go    # server-side mux: sessions, subdomain routing, frame dispatch
    ingress.go    # HTTP ingress listener (behind Caddy on 443)
  mux/
    *.go          # 9-byte-binary multiplexer protocol (frame codec, streams)
  inspection/
    server.go     # inspection web UI (127.0.0.1:4040) — Host allowlist + per-launch token; replay
  token/
    token.go      # signed, scoped tunnel tokens (HMAC-SHA256); Mint/Parse/IDOf
  forwardauth/
    forwardauth.go # zero-trust: session cookies, identity header injection, login flow
integration/
  shutdown_test.go # regression tests: real in-process server+client, ctx shutdown
  websocket_test.go # WebSocket tunnel end-to-end (hijack → raw pipe)
  token_auth_test.go # signed + static token auth, scoped subdomains
  forwardauth_test.go # protected tunnels: redirect, login flow, header injection, spoof stripping
  tls_test.go      # TLS control port, cert pin, reserved names (TLS-only, enrollment refusal)
  liveness_test.go # dead peer, same-token takeover, 504 header timeout, viewer disconnect closes local SSE
  handshake_test.go # hello/ack line framing at 64/128/256…-byte boundaries
  inspector_test.go # inspector Host/Origin allowlist + token
docs/
  OPERATIONS.md   # operator runbook: deploy, SSH, logs, token rotation, hardening, teardown
deploy/
  README.md       # cross-provider deploy guide
  cloud-init.yaml # portable user-data (Docker + .env + systemd unit)
  lib.sh          # shared deploy helpers (render_user_data, wait_ssh, ship_and_start)
  azure/          # Bicep + deploy.sh
  aws/            # CloudFormation + deploy.sh
  hetzner/        # deploy.sh (hcloud)
  digitalocean/   # deploy.sh (doctl)
  gcp/            # deploy.sh (gcloud)
.github/
  workflows/deploy-server.yml  # manual workflow_dispatch: test on ubuntu-latest, deploy via self-hosted runner on the VM
Caddyfile.example # on-demand TLS with ask http://ask:8080/check
docker-compose.yml# munnel-server + Caddy + approve (built from source, no registry)
Dockerfile        # golang:1.25 → server binary
approve.py        # Caddy ask endpoint: gates on-demand TLS by token+subdomain
install.sh        # end-user: build+install client/server from source
install-dev.sh    # dev: build client, write ~/.munnel/config (token via --token)
```

## Architecture notes agents must not break

- **Multiplexer protocol** (`internal/mux`): a custom 9-byte binary header per
  frame. Do **not** "simplify" to text/JSON without rewriting both ends — the
  binary header is load-bearing for framing over a raw TCP socket. Any change
  to the wire format is a breaking client/server co-change.
- **Shutdown order** (`internal/client/tunnel.go`): `connectOnce` has a
  ctx-watcher goroutine that closes the socket on `ctx.Done()` so `sess.Run()`
  unblocks. `Run` defers `shutdown()` which sets `closed=true` and closes the
  events channel. `emit` is mutex-guarded and no-ops once `closed`. If you touch
  shutdown, re-run `integration/shutdown_test.go` with `-race` — these tests
  were verified to **fail** with the fix reverted, so they will catch regressions.
- **Precedence**: flag > env (`MUNNEL_*`) > config file (`~/.munnel/config`) >
  builtin. `applyDefaults` runs *before* flag parsing so explicit flags still win.
  See `cmd/client/defaults.go` + `defaults_test.go`.
- **On-demand TLS gate**: Caddy calls `ask http://ask:8080/check` before issuing
  any subdomain cert. `approve.py` approves only subdomains with a connected,
  token-valid tunnel. Without this, anyone could mint certs for your domain.
- **Two token kinds, one Authenticator**: static tokens (CSV/JSON, server holds
  the list) and signed tokens (HMAC-SHA256, package `token`, self-describing
  subdomain + expiry). A token starting with `m1.` is signed; anything else is
  treated as static. They coexist — don't make one path exclude the other. A
  signed token's `sub` claim overrides the client's requested subdomain (same
  as a static reserved token), so scoping is enforced by assignment, not
  rejection. Revocation is by token ID in `--revoked-file`, loaded once at
  startup. `munnel-server mint` signs tokens; the signing key never leaves the
  server.
- **`--public-port`**: the server reports `https://<sub>.<domain>` (not `:8080`)
  because it runs behind Caddy on 443. Don't remove this flag or client URLs
  will show an internal port.
- **WebSocket upgrades** take a separate code path from normal HTTP. In
  `proxy.go`, `isUpgrade(r)` routes to `proxyWebSocket`, which hijacks the
  public TCP conn and `io.Copy`s it bidirectionally against a mux stream. On
  the client side, `forwarder.go`'s `Serve` branches to `serveWebSocket`,
  which dials the local service as raw TCP and pipes the same way. The
  hop-by-hop header stripping the HTTP path does **must not** run here —
  `Upgrade`/`Connection`/`Sec-WebSocket-*` are load-bearing for the handshake.
  Regression test: `integration/websocket_test.go` (verified to fail with
  `status=501` when the hijack path is removed).
- **Forward-auth / zero-trust** (`internal/forwardauth`): a tunnel is protected
  when the client passes `--protect` **or** its signed token carries `prot:true`
  (minted with `munnel-server mint --protect`). A protected tunnel requires a
  viewer session before any request reaches the local service. The server's
  `ServeHTTP` (in `proxy.go`) handles the `/__munnel/` login/auth/logout paths
  on the subdomain host, **always** strips `X-Authenticated-User` /
  `X-Authenticated-Groups` from incoming requests (so viewers can't spoof them),
  then calls `Authorize` which validates the session cookie and injects the
  identity headers on success. The session cookie is HMAC-signed (`s1.` prefix,
  same family as signed tokens) and scoped to the tunnel subdomain. The only
  wired provider is `StubProvider` (gated behind `--auth-stub`, dev/test only —
  it trusts any submitted user); a real OIDC provider implements the
  `forwardauth.Provider` interface. A protected tunnel on a server with no auth
  provider enabled is **rejected at handshake** in `control.go`. Regression
  tests: `internal/forwardauth/forwardauth_test.go` (unit) and
  `integration/forwardauth_test.go` (end-to-end; verified to fail when the FA
  block in `proxy.go` is removed).

- **Handshake framing** (`proto.ReadMessage`/`WriteMessage`): hello and ack
  are single JSON lines, and the same `bufio.Reader` is then handed to the mux.
  Never parse them with `json.Decoder`: it may read past the newline or stop
  before it (Go 1.27 does so for 64/128/256…-byte messages), shifting every
  frame by a byte. `integration/handshake_test.go` covers the boundaries.
- **TLS control port + reserved names**: `--control-tls-addr` (:7002) runs
  beside plaintext :7001 once `--tls-cert-file/--tls-key-file` are set
  (`CertFile` re-reads them on change). `handleControlConn(conn, overTLS)`
  enforces `Authenticator.CheckReserved`: a reserved name only for its listed
  signed-token IDs and only over TLS. The plaintext refusal carries
  `proto.CodeTLSRequired` in the ack and the client stops reconnecting (a
  retry would resend the token in the clear). `/__munnel/token` refuses
  reserved subs. The server registers a client before writing the ack, so
  proxies wait on `Client.waitReady` (no frame may precede the ack line).
- **Liveness and aborts** (`internal/mux`): pongs are sent by the heartbeat
  goroutine, never the read loop; the watchdog closes a session after
  `IdleTimeout` (45 s) without any received byte (the session's reader marks
  every read, so a 1 MiB frame arriving slowly counts), except while the read
  loop itself is stalled on a slow stream reader. Silence is measured on the
  monotonic clock (offsets from `Session.epoch`), never the wall clock.
  `Stream.Abort` sends RESET even after CloseWrite and closes `Aborted()`.
  `proxyTo` aborts on `r.Context().Done()` and before closing an unfinished
  body (Close would drain an endless SSE body); the client forwarder cancels
  the local request on `Aborted()`. A reconnect with the same signed-token
  ID takes over its name only from a `Session.Stale()` holder (nothing
  received for 1.5 ping intervals); a live holder refuses it as "in use", so
  a sniffed plaintext token cannot evict a live tunnel (`Registry.Register`
  returns the evicted client).

## Conventions

- **Go module path**: `github.com/mtufekci/munnel`. Import paths follow.
- **Tests are real, not coverage-satisfiers.** Prefer an in-process server+client
  over mocking internals. If a test would pass even with the code broken, delete
  or rewrite it. Run `go test -race ./...` before claiming anything works.
- **No secrets in the repo.** Tokens go in `.env` (gitignored) or are passed via
  `--token` / `MUNNEL_TOKEN`. Never hardcode a token in a script or doc; use
  `<TOKEN>` placeholders in docs and example files.
- **Shell scripts are POSIX `sh`** (not bash) so they run on Alpine/minimal VMs.
  Quote variables, avoid bashisms (`[[ ]]`, arrays, `==`).
- **Deploy scripts are idempotent** — re-running must redeploy without
  duplicating resources or clobbering the cloud-init-written `.env`.
- **Docs are the source of truth for ops**: `docs/OPERATIONS.md` for the runbook,
  `deploy/README.md` for provisioning, this file for code orientation. Keep them
  in sync with the code.

## Where to make common changes

| You want to… | Touch this | Verify with |
|--------------|-----------|-------------|
| Add a client flag | `cmd/client/main.go` (+ `defaults.go` if it should have a config/env default) | `cmd/client/defaults_test.go`, build client |
| Change the mux wire format | `internal/mux/*.go` (both ends) | `go test -race ./internal/mux/... ./integration/...` |
| Change server routing | `internal/server/control.go` | `integration/shutdown_test.go` + a manual round-trip |
| Change token/auth logic | `internal/server/auth.go` + `internal/token/token.go` | `internal/token/token_test.go` + `integration/token_auth_test.go` |
| Change forward-auth | `internal/forwardauth/forwardauth.go` + `proxy.go` ServeHTTP | `internal/forwardauth/forwardauth_test.go` + `integration/forwardauth_test.go` |
| Add a cloud provider | new `deploy/<provider>/deploy.sh` sourcing `deploy/lib.sh` + an IaC file | dry-run the provision, then a real deploy |
| Change the CI deploy | `.github/workflows/deploy-server.yml` (manual `workflow_dispatch`) | trigger it from the Actions tab after pushing |
| Rotate the dev token | on the VM: `docs/OPERATIONS.md` § token rotation | client reconnects with the new token |
| Add an inspection feature | `internal/inspection/server.go` (every route goes through `guard`) | `integration/inspector_test.go` + `integration/e2e_test.go` |

## Things that look wrong but aren't

- **`Caddyfile.example` references `{$MUNNEL_DOMAIN}`** — that's Caddy's env-var
  substitution, read from `.env` at container start. It's not a Go template.
- **`docker-compose.yml` has no published image** — it builds from the repo's
  `Dockerfile`. That's intentional: no registry dependency, private repo.
- **The scp-based deploy** — the repo is private, so the VM can't `git clone`.
  `ship_and_start` scp's the source instead. See `deploy/README.md` § "Why scp".
- **`install-dev.sh` doesn't hardcode the token** — it requires `--token` /
  `MUNNEL_TOKEN`. This is a security constraint, not an oversight.