# munnel

a lightweight self-hosted tunneling engine, binary multiplexer, and real-time
request inspection suite. no ngrok accounts, no rate limits, no third-party
cloud lock-in. expose localhost to the public internet instantly.

inspired by [tunneru](https://github.com/pranav718/tunneru), built in the same
spirit: your server, your domain, your tokens.

---

## contents

- [features](#features)
- [architecture](#architecture)
- [quickstart](#quickstart)
  - [1. build](#1-build)
  - [2. run the server](#2-run-the-server)
  - [3. expose a local port](#3-expose-a-local-port)
  - [4. subdomains and token auth](#4-subdomains-and-token-auth)
- [CLI reference](#cli-reference)
- [request inspector](#request-inspector)
- [self-hosting in production](#self-hosting-in-production)
- [managed Azure deployment](#managed-azure-deployment)
- [how multiplexing works](#how-multiplexing-works)
  - [websocket and upgrade tunnels](#websocket-and-upgrade-tunnels)
- [limitations](#limitations)
- [project structure](#project-structure)

---

## features

**custom 9-byte binary multiplexer**

- stream multiplexing over a single persistent TCP connection
- compact 9-byte binary frame header (1-byte type, 4-byte stream id, 4-byte length)
- big payloads are chunked transparently into 1 MiB frames
- ping/pong keepalives ride the same framing

**terminal TUI and live telemetry**

- interactive dashboard (bubble tea) with connection status, uptime, request counts
- live request stream: method, path, status code, latency — right in your shell

![terminal TUI](docs/images/terminal-tui.png)

**web request inspector**

- dark single-page inspector on `localhost:4040`, served by the client itself
- full request/response inspection: headers, bodies, syntax-highlighted JSON
- one-click **replay**: re-dispatch any captured request to localhost without
  re-triggering the external provider (webhooks from stripe, github, shopify, …)
- websocket live feed — new traffic appears instantly

**security and routing**

- claim predictable subdomains with `-s/--subdomain`
- optional shared token auth (`--auth-tokens`) and per-token reserved subdomains (`--auth-file`)
- HMAC-signed scoped tokens with expiry + revocation (no server-side token list)
- **zero-trust tunnels** — `--protect` requires viewer login; munnel injects a
  trusted `X-Authenticated-User` header the local service can rely on
- 100 % self-hosted; no external telemetry

---

## architecture

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/diagrams/architecture-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="docs/diagrams/architecture-light.png">
  <img alt="munnel tunnel architecture: visitor → munnel-server (public internet) → munnel client → forwarder → your app + inspector (your machine)" src="docs/diagrams/architecture-dark.png">
</picture>

**[interactive version](docs/diagrams/munnel-architecture.html)** — pan/zoom, focus, dark & light themes

one TCP connection per tunnel carries every request concurrently. the server
parses each public HTTP request, opens a mux stream, writes the request in
HTTP/1.1 wire format, and reads the response the client relayed back from
localhost.

---

## quickstart

### 1. build

```bash
git clone https://github.com/mtufekci/munnel && cd munnel
make build          # → bin/munnel, bin/munnel-server
```

or client-only install:

```bash
./install.sh --client-only
```

### 2. run the server

any linux VPS works (hetzner, digitalocean, fly.io, aws). minimal:

```bash
./bin/munnel-server --domain tunnels.example.com
```

### 3. expose a local port

start your dev server (next.js, rails, fastapi, express — anything HTTP) on
port 3000, then:

```bash
./bin/munnel 3000 --server tunnels.example.com:7001
```

munnel connects, claims a random public URL
(`https://a1b2c3.tunnels.example.com`), opens the TUI, and starts the
inspector on <http://localhost:4040>.

> **using a managed server?** if an operator runs munnel for you, run
> `./install-dev.sh --token <TOKEN>` once — it builds & installs the client on
> your PATH and writes `~/.munnel/config` with the server + token. after that
> you only ever type `munnel 3000 -s myapp`.

### 4. subdomains and token auth

```bash
munnel 3000 -s myapp                                   # → myapp.tunnels.example.com
munnel 3000 -s myapp -t secrettoken123 --server tunnels.example.com:7001
munnel 3000 --inspect=false                            # headless mode
```

server side, restrict who may connect:

```bash
munnel-server --domain tunnels.example.com --auth-tokens secrettoken123,friendtoken456
```

or bind tokens to reserved subdomains with an auth file:

```json
// auth.json — {"token": "reserved subdomain"}
{ "secrettoken123": "myapp", "friendtoken456": "friends-app" }
```

```bash
munnel-server --domain tunnels.example.com --auth-file auth.json
```

#### signed, scoped tokens

for per-developer tokens with expiry and revocation — without the server
holding a list of every token — use HMAC-signed tokens. generate a signing
key once, mint tokens for each dev, and revoke by id:

```bash
# 1. generate a signing key (once)
openssl rand -hex 32 > signing.key

# 2. mint a token scoped to the "alice" subdomain, valid 24h
munnel-server mint --sub alice --ttl 24h --key-file signing.key
#   token: tok_a1b2c3d4e5f6a7b8
#   m1.<payload>.<signature>
#   expires: 2026-08-27T15:40:00Z

# 3. run the server with the signing key (+ optional revocation list)
munnel-server --domain tunnels.example.com \
  --signing-key-file signing.key --revoked-file revoked.txt

# 4. the dev connects with their signed token
munnel 3000 -s alice -t m1.<...> --server tunnels.example.com:7001
```

a signed token carries its own subdomain claim and expiry — the server
verifies the signature, so you don't redistribute a token list when someone
joins or leaves. revoke by adding the token id (printed by `mint`) to
`revoked.txt` and restarting. signed and static tokens coexist on the same
server.

#### forward-auth (zero-trust) tunnels

a protected tunnel requires a viewer to log in before any request reaches your
local service — useful for staging sites, internal tools, or preview URLs you
only want your team to see. munnel gates the tunnel at the proxy and, after
login, injects a trusted `X-Authenticated-User` header (and optional
`X-Authenticated-Groups`) that your app can read directly. viewers cannot
spoof these headers: munnel strips them from every incoming request before it
ever sets them.

```bash
# 1. server: enable the stub auth provider (dev/test — trusts any submitted user)
munnel-server --domain tunnels.example.com --auth-stub \
  --session-key-file session.key

# 2. client: opt the tunnel into protection
munnel 3000 -s staging --protect --server tunnels.example.com:7001

# 3. viewers hit https://staging.tunnels.example.com → redirected to a login
#    form → after login, their session cookie authorizes access and your app
#    sees X-Authenticated-User: <whoever they entered>
```

the session cookie is HMAC-signed (`s1.` prefix, same family as signed tokens)
and scoped to the tunnel subdomain. `--auth-stub` is **dev/test only** — it
trusts any username a viewer types. a real OIDC provider is the production
path (the `forwardauth.Provider` interface is the integration point). a tunnel
can also be forced into protection by its signed token: `munnel-server mint
--protect` mints a token whose `prot` claim mandates forward-auth regardless of
the client's `--protect` flag.

---

## CLI reference

### `munnel` (client)

| flag | default | description |
|---|---|---|
| `<port>` | — | local port to expose (positional, required) |
| `-s, --subdomain` | `""` | requested subdomain for public routing |
| `-t, --token` | `""` | authentication token for protected servers |
| `--server` | `localhost:7001` | control server address |
| `--local-host` | `127.0.0.1` | local service host |
| `--inspect` | `true` | run the web inspector |
| `--inspect-addr` | `:4040` | inspector listen address |
| `--max-body-mb` | `32` | max request body in megabytes |
| `--protect` | `false` | require viewer login (forward-auth) on this tunnel |

every flag above can also be set from a config file or environment variable, so
day-to-day usage is just `munnel <port> -s <subdomain>`:

| flag | config key | env var |
|---|---|---|
| `--server` | `server` | `MUNNEL_SERVER` |
| `-t, --token` | `token` | `MUNNEL_TOKEN` |
| `-s, --subdomain` | `subdomain` | `MUNNEL_SUBDOMAIN` |
| `--local-host` | `local-host` | `MUNNEL_LOCAL_HOST` |
| `--inspect-addr` | `inspect-addr` | `MUNNEL_INSPECT_ADDR` |
| `--max-body-mb` | `max-body-mb` | `MUNNEL_MAX_BODY_MB` |
| `--inspect` | `inspect` | `MUNNEL_INSPECT` |

the config file is `~/.munnel/config` (or `$MUNNEL_CONFIG`), `KEY=VAL` one per
line, `#` comments allowed. precedence: **flag > env var > config file > builtin
default**. `install-dev.sh` writes this file for you with the managed server's
address and token.

### `munnel-server`

| flag | default | description |
|---|---|---|
| `--domain` | `localhost` | base domain for tunnel routing |
| `--control-addr` | `:7001` | control + multiplex listening address |
| `--proxy-addr` | `:8080` | public HTTP ingress address |
| `--auth-tokens` | `""` | comma-separated valid client tokens |
| `--auth-file` | `""` | JSON file mapping tokens → reserved subdomains |
| `--signing-key-file` | `""` | file with the HMAC key for signed, scoped tokens (or `$MUNNEL_SIGNING_KEY`) |
| `--revoked-file` | `""` | file of revoked signed-token ids (one per line); reload requires restart |
| `--auth-stub` | `false` | enable the stub forward-auth provider (dev/test only — trusts any user; **not for production**) |
| `--session-key-file` | `""` | HMAC key for forward-auth session cookies (or `$MUNNEL_SESSION_KEY`; ephemeral if unset with `--auth-stub`) |
| `--public-scheme` | `http` | URL scheme (use `https` behind Caddy/Cloudflare) |
| `--public-port` | `""` | port in generated URLs (defaults to the proxy port; set `443` behind a TLS proxy so clients see clean `https://sub.domain` URLs) |
| `--max-body-mb` | `32` | max request body in megabytes |

---

## request inspector

while a tunnel runs, open <http://localhost:4040>:

![web inspector](docs/images/inspector.png)

- **request stream** — live list with method, path, status, latency
- **filters** — by method or errors, plus text search on the path
- **inspection** — request/response bodies with JSON formatting and
  syntax highlighting, full header tables
- **replay** — click `↻ replay` to re-send a captured request to your local
  server; the fresh exchange is captured as a new entry (marked `replay`)

the inspector state lives in an in-memory ring buffer (200 requests) and is
cleared when the client exits.

---

## self-hosting in production

1. **DNS** — point both the apex and the wildcard at your VPS:

   ```
   tunnels.example.com     A    <vps-ip>
   *.tunnels.example.com   A    <vps-ip>
   ```

2. **run the server** — docker:

   ```bash
   MUNNEL_DOMAIN=tunnels.example.com MUNNEL_TOKENS=secret123 \
   MUNNEL_SCHEME=https docker compose up -d
   ```

3. **TLS** — the server speaks plain HTTP; terminate TLS in front. the
   included `docker-compose.yml` runs Caddy alongside the server and a tiny
   `ask` permission endpoint. Caddy obtains the apex certificate on startup
   and a per-subdomain Let's Encrypt certificate on each `*.tunnels.example.com`
   subdomain's first request (on-demand TLS). the `ask` service (see
   `approve.py`) gates issuance to your own domain only — Caddy v2.8+
   requires a permission module for on-demand TLS. no DNS-provider plugin
   or wildcard certificate is needed. with the stack running, clients use:

   ```bash
   munnel 3000 -s myapp -t secret123 --server tunnels.example.com:7001
   ```

4. **hardening** — always set `--auth-tokens` (or `--auth-file`) on a public
   server; otherwise anyone who finds it can host content through your domain.
   the control port (7001) must be reachable from clients; it carries no
   plaintext secrets once you have tokens, but you can additionally firewall
   it to known IPs.

---

## managed Azure deployment

a production-grade managed instance for devs is documented in
[docs/OPERATIONS.md](docs/OPERATIONS.md) — an isolated resource group
(`rg-munnel-dev-westeurope`), a Ubuntu VM running the server behind Caddy with
on-demand TLS, Log Analytics + alerts, and an operator runbook (SSH access,
token rotation, redeploy, troubleshooting). the `docker-compose.yml` and
`approve.py` in this repo are the shape that deployment runs.

redeploys can be triggered manually from the **Actions** tab via the `Deploy
server` workflow (`.github/workflows/deploy-server.yml`) — it ships the source
to the VM, rebuilds the Docker image, runs a health check, and never touches
the live `.env` secrets. see the runbook §6 for the required repository
secrets.

---

## how multiplexing works

munnel multiplexes every concurrent HTTP exchange across one persistent TCP
socket using a 9-byte binary frame header:

**`type` (1 B) · `stream id` (4 B, big-endian) · `payload length` (4 B) · payload (≤ 1 MiB per frame)**

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/diagrams/lifecycle-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="docs/diagrams/lifecycle-light.png">
  <img alt="request lifecycle: dispatch → local exchange → response + teardown across one mux stream on TCP :7001" src="docs/diagrams/lifecycle-dark.png">
</picture>

**[interactive version](docs/diagrams/munnel-request-lifecycle.html)** — step through dispatch, the local exchange, and teardown

| type | byte | meaning |
|---|---|---|
| `OPEN` | `0x01` | open a stream (payload: json metadata) |
| `DATA` | `0x02` | stream payload bytes |
| `PING` / `PONG` | `0x03` / `0x04` | keepalive / RTT |
| `CLOSE` | `0x05` | sender finished writing (half-close) |
| `RESET` | `0x06` | abort the stream immediately |

stream ids use parity (server: odd, client: even), so either side may open
streams without coordination. `CLOSE` is directional — the peer sees `EOF`
while remaining free to write — which maps cleanly onto request → response.

1. public traffic arrives at the proxy (`:8080`); the host header selects a
   tunnel from the registry
2. the proxy opens a stream on that tunnel's session and writes the raw
   HTTP/1.1 request
3. the client decodes frames by stream id, dispatches to `localhost:<port>`,
   and writes the raw response back — responses stream (tee'd into the
   inspector), so SSE and large downloads stay live end-to-end
4. `CLOSE` frames from both sides retire the stream

the control handshake happens before the first binary frame: one JSON `hello`
(token, requested subdomain) and one JSON `ack` (assigned public URL), then
the socket switches to binary frames exclusively.

### websocket and upgrade tunnels

requests carrying `Connection: Upgrade` (WebSocket, h2c, etc.) skip the framed
request/response path entirely — the server hijacks the public connection and
pipes it raw over one mux stream:

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/diagrams/websocket-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="docs/diagrams/websocket-light.png">
  <img alt="WebSocket upgrade lifecycle: handshake replayed verbatim over a mux stream, then raw bidirectional pipe end-to-end" src="docs/diagrams/websocket-dark.png">
</picture>

**[interactive version](docs/diagrams/munnel-websocket-upgrade.html)** — see the hijack boundary and where capture stops

- the upgrade handshake (including `Sec-WebSocket-*` headers) is replayed
  verbatim; the local app sees the request exactly as the browser sent it
- after `101 Switching Protocols`, two `io.Copy` goroutines shuttle raw bytes
  in both directions — arbitrary frame sizes, no re-framing, no buffering caps
- the inspector records only the `101` handshake; individual WS frames are not
  captured and upgrade requests cannot be replayed

---

## limitations

- **HTTP(S) + WebSocket only.** raw TCP tunnels (databases, ssh) are not carried
  — there is no HTTP handshake to bootstrap them.
- request bodies are buffered up to `--max-body-mb` on both ends; responses
  stream without a cap.
- inspector capture is truncated at 256 KiB per body for display (proxying is
  unaffected); truncated request bodies cannot be replayed.

---

## project structure

```
munnel/
├── cmd/
│   ├── client/main.go          # munnel — CLI entry point
│   └── server/main.go          # munnel-server — CLI entry point
├── internal/
│   ├── mux/                    # 9-byte binary multiplexer
│   │   ├── frame.go            #   wire format encode/decode
│   │   ├── session.go          #   session manager, heartbeat, dispatch
│   │   ├── stream.go           #   per-stream net.Conn implementation
│   │   └── mux_test.go         #   unit + concurrency tests (-race clean)
│   ├── proto/message.go        # handshake wire messages, subdomain rules
│   ├── server/
│   │   ├── auth.go             # token auth (static + signed) + reserved subdomains
│   │   ├── control.go          # control listener, handshake, registration
│   │   ├── registry.go         # thread-safe subdomain → tunnel registry
│   │   ├── proxy.go            # public HTTP ingress + request/WebSocket relay
│   │   └── landing.go          # landing page on the bare domain
│   ├── token/token.go          # signed, scoped tunnel tokens (HMAC-SHA256)
│   ├── forwardauth/forwardauth.go  # zero-trust: session cookies, identity injection, login flow
│   ├── client/
│   │   ├── config.go           # client settings
│   │   ├── tunnel.go           # reconnect loop, session wiring, events
│   │   └── forwarder.go        # localhost dispatcher + traffic capture
│   ├── inspection/
│   │   ├── store.go            # ring buffer of captured exchanges
│   │   ├── hub.go              # websocket fan-out to inspector tabs
│   │   ├── server.go           # inspector HTTP API + replay endpoint
│   │   └── web/index.html      # embedded single-page inspector UI
│   └── tui/
│       ├── tui.go / model.go   # bubble tea dashboard
│       └── styles.go           # palette
├── Dockerfile                  # multi-stage server image (scratch)
├── docker-compose.yml          # production shape: server + caddy + ask (TLS)
├── approve.py                  # caddy on-demand TLS permission endpoint
├── Caddyfile.example           # on-demand TLS reverse proxy template
├── .env.example                # MUNNEL_DOMAIN / MUNNEL_TOKENS / MUNNEL_SCHEME
├── Makefile                    # build / test / cross-compile
├── install.sh                  # source installer (builds client + server)
├── install-dev.sh              # one-command dev setup for a managed server
└── docs/
    ├── OPERATIONS.md           # managed Azure deployment + operator runbook
    └── diagrams/               # archify diagrams (HTML viewer + dark/light PNG exports)
        ├── munnel-architecture.*      # tunnel topology
        ├── munnel-request-lifecycle.* # frame-level request lifecycle
        └── munnel-websocket-upgrade.* # WS upgrade hijack + raw pipe
```
