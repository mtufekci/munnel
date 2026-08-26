#!/bin/sh
# install-dev.sh — one-command setup for devs using the managed munnel server.
#
#   ./install-dev.sh --token <TOKEN>
#   MUNNEL_TOKEN=<TOKEN> ./install-dev.sh
#
# Builds the munnel client, installs it on PATH, and writes ~/.munnel/config
# with the server + token so day-to-day usage is just:
#
#   munnel 3000 -s myapp        → https://myapp.tunnels.momentumpay.xyz
#   munnel 3000                → random subdomain
#
# Re-run anytime to update the binary or rotate the token.
set -eu

# Public server address (non-secret). Override with MUNNEL_SERVER if needed.
SERVER="${MUNNEL_SERVER:-tunnels.momentumpay.xyz:7001}"
# Auth token is a secret — never hardcode it here. Pass via --token / MUNNEL_TOKEN.
TOKEN=""

# --- parse args ---
while [ $# -gt 0 ]; do
  case "$1" in
    --token) TOKEN="${2:-}"; shift 2 ;;
    --token=*) TOKEN="${1#--token=}"; shift ;;
    --server) SERVER="${2:-}"; shift 2 ;;
    --server=*) SERVER="${1#--server=}"; shift ;;
    -h|--help)
      cat <<HELP
install-dev.sh — set up the munnel client for the managed dev server

usage:
  ./install-dev.sh --token <TOKEN>            # token from your operator
  MUNNEL_TOKEN=<TOKEN> ./install-dev.sh       # same, via env
  ./install-dev.sh --token <TOKEN> --server tunnels.example.com:7001

what it does:
  1. builds the munnel client (uses go if installed, else docker)
  2. installs it to /usr/local/bin (or ~/.local/bin if no write access)
  3. writes ~/.munnel/config with server + token (chmod 600)

after that:
  munnel 3000 -s myapp        # → https://myapp.tunnels.momentumpay.xyz
HELP
      exit 0 ;;
    *) echo "install-dev.sh: unknown arg: $1 (try --help)" >&2; exit 2 ;;
  esac
done

# fall back to env if --token wasn't given
[ -z "$TOKEN" ] && TOKEN="${MUNNEL_TOKEN:-}"
[ -z "$TOKEN" ] && {
  echo "install-dev.sh: token required." >&2
  echo "  Get it from your operator, then run:" >&2
  echo "    ./install-dev.sh --token <TOKEN>" >&2
  exit 1
}

fail() { echo "install-dev.sh: $*" >&2; exit 1; }

# --- 1. build the client ---
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
BUILT="$TMP/munnel"

if command -v go >/dev/null 2>&1; then
  echo "→ building with $(go version)"
  CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$BUILT" ./cmd/client
else
  command -v docker >/dev/null 2>&1 || fail "neither go nor docker found — install one to build"
  case "$(uname -s)" in Darwin) GOOS=darwin ;; Linux) GOOS=linux ;; *) fail "unsupported OS: $(uname -s)" ;; esac
  case "$(uname -m)" in arm64|aarch64) GOARCH=arm64 ;; x86_64|amd64) GOARCH=amd64 ;; *) fail "unsupported arch: $(uname -m)" ;; esac
  echo "→ no go toolchain; building $GOOS/$GOARCH via docker"
  # write the artifact into the repo root (mounted as /src), then move it aside
  docker run --rm -v "$PWD":/src -w /src \
    -e GOOS="$GOOS" -e GOARCH="$GOARCH" -e CGO_ENABLED=0 \
    golang:1.25-alpine go build -trimpath -ldflags="-s -w" -o /src/.munnel-build ./cmd/client \
    || fail "docker build failed"
  mv "$PWD/.munnel-build" "$BUILT"
fi
[ -x "$BUILT" ] || fail "build produced no binary"

# --- 2. install on PATH ---
DEST="$HOME/.local/bin"
if [ -w /usr/local/bin ] 2>/dev/null; then DEST=/usr/local/bin; fi
mkdir -p "$DEST"
install -m 0755 "$BUILT" "$DEST/munnel"
echo "✓ installed: $DEST/munnel"

# --- 3. write config ---
mkdir -p "$HOME/.munnel"
CONFIG="$HOME/.munnel/config"
cat > "$CONFIG" <<EOF
# munnel client defaults — written by install-dev.sh $(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || true)
# edit or re-run install-dev.sh to change. precedence: flag > env > this file.
server=$SERVER
token=$TOKEN
EOF
chmod 600 "$CONFIG"
echo "✓ config:   $CONFIG  (chmod 600)"

# --- done ---
case ":$PATH:" in
  *":$DEST:"*) ;;
  *) echo "note: add $DEST to your PATH (e.g. 'export PATH=\"$DEST:\$PATH\"' in ~/.zshrc)" ;;
esac
echo
echo "next:  munnel 3000 -s myapp      → https://myapp.tunnels.momentumpay.xyz"
echo "       munnel 3000               → random subdomain"
echo "       munnel --help             → full options"