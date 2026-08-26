#!/bin/sh
# install.sh — build and install the munnel client (and server) from source.
#
#   curl -fsSL https://raw.githubusercontent.com/mtufekci/munnel/main/install.sh | sh
#   ./install.sh --client-only
set -eu

PREFIX="${PREFIX:-/usr/local}"
if [ ! -w "$PREFIX/bin" ] 2>/dev/null; then
  PREFIX="$HOME/.local"
fi
BIN="$PREFIX/bin"

CLIENT_ONLY=0
[ "${1:-}" = "--client-only" ] && CLIENT_ONLY=1

fail() { echo "install.sh: $*" >&2; exit 1; }

# 1. go via PATH — the clean path.
if command -v go >/dev/null 2>&1; then
  echo "→ building with $(go version)"
  mkdir -p "$BIN"
  GOFLAGS="-trimpath -ldflags=-s -w"
  # shellcheck disable=SC2086
  CGO_ENABLED=0 go build $GOFLAGS -o "$BIN/munnel" ./cmd/client
  echo "✓ munnel → $BIN/munnel"
  if [ "$CLIENT_ONLY" -eq 0 ]; then
    # shellcheck disable=SC2086
    CGO_ENABLED=0 go build $GOFLAGS -o "$BIN/munnel-server" ./cmd/server
    echo "✓ munnel-server → $BIN/munnel-server"
  fi
  case ":$PATH:" in
    *":$BIN:"*) ;;
    *) echo "note: add $BIN to your PATH" ;;
  esac
  exit 0
fi

fail "go toolchain not found — install Go from https://go.dev/dl/ then re-run, or download a release binary"
