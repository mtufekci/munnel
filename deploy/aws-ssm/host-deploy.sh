#!/usr/bin/env bash
# Deploys the munnel server on the AWS host. Runs as root on the host, started
# by the "Deploy server" workflow through SSM (.github/workflows/deploy-server.yml);
# it can also be run by hand in an SSM session (docs/OPERATIONS.md §6).
#
# Usage: host-deploy.sh <git-sha> [--no-caddy-reload]
#
# Takes no secrets. It expects $MUNNEL_SRC to be a checkout of <git-sha> (the
# SSM command fetches it first) and then:
#   1. rsyncs the checkout to $MUNNEL_DIR (live .env and Caddyfile survive),
#   2. renders $MUNNEL_DIR/.env from Secrets Manager, byte for byte,
#   3. rebuilds and restarts the stack,
#   4. reloads Caddy (unless --no-caddy-reload),
#   5. checks /healthz and Caddy's on-demand TLS ask endpoint.
#
# Config comes from /etc/munnel/host.env (MUNNEL_HOST_ENV overrides the path, for
# the tests): MUNNEL_SECRET_ID, AWS_DEFAULT_REGION, MUNNEL_SRC, MUNNEL_DIR.
#
# The secret is never printed: no `set -x`, and it is only ever piped from `aws`
# through `jq` into a 0600 file. The Docker volume munnel_caddy_data holds
# Caddy's certificates; nothing here removes or recreates it.
set -euo pipefail

die() {
  echo "ERROR: $*" >&2
  exit 1
}

usage() {
  echo "usage: $0 <git-sha> [--no-caddy-reload]" >&2
  exit 2
}

sha=""
caddy_reload=1
for arg in "$@"; do
  case "$arg" in
    --no-caddy-reload) caddy_reload=0 ;;
    -*) usage ;;
    *)
      [ -z "$sha" ] || usage
      sha=$arg
      ;;
  esac
done
[ -n "$sha" ] || usage

host_env=${MUNNEL_HOST_ENV:-/etc/munnel/host.env}
[ -r "$host_env" ] || die "cannot read $host_env"
set -a
# shellcheck source=/dev/null
. "$host_env"
set +a
: "${MUNNEL_SECRET_ID:?MUNNEL_SECRET_ID is not set in $host_env}"
: "${MUNNEL_SRC:?MUNNEL_SRC is not set in $host_env}"
: "${MUNNEL_DIR:?MUNNEL_DIR is not set in $host_env}"

caddy=munnel-caddy-1
tmp_env=""
build_log=""
dump_logs=0

# On any failure (after the SHA check) show the server's last log lines; always
# remove the temp files.
cleanup() {
  rc=$?
  if [ -n "$tmp_env" ]; then rm -f "$tmp_env"; fi
  if [ -n "$build_log" ]; then rm -f "$build_log"; fi
  if [ "$rc" -ne 0 ] && [ "$dump_logs" = 1 ]; then
    echo "=== docker compose logs --tail=40 munnel-server ==="
    (cd "$MUNNEL_DIR" && docker compose logs --tail=40 munnel-server 2>&1) || true
  fi
  exit "$rc"
}
trap cleanup EXIT

src_head=$(git -C "$MUNNEL_SRC" rev-parse HEAD) || die "cannot read the checkout at $MUNNEL_SRC"
[ "$src_head" = "$sha" ] || die "the checkout at $MUNNEL_SRC is at $src_head, expected $sha"
dump_logs=1
echo "✓ checkout at ${sha}"

# --delete keeps the deploy clean (files removed from the repo are removed on
# the host), but .env and Caddyfile are excluded so they survive the sync.
rsync -a --delete \
  --exclude=.env --exclude=Caddyfile \
  --exclude=bin --exclude=dist --exclude=.git \
  --exclude=node_modules --exclude='*.tgz' \
  "$MUNNEL_SRC/" "$MUNNEL_DIR/"
# Regenerate Caddyfile from the template ({$MUNNEL_DOMAIN} env substitution is
# read from .env at container start). cp writes into the existing file, keeping
# the inode the caddy container's single-file bind mount points at; deleting and
# recreating it (as rsync --delete would) leaves caddy reading the old content.
cp "$MUNNEL_DIR/Caddyfile.example" "$MUNNEL_DIR/Caddyfile"
echo "✓ source synced to $MUNNEL_DIR"

# Render .env from the secret. The temp file is created 0600 beside .env (same
# filesystem, so the mv is atomic) and `jq -j` writes the string with no added
# newline; going through a shell variable would strip trailing newlines. A
# secret with no value (SecretString null or empty) must not replace the live .env.
tmp_env=$(umask 077 && mktemp "$MUNNEL_DIR/.env.XXXXXX")
if ! aws secretsmanager get-secret-value --secret-id "$MUNNEL_SECRET_ID" \
  --query SecretString --output json | jq -j 'select(type == "string")' > "$tmp_env"; then
  die "could not read the secret $MUNNEL_SECRET_ID from Secrets Manager"
fi
[ -s "$tmp_env" ] || die "the secret $MUNNEL_SECRET_ID has no value yet; put-secret-value first (docs/OPERATIONS.md §4)"
chmod 600 "$tmp_env"
# Let compose parse the rendered file before it goes live. Its parse errors quote
# the offending line, and this script's output ends up in a public job log, so
# the output is discarded. The live .env stays untouched on failure, which also
# keeps the exit trap's `compose logs` from parsing the bad file.
docker compose --project-directory "$MUNNEL_DIR" --env-file "$tmp_env" config --quiet >/dev/null 2>&1 \
  || die "the secret does not parse as a compose .env; the error is withheld from this log; run 'docker compose config --quiet' in $MUNNEL_DIR in an SSM session"
mv -f "$tmp_env" "$MUNNEL_DIR/.env"
tmp_env=""
echo "✓ .env rendered from the secret"

cd "$MUNNEL_DIR"

# SSM returns at most 24,000 characters of output, and a build prints more than
# that, so keep the build output in a file and show only its tail.
build_log=$(mktemp)
# --remove-orphans drops services deleted from the compose file.
if docker compose up -d --build --remove-orphans > "$build_log" 2>&1; then
  tail -n 15 "$build_log"
else
  echo "=== docker compose up failed, last 60 lines ==="
  tail -n 60 "$build_log"
  die "docker compose up failed"
fi
echo "=== compose ps ==="
docker compose ps
echo "✓ stack up"

if [ "$caddy_reload" = 1 ]; then
  # A container still bound to a replaced Caddyfile would reload the old config
  # and pass; recreate it instead (certs live in the munnel_caddy_data volume,
  # so nothing is re-issued).
  if docker exec "$caddy" cat /etc/caddy/Caddyfile | cmp -s - "$MUNNEL_DIR/Caddyfile"; then
    docker exec "$caddy" caddy reload --config /etc/caddy/Caddyfile 2>&1 \
      || docker compose restart caddy
  else
    echo "caddy sees a stale Caddyfile; recreating the container"
    docker compose up -d --force-recreate caddy
  fi
  echo "✓ caddy reloaded"
else
  echo "- caddy reload skipped (--no-caddy-reload)"
fi

# The server takes a few seconds to bind after recreate. Poll from the host
# itself (the ingress is bound to 127.0.0.1:8080, not the public IP).
healthy=0
for i in $(seq 1 12); do
  if curl -sf http://localhost:8080/healthz; then
    echo
    echo "✓ server healthy"
    healthy=1
    break
  fi
  if [ "$i" -lt 12 ]; then
    echo "  …waiting (attempt $i/12)"
    sleep 5
  fi
done
[ "$healthy" = 1 ] || die "health check failed: the server did not respond on :8080/healthz"

# Caddy must reach munnel-server's ask listener, or no new subdomain gets a
# certificate. The apex is always approved.
domain=$(docker exec "$caddy" printenv MUNNEL_DOMAIN) || die "caddy has no MUNNEL_DOMAIN"
docker exec "$caddy" wget -q -O /dev/null "http://munnel-server:8081/check?domain=$domain" \
  || die "caddy cannot reach the ask endpoint at munnel-server:8081"
echo "✓ ask endpoint reachable from caddy"
