#!/usr/bin/env bash
# Tests for deploy/aws-ssm/host-deploy.sh.
#
# No network, no root, no real docker/aws: each test builds a sandbox with stub
# `aws`, `docker`, `git`, `curl` and `sleep` on PATH (rsync is the real one,
# wrapped only to log the call), points the script at a sandbox host.env via
# MUNNEL_HOST_ENV, and checks what ended up on disk and which commands ran.
#
# Run: bash deploy/aws-ssm/host-deploy_test.sh   (exit 0 only if every test passes)
#
# A test that would pass with the script missing or broken is wrong: each one
# first requires the run to behave as expected (exit code, message) before it
# asserts the property it is about.

set -u

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
script="$here/host-deploy.sh"
real_rsync=$(command -v rsync)

SHA=0123456789abcdef0123456789abcdef01234567
MARKER='MARKER-7f3a9c1e-must-never-be-printed'

# --- sandbox -----------------------------------------------------------------

setup() {
  SB=$(mktemp -d "${TMPDIR:-/tmp}/host-deploy-test.XXXXXX") || exit 1
  export SB
  mkdir -p "$SB/bin" "$SB/src" "$SB/opt/munnel"
  : > "$SB/calls.log"

  cat > "$SB/host.env" <<EOF
MUNNEL_SECRET_ID='munnel/nonprod/server-env'
AWS_DEFAULT_REGION='eu-central-1'
MUNNEL_REPO_URL='https://github.com/mtufekci/munnel.git'
MUNNEL_SRC='$SB/src'
MUNNEL_DIR='$SB/opt/munnel'
EOF

  # The checkout the SSM command would have made.
  printf 'services: {}\n' > "$SB/src/docker-compose.yml"
  printf 'NEW-CADDYFILE\n' > "$SB/src/Caddyfile.example"

  # A secret with the things that break naive rendering: '=', quotes, '$' and
  # $(...) text, and trailing newlines (command substitution would eat them).
  {
    printf '%s\n' 'MUNNEL_DOMAIN=tunnels.test'
    printf '%s\n' 'MUNNEL_TOKENS=tok=with=equals'
    printf '%s\n' "MUNNEL_QUOTED=\"a b\" 'c d'"
    # shellcheck disable=SC2016  # the '$' text must stay literal
    printf '%s\n' 'MUNNEL_DOLLAR=pa$$w0rd$(not-a-command)${NOT_EXPANDED}'
    printf '%s\n' "MUNNEL_MARKER=$MARKER"
    printf '\n'  # a blank last line: $(...) would strip both newlines
  } > "$SB/secret.txt"

  cat > "$SB/bin/aws" <<'EOF'
#!/usr/bin/env bash
echo "aws $*" >> "$SB/calls.log"
# What the .env looked like when the secret was fetched (after the sync).
if [ -f "$SB/opt/munnel/.env" ]; then cp "$SB/opt/munnel/.env" "$SB/env_at_fetch"; fi
case "$*" in
  *"secretsmanager get-secret-value"*"--secret-id munnel/nonprod/server-env"*)
    # What `--query SecretString --output json` prints.
    if [ -n "${STUB_SECRET_NULL:-}" ]; then echo null; else jq -Rs . < "$SB/secret.txt"; fi ;;
  *) echo "stub aws: unexpected call: $*" >&2; exit 99 ;;
esac
EOF

  cat > "$SB/bin/git" <<'EOF'
#!/usr/bin/env bash
echo "git $*" >> "$SB/calls.log"
case "$*" in
  *"rev-parse HEAD"*) echo "${STUB_GIT_HEAD:?}" ;;
  *) echo "stub git: unexpected call: $*" >&2; exit 99 ;;
esac
EOF

  cat > "$SB/bin/docker" <<'EOF'
#!/usr/bin/env bash
echo "docker $*" >> "$SB/calls.log"
case "$*" in
  "compose logs "*) echo "STUB-DOCKER-LOGS" ;;
  "compose ps") echo "STUB-COMPOSE-PS" ;;
  "exec munnel-caddy-1 cat /etc/caddy/Caddyfile") cat "$SB/opt/munnel/Caddyfile" ;;
  "exec munnel-caddy-1 printenv MUNNEL_DOMAIN") echo tunnels.test ;;
  *) : ;;  # compose up, caddy reload, wget ask check, ...
esac
exit 0
EOF

  cat > "$SB/bin/curl" <<'EOF'
#!/usr/bin/env bash
echo "curl $*" >> "$SB/calls.log"
if [ -n "${STUB_CURL_FAIL:-}" ]; then exit 22; fi
echo ok
EOF

  cat > "$SB/bin/sleep" <<'EOF'
#!/usr/bin/env bash
echo "sleep $*" >> "$SB/calls.log"
EOF

  cat > "$SB/bin/rsync" <<'EOF'
#!/usr/bin/env bash
echo "rsync $*" >> "$SB/calls.log"
exec "$REAL_RSYNC" "$@"
EOF

  chmod +x "$SB"/bin/*
}

teardown() { rm -rf "$SB"; }

# run_deploy <args...>: runs host-deploy.sh in the sandbox; sets $rc and $SB/out.txt
# (stdout and stderr together).
run_deploy() {
  PATH="$SB/bin:$PATH" MUNNEL_HOST_ENV="$SB/host.env" REAL_RSYNC="$real_rsync" \
    STUB_GIT_HEAD="${STUB_GIT_HEAD:-$SHA}" \
    bash "$script" "$@" > "$SB/out.txt" 2>&1
  rc=$?
}

mode_of() { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"; }
# shellcheck disable=SC2012  # ls -i is the portable inode lookup (GNU and BSD)
inode_of() { ls -i "$1" | awk '{print $1}'; }

# need_success: the precondition most tests share.
need_success() {
  if [ "$rc" -ne 0 ]; then
    echo "deploy exited $rc, expected 0; output:"
    sed 's/^/    /' "$SB/out.txt"
    return 1
  fi
}

# --- tests -------------------------------------------------------------------

test_env_is_exact_bytes_and_0600() {
  run_deploy "$SHA"
  need_success || return 1
  [ -f "$SB/opt/munnel/.env" ] || { echo ".env was not rendered"; return 1; }
  cmp -s "$SB/secret.txt" "$SB/opt/munnel/.env" || {
    echo ".env differs from the secret's SecretString:"
    cmp "$SB/secret.txt" "$SB/opt/munnel/.env" 2>&1 | sed 's/^/    /'
    return 1
  }
  m=$(mode_of "$SB/opt/munnel/.env")
  [ "$m" = 600 ] || { echo ".env mode is $m, expected 600"; return 1; }
}

test_secret_never_printed() {
  run_deploy "$SHA"
  need_success || return 1
  cmp -s "$SB/secret.txt" "$SB/opt/munnel/.env" || { echo ".env was not rendered, so the check below proves nothing"; return 1; }
  if grep -F -q "$MARKER" "$SB/out.txt"; then
    echo "the secret marker appears in the script's output"
    return 1
  fi
}

test_env_and_caddyfile_survive_sync() {
  dir="$SB/opt/munnel"
  printf 'OLD-ENV\n' > "$dir/.env"
  printf 'OLD-CADDYFILE\n' > "$dir/Caddyfile"
  : > "$dir/stale.txt"
  inode_before=$(inode_of "$dir/Caddyfile")

  run_deploy "$SHA"
  need_success || return 1

  [ -f "$SB/env_at_fetch" ] && [ "$(cat "$SB/env_at_fetch")" = OLD-ENV ] || {
    echo ".env was gone or changed when the secret was fetched: the sync touched it"
    return 1
  }
  cmp -s "$SB/secret.txt" "$dir/.env" || { echo ".env was not replaced by the render"; return 1; }
  [ -f "$dir/docker-compose.yml" ] || { echo "the sync did not copy the source"; return 1; }
  [ ! -e "$dir/stale.txt" ] || { echo "--delete did not remove a stale file"; return 1; }
  cmp -s "$SB/src/Caddyfile.example" "$dir/Caddyfile" || { echo "Caddyfile was not regenerated from Caddyfile.example"; return 1; }
  [ "$(inode_of "$dir/Caddyfile")" = "$inode_before" ] || {
    echo "Caddyfile inode changed; caddy's single-file bind mount would keep the old content"
    return 1
  }
}

test_sha_mismatch_refuses() {
  dir="$SB/opt/munnel"
  : > "$dir/sentinel"
  STUB_GIT_HEAD=ffffffffffffffffffffffffffffffffffffffff run_deploy "$SHA"
  [ "$rc" -eq 1 ] || { echo "exit code $rc, expected 1"; sed 's/^/    /' "$SB/out.txt"; return 1; }
  grep -q "$SHA" "$SB/out.txt" || { echo "the message does not name the expected SHA"; sed 's/^/    /' "$SB/out.txt"; return 1; }
  if grep -E -q '^(docker|rsync|aws|curl) ' "$SB/calls.log"; then
    echo "a sync/docker/aws call ran before the SHA check:"
    grep -E '^(docker|rsync|aws|curl) ' "$SB/calls.log" | sed 's/^/    /'
    return 1
  fi
  [ -e "$dir/sentinel" ] || { echo "the deploy dir was modified"; return 1; }
}

test_health_failure_exits_nonzero_and_dumps_logs() {
  STUB_CURL_FAIL=1 run_deploy "$SHA"
  [ "$rc" -eq 1 ] || { echo "exit code $rc, expected 1"; sed 's/^/    /' "$SB/out.txt"; return 1; }
  n=$(grep -c '^curl .*healthz' "$SB/calls.log")
  [ "$n" -eq 12 ] || { echo "health check tried $n times, expected 12"; return 1; }
  grep -q '^docker compose logs --tail=40 munnel-server' "$SB/calls.log" || {
    echo "the munnel-server logs were not requested"
    return 1
  }
  grep -q 'STUB-DOCKER-LOGS' "$SB/out.txt" || { echo "the logs were not printed"; return 1; }
}

test_never_touches_caddy_volume() {
  run_deploy "$SHA"
  need_success || return 1
  grep -q '^docker compose up ' "$SB/calls.log" || { echo "no 'docker compose up' call was recorded, so the check below proves nothing"; return 1; }
  if grep -E -q '^docker (compose )?(down.* (-v|--volumes)|volume (rm|remove|prune)|system prune)' "$SB/calls.log" \
     || grep -E -q -- '--volumes' "$SB/calls.log"; then
    echo "a call that can delete the caddy volume was made:"
    grep -E -- 'down|volume|prune' "$SB/calls.log" | sed 's/^/    /'
    return 1
  fi
}

# Not in the brief's six, but the brief requires the behaviour: a secret with no
# value must fail clearly and leave the live .env alone.
test_empty_secret_fails_and_keeps_env() {
  printf 'OLD-ENV\n' > "$SB/opt/munnel/.env"
  STUB_SECRET_NULL=1 run_deploy "$SHA"
  [ "$rc" -eq 1 ] || { echo "exit code $rc, expected 1"; sed 's/^/    /' "$SB/out.txt"; return 1; }
  grep -q 'no value' "$SB/out.txt" || { echo "no clear 'no value' message"; sed 's/^/    /' "$SB/out.txt"; return 1; }
  [ "$(cat "$SB/opt/munnel/.env")" = OLD-ENV ] || { echo "the live .env was replaced"; return 1; }
  if grep -q '^docker compose up ' "$SB/calls.log"; then echo "the stack was rebuilt without a secret"; return 1; fi
}

# --- runner ------------------------------------------------------------------

failures=0
run_test() {
  name=$1
  if out=$( ( setup; trap teardown EXIT; "test_$name" ) 2>&1 ); then
    echo "PASS $name"
  else
    echo "FAIL $name"
    [ -z "$out" ] || printf '%s\n' "$out" | sed 's/^/     /'
    failures=$((failures + 1))
  fi
}

for t in \
  env_is_exact_bytes_and_0600 \
  secret_never_printed \
  env_and_caddyfile_survive_sync \
  sha_mismatch_refuses \
  health_failure_exits_nonzero_and_dumps_logs \
  never_touches_caddy_volume \
  empty_secret_fails_and_keeps_env
do
  run_test "$t"
done

if [ "$failures" -ne 0 ]; then
  echo "$failures test(s) failed"
  exit 1
fi
echo "all tests passed"
