#!/bin/sh
# deploy/lib.sh — shared helpers sourced by each provider's deploy.sh.
#
# Source it from a provider script like:
#   DEPLOY_DIR="$(cd "$(dirname "$0")/.." && pwd)"; . "$DEPLOY_DIR/lib.sh"
#
# The caller sets these before calling the helpers:
#   DOMAIN, TOKEN           — munnel server config (required)
#   REMOTE_HOST, SSH_USER, SSH_KEY — provisioned VM access
#
# Helpers:
#   render_user_data <out-path>   substitute __DOMAIN__/__TOKEN__ into cloud-init.yaml
#   ensure_ssh_key <key-path>     generate an ed25519 key if missing; print the pubkey
#   wait_ssh                      block until the VM accepts SSH
#   ship_and_start                scp the repo to /opt/munnel, build, enable the unit
#
# Runs on the operator's laptop (macOS/Linux). POSIX-ish sh + standard tools.

REPO_ROOT="$(cd "$DEPLOY_DIR/.." && pwd)"

render_user_data() {
	[ -n "$DOMAIN" ] || { echo "render_user_data: DOMAIN not set" >&2; return 1; }
	[ -n "$TOKEN" ]  || { echo "render_user_data: TOKEN not set" >&2; return 1; }
	sed -e "s|__DOMAIN__|$DOMAIN|g" -e "s|__TOKEN__|$TOKEN|g" \
		"$DEPLOY_DIR/cloud-init.yaml" > "$1"
}

ensure_ssh_key() {
	key="$1"
	if [ ! -f "$key" ]; then
		ssh-keygen -q -t ed25519 -N "" -C "munnel-deploy" -f "$key"
	fi
	cat "${key}.pub"
}

wait_ssh() {
	[ -n "$REMOTE_HOST" ] && [ -n "$SSH_USER" ] && [ -n "$SSH_KEY" ] || {
		echo "wait_ssh: REMOTE_HOST/SSH_USER/SSH_KEY not set" >&2; return 1; }
	echo "→ waiting for SSH at ${SSH_USER}@${REMOTE_HOST} ..."
	i=0
	while [ "$i" -lt 60 ]; do
		if ssh -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 \
			"$SSH_USER@$REMOTE_HOST" true 2>/dev/null; then
			echo "✓ SSH up"
			return 0
		fi
		i=$((i + 1)); sleep 5
	done
	echo "SSH did not come up at ${REMOTE_HOST}" >&2
	return 1
}

# ship_and_start: push the repo tree to /opt/munnel (without clobbering the
# cloud-init-written .env) and bring the stack up. Idempotent — safe to re-run
# for redeployments after a code change.
ship_and_start() {
	[ -n "$REMOTE_HOST" ] && [ -n "$SSH_USER" ] && [ -n "$SSH_KEY" ] || {
		echo "ship_and_start: REMOTE_HOST/SSH_USER/SSH_KEY not set" >&2; return 1; }
	echo "→ shipping source to ${SSH_USER}@${REMOTE_HOST}:/opt/munnel ..."
	tarball="/tmp/munnel-src.$$.tgz"
	tar -czf "$tarball" \
		--exclude=bin --exclude=dist --exclude=.git --exclude=.claude \
		--exclude=.env --exclude='*.tgz' \
		-C "$REPO_ROOT" .
	scp -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new \
		"$tarball" "$SSH_USER@$REMOTE_HOST:/tmp/munnel-src.tgz"
	rm -f "$tarball"
	echo "→ building and starting the stack (this takes ~2 min on first run) ..."
	ssh -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new "$SSH_USER@$REMOTE_HOST" '
		set -e
		sudo mkdir -p /opt/munnel
		# Extract over /opt/munnel; .env is excluded from the tar so the
		# cloud-init-written secrets survive.
		sudo tar xzf /tmp/munnel-src.tgz -C /opt/munnel
		rm -f /tmp/munnel-src.tgz
		cd /opt/munnel
		sudo cp Caddyfile.example Caddyfile
		sudo docker compose up -d --build
		sudo systemctl enable munnel.service
		echo "✓ stack live"
		sudo docker compose ps
	'
}

# print_done: standard success footer. $1 = public URL base (the domain).
print_done() {
	domain="$1"
	echo
	echo "════════════════════════════════════════════════════════════"
	echo "  munnel server is up."
	echo "  Next: point DNS at this VM's public IP:"
	echo "    ${domain}        A   <this VM's public IP>"
	echo "    *.${domain}      A   <this VM's public IP>"
	echo "  Then connect a client:"
	echo "    munnel 3000 -s myapp -t <TOKEN> --server ${domain}:7001"
	echo "  (TLS control port 7002: see deploy/README.md § TLS control port)"
	echo "  Logs (on the VM): sudo docker compose -f /opt/munnel/docker-compose.yml logs -f"
	echo "════════════════════════════════════════════════════════════"
}