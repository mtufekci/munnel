#!/bin/sh
# deploy/hetzner/deploy.sh — provision a munnel server on Hetzner Cloud.
#
# Usage:
#   deploy/hetzner/deploy.sh --domain tunnels.example.com --token <TOKEN> \
#     [--hcloud-token <HCLOUD_TOKEN>] [--type cx22] [--name munnel] [--location nbg1]
#
# Requires: hcloud CLI (or HCLOUD_TOKEN env), ssh, ssh-keygen, tar, scp, base64, sed.
# Cheapest provider: cx22 (2 vCPU / 4 GiB) ~€4.5/mo. Set HCLOUD_TOKEN or pass
# --hcloud-token; get one at https://console.hetzner.cloud/projects -> API tokens.
set -eu

DEPLOY_DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DEPLOY_DIR/lib.sh"

DOMAIN=""
TOKEN=""
HCLOUD_TOKEN="${HCLOUD_TOKEN:-}"
SERVER_TYPE="cx22"
NAME="munnel"
LOCATION="nbg1"

usage() { cat >&2 <<EOF
Usage: $0 --domain <fqdn> --token <token> [--hcloud-token <api-token>] [--type cx22] [--name munnel] [--location nbg1]
EOF
	exit 1; }

while [ $# -gt 0 ]; do
	case "$1" in
		--domain) DOMAIN="$2"; shift 2;;
		--token)  TOKEN="$2";  shift 2;;
		--hcloud-token) HCLOUD_TOKEN="$2"; shift 2;;
		--type) SERVER_TYPE="$2"; shift 2;;
		--name) NAME="$2"; shift 2;;
		--location) LOCATION="$2"; shift 2;;
		-h|--help) usage;;
		*) echo "unknown arg: $1" >&2; usage;;
	esac
done
[ -n "$DOMAIN" ] && [ -n "$TOKEN" ] || usage
[ -n "$HCLOUD_TOKEN" ] || { echo "HCLOUD_TOKEN not set (use --hcloud-token or env)" >&2; exit 1; }

command -v hcloud >/dev/null || { echo "hcloud CLI not found (https://github.com/hetznercloud/cli)" >&2; exit 1; }
export HCLOUD_TOKEN

SSH_KEY="$HOME/.ssh/munnel_deploy_key"
SSH_USER="root"
KEY_LABEL="munnel-deploy"

PUBKEY="$(ensure_ssh_key "$SSH_KEY")"

# Register the SSH key (idempotent: reuse if the label exists).
if ! hcloud ssh-key describe "$KEY_LABEL" >/dev/null 2>&1; then
	printf '%s' "$PUBKEY" | hcloud ssh-key create --name "$KEY_LABEL" --public-key -
fi

USERDATA_FILE="$(mktemp)"
trap 'rm -f "$USERDATA_FILE"' EXIT
render_user_data "$USERDATA_FILE"

echo "→ creating server $NAME (type $SERVER_TYPE in $LOCATION) ..."
SERVER_ID="$(hcloud server create \
	--name "$NAME" --type "$SERVER_TYPE" --location "$LOCATION" \
	--image ubuntu-22.04 --ssh-key "$KEY_LABEL" \
	--user-data-from-file "$USERDATA_FILE" -o format=json -o no-header 2>/dev/null \
	| sed -n 's/.*"id":\([0-9]*\).*/\1/p' | head -1)"
# Fallback: hcloud prints the id in non-json mode; parse the server list.
if [ -z "$SERVER_ID" ]; then
	SERVER_ID="$(hcloud server list -o columns=id,name | awk -v n="$NAME" '$2==n{print $1}')"
fi
echo "✓ server id: $SERVER_ID"

REMOTE_HOST="$(hcloud server describe "$SERVER_ID" -o format=json | sed -n 's/.*"ipv4":"\([^"]*\)".*/\1/p' | head -1)"
echo "✓ server up at $REMOTE_HOST"

wait_ssh
ship_and_start
print_done "$DOMAIN"