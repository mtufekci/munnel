#!/bin/sh
# deploy/digitalocean/deploy.sh — provision a munnel server on DigitalOcean.
#
# Usage:
#   deploy/digitalocean/deploy.sh --domain tunnels.example.com --token <TOKEN> \
#     [--do-token <DO_TOKEN>] [--size s-2vcpu-2gb] [--name munnel] [--region nyc3]
#
# Requires: doctl CLI (authed: 'doctl auth init'), ssh, ssh-keygen, tar, scp, base64, sed.
# s-2vcpu-2gb ~$12/mo. Set DIGITALOCEAN_ACCESS_TOKEN or pass --do-token.
set -eu

DEPLOY_DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DEPLOY_DIR/lib.sh"

DOMAIN=""
TOKEN=""
DO_TOKEN="${DIGITALOCEAN_ACCESS_TOKEN:-}"
SIZE="s-2vcpu-2gb"
NAME="munnel"
REGION="nyc3"

usage() { cat >&2 <<EOF
Usage: $0 --domain <fqdn> --token <token> [--do-token <api-token>] [--size s-2vcpu-2gb] [--name munnel] [--region nyc3]
EOF
	exit 1; }

while [ $# -gt 0 ]; do
	case "$1" in
		--domain) DOMAIN="$2"; shift 2;;
		--token)  TOKEN="$2";  shift 2;;
		--do-token) DO_TOKEN="$2"; shift 2;;
		--size) SIZE="$2"; shift 2;;
		--name) NAME="$2"; shift 2;;
		--region) REGION="$2"; shift 2;;
		-h|--help) usage;;
		*) echo "unknown arg: $1" >&2; usage;;
	esac
done
[ -n "$DOMAIN" ] && [ -n "$TOKEN" ] || usage
[ -n "$DO_TOKEN" ] || { echo "DIGITALOCEAN_ACCESS_TOKEN not set (use --do-token or env)" >&2; exit 1; }

command -v doctl >/dev/null || { echo "doctl not found (https://github.com/digitalocean/doctl)" >&2; exit 1; }
export DIGITALOCEAN_ACCESS_TOKEN="$DO_TOKEN"

SSH_KEY="$HOME/.ssh/munnel_deploy_key"
SSH_USER="root"
KEY_NAME="munnel-deploy"

PUBKEY="$(ensure_ssh_key "$SSH_KEY")"

# Register the SSH key with DO (idempotent: reuse by fingerprint).
KEY_FP="$(printf '%s' "$PUBKEY" | ssh-keygen -lf - | awk '{print $2}')"
DO_KEY_ID="$(doctl compute ssh-key list --format ID,Fingerprint --no-header 2>/dev/null | awk -v fp="$KEY_FP" '$2==fp{print $1}')"
if [ -z "$DO_KEY_ID" ]; then
	DO_KEY_ID="$(doctl compute ssh-key create "$KEY_NAME" --public-key "$PUBKEY" --format ID --no-header)"
fi

USERDATA_FILE="$(mktemp)"
trap 'rm -f "$USERDATA_FILE"' EXIT
render_user_data "$USERDATA_FILE"

echo "→ creating droplet $NAME (size $SIZE in $REGION) ..."
DROPLET_ID="$(doctl compute droplet create "$NAME" \
	--size "$SIZE" --region "$REGION" --image ubuntu-22-04-x64 \
	--ssh-keys "$DO_KEY_ID" --user-data-file "$USERDATA_FILE" \
	--enable-ipv6 --wait --format ID --no-header | head -1)"
echo "✓ droplet id: $DROPLET_ID"

REMOTE_HOST="$(doctl compute droplet get "$DROPLET_ID" --template '{{.Networks.V4 | len}}' >/dev/null 2>&1; doctl compute droplet get "$DROPLET_ID" --format PublicIPv4 --no-header)"
echo "✓ droplet up at $REMOTE_HOST"

wait_ssh
ship_and_start
print_done "$DOMAIN"