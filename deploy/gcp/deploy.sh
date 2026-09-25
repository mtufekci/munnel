#!/bin/sh
# deploy/gcp/deploy.sh — provision a munnel server on Google Compute Engine.
#
# Usage:
#   deploy/gcp/deploy.sh --domain tunnels.example.com --token <TOKEN> \
#     [--zone europe-west1-b] [--machine-type e2-small] [--name munnel] [--project <PROJECT>]
#
# Requires: gcloud CLI (authed), ssh, ssh-keygen, tar, scp, base64, sed.
# e2-small (2 vCPU shared / 2 GiB) ~$13/mo. Uses the default project unless
# --project is given; enable compute API first:
#   gcloud services enable compute.googleapis.com
set -eu

DEPLOY_DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DEPLOY_DIR/lib.sh"

DOMAIN=""
TOKEN=""
ZONE="europe-west1-b"
MACHINE_TYPE="e2-small"
NAME="munnel"
PROJECT=""

usage() { cat >&2 <<EOF
Usage: $0 --domain <fqdn> --token <token> [--zone europe-west1-b] [--machine-type e2-small] [--name munnel] [--project <id>]
EOF
	exit 1; }

while [ $# -gt 0 ]; do
	case "$1" in
		--domain) DOMAIN="$2"; shift 2;;
		--token)  TOKEN="$2";  shift 2;;
		--zone) ZONE="$2"; shift 2;;
		--machine-type) MACHINE_TYPE="$2"; shift 2;;
		--name) NAME="$2"; shift 2;;
		--project) PROJECT="$2"; shift 2;;
		-h|--help) usage;;
		*) echo "unknown arg: $1" >&2; usage;;
	esac
done
[ -n "$DOMAIN" ] && [ -n "$TOKEN" ] || usage

command -v gcloud >/dev/null || { echo "gcloud CLI not found (run 'gcloud auth login')" >&2; exit 1; }
GCLOUD="gcloud"
[ -n "$PROJECT" ] && GCLOUD="$GCLOUD --project $PROJECT"

SSH_KEY="$HOME/.ssh/munnel_deploy_key"
SSH_USER="munnel"

PUBKEY="$(ensure_ssh_key "$SSH_KEY")"

# GCE passes the SSH key via instance metadata (ssh-keys=USER:PUBKEY).
# gcloud's os-login is heavier; the metadata route is simpler and portable.

USERDATA_FILE="$(mktemp)"
trap 'rm -f "$USERDATA_FILE"' EXIT
render_user_data "$USERDATA_FILE"

# Firewall: open 22/80/443/7001/7002. Idempotent — re-applies if it exists.
echo "→ firewall rules ..."
$GCLOUD compute firewall-rules describe "munnel-allow-22"   >/dev/null 2>&1 || \
	$GCLOUD compute firewall-rules create "munnel-allow-22"   --allow tcp:22   --source-ranges 0.0.0.0/0 --network default >/dev/null 2>&1 || true
$GCLOUD compute firewall-rules describe "munnel-allow-http" >/dev/null 2>&1 || \
	$GCLOUD compute firewall-rules create "munnel-allow-http" --allow tcp:80   --source-ranges 0.0.0.0/0 --network default >/dev/null 2>&1 || true
$GCLOUD compute firewall-rules describe "munnel-allow-https">/dev/null 2>&1 || \
	$GCLOUD compute firewall-rules create "munnel-allow-https" --allow tcp:443  --source-ranges 0.0.0.0/0 --network default >/dev/null 2>&1 || true
$GCLOUD compute firewall-rules describe "munnel-allow-mux"  >/dev/null 2>&1 || \
	$GCLOUD compute firewall-rules create "munnel-allow-mux"  --allow tcp:7001 --source-ranges 0.0.0.0/0 --network default >/dev/null 2>&1 || true
$GCLOUD compute firewall-rules describe "munnel-allow-mux-tls" >/dev/null 2>&1 || \
	$GCLOUD compute firewall-rules create "munnel-allow-mux-tls" --allow tcp:7002 --source-ranges 0.0.0.0/0 --network default >/dev/null 2>&1 || true

echo "→ creating instance $NAME in $ZONE ..."
$GCLOUD compute instances create "$NAME" \
	--zone "$ZONE" --machine-type "$MACHINE_TYPE" \
	--image-family ubuntu-2204-lts --image-project ubuntu-os-cloud \
	--metadata-from-file user-data="$USERDATA_FILE" \
	--metadata "ssh-keys=${SSH_USER}:${PUBKEY}" \
	--tags munnel-server >/dev/null

REMOTE_HOST="$($GCLOUD compute instances describe "$NAME" --zone "$ZONE" --format='get(networkInterfaces[0].accessConfigs[0].natIP)')"
echo "✓ instance up at $REMOTE_HOST"

wait_ssh
ship_and_start
print_done "$DOMAIN"