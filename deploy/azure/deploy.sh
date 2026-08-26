#!/bin/sh
# deploy/azure/deploy.sh — provision a munnel server on Azure.
#
# Usage:
#   deploy/azure/deploy.sh --domain tunnels.example.com --token <TOKEN> \
#     [--location westeurope] [--name munnel] [--vm-size Standard_D2als_v7]
#
# Requires: az CLI (logged in), ssh, ssh-keygen, tar, scp, base64, sed, jq.
# The script creates the resource group if missing, provisions the VM via
# Bicep, then scp's your local repo to /opt/munnel and brings the stack up.
set -eu

DEPLOY_DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DEPLOY_DIR/lib.sh"

DOMAIN=""
TOKEN=""
LOCATION="westeurope"
NAME="munnel"
VM_SIZE="Standard_D2als_v7"

usage() { cat >&2 <<EOF
Usage: $0 --domain <fqdn> --token <token> [--location westeurope] [--name munnel] [--vm-size Standard_D2als_v7]
EOF
	exit 1; }

while [ $# -gt 0 ]; do
	case "$1" in
		--domain) DOMAIN="$2"; shift 2;;
		--token)  TOKEN="$2";  shift 2;;
		--location) LOCATION="$2"; shift 2;;
		--name) NAME="$2"; shift 2;;
		--vm-size) VM_SIZE="$2"; shift 2;;
		-h|--help) usage;;
		*) echo "unknown arg: $1" >&2; usage;;
	esac
done
[ -n "$DOMAIN" ] && [ -n "$TOKEN" ] || usage

command -v az >/dev/null || { echo "az CLI not found (run 'az login')" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq not found" >&2; exit 1; }

SSH_KEY="$HOME/.ssh/munnel_deploy_key"
SSH_USER="azureuser"
RG="rg-${NAME}-${LOCATION}"

echo "→ resource group: $RG"
az group create -n "$RG" -l "$LOCATION" -o table >/dev/null

PUBKEY="$(ensure_ssh_key "$SSH_KEY")"

USERDATA_FILE="$(mktemp)"
trap 'rm -f "$USERDATA_FILE"' EXIT
render_user_data "$USERDATA_FILE"
USERDATA_B64="$(base64 < "$USERDATA_FILE" | tr -d '\n')"

echo "→ provisioning VM (this takes ~2 min) ..."
DEPLOY_OUT="$(az deployment group create -g "$RG" -f "$DEPLOY_DIR/azure/main.bicep" \
	--parameters name="$NAME" location="$LOCATION" vmSize="$VM_SIZE" \
	adminUsername="$SSH_USER" adminKey="$PUBKEY" userData="$USERDATA_B64" -o json)"

REMOTE_HOST="$(printf '%s' "$DEPLOY_OUT" | jq -r '.properties.outputs.publicIp.value')"
[ -n "$REMOTE_HOST" ] && [ "$REMOTE_HOST" != "null" ] || { echo "deployment produced no public IP" >&2; exit 1; }
echo "✓ VM up at $REMOTE_HOST"

wait_ssh
ship_and_start
print_done "$DOMAIN"