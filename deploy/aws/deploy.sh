#!/bin/sh
# deploy/aws/deploy.sh — provision a munnel server on AWS (EC2).
#
# Usage:
#   deploy/aws/deploy.sh --domain tunnels.example.com --token <TOKEN> \
#     [--region eu-west-1] [--instance-type t3.small] [--stack munnel]
#
# Requires: aws CLI (logged in), ssh, ssh-keygen, tar, scp, base64, sed, jq.
# Uses your default VPC and its first public subnet. For a locked-down deploy,
# pass a different VpcId/SubnetId via --vpc / --subnet.
set -eu

DEPLOY_DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DEPLOY_DIR/lib.sh"

DOMAIN=""
TOKEN=""
REGION="eu-west-1"
INSTANCE_TYPE="t3.small"
STACK="munnel"
VPC=""
SUBNET=""

usage() { cat >&2 <<EOF
Usage: $0 --domain <fqdn> --token <token> [--region eu-west-1] [--instance-type t3.small] [--stack munnel] [--vpc <vpc-id> --subnet <subnet-id>]
EOF
	exit 1; }

while [ $# -gt 0 ]; do
	case "$1" in
		--domain) DOMAIN="$2"; shift 2;;
		--token)  TOKEN="$2";  shift 2;;
		--region) REGION="$2"; shift 2;;
		--instance-type) INSTANCE_TYPE="$2"; shift 2;;
		--stack) STACK="$2"; shift 2;;
		--vpc) VPC="$2"; shift 2;;
		--subnet) SUBNET="$2"; shift 2;;
		-h|--help) usage;;
		*) echo "unknown arg: $1" >&2; usage;;
	esac
done
[ -n "$DOMAIN" ] && [ -n "$TOKEN" ] || usage

command -v aws >/dev/null || { echo "aws CLI not found (run 'aws configure')" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq not found" >&2; exit 1; }

AWS="aws --region $REGION"
SSH_KEY="$HOME/.ssh/munnel_deploy_key"
SSH_USER="ubuntu"
KEY_NAME="munnel-deploy"

PUBKEY="$(ensure_ssh_key "$SSH_KEY")"

# Resolve the default VPC + a public subnet if not given.
if [ -z "$VPC" ]; then
	VPC="$($AWS ec2 describe-vpcs --filters "isDefault=true" --query 'Vpcs[0].VpcId' --output text)"
fi
if [ -z "$SUBNET" ]; then
	SUBNET="$($AWS ec2 describe-subnets --filters "vpc-id=$VPC" "default-for-az=true" --query 'Subnets[0].SubnetId' --output text)"
fi
echo "→ VPC: $VPC  subnet: $SUBNET"

# Ubuntu 24.04 LTS AMI via SSM (no hard-coded AMI ids, works in every region).
AMI="$($AWS ssm get-parameter --name /aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id --query 'Parameter.Value' --output text)"
echo "→ AMI: $AMI"

# Import the SSH public key as a key pair (idempotent-ish: delete + recreate).
$AWS ec2 describe-key-pairs --key-names "$KEY_NAME" >/dev/null 2>&1 && {
	$AWS ec2 delete-key-pair --key-name "$KEY_NAME" >/dev/null; }
printf '%s' "$PUBKEY" | $AWS ec2 import-key-pair --key-name "$KEY_NAME" --public-key-material file:///dev/stdin >/dev/null

USERDATA_FILE="$(mktemp)"
PARAMS_FILE="$(mktemp)"
trap 'rm -f "$USERDATA_FILE" "$PARAMS_FILE"' EXIT
render_user_data "$USERDATA_FILE"
# CloudFormation expects UserData raw (it base64-encodes !Ref). We pass it as
# a parameter string; CFN treats the Ref as the literal text and encodes it.
USERDATA_RAW="$(cat "$USERDATA_FILE")"
jq -n \
	--arg p "$STACK" --arg t "$INSTANCE_TYPE" --arg k "$KEY_NAME" \
	--arg v "$VPC" --arg s "$SUBNET" --arg a "$AMI" --arg u "$USERDATA_RAW" \
	'{"StackName":$p,"Capabilities":["CAPABILITY_IAM"],"Parameters":[
		{"ParameterKey":"InstanceType","ParameterValue":$t},
		{"ParameterKey":"KeyName","ParameterValue":$k},
		{"ParameterKey":"VpcId","ParameterValue":$v},
		{"ParameterKey":"SubnetId","ParameterValue":$s},
		{"ParameterKey":"AmiId","ParameterValue":$a},
		{"ParameterKey":"UserData","ParameterValue":$u}
	]}' > "$PARAMS_FILE"

echo "→ provisioning stack $STACK (this takes ~2 min) ..."
$AWS cloudformation create-stack --cli-input-json file://"$PARAMS_FILE" \
	--template-body "file://$DEPLOY_DIR/aws/cloudformation.yaml" >/dev/null
$AWS cloudformation wait stack-create-complete --stack-name "$STACK" >/dev/null

REMOTE_HOST="$($AWS cloudformation describe-stacks --stack-name "$STACK" \
	--query 'Stacks[0].Outputs[?OutputKey==`PublicIp`].OutputValue' --output text)"
echo "✓ EC2 up at $REMOTE_HOST"

wait_ssh
ship_and_start
print_done "$DOMAIN"