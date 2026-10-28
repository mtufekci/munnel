# deploy/aws-ssm

Deploys the munnel server to an AWS host that is reached only through SSM (no SSH,
no inbound deploy port). The host is provisioned elsewhere (a landing-zone root, not
this repo); this directory holds what runs on it.

- `host-deploy.sh <git-sha> [--no-caddy-reload]` — runs as root on the host, from a
  checkout of `<git-sha>` in `$MUNNEL_SRC`. Syncs the source to `$MUNNEL_DIR`, renders
  `.env` from Secrets Manager (exact bytes, never printed), rebuilds the stack, reloads
  Caddy, checks `/healthz` and the ask endpoint. Config: `/etc/munnel/host.env`.
- `host-deploy_test.sh` — tests for it, with stub `aws`, `docker`, `git`, `curl`.
  No network, no root: `bash deploy/aws-ssm/host-deploy_test.sh`.

The `Deploy server` workflow (`.github/workflows/deploy-server.yml`) fetches the commit
on the host over an SSM command and runs the script. See `docs/OPERATIONS.md` §6.
