# Deploying the munnel server

One-shot deploy scripts for the major clouds. Each script provisions a VM
(Ubuntu 22.04/24.04), installs Docker + writes the secret `.env` via
cloud-init, then scp's your local repo source to `/opt/munnel` and runs
`docker compose up -d --build`. The result is a running munnel server with
a static public IP.

| Provider | Script | Cheapest size | ~Price/mo | CLI |
|----------|--------|---------------|-----------|-----|
| Azure | `deploy/azure/deploy.sh` | `Standard_D2als_v7` (2vCPU/4GB) | ~€70 | `az` |
| AWS | `deploy/aws/deploy.sh` | `t3.small` (2vCPU/2GB) | ~$15 | `aws` |
| Hetzner | `deploy/hetzner/deploy.sh` | `cx22` (2vCPU/4GB) | ~€4.5 | `hcloud` |
| DigitalOcean | `deploy/digitalocean/deploy.sh` | `s-2vcpu-2gb` | ~$12 | `doctl` |
| GCP | `deploy/gcp/deploy.sh` | `e2-small` (2vCPU/2GB) | ~$13 | `gcloud` |

> **Hetzner is by far the cheapest** for a side-project tunnel server.

## Prerequisites (all providers)

- The provider's CLI installed and authenticated.
- `ssh`, `ssh-keygen`, `tar`, `scp`, `base64`, `sed` (macOS ships all of these).
- `jq` for the Azure and AWS scripts.
- A domain you control, with the ability to add A + wildcard A records.
- A munnel auth token: generate one with `openssl rand -hex 24`.

## Common usage

```sh
# from the repo root
./deploy/<provider>/deploy.sh --domain tunnels.example.com --token $(openssl rand -hex 24)
```

Every script accepts `--domain` (the apex you'll point DNS at) and `--token`
(the munnel auth token clients must present). Provider-specific knobs
(`--region`, `--instance-type`, etc.) are documented in each script's header.

The script:
1. Creates / reuses an SSH key at `~/.ssh/munnel_deploy_key` (ed25519).
2. Provisions a VM with the cloud-init user-data (Docker + `.env` + systemd unit).
3. Waits for SSH to come up.
4. scp's the repo (minus `.git`, `.env`, build artifacts) to `/opt/munnel`.
5. Runs `docker compose up -d --build` and enables `munnel.service`.

When it finishes it prints the VM's public IP and the DNS records to add:

```
   tunnels.example.com        A   <IP>
   *.tunnels.momentumpay.xyz  A   <IP>
```

Point those records at the IP, then connect a client:

```sh
munnel 3000 -s myapp -t <TOKEN> --server tunnels.example.com:7001
```

## What gets deployed

```
Internet ──:443──► Caddy (TLS, on-demand certs) ──► :8080 munnel-server (HTTP ingress)
            :7001 ► munnel-server (control/mux, clients connect here)
                          │ ask http://ask:8080/check  (Caddy calls this before issuing a cert)
                          ▼
                     approve.py (token-gated TLS approval)
```

- **Caddy** terminates TLS and fronts the HTTP ingress on `:8080` (localhost only).
- **munnel-server** runs the control/mux protocol on `:7001` and the HTTP ingress on `:8080`.
- **approve.py** gates Caddy's on-demand TLS: it only lets a subdomain get a cert if a connected tunnel's token is valid for that subdomain.

Files of interest on the VM:
- `/opt/munnel/.env` — `MUNNEL_DOMAIN`, `MUNNEL_TOKENS`, `MUNNEL_SCHEME` (chmod 600, written by cloud-init).
- `/opt/munnel/docker-compose.yml`, `Caddyfile` (copied from `Caddyfile.example`).
- `/etc/systemd/system/munnel.service` — `docker compose up -d --build` on boot.

## Redeploying after a code change

Re-run the same deploy script. `ship_and_start` is idempotent — it extracts the
new source over `/opt/munnel` (leaving the cloud-init-written `.env` intact) and
rebuilds the containers:

```sh
./deploy/<provider>/deploy.sh --domain tunnels.example.com --token <existing-token>
```

To rebuild without re-provisioning, SSH in and run:

```sh
ssh -i ~/.ssh/munnel_deploy_key <user>@<IP>
cd /opt/munnel && sudo docker compose up -d --build
```

See [docs/OPERATIONS.md](../docs/OPERATIONS.md) for the full operator runbook
(token rotation, logs, troubleshooting, teardown).

## Why scp instead of git clone / a container registry

The repo is private, so the VM can't `git clone` it without credentials, and
baking the source into cloud-init user-data blows past the ~16–64 KB user-data
limit on most providers. scp'ing after provisioning has no size limit and no
credential handling. For a public repo or a registry-based deploy, swap
`ship_and_start` for a `git clone` or `docker pull` — the rest is unchanged.

## Security notes

- The deploy scripts take `--token` as a parameter; **never commit a token**. `.env` is gitignored.
- SSH key is generated locally and only the public half leaves your machine.
- For production, restrict the SSH security-group rule to your office/VPN CIDR instead of `0.0.0.0/0` (see `docs/OPERATIONS.md` § hardening).
- The `.env` is written by cloud-init with `0600 root:root` and is excluded from the scp tarball, so redeployments never overwrite or leak it.