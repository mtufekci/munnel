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
            :7001 ► munnel-server (control/mux, plaintext, clients connect here)
            :7002 ► munnel-server (control/mux over TLS; off until a certificate is configured)
                          │ ask http://ask:8080/check  (Caddy calls this before issuing a cert)
                          ▼
                     approve.py (token-gated TLS approval)
```

- **Caddy** terminates TLS and fronts the HTTP ingress on `:8080` (localhost only).
- **munnel-server** runs the control/mux protocol on `:7001` (and over TLS on `:7002` once enabled) and the HTTP ingress on `:8080`.
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

## TLS control port (7002)

`:7001` is plaintext: tokens and tunnelled traffic cross the network in
cleartext between clients and the VM. `:7002` speaks the same protocol over
TLS. It reuses the Let's Encrypt certificate Caddy already keeps for the apex
domain: `docker-compose.yml` mounts Caddy's storage read-only at
`/caddy-data` in the munnel-server container, and munnel-server re-reads the
files when Caddy renews them. Nothing changes for existing clients; 7001
stays up.

1. Open TCP 7002 in the cloud firewall. The templates in this directory now
   include it for new deployments; an existing VM needs it added by hand
   (for example on Azure:
   `az network nsg list -g <resource-group> -o table`, then
   `az network nsg rule create -g <resource-group> --nsg-name <nsg> -n AllowMunnelTLS --priority 131 --protocol Tcp --destination-port-ranges 7002 --access Allow --direction Inbound`).
2. Point munnel-server at the certificate in `/opt/munnel/.env` (the deploy
   workflow never touches `.env`):

   ```sh
   MUNNEL_TLS_CERT_FILE=/caddy-data/caddy/certificates/acme-v02.api.letsencrypt.org-directory/<domain>/<domain>.crt
   MUNNEL_TLS_KEY_FILE=/caddy-data/caddy/certificates/acme-v02.api.letsencrypt.org-directory/<domain>/<domain>.key
   ```

   `<domain>` is `MUNNEL_DOMAIN`. If Caddy fell back to ZeroSSL, the issuer
   directory is `acme.zerossl.com-v2-dv90` instead; list
   `caddy/certificates/` in the `caddy_data` volume to check.
3. Redeploy (`docker compose up -d --build`, or the Deploy server workflow).
   The startup log shows `control-tls=[::]:7002`; a warning about the
   certificate means the path is wrong or Caddy has not obtained it yet.
4. Check from a laptop:
   `openssl s_client -connect <domain>:7002 -servername <domain> </dev/null | openssl x509 -noout -subject -dates`,
   then `munnel 3000 --tls --server <domain>:7002`.

Clients connect with the apex host name (`<domain>:7002`), which is the name
on the certificate. No Caddyfile change is needed.

## Reserved names

A reserved name can be claimed only by the signed-token ids listed for it,
and only over the TLS port. In `/opt/munnel/.env`, entries separated by `;`:

```sh
MUNNEL_RESERVED=hop=tok_0123456789abcdef
```

Outside docker, use `--reserved-file` with one `name tokenID[,tokenID...]`
per line. Token ids are not secrets. Changes need a restart.

## Operator note: the hop tunnel

hop room is exposed at `https://hop.<domain>/` through a munnel tunnel from
the founder's laptop. That tunnel carries a long-lived token and signed-in
sessions, so it runs only over TLS on a reserved name. One-time setup, on the
VM and the laptop:

1. **Mint the hop token** on the VM (the signing key is already in the
   container's environment):

   ```sh
   cd /opt/munnel
   sudo docker compose exec munnel-server /munnel-server mint --sub hop --ttl 8760h
   ```

   It prints the token id (`tok_…`) and the token (`m1.…`). Move the token
   to the laptop without pasting it anywhere else (it is valid for a year),
   into `~/.munnel/hop.config` with mode 0600:

   ```sh
   server=<domain>:7002
   tls=true
   token=<TOKEN>
   ```

2. **Reserve `hop` for that token id**: add
   `MUNNEL_RESERVED=hop=<tok_id>` to `/opt/munnel/.env` (append
   `;name=tok_…` for more names).
3. **Enable the TLS listener on 7002**: the two `MUNNEL_TLS_*` lines from
   [TLS control port](#tls-control-port-7002) in the same `.env`.
4. **Open 7002** in the NSG / firewall (step 1 of that section).
5. **Redeploy** and check the startup log for `control-tls=` and
   `reserved=hop`.
6. **Laptop**: rebuild and install the client (`./install-dev.sh`; `munnel
   --help` must list `--tls`), then run
   `MUNNEL_CONFIG=~/.munnel/hop.config munnel <port> -s hop --tls --inspect=false`.
   Over plaintext 7001 the server now refuses `hop`, and nobody else can
   claim it, even while the laptop is asleep.
7. **Tell the other munnel users**: 7002 exists and 7001 stays for now; move
   to TLS by rebuilding the client and setting `tls=true` and
   `server=<domain>:7002` in `~/.munnel/config`; `hop` is reserved (the
   enrollment endpoint will refuse it); the local inspector now opens only
   through the link munnel prints.

To rotate the hop token, mint a new one, add its id next to the old one
(`hop=tok_new,tok_old`), redeploy, switch the laptop, then drop the old id and
redeploy again. A token scoped to `hop` whose id is no longer listed cannot
claim anything.

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