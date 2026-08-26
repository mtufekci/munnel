# munnel dev server — operations runbook

Managed munnel tunnel server for developers. This is an agent/operator
runbook: every section lists exact commands, paths, and resource names so it
can be executed without further context.

> **Status**: deployed 2026-08-26. Region: westeurope (VMs cannot be deployed
> in uksouth for this subscription — `NotAvailableForSubscription` on every
> VM SKU there; all other munnel infra lives in westeurope too).

---

## 1. What this is

A self-hosted ngrok replacement. Devs run `munnel <port> -s <sub>` and get a
public `https://<sub>.tunnels.momentumpay.xyz` URL that tunnels to their
localhost. The server address and auth token live in `~/.munnel/config`
(written by `install-dev.sh`), so day-to-day usage is a single short command.
One VM runs the tunnel server; Caddy terminates TLS; a tiny Python `ask`
endpoint gates on-demand cert issuance to our domain only.

```
dev machine                         Azure (rg-munnel-dev-westeurope)
┌────────────┐   TCP/7001 (mux)    ┌─────────────────────────────────┐
│ munnel     │ ──────────────────► │ vm-munnel-dev                   │
│ client     │                     │  ├─ munnel-server  :7001/:8080  │
│ (forwards  │                     │  ├─ caddy          :80/:443     │
│  :3000)    │                     │  └─ ask            :8080 (perm) │
└────────────┘                     └────────────┬────────────────────┘
        ▲                                        │ HTTPS 443
        │ relayed HTTP/1.1 over mux stream       ▼
        │                                  public webhooks/clients
   ┌────────────┐                      → https://sub.tunnels.momentumpay.xyz
   │ dev server │
   │ :3000      │
   └────────────┘
```

---

## 2. Resources (all in `rg-munnel-dev-westeurope`, westeurope)

| Resource | Name | Notes |
|----------|------|-------|
| VM | `vm-munnel-dev` | Standard_D2als_v7 (2 vCPU / 4 GB), Ubuntu 24.04, OS disk 30 GB |
| Public IP | `pip-munnel-dev` | `51.105.170.135`, FQDN `munnel-dev.westeurope.cloudapp.azure.com` |
| NSG | `nsg-munnel-dev` | 22 (deployer IP only), 80/443/7001 (any) |
| Log Analytics | `log-munnel-dev-westeurope` | syslog + perf counters |
| Data collection rule | `dcr-munnel-dev-westeurope` | associated to the VM |
| Action group | `ag-munnel-dev-westeurope` | emails `murat@momentumpay.xyz` |
| Metric alert | `alert-vm-cpu-munnel-dev` | Percentage CPU > 80% for 5 min |
| Activity alert | `alert-vm-downtime-munnel-dev` | VM deallocated/stopped |

The VM stack lives at `/opt/munnel` and is managed by `docker compose`.
A systemd unit `munnel.service` runs `docker compose up -d` on boot.

---

## 3. SSH access

An entry is already in `~/.ssh/config`:

```bash
ssh munnel-dev          # → azureuser@munnel-dev.westeurope.cloudapp.azure.com
```

The SSH key is `~/.ssh/id_ed25519`. Password auth and root login are disabled
on the VM; `fail2ban` bans brute-forceers.

### Giving another dev SSH access

1. Collect their public key.
2. `ssh munnel-dev`
3. `echo '<their ssh-ed25519 AAA...>' | tee -a ~/.ssh/authorized_keys`
4. Add their source IP to the NSG (port 22 is locked to a single IP today):

```bash
# add a second allowed source CIDR (keep the existing rule)
az network nsg rule create -g rg-munnel-dev-westeurope --nsg-name nsg-munnel-dev \
  --name AllowSSH-dev2 --priority 101 --direction Inbound --access Allow \
  --protocol Tcp --source-address-prefixes <THEIR.IP>/32 --destination-port-ranges 22 -o none
```

### Updating the SSH IP (e.g. your office IP changed)

```bash
az network nsg rule update -g rg-munnel-dev-westeurope --nsg-name nsg-munnel-dev \
  --name AllowSSH --source-address-prefixes <NEW.IP>/32
```

To find your current public IP: `curl -s4 https://ifconfig.me/ip`.

---

## 4. The tunnel token

A single shared dev token is in `/opt/munnel/.env` on the VM (`MUNNEL_TOKENS`).
It is also the token devs pass with `-t`. To rotate it:

```bash
ssh munnel-dev
TOKEN=$(openssl rand -hex 24)
sed -i "s/^MUNNEL_TOKENS=.*/MUNNEL_TOKENS=$TOKEN/" /opt/munnel/.env
docker compose -f /opt/munnel/docker-compose.yml restart munnel-server
# distribute $TOKEN to devs; the old one stops working immediately
```

### Per-dev tokens with reserved subdomains (recommended as the team grows)

`munnel-server` supports an auth file mapping token → reserved subdomain.
Replace `--auth-tokens` with `--auth-file`:

```bash
ssh munnel-dev
cat > /opt/munnel/auth.json <<'EOF'
{ "aliceTokenHex": "alice", "bobTokenHex": "bob-app" }
EOF
```

Edit `/opt/munnel/docker-compose.yml`: remove the `--auth-tokens=...` line and
add `- --auth-file=/auth.json`, plus a volume `./auth.json:/auth.json:ro`.
Then `docker compose up -d`. Each dev then gets a guaranteed subdomain and
can't claim another's.

---

## 5. Connecting a dev tunnel

### One-time setup (per dev machine)

Devs clone this repo and run the installer with the shared token (§4):

```bash
git clone <repo> && cd munnel
./install-dev.sh --token <TOKEN>
# builds the client, installs it on PATH, writes ~/.munnel/config (server + token)
```

That's it — `~/.munnel/config` now holds the server address and token, so they
never need to pass `--server` or `-t` again. The token file is `chmod 600`.

### Day-to-day

```bash
munnel 3000 -s myapp        # → https://myapp.tunnels.momentumpay.xyz
munnel 3000                 # → https://<random>.tunnels.momentumpay.xyz
```

`-s` is self-service: any subdomain under `tunnels.momentumpay.xyz` works and
gets its own TLS cert on first request. Omit `-s` for a random subdomain. The
inspector opens at <http://localhost:4040>; use `--inspect-addr :4041` for a
second concurrent tunnel (each tunnel needs a unique subdomain and inspector
port).

Any flag still overrides the config — e.g. `munnel 3000 -s other
--inspect=false`. Env vars (`MUNNEL_SERVER`, `MUNNEL_TOKEN`, …) override the
config file too; see `munnel --help`.

> The client must use `tunnels.momentumpay.xyz:7001` for the control
> connection. The public URL is always `https://<sub>.tunnels.momentumpay.xyz`
> (port 443, no port suffix).

### Rotating the token for all devs

Rotate on the VM (§4) to get the new `$TOKEN`, then each dev re-runs
`./install-dev.sh --token $TOKEN` (or edits `~/.munnel/config`). The old token
stops working the moment the server restarts.

---

## 6. Rebuilding / redeploying after a code change

The server image is built on the VM from this repo's source. To deploy a
change (after editing Go code, Dockerfile, compose, or Caddyfile):

```bash
# from your laptop, sync changed files (or the whole tree)
cd /Users/murattufekci/Repo/Munnel
tar -czf /tmp/munnel-src.tgz --exclude=bin --exclude=dist --exclude=.git --exclude=.claude -C .. Munnel
scp /tmp/munnel-src.tgz munnel-dev:/opt/munnel/
ssh munnel-dev 'cd /opt/munnel && tar xzf munnel-src.tgz --strip-components=1 && rm munnel-src.tgz && \
  # re-apply the live .env and Caddyfile if the tar overwrote them
  docker compose up -d --build'
```

If the tar overwrites `docker-compose.yml` / `Caddyfile` / `.env` (because the
repo has its own versions), re-copy the live ones from `docs/OPERATIONS.md`
references or keep a `/opt/munnel/live/` backup. Simpler: scp only the files
that changed.

```bash
# quick single-file deploy
scp internal/server/control.go munnel-dev:/opt/munnel/internal/server/control.go
ssh munnel-dev 'cd /opt/munnel && docker compose up -d --build'
```

The image build takes ~2 min (Go build inside `golang:1.25-alpine`). Caddy and
the ask container are pulled images, no rebuild.

---

## 7. DNS and TLS

DNS (managed outside Azure — no Azure DNS zone in this subscription), both A
records point at `51.105.170.135`:

```
tunnels.momentumpay.xyz     A   51.105.170.135
*.tunnels.momentumpay.xyz   A   51.105.170.135
```

Caddy auto-obtains:
- the apex cert on startup (normal ACME), and
- a per-subdomain cert on each `*.tunnels.momentumpay.xyz` first request
  (on-demand TLS, gated by the `ask` service to our domain only).

Certs are stored in the `caddy_data` docker volume and auto-renewed. If the
public IP ever changes (it shouldn't — it's static), update the A records and
restart Caddy: `ssh munnel-dev 'docker compose restart caddy'`.

---

## 8. Operations cheat sheet (all on the VM)

```bash
ssh munnel-dev
cd /opt/munnel

docker compose ps                       # stack status
docker compose logs -f munnel-server    # server log (tunnel up/down, handshakes)
docker compose logs -f caddy            # TLS issuance / proxy
docker compose logs --tail=50 ask       # on-demand permission checks
docker compose restart munnel-server    # reload server (picks up new .env)
docker compose down                     # stop everything
docker compose up -d                    # start everything
docker compose up -d --build            # rebuild after a code change
docker system df                        # disk usage by docker
df -h                                   # OS disk
```

Caddy config reload without restart (after editing Caddyfile):
```bash
docker exec munnel-caddy-1 caddy reload --config /etc/caddy/Caddyfile
```

---

## 9. Monitoring & alerts

- **Logs/metrics**: syslog (auth, daemon) + perf counters (CPU, memory, disk)
  flow to `log-munnel-dev-westeurope` via the Azure Monitor Agent and
  `dcr-munnel-dev-westeurope`.
- **Alerts** → `ag-munnel-dev-westeurope` → `murat@momentumpay.xyz`:
  - `alert-vm-cpu-munnel-dev`: CPU > 80% for 5 min.
  - `alert-vm-downtime-munnel-dev`: VM deallocated/stopped.

Query logs in the portal (Log Analytics → Logs) or CLI:
```bash
az monitor log-analytics query -w $(az monitor log-analytics workspace show \
  -g rg-munnel-dev-westeurope --workspace-name log-munnel-dev-westeurope \
  --query customerId -o tsv) \
  --analytics-query 'Syslog | where TimeGenerated > ago(1h) | order by TimeGenerated desc'
```

Change the alert recipient:
```bash
az monitor action-group update -g rg-munnel-dev-westeurope --name ag-munnel-dev-westeurope \
  --action email murat-notify new@email.example
```

---

## 10. Backups & state

There is no precious state to back up:
- munnel-server is stateless (tunnels live in memory).
- Caddy certs auto-reissue on demand.
- The token is a single line in `/opt/munnel/.env` — keep a copy in your
  secrets manager (it's the only thing worth preserving).

Redeploying from scratch is fully scripted (see §6 and the deployment
history). The source of truth is this repo.

---

## 11. Troubleshooting

| Symptom | Check |
|--------|-------|
| Client can't connect to `:7001` | `nc -zv tunnels.momentumpay.xyz 7001` from the dev box. If it fails, NSG rule `AllowMunnelControl` may have been removed. |
| `curl https://sub.tunnels...` → TLS error / no cert | First request triggers issuance (can take ~10-30s). Retry. Check `docker compose logs caddy` for `certificate obtained` or ask-endpoint 403s. |
| `curl https://sub.tunnels...` → 502/504 | No tunnel registered for that subdomain, or the dev's local server is down. `docker compose logs munnel-server` shows `tunnel up/down`. |
| Caddy restart-looping | Usually a Caddyfile parse error. `docker compose logs caddy` prints the line. `on_demand_tls` must have an `ask` URL (mandatory in Caddy v2.8+). |
| 8080 reachable from the internet | It shouldn't be. Compose binds `127.0.0.1:8080:8080`. If exposed, the repo/VM compose drifted — fix the port binding. |
| `SkuNotAvailable` creating/recreating the VM | westeurope D2als_v7 was unrestricted at deploy time. If it's capacity-blocked, pick another unrestricted 2-vCPU SKU: `az rest --method get --url "https://management.azure.com/subscriptions/<sub>/providers/Microsoft.Compute/skus?api-version=2021-07-01&\$filter=location%20eq%20'westeurope'"` and filter `restrictions == []`. uksouth will not work. |
| SSH fails from a new location | Port 22 is locked to a deployer IP. Update the `AllowSSH` NSG rule (§3). |

---

## 12. Cost

- Standard_D2als_v7: ~€0.096/h → ~€70/mo continuous (dev, can be deallocated
  off-hours to save: `az vm deallocate -g rg-munnel-dev-westeurope -n vm-munnel-dev`).
- Standard static public IP: ~€3/mo (billed even when VM deallocated).
- Log Analytics: ~€2.3/GB ingestion; a single dev VM is well under 1 GB/mo.
- DNS records: cost is at your DNS provider, not Azure.

Estimated total running 24/7: ~€75/mo. Deallocate nights/weekends to cut
~70%. (Tunnels obviously stop while the VM is off.)

---

## 13. Teardown (if ever needed)

```bash
az group delete --name rg-munnel-dev-westeurope --yes
```
Removes the VM, IP, NSG, workspace, DCR, alerts, and action group in one
step. DNS records (outside Azure) must be removed separately at your DNS
provider.