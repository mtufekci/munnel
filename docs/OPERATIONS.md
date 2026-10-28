# munnel dev server — operations runbook

Managed munnel tunnel server for developers. This is an agent/operator
runbook: every section lists exact commands, paths, and resource names so it
can be executed without further context.

> **Status**: runs on AWS (nonprod account, eu-central-1) since October 2026.
> History: on Azure (a westeurope VM) from 26 Aug to October 2026.
>
> The AWS account, instance ID, role ARN and Elastic IP are deliberately not in
> this repo (it is public). They are outputs of the landing-zone root
> `munnel-nonprod` (a separate, private repo).

---

## 1. What this is

A self-hosted ngrok replacement. Devs run `munnel <port> -s <sub>` and get a
public `https://<sub>.tunnels.momentumpay.xyz` URL that tunnels to their
localhost. The server address and auth token live in `~/.munnel/config`
(written by `install-dev.sh`), so day-to-day usage is a single short command.
One host runs the tunnel server; Caddy terminates TLS; before issuing an
on-demand cert Caddy asks munnel-server (internal `:8081`), which approves only
the apex and subdomains with a live tunnel.

```
dev machine                         AWS nonprod (eu-central-1, own VPC)
┌────────────┐   TLS/7002 (mux)    ┌─────────────────────────────────┐
│ munnel     │ ──────────────────► │ EC2 t4g.small (Elastic IP)      │
│ client     │                     │  ├─ munnel-server  :7002/:8080  │
│ (forwards  │                     │  │    + :8081 ask (internal)    │
│  :3000)    │                     │  └─ caddy          :80/:443     │
└────────────┘                     └────────────┬────────────────────┘
        ▲                                        │ HTTPS 443
        │ relayed HTTP/1.1 over mux stream       ▼
        │                                  public webhooks/clients
   ┌────────────┐                      → https://sub.tunnels.momentumpay.xyz
   │ dev server │
   │ :3000      │       GitHub Actions ──OIDC──► AWS role ──SSM──► the host
   └────────────┘       (deploys; no SSH, no inbound port)
```

---

## 2. What runs where

| Piece | Detail |
|-------|--------|
| Account / region | the AWS **nonprod** account (landing-zone root `munnel-nonprod`), `eu-central-1` (Frankfurt), one AZ |
| Network | Its own small VPC (one public subnet, internet gateway, no NAT), not a shared VPC. Open to the internet: 80, 443, 7002. 7001 (plaintext control) is closed. **No port 22.** |
| Host | EC2 `t4g.small` (2 vCPU Graviton, 2 GiB), Ubuntu 24.04 arm64, gp3 20 GiB encrypted. IMDSv2 only, no key pair |
| Address | One Elastic IP, kept across host replacements; DNS points at it (§7) |
| Secret | Secrets Manager `munnel/nonprod/server-env`: munnel's `.env`, byte for byte (§4) |
| Alarms | Status-check recover and reboot alarms, CPU alarm → SNS topic `munnel-alerts` → email (§9) |
| Deploys | GitHub Actions: OIDC → deploy role → SSM Run Command (§6) |
| Provisioning | The landing-zone root `munnel-nonprod` (OpenTofu). Its outputs give the instance ID, role ARN and Elastic IP |

`7001` is still published by `docker-compose.yml` on the host; the security
group is what keeps it closed. It sent the token in the clear, which is why
clients use 7002 with TLS (§5).

The stack lives at `/opt/munnel` and is managed by `docker compose`. A systemd
unit `munnel.service` runs `docker compose up -d` on boot once
`/opt/munnel/docker-compose.yml` exists. The compose project is `munnel`, so the
containers are `munnel-munnel-server-1` and `munnel-caddy-1` and the volumes are
`munnel_caddy_data` and `munnel_caddy_config`.

Host settings (not secret) are in `/etc/munnel/host.env`: `MUNNEL_SECRET_ID`,
`AWS_DEFAULT_REGION`, `MUNNEL_REPO_URL`, `MUNNEL_SRC` (`/opt/munnel-src`, the
git checkout deploys fetch into) and `MUNNEL_DIR` (`/opt/munnel`).

---

## 3. Access (SSM Session Manager, no SSH)

The host has no SSH daemon exposed and no key pair. Open a shell with SSM, with
the AWS CLI, the Session Manager plugin and your SSO profile for that account:

```bash
aws sso login --profile <nonprod-profile>
aws ssm start-session --target <instance-id> --profile <nonprod-profile> --region eu-central-1
sudo -i          # the session user is not root; the stack is root's
```

`<instance-id>` is an output of the landing-zone root `munnel-nonprod`.

### Giving another dev access

There is no key to hand out. Access is the IAM permission to start a session on
that instance (`ssm:StartSession`), granted in the landing zone, not in this repo.

---

## 4. The tunnel token

A single shared dev token is `MUNNEL_TOKENS` in the `.env`, which lives in the
Secrets Manager secret `munnel/nonprod/server-env` (never edit `.env` on the
host: the next deploy re-renders it from the secret and overwrites the edit).
It is also the token devs pass with `-t`.

### Changing a key in the secret

The secret's SecretString is the whole `.env`. Fetch it to a private file, edit
it, put it back, then redeploy:

```bash
export AWS_PROFILE=<nonprod-profile> AWS_REGION=eu-central-1
f=$(umask 077 && mktemp)
aws secretsmanager get-secret-value --secret-id munnel/nonprod/server-env \
  --query SecretString --output json | jq -j . > "$f"
"${EDITOR:-vi}" "$f"            # keep the final newline
aws secretsmanager put-secret-value --secret-id munnel/nonprod/server-env \
  --secret-string "file://$f"
rm -f "$f"
```

Then run **Deploy server** (§6). The deploy renders the new `.env` and
`docker compose up -d --build` recreates the containers whose configuration
changed.

> Use a deploy (or `up -d`), not `restart`, after any `.env` change. `.env`
> values reach the server through `${…}` in the compose `command:`, which compose
> fills in when it creates the container; `restart` reuses the old container and
> its old flags, so the old token would keep working. `up -d` recreates the
> container only when its config changed.

To rotate the shared token, use the same recipe with the edit step replaced by:

```bash
TOKEN=$(openssl rand -hex 24)
sed -i.bak "s/^MUNNEL_TOKENS=.*/MUNNEL_TOKENS=$TOKEN/" "$f" && rm -f "$f.bak"
# ...put-secret-value, rm, deploy; keep this shell open until you have
# distributed $TOKEN to devs. The old token stops working at the deploy.
```

### Files on the host do not survive a deploy

A deploy replaces everything in `/opt/munnel` except `.env` (rendered from the
secret) and `Caddyfile` (copied from `Caddyfile.example`). A hand-made file such
as `auth.json` or `revoked.txt`, or a hand edit to `docker-compose.yml`, is
deleted or overwritten at the next deploy. Anything the stack needs must come
from this repo or from a key in the secret. The two sections below describe the
server's options; use them with that in mind.

### Per-dev tokens with reserved subdomains (recommended as the team grows)

`munnel-server` supports an auth file mapping token → reserved subdomain.
Replace `--auth-tokens` with `--auth-file`: change `docker-compose.yml` in the
repo to drop the `--auth-tokens=...` line, add `- --auth-file=/auth.json` and a
volume `./auth.json:/auth.json:ro`, and get `auth.json` onto the host by a
route that survives a deploy (for example rendered from a new secret key). Each
dev then gets a guaranteed subdomain and can't claim another's.

```json
{ "aliceTokenHex": "alice", "bobTokenHex": "bob-app" }
```

### Signed, scoped tokens (no server-side token list)

For per-dev tokens with expiry + revocation without holding a list of every
token, use HMAC-signed tokens. The signing key is in `.env`
(`MUNNEL_SIGNING_KEY`); the server picks it up automatically (no flag needed).
Mint a token on the host, in an SSM session (§3):

```bash
cd /opt/munnel && docker compose exec -T munnel-server \
  /munnel-server mint --sub alice --ttl 7d
#   token: tok_<id>
#   m1.<payload>.<signature>
#   expires: <date>
```

Give the dev the `m1....` string. They connect with
`munnel 3000 -s alice -t m1....`. The token's `sub` claim overrides any
requested subdomain, so scoping is enforced by assignment. Revoke by adding
the token id (printed by `mint`) to a `--revoked-file` and restarting. Signed
and static tokens coexist. To mandate forward-auth on a token's tunnel, mint
with `--protect`:

```bash
docker compose exec -T munnel-server /munnel-server mint --sub staging --ttl 7d --protect
```

### Forward-auth (zero-trust) tunnels

A protected tunnel requires a viewer to log in before any request reaches the
dev's local service. The dev opts in with `--protect`:

```bash
munnel 3000 -s staging --protect
```

Viewers hit `https://staging.tunnels.momentumpay.xyz` → redirected to a login
form → after login, a session cookie authorizes access and the dev's app sees
`X-Authenticated-User: <whoever they entered>`. The header is always stripped
from incoming requests first, so viewers can't spoof it.

The dev server has **no auth provider** (`MUNNEL_AUTH_STUB=false` in `.env`
since 2026-10-13), so `--protect` tunnels, and signed tokens minted with
`--protect`, are refused at connect: `tunnel protection requested but server
has no auth provider configured`. Regular tunnels are unaffected and public by
design. Setting `MUNNEL_AUTH_STUB=true` in the secret (then a deploy) turns on
the **stub** provider, which trusts any submitted username, so a "protected"
tunnel is open to anyone who types a name: **dev/test only**. A real OIDC
provider is the production path (implement `forwardauth.Provider`). The
session-cookie HMAC key is `MUNNEL_SESSION_KEY` in `.env` (unused while no
provider is on; ephemeral if unset, so sessions don't survive a restart).

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

> The client must use `tunnels.momentumpay.xyz:7002` with `tls=true` (what
> `install-dev.sh` writes) for the control connection. The plaintext port 7001
> is closed in the security group: it sent the token in the clear. The public URL is always `https://<sub>.tunnels.momentumpay.xyz`
> (port 443, no port suffix).

### Rotating the token for all devs

Rotate in the secret (§4) to get the new `$TOKEN`, then each dev re-runs
`./install-dev.sh --token $TOKEN` (or edits `~/.munnel/config`). The old token
stops working the moment the deploy recreates the server container.

---

## 6. Deploying

The server image is built on the host from this repo's source. Every change
(Go code, Dockerfile, compose, Caddyfile, or a key in the secret) goes out the
same way: the **Deploy server** workflow.

### Deploy via GitHub Actions (manual)

`.github/workflows/deploy-server.yml` is triggered manually from the Actions tab
(no push/PR trigger), and only from `main`. Everything runs on GitHub-hosted
runners:

1. An optional `go test -race ./...` gate. The deploy aborts if a test fails.
2. The deploy job assumes the AWS deploy role through GitHub's OIDC provider (no
   AWS secret is stored in GitHub). The role may only run `ssm:SendCommand` with
   `AWS-RunShellScript` on this one instance and read the result; it trusts this
   repo's `main` branch only, so the job has no `environment:` (adding one
   changes the OIDC subject and the role refuses it).
3. It sends one SSM command. On the host (as root) the command fetches the commit
   into `/opt/munnel-src`, then runs `deploy/aws-ssm/host-deploy.sh <sha>`, which:
   rsyncs the source to `/opt/munnel` (`.env` and `Caddyfile` excluded), copies
   `Caddyfile.example` over `Caddyfile` in place, renders `.env` from the secret,
   runs `docker compose up -d --build --remove-orphans`, reloads Caddy, then
   checks `/healthz` and the ask endpoint from inside the caddy container.
4. The job polls the command every 10 s (up to ~18 min), prints the host's
   output prefixed with `| `, and fails unless the SSM status is `Success`. On a
   failed deploy the last 40 lines of the `munnel-server` log are in that output.

Run it: Actions → **Deploy server** → Run workflow. Inputs:

- **Run tests** (default on) — runs `go test -race ./...` first.
- **Reload Caddy** (default on) — reloads the Caddyfile after deploy (needed
  only if `Caddyfile.example` changed; harmless otherwise).

**One-time setup:** apply the landing-zone root `munnel-nonprod` (host, secret,
deploy role). Then set one repository secret and two repository variables from
its outputs. None of them is stored in this public repo. The role ARN is a
secret because the deploy job prints its step inputs and GitHub masks secrets,
not variables, in the public job log:

```bash
gh secret set   MUNNEL_DEPLOY_ROLE_ARN --repo mtufekci/munnel   # the deploy role's ARN
gh variable set MUNNEL_INSTANCE_ID     --repo mtufekci/munnel   # the instance ID
gh variable set MUNNEL_AWS_REGION      --repo mtufekci/munnel --body eu-central-1
```

The host script never prints the secret and never touches the `munnel_caddy_data`
volume (certificates), so a deploy does not itself reissue any certificate. The
exception is the first Caddy restart after the Caddyfile lost its ACME email
(§7): Caddy then looks only in the Let's Encrypt folder, so it reissues the
copied ZeroSSL certificates, from Let's Encrypt, on their next request.
The SSM output is cut at 24,000 characters, so the script shows only the tail of
the image build.

### Deploying by hand

If Actions is unavailable, do what the workflow does, in an SSM session (§3) as root:

```bash
. /etc/munnel/host.env
[ -d "$MUNNEL_SRC/.git" ] || git clone --no-checkout "$MUNNEL_REPO_URL" "$MUNNEL_SRC"
sha=<full commit id>
git -C "$MUNNEL_SRC" fetch --depth 1 origin "$sha"
git -C "$MUNNEL_SRC" checkout --detach --force "$sha"
bash "$MUNNEL_SRC/deploy/aws-ssm/host-deploy.sh" "$sha"     # add --no-caddy-reload to skip the reload
```

The image build takes ~2 min (Go build inside `golang:1.25-alpine`). Caddy is
a pulled image, no rebuild.

> **`.env` newline caveat**: the secret is the `.env` byte for byte. If you add a
> var to it by appending text, check the previous last line ended in a newline.
> Without it the append concatenates the new var onto the previous line (e.g.
> `MUNNEL_SCHEME=httpsMUNNEL_SIGNING_KEY=...`), which makes the server
> crash-loop on an invalid `--public-scheme`. Fix it in the secret (§4) and
> redeploy. The editing recipe in §4 keeps lines intact.

> **Caddyfile is bind-mounted as a single file.** `cp` rewrites it in place,
> which the running Caddy sees. Deleting and recreating it (e.g. `rsync
> --delete`) gives it a new inode, and Caddy keeps reading the old one even
> after `caddy reload`. The deploy script copies in place and recreates the
> container if it finds a stale mount. By hand: `docker compose up -d
> --force-recreate caddy` (certs live in the `munnel_caddy_data` volume and
> survive).

---

## 7. DNS and TLS

DNS is at Namecheap (the `momentumpay.xyz` zone). Both A
records point at the host's Elastic IP, TTL 300:

```
tunnels.momentumpay.xyz     A   <elastic-ip>
*.tunnels.momentumpay.xyz   A   <elastic-ip>
```

The Elastic IP is an output of the landing-zone root `munnel-nonprod`. It is kept
when the host is replaced, so the records do not change.

Caddy auto-obtains (Let's Encrypt, HTTP-01, no DNS plugin):
- the apex cert on startup (normal ACME), and
- a per-subdomain cert on each `*.tunnels.momentumpay.xyz` first request
  (on-demand TLS). Caddy first asks munnel-server's internal `:8081` ask
  listener, which approves only names with a live tunnel, so nobody can make
  the server request certs for made-up names.

The Caddyfile sets no ACME email on purpose: Let's Encrypt refuses the
`example.com` address the file used to carry (`invalidContact`), and it names
Let's Encrypt as the only issuer, so there is no ZeroSSL fallback and every
new certificate comes from Let's Encrypt. Caddy looks for a certificate only in
the folder of its configured issuer. A certificate it obtained earlier from
ZeroSSL, in `caddy/certificates/acme.zerossl.com-v2-dv90/`, is therefore used
only until Caddy's next start; a Caddy that was only reloaded keeps it in
memory until its renewal window opens, then gets a Let's Encrypt one. Caddy
never renews, moves or deletes the ZeroSSL files: they stay on disk, and the
new certificate goes in `acme-v02.api.letsencrypt.org-directory/`.

Certs and the ACME account are stored in the `munnel_caddy_data` docker volume
and auto-renewed; munnel-server serves the apex certificate on 7002 from the
same volume (read-only). A deploy never deletes or recreates that volume. If
the Elastic IP ever changes, update the A records and restart Caddy:
`docker compose restart caddy`.

The TLS control port (7002) reads the apex certificate from
`MUNNEL_TLS_CERT_FILE` / `MUNNEL_TLS_KEY_FILE` in the secret. On 28 Oct 2026
Caddy got the apex from Let's Encrypt and both keys now point at
`/caddy-data/caddy/certificates/acme-v02.api.letsencrypt.org-directory/<domain>/<domain>.crt|.key`.
Caddy renews in that same folder, so nothing is due. Caddy only reads the folder
of its configured issuer, so if the issuer ever changes, the two keys must
follow, before the old certificate expires. Check what 7002 serves with
`openssl s_client -connect <domain>:7002 -servername <domain> </dev/null | openssl x509 -noout -issuer -dates`.

---

## 8. Operations cheat sheet (all on the host, in an SSM session as root)

```bash
cd /opt/munnel

docker compose ps                       # stack status
docker compose logs -f munnel-server    # server log (tunnel up/down, handshakes)
docker compose logs -f caddy            # TLS issuance / proxy
# on-demand permission check: 200 = live tunnel (cert allowed), 403 = refused
docker exec munnel-caddy-1 wget -qSO /dev/null "http://munnel-server:8081/check?domain=<sub>.tunnels.momentumpay.xyz"
docker compose up -d munnel-server      # recreate after a changed .env (restart would keep the old values)
docker compose down                     # stop everything (never add -v: it deletes the certificate volume)
docker compose up -d                    # start everything
docker compose up -d --build            # rebuild after a code change
docker system df                        # disk usage by docker
df -h                                   # OS disk
```

Do not edit `/opt/munnel/.env` for a lasting change (§4); a deploy overwrites it.

Caddy config reload without restart (after editing Caddyfile):
```bash
docker exec munnel-caddy-1 caddy reload --config /etc/caddy/Caddyfile
```

---

## 9. Monitoring & alerts

- **Logs**: they stay in Docker on the host (`docker compose logs`, §8). There is
  no log shipping; CloudWatch Logs would be a small addition if wanted.
- **Alarms** (CloudWatch, defined in the landing-zone root `munnel-nonprod`):
  - status-check recover: the instance is recovered if the system status check fails;
  - status-check reboot: the instance is rebooted if the instance status check fails;
  - CPU > 80% for 15 min.
- All alarms notify the SNS topic `munnel-alerts`, which emails the operator. The
  recipient must confirm the subscription once. To change the recipient, change it
  in the landing-zone root and apply.

---

## 10. Backups & state

There is no precious state to back up:
- munnel-server is stateless (tunnels live in memory).
- The `.env` is in Secrets Manager (versioned; `aws secretsmanager
  list-secret-version-ids --secret-id munnel/nonprod/server-env` shows the history).
- Caddy's certificates and ACME account are in the host's `munnel_caddy_data`
  volume. They are not backed up: if the volume is lost, Caddy reissues on
  demand (mind the ACME rate limits if it happens repeatedly), but the apex
  certificate that 7002 serves changes with it.

Rebuilding from scratch: apply the landing-zone root, then run **Deploy server**.
The source of truth is this repo plus the secret.

---

## 11. Troubleshooting

| Symptom | Check |
|--------|-------|
| Client can't connect to `:7002` | `nc -zv tunnels.momentumpay.xyz 7002` from the dev box. If it fails, the security group rule for 7002 may have been removed. A TLS/certificate error: `openssl s_client -connect tunnels.momentumpay.xyz:7002 </dev/null` and check `MUNNEL_TLS_*` in the secret. If 7002 serves an expired or wrong certificate, check that `MUNNEL_TLS_CERT_FILE` / `MUNNEL_TLS_KEY_FILE` point at the folder of the issuer Caddy uses (§7), fix them with `put-secret-value`, redeploy. |
| Client times out on `:7001` | 7001 (plaintext) is closed. Set `server=tunnels.momentumpay.xyz:7002` and `tls=true` in `~/.munnel/config`, or re-run `install-dev.sh`. |
| `curl https://sub.tunnels...` → TLS error / no cert | Certs are issued only while a tunnel holds the name: no live tunnel → TLS error, by design. With a tunnel up, the first request triggers issuance (can take ~10-30s); retry. Check `docker compose logs caddy` for `certificate obtained` or ask refusals, and the `wget` ask check in §8. |
| `curl https://sub.tunnels...` → 502/504 | No tunnel registered for that subdomain, or the dev's local server is down. `docker compose logs munnel-server` shows `tunnel up/down`. |
| Caddy restart-looping | Usually a Caddyfile parse error. `docker compose logs caddy` prints the line. `on_demand_tls` must have an `ask` URL (mandatory in Caddy v2.8+). |
| munnel-server restart-looping (`--public-scheme must be http or https`) | A `.env` var got concatenated onto the previous line (missing trailing newline in the secret — see §6 caveat). `docker compose config \| grep public-scheme` shows the mangled value. Fix the secret and redeploy. |
| 8080 reachable from the internet | It shouldn't be. Compose binds `127.0.0.1:8080:8080` and the security group has no rule for it. If exposed, the repo/host compose drifted — fix the port binding. |
| Workflow fails at "Assume the deploy role" (`Not authorized to perform sts:AssumeRoleWithWebIdentity`) | The run was not on `main`, or the job gained an `environment:` (changes the OIDC subject), or the `MUNNEL_DEPLOY_ROLE_ARN` secret / `MUNNEL_AWS_REGION` variable is wrong. |
| Workflow fails at `send-command` (`AccessDenied`, `InvalidInstanceId`) | `MUNNEL_INSTANCE_ID` points at another instance (the role is limited to one), or the SSM agent on the host is offline: `aws ssm describe-instance-information --profile <nonprod-profile> --region eu-central-1`. |
| Deploy status `TimedOut` or `Failed` | Read the `| ` host output in the job log and the `details:` in the error line. `DeliveryTimedOut` / `Undeliverable`: the host is unreachable by SSM (stopped, or its role lost SSM permissions). `ExecutionTimedOut`: the script ran past 900 s. Output is cut at 24,000 characters; the full log is on the host. |
| Deploy says the secret does not parse as a compose `.env` | The secret has a malformed line (an unclosed quote, say). Compose's error quotes the line, so it is withheld from the public job log. Fix the secret (§4) and redeploy; to see the error, run `docker compose config --quiet` in `/opt/munnel` in an SSM session. The live `.env` was left alone. |
| Deploy says the secret has no value | `put-secret-value` was never run for `munnel/nonprod/server-env` (§4). The live `.env` was left alone. |
| Deploy says the checkout is at a different commit | Something moved `/opt/munnel-src` between the fetch and the script. Re-run the deploy. |
| Host replaced or capacity error creating it | Change it in the landing-zone root (`t3a.small`, x86, is the no-surprise fallback to the Graviton `t4g.small`). The host must have `/etc/munnel/host.env` and restored certificates (`munnel_caddy_data`) before the first deploy. |
| Can't open an SSM session | `aws sso login --profile <nonprod-profile>`; the Session Manager plugin must be installed; your role needs `ssm:StartSession` on the instance (§3). |

---

## 12. Cost

About USD 20 a month, running 24/7, on the account's AWS credits:

| Item | USD / month |
|------|-------------|
| EC2 `t4g.small` | 14.02 |
| gp3 20 GiB | 1.90 |
| Elastic IP | 3.65 |
| Secrets Manager secret | 0.40 |
| CloudWatch alarms | 0.30 |
| **Total** | **~20.27** |

Egress is a few GB a month, inside AWS's free allowance. DNS records: cost is at
Namecheap. (On Azure the same setup cost about GBP 60 a month.)

---

## 13. Teardown (if ever needed)

Teardown is a landing-zone change (the root `munnel-nonprod`), not a command in
this repo. The host and the Elastic IP have `prevent_destroy`, so `tofu destroy`
refuses until that lifecycle setting is removed in the code and applied on
purpose. That removes the host, address, network, secret, alarms and deploy
role. Then, outside AWS:

- remove the `tunnels` and `*.tunnels` A records at Namecheap;
- delete the repository secret `MUNNEL_DEPLOY_ROLE_ARN` and the repository
  variables `MUNNEL_INSTANCE_ID` and `MUNNEL_AWS_REGION`.

Secrets Manager keeps a deleted secret for its recovery window unless it is
force-deleted.
