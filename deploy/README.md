# Deploying Claude Cloak

Three supported shapes, one shared idea: resolve the locked dependency set
once at deploy time with `uv sync --locked --no-dev`, then run the resulting
entry point directly. Nothing resolves at boot.

| Target | Use when | Guide |
|---|---|---|
| **systemd** | Linux VM dedicated to the proxy — the native default | [below](#1-native-systemd-linux) |
| **Docker** | The VM already runs containers, or you want image rollback | [below](#2-docker) |
| **Windows** | The VM is Windows | [below](#3-windows) |

## Constraints that shape every deployment

**One process. Always.** Quota counters, coach counters and the captured
device identity are in-process state, by design (`state.py`). A second worker
or replica splits every counter, enforces each user's cap twice, and lets two
workers race to capture the identity. Never pass `--workers`, never scale the
service.

**No reverse proxy unless you configure one.** Every IP gate — `ALLOWED_IPS`,
`ADMIN_IPS`, `STATS_VIEW_IPS`, per-user labels — judges the TCP peer address.
Put nginx or Caddy in front without telling the proxy, and the peer becomes
the proxy: the whitelist rejects your real users while `ADMIN_IPS`, which
defaults to loopback, hands the config console to every visitor. If you do
need one, list it in `TRUSTED_PROXY_IPS` — the proxy will then take the client
address from `X-Forwarded-For`, but only for connections that genuinely come
from a listed address.

**The guides below avoid the problem entirely** by terminating TLS inside the
proxy, so there is no extra hop and the peer is always the real client.

---

## Getting a hostname and a certificate

Let's Encrypt does not issue certificates for bare IP addresses, so
`https://203.0.113.10:9999` can never be secured as-is. Azure gives every
public IP a free, real DNS name — that is enough.

### Step 1 — make the public IP static and give it a DNS label

A dynamic address can change when the VM is deallocated, which breaks both
the DNS record and the certificate. Make it static first.

```bash
az network public-ip update \
  --resource-group <rg> --name <public-ip-name> \
  --allocation-method Static \
  --dns-name <label>          # must be unique within the region
```

Azure appends the region and registers the record in its own DNS, producing:

```
<label>.<region>.cloudapp.azure.com     e.g. claude-cloak.eastus.cloudapp.azure.com
```

Confirm it resolves to the VM before going further:

```bash
az network public-ip show -g <rg> -n <public-ip-name> --query "{fqdn:dnsSettings.fqdn, ip:ipAddress}" -o tsv
dig +short <label>.<region>.cloudapp.azure.com
```

In the portal the same setting is **Public IP address → Configuration → DNS
name label**.

### Step 2 — open 80 and 443 in the NSG

Port 80 is needed for the ACME http-01 challenge, and afterwards it only
redirects to HTTPS. Port 443 carries the traffic.

```bash
az network nsg rule create -g <rg> --nsg-name <nsg> --name allow-https \
  --priority 1000 --destination-port-ranges 443 --access Allow --protocol Tcp
az network nsg rule create -g <rg> --nsg-name <nsg> --name allow-http-acme \
  --priority 1010 --destination-port-ranges 80 --access Allow --protocol Tcp
```

Leave the old `9999` rule in place until every client has moved, then delete it.

> Azure's NSG is not the proxy's whitelist. The NSG must allow 80/443 from
> anywhere so Let's Encrypt can reach the challenge; `ALLOWED_IPS` inside the
> proxy is what actually restricts who may spend tokens.

### Step 3 — issue the certificate

First issue with the proxy stopped, because certbot needs port 80 to itself
for one moment:

```bash
sudo apt install -y certbot
sudo systemctl stop claude-cloak            # only for the very first issue
sudo certbot certonly --standalone -d <label>.<region>.cloudapp.azure.com \
     --agree-tos -m you@example.com --no-eff-email
```

Certificates land in `/etc/letsencrypt/live/<fqdn>/`.

### Step 4 — renew without downtime

Once the proxy runs with `HTTP_REDIRECT_PORT=80` and `ACME_WEBROOT` set, it
serves the challenge itself, so renewals need no stop:

```bash
sudo certbot certonly --webroot -w /var/lib/claude-cloak/acme \
     -d <label>.<region>.cloudapp.azure.com --cert-name <fqdn> --force-renewal
sudo install -m 755 deploy/systemd/certbot-deploy-hook.sh \
     /etc/letsencrypt/renewal-hooks/deploy/claude-cloak.sh
sudo certbot renew --dry-run
```

certbot's own timer handles renewal from then on; the deploy hook restarts the
proxy (about a second) only when a certificate actually changed — uvicorn
reads the certificate once at startup.

---

## 1. Native systemd (Linux)

```bash
git clone https://github.com/phongptn93/claude-cloak && cd claude-cloak
sudo deploy/systemd/install.sh
sudo -e /var/lib/claude-cloak/.env
sudo systemctl restart claude-cloak
systemctl status claude-cloak
journalctl -u claude-cloak -f
```

The relevant part of `/var/lib/claude-cloak/.env`:

```ini
DEPLOY_MODE=server
LOCAL_HOST=0.0.0.0
LOCAL_PORT=443
HTTP_REDIRECT_PORT=80
ACME_WEBROOT=/var/lib/claude-cloak/acme
PUBLIC_HOSTNAME=<label>.<region>.cloudapp.azure.com
TLS_CERTFILE=/etc/letsencrypt/live/<fqdn>/fullchain.pem
TLS_KEYFILE=/etc/letsencrypt/live/<fqdn>/privkey.pem

ALLOWED_IPS=203.0.113.5,198.51.100.0/24
ADMIN_TOKEN=<openssl rand -hex 32>
SESSION_SECRET=<openssl rand -hex 32>   # pin it, or admin sessions drop on restart
```

The unit binds 80 and 443 as an unprivileged user through
`AmbientCapabilities=CAP_NET_BIND_SERVICE`, and reads the certificates
read-only. `certbot` keeps `/etc/letsencrypt` root-owned; the service user
needs read access to the `live` and `archive` trees:

```bash
sudo setfacl -Rm u:claude-cloak:rX /etc/letsencrypt/live /etc/letsencrypt/archive
```

To deploy a new revision: `sudo deploy/systemd/install.sh main`. `.env` and the
persisted counters are never touched.

## 2. Docker

```bash
cp deploy/docker/.env.example deploy/docker/.env   # set CLOAK_DOMAIN
docker compose -f deploy/docker/compose.yaml up -d --build
```

The image is a two-stage build: uv resolves into `/app/.venv` in the builder,
and the runtime stage carries only that venv — no uv, no pip, no compiler,
running as uid 10001. `--locked` fails the build if `uv.lock` and
`pyproject.toml` have drifted, so an image is always the reviewed dependency
set.

Ports are published `443:9999` and `80:8080`, which is why the compose file
sets `PUBLIC_HTTPS_PORT=443`: the process binds 9999 but clients arrive on
443, and the redirect must point at what clients can reach.

The proxy's own settings live in the `cloak-data` volume, at `/data/.env`.
Seed it before the first start:

```bash
docker compose -f deploy/docker/compose.yaml run --rm --entrypoint sh proxy \
  -c 'cat > /data/.env' < client/.env.example
```

## 3. Windows

```powershell
# elevated PowerShell
.\deploy\windows\install-service.ps1
notepad C:\ProgramData\claude-cloak\.env
schtasks /run /tn ClaudeCloakServer
```

For TLS use [win-acme](https://www.win-acme.com/); it can write PEM files
directly, which is what `TLS_CERTFILE`/`TLS_KEYFILE` expect:

```powershell
wacs.exe --target manual --host <label>.<region>.cloudapp.azure.com `
         --store pemfiles --pemfilespath C:\ProgramData\claude-cloak\tls `
         --installation script --script "powershell.exe" `
         --scriptparameters "-File C:\Program Files\claude-cloak\renew-cert.ps1"
```

win-acme installs its own renewal task; `renew-cert.ps1` restarts the proxy
when a certificate changes.

---

## Pointing clients at it

On each machine:

```bash
uv run claude-cloak-setup --remote https://<label>.<region>.cloudapp.azure.com/u/<username>
```

Verify from the client side — this also confirms the whitelist and the cap:

```bash
curl https://<label>.<region>.cloudapp.azure.com/u/<username>/whoami
```

## Operational checks

```bash
curl -s https://<fqdn>/health  | jq '{identity_captured, deploy, stream}'
curl -s https://<fqdn>/quota   | jq '{cost_usd_total, messages_requests}'
curl -s https://<fqdn>/quota/users | jq '.users[] | {label, cost_usd, over_cap}'
```

`/health`'s `stream` block is the first place to look when a client reports
"Response stalled mid-stream": a non-zero `stalls` points at the upstream
connection, while a high `ttfb_ms_avg` together with `pool_waits` means the
connection pool is too small for the traffic.
