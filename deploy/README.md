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

Certificates land in `/etc/letsencrypt/live/<fqdn>/`. Publish them to the
service and start it:

```bash
sudo /etc/letsencrypt/renewal-hooks/deploy/claude-cloak.sh \
     /etc/letsencrypt/live/<fqdn>
```

### Step 4 — switch renewal to webroot, so it never needs downtime

**This step is not optional.** The first issue above used `--standalone`,
and certbot records that in the renewal config. Standalone needs port 80 to
itself, which the running proxy now holds — so every future automatic
renewal would fail, quietly, until the certificate expires and every client
drops at once. Re-issue once through the webroot to rewrite that config:

```bash
sudo certbot certonly --webroot -w /var/lib/claude-cloak/acme \
     -d <label>.<region>.cloudapp.azure.com --cert-name <fqdn> --force-renewal
grep authenticator /etc/letsencrypt/renewal/<fqdn>.conf     # must say: webroot
```

The proxy serves `/.well-known/acme-challenge/` itself from `ACME_WEBROOT`,
so from here renewals happen with the service running.

### Step 5 — verify the automation

certbot ships its own scheduled renewal; installing it is not something you
need to do. Confirm it is armed and that a renewal actually succeeds against
the running proxy:

```bash
systemctl list-timers certbot.timer      # ExecStart=/usr/bin/certbot -q renew
sudo certbot renew --dry-run             # proxy stays up throughout
```

`certbot renew` is safe to run at any frequency: as of certbot 4.0 it only
acts when less than a third of the certificate's lifetime remains (30 days
of a 90-day certificate; earlier versions used a fixed 30 days). The deploy
hook fires only when a certificate really changed.

Renewal is the part of this deployment most likely to break silently, so the
proxy reports what it is actually serving:

```bash
curl -s https://<fqdn>/health | jq .tls
# {"enabled":true,"status":"ok","expires_at":"...","days_remaining":89.9}
```

`status` goes to `warning` under 21 days and `critical` under 7 — both mean
automatic renewal has already missed a window and needs looking at.

---

## 1. Native systemd (Linux)

Install from a published release — no clone, no build, no toolchain on the
host beyond its own python3:

```bash
curl -fsSL https://raw.githubusercontent.com/phongptn93/claude-cloak/main/deploy/install-from-release.sh | sudo bash
sudo -e /var/lib/claude-cloak/.env
sudo systemctl restart claude-cloak
journalctl -u claude-cloak -f
```

Pin a version, or install from an internal mirror:

```bash
sudo ./install-from-release.sh v0.2.0
sudo BASE_URL=http://10.0.0.5/releases ./install-from-release.sh v0.2.0
```

The script downloads the bundle, checks it against the release's
`SHA256SUMS`, and refuses to install on a mismatch. Where `gh` and a token
are available it also runs `gh attestation verify`, which ties the bundle to
the workflow run and commit that produced it.

Upgrading is the same command; `.env` and the persisted counters are never
touched. To roll back, install the previous tag.

<details>
<summary>Installing from a source checkout instead</summary>

```bash
git clone https://github.com/phongptn93/claude-cloak && cd claude-cloak
sudo deploy/systemd/install.sh          # falls back to uv sync --locked
```

This needs uv on the host and is the path used while developing.
</details>

The relevant part of `/var/lib/claude-cloak/.env`:

```ini
DEPLOY_MODE=server
LOCAL_HOST=0.0.0.0
LOCAL_PORT=443
HTTP_REDIRECT_PORT=80
ACME_WEBROOT=/var/lib/claude-cloak/acme
PUBLIC_HOSTNAME=<label>.<region>.cloudapp.azure.com
TLS_CERTFILE=/var/lib/claude-cloak/tls/fullchain.pem
TLS_KEYFILE=/var/lib/claude-cloak/tls/privkey.pem

ALLOWED_IPS=203.0.113.5,198.51.100.0/24
ADMIN_TOKEN=<openssl rand -hex 32>
SESSION_SECRET=<openssl rand -hex 32>   # pin it, or admin sessions drop on restart
```

The unit binds 80 and 443 as an unprivileged user through
`AmbientCapabilities=CAP_NET_BIND_SERVICE`. It never reads
`/etc/letsencrypt`: the deploy hook copies the certificate into
`/var/lib/claude-cloak/tls/` with the right ownership, which is what
`TLS_CERTFILE`/`TLS_KEYFILE` point at.

Do **not** try to grant the service user access to the letsencrypt tree
instead. It appears to work and then fails on the first renewal — certbot
writes a new `privkey<N>.pem` into `archive/` each time, and a plain
`setfacl -Rm` only covers the files that existed when it ran. The service
then crash-loops on a key it cannot read, unattended, two months later.

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
  -c 'cat > /data/.env' < .env.example
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

## Release pipeline

`.github/workflows/release.yml` runs on a `v*` tag:

| Job | What it guarantees |
|---|---|
| `verify` | `uv sync --locked`, ruff, ty, pytest — a tag whose lockfile drifted fails here, not on a host |
| `build` | Refuses a tag that disagrees with the project version; builds the bundle; publishes SHA256SUMS and a signed build provenance attestation |
| `smoke` | Installs the bundle in a bare `ubuntu:24.04` container with no uv, no git and no compiler, then imports the app and asserts the br/zstd decoders are present — the consumer's copy is tested, not the build environment's |
| `publish` | Attaches the bundle to the GitHub Release |

Cutting a release:

```bash
uv version --bump patch          # or minor/major
git commit -am "release: $(uv version --short)"
git tag "v$(uv version --short)" && git push --follow-tags
```

Hosts then upgrade with the same `install-from-release.sh` they installed
with.

## Running alongside another service on the same VM

The question comes up as soon as a second HTTPS service wants port 443 — a
chat-platform bot endpoint, for instance, which typically serves plain HTTP
on a local port and needs a public HTTPS URL with a chain-trusted
certificate for the platform to deliver webhooks to.

The two have **opposite exposure requirements**, and that decides the shape:

| | claude-cloak | a bot / webhook endpoint |
|---|---|---|
| Who may connect | your team's IPs only | the platform's servers, from undisclosed dynamic IPs |
| Client IP | load-bearing — every gate judges it | irrelevant; requests carry their own signed auth |
| TLS | terminates in-process, by design | needs a terminator in front |

Putting both behind one shared reverse proxy forces `443` open to the
internet, which throws away claude-cloak's network-layer restriction and
leaves only the application-level `ALLOWED_IPS`. Better to keep them apart.

### Recommended: a second public IP on the same VM

Azure lets one NIC carry several IP configurations, each with its own public
IP and its own DNS label. Give each service an address and the conflict
disappears — no shared proxy, no shared failure, and claude-cloak keeps
seeing real client addresses.

```bash
RG=rg-claude-cloak
az network public-ip create -g $RG -n public-ip-svc2 --sku Standard \
   --allocation-method Static --dns-name <second-label>
NIC=$(az network nic list -g $RG --query "[0].name" -o tsv)
az network nic ip-config create -g $RG --nic-name $NIC -n ipconfig-svc2 \
   --private-ip-address 10.0.0.5 --public-ip-address public-ip-svc2
sudo reboot     # the OS only picks up a new IP configuration on restart
```

Then bind each service to its own private address — Azure maps each to its
matching public IP:

```ini
# /var/lib/claude-cloak/.env
LOCAL_HOST=10.0.0.4          # primary IP config
```

Under Docker, `LOCAL_HOST` stays `0.0.0.0` — that is the address *inside* the
container. The interface is chosen by the publish map instead:

```yaml
    ports:
      - "10.0.0.4:443:9999"
      - "10.0.0.4:80:8080"
```

```caddy
# /etc/caddy/Caddyfile — Caddy fronts ONLY the second service, and obtains
# its own certificate for the second label. claude-cloak is untouched.
<second-label>.<region>.cloudapp.azure.com {
    bind 10.0.0.5
    reverse_proxy 127.0.0.1:<service-port>
}
```

NSG rules target the destination address, so each service keeps its own
policy:

```bash
az network nsg rule create -g $RG --nsg-name <nsg> -n allow-https-cloak \
   --priority 1020 --destination-address-prefixes 10.0.0.4 \
   --destination-port-ranges 443 --source-address-prefixes <team IPs> --access Allow --protocol Tcp
az network nsg rule create -g $RG --nsg-name <nsg> -n allow-https-svc2 \
   --priority 1030 --destination-address-prefixes 10.0.0.5 \
   --destination-port-ranges 443 --source-address-prefixes Internet --access Allow --protocol Tcp
```

Cost: one extra Standard static IPv4 address, $0.005/hour — about $3.65 a
month (Azure retail price, southeastasia, at the time of writing).

### Alternatives

**Separate ports on one IP** — free. The other service takes 443, claude-cloak moves to
`LOCAL_PORT=8443`; both read the same certificate, and the certbot deploy
hook restarts both. Clients set `https://<fqdn>:8443/u/<name>`. The cost is
a non-standard port, which some restrictive networks block.

**One shared reverse proxy** — supported: list the proxy in
`TRUSTED_PROXY_IPS` and claude-cloak will take the client address from
`X-Forwarded-For` for connections that genuinely come from it. Use `Caddy`
with `flush_interval -1` so SSE is not buffered. Accept that `443` is then
open to the internet for everyone, and that a proxy restart drops both
services at once.

**Separate VMs** — the cleanest isolation, and the obvious answer if the
other service ever needs to scale, since claude-cloak cannot run more than one process.
Costs a second VM (`Standard_B2s`, ~$38.54/month in southeastasia).

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
