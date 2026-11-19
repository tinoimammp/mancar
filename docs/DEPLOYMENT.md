# Deployment guide

This guide takes a fresh VPS to a working gateway. Commands assume Docker with
the Compose plugin is installed.

## 1. What you need

| Item | Notes |
|---|---|
| VPS with public IPv4 | 1 vCPU / 1 GB RAM is enough to start |
| Domain on Cloudflare | Free plan is fine; the DNS-01 workflow needs no paid feature |
| Open ports | `80/tcp`, `443/tcp`, `443/udp`, and the TCP tunnel range (default `20000-20099/tcp`) |

Use a dedicated domain or a dedicated subdomain (for example `tunnel.example.com`)
as `BASE_DOMAIN`: every name under it will be handed out to tunnels.

## 2. DNS

In the Cloudflare dashboard, zone of your domain, create:

```text
Type  Name   Content                 Proxy status
A     @      <VPS public IPv4>       DNS only
A     *      <VPS public IPv4>       DNS only
```

If `BASE_DOMAIN` is `tunnel.example.com`, the names are `tunnel` and `*.tunnel`.
Add matching `AAAA` records only if the server really has working IPv6.

### Why "DNS only"

The orange-cloud proxy must be **off** for two reasons:

1. Agents connect with an HTTP `Upgrade: mancar/1` handshake. Cloudflare's
   proxy only passes WebSocket upgrades.
2. TCP tunnels listen on arbitrary ports of your server; the proxy forwards only
   a fixed set of HTTP(S) ports.

The wildcard certificate does not need the proxy either: it is obtained through
the DNS API (challenge DNS-01), so no inbound connection from Let's Encrypt is
required.

## 3. Cloudflare API token

Create a token at *My Profile → API Tokens → Create Token → Custom token*:

* Permissions: **Zone → DNS → Edit**, and **Zone → Zone → Read**
* Zone resources: **Include → Specific zone →** your domain only

Never use the Global API Key. The token is used only to publish and remove the
`_acme-challenge` TXT records. The Caddy DNS plugin documents the two
permissions above; if certificate issuance fails with a permissions error, check
them first (this guide could not verify them against a live Cloudflare account).

## 4. Firewall

Open `80/tcp`, `443/tcp`, `443/udp` and the TCP tunnel range.

> **Docker and ufw:** ports published by Docker bypass `ufw` rules. Do not rely
> on `ufw deny` to hide a published port; narrow the range in `.env` instead
> (`TCP_PORT_MIN` / `TCP_PORT_MAX`) or use the cloud provider's firewall.

PostgreSQL and the gateway's internal HTTP port are **not** published; they are
reachable only on the Compose network.

## 5. Configure and start

```bash
git clone https://github.com/tinoimammp/mancar.git && cd mancar
cp .env.example .env
./scripts/setup.sh      # generates JWT_SECRET, ENCRYPTION_KEY, POSTGRES_PASSWORD once
```

Edit `.env` and set the three remaining values:

```env
BASE_DOMAIN=tunnel.example.com
ACME_EMAIL=you@example.com
CLOUDFLARE_API_TOKEN=...
```

`scripts/setup.sh` never overwrites a value that is already set, so it is safe to
run again. **Back up `.env`**, ideally somewhere other than the server: it holds
every secret.

First, try with Let's Encrypt's staging CA so a typo cannot burn production rate
limits (browsers will not trust the staging certificate):

```bash
echo 'ACME_CA=https://acme-staging-v02.api.letsencrypt.org/directory' >> .env
docker compose up -d
docker compose logs -f caddy      # wait for "certificate obtained successfully", twice
```

Two certificates are issued: one for `*.BASE_DOMAIN`, one for `BASE_DOMAIN`.
When that works, remove the `ACME_CA` line, then:

```bash
docker compose stop caddy && docker compose rm -f caddy && docker volume rm mancar_caddy_data   # drop the staging certificates
docker compose up -d
```

Check that everything is healthy:

```bash
docker compose ps                                  # all services "healthy"
curl -fsS https://tunnel.example.com/healthz       # -> ok
```

## 6. Create the first token and connect

```bash
docker compose exec gateway /mancard token create --user alice --name laptop
```

The token (`mc_` followed by 64 characters) is printed once. On the user's machine:

```bash
mancar config set server https://tunnel.example.com
mancar config set token -          # paste, Ctrl+D
mancar http 3000
```

## 7. Upgrading

```bash
scripts/backup.sh                    # before releases that change the database
docker compose pull                  # download first: the running gateway keeps serving
docker compose up -d --wait          # swap the containers (tunnels pause ±15-45 s), wait until healthy
```

The server never compiles anything: it runs the released images. Wait until the
release on GitHub is finished (its images are published) before upgrading. In
production pin a version in `.env`, written **without** a `v`
(`MANCAR_VERSION=0.7.0`, the image tag); a tag that does not exist makes `pull`
fail and leaves the running gateway untouched. Database migrations run when the
new gateway starts. Agents reconnect on their own and keep their hostnames.

## Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| `docker compose up` stops with *"X is required"* | `.env` is incomplete; the message names the variable |
| Caddy keeps logging `obtain` errors | Wrong or under-scoped Cloudflare token; the zone is not the one of `BASE_DOMAIN`; or DNS records missing |
| `too many certificates` / `rate limit` | You hit Let's Encrypt limits. Use the staging CA while testing; wait for the window to pass |
| Agent: *"rejected the agent token"* | Token mistyped, revoked, or created for another deployment. `docker compose exec gateway /mancard token list` |
| Agent: *"refusing http://..."* | The server URL must be `https://` (plain http is only allowed for localhost) |
| Agent: *"TLS handshake ... failed"* | Certificate not issued yet, or you are still on the staging CA |
| Agent loops on *"RECONNECTING"* with `429` | Too many failed logins from your address (limit: `AUTH_FAILURE_LIMIT_PER_MINUTE`, per minute); wait and fix the token |
| `https://name.domain` shows *"tunnel not found"* | The agent is offline, or the name differs. `mancar status` |
| `502 ... local service is not reachable` | Nothing listens on the local port the agent forwards to |
| TCP tunnel unreachable from outside | The port range is not open in the firewall, or is outside `TCP_PORT_MIN..MAX` |
| Public request returns `503 tunnel_busy` | The per-tunnel connection limit was reached (`MAX_CONNECTIONS_PER_TUNNEL`) |
