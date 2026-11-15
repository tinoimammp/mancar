# mancar

A self-hosted tunnelling platform: expose a service on your laptop to the
internet through **your own server and your own domain**, with automatic HTTPS.
No third-party tunnelling provider is involved.

```text
$ mancar http 3000 --subdomain my-api

Tunnel established.

Forwarding:
https://my-api.mydomain.com
    -> http://localhost:3000

Status: ONLINE
Protocol: HTTP
TLS: ENABLED
```

> **Status: early but real.** The core (HTTP, WebSocket and TCP tunnels, custom
> and random subdomains, per-user tokens, PostgreSQL, Docker deployment) is
> implemented and tested. Much of what makes ngrok *ngrok* (dashboard, traffic
> inspector, auth policies, custom domains, UDP, ...) is **not built yet**.
> Read [docs/STATUS.md](docs/STATUS.md) for the exact, honest list before you
> depend on this.

## How it works

```text
 public client ──HTTPS──▶ ┌────────┐      ┌─────────────┐      ┌──────────┐
 (browser, curl)          │ Caddy  │─────▶│  mancard  │─────▶│ Postgres │
                          │  edge  │ HTTP │  (gateway)  │      └──────────┘
 mancar agent ─HTTPS──▶ └────────┘      └──────┬──────┘
 (your laptop)   upgrade     TLS, wildcard cert  │ one multiplexed connection per agent
        ▲                                        ▼
        └──────────── requests are streamed back to the agent, which dials
                      only the local address you configured
```

* The **agent** (`mancar`) opens one outbound, authenticated connection to the
  gateway. Nothing on your machine listens for the internet.
* The **gateway** (`mancard`) maps `name.yourdomain.com` to the agent that owns
  it and streams requests through that connection. Hostname ownership is decided
  atomically in PostgreSQL, never by DNS lookups.
* The **edge** (Caddy) terminates TLS with a wildcard certificate obtained
  automatically through the Cloudflare DNS API.

Design details: [docs/adr](docs/adr), wire protocol: [docs/protocol.md](docs/protocol.md).

## Requirements

* A VPS with a public IPv4 address and Docker with the Compose plugin
* A registered domain whose DNS is managed by **Cloudflare**
* Ports **80**, **443** (TCP and UDP) and the TCP-tunnel range (default
  20000-20099) reachable from the internet

## Install the server

```bash
git clone https://github.com/tinoimammp/mancar.git
cd mancar
cp .env.example .env
./scripts/setup.sh        # generates the three secrets, once
nano .env                 # fill in BASE_DOMAIN, ACME_EMAIL, CLOUDFLARE_API_TOKEN
docker compose up -d
```

Before the first start, create these two DNS records in Cloudflare, **DNS only**
(grey cloud, *not* proxied; see [why](docs/DEPLOYMENT.md#why-dns-only)):

```text
A   @   <your VPS public IP>
A   *   <your VPS public IP>
```

Then create a token for a user and hand it to them:

```bash
docker compose exec gateway /mancard token create --user alice --name laptop
```

Or use the web dashboard at `https://mydomain.com/dashboard/`. Create an admin
account first (a strong password is generated and shown once):

```bash
docker compose exec gateway /mancard admin set --user admin
```

Already running nginx on ports 80/443? See [docs/NGINX.md](docs/NGINX.md).

Step-by-step with troubleshooting: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Use the client

Download `mancar` for your platform from the releases page (or `make build`).

```bash
mancar config set server https://mydomain.com
mancar config set token -        # paste the token, then Ctrl+D (keeps it out of shell history)

mancar http 3000                      # prompts: random or custom subdomain
mancar http 3000 --subdomain my-api   # non-interactive, custom
mancar http 8080 --random             # non-interactive, random
mancar tcp 5432                       # raw TCP, e.g. PostgreSQL

mancar config add-tunnel web http 3000 --subdomain my-api
mancar config add-tunnel db  tcp  5432
mancar start                          # all saved tunnels at once

mancar status                         # what is running
mancar stop                           # stop everything (or: stop PID)
mancar version
```

If a custom name is taken, an interactive session asks for another one; a
non-interactive one fails with a clear message. A disconnected agent keeps its
name reserved for you (24 h for custom names, 5 min for random ones) so a
reconnect gets the same address.

## What you get today

* HTTP/HTTPS tunnels, including WebSocket and streaming responses
* TCP tunnels on a configurable public port range
* Random (`blue-falcon`) and custom subdomains with atomic reservation
* Per-user agent tokens (stored only as hashes), revocable instantly
* Web dashboard: live agents and tunnels, token, user and hostname management
* Automatic reconnect with backoff; the public address survives reconnects
* Limits on tunnels, agents, connections and request size; failed-login rate limiting
* Structured JSON logs, health checks, graceful shutdown
* PostgreSQL with versioned, atomic migrations; backup and restore scripts

## Documentation

| | |
|---|---|
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | DNS, Cloudflare token, firewall, first start, troubleshooting |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | Tokens, backups, upgrades, logs, monitoring, limits |
| [docs/SECURITY.md](docs/SECURITY.md) | Threat model, what is and is not protected, hardening |
| [docs/protocol.md](docs/protocol.md) | Agent/gateway wire protocol |
| [docs/STATUS.md](docs/STATUS.md) | Feature-by-feature status and test evidence |
| [docs/adr](docs/adr) | Architecture decisions |

## Development

```bash
make check            # gofmt, vet, tests with the race detector, shellcheck
make build            # bin/mancard and bin/mancar
make dist             # release binaries for all platforms + SHA256SUMS
make e2e-edge         # real Caddy in front of the real gateway (needs caddy)
```

PostgreSQL tests run when `TEST_DATABASE_URL` is set (see the `Makefile`). The
module path in this repository is the placeholder `github.com/tinoimammp/mancar`;
`scripts/rename-module.sh github.com/you/repo` replaces it everywhere.

## License

MIT, see [LICENSE](LICENSE).
