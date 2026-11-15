# mancar

Self-hosted tunnels: put a service running on your laptop on the internet
through **your own server and your own domain**, with automatic HTTPS. Like
ngrok, but you run it.

```text
$ mancar http 3000 --subdomain my-api

Forwarding:
https://my-api.example.com  ->  http://localhost:3000
```

There are two programs:

| Program | Runs on | What it does |
|---|---|---|
| `mancard` | your server (Docker) | the gateway: receives public traffic and the web dashboard |
| `mancar` | your laptop | the client: connects to the gateway and forwards to `localhost` |

## Features

| Area | Feature | Status |
|---|---|---|
| Tunnels | HTTP / HTTPS tunnels | ✅ |
| | WebSocket and streaming responses (SSE, long polling) | ✅ |
| | Raw TCP tunnels (databases, SSH, game servers) | ✅ |
| | Custom (`my-api`) or random (`blue-falcon`) subdomains | ✅ |
| | Several tunnels per client, saved and started together | ✅ |
| | Live request log in the client terminal (method, path, status, time) | ✅ |
| | Automatic reconnect, same public address afterwards | ✅ |
| | `mancar update`: self-update with checksum verification | ✅ |
| | UDP tunnels | ❌ |
| | Your own domains (not just subdomains of `BASE_DOMAIN`) | ❌ |
| Server | Automatic wildcard HTTPS (Let's Encrypt via Cloudflare DNS) | ✅ |
| | Standalone (bundled Caddy) or behind an existing nginx | ✅ |
| | Docker Compose deployment, PostgreSQL with automatic migrations | ✅ |
| | Backup / restore scripts, health checks, JSON logs | ✅ |
| Dashboard | Live clients and tunnels, disconnect a client | ✅ |
| | Create and revoke tokens (revoke disconnects at once) | ✅ |
| | Manage users and reserved hostnames | ✅ |
| | Traffic per hostname and user: 24 h, 7 days and all time (requests, errors, bytes) | ✅ |
| | Request inspector and replay (stored encrypted, auto-deleted) | ✅ |
| Security | Per-user tokens, stored only as hashes | ✅ |
| | Isolation: users cannot take over each other's hostnames | ✅ |
| | Limits on tunnels, connections, request size; failed-login lockout | ✅ |
| | Dashboard: hashed passwords, signed cookies, CSRF protection, strict CSP | ✅ |
| | Basic auth / OAuth / IP rules in front of a tunnel | ❌ |

✅ available · ❌ not yet. Details: [docs/STATUS.md](docs/STATUS.md).

---

## Run as server

### What you need

- A VPS with a public IP, Docker and the Compose plugin
- A domain on **Cloudflare** DNS, and a Cloudflare API token with only
  *Zone / DNS / Edit* on that zone
- Open ports: **80**, **443** and **20000-20099** (TCP tunnels)

### 1. DNS

In Cloudflare, add two records pointing at the server, **DNS only** (grey
cloud, not proxied):

| Type | Name | Value |
|---|---|---|
| A | `@` | server IP |
| A | `*` | server IP |

Using a subdomain such as `tunnel.example.com` instead? The names are `tunnel`
and `*.tunnel`.

### 2. Configure

```bash
git clone https://github.com/tinoimammp/mancar.git
cd mancar
cp .env.example .env
./scripts/setup.sh     # generates the secrets
nano .env              # set BASE_DOMAIN, ACME_EMAIL, CLOUDFLARE_API_TOKEN
```

`MANCAR_VERSION` picks the release: `latest` (the default) always runs the
newest one, or pin a version such as `0.3.0`.

### 3. Start

```bash
docker compose up -d
```

> **nginx already uses ports 80/443 on this server?** Don't run the command
> above; follow [docs/NGINX.md](docs/NGINX.md) instead. Your other sites keep
> working.

### 4. Create a dashboard admin

```bash
docker compose exec gateway /mancard admin set --user admin
```

The password is printed once. Open `https://YOUR_DOMAIN/dashboard/` and log in.

### 5. Give someone access

In the dashboard: **Tokens → New token**. Copy the token (it is shown once)
and send it to the person who will run the client. From the command line:

```bash
docker compose exec gateway /mancard token create --user alice --name laptop
```

### Updating the server

```bash
docker compose up -d     # with MANCAR_VERSION=latest this pulls the newest release
```

To run a specific version, set `MANCAR_VERSION=0.3.0` in `.env` and run the
same command. Take a backup first (`scripts/backup.sh`).

More: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) (troubleshooting) and
[docs/OPERATIONS.md](docs/OPERATIONS.md) (backups, upgrades, logs).

---

## Run as client

### 1. Install

Download `mancar` from the
[latest release](https://github.com/tinoimammp/mancar/releases/latest):

| System | File |
|---|---|
| macOS, Apple Silicon | `mancar-<version>-darwin-arm64` |
| macOS, Intel | `mancar-<version>-darwin-amd64` |
| Linux | `mancar-<version>-linux-amd64` (or `-arm64`) |
| Windows | `mancar-<version>-windows-amd64.exe` |

macOS / Linux:

```bash
curl -fL -o /tmp/mancar https://github.com/tinoimammp/mancar/releases/download/v0.2.0/mancar-v0.2.0-darwin-arm64
chmod +x /tmp/mancar
sudo mv /tmp/mancar /usr/local/bin/mancar
mancar version
```

Later, update to the newest release with:

```bash
mancar update            # or: sudo mancar update, if installed in /usr/local/bin
mancar update --check    # only check
```

The download is verified against the release's `SHA256SUMS` before it
replaces the binary. When a newer release exists, every `mancar` command
prints a one-line notice; running tunnels look for one once a day and
`mancar version` checks right away. `MANCAR_NO_UPDATE_CHECK=1` turns this off.

### 2. Connect to your server

```bash
mancar config set server https://YOUR_DOMAIN
mancar config set token -     # paste the token, press Enter, then Ctrl+D
```

### 3. Open a tunnel

```bash
mancar http 3000 --subdomain my-api   # https://my-api.YOUR_DOMAIN -> localhost:3000
mancar http 3000 --random             # random name, e.g. blue-falcon
mancar http 3000                      # asks which one you want
mancar tcp 5432                       # raw TCP, e.g. a database -> YOUR_DOMAIN:200xx
```

While it runs, every request is printed:

```text
Requests
--------
14:02:11  GET    /api/users                               200 OK                   12 ms
14:02:13  POST   /api/login                               401 Unauthorized         8 ms
```

Add `--quiet` to hide the log. Stop with Ctrl+C. If the connection drops, the
client reconnects and keeps the same address.

### Save tunnels and run them together

```bash
mancar config add-tunnel web http 3000 --subdomain my-api
mancar config add-tunnel db  tcp  5432
mancar start      # start all saved tunnels
mancar status     # what is running
mancar stop       # stop everything
```

---

## How it works

```text
 visitor ──HTTPS──▶ edge (TLS) ──▶ mancard (gateway) ◀── one connection ── mancar (laptop) ──▶ localhost:3000
                                        │
                                    PostgreSQL
```

The client opens one outbound connection to the gateway, so nothing on your
laptop listens for the internet. The gateway maps `name.YOUR_DOMAIN` to the
client that owns it and streams each request through that connection. TLS is
handled by the bundled Caddy edge (wildcard certificate via Cloudflare DNS) or
by your own nginx.

## Documentation

| | |
|---|---|
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Server setup in detail, troubleshooting |
| [docs/NGINX.md](docs/NGINX.md) | Running behind an existing nginx |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | Dashboard admins, tokens, backups, upgrades, logs |
| [docs/SECURITY.md](docs/SECURITY.md) | What is and is not protected |
| [docs/STATUS.md](docs/STATUS.md) | Feature-by-feature status |
| [docs/protocol.md](docs/protocol.md), [docs/adr](docs/adr) | Protocol and design decisions |

## Development

```bash
make check     # gofmt, vet, tests with the race detector, shellcheck
make build     # bin/mancard and bin/mancar
make dist      # release binaries for all platforms
```

PostgreSQL tests run when `TEST_DATABASE_URL` is set (see the `Makefile`).
Releases are built by pushing a `v*` tag.

## License

MIT, see [LICENSE](LICENSE).
