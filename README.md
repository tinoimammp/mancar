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
| | Live request log in the client terminal, static files summarised | ✅ |
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
| | Accounts with two roles: admins see everything, users only their own tunnels | ✅ |
| | Sign up on the web with email confirmation, forgot password (optional) | ✅ |
| | Disable, promote, limit and reset accounts; activity log | ✅ |
| | Traffic per hostname and user: 24 h, 7 days and all time (requests, errors, bytes) | ✅ |
| | Request inspector and replay (stored encrypted, auto-deleted) | ✅ |
| Security | Per-user tokens, stored only as hashes | ✅ |
| | Isolation: users cannot take over each other's hostnames | ✅ |
| | Limits on tunnels, connections, request size; failed-login lockout | ✅ |
| | Dashboard: hashed passwords, signed cookies, CSRF protection, strict CSP | ✅ |
| | Private tunnels: only the owner opens them, after signing in (`--private`) | ✅ |
| | Share a private tunnel with other accounts (`--allow budi,ana`) | ✅ |
| | A password in front of a tunnel, for people without an account (`--auth`) | ✅ |
| | IP rules in front of a tunnel | ❌ |

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
newest one, or pin a version such as `0.7.0`.

### 3. Start

```bash
docker compose up -d
```

> **nginx already uses ports 80/443 on this server?** Don't run the command
> above; follow [docs/NGINX.md](docs/NGINX.md) instead. Your other sites keep
> working.

### 4. Create a dashboard admin

Open `https://YOUR_DOMAIN/dashboard/` right after the gateway starts: a new
gateway asks you to **create the first admin** there. Do it straight away, since
until then whoever opens the page first becomes the admin. On the server you
can always do it (or take it back) instead:

```bash
docker compose exec gateway /mancard user create admin --admin
```

That password is printed once (forgot it? `mancard user password admin`).
To let people create their own account, set `REGISTER_ENABLED=true` and
`SMTP_URL` (see [docs/OPERATIONS.md](docs/OPERATIONS.md#sign-up-from-the-web)).

### 5. Give someone access

In the dashboard: **Tokens → New token**. Copy the token (it is shown once)
and send it to the person who will run the client. From the command line:

```bash
docker compose exec gateway /mancard token create --user alice --name laptop
```

### Updating the server

```bash
docker compose pull && docker compose up -d --wait   # download first, then swap (tunnels pause briefly)
```

To run a specific version, set `MANCAR_VERSION=0.7.0` in `.env` and run the
same command. Take a backup first (`scripts/backup.sh`).

More: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) (troubleshooting) and
[docs/OPERATIONS.md](docs/OPERATIONS.md) (backups, upgrades, logs).

---

## Run as client

### 1. Install

Installs the latest release for your system and checks its checksum.

macOS / Linux:

```bash
curl -fsSL https://raw.githubusercontent.com/tinoimammp/mancar/main/scripts/install.sh | sh
```

It installs to `/usr/local/bin` (asking for sudo when needed); to install
without sudo, pipe it to `MANCAR_INSTALL_DIR=$HOME/.local/bin sh` instead.

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/tinoimammp/mancar/main/scripts/install.ps1 | iex
```

Update later with:

```bash
mancar update            # macOS/Linux: sudo mancar update
```

### 2. Connect to your server

```bash
mancar login https://YOUR_DOMAIN
```

Your browser opens the dashboard: sign in, check that the code matches the
one in your terminal, and click **Allow**. A token named after your computer
is created and saved. Revoke it any time under **Tokens**.

With a token you already have (no browser, e.g. on a server):

```bash
mancar config set server https://YOUR_DOMAIN
mancar config set token -     # paste the token, press Enter, then Ctrl+D
```

### 3. Open a tunnel

```bash
mancar http 3000 --subdomain my-api   # https://my-api.YOUR_DOMAIN -> localhost:3000
mancar http 3000 --random             # random name, e.g. blue-falcon
mancar http 3000                      # asks: random, custom, or one of your last 3 names
mancar http 3000 --last               # reuse the name you used most recently
mancar tcp 5432                       # raw TCP, e.g. a database -> YOUR_DOMAIN:200xx
mancar http 3000 --private            # only you can open it (see below)
mancar http 3000 --allow budi,ana     # private, and budi and ana may open it too
mancar http 3000 --auth klien:rahasia123   # anyone with this user name and password
```

**Private tunnels.** With `--private`, a visitor sees a **Restricted** page
with a **Log in to continue** button. After logging in on the dashboard, the
account that owns the tunnel is sent on to it; anyone else lands on the
Restricted page again. `--allow` shares it with other accounts on the server
(usernames or email addresses, comma separated; it implies `--private`). An
unknown name stops `mancar` with "no account: NAME". Access lasts 12 hours per
browser and tunnel. Good for admin panels and work in progress. It works for
HTTP tunnels on servers with the dashboard (PostgreSQL). Requests without a
browser (curl, webhooks) get `401`, so use a normal tunnel for those.

**Password.** `--auth USER:PASSWORD` is for people without an account, such as
a client looking at a demo: the browser asks for the user name and password
(`curl -u USER:PASSWORD` from scripts). The gateway checks it and never passes
it to your app; 20 wrong tries from one address within 10 minutes block it until
that window ends. The
password needs at least 8 characters. To keep it out of your shell history,
give only `--auth USER` and put the password in `MANCAR_AUTH_PASSWORD`. A tunnel
is either private or behind a password, not both; apps that use the
`Authorization` header themselves (bearer tokens) should use `--private`.

While it runs, requests are printed. Successful static files (`.js`, `.css`,
images, fonts) are folded into one line per page load, so the requests that
matter stay visible; failed ones are always listed:

```text
Requests
--------
14:02:11  GET    /                                        200 OK                   45 ms
          + 23 static files (1.2 MB)
14:02:13  POST   /api/login                               401 Unauthorized         8 ms
14:02:14  GET    /assets/app.js                           404 Not Found            2 ms
```

`--log all` lists every request, `--log errors` only 4xx/5xx, `--quiet` none.
Every request is also in the dashboard's **Requests** page. Stop with Ctrl+C. If the connection drops, the
client reconnects and keeps the same address.

### Save tunnels and run them together

```bash
mancar config add-tunnel web http 3000 --subdomain my-api
mancar config add-tunnel db  tcp  5432
mancar config add-tunnel admin http 8080 --private
mancar start      # start all saved tunnels
mancar status     # what is running
mancar stop       # stop everything
```

A saved `--auth` keeps its password in the config file (readable only by you).

`MANCAR_SERVER` and `MANCAR_TOKEN` override the config file;
`MANCAR_NO_UPDATE_CHECK=1` stops looking for new releases. `mancar help` lists
everything.

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
