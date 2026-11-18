# Operations guide

Day-2 tasks for a running deployment. Commands run in the repository directory
on the server.

## Health

```bash
docker compose ps                                       # every service should be "healthy"
curl -fsS https://tunnel.example.com/healthz            # -> ok (public, minimal)
docker compose exec gateway /mancard healthcheck      # the container's own check
```

`/api/v1/system/health` answers `{"status":"ok"}` to the internet. Version,
database state and tunnel/session counters are returned only to clients inside
the deployment (private address ranges), for example:

```bash
docker compose exec caddy wget -qO- --header 'Host: tunnel.example.com' \
  http://gateway:8080/api/v1/system/health
```

A database outage turns this into HTTP 503 with `"status":"degraded"`.

## Dashboard

The dashboard is served at `https://BASE_DOMAIN/dashboard/` (PostgreSQL storage
only). Accounts have one of two roles:

| Role | Sees and manages |
|---|---|
| `admin` | the whole gateway: agents, tunnels, requests, every account, tokens, hostnames, the audit log |
| `user` | only their own tunnels, subdomains, tokens and requests, and their account |

The first admin is made on the server; more can be promoted in the dashboard
(Users → a user → Make admin, which asks for your own password) or on the
server. Every account command (`docker compose exec gateway /mancard ...`):

```bash
mancard user list                                  # every account: role, email, status, last sign in
mancard user create admin --admin                  # first admin; prints a generated password
mancard user create rina --email rina@example.com  # a plain user
mancard user password rina                         # new password, role unchanged
mancard user role rina admin                       # or: user
mancard user disable rina                          # block sign in, refuse tokens; enable undoes it
mancard user delete rina                           # with tokens, subdomains, requests, statistics
mancard help                                       # everything else
```

To choose the password yourself, pipe it in:

```bash
echo 'my long passphrase' | docker compose exec -T gateway /mancard user password admin --password-stdin
```

Without `--password-stdin` a random password is generated and printed once.
The older `mancard admin set|list|delete` commands still work.
Resetting a password, disabling or deleting an account signs its sessions
out at once, and a role change applies to open sessions immediately. An
admin cannot demote, disable or delete themselves, and the gateway always
keeps at least one active admin. Sessions last 12 hours. Admin actions are
listed in the dashboard (Activity) for a year and logged as `dashboard action`.

### Sign up from the web

Off by default. To let people create their own account:

```bash
REGISTER_ENABLED=true
SMTP_URL=smtps://user:password@smtp.example.com:465   # or smtp://...:587 (STARTTLS)
```

Emails are sent from `no-reply@BASE_DOMAIN`. URL-encode special characters in
the password (`@` is `%40`). `SMTP_URL` alone (sign up off) still enables
"Forgot password" and reset links sent by an admin.

- A new account must confirm its email (link valid 24 hours) before it can
  create tokens. Unconfirmed sign ups are deleted after 7 days.
- Privacy: sign up, "send again" and "forgot password" answer the same
  whether an address is registered or not. The owner of a registered address
  gets an email saying someone tried to sign up with it.
- A signed-up account may have 3 active tokens and 3 custom subdomains;
  admins change this per account (Users → Limits). Admins have no limits.
- Disabling an account refuses its tokens and disconnects its agents; enabling
  it makes the same tokens work again.
- Each client may trigger 5 emails an hour, and each address receives at most
  3 an hour.

## Traffic statistics

The dashboard shows HTTP requests, server errors (5xx or no response) and
bytes per hostname and per user for the last 24 hours, the last 7 days and
all time, plus the busiest hostnames on the overview. Counts are kept in
memory and written every 30 seconds (and on shutdown), in one transaction, to:

| Table | Granularity | Kept |
|---|---|---|
| `usage_hourly` | hostname, user, hour | 90 days |
| `usage_daily` | hostname, user, day (UTC) | forever |
| `usage_total` | hostname, user | forever |

Purging old hourly rows never changes the daily history or the all-time
totals. Deleting a user deletes their statistics. TCP tunnels are not counted.

## Request inspector

The dashboard's **Requests** page lists HTTP requests through the tunnels with
headers, bodies and responses, and can replay them. Settings in `.env`:

| Variable | Default | |
|---|---|---|
| `INSPECT` | `on` | `off` stops recording |
| `INSPECT_RETENTION` | `24h` | captures older than this are deleted (checked every 5 minutes) |
| `INSPECT_MAX_BODY_BYTES` | `65536` | bytes of each body kept; a longer request cannot be replayed |
| `INSPECT_MAX_ROWS` | `50000` | oldest captures beyond this are deleted |

Captures are encrypted with `ENCRYPTION_KEY` (AES-256-GCM) before they are
written; the database only holds the hostname, status, timing and sizes in the
clear. Recording is asynchronous and never slows traffic: under extreme load
some captures are dropped (logged as `captures dropped`). WebSocket and TCP
traffic is not recorded. Replay sends the stored request to the tunnel again,
so the application processes it a second time.

## Users and tokens

Users exist implicitly: creating a token for a name creates the user.

```bash
docker compose exec gateway /mancard token create --user alice --name laptop
docker compose exec gateway /mancard token list
docker compose exec gateway /mancard token revoke <ID>
```

* The token is shown **once** and stored only as a SHA-256 hash. Lost token: revoke it and create another.
* Revocation stops new connections immediately. An agent that is already
  connected is dropped within 30 seconds (from the dashboard: at once). The
  same goes for `mancard user disable` and `mancard user delete`.
* Remove a user and everything they own (tokens, hostnames):

  ```bash
  docker compose exec postgres psql -U mancar -d mancar \
    -c "DELETE FROM users WHERE username = 'alice'"
  ```

  then restart the gateway to drop their live sessions.

## Hostnames

A custom name stays reserved for its owner for `HOSTNAME_HOLD_CUSTOM` (default
24 h) after the tunnel disconnects, a random one for `HOSTNAME_HOLD_RANDOM`
(default 5 min). Nobody else can take it during that time. Expired reservations
are purged hourly.

```bash
docker compose exec postgres psql -U mancar -d mancar -c \
  "SELECT d.hostname, u.username, d.kind, d.active_tunnel_id IS NOT NULL AS online, d.hold_until
     FROM domains d JOIN users u ON u.id = d.user_id ORDER BY d.hostname"
```

To give a held name back early, delete its row (only when it is not online):
`DELETE FROM domains WHERE hostname = 'x.tunnel.example.com' AND active_tunnel_id IS NULL`.

## Backups

```bash
scripts/backup.sh                                   # -> backups/mancar-<UTC>.sql.gz (mode 600)
BACKUP_RETAIN=30 scripts/backup.sh                  # keep the 30 newest
```

Schedule it, for example with `crontab -e`:

```cron
17 3 * * *  cd /opt/mancar && ./scripts/backup.sh >> backups/backup.log 2>&1
```

Back up, and keep **off the server**:

| What | Why |
|---|---|
| `backups/*.sql.gz` | All users, tokens (hashes) and hostname reservations |
| `.env` | Contains every secret; without it a restored database is not usable |
| `caddy_data` volume (optional) | Holds the TLS certificates. They can be re-issued, but Let's Encrypt rate limits apply |

**Test your restores.** A backup you have never restored is a hope, not a backup:

```bash
scripts/restore.sh backups/mancar-20260101T031700Z.sql.gz --yes
```

This replaces the current database contents. It stops the gateway during the
restore and starts it again afterwards; agents reconnect by themselves.

The scripts have been exercised against a real PostgreSQL 16 (retention,
permissions, destroy-and-restore, a failing dump leaves no file), but not against
a Compose stack in this repository's CI.

## Upgrades and rollback

`MANCAR_VERSION` in `.env` chooses the gateway and edge images:

| `MANCAR_VERSION` | Runs |
|---|---|
| `latest` (default) | the newest release; every `docker compose up -d` checks for a newer one |
| `0.3.0` | exactly that release |
| `0.3` | the newest `0.3.x` patch release |

```bash
scripts/backup.sh
docker compose up -d          # pulls a newer image if there is one, recreates changed containers
```

To move to a specific version, set `MANCAR_VERSION=0.3.0` and run the same
command; to go back, set the previous version (and see below). Behind nginx,
add `-f docker-compose.yml -f docker-compose.nginx.yml` as usual.
`MANCAR_PULL_POLICY=missing` stops `up` from contacting the registry when the
image is already present.

Migrations run automatically when the gateway starts. They only move forward, so
**rollback means restoring the pre-upgrade backup** together with the previous
version. Releases that change the schema say so in the release notes.

## Logs

```bash
docker compose logs -f gateway          # JSON lines in production
docker compose logs -f caddy
```

Container logs rotate at 10 MB x 5 files per service. The gateway logs one line
per public request (`host`, `method`, `path`, `status`, `duration_ms`, `client`,
`tunnel`), agent connections and failures. It never logs tokens, secrets, the
database URL or query strings (URLs often carry credentials). Caddy access logs
are off for the same reason.

## Limits

| Variable | Default | Meaning |
|---|---|---|
| `MAX_TUNNELS_PER_AGENT` | 10 | Tunnels one agent connection may register |
| `MAX_AGENTS_PER_USER` | 10 | Simultaneous agent connections per user |
| `MAX_CONNECTIONS_PER_TUNNEL` | 256 | Concurrent public connections per tunnel; beyond it clients get `503 tunnel_busy` |
| `MAX_REQUEST_BODY_BYTES` | 100 MiB | Larger requests get `413`; `0` = unlimited |
| `RESPONSE_HEADER_TIMEOUT` | 2 m | Wait for the local app's response headers (`502` afterwards) |
| `AUTH_FAILURE_LIMIT_PER_MINUTE` | 10 | Failed agent logins per client address; beyond it `429` without touching the database; `0` = off |
| `TCP_PORT_MIN` / `TCP_PORT_MAX` | 20000 / 20099 | Public TCP tunnel ports (each published by Docker) |

The limits live in the gateway's memory and apply per gateway process.

## Monitoring

There is no metrics endpoint yet. Until there is, watch:

* an external uptime probe on `https://<BASE_DOMAIN>/healthz`
* `docker compose ps` health and container restart counts
* certificate renewal in `docker compose logs caddy` (Caddy renews about 30 days before expiry and logs failures)
* free disk (volumes `pgdata`, `caddy_data`, and `backups/`)

## Rotating secrets

| Secret | How |
|---|---|
| `CLOUDFLARE_API_TOKEN` | Create a new token, update `.env`, `docker compose up -d caddy`, delete the old token in Cloudflare |
| `POSTGRES_PASSWORD` | `docker compose exec postgres psql -U mancar -c "ALTER USER mancar PASSWORD '<new>'"`, update `.env`, `docker compose up -d gateway` |
| Agent tokens | Create new, distribute, revoke old (see above) |
| `JWT_SECRET` | Signs dashboard sessions. Changing it and restarting the gateway signs every admin out; nothing else is affected |
| `ENCRYPTION_KEY` | Encrypts captured requests. Changing it makes existing captures unreadable (the dashboard hides them; they expire with `INSPECT_RETENTION`). Nothing else uses it |

## Moving to a new server

1. Copy `.env` and the newest backup to the new machine.
2. Point the DNS records at the new IP (lower the TTL beforehand).
3. `docker compose up -d`, then `scripts/restore.sh <backup> --yes`.
4. Caddy obtains new certificates (two) on first start.
