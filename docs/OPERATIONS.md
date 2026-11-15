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
only). It shows connected agents and their tunnels and manages users, tokens
and hostname reservations. Admin accounts are managed on the server:

```bash
docker compose exec gateway /mancard admin set --user admin      # create, or reset the password
echo 'my long passphrase' | docker compose exec -T gateway /mancard admin set --user admin --password-stdin
docker compose exec gateway /mancard admin list
docker compose exec gateway /mancard admin delete admin
```

Without `--password-stdin` a random password is generated and printed once.
Resetting a password or deleting an admin signs their sessions out at once.
Sessions last 12 hours. Every dashboard change is logged as
`dashboard action` with the admin's name and client address.

## Users and tokens

Users exist implicitly: creating a token for a name creates the user.

```bash
docker compose exec gateway /mancard token create --user alice --name laptop
docker compose exec gateway /mancard token list
docker compose exec gateway /mancard token revoke <ID>
```

* The token is shown **once** and stored only as a SHA-256 hash. Lost token: revoke it and create another.
* Revocation stops **new** connections immediately. An agent that is already
  connected stays connected until it reconnects. To cut it off at once, restart
  the gateway (`docker compose restart gateway`): every agent reconnects within
  seconds and keeps its hostnames, except the revoked one, which is refused.
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

```bash
scripts/backup.sh
git pull && docker compose up -d --build      # or: set MANCAR_VERSION and docker compose pull
```

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
| `ENCRYPTION_KEY` | Validated at start-up but **not used by any feature yet**. Nothing is encrypted with it today |

## Moving to a new server

1. Copy `.env` and the newest backup to the new machine.
2. Point the DNS records at the new IP (lower the TTL beforehand).
3. `docker compose up -d`, then `scripts/restore.sh <backup> --yes`.
4. Caddy obtains new certificates (two) on first start.
