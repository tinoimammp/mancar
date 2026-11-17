# Changelog

All notable changes to mancar. Versions follow [semantic versioning](https://semver.org/).
Each release publishes the `mancar` client for Linux, macOS and Windows, the
`mancard` gateway for Linux, and the Docker images
`ghcr.io/tinoimammp/mancar` and `ghcr.io/tinoimammp/mancar-edge`.

## [v0.3.3] - 2026-11-17

### Changed
- Redesigned dashboard: a floating header with a light / dark switch,
  section tabs with icons, stat cards and cleaner detail sheets.
- Agents, requests, users, tokens and domains lists are paged, and agents,
  users, tokens and domains can be searched. Agents can be filtered to the
  ones with open connections.
- Commands, tokens, curl commands and request bodies show in code blocks
  with a Copy button; headers show as a compact name / value table.
- Confirmations (revoke, delete, disconnect, replay) use an in-page dialog
  instead of the browser's.
- Tokens are created from a **Create token** dialog.

## [v0.3.2] - 2026-11-15

### Added
- `mancar http PORT` now offers the three subdomains you used most recently
  with that server, so a name does not have to be typed again:
  ```text
    1) Random subdomain
    2) Custom subdomain

    Recently used:
    3) my-api                   (used 2h ago)
    4) shop                     (used 3 days ago)
  ```
  `--last` reuses the most recent one without asking. The history is kept on
  your machine only (`recent-subdomains.json` in the mancar state directory).

## [v0.3.1] - 2026-11-15

### Changed
- The client's request log no longer lists every successful static file
  (`.js`, `.css`, images, fonts, media): they are summarised as
  `+ 23 static files (1.2 MB)` per page load. Failed static files are still
  listed. New `--log all|errors|smart` flag (`smart` is the default; `--quiet`
  still hides the log).

## [v0.3.0] - 2026-11-15

### Added
- **Request inspector** in the dashboard (**Requests** page): every HTTP
  request through your tunnels with headers, bodies and the response.
  Requests can be **replayed** to the tunnel or copied as `curl`.
  - Stored in PostgreSQL **encrypted with `ENCRYPTION_KEY`** (AES-256-GCM).
    Only the hostname, status, timing and sizes are readable without the key.
  - Deleted automatically after `INSPECT_RETENTION` (default `24h`) and beyond
    `INSPECT_MAX_ROWS` (default 50,000). Bodies are kept up to
    `INSPECT_MAX_BODY_BYTES` (default 64 KiB). `INSPECT=off` disables it.
- **Live request log in the client**: `mancar http` prints one line per
  request (time, method, path, status, duration); TCP tunnels print one line
  per connection. `--quiet` hides it.
- **Traffic statistics** per hostname and per user: requests, server errors
  and bytes for the last 24 hours, the last 7 days and **all time**, shown on
  the Overview (with the busiest hostnames), Domains and Users pages.
  Hourly data is kept 90 days; daily and all-time totals are kept forever.
- **`mancar update`**: installs the newest release for your system after
  verifying it against the release's `SHA256SUMS`. `mancar update --check`
  only checks.
- **Update notices**: every `mancar` command prints one line when a newer
  release exists; running tunnels check once a day and `mancar version` checks
  immediately. `MANCAR_NO_UPDATE_CHECK=1` turns this off.
- **`latest` Docker tag**: releases are also tagged `latest`, and
  `docker compose up -d` now pulls newer images (`MANCAR_PULL_POLICY`, default
  `always`). Set `MANCAR_VERSION=latest` to follow releases or pin one such as
  `0.3.0`.
- Guide and config for running behind an **existing nginx**
  ([docs/NGINX.md](docs/NGINX.md)).

### Changed
- The README is reorganised into "Run as server" and "Run as client" with a
  feature table.
- CI no longer runs for documentation-only changes.

### Upgrading
- Database migrations `0003`–`0005` run automatically when the gateway starts.
  Take a backup first: `scripts/backup.sh`.
- Install this client version by hand once (older clients have no
  `mancar update`); from now on `mancar update` is enough.
- Agents and gateways of different versions keep working together; the request
  log needs both sides on v0.3.0.

## [v0.2.0] - 2026-11-15

### Added
- **Web dashboard** at `https://BASE_DOMAIN/dashboard/`: connected agents and
  their tunnels (with disconnect), users, agent tokens (create, revoke with
  immediate disconnect) and hostname reservations.
- Dashboard admin accounts: `mancard admin set --user NAME` (generates a
  password, or reads one with `--password-stdin`), `admin list`,
  `admin delete`.
- Dashboard security: PBKDF2-SHA256 password hashing, HMAC-signed session
  cookies (`JWT_SECRET`), login rate limiting, CSRF protection and a strict
  Content-Security-Policy.

### Changed
- PostgreSQL 16 → **18**. The data volume is now mounted at
  `/var/lib/postgresql`.
- Caddy 2.10.2 → 2.11.9; gateway base image distroless Debian 12 → 13.
- GitHub Actions updated to current major versions.

### Fixed
- When the local service was down, visitors sometimes received
  `tunnel_unreachable` instead of `local_service_unreachable`.

### Upgrading
- **PostgreSQL 18 cannot read a PostgreSQL 16 data directory.** If you ran
  v0.1.0 with data you want to keep: `scripts/backup.sh` on v0.1.0, upgrade,
  then `scripts/restore.sh`. Fresh installs need nothing.

## [v0.1.0] - 2026-11-15

First release.

### Added
- HTTP/HTTPS tunnels (including WebSocket and streaming) and raw TCP tunnels.
- Custom (`--subdomain`) and random subdomains, reserved atomically and kept
  for their owner across reconnects.
- `mancar` client: `http`, `tcp`, saved tunnels with `start`, `status`,
  `stop`, automatic reconnect.
- `mancard` gateway with per-user agent tokens (`mancard token create|list|revoke`),
  stored only as hashes.
- Automatic wildcard HTTPS through Caddy and Let's Encrypt (Cloudflare DNS).
- Docker Compose deployment with PostgreSQL, backup and restore scripts,
  health checks and structured logs.
- Limits on tunnels, agents, connections and request size; failed-login
  rate limiting.
- Built with Go 1.26.11.

[v0.3.3]: https://github.com/tinoimammp/mancar/compare/v0.3.2...v0.3.3
[v0.3.2]: https://github.com/tinoimammp/mancar/compare/v0.3.1...v0.3.2
[v0.3.1]: https://github.com/tinoimammp/mancar/compare/v0.3.0...v0.3.1
[v0.3.0]: https://github.com/tinoimammp/mancar/compare/v0.2.0...v0.3.0
[v0.2.0]: https://github.com/tinoimammp/mancar/compare/v0.1.0...v0.2.0
[v0.1.0]: https://github.com/tinoimammp/mancar/releases/tag/v0.1.0
