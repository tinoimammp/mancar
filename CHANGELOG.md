# Changelog

All notable changes to mancar. Versions follow [semantic versioning](https://semver.org/).
Each release publishes the `mancar` client for Linux, macOS and Windows, the
`mancard` gateway for Linux, and the Docker images
`ghcr.io/tinoimammp/mancar` and `ghcr.io/tinoimammp/mancar-edge`.

## [Unreleased]

## [v0.7.0] - 2026-11-18

### Added
- **PgBouncer** between the gateway and PostgreSQL (transaction pooling;
  `PGBOUNCER_POOL_SIZE`, default 10 server connections). Migrations now take a
  transaction-level lock so they work behind it, and CI runs the database
  tests through PgBouncer too. Backups and restores still use PostgreSQL
  directly.

### Security
- A dashboard replay could reach another account's private tunnel when the
  hostname had changed hands since the capture. A replay now only goes to a
  tunnel of the account that recorded it.
- `--allow` by email address could let in someone who signed up with that
  address without confirming it. Only active accounts with a confirmed email
  can be shared with.
- A `#ref=` link to the dashboard could send a person who just signed in to
  any app under the base domain (phishing). It now leads only to a tunnel the
  account may open, or to a private tunnel's Restricted page. A tunnel shared
  with you opens on a click, without the countdown.
- `mancard admin set NAME` no longer promotes an account made by web sign up
  (its email address could reset the new admin's password).
- Demoting or deleting the last admin no longer reopens the public first-run
  setup page; only a server where no account has a password offers it.
- Creating an admin, giving another admin a temporary password and changing
  another admin's email now ask for your own password.
- An agent can no longer hold gateway memory with streams it never uses, nor
  flood the control channel (over 120 messages in 10 s disconnects it).
- Request paths and server messages are cleaned of control characters before
  `mancar` prints them (no terminal escape injection by visitors).
- `X-Real-IP`, `True-Client-IP`, `CF-Connecting-IP` and similar headers sent
  by visitors are removed; `X-Real-IP` carries the real address.
- `mancar login` only opens a web link on the server it asked.
- Disabling or deleting an account, or a new password, ends its access to
  private tunnels at once, not only its dashboard sessions.
- Logins count against the limit before the password is checked, failures
  for one account from other addresses no longer lock it out, and an IPv6
  /64 counts as one address. A password reset is rate limited before hashing.
- "Forgot password" and "send again" answer before looking the address up,
  so response times do not show whether it is registered.
- The release workflow pins every action to a commit and gives each job only
  the permissions it needs.
- `JWT_SECRET` is required whenever PostgreSQL is used, also in development.
- `/api/v1/system/health` shows details only to direct requests from inside
  the deployment, never to anything that came through the edge.

### Fixed
- `docker-compose.yml` now passes `INSPECT*`, `REGISTER_ENABLED`, `SMTP_URL`,
  `TRUSTED_PROXIES` and the new `MAX_TCP_TUNNELS_PER_USER` to the gateway;
  before, these settings in `.env` were ignored (sign up and password reset
  could not work).
- The compose file no longer builds images: a version that does not exist
  makes `docker compose pull` fail instead of compiling on the server.
  Upgrade with `docker compose pull && docker compose up -d --wait`.
- One account can hold at most `MAX_TCP_TUNNELS_PER_USER` (10) TCP tunnels,
  so it cannot take the whole port range.
- `scripts/restore.sh` restores in one transaction: a failed restore changes
  nothing.
- Abandoned sign ups are purged only when they never signed in and were not
  changed for a week; an admin changing an address no longer gets an account
  in use deleted.
- An emailed password reset by an admin now signs the account out, as stated.
- A device approved twice at once no longer leaves an undelivered token.
- A hostname whose reservation timed out is released instead of staying
  blocked until the next restart.
- `mancar update` allows slow downloads (only the wait for an answer is
  limited to a minute).
- `mancard user` and `admin` commands no longer upgrade a database the
  running gateway still uses; they prepare a new database only.

### Upgrading
- **Update `docker-compose.yml` first** (`git pull` in the server's mancar
  folder): it adds PgBouncer, passes the missing settings and no longer
  builds images. Then `docker compose pull && docker compose up -d --wait`.
  `docker compose ps` should show postgres, pgbouncer, gateway and caddy.
- Settings in `.env` that were ignored before now apply (`INSPECT*`,
  `REGISTER_ENABLED`, `SMTP_URL`, `TRUSTED_PROXIES`): check them.
- An account may hold at most 10 TCP tunnels (`MAX_TCP_TUNNELS_PER_USER`).
- `JWT_SECRET` is required with PostgreSQL also when `APP_ENV=development`.
- A pinned `MANCAR_VERSION` is written without "v" (`0.7.0`).
- No database migration; agents reconnect by themselves.

## [v0.6.0] - 2026-11-18

### Added
- `--allow budi,ana@example.com` shares a private tunnel with other accounts
  (usernames or email addresses; implies `--private`), also for
  `config add-tunnel`. An unknown name stops `mancar` with "no account:
  NAME". The dashboard shows "Private, with budi, ana". Needs the server and
  the client at the new version.

### Upgrading
- No migration. Update the server first, then the clients.

## [v0.5.1] - 2026-11-18

### Fixed
- `mancar update` no longer fails with "403 Forbidden" on shared networks.
  It reads the latest version from the release's `SHA256SUMS` on github.com
  instead of the GitHub API, which allows only 60 requests an hour per
  address. When GitHub does refuse, it says so and suggests waiting.

## [v0.5.0] - 2026-11-18

### Added
- **Private tunnels**: `mancar http 3000 --private` (or `config add-tunnel
  ... --private`). Visitors see a Restricted page with "Log in to continue";
  after logging in, only the account that owns the tunnel gets in, and
  everyone else is back on the Restricted page. Access lasts 12 hours per
  browser. The dashboard marks these tunnels "Private". They need the
  dashboard (PostgreSQL); a server without it, or an older one, refuses
  them instead of serving them publicly.
- `mancar status` marks private tunnels.

### Changed
- `mancar config` refuses `--subdomain` and `--private` outside
  `add-tunnel` instead of ignoring them.

### Upgrading
- No migration. Update the server and the clients; `--private` needs both
  at v0.5.0 (an older client has no such flag, an older server refuses it
  through a new client).

## [v0.4.0] - 2026-11-18

### Added
- Accounts with two roles. **Admins** see and manage the whole gateway;
  **users** sign in to see only their own tunnels, subdomains, tokens and
  captured requests, and manage their account (password, delete).
- Optional sign up from the web, off by default:
  ```bash
  REGISTER_ENABLED=true
  SMTP_URL=smtps://user:password@smtp.example.com:465
  ```
  New accounts confirm their email before they can create tokens, and get 3
  active tokens and 3 custom subdomains. Unconfirmed sign ups are deleted
  after 7 days. Sign up, "send again" and "forgot password" answer the same
  whether an address is registered or not.
- **Forgot password** on the sign in page when `SMTP_URL` is set.
- User management for admins: search and filter by role or status, add a
  user, make admin (asks for your password) or user, disable / enable,
  confirm an email, reset a password (by email or a temporary one), revoke
  all tokens, change limits. The last active admin cannot be removed, and
  nobody can demote or disable themselves.
- **Activity** page: what admins and users did, kept for a year.
- A new gateway asks for the **first admin in the dashboard**: no command on
  the server is needed. The page closes for good once an admin exists.
- Sign in with your email or your username.
- **`mancar login https://YOUR_DOMAIN`**: no more copying tokens. The
  browser opens the dashboard, you check the code and click Allow, and a
  token named after the computer is saved. `--name` sets another name,
  `--no-browser` only prints the link.
- `mancard user list|create|password|role|disable|enable|delete` manage
  accounts on the server, and `mancard help` is grouped by topic. For
  example, `mancard user password NAME` resets a password without changing
  the role.

### Changed
- Dashboard admins and users are now one list of accounts. Upgrading moves
  every admin into it; an admin and a user with the same name become one
  admin account that keeps the user's tokens. Open sessions must sign in
  again once.
- `mancard admin set|list|delete` still work; `admin delete NAME` now takes
  admin rights away and keeps the account as a user.
- Tokens of a disabled account are refused until it is enabled again.
- Agents connected with a token that was revoked, or whose account was
  disabled or deleted, from the CLI are now dropped within 30 seconds
  instead of staying connected until they reconnect.
- The logo is now an image, also used as the browser icon.

### Upgrading
- Take a backup first (`scripts/backup.sh`): migration 0006 moves the
  `admins` table into `users` and drops it.
- Everyone signed in to the dashboard must sign in again once. Agents
  reconnect by themselves and keep their hostnames.
- Sign up stays off unless you set `REGISTER_ENABLED=true` and `SMTP_URL`.

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

[v0.7.0]: https://github.com/tinoimammp/mancar/compare/v0.6.0...v0.7.0
[v0.6.0]: https://github.com/tinoimammp/mancar/compare/v0.5.1...v0.6.0
[v0.5.1]: https://github.com/tinoimammp/mancar/compare/v0.5.0...v0.5.1
[v0.5.0]: https://github.com/tinoimammp/mancar/compare/v0.4.0...v0.5.0
[v0.4.0]: https://github.com/tinoimammp/mancar/compare/v0.3.3...v0.4.0
[v0.3.3]: https://github.com/tinoimammp/mancar/compare/v0.3.2...v0.3.3
[v0.3.2]: https://github.com/tinoimammp/mancar/compare/v0.3.1...v0.3.2
[v0.3.1]: https://github.com/tinoimammp/mancar/compare/v0.3.0...v0.3.1
[v0.3.0]: https://github.com/tinoimammp/mancar/compare/v0.2.0...v0.3.0
[v0.2.0]: https://github.com/tinoimammp/mancar/compare/v0.1.0...v0.2.0
[v0.1.0]: https://github.com/tinoimammp/mancar/releases/tag/v0.1.0
