# Project status

An honest feature-by-feature account against the original specification. Nothing
here claims ngrok parity: that requires features that do not exist yet.

Legend: ✅ implemented and tested · ⚠️ partly, or not verifiable in the authoring
environment (see the note) · ❌ not implemented.

## Core capabilities

| Capability | State | Notes |
| --- | --- | --- |
| HTTP tunnelling | ✅ | Integration tests through the real gateway and agent |
| HTTPS tunnelling | ⚠️ | TLS is terminated by Caddy. Verified end to end with Caddy's internal CA. **Not verified against real Let's Encrypt and Cloudflare DNS-01** |
| TCP tunnelling | ✅ | Raw TCP on a configurable public port range |
| TLS tunnelling (SNI passthrough) | ❌ | |
| WebSocket | ✅ | Upgrade and bidirectional traffic through the gateway are tested; the agent's own upgrade is tested through Caddy |
| Random subdomains | ✅ | `adjective-noun`, e.g. `blue-falcon`; collisions get a numeric suffix |
| Custom subdomains | ✅ | Atomic reservation, duplicate rejection, per-user hold |
| Custom domains | ❌ | Only subdomains of `BASE_DOMAIN` |
| Automatic certificates and renewal | ⚠️ | Delegated to Caddy; the wildcard flow is tested with an internal CA, **not with a real issuer** |
| Multiple simultaneous tunnels | ✅ | Up to 10 per agent connection, many agents |
| Persistent connections, reconnect | ✅ | Backoff 1 s → 30 s with jitter; a gateway restart is survived in about 2.5 s; random names survive reconnects |
| Traffic inspection, request replay | ✅ | Dashboard **Requests** page: headers, bodies (first 64 KiB), responses, replay, copy as curl. Stored AES-256-GCM encrypted in PostgreSQL, deleted after `INSPECT_RETENTION`. HTTP only, not WebSocket frames or TCP |
| Private tunnels (owner signs in through the dashboard) | ✅ | `--private`; HTTP only, needs PostgreSQL |
| Password in front of a tunnel (HTTP Basic Auth) | ✅ | `--auth USER:PASSWORD`, checked by the gateway |
| IP allow/deny in front of a tunnel | ❌ | |
| Rate limiting | ⚠️ | Failed agent logins, dashboard logins and `--auth` passwords, per client address. No limit on public traffic itself |
| Request size and connection limits | ✅ | |
| Management REST API (OpenAPI) | ❌ | Only `/healthz` and `/api/v1/system/health`. Tokens are managed with `mancard token ...` |
| Web dashboard | ✅ | `/dashboard/`: live agents and tunnels, disconnect, users, tokens (create, revoke with immediate disconnect), hostname reservations. Needs PostgreSQL storage |
| Access logs | ✅ | One structured log line per public request on the gateway; a live request log in the client terminal; per-hostname statistics (hourly for 90 days, daily and all-time forever) and the encrypted request inspector in the dashboard |
| Docker self-hosting | ⚠️ | Compose file validated with the real Compose v2 binary; **images not built in the authoring environment** (no Docker there). CI builds them |

## Advanced

| | |
| --- | --- |
| UDP tunnelling, OAuth, traffic policies, endpoint management | ❌ |
| Observability | ⚠️ health endpoints and structured logs; no metrics |
| Multi-user management | ⚠️ users and tokens via CLI and dashboard; `admin` and `user` roles (users see only their own tunnels, tokens and requests); no public management API |
| High availability, horizontal scaling | ❌ single gateway node; hostname and port allocation assume one node (the data model is already in PostgreSQL) |
| Redis | ❌ not needed yet |

## Security checklist from the specification

| | |
| --- | --- |
| Agent authentication, token hashing | ✅ |
| Dashboard authentication, signed sessions, password hashing | ✅ PBKDF2-SHA256, HMAC-signed cookie keyed by `JWT_SECRET`, login rate limit, CSRF protection. API tokens for automation: ❌ |
| Request size / connection limits | ✅ |
| Cross-user isolation, hostname spoofing, open-proxy prevention | ✅ tested |
| No plaintext secrets in logs | ✅ tested |

Details and gaps: [SECURITY.md](SECURITY.md).

## Database

Implemented: `users` (with roles and dashboard passwords), `agent_tokens`,
`email_tokens`, `domains`, `captured_requests`, `usage_hourly`, `usage_daily`,
`usage_total`, `audit_log` (UUID keys, foreign keys with cascade, unique
constraints, check constraints, indexes, versioned atomic migrations,
advisory-locked so parallel starts are safe, also behind PgBouncer).
Not yet: `agents`, `tunnels` (history), `certificates`, `api_keys`,
`traffic_logs`, `auth_policies`, `system_settings`; each arrives with the
feature that needs it.

## The specification's 15 test scenarios

| # | Scenario | |
| --- | --- | --- |
| 1-4 | Local server, tunnel, public URL, request/response forwarding | ✅ |
| 5 | Random hostname | ✅ |
| 6-7 | Custom hostname; duplicate rejected | ✅ |
| 8 | Reconnect after interruption | ✅ |
| 9 | HTTPS certificate | ⚠️ verified with Caddy's internal CA (wildcard and apex), not Let's Encrypt |
| 10 | WebSocket | ✅ |
| 11 | TCP | ✅ |
| 12 | Authentication | ✅ |
| 13 | Cross-user isolation | ✅ |
| 14 | Rate limiting | ⚠️ failed logins and passwords only |
| 15 | Graceful shutdown | ✅ |

## Evidence

| What | Result |
| --- | --- |
| Automated tests | 236 test functions across 14 packages, run with the race detector |
| Statement coverage | 87.9 % across `internal/...` when all test suites run together |
| PostgreSQL | Store, migrations, registry contract and token administration tested in CI against PostgreSQL 18, directly and through PgBouncer |
| Edge end-to-end | `scripts/e2e-edge.sh`: real Caddy 2.11.9 with the production Caddyfile → real gateway → real agent → local app. Checks the upgrade handshake over HTTPS, wildcard and apex certificates, forwarded headers and spoofing, streaming, redirect, shutdown, wrong token, brute-force protection. Passed repeatedly |
| Scripts | `setup.sh`, `backup.sh`, `restore.sh`, `rename-module.sh` exercised for real (destroy-and-restore on PostgreSQL included); `shellcheck` clean |
| Compose file | Rendered and validated with Docker Compose v2.29.7: required-variable errors, published ports, hardening options |
| CI workflows | Linted with `actionlint` (not executed) |
| Cross-compilation | Linux, macOS, Windows build; only Linux binaries were run |

## What has not been verified or done

* **Docker images were not built** and `docker compose up` was never run (the authoring environment had no Docker). The CI `docker` job builds both images and validates the Compose file, but nobody has watched a full stack start.
* **Real certificate issuance** (Let's Encrypt, Cloudflare DNS-01, token permissions, renewal) was not exercised; the Caddy Cloudflare plugin (`caddy-dns/cloudflare@v0.2.4`) was not built. Image tags (`golang:1.26-alpine`, `caddy:2.11.9`, `postgres:18-alpine`) were not checked against the registries.
* **No load or performance testing.** Only functional concurrency tests exist (many concurrent requests, large bodies). Do not assume capacity numbers.
* **No independent security audit** and no penetration test.
* The macOS and Windows clients were cross-compiled but never run.

## Roadmap

Ordered by what makes the gateway safer to expose, then by what users ask for:

1. Run the full stack in CI and fix what that finds; run a real certificate issuance once
2. IP allow/deny and rate limits on public traffic
3. Management REST API with OpenAPI
4. Metrics endpoint
5. Custom domains, TLS (SNI) tunnels
6. UDP, OAuth, multi-node operation
