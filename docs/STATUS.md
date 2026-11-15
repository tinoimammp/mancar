# Project status

An honest feature-by-feature account against the original specification. Nothing
here claims ngrok parity: that requires features that do not exist yet.

Legend: ✅ implemented and tested · ⚠️ partly, or not verifiable in the authoring
environment (see the note) · ❌ not implemented.

## Core capabilities

| Capability | State | Notes |
|---|---|---|
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
| Traffic inspection, request replay | ❌ | |
| Authentication policies (basic auth, OAuth), IP allow/deny | ❌ | Only agent-token authentication exists |
| Rate limiting | ⚠️ | Only failed agent logins per client address. No per-tunnel or per-IP limit on public traffic |
| Request size and connection limits | ✅ | |
| Management REST API (OpenAPI) | ❌ | Only `/healthz` and `/api/v1/system/health`. Tokens are managed with `mancard token ...` |
| Web dashboard | ❌ | |
| Access logs | ⚠️ | One structured log line per public request; no stored traffic log |
| Docker self-hosting | ⚠️ | Compose file validated with the real Compose v2 binary; **images not built in the authoring environment** (no Docker there). CI builds them |

## Advanced

| | |
|---|---|
| UDP tunnelling, OAuth, traffic policies, endpoint management | ❌ |
| Observability | ⚠️ health endpoints and structured logs; no metrics |
| Multi-user management | ⚠️ users and tokens via CLI; no roles, no UI or API |
| High availability, horizontal scaling | ❌ single gateway node; hostname and port allocation assume one node (the data model is already in PostgreSQL) |
| Redis | ❌ not needed yet |

## Security checklist from the specification

| | |
|---|---|
| Agent authentication, token hashing | ✅ |
| Dashboard authentication, JWT sessions, password hashing, API tokens | ❌ nothing to protect yet; `JWT_SECRET`/`ENCRYPTION_KEY` are validated but unused |
| Request size / connection limits | ✅ |
| Cross-user isolation, hostname spoofing, open-proxy prevention | ✅ tested |
| No plaintext secrets in logs | ✅ tested |

Details and gaps: [SECURITY.md](SECURITY.md).

## Database

Implemented: `users`, `agent_tokens`, `domains` (UUID keys, foreign keys with
cascade, unique constraints, check constraints, indexes, versioned atomic
migrations, advisory-locked so parallel starts are safe).
Not yet: `agents`, `tunnels` (history), `certificates`, `api_keys`,
`traffic_logs`, `auth_policies`, `audit_logs`, `system_settings`; each arrives
with the feature that needs it.

## The specification's 15 test scenarios

| # | Scenario | |
|---|---|---|
| 1-4 | Local server, tunnel, public URL, request/response forwarding | ✅ |
| 5 | Random hostname | ✅ |
| 6-7 | Custom hostname; duplicate rejected | ✅ |
| 8 | Reconnect after interruption | ✅ |
| 9 | HTTPS certificate | ⚠️ verified with Caddy's internal CA (wildcard and apex), not Let's Encrypt |
| 10 | WebSocket | ✅ |
| 11 | TCP | ✅ |
| 12 | Authentication | ✅ |
| 13 | Cross-user isolation | ✅ |
| 14 | Rate limiting | ⚠️ failed logins only |
| 15 | Graceful shutdown | ✅ |

## Evidence

| What | Result |
|---|---|
| Automated tests | 236 test functions across 14 packages, run with the race detector |
| Statement coverage | 87.9 % across `internal/...` when all test suites run together |
| PostgreSQL | Store, migrations, registry contract and token administration tested against PostgreSQL 16 |
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
* The placeholder module path `github.com/tinoimammp/mancar`, the image names `ghcr.io/tinoimammp/...` and the MIT licence holder `USERNAME` must be replaced (`scripts/rename-module.sh`).

## Roadmap

Ordered by what makes the gateway safer to expose, then by what users ask for:

1. Run the full stack in CI and fix what that finds; run a real certificate issuance once
2. Per-tunnel auth (basic auth), IP allow/deny and rate limits
3. Management REST API with OpenAPI, then the dashboard
4. Traffic inspector and replay
5. Metrics endpoint
6. Custom domains, TLS (SNI) tunnels
7. UDP, OAuth, multi-node operation
