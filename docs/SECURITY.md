# Security

This document says what mancar protects, how, and, just as important, what
it does **not** protect. It describes the code as it is, not as it might become.

> **The most important thing to know:** a tunnel makes your local service
> reachable by **anyone who knows or guesses its URL or port**. There are no
> authentication policies (basic auth, OAuth, IP allow-lists) yet. Do not expose
> an admin panel, a database or anything sensitive through a tunnel unless that
> service protects itself. A TCP tunnel is a raw public port with no protection at all.

No independent security audit has been performed. The review behind this
document was done by the authors of the code; treat it accordingly.

## Trust boundaries

```text
internet ──▶ Caddy (TLS) ──▶ gateway ──▶ agent ──▶ local service
 untrusted    edge          authenticates   dials only the address
                            agents          you configured
```

* The **internet** is untrusted. Everything arriving at Caddy is treated as hostile input.
* The **gateway** trusts only the proxies listed in `TRUSTED_PROXIES` (default: private address ranges, which covers the Compose network) for client-address headers.
* The **agent** does not trust the gateway more than necessary: it only ever dials the local addresses its user configured and ignores streams for tunnels it did not register. A compromised gateway cannot use an agent as a proxy into the user's network.

## Authentication and tokens

* Agents authenticate with a bearer token: `mc_` plus 256 bits from the operating system's CSPRNG (64 hex characters).
* Only the SHA-256 hash is stored. A single fast hash is appropriate because the token is uniformly random; a slow password KDF would add nothing. The plaintext is shown once, never logged, and never written to the CLI's state files.
* The CLI keeps the token in `config.json` (mode `0600`, directory `0700`) or in `MANCAR_TOKEN`. It deliberately has **no `--token` flag**: command lines leak through shell history and process lists.
* Malformed tokens are rejected before any database access. Revoked and unknown tokens are indistinguishable to the client.
* **Failed-login rate limiting:** each client address (the real one behind the edge, not the proxy's) may fail `AUTH_FAILURE_LIMIT_PER_MINUTE` times per minute (default 10). Beyond that the request is answered `429` without a database lookup. One abusive client does not lock out others behind the same proxy.
* Revocation stops new connections immediately; agents that are already connected are dropped within 30 seconds, or at once when revoked from the dashboard (see [OPERATIONS.md](OPERATIONS.md)).

### Dashboard

* Admin passwords are hashed with PBKDF2-SHA256 (600,000 iterations, random
  salt) and must be at least 12 characters. Unknown usernames cost the same
  time as wrong passwords.
* Failed logins are limited to 10 per 15 minutes per client address and per
  username.
* The session is a cookie signed with HMAC-SHA256 under a key derived from
  `JWT_SECRET`: `HttpOnly`, `SameSite=Strict`, and over HTTPS `Secure` with the
  `__Host-` prefix, so a tunnel subdomain can neither read nor overwrite it.
  It is re-checked against the database on every request; resetting the
  password or deleting the admin ends it immediately.
* State-changing requests need the `X-Mancar-CSRF` header and a matching
  `Origin`, which blocks cross-site request forgery (including from a tunnel
  subdomain, which is a different origin).
* The page is served with a strict Content-Security-Policy (no inline or
  third-party scripts, `frame-ancestors 'none'`), and the front end inserts
  all server data as text, never as HTML.
* Agent token secrets are shown once at creation and never stored.

### Request inspector

Captured requests contain whatever users send through their tunnels:
passwords, cookies, tokens. They are therefore:

* encrypted before storage with AES-256-GCM under `ENCRYPTION_KEY`, with the
  row ID as associated data (a ciphertext cannot be moved to another row).
  Method, URL, headers, bodies and client address are all inside the
  ciphertext; hostname, status, timing and sizes are stored in the clear;
* decrypted only in the gateway, for a logged-in admin;
* deleted automatically after `INSPECT_RETENTION` (default 24 h) and beyond
  `INSPECT_MAX_ROWS`, and when their user is deleted;
* visible to every dashboard admin (there are no per-user views yet).

Set `INSPECT=off` if admins must not see tunnel traffic. A database dump
without `ENCRYPTION_KEY` does not reveal captured content.

## Isolation between users

* Hostnames are reserved atomically in PostgreSQL (a `UNIQUE` constraint plus a single conditional statement), so concurrent claims have exactly one winner. This is tested with 100 concurrent claimants and against the real database.
* A name is held for its owner after a disconnect (24 h custom / 5 min random), so nobody can take over an address that others still link to.
* A user can only unregister tunnels of their own session; reconnect instance IDs are scoped per user, so one user can never disconnect another's agent.
* Each tunnel has its own connection pool toward its agent: a connection can never be reused across tunnels.

## Private tunnels

A tunnel started with `--private` is only forwarded for its owner.

* The dashboard session cookie belongs to the base domain and is never sent to tunnel hosts, because any tunnel's app would receive it. A browser without access gets a self-contained **Restricted** page on the tunnel's host (no scripts, strict CSP, nothing loaded from the app) whose button opens the dashboard sign in page with the tunnel as its ref (`/dashboard/#ref=HOST/PATH`). Once signed in, `POST /api/v1/me/access` (CSRF protected) issues a ticket only when the signed-in account owns a live tunnel on that host. Anyone else, and any host that is offline, gets the same answer: the plain tunnel address, which shows the Restricted page again. Hosts outside `BASE_DOMAIN` are refused, so the ref is never an open redirect.
* The ticket is HMAC-signed with a key derived from `JWT_SECRET`, bound to the host and the account, valid for 60 seconds, and accepted once.
* The gateway redeems it at `https://HOST/_mancar/access` for a `__Host-mancar_access` cookie: host-only, `Secure`, `HttpOnly`, `SameSite=Lax`, 12 hours. The cookie names the owner's account, so it stops working if the hostname later belongs to someone else.
* The gateway removes that cookie from every request it forwards, so the app never sees it. Refused requests never reach the agent, the request inspector or the traffic counters.
* Requests that are not page loads by a browser (API calls, `POST`, WebSocket upgrades) get `401` instead of a redirect.
* Signing out of the dashboard does not end access that was already granted; it expires after 12 hours. Disabling the account or revoking the token disconnects the agent, which ends the tunnel itself.

## Preventing open-proxy behaviour

* The router forwards a request only if its `Host` header is `<name>.<BASE_DOMAIN>` **and** that tunnel is currently registered. Any other host, including `BASE_DOMAIN.evil.com` or `evilBASE_DOMAIN`, is refused with `404 unknown_host` before any lookup.
* Nested names (`a.b.<BASE_DOMAIN>`) are looked up verbatim and never fall back to a parent tunnel.
* The agent dials only its configured local addresses (see above).

## Forwarded headers and client addresses

* `X-Forwarded-For` / `-Proto` / `-Host` sent by clients are discarded and rebuilt by the gateway. The gateway only believes the headers of a *trusted proxy*, and walks the chain from the right, skipping trusted hops, so a client cannot prepend a fake address.
* Caddy replaces any client-supplied `X-Forwarded-For` with the real peer address; the edge test verifies that a spoofed `X-Forwarded-For: 6.6.6.6` never reaches the local application.

## Information disclosure

* The public `/api/v1/system/health` answers only `{"status": ...}`. Version, database state and counters are for internal clients only; spoofing `X-Forwarded-For` cannot unlock them.
* The root page does not show the version. Error pages are fixed strings: request paths, internal addresses and backend error text are never reflected.
* Logs never contain tokens, secrets, database URLs or query strings. Configuration errors name the variable but never echo its value; database errors have the connection string redacted.

## Transport security

* TLS is terminated by Caddy (TLS 1.2+, HTTP/2 and HTTP/3 for browsers, automatic HTTPS and renewal). Certificates come from Let's Encrypt through the DNS-01 challenge.
* The agent verifies the server certificate (TLS 1.2 minimum) and has **no option to skip verification**. It refuses `http://` server URLs unless the host is loopback (or `MANCAR_ALLOW_INSECURE=1` is set for a network you trust), because the token travels in the handshake.
* Between Caddy and the gateway, and between the gateway and PostgreSQL, traffic is plain text inside the private Compose network.

## Resource limits (denial-of-service)

Header read timeout 10 s; request body limit; per-tunnel connection limit; tunnels per agent; agents per user; failed-login limit; yamux flow control gives end-to-end backpressure, so memory per connection is bounded. Idle agents are detected by keep-alive pings (15 s). Limits are per gateway process and kept in memory. See [OPERATIONS.md](OPERATIONS.md#limits).

## Secrets handling

`.env` is created with mode `0600` and is in `.gitignore`. Placeholder values (`changeme`, `password`, ...) and short secrets are rejected at start-up with an explanation. `scripts/setup.sh` generates secrets once and never overwrites an existing one, so a restart can never silently produce a new key.

## Container hardening

The gateway image is distroless (no shell, no package manager) and runs as an unprivileged user with a read-only root filesystem, all capabilities dropped and `no-new-privileges`. PostgreSQL and the gateway's HTTP port are not published. The Caddy admin endpoint listens on localhost inside its container. Consider pinning images by digest.

## Known gaps

| Gap | Consequence |
|---|---|
| No per-tunnel authentication, IP filtering or rate limiting | Anyone with the URL reaches your service. TCP tunnels are open public ports |
| No audit log, no traffic log, no alerting | You see request logs but cannot answer "who created which tunnel when" |
| Revocation does not end live sessions | Restart the gateway to cut a session immediately |
| Limits and the failed-login limiter are in memory, per process | Not shared across several gateways; a restart resets them |
| Limiter is keyed on the client IP | Many users behind one NAT share a budget; an attacker with a large IPv6 range can dilute it |
| Hostname and TCP-port allocation assume a single gateway node | Do not run several gateway replicas against one database yet |
| No built-in encryption of data at rest | Use disk encryption on the server; only token hashes and hostnames are stored |
| Plain-text hops inside the Compose network | Acceptable on one host; reconsider for multi-host setups |

## Operator checklist

- [ ] DNS records are **DNS only**; Cloudflare token limited to the one zone and to DNS edit (plus zone read)
- [ ] `.env` is `chmod 600`, backed up off the server, never committed
- [ ] Firewall allows only 80, 443 (tcp+udp) and the TCP range; remember Docker bypasses `ufw`
- [ ] Narrow `TCP_PORT_MIN`/`MAX` to what you need
- [ ] Pin `MANCAR_VERSION` to a release; keep the host and Docker updated
- [ ] Scheduled `scripts/backup.sh`, and a restore tested at least once
- [ ] One token per person and device; revoke on departure; restart the gateway to cut live sessions
- [ ] Nothing sensitive behind a tunnel unless it authenticates itself

## Reporting a vulnerability

Please report vulnerabilities privately (for example through GitHub's
*Security → Report a vulnerability* on the repository) instead of opening a
public issue. Replace this paragraph with your preferred contact before publishing.
