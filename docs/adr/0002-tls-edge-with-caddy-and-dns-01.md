# 2. TLS edge: Caddy with a wildcard certificate through DNS-01

**Status:** accepted

## Context

Tunnels get arbitrary subdomains, so the platform needs a wildcard certificate;
Let's Encrypt only issues wildcards through the DNS-01 challenge. Users must not
install certificates by hand, and the gateway should not hold TLS private keys or
speak ACME.

## Decision

A Caddy container in front of the gateway terminates TLS for `BASE_DOMAIN` and
`*.BASE_DOMAIN` using the Cloudflare DNS plugin, and forwards plain HTTP to the
gateway over the private network. The gateway trusts the edge's
`X-Forwarded-*` headers (private address ranges by default).

## Consequences

* Issuance and renewal are automatic and battle-tested; the gateway stays free of TLS code.
* Caddy issues two certificates (wildcard and apex), not one. Let's Encrypt allows 50 per registered domain per week.
* The Cloudflare token must be scoped to the one zone. The image needs the plugin, so it is built with `xcaddy` and pinned.
* The wildcard DNS record must not be proxied (see ADR 1) and TCP tunnels bypass the edge entirely.
* The production Caddyfile is tested unchanged except for the `tls` block, which cannot be tested without a real Cloudflare token.
