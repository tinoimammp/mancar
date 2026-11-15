# Caddy with the Cloudflare DNS plugin, needed for the wildcard certificate.
# Versions are pinned so the image is reproducible.
FROM caddy:2.10.2-builder AS builder
RUN xcaddy build v2.10.2 --with github.com/caddy-dns/cloudflare@v0.2.4

FROM caddy:2.10.2
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
COPY Caddyfile /etc/caddy/Caddyfile
