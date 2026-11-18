# Running behind an existing nginx

Use this when nginx already serves other sites on ports 80 and 443 of the same
server. nginx terminates TLS for the tunnel domain and proxies to the gateway;
the bundled Caddy edge is not started. Other nginx sites are not touched.

DNS is unchanged: `A BASE_DOMAIN` and `A *.BASE_DOMAIN` to the server, DNS only.

## 1. Wildcard certificate (certbot + Cloudflare DNS)

```bash
sudo apt install python3-certbot-dns-cloudflare
sudo install -m 600 /dev/null /root/.cloudflare.ini
echo "dns_cloudflare_api_token = YOUR_CLOUDFLARE_API_TOKEN" | sudo tee /root/.cloudflare.ini >/dev/null
sudo certbot certonly --dns-cloudflare --dns-cloudflare-credentials /root/.cloudflare.ini \
  -d tunnel.example.com -d '*.tunnel.example.com'
```

The same token as `CLOUDFLARE_API_TOKEN` works (Zone / DNS / Edit). Certbot's
timer renews the certificate; add `--deploy-hook "systemctl reload nginx"` so
nginx picks up renewals.

## 2. Start mancar without Caddy

```bash
docker compose stop caddy && docker compose rm -f caddy   # if it was started
docker compose -f docker-compose.yml -f docker-compose.nginx.yml up -d postgres pgbouncer gateway
```

The gateway now listens on `127.0.0.1:8080` only. TCP tunnels still use the
published port range (20000-20099 by default) directly, not nginx.

Use the same `-f docker-compose.yml -f docker-compose.nginx.yml` flags for
every later `pull`, `up`, `logs` or `exec`.

## 3. nginx site

```bash
sed 's/tunnel\.example\.com/YOUR_BASE_DOMAIN/g' docker/nginx/mancar.conf | sudo tee /etc/nginx/sites-available/mancar >/dev/null
sudo ln -s /etc/nginx/sites-available/mancar /etc/nginx/sites-enabled/mancar
sudo nginx -t && sudo systemctl reload nginx
```

The site passes any `Upgrade` through (agents use `Upgrade: mancar/1`, tunnels
use WebSockets), disables buffering so responses stream, and overwrites
`X-Forwarded-For` so clients cannot spoof their address. The gateway trusts
it because the connection arrives from the Docker bridge, a private range in
the default `TRUSTED_PROXIES`.

## Check

```bash
curl -s https://YOUR_BASE_DOMAIN/healthz              # ok
mancar config set server https://YOUR_BASE_DOMAIN && mancar http 3000
```
