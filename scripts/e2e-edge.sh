#!/usr/bin/env bash
# End-to-end test of the TLS edge: a real Caddy in front of a real gateway,
# a real agent, and a local application.
#
#   CADDY_BIN=/path/to/caddy scripts/e2e-edge.sh
#
# It runs the production docker/caddy/Caddyfile unchanged except for one
# thing: the `tls { dns cloudflare ... }` block, which needs a real Cloudflare
# token, is replaced by `tls internal` (Caddy's own CA). Everything else -
# wildcard site, upgrade handling, streaming, forwarded headers, redirect - is
# exactly what runs in production.
#
# Requires: go, caddy >= 2.8, curl, openssl, python3.
# shellcheck disable=SC2015,SC2317  # "A && ok || fail" is intentional: ok never fails; cleanup runs via trap
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
CADDY=${CADDY_BIN:-caddy}
for tool in go curl openssl python3 "$CADDY"; do
  command -v "$tool" >/dev/null 2>&1 || { echo "missing required tool: $tool (set CADDY_BIN for caddy)" >&2; exit 2; }
done

WORK=$(mktemp -d)
PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
  wait 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

free_port() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
GW=$(free_port); HTTP=$(free_port); HTTPS=$(free_port); APP=$(free_port); ADMIN=$(free_port)
DOMAIN=tunnel.test
FAILS=0
ok()   { echo "  ok    $1"; }
fail() { echo "  FAIL  $1"; FAILS=$((FAILS+1)); }
check() { # description, command...
  local d=$1; shift
  if "$@" >/dev/null 2>&1; then ok "$d"; else fail "$d"; fi
}

echo "== building"
(cd "$ROOT" && go build -o "$WORK/mancard" ./cmd/mancard && go build -o "$WORK/mancar" ./cmd/mancar) || { echo "build failed"; exit 1; }
TOKEN=$("$WORK/mancard" token generate)

echo "== starting gateway, edge and a local app"
APP_ENV=development STORAGE=memory BASE_DOMAIN=$DOMAIN LISTEN_ADDR=127.0.0.1:$GW \
  PUBLIC_SCHEME=https PUBLIC_PORT=$HTTPS DEV_AGENT_TOKEN=$TOKEN LOG_LEVEL=warn \
  "$WORK/mancard" serve >"$WORK/gateway.log" 2>&1 &
PIDS+=($!)

# Production Caddyfile with only the DNS-01 tls block swapped for `tls internal`.
awk '
  /^\ttls \{$/ { print "\ttls internal"; skip=1; next }
  skip && /^\t\}$/ { skip=0; next }
  !skip { print }
' "$ROOT/docker/caddy/Caddyfile" >"$WORK/Caddyfile"
grep -q 'tls internal' "$WORK/Caddyfile" || { echo "could not derive the test Caddyfile"; exit 1; }

export XDG_DATA_HOME=$WORK/data XDG_CONFIG_HOME=$WORK/cfg
BASE_DOMAIN=$DOMAIN ACME_EMAIL=test@example.com GATEWAY_UPSTREAM=127.0.0.1:$GW \
  CADDY_HTTP_PORT=$HTTP CADDY_HTTPS_PORT=$HTTPS CADDY_ADMIN_PORT=$ADMIN \
  "$CADDY" run --config "$WORK/Caddyfile" --adapter caddyfile >"$WORK/caddy.log" 2>&1 &
PIDS+=($!)

cat >"$WORK/app.py" <<PY
import http.server, json, time
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/stream":
            self.send_response(200); self.send_header("Content-Type", "text/event-stream"); self.end_headers()
            self.wfile.write(b"data: one\n\n"); self.wfile.flush(); time.sleep(2)
            self.wfile.write(b"data: two\n\n"); self.wfile.flush(); return
        body = json.dumps({"path": self.path, "headers": dict(self.headers)}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("127.0.0.1", $APP), H).serve_forever()
PY
python3 "$WORK/app.py" & PIDS+=($!)

ROOTCRT=$XDG_DATA_HOME/caddy/pki/authorities/local/root.crt
RESOLVE=(--resolve "$DOMAIN:$HTTPS:127.0.0.1" --resolve "edge-test.$DOMAIN:$HTTPS:127.0.0.1" --resolve "nobody.$DOMAIN:$HTTPS:127.0.0.1" --resolve "edge-test.$DOMAIN:$HTTP:127.0.0.1")
for _ in $(seq 1 100); do
  curl -sk "${RESOLVE[@]}" "https://$DOMAIN:$HTTPS/healthz" 2>/dev/null | grep -q ok && [ -f "$ROOTCRT" ] && break
  sleep 0.2
done
[ -f "$ROOTCRT" ] || { echo "edge did not come up"; tail -20 "$WORK/caddy.log"; exit 1; }
CURL=(curl -s --cacert "$ROOTCRT" "${RESOLVE[@]}")

# The apex and the wildcard certificate are obtained concurrently and Caddy
# retries a failed first attempt after 60s, so wait until a *subdomain*
# handshake verifies before testing anything that depends on the wildcard.
echo "== waiting for the wildcard certificate"
WILD=0
for _ in $(seq 1 450); do
  if curl -s --cacert "$ROOTCRT" "${RESOLVE[@]}" -o /dev/null "https://nobody.$DOMAIN:$HTTPS/" 2>/dev/null; then WILD=1; break; fi
  sleep 0.2
done
[ $WILD -eq 1 ] || { echo "wildcard certificate was not issued within 90s"; tail -20 "$WORK/caddy.log"; exit 1; }

echo "== connecting an agent through the edge (HTTPS, HTTP/1.1 upgrade)"
SSL_CERT_FILE=$ROOTCRT MANCAR_SERVER=https://$DOMAIN:$HTTPS MANCAR_DIAL_ADDR=127.0.0.1:$HTTPS \
  MANCAR_TOKEN=$TOKEN MANCAR_CONFIG_DIR=$WORK/mtcfg MANCAR_STATE_DIR=$WORK/mtstate \
  "$WORK/mancar" http "$APP" --subdomain edge-test >"$WORK/agent.out" 2>"$WORK/agent.err" &
AGENT=$!; PIDS+=("$AGENT")
for _ in $(seq 1 150); do grep -q 'Status: ONLINE' "$WORK/agent.out" && break; sleep 0.2; done
check "agent comes online through the edge"          grep -q 'Status: ONLINE' "$WORK/agent.out"
check "public URL is https on the edge port"         grep -q "https://edge-test.$DOMAIN:$HTTPS" "$WORK/agent.out"
check "agent reports TLS: ENABLED"                   grep -q 'TLS: ENABLED' "$WORK/agent.out"

echo "== public traffic"
BODY=$("${CURL[@]}" -H 'X-Forwarded-For: 6.6.6.6' "https://edge-test.$DOMAIN:$HTTPS/hello?x=1")
field() { python3 -c 'import json,sys;d=json.loads(sys.argv[1]);print(eval(sys.argv[2]))' "$BODY" "$1" 2>/dev/null; }
[ "$(field 'd["path"]')" = "/hello?x=1" ]                         && ok "request reaches the local app with path and query" || fail "request reaches the local app"
[ "$(field 'd["headers"].get("Host")')" = "edge-test.$DOMAIN:$HTTPS" ] && ok "local app sees the public Host header"        || fail "public Host header ($(field 'd["headers"].get("Host")'))"
[ "$(field 'd["headers"].get("X-Forwarded-Proto")')" = "https" ]  && ok "X-Forwarded-Proto is https"                      || fail "X-Forwarded-Proto"
XFF=$(field 'd["headers"].get("X-Forwarded-For")')
[ "$XFF" = "127.0.0.1" ]                                          && ok "client-supplied X-Forwarded-For is discarded (saw: $XFF)" || fail "X-Forwarded-For spoofing: saw '$XFF'"

STREAM=$("${CURL[@]}" -N -o "$WORK/sse.out" -w '%{http_code} %{time_starttransfer}' "https://edge-test.$DOMAIN:$HTTPS/stream")
STREAM_CODE=${STREAM% *}; TTFB=${STREAM#* }
if [ "$STREAM_CODE" = 200 ] && python3 -c "import sys; sys.exit(0 if 0 < float('$TTFB') < 1.5 else 1)"; then
  ok "streaming responses are not buffered (first byte after ${TTFB}s)"
else
  fail "streaming check (status $STREAM_CODE, first byte after ${TTFB}s)"
fi
grep -q 'data: two' "$WORK/sse.out" 2>/dev/null && ok "streamed response completes" || fail "streamed response incomplete"

check "unknown subdomain gives 404 tunnel_not_found" \
  bash -c "'${CURL[0]}' ${CURL[*]:1} -D- -o /dev/null 'https://nobody.$DOMAIN:$HTTPS/' | grep -qi 'x-mancar-error: tunnel_not_found'"
check "HTTP is redirected to HTTPS" \
  bash -c "curl -s -o /dev/null -D- ${RESOLVE[*]} 'http://edge-test.$DOMAIN:$HTTP/' | grep -qiE '^location: https://'"
check "base domain /healthz answers over TLS" bash -c "'${CURL[0]}' ${CURL[*]:1} 'https://$DOMAIN:$HTTPS/healthz' | grep -q ok"

echo "== certificate"
san_for() { echo | openssl s_client -connect "127.0.0.1:$HTTPS" -servername "$1" 2>/dev/null | openssl x509 -noout -ext subjectAltName 2>/dev/null; }
# Caddy manages one certificate per name in the site address: a wildcard one
# for the tunnels and a separate one for the base domain itself.
WSAN=$(san_for "x.$DOMAIN"); ASAN=$(san_for "$DOMAIN")
echo "$WSAN" | grep -q "DNS:\*.$DOMAIN" && ok "tunnel subdomains are served with a *.$DOMAIN certificate" || fail "wildcard SAN missing: $WSAN"
echo "$ASAN" | grep -q "DNS:$DOMAIN"    && ok "the base domain is served with its own certificate"         || fail "apex SAN missing: $ASAN"

echo "== shutdown and failure paths"
kill -TERM $AGENT; wait $AGENT 2>/dev/null; AGENT_EXIT=$?
[ $AGENT_EXIT -eq 0 ] && ok "agent exits 0 on SIGTERM" || fail "agent exit code $AGENT_EXIT"
grep -q 'Shutting down.' "$WORK/agent.out" && ok "agent says it is shutting down" || fail "no shutdown message"
GONE=000
for _ in $(seq 1 50); do
  GONE=$("${CURL[@]}" -o /dev/null -w '%{http_code}' "https://edge-test.$DOMAIN:$HTTPS/")
  [ "$GONE" = 404 ] && break; sleep 0.2
done
[ "$GONE" = 404 ] && ok "tunnel is gone after the agent stops (404)" || fail "after the agent stopped the public URL answered $GONE, want 404"

WRONG=mc_$(printf '9%.0s' $(seq 1 64))
SSL_CERT_FILE=$ROOTCRT MANCAR_SERVER=https://$DOMAIN:$HTTPS MANCAR_DIAL_ADDR=127.0.0.1:$HTTPS MANCAR_TOKEN=$WRONG \
  MANCAR_CONFIG_DIR=$WORK/mtcfg2 MANCAR_STATE_DIR=$WORK/mtstate2 "$WORK/mancar" http "$APP" >"$WORK/wrong.out" 2>"$WORK/wrong.err"
[ $? -eq 1 ] && grep -q 'rejected the agent token' "$WORK/wrong.err" && ok "a wrong token is rejected with a clear message" || fail "wrong token handling: $(cat "$WORK/wrong.err")"

echo "== brute-force protection reaches the real client address through the edge"
GOT429=0
for _ in $(seq 1 15); do
  CODE=$("${CURL[@]}" --http1.1 -o /dev/null -w '%{http_code}' -H 'Connection: Upgrade' -H 'Upgrade: mancar/1' \
    -H "Authorization: Bearer $WRONG" "https://$DOMAIN:$HTTPS/_mancar/v1/connect")
  [ "$CODE" = 429 ] && GOT429=1
done
[ $GOT429 -eq 1 ] && ok "repeated failed logins are answered with 429" || fail "no 429 after 15 failed logins"

echo
if [ $FAILS -eq 0 ]; then echo "edge e2e: ALL CHECKS PASSED"; exit 0; fi
echo "edge e2e: $FAILS CHECK(S) FAILED"
echo "--- caddy.log (tail)"; tail -15 "$WORK/caddy.log"; echo "--- gateway.log (tail)"; tail -10 "$WORK/gateway.log"; echo "--- agent.err"; cat "$WORK/agent.err"
exit 1
