# Agent / gateway protocol, version 1

The contract between `mancar` (agent) and `mancard` (gateway). The reference
implementation is `internal/protocol`; the constants below are pinned by tests.

## 1. Handshake

The agent opens a TCP connection (TLS in production, normally through the edge)
and sends an HTTP/1.1 request. HTTP/2 must not be negotiated: the agent offers
only `http/1.1` in ALPN.

```http
GET /_mancar/v1/connect HTTP/1.1
Host: tunnel.example.com
Connection: Upgrade
Upgrade: mancar/1
Authorization: Bearer mc_<64 characters>
X-Mancar-Instance: <16 hex>          identifies this agent process across reconnects
X-Mancar-Agent-Version: <version>    informational
X-Mancar-Features: events            optional features the agent supports
```

| Status | Meaning | Agent behaviour |
|---|---|---|
| `101 Switching Protocols` with `Upgrade: mancar/1` | Accepted | Proceed |
| `426` | The request was not a valid upgrade | Fatal |
| `401` | Token missing, malformed, unknown or revoked | Fatal (not retried) |
| `429` | Too many failed logins from this address, or too many agents for this user | Retry with backoff |
| `4xx` (other) | Wrong URL or an incompatible server | Fatal |
| `5xx`, network errors | Transient | Retry with backoff |
| `101` without `Upgrade: mancar/1` | Not a mancar server | Fatal |

`Retry-After` accompanies the failed-login `429`.

## 2. Multiplexing

After `101` both sides speak [yamux](https://github.com/hashicorp/yamux) over the
connection: the gateway as server, the agent as client. Keep-alive pings (15 s
default) are the heartbeat: a peer that stops answering (write timeout 10 s) has
its session closed and all its tunnels removed. Stream flow-control windows give
backpressure end to end.

## 3. Control stream

The agent opens the **first** yamux stream within 10 s. It carries newline-delimited
JSON messages (one object per line, at most 64 KiB per line), request/response,
correlated by `req_id`. Unknown fields are ignored (forward compatibility).

```json
{"type":"register","req_id":"0","register":{"proto":"http","subdomain":"my-api"}}
{"type":"registered","req_id":"0","registered":{"tunnel_id":"...","proto":"http","hostname":"my-api.tunnel.example.com","public_url":"https://my-api.tunnel.example.com"}}
```

| `type` | Direction | Payload |
|---|---|---|
| `register` | agent → gateway | `proto` = `http` or `tcp`; `subdomain` optional (HTTP only, empty = random) |
| `registered` | gateway → agent | `tunnel_id`, `proto`, `hostname` (HTTP), `port` (TCP), `public_url` |
| `unregister` | agent → gateway | `tunnel_id`; only the session's own tunnels |
| `ok` | gateway → agent | acknowledgement |
| `error` | gateway → agent | `{"code": ..., "message": ...}` |

Error codes: `hostname_taken`, `hostname_invalid`, `limit_exceeded`, `unsupported`,
`not_found`, `bad_request`, `internal`.

Subdomain rules: 3-63 characters of `a-z`, `0-9`, `-`; must start and end with a
letter or digit; no `--` (which also excludes punycode); a list of reserved names
(`www`, `api`, `admin`, ...) is refused. Input is lower-cased and trimmed.

An agent reconnecting re-registers its tunnels. For random names it re-requests
the label it had so the public address survives (a new one is allocated only if it
was lost in the meantime).

## 4. Data streams

For every public connection the gateway opens a new yamux stream toward the
agent and writes one header line, then relays raw bytes in both directions:

```json
{"tunnel_id":"...","remote_addr":"203.0.113.9:51234"}
```

The header is at most 4096 bytes. The agent looks `tunnel_id` up among the
tunnels it registered, closes the stream if unknown, and otherwise dials the
local address configured for that tunnel (5 s timeout) and pipes the two
connections. If the local service is unreachable, HTTP tunnels get
`502` with `X-Mancar-Error: local_service_unreachable`.

HTTP tunnels carry the HTTP/1.1 conversation unchanged (including WebSocket
upgrades and streaming responses); TCP tunnels carry the raw byte stream.
Half-close is propagated, so request/response protocols complete correctly.

## 4a. Events stream (request log)

An agent that sends `X-Mancar-Features: events` may receive one extra stream,
opened by the gateway when the first event occurs, with the header

```json
{"kind":"events"}
```

followed by one JSON line per finished exchange on the agent's tunnels:

```json
{"tunnel_id":"...","time":"2026-11-15T14:02:11Z","method":"GET","path":"/api/users","status":200,"duration_ms":12,"bytes_in":0,"bytes_out":512,"remote":"203.0.113.9"}
```

HTTP tunnels report every request (the path never includes the query
string); TCP tunnels report every connection when it closes (`method`, `path`
and `status` are absent). Delivery is best effort: the gateway drops events
rather than slow traffic down. Agents ignore streams with an unknown `kind`,
and gateways only open this stream for agents that asked for it, so mixed
versions keep working.

## 5. Limits

| What | Limit |
|---|---|
| Control message / stream header | 64 KiB / 4 KiB |
| Tunnels per session | `MAX_TUNNELS_PER_AGENT` (10) |
| Sessions per user | `MAX_AGENTS_PER_USER` (10) |
| Concurrent connections per tunnel | `MAX_CONNECTIONS_PER_TUNNEL` (256) |

## 6. Versioning

The version is in the URL path and in the `Upgrade` token. A future incompatible
protocol will use a new path/token and be served alongside this one.
