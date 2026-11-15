# 1. Agent transport: yamux over an HTTP/1.1 upgrade

**Status:** accepted

## Context
Agents sit behind NAT and firewalls, so the connection must be outbound. One
agent serves several tunnels and many concurrent public connections. The
transport must work through a reverse proxy that terminates TLS, give each
connection its own flow control, and detect dead peers.

## Decision
The agent sends an HTTP/1.1 `Upgrade: mancar/1` request to a fixed path on the
base domain. After `101`, both sides run yamux. One stream carries control
messages (JSON lines); every public connection gets its own stream.

## Consequences
* Works with any proxy that forwards HTTP upgrades (verified with Caddy) and needs one port (443).
* yamux gives multiplexing, per-stream windows (backpressure) and keep-alive pings (heartbeat) without writing them ourselves.
* Rules out Cloudflare's orange-cloud proxy, which passes only WebSocket upgrades. DNS must be "DNS only".
* HTTP/2 cannot be used for the agent connection (no `Upgrade` in HTTP/2); the agent offers only `http/1.1`.
* Considered: raw TLS with a custom framing (needs a second port or SNI routing), WebSocket (would even pass Cloudflare's proxy, but adds a framing layer and a second protocol to maintain), QUIC (UDP is often blocked, more dependencies). They can be added later behind the same protocol version path.
