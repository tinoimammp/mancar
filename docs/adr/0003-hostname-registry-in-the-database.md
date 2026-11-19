# 3. Hostname registry: atomic claims in the database, with holds

**Status:** accepted

## Context

Random and custom names must never be handed to two owners, even under
concurrent requests, and availability must never be inferred from DNS (the
wildcard record makes every name "resolve").

## Decision

`domains.hostname` is `UNIQUE`. A claim is one conditional `INSERT ... ON
CONFLICT DO UPDATE ... WHERE` statement that succeeds for a new name, for the
current owner re-claiming an inactive name, or for anyone once an inactive name's
hold has expired. Disconnecting does not delete the row: it sets
`active_tunnel_id = NULL` and `hold_until = now() + hold` (24 h custom, 5 min
random). Random and custom names use the same call. An in-memory implementation
follows the same rules and both are checked by one shared contract suite.

## Consequences

* Correct under concurrency without application-level locks (tested with many racing claimants, against PostgreSQL too).
* An owner reconnecting gets the same address; others cannot take it over during the hold.
* At start-up all active markers are cleared, which assumes a single gateway node. Multi-node operation needs a liveness lease instead.
