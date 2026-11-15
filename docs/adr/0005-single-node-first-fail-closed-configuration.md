# 5. Single node first, and fail-closed configuration

**Status:** accepted

## Context
The goal is a simple, safe self-hosted deployment, with room to scale later. The
only required input is seven environment variables; mistakes in them are the most
likely cause of an insecure or broken installation.

## Decision
* One gateway process owns all live sessions. State that must survive restarts (users, tokens, hostnames) is in PostgreSQL; live sessions, limits and the failed-login limiter are in memory. Redis is not introduced until something needs shared state.
* Configuration is validated at start-up and **all** problems are reported together, naming the variable but never its value. Placeholder and weak secrets are rejected. Production refuses `STORAGE=memory`.
* Secrets are generated once by `scripts/setup.sh` and never regenerated automatically.

## Consequences
* Simple to operate and to reason about; no distributed-systems failure modes yet.
* Horizontal scaling needs: a liveness lease for hostnames and ports, shared limit counters, and routing between nodes. The registry's data model does not have to change.
* A bad `.env` fails fast with a readable message instead of running half-configured.
