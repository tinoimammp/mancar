-- Phase 1-3 schema: identities, agent credentials and hostname reservations.
-- Tables for later milestones (tunnels history, certificates, api_keys,
-- traffic_logs, auth_policies, audit_logs, system_settings) are added by the
-- migrations that introduce those features.

CREATE TABLE users (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    username    text NOT NULL UNIQUE CHECK (username = lower(username) AND username <> ''),
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE agent_tokens (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         text NOT NULL,
    token_hash   text NOT NULL UNIQUE,          -- SHA-256 of the token, never the token
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    revoked_at   timestamptz
);
CREATE INDEX agent_tokens_user_id_idx ON agent_tokens(user_id);

-- One row per reserved hostname. The UNIQUE constraint on hostname is what
-- makes reservation atomic (see Registry.Claim).
CREATE TABLE domains (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname         text NOT NULL UNIQUE CHECK (hostname = lower(hostname)),
    user_id          uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind             text NOT NULL CHECK (kind IN ('random', 'custom')),
    active_tunnel_id text,                      -- NULL when no tunnel is connected
    hold_until       timestamptz NOT NULL DEFAULT now(),
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX domains_user_id_idx ON domains(user_id);
CREATE INDEX domains_expiry_idx ON domains(hold_until) WHERE active_tunnel_id IS NULL;
