-- Accounts: admins and users share the users table, told apart by role, so a
-- user can sign up on the web, sign in, and be promoted to admin (or back).
--
-- A user created the old way (by an admin making a token) has no email and
-- no password: they cannot sign in until an admin sets one. Limits are NULL
-- (no limit) for those users; sign up sets them, and admins ignore them.

ALTER TABLE users
    ADD COLUMN email               text CHECK (email IS NULL OR (email = lower(email) AND email <> '')),
    ADD COLUMN password_hash       text,                  -- PBKDF2-SHA256, never the password
    ADD COLUMN role                text NOT NULL DEFAULT 'user' CHECK (role IN ('admin', 'user')),
    ADD COLUMN email_verified_at   timestamptz,
    ADD COLUMN disabled_at         timestamptz,           -- set: no sign in, tokens refused
    ADD COLUMN password_changed_at timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN last_login_at       timestamptz,
    ADD COLUMN signed_up           boolean NOT NULL DEFAULT false, -- created by web sign up
    ADD COLUMN max_tokens          integer CHECK (max_tokens >= 0),
    ADD COLUMN max_custom_domains  integer CHECK (max_custom_domains >= 0);

CREATE UNIQUE INDEX users_email_key ON users (email) WHERE email IS NOT NULL;

-- Every admin becomes a user with role admin. An admin and a user with the
-- same name merge into one admin account that keeps the user's tokens and
-- hostnames.
INSERT INTO users (id, username, password_hash, role, password_changed_at, last_login_at, created_at)
SELECT id, username, password_hash, 'admin', password_changed_at, last_login_at, created_at FROM admins
ON CONFLICT (username) DO UPDATE SET
    password_hash       = EXCLUDED.password_hash,
    role                = 'admin',
    password_changed_at = EXCLUDED.password_changed_at,
    last_login_at       = EXCLUDED.last_login_at;

DROP TABLE admins;

-- One-time links sent by email: confirm an address, or reset a password.
-- Only a hash of the link's secret is stored. A link is deleted when used,
-- and is void when the account's email changed after it was sent.
CREATE TABLE email_tokens (
    token_hash  text PRIMARY KEY,                       -- SHA-256 of the secret
    user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose     text NOT NULL CHECK (purpose IN ('verify', 'reset')),
    email       text NOT NULL,
    expires_at  timestamptz NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX email_tokens_user_idx ON email_tokens (user_id, purpose);
CREATE INDEX email_tokens_expiry_idx ON email_tokens (expires_at);

-- What admins did to accounts and the gateway, newest first in the dashboard.
CREATE TABLE audit_log (
    id      bigserial PRIMARY KEY,
    at      timestamptz NOT NULL DEFAULT now(),
    actor   text NOT NULL,                 -- username, or "system"
    action  text NOT NULL,                 -- e.g. user.role, user.disable
    target  text NOT NULL DEFAULT '',      -- what it was done to
    detail  text NOT NULL DEFAULT ''
);
CREATE INDEX audit_log_at_idx ON audit_log (at DESC);
