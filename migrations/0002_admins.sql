-- Dashboard operators. Separate from "users" (who own agent tokens and
-- hostnames): an admin manages the gateway, a user runs agents.

CREATE TABLE admins (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    username            text NOT NULL UNIQUE CHECK (username = lower(username) AND username <> ''),
    password_hash       text NOT NULL,          -- PBKDF2-SHA256, never the password
    password_changed_at timestamptz NOT NULL DEFAULT now(),
    last_login_at       timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now()
);
