-- Traffic statistics: one row per hostname per hour (HTTP requests, server
-- errors, bytes). Counts are aggregated in the gateway and added here every
-- 30 seconds; rows older than 90 days are deleted.

CREATE TABLE usage_hourly (
    hostname   text NOT NULL,
    hour       timestamptz NOT NULL,
    user_id    uuid NOT NULL,        -- no FK: writes are batched; DeleteUser removes these
    requests   bigint NOT NULL DEFAULT 0,
    errors     bigint NOT NULL DEFAULT 0,
    bytes_in   bigint NOT NULL DEFAULT 0,
    bytes_out  bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (hostname, hour, user_id)  -- a name can change owner within an hour
);
CREATE INDEX usage_hourly_hour_idx ON usage_hourly(hour);
CREATE INDEX usage_hourly_user_idx ON usage_hourly(user_id, hour);
