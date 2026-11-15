-- Long-term traffic statistics. Every flush adds the same counts to three
-- tables in one transaction:
--   usage_hourly  per hour, kept 90 days (recent windows)
--   usage_daily   per day, kept forever (long-term history)
--   usage_total   one row per hostname and user, kept forever (lifetime)

CREATE TABLE usage_daily (
    hostname   text NOT NULL,
    day        date NOT NULL,        -- UTC
    user_id    uuid NOT NULL,
    requests   bigint NOT NULL DEFAULT 0,
    errors     bigint NOT NULL DEFAULT 0,
    bytes_in   bigint NOT NULL DEFAULT 0,
    bytes_out  bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (hostname, day, user_id)
);
CREATE INDEX usage_daily_user_idx ON usage_daily(user_id, day);

CREATE TABLE usage_total (
    hostname   text NOT NULL,
    user_id    uuid NOT NULL,
    requests   bigint NOT NULL DEFAULT 0,
    errors     bigint NOT NULL DEFAULT 0,
    bytes_in   bigint NOT NULL DEFAULT 0,
    bytes_out  bigint NOT NULL DEFAULT 0,
    first_seen timestamptz NOT NULL,
    last_seen  timestamptz NOT NULL,
    PRIMARY KEY (hostname, user_id)
);
CREATE INDEX usage_total_user_idx ON usage_total(user_id);

-- Carry over what the hourly table already holds.
INSERT INTO usage_daily (hostname, day, user_id, requests, errors, bytes_in, bytes_out)
SELECT hostname, (hour AT TIME ZONE 'UTC')::date, user_id, sum(requests), sum(errors), sum(bytes_in), sum(bytes_out)
FROM usage_hourly GROUP BY 1, 2, 3;

INSERT INTO usage_total (hostname, user_id, requests, errors, bytes_in, bytes_out, first_seen, last_seen)
SELECT hostname, user_id, sum(requests), sum(errors), sum(bytes_in), sum(bytes_out), min(hour), max(hour)
FROM usage_hourly GROUP BY 1, 2;
