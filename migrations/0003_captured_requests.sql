-- Request inspector. The exchange itself (method, URL, headers, bodies, client
-- address) is AES-256-GCM ciphertext under ENCRYPTION_KEY; only the columns
-- needed for listing and retention are stored in the clear. Rows are deleted
-- automatically after INSPECT_RETENTION.

CREATE TABLE captured_requests (
    id             uuid PRIMARY KEY,               -- also the AEAD associated data
    user_id        uuid,                           -- no FK: inserts are batched; DeleteUser removes these
    hostname       text NOT NULL,
    status         integer NOT NULL,
    duration_ms    bigint NOT NULL,
    request_bytes  bigint NOT NULL,
    response_bytes bigint NOT NULL,
    created_at     timestamptz NOT NULL,
    nonce          bytea NOT NULL,
    ciphertext     bytea NOT NULL
);
CREATE INDEX captured_requests_created_idx ON captured_requests(created_at);
CREATE INDEX captured_requests_host_idx ON captured_requests(hostname, created_at DESC);
