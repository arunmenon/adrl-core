-- Evidence ledger schema v2 (ADRL-MEM-003, ADRL-MEM-005, ADRL-MEM-010). Additive only.
CREATE TABLE verification_jobs (
    seq             INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id          TEXT NOT NULL,
    route_id        TEXT NOT NULL,
    status          TEXT NOT NULL,
    payload_json    TEXT NOT NULL,
    ts              TEXT NOT NULL
);
CREATE INDEX verification_jobs_idx ON verification_jobs(job_id, seq);
CREATE INDEX verification_jobs_route_idx ON verification_jobs(route_id, seq);

CREATE TABLE instruction_hashes (
    seq             INTEGER PRIMARY KEY AUTOINCREMENT,
    route_id        TEXT NOT NULL,
    session_hmac    TEXT NOT NULL,
    hmac_key_id     TEXT NOT NULL,
    ciphertext      BLOB NOT NULL,
    nonce           BLOB NOT NULL,
    ts              TEXT NOT NULL
);
CREATE INDEX instruction_hashes_session_idx ON instruction_hashes(session_hmac, seq);
