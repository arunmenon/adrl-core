-- Local operator verification receipts (ADRL-MEM-003, ADRL-MEM-001/010).
CREATE TABLE product_verifications (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    session_hmac TEXT NOT NULL REFERENCES product_sessions(session_hmac),
    job_key TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN ('started','finished')),
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    ts TEXT NOT NULL,
    UNIQUE(session_hmac, job_key, phase)
);
CREATE INDEX product_verifications_session_idx ON product_verifications(session_hmac, seq);
