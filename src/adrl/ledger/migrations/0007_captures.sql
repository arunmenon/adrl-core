-- Retained operator captures. Primary: ADRL-MEM-001. Secondary: ADRL-MEM-010.
CREATE TABLE product_captures (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    session_hmac TEXT NOT NULL REFERENCES product_sessions(session_hmac),
    capture_key TEXT NOT NULL,
    attempt_key TEXT NOT NULL,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    ts TEXT NOT NULL,
    UNIQUE(session_hmac, capture_key),
    UNIQUE(session_hmac, attempt_key)
);
CREATE INDEX product_captures_session_idx ON product_captures(session_hmac, seq);
