-- Local operator attempt history. Primary: ADRL-MEM-002. Secondary: ADRL-MEM-001/010.
CREATE TABLE product_attempt_events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    session_hmac TEXT NOT NULL REFERENCES product_sessions(session_hmac),
    attempt_key TEXT NOT NULL,
    event_key TEXT NOT NULL,
    workspace_key TEXT NOT NULL,
    event_type TEXT NOT NULL,
    attempt_seq INTEGER NOT NULL CHECK (attempt_seq >= 0),
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    ts TEXT NOT NULL,
    UNIQUE(session_hmac, event_key),
    UNIQUE(session_hmac, attempt_key, attempt_seq)
);
CREATE INDEX product_attempt_identity_idx ON product_attempt_events(session_hmac, attempt_key);
CREATE INDEX product_attempt_workspace_idx ON product_attempt_events(workspace_key, seq);
