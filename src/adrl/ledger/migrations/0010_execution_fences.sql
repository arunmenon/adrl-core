-- Persistent workspace blocks. Primary: ADRL-OPS-001. Secondary: ADRL-MEM-001/002/005/010.
CREATE TABLE product_execution_fences (
    workspace_key TEXT PRIMARY KEY NOT NULL,
    session_hmac TEXT NOT NULL,
    attempt_key TEXT NOT NULL,
    start_event_key TEXT NOT NULL,
    host_key_id TEXT NOT NULL,
    policy_json TEXT NOT NULL CHECK (length(policy_json) BETWEEN 1 AND 1024),
    ts TEXT NOT NULL,
    UNIQUE (session_hmac, attempt_key),
    FOREIGN KEY (session_hmac, start_event_key)
        REFERENCES product_attempt_events(session_hmac, event_key)
);
