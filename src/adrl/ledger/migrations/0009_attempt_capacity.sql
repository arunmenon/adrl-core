-- Reserved terminal quota. Primary: ADRL-MEM-002. Secondary: ADRL-MEM-001/005/010, ADRL-OPS-001.
ALTER TABLE product_attempt_events ADD COLUMN capacity_version INTEGER NOT NULL DEFAULT 0
    CHECK (capacity_version IN (0,1));

CREATE TABLE product_attempt_capacity (
    session_hmac TEXT NOT NULL,
    attempt_key TEXT NOT NULL,
    start_event_key TEXT NOT NULL,
    reserved_bytes INTEGER NOT NULL CHECK (reserved_bytes BETWEEN 1024 AND 4096),
    history_limit INTEGER NOT NULL CHECK (history_limit BETWEEN 1 AND 32000000),
    PRIMARY KEY (session_hmac, attempt_key),
    UNIQUE (session_hmac, start_event_key),
    FOREIGN KEY (session_hmac, start_event_key)
        REFERENCES product_attempt_events(session_hmac, event_key)
);
