-- Local product bindings and encrypted observations (ADRL-TRU-001, ADRL-MEM-001/010).
CREATE TABLE product_sessions (
    session_hmac TEXT PRIMARY KEY,
    workload_ref TEXT NOT NULL,
    adapter_id TEXT NOT NULL,
    adapter_version TEXT NOT NULL,
    profile_id TEXT NOT NULL,
    profile_version TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    config_digest TEXT NOT NULL,
    ts TEXT NOT NULL
);
CREATE TABLE product_events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    session_hmac TEXT NOT NULL REFERENCES product_sessions(session_hmac),
    producer_id TEXT NOT NULL,
    event_key TEXT NOT NULL,
    producer_seq INTEGER NOT NULL,
    route_id TEXT,
    event_type TEXT NOT NULL,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    sequence_status TEXT NOT NULL,
    ts TEXT NOT NULL,
    UNIQUE(producer_id, event_key),
    UNIQUE(producer_id, producer_seq)
);
CREATE INDEX product_events_session_idx ON product_events(session_hmac, seq);
-- Reference-only projection. Index order is not a claim of execution order.
CREATE TABLE product_timeline (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    session_hmac TEXT NOT NULL,
    source TEXT NOT NULL,
    source_seq INTEGER NOT NULL,
    route_id TEXT,
    ts TEXT NOT NULL,
    UNIQUE(source, source_seq)
);
CREATE INDEX product_timeline_session_idx ON product_timeline(session_hmac, seq);
