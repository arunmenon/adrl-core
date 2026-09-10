-- Evidence ledger schema v1 (ADRL-MEM-001). Append-only: no statement in src/ updates or deletes.
CREATE TABLE decisions (
    route_id            TEXT PRIMARY KEY,
    ts                  TEXT NOT NULL,
    session_hmac        TEXT NOT NULL,
    lineage_hmac        TEXT NOT NULL,
    request_class       TEXT NOT NULL,
    content_bearing     INTEGER NOT NULL,
    permitted_set       TEXT NOT NULL,
    decided_rung        TEXT NOT NULL,
    estimator           TEXT NOT NULL,
    estimator_version   TEXT NOT NULL,
    policy_version      TEXT NOT NULL,
    objective_version   TEXT NOT NULL,
    cascade_feasible    INTEGER NOT NULL,
    cascade_reason      TEXT,
    features_json       TEXT NOT NULL,
    features_version    TEXT NOT NULL,
    propensity          REAL NOT NULL DEFAULT 1.0,
    explore_version     TEXT,
    no_rung_met_threshold INTEGER NOT NULL DEFAULT 0,
    classifier_provenance_json TEXT,
    context_json        TEXT NOT NULL,
    schema_version      TEXT NOT NULL
);
CREATE INDEX decisions_lineage_idx ON decisions(lineage_hmac, ts);
CREATE INDEX decisions_session_idx ON decisions(session_hmac, ts);

CREATE TABLE events (
    seq             INTEGER PRIMARY KEY AUTOINCREMENT,
    route_id        TEXT NOT NULL,
    event_type      TEXT NOT NULL,
    producer        TEXT NOT NULL,
    producer_seq    INTEGER NOT NULL,
    ts              TEXT NOT NULL,
    schema_version  TEXT NOT NULL,
    payload_json    TEXT NOT NULL,
    UNIQUE (route_id, event_type, producer, producer_seq)
);
CREATE INDEX events_route_idx ON events(route_id, seq);
CREATE INDEX events_type_idx ON events(event_type, seq);

CREATE TABLE lineage_events (
    seq             INTEGER PRIMARY KEY AUTOINCREMENT,
    lineage_hmac    TEXT NOT NULL,
    event_type      TEXT NOT NULL,
    ts              TEXT NOT NULL,
    payload_json    TEXT NOT NULL
);
CREATE INDEX lineage_events_idx ON lineage_events(lineage_hmac, seq);
CREATE INDEX lineage_events_type_idx ON lineage_events(event_type, seq);

CREATE TABLE embeddings (
    seq                 INTEGER PRIMARY KEY AUTOINCREMENT,
    route_id            TEXT NOT NULL,
    session_hmac        TEXT NOT NULL,
    ciphertext          BLOB NOT NULL,
    nonce               BLOB NOT NULL,
    embedder_version    TEXT NOT NULL,
    dimension           INTEGER NOT NULL,
    ts                  TEXT NOT NULL
);
CREATE INDEX embeddings_session_idx ON embeddings(session_hmac, seq);

CREATE TABLE session_keys (
    seq             INTEGER PRIMARY KEY AUTOINCREMENT,
    session_hmac    TEXT NOT NULL,
    key_id          TEXT NOT NULL,
    wrapped_key     BLOB,
    action          TEXT NOT NULL,
    reason          TEXT,
    ts              TEXT NOT NULL
);
CREATE INDEX session_keys_idx ON session_keys(session_hmac, seq);

CREATE TABLE projections (
    seq                 INTEGER PRIMARY KEY AUTOINCREMENT,
    name                TEXT NOT NULL,
    high_water_seq      INTEGER NOT NULL,
    embedder_version    TEXT,
    code_version        TEXT NOT NULL,
    state               TEXT NOT NULL,
    ts                  TEXT NOT NULL
);
CREATE INDEX projections_name_idx ON projections(name, seq);
