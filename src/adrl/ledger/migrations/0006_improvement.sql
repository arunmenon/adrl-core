-- Offline experiment history. Primary: ADRL-MEM-001. Secondary: ADRL-MEM-010.
CREATE TABLE improvement_records (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    experiment_hmac TEXT NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type IN ('started','trial','finished')),
    record_key TEXT NOT NULL UNIQUE,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    ts TEXT NOT NULL
);
CREATE INDEX improvement_records_experiment_idx ON improvement_records(experiment_hmac,seq);
