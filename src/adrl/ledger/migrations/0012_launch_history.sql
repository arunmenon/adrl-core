-- One-shot fixture launch history. Primary: ADRL-OPS-001. Secondary: ADRL-MEM-001/002/010.
CREATE TABLE product_launch_events (
    operation_key TEXT NOT NULL,
    event_seq INTEGER NOT NULL CHECK (event_seq BETWEEN 0 AND 7),
    event_type TEXT NOT NULL CHECK (event_type IN
        ('claim','acknowledged','sealed','stopped','discard_issued','discarded')),
    payload_json TEXT NOT NULL CHECK (length(CAST(payload_json AS BLOB)) <= 4096),
    prev_mac TEXT NOT NULL,
    mac TEXT NOT NULL,
    PRIMARY KEY (operation_key,event_seq)
);
