-- Stopped resource ownership. Primary: ADRL-OPS-001. Secondary: ADRL-MEM-001/002/005/010.
CREATE TABLE product_resource_events (
    operation_key TEXT NOT NULL,
    workspace_key TEXT NOT NULL,
    event_seq INTEGER NOT NULL CHECK (event_seq BETWEEN 0 AND 4),
    event_type TEXT NOT NULL CHECK (event_type IN
        ('intent','create_issued','bound','remove_issued','removed')),
    payload_json TEXT NOT NULL CHECK (length(CAST(payload_json AS BLOB)) <= 4096),
    prev_mac TEXT NOT NULL,
    mac TEXT NOT NULL,
    PRIMARY KEY (operation_key,event_seq),
    UNIQUE (workspace_key,event_seq),
    FOREIGN KEY (workspace_key) REFERENCES product_execution_fences(workspace_key)
);
