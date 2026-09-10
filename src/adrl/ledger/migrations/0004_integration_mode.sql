-- Explicit session coverage mode (ADRL-SEM-007, ADRL-MEM-001).
-- Existing preview-2 bindings were gateway bindings. No observation mode existed.
ALTER TABLE product_sessions ADD COLUMN integration_mode TEXT NOT NULL DEFAULT 'gateway'
    CHECK (integration_mode IN ('gateway', 'observe'));
