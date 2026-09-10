"""Prometheus SLIs named in the decisions. Primary: ADRL-FND-004.

Secondary: ADRL-SAF-001 (gate latency), ADRL-SAF-005 (block rate), ADRL-MEM-006, ADRL-SAF-009,
ADRL-SEM-001 (fingerprint divergence).
"""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

REGISTRY = CollectorRegistry()

FAIL_OPEN_TOTAL = Counter(
    "adrl_fail_open_total",
    "Automatic fail-open events by failure class and pin state",
    ["failure_class", "pinned"],
    registry=REGISTRY,
)
GATE_LATENCY_SECONDS = Histogram(
    "adrl_gate_latency_seconds",
    "Wall-clock of the full gate pipeline per request class",
    ["request_class"],
    buckets=(0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0),
    registry=REGISTRY,
)
BLOCK_TOTAL = Counter(
    "adrl_block_total", "Blocked requests by error code", ["code"], registry=REGISTRY
)
MEMORY_DEGRADED_TOTAL = Counter(
    "adrl_memory_degraded_total",
    "Decisions the memory facade could not persist",
    ["reason"],
    registry=REGISTRY,
)
LEDGER_DEGRADED_TOTAL = Counter(
    "adrl_ledger_degraded_total",
    "Unpinned requests forwarded with a failed egress append",
    registry=REGISTRY,
)
FINGERPRINT_DIVERGENCE_TOTAL = Counter(
    "adrl_fingerprint_divergence_total",
    "Requests where header-based and body-fingerprint classification disagreed",
    ["header_class", "fingerprint_class"],
    registry=REGISTRY,
)
REQUESTS_TOTAL = Counter(
    "adrl_requests_total",
    "Requests by class and served rung",
    ["request_class", "rung"],
    registry=REGISTRY,
)
UNSCANNED_TOTAL = Counter(
    "adrl_unscanned_total", "Requests forwarded with the unscanned mark", registry=REGISTRY
)
PIN_WRITE_FAILED_TOTAL = Counter(
    "adrl_pin_write_failed_total",
    "Pinning findings whose durable write failed; the request was failed closed (ADRL-SAF-002)",
    registry=REGISTRY,
)
EVENT_DROPPED_TOTAL = Counter(
    "adrl_event_dropped_total",
    "Ledger events the provider reported as not stored (duplicate key or degraded)",
    ["producer"],
    registry=REGISTRY,
)
EGRESS_CHECKPOINTS_TOTAL = Counter(
    "adrl_egress_checkpoints_total",
    "Signed egress checkpoints by trigger (count, interval, manual) (ADRL-SAF-009)",
    ["trigger"],
    registry=REGISTRY,
)
EGRESS_SHIP_FAILURES_TOTAL = Counter(
    "adrl_egress_ship_failures_total",
    "Checkpoint shipments that failed and will be retried",
    ["destination"],
    registry=REGISTRY,
)
EGRESS_UNSHIPPED_CHECKPOINTS = Gauge(
    "adrl_egress_unshipped_checkpoints",
    "Signed checkpoints not yet acknowledged by any anchor",
    registry=REGISTRY,
)
EGRESS_NEWEST_ANCHOR_AGE_SECONDS = Gauge(
    "adrl_egress_newest_anchor_age_seconds",
    "Age of the newest acknowledged anchor; absent anchors report -1",
    registry=REGISTRY,
)
SHADOW_FINDING_TOTAL = Counter(
    "adrl_shadow_finding_total",
    "Would-pin findings recorded in observe mode without pinning (ADRL-SAF-001 observe mode)",
    ["detector"],
    registry=REGISTRY,
)
