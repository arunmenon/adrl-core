"""Logging, metrics and semantic conventions. Primary: ADRL-OPS-001 (referenced by gloss)."""

from adrl.telemetry.logging import bind_request, configure_logging
from adrl.telemetry.metrics import (
    BLOCK_TOTAL,
    FAIL_OPEN_TOTAL,
    FINGERPRINT_DIVERGENCE_TOTAL,
    GATE_LATENCY_SECONDS,
    LEDGER_DEGRADED_TOTAL,
    MEMORY_DEGRADED_TOTAL,
    REGISTRY,
)

__all__ = [
    "BLOCK_TOTAL",
    "FAIL_OPEN_TOTAL",
    "FINGERPRINT_DIVERGENCE_TOTAL",
    "GATE_LATENCY_SECONDS",
    "LEDGER_DEGRADED_TOTAL",
    "MEMORY_DEGRADED_TOTAL",
    "REGISTRY",
    "bind_request",
    "configure_logging",
]
