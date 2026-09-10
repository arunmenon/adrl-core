"""Schema upcasters for old event payloads. Primary: ADRL-MEM-001. Secondary: ADRL-MEM-004.

Readers tolerate unknown fields and upcast old versions. The failure-type enum went from four
types (failure-types-v1: task_capability, harness_dialect, infrastructure, policy_constraint)
to seven (failure-types-v2). Legacy trip-wire type names that some v1 producers wrote into the
failure_type field are mapped as documented in LEGACY_FAILURE_ALIASES; anything unplaceable
becomes unverifiable, never task_capability (ADRL-MEM-004 clause 2).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from adrl.core.enums import FAILURE_TYPES_VERSION, FailureType
from adrl.core.types import LedgerEvent

FAILURE_TYPES_V1 = "failure-types-v1"

FAILURE_TYPES_V1_MEMBERS: frozenset[str] = frozenset(
    {
        FailureType.TASK_CAPABILITY.value,
        FailureType.HARNESS_DIALECT.value,
        FailureType.INFRASTRUCTURE.value,
        FailureType.POLICY_CONSTRAINT.value,
    }
)

LEGACY_FAILURE_ALIASES: dict[str, FailureType] = {
    "dialect": FailureType.HARNESS_DIALECT,
    "difficulty": FailureType.TASK_CAPABILITY,
    "cost": FailureType.TASK_CAPABILITY,
    "quality": FailureType.USER_ABORT,
    "user_abort": FailureType.USER_ABORT,
    "unverifiable": FailureType.UNVERIFIABLE,
}

Upcaster = Callable[[Mapping[str, Any]], dict[str, Any]]


def _failure_v1_to_v2(payload: Mapping[str, Any]) -> dict[str, Any]:
    out = dict(payload)
    notes: list[str] = list(out.get("upcast_notes", []))
    for key in ("failure_type", "secondary_type"):
        raw = out.get(key)
        if raw is None:
            continue
        value = str(raw)
        if value in FAILURE_TYPES_V1_MEMBERS:
            continue
        alias = LEGACY_FAILURE_ALIASES.get(value)
        if alias is not None:
            out[key] = alias.value
            notes.append(f"{key}: {value} -> {alias.value}")
        else:
            out[key] = FailureType.UNVERIFIABLE.value
            notes.append(f"{key}: {value} -> unverifiable (unplaceable)")
    causes = out.get("causes")
    if isinstance(causes, list):
        fixed: list[Any] = []
        for cause in causes:
            if isinstance(cause, dict) and "failure_type" in cause:
                fixed.append(_failure_v1_to_v2(cause))
            else:
                fixed.append(cause)
        out["causes"] = fixed
    out["failure_types_version"] = FAILURE_TYPES_VERSION
    if notes:
        out["upcast_notes"] = notes
    return out


UPCASTERS: dict[str, Upcaster] = {FAILURE_TYPES_V1: _failure_v1_to_v2}


def upcast_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Return a payload at the current schema; unknown fields pass through untouched."""
    current = dict(payload)
    carries_failure = any(
        k in current for k in ("failure_type", "secondary_type", "causes", "label")
    )
    version = str(current.get("failure_types_version") or FAILURE_TYPES_V1)
    if carries_failure and version != FAILURE_TYPES_VERSION:
        upcaster = UPCASTERS.get(version)
        if upcaster is None:
            current["failure_type"] = FailureType.UNVERIFIABLE.value
            current["upcast_notes"] = [f"unknown failure_types_version {version}"]
            current["failure_types_version"] = FAILURE_TYPES_VERSION
        else:
            current = upcaster(current)
    label = current.get("label")
    if isinstance(label, dict):
        current["label"] = upcast_payload(label)
    return current


def upcast_event(event: LedgerEvent) -> LedgerEvent:
    return LedgerEvent(
        route_id=event.route_id,
        event_type=event.event_type,
        producer=event.producer,
        producer_seq=event.producer_seq,
        payload=upcast_payload(event.payload),
        schema_version=event.schema_version,
    )
