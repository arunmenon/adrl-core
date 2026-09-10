"""Pre-decision features, enforced by construction. Primary: ADRL-LRN-004.
Also implements: ADRL-EVL-002 (register additions of 2026-09-03).

Secondary: ADRL-LRN-001 (T1-only holdout), ADRL-MEM-007 (as-of projections).

Training reads only the feature snapshot the router persisted at decision time. The deny-list
is checked on every row, neighbours must be strictly earlier than the query decision, and
splits are temporal and session-grouped. Random K-fold is rejected by construction.
"""

from __future__ import annotations

import fnmatch
import json
import math
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

import numpy as np

from adrl.config.models import LearningContract
from adrl.core.enums import EvidenceTier, Rung
from adrl.core.ids import RouteId, route_id_timestamp_ms
from adrl.learning.tiers import PoolingError, TieredExample
from adrl.ledger.store import LedgerStore

EMBEDDING_MISSING_FEATURE = "embedding_missing"
NEIGHBOUR_FEATURE_PREFIX = "neighbour_"
DATASET_VERSION = "dataset-v1"


class LeakageError(ValueError):
    """A feature, neighbour or split would leak post-decision information (ADRL-LRN-004)."""


class ForbiddenSplitError(ValueError):
    """A split strategy the decision prohibits (random K-fold over dependent turns)."""


def deny_listed(name: str, contract: LearningContract) -> bool:
    for pattern in contract.deny_list:
        if name == pattern or fnmatch.fnmatchcase(name, pattern):
            return True
        if pattern.endswith("_*") and name.startswith(pattern[:-1]):
            return True
    return name.startswith(("outcome_", "verified_", "closed_"))


@dataclass(frozen=True, slots=True)
class FeatureRow:
    route_id: RouteId
    session_hmac: str
    ts: str
    features: Mapping[str, Any]
    tier: EvidenceTier
    label: int | None
    rung: Rung
    propensity: float
    slice_id: str


@dataclass(slots=True)
class FeatureFrame:
    rows: list[FeatureRow] = field(default_factory=list)
    features_version: str = ""
    dataset_version: str = DATASET_VERSION

    def __len__(self) -> int:
        return len(self.rows)

    def labelled(self) -> FeatureFrame:
        return FeatureFrame(
            [r for r in self.rows if r.label is not None],
            self.features_version,
            self.dataset_version,
        )

    def tiers(self) -> frozenset[EvidenceTier]:
        return frozenset(r.tier for r in self.rows)

    def sessions(self) -> frozenset[str]:
        return frozenset(r.session_hmac for r in self.rows)


def build_frame(
    items: Iterable[TieredExample],
    contract: LearningContract,
    *,
    feature_source: Literal["decision_snapshot"] = "decision_snapshot",
) -> FeatureFrame:
    """Build a frame from tiered examples using only the decision-time snapshot.

    The feature_source parameter exists so a manifest naming any other source is rejected
    loudly (ADRL-LRN-004 clause 1) rather than silently recomputed.
    """
    if feature_source != "decision_snapshot":
        raise LeakageError(f"feature source {feature_source!r} is not the decision snapshot")
    allowed = {spec.name for spec in contract.features}
    frame = FeatureFrame(features_version=contract.feature_schema_version)
    for item in items:
        example = item.example
        if example.features_version != contract.feature_schema_version:
            raise LeakageError(
                f"{example.route_id}: snapshot version {example.features_version} does not "
                f"match contract {contract.feature_schema_version}"
            )
        cleaned: dict[str, Any] = {}
        for name, value in example.features.items():
            if deny_listed(name, contract):
                raise LeakageError(f"{example.route_id}: deny-listed feature {name}")
            if name in allowed or name.startswith(NEIGHBOUR_FEATURE_PREFIX):
                cleaned[name] = value
        missing = not any(
            name.startswith(NEIGHBOUR_FEATURE_PREFIX) and value is not None
            for name, value in cleaned.items()
        )
        cleaned[EMBEDDING_MISSING_FEATURE] = bool(example.privacy_suppressed or missing)
        frame.rows.append(
            FeatureRow(
                route_id=example.route_id,
                session_hmac=str(example.session_hmac),
                ts=example.decision_ts,
                features=cleaned,
                tier=item.tier,
                label=example.label,
                rung=example.rung,
                propensity=example.propensity,
                slice_id=example.slice_id,
            )
        )
    return frame


# as-of neighbour features ----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class NeighbourRecord:
    route_id: RouteId
    rung: Rung
    success: bool


class AsOfNeighbourSource(Protocol):
    """Neighbours computed from a projection frozen at the query decision's position."""

    def neighbours(self, route_id: RouteId, *, k: int) -> Sequence[NeighbourRecord]: ...


class LedgerNeighbourSource:
    """Neighbours read from the ledger strictly before the query decision (ADRL-MEM-007).

    Similarity here is the band and request class recorded in the snapshot, which is the
    projection-free fallback; an embedding projection plugs in through the same Protocol.
    """

    def __init__(self, store: LedgerStore, *, outcome_event: str = "outcome") -> None:
        self._store = store
        self._outcome_event = outcome_event

    def neighbours(self, route_id: RouteId, *, k: int) -> Sequence[NeighbourRecord]:
        query = self._store.read_decision(route_id)
        if query is None:
            return []
        rows = self._store.read(
            "SELECT d.route_id, d.decided_rung, e.payload_json FROM decisions d "
            "JOIN events e ON e.route_id = d.route_id AND e.event_type = ? "
            "WHERE d.ts < ? AND d.route_id < ? AND e.ts < ? "
            "AND json_extract(d.features_json, '$.band_id') = "
            "json_extract(?, '$.band_id') "
            "ORDER BY d.ts DESC LIMIT ?",
            (
                self._outcome_event,
                query["ts"],
                route_id,
                query["ts"],
                query["features_json"],
                int(k),
            ),
        )
        records: list[NeighbourRecord] = []
        for row in rows:
            payload = json.loads(row["payload_json"])
            if payload.get("state") != "closed_final":
                continue
            success = payload.get("failure_type") is None and bool(payload.get("success", True))
            records.append(
                NeighbourRecord(RouteId(row["route_id"]), Rung(row["decided_rung"]), success)
            )
        return records


def attach_neighbour_features(
    frame: FeatureFrame, source: AsOfNeighbourSource, *, k: int = 20
) -> FeatureFrame:
    """Attach neighbour_* features; a neighbour later than the query is a leak."""
    out = FeatureFrame(features_version=frame.features_version)
    for row in frame.rows:
        query_ms = route_id_timestamp_ms(row.route_id)
        records = source.neighbours(row.route_id, k=k)
        for record in records:
            if route_id_timestamp_ms(record.route_id) >= query_ms:
                raise LeakageError(
                    f"neighbour {record.route_id} is not earlier than query {row.route_id}"
                )
        local = [r for r in records if r.rung is Rung.LOCAL]
        features = dict(row.features)
        features["neighbour_count"] = len(records)
        features["neighbour_local_success_rate"] = (
            sum(1 for r in local if r.success) / len(local) if local else None
        )
        features[EMBEDDING_MISSING_FEATURE] = bool(
            row.features.get(EMBEDDING_MISSING_FEATURE, False) and not records
        )
        out.rows.append(
            FeatureRow(
                row.route_id,
                row.session_hmac,
                row.ts,
                features,
                row.tier,
                row.label,
                row.rung,
                row.propensity,
                row.slice_id,
            )
        )
    return out


# splits ---------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TemporalSplit:
    train: FeatureFrame
    holdout: FeatureFrame
    dropped_straddling_sessions: int
    cutoff_ts: str


def temporal_session_split(
    frame: FeatureFrame,
    *,
    holdout_fraction: float = 0.3,
    require_t1_holdout: bool = True,
) -> TemporalSplit:
    """Time-ordered, session-grouped split (ADRL-LRN-004 clause 3).

    Sessions whose first decision is at or after the cutoff form the holdout; sessions whose
    last decision is before the cutoff form the training set; sessions straddling the cutoff
    are dropped so no session spans both and every holdout row is later than every train row.
    """
    if not 0.0 < holdout_fraction < 1.0:
        raise ValueError("holdout_fraction must be within (0, 1)")
    ordered = sorted(frame.rows, key=lambda r: (r.ts, r.route_id))
    if not ordered:
        return TemporalSplit(FeatureFrame(), FeatureFrame(), 0, "")
    cut_index = math.floor(len(ordered) * (1.0 - holdout_fraction))
    cut_index = min(max(cut_index, 0), len(ordered) - 1)
    cutoff_ts = ordered[cut_index].ts
    first_ts: dict[str, str] = {}
    last_ts: dict[str, str] = {}
    for row in ordered:
        first_ts.setdefault(row.session_hmac, row.ts)
        last_ts[row.session_hmac] = row.ts
    train = FeatureFrame(features_version=frame.features_version)
    holdout = FeatureFrame(features_version=frame.features_version)
    dropped: set[str] = set()
    for row in ordered:
        session = row.session_hmac
        if first_ts[session] >= cutoff_ts:
            holdout.rows.append(row)
        elif last_ts[session] < cutoff_ts:
            train.rows.append(row)
        else:
            dropped.add(session)
    if train.sessions() & holdout.sessions():
        raise LeakageError("a session spans train and holdout")
    if (
        train.rows
        and holdout.rows
        and max(r.ts for r in train.rows) >= min(r.ts for r in holdout.rows)
    ):
        raise LeakageError("holdout is not strictly later than training")
    if require_t1_holdout:
        assert_frame_is_t1(holdout)
    return TemporalSplit(train, holdout, len(dropped), cutoff_ts)


def assert_frame_is_t1(frame: FeatureFrame) -> None:
    """The evaluation holdout is T1-only (ADRL-LRN-001 clause 2)."""
    offending = sorted({r.tier.value for r in frame.rows if not r.tier.enters_objective})
    if offending:
        raise PoolingError("holdout contains non-T1 tiers: " + ",".join(offending))


def split(frame: FeatureFrame, strategy: str, **kwargs: Any) -> TemporalSplit:
    """Dispatch on strategy; random K-fold is prohibited (ADRL-LRN-004 clause 3)."""
    if strategy in ("random_kfold", "kfold", "shuffle"):
        raise ForbiddenSplitError(
            f"{strategy} is prohibited: turns within a session are dependent (ADRL-LRN-004)"
        )
    if strategy != "temporal_session":
        raise ValueError(f"unknown split strategy {strategy}")
    return temporal_session_split(frame, **kwargs)


# encoding -------------------------------------------------------------------------------


@dataclass(slots=True)
class FeatureEncoder:
    """Deterministic encoder: numeric columns as floats, strings one-hot with a fixed vocab."""

    contract: LearningContract
    vocab: dict[str, list[str]] = field(default_factory=dict)
    columns: list[str] = field(default_factory=list)

    def fit(self, frame: FeatureFrame) -> FeatureEncoder:
        categorical: dict[str, set[str]] = defaultdict(set)
        numeric: set[str] = set()
        for row in frame.rows:
            for name, value in row.features.items():
                if deny_listed(name, self.contract):
                    raise LeakageError(f"deny-listed feature {name}")
                if isinstance(value, str):
                    categorical[name].add(value)
                elif value is None or isinstance(value, bool | int | float):
                    numeric.add(name)
        self.vocab = {name: sorted(values) for name, values in sorted(categorical.items())}
        self.columns = sorted(numeric)
        for name, values in self.vocab.items():
            self.columns.extend(f"{name}={value}" for value in values)
            self.columns.append(f"{name}=<unknown>")
        return self

    def transform(self, frame: FeatureFrame) -> np.ndarray:
        if not self.columns:
            raise ValueError("encoder is not fitted")
        index = {name: i for i, name in enumerate(self.columns)}
        matrix = np.zeros((len(frame.rows), len(self.columns)), dtype=float)
        for r, row in enumerate(frame.rows):
            for name, value in row.features.items():
                if name in self.vocab:
                    key = f"{name}={value}" if f"{name}={value}" in index else f"{name}=<unknown>"
                    matrix[r, index[key]] = 1.0
                elif name in index:
                    if value is None:
                        matrix[r, index[name]] = float("nan")
                    else:
                        matrix[r, index[name]] = float(value)
        col_means = np.nanmean(matrix, axis=0) if len(frame.rows) else np.zeros(len(self.columns))
        nan_mask = np.isnan(matrix)
        if nan_mask.any():
            matrix[nan_mask] = np.take(np.nan_to_num(col_means), np.where(nan_mask)[1])
        return matrix

    def fit_transform(self, frame: FeatureFrame) -> np.ndarray:
        return self.fit(frame).transform(frame)


def labels(frame: FeatureFrame) -> np.ndarray:
    values = [row.label for row in frame.rows]
    if any(v is None for v in values):
        raise ValueError("frame has unlabelled rows; call labelled() first")
    return np.asarray(values, dtype=float)


def treatments(frame: FeatureFrame, treatment_rung: Rung) -> np.ndarray:
    return np.asarray([1.0 if row.rung is treatment_rung else 0.0 for row in frame.rows])
