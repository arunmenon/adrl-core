"""Outcome lifecycle: pending, closed_turn, closed_final. Primary: ADRL-MEM-002.

Secondary: ADRL-MEM-004 (label freeze), ADRL-CAS-005 (episode boundary trigger).

The closing window is a parameter, not a promise: close-v1 emits closed_final after N subsequent
user turns in the same session, T minutes of session inactivity, or an explicit episode boundary,
whichever comes first. The rule id and trigger are stored on the event so a longer window can be
applied retroactively by replay. Evidence arriving after closed_final is appended as late_evidence
and the label is re-derived; the freeze point is recorded, the truth keeps moving.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from statistics import median
from typing import Any

import structlog

from adrl.config.models import CloseRule
from adrl.core.enums import FailureType, OutcomeState
from adrl.core.ids import RouteId
from adrl.core.types import LedgerEvent
from adrl.ledger.events import (
    EPISODE_BOUNDARY_EVENT,
    LABEL_CORRECTION_EVENT,
    LABEL_EVENT,
    LATE_EVIDENCE_EVENT,
    OUTCOME_EVENT,
    PRODUCER_CLOSER,
    PRODUCER_CORRECTION,
    PRODUCER_LABELER,
    CauseCandidate,
    StoredEvent,
    label_event,
    late_evidence_event,
    outcome_event,
    producer_seq_for,
    read_stored_events,
    stored_event_from_row,
)
from adrl.ledger.labels import Label, derive_label, outcome_state
from adrl.ledger.store import LedgerStore, utc_now_iso

log = structlog.get_logger(__name__)


def _parse_ts(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class OutcomeProjection:
    """Current state of one route, derived from its events (never a source of truth)."""

    route_id: RouteId
    state: OutcomeState | None
    pending_ts: str | None
    closed_turn_ts: str | None
    closed_final_ts: str | None
    closed_final_rule_id: str | None
    label: Label
    late_evidence_count: int
    session_hmac: str | None
    lineage_hmac: str | None

    @property
    def countable(self) -> bool:
        return self.state is OutcomeState.CLOSED_FINAL


def project_outcome(route_id: RouteId, events: Sequence[StoredEvent]) -> OutcomeProjection:
    pending_ts = closed_turn_ts = closed_final_ts = rule_id = None
    session = lineage = None
    late = 0
    for event in events:
        if event.event_type == OUTCOME_EVENT:
            state = str(event.payload.get("state"))
            if state == OutcomeState.PENDING.value and pending_ts is None:
                pending_ts = event.ts
            elif state == OutcomeState.CLOSED_TURN.value:
                closed_turn_ts = event.ts
            elif state == OutcomeState.CLOSED_FINAL.value:
                closed_final_ts = event.ts
                rule_id = event.payload.get("rule_id")
            session = event.payload.get("session_hmac") or session
            lineage = event.payload.get("lineage_hmac") or lineage
        elif event.event_type == LATE_EVIDENCE_EVENT:
            late += 1
    return OutcomeProjection(
        route_id=route_id,
        state=outcome_state(events),
        pending_ts=pending_ts,
        closed_turn_ts=closed_turn_ts,
        closed_final_ts=closed_final_ts,
        closed_final_rule_id=str(rule_id) if rule_id else None,
        label=derive_label(events),
        late_evidence_count=late,
        session_hmac=str(session) if session else None,
        lineage_hmac=str(lineage) if lineage else None,
    )


def read_projection(store: LedgerStore, route_id: RouteId) -> OutcomeProjection:
    return project_outcome(route_id, read_stored_events(store, route_id))


def _latest_outcome_rows(store: LedgerStore) -> list[StoredEvent]:
    rows = store.read(
        "SELECT e.* FROM events e JOIN (SELECT route_id, MAX(seq) AS mseq FROM events "
        "WHERE event_type=? GROUP BY route_id) m ON e.seq = m.mseq ORDER BY e.seq",
        (OUTCOME_EVENT,),
    )
    return [stored_event_from_row(r) for r in rows]


def routes_in_state(store: LedgerStore, state: OutcomeState) -> list[StoredEvent]:
    return [e for e in _latest_outcome_rows(store) if str(e.payload.get("state")) == state.value]


class Closer:
    """Emits closed_final under a named rule; idempotent per (route_id, rule_id)."""

    def __init__(self, store: LedgerStore, rule: CloseRule) -> None:
        self._store = store
        self._rule = rule

    @property
    def rule_id(self) -> str:
        return self._rule.rule_id

    def _session_of(
        self, route_id: RouteId, payload: Mapping[str, Any]
    ) -> tuple[str | None, str | None]:
        session = payload.get("session_hmac")
        lineage = payload.get("lineage_hmac")
        if session is None or lineage is None:
            row = self._store.read_decision(str(route_id))
            if row is not None:
                session = session or row["session_hmac"]
                lineage = lineage or row["lineage_hmac"]
        return (str(session) if session else None, str(lineage) if lineage else None)

    def trigger_for(self, closed_turn: StoredEvent, *, now: datetime) -> str | None:
        """Return the trigger name if the closing window has elapsed, else None."""
        session, lineage = self._session_of(closed_turn.route_id, closed_turn.payload)
        if lineage is not None:
            boundaries = self._store.read(
                "SELECT seq FROM lineage_events WHERE lineage_hmac=? AND event_type=? AND ts>? "
                "LIMIT 1",
                (lineage, EPISODE_BOUNDARY_EVENT, closed_turn.ts),
            )
            if boundaries:
                return "episode_boundary"
        if session is not None:
            turns = self._store.read(
                "SELECT COUNT(*) AS c FROM decisions WHERE session_hmac=? AND "
                "request_class='user_turn' AND ts>?",
                (session, closed_turn.ts),
            )[0]["c"]
            if int(turns) >= self._rule.subsequent_turns:
                return "subsequent_turns"
            last = self._store.read(
                "SELECT MAX(ts) AS t FROM decisions WHERE session_hmac=?", (session,)
            )[0]["t"]
            last_activity = _parse_ts(str(last)) if last else _parse_ts(closed_turn.ts)
        else:
            last_activity = _parse_ts(closed_turn.ts)
        idle = (now - max(last_activity, _parse_ts(closed_turn.ts))).total_seconds() / 60.0
        if idle >= self._rule.idle_minutes:
            return "idle"
        return None

    async def close_route(self, closed_turn: StoredEvent, trigger: str) -> bool:
        events = read_stored_events(self._store, closed_turn.route_id)
        label = derive_label(events)
        session, lineage = self._session_of(closed_turn.route_id, closed_turn.payload)
        event = outcome_event(
            closed_turn.route_id,
            OutcomeState.CLOSED_FINAL,
            PRODUCER_CLOSER,
            producer_seq_for(self._rule.rule_id),
            rule_id=self._rule.rule_id,
            trigger=trigger,
            label=label.as_dict(),
        )
        payload = dict(event.payload)
        payload["closed_turn_seq"] = closed_turn.seq
        payload["session_hmac"] = session
        payload["lineage_hmac"] = lineage
        ok = bool(
            await self._store.write_through(
                LedgerStore.insert_event(
                    event.route_id,
                    event.event_type,
                    event.producer,
                    event.producer_seq,
                    payload,
                    event.schema_version,
                )
            )
        )
        if ok:
            await self._store.write_through(
                LedgerStore.insert_event(
                    event.route_id,
                    LABEL_EVENT,
                    PRODUCER_LABELER,
                    producer_seq_for("closed_final", self._rule.rule_id),
                    {**label.as_dict(), "supersedes_seq": None},
                    event.schema_version,
                )
            )
        return ok

    async def scan(self, *, now: datetime | None = None) -> list[tuple[RouteId, str]]:
        """Close every route whose window has elapsed. Returns (route_id, trigger) pairs."""
        current = now or datetime.now(UTC)
        closed: list[tuple[RouteId, str]] = []
        for closed_turn in routes_in_state(self._store, OutcomeState.CLOSED_TURN):
            trigger = self.trigger_for(closed_turn, now=current)
            if trigger is None:
                continue
            if await self.close_route(closed_turn, trigger):
                closed.append((closed_turn.route_id, trigger))
        return closed


async def append_late_evidence(
    store: LedgerStore,
    route_id: RouteId,
    *,
    source: str,
    detail: Mapping[str, Any],
    causes: Sequence[CauseCandidate] = (),
    producer: str = PRODUCER_CORRECTION,
    evidence_id: str | None = None,
) -> Label:
    """Append late evidence and re-derive the label; returns the new label."""
    ident = evidence_id or json.dumps(dict(detail), sort_keys=True, default=str)
    event = late_evidence_event(
        route_id, source, producer, producer_seq_for(source, ident), detail, causes=causes
    )
    await store.write_through(
        LedgerStore.insert_event(
            event.route_id,
            event.event_type,
            event.producer,
            event.producer_seq,
            event.payload,
            event.schema_version,
        )
    )
    events = read_stored_events(store, route_id)
    label = derive_label(events)
    previous = [e for e in events if e.event_type in (LABEL_EVENT, LABEL_CORRECTION_EVENT)]
    supersedes = previous[-1].seq if previous else None
    if outcome_state(events) is OutcomeState.CLOSED_FINAL or previous:
        correction = label_event(
            route_id,
            producer_seq_for("late", source, ident),
            label.as_dict(),
            supersedes_seq=supersedes,
        )
        await store.write_through(
            LedgerStore.insert_event(
                correction.route_id,
                correction.event_type,
                correction.producer,
                correction.producer_seq,
                correction.payload,
                correction.schema_version,
            )
        )
    return label


def current_label(store: LedgerStore, route_id: RouteId) -> Label:
    return derive_label(read_stored_events(store, route_id))


class HumanCorrectionDetector:
    """Late evidence from ledger-visible human corrections (ADRL-MEM-002 follow-up).

    A later route in the same session whose closed_turn reports touched_paths overlapping the
    routed turn's touched_paths, or a revert_paths entry touching them, within the window is a
    correction. Paths are keyed hashes supplied by the producer, never raw paths.
    """

    def __init__(self, store: LedgerStore, window_minutes: int) -> None:
        self._store = store
        self._window = window_minutes

    def find(self, route_id: RouteId) -> list[dict[str, Any]]:
        events = read_stored_events(self._store, route_id)
        touched: set[str] = set()
        closed_turn_ts: str | None = None
        session: str | None = None
        for event in events:
            if event.event_type != OUTCOME_EVENT:
                continue
            touched.update(str(p) for p in event.payload.get("touched_paths", []) or [])
            session = event.payload.get("session_hmac") or session
            if str(event.payload.get("state")) == OutcomeState.CLOSED_TURN.value:
                closed_turn_ts = event.ts
        if not touched or closed_turn_ts is None:
            return []
        if session is None:
            row = self._store.read_decision(str(route_id))
            session = str(row["session_hmac"]) if row else None
        if session is None:
            return []
        rows = self._store.read(
            "SELECT e.* FROM events e WHERE e.event_type=? AND e.route_id!=? AND e.ts>? "
            "AND json_extract(e.payload_json,'$.session_hmac')=? ORDER BY e.seq",
            (OUTCOME_EVENT, str(route_id), closed_turn_ts, session),
        )
        limit = _parse_ts(closed_turn_ts).timestamp() + self._window * 60
        found: list[dict[str, Any]] = []
        for row in rows:
            event = stored_event_from_row(row)
            if _parse_ts(event.ts).timestamp() > limit:
                break
            later = set(str(p) for p in event.payload.get("touched_paths", []) or [])
            reverted = set(str(p) for p in event.payload.get("revert_paths", []) or [])
            overlap = sorted(touched & (later | reverted))
            if overlap:
                found.append(
                    {
                        "correcting_route_id": str(event.route_id),
                        "correcting_seq": event.seq,
                        "overlap": overlap,
                        "kind": "revert" if touched & reverted else "re_edit",
                    }
                )
        return found

    async def emit(self, route_id: RouteId) -> int:
        emitted = 0
        for hit in self.find(route_id):
            await append_late_evidence(
                self._store,
                route_id,
                source="human_correction",
                detail=hit,
                causes=(CauseCandidate(FailureType.TASK_CAPABILITY, None, "human_correction"),),
                evidence_id=str(hit["correcting_seq"]),
            )
            emitted += 1
        return emitted


@dataclass(frozen=True, slots=True)
class CloseMeasurements:
    time_to_close_seconds: tuple[float, ...]
    label_flip_fraction: float
    closed_final_count: int

    @property
    def median_seconds(self) -> float | None:
        return median(self.time_to_close_seconds) if self.time_to_close_seconds else None


def measure_closing(store: LedgerStore) -> CloseMeasurements:
    """Time-to-close distribution and the fraction of labels that changed after closed_turn."""
    rows = store.read(
        "SELECT DISTINCT route_id FROM events WHERE event_type=? AND "
        "json_extract(payload_json,'$.state')=?",
        (OUTCOME_EVENT, OutcomeState.CLOSED_FINAL.value),
    )
    durations: list[float] = []
    flips = 0
    total = 0
    for row in rows:
        route_id = RouteId(str(row["route_id"]))
        events = read_stored_events(store, route_id)
        projection = project_outcome(route_id, events)
        if projection.closed_turn_ts is None or projection.closed_final_ts is None:
            continue
        total += 1
        evidence_ts = [e.ts for e in events if e.event_type == LATE_EVIDENCE_EVENT] or [
            projection.closed_final_ts
        ]
        start = _parse_ts(projection.closed_turn_ts)
        durations.append((_parse_ts(evidence_ts[-1]) - start).total_seconds())
        frozen = next(
            (
                e.payload.get("label")
                for e in events
                if e.event_type == OUTCOME_EVENT
                and str(e.payload.get("state")) == OutcomeState.CLOSED_FINAL.value
            ),
            None,
        )
        if isinstance(frozen, dict):
            now = projection.label.as_dict()
            if (frozen.get("result"), frozen.get("failure_type")) != (
                now["result"],
                now["failure_type"],
            ):
                flips += 1
    return CloseMeasurements(tuple(durations), (flips / total) if total else 0.0, total)


def ledger_event_to_write(event: LedgerEvent) -> Any:
    """Convenience: a WriteFn for a typed event."""
    return LedgerStore.insert_event(
        event.route_id,
        event.event_type,
        event.producer,
        event.producer_seq,
        event.payload,
        event.schema_version,
    )


def now_iso() -> str:
    return utc_now_iso()
