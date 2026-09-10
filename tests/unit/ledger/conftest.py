"""Fixtures for ledger evidence tests: keystore, decision and event helpers, fake sandbox runner."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from adrl.core.enums import OutcomeState, Rung
from adrl.core.ids import RouteId, mint_route_id
from adrl.core.ports import SandboxResult
from adrl.core.types import Decision, PermittedSet
from adrl.ledger.events import (
    PRODUCER_CASCADE,
    OutcomeFields,
    outcome_event,
)
from adrl.ledger.keystore import FileKeyStore
from adrl.ledger.store import LedgerStore


@pytest.fixture
def keystore(ledger_store: LedgerStore, tmp_path: Path) -> FileKeyStore:
    return FileKeyStore(tmp_path / "keystore", store=ledger_store)


def decision_for(route_id: RouteId, rung: Rung = Rung.LOCAL, **features: Any) -> Decision:
    return Decision(
        route_id=route_id,
        rung=rung,
        permitted=PermittedSet.all(),
        estimator="band-heuristic",
        estimator_version="v1",
        policy_version="policy-v1",
        objective_version="objective-v1",
        cascade_feasible=True,
        cascade_reason=None,
        features={"band_id": "clear-local", "repo_class": "default", **features},
        features_version="features-v1",
    )


def write_decision(
    store: LedgerStore,
    *,
    session: str = "sess",
    lineage: str = "lin",
    rung: Rung = Rung.LOCAL,
    request_class: str = "user_turn",
    route_id: RouteId | None = None,
) -> RouteId:
    rid = route_id or mint_route_id()
    store.submit(
        LedgerStore.insert_decision(
            decision_for(rid, rung).as_row(),
            {
                "session_hmac": session,
                "lineage_hmac": lineage,
                "request_class": request_class,
                "content_bearing": True,
            },
        )
    ).result(timeout=5)
    return rid


def write_outcome(
    store: LedgerStore,
    route_id: RouteId,
    state: OutcomeState,
    *,
    producer_seq: int,
    session: str = "sess",
    lineage: str = "lin",
    served_rung: str = "local",
    causes: Sequence[Any] = (),
    touched_paths: Sequence[str] = (),
    harness_reported_success: bool | None = None,
    tree_identity: Mapping[str, Any] | None = None,
    extra: Mapping[str, Any] | None = None,
) -> None:
    event = outcome_event(
        route_id,
        state,
        PRODUCER_CASCADE,
        producer_seq,
        OutcomeFields(
            served_rung=served_rung,
            session_hmac=session,
            lineage_hmac=lineage,
            causes=tuple(causes),
            touched_paths=tuple(touched_paths),
            harness_reported_success=harness_reported_success,
            tree_identity=tree_identity,
            extra=dict(extra or {}),
        ),
    )
    store.submit(
        LedgerStore.insert_event(
            event.route_id,
            event.event_type,
            event.producer,
            event.producer_seq,
            event.payload,
            event.schema_version,
        )
    ).result(timeout=5)


@dataclass
class FakeRunner:
    """Subprocess-free SandboxRunner: exit codes by argv[0]; can be marked unavailable."""

    exit_codes: dict[str, int] = field(default_factory=dict)
    available: bool = True
    calls: list[tuple[str, ...]] = field(default_factory=list)

    def run(
        self, argv: Sequence[str], snapshot_dir: str, allow_list: Sequence[str], *, timeout_s: float
    ) -> SandboxResult:
        self.calls.append(tuple(argv))
        if not self.available:
            return SandboxResult(available=False, unavailable_reason="sandbox_unavailable")
        code = self.exit_codes.get(argv[0], 0)
        return SandboxResult(available=True, exit_code=code, duration_s=0.01)

    @property
    def platform_id(self) -> str:
        return "fake"
