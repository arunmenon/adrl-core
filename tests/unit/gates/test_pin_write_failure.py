"""A detected secret never reaches the cloud when the pin write fails (ADRL-SAF-002, FND-004).

Promoted from the conformance reviewer's repro. Also covers the transient facade degradation
(ADRL-MEM-006), cross-process release visibility (SAF-002 clause 3) and the fail-open record
written for gate-internal failures (FND-004).
"""

from __future__ import annotations

import json
from typing import Any

from adrl.core.enums import ReleaseReason, Rung
from adrl.core.errors import ErrorCode
from adrl.core.ports import LineageEvent
from adrl.gates.coverage import ScanCoverage
from adrl.gates.egress import EgressWriter
from adrl.gates.pin import PinRegistry
from adrl.gates.pipeline import FAIL_OPEN_EVENT, GatePipeline
from adrl.gates.repo_class import RepoClassifier
from adrl.ledger.facade import PIN_EVENT, MemoryFacade, SqliteLedgerProvider
from tests.unit.gates.conftest import AWS_KEY, HMAC_KEY, continuation_with_tool_result, user_turn


class FlakyOnceProvider(SqliteLedgerProvider):
    """Raises exactly once on the first append of `fail_on`, then behaves normally."""

    def __init__(self, store: Any, fail_on: str, times: int = 1) -> None:
        super().__init__(store)
        self._fail_on = fail_on
        self.failures_left = times
        self.failed = 0

    async def append_lineage_event(self, event: LineageEvent) -> int:
        if event.event_type == self._fail_on and self.failures_left > 0:
            self.failures_left -= 1
            self.failed += 1
            raise RuntimeError("database is locked")
        return await super().append_lineage_event(event)


class _RaisingClassifier(RepoClassifier):
    async def classify(self, ctx: Any, blocks: Any) -> Any:
        raise RuntimeError("manifest unreadable")


def _pipeline(
    bundle: Any,
    scanner: Any,
    facade: MemoryFacade,
    egress_ledger: Any,
    feasibility: Any,
    *,
    classifier: RepoClassifier | None = None,
    pins: PinRegistry | None = None,
) -> GatePipeline:
    return GatePipeline(
        classifier=classifier or RepoClassifier(bundle.repo_classification, facade),
        scanner=scanner,
        coverage=ScanCoverage(facade),
        pins=pins or PinRegistry(facade, egress_ledger, deployment_tag="t"),
        feasibility=feasibility,
        egress=EgressWriter(egress_ledger, deployment_tag="t"),
        hmac_key=HMAC_KEY,
    )


async def test_transient_pin_append_failure_on_the_pinning_request_fails_closed(
    bundle: Any, scanner: Any, ledger_store: Any, egress_ledger: Any, feasibility: Any
) -> None:
    provider = FlakyOnceProvider(ledger_store, fail_on=PIN_EVENT)
    facade = MemoryFacade(provider)
    pipeline = _pipeline(bundle, scanner, facade, egress_ledger, feasibility)
    outcome = await pipeline.evaluate(
        continuation_with_tool_result(f"AWS_ACCESS_KEY_ID={AWS_KEY}", session="flaky")
    )
    assert outcome.pinned
    assert not outcome.unscanned, "a pin write failure is never an unscanned fail-open"
    assert Rung.FRONTIER not in outcome.permitted and Rung.CHEAP_CLOUD not in outcome.permitted
    # one transient failure is retried within the same request and the pin lands durably
    assert provider.failed == 1
    assert await facade.pin_state(outcome.pin_record.lineage) is not None


async def test_persistent_pin_write_failure_blocks_and_stays_pinned_in_process(
    bundle: Any, scanner: Any, ledger_store: Any, egress_ledger: Any, feasibility: Any
) -> None:
    provider = FlakyOnceProvider(ledger_store, fail_on=PIN_EVENT, times=10)
    facade = MemoryFacade(provider)
    pins = PinRegistry(facade, egress_ledger, deployment_tag="t")
    pipeline = _pipeline(bundle, scanner, facade, egress_ledger, feasibility, pins=pins)
    outcome = await pipeline.evaluate(
        continuation_with_tool_result(f"AWS_ACCESS_KEY_ID={AWS_KEY}", session="down")
    )
    assert outcome.pinned and outcome.block is ErrorCode.GATE_UNAVAILABLE
    assert outcome.permitted.rungs <= frozenset({Rung.LOCAL})
    assert not outcome.unscanned
    # the next request on the same lineage is still pinned even though nothing was durable
    later = await pipeline.evaluate(user_turn("anything", session="down"))
    assert later.pinned and Rung.FRONTIER not in later.permitted
    # once the provider recovers, the retry lands the pin durably on the next lookup
    provider.failures_left = 0
    recovered = await pipeline.evaluate(user_turn("again", session="down"))
    assert recovered.pinned and recovered.block is None
    events = await facade.read_lineage_events(recovered.pin_record.lineage, PIN_EVENT)
    assert events, "the undurable pin was written once the ledger recovered"


async def test_earlier_transient_failure_does_not_poison_later_pins(
    bundle: Any, scanner: Any, ledger_store: Any, egress_ledger: Any, feasibility: Any
) -> None:
    provider = FlakyOnceProvider(ledger_store, fail_on="scan_coverage")
    facade = MemoryFacade(provider)
    pipeline = _pipeline(bundle, scanner, facade, egress_ledger, feasibility)
    clean = await pipeline.evaluate(user_turn("no secret here", session="poison"))
    assert not clean.pinned
    assert facade.degraded_episodes == 1
    outcome = await pipeline.evaluate(
        continuation_with_tool_result(f"AWS_ACCESS_KEY_ID={AWS_KEY}", session="poison2")
    )
    assert outcome.pinned and outcome.block is None
    assert not facade.degraded, "degradation is transient and cleared by the next success"
    events = await facade.read_lineage_events(outcome.pin_record.lineage, PIN_EVENT)
    assert len(events) == 1


async def test_release_from_another_registry_is_visible_without_restart(
    bundle: Any, scanner: Any, ledger_store: Any, egress_ledger: Any, feasibility: Any
) -> None:
    facade_a = MemoryFacade(SqliteLedgerProvider(ledger_store))
    facade_b = MemoryFacade(SqliteLedgerProvider(ledger_store))
    pins_a = PinRegistry(facade_a, egress_ledger, deployment_tag="a")
    pins_b = PinRegistry(facade_b, egress_ledger, deployment_tag="b")
    proxy = _pipeline(bundle, scanner, facade_a, egress_ledger, feasibility, pins=pins_a)
    # neutral text after the key keeps the scanner's split-secret tail free of the key
    outcome = await proxy.evaluate(
        continuation_with_tool_result(f"AWS_ACCESS_KEY_ID={AWS_KEY}\n" + "ok " * 40, session="rel")
    )
    assert outcome.pinned and outcome.pin_record is not None
    lineage = outcome.pin_record.lineage
    assert await pins_b.is_pinned(lineage)
    # the operator CLI runs in another process: a second registry over the same store
    await pins_b.release(
        lineage,
        outcome.pin_record.finding_id,
        ReleaseReason.FALSE_POSITIVE,
        "operator",
        release_permitted=True,
    )
    after = await proxy.evaluate(user_turn("next request", session="rel"))
    assert not after.pinned, "the live proxy sees the release on its next request"


async def test_gate_internal_fail_open_records_exactly_one_event_with_real_pin_state(
    bundle: Any, scanner: Any, ledger_store: Any, egress_ledger: Any, feasibility: Any
) -> None:
    facade = MemoryFacade(SqliteLedgerProvider(ledger_store))
    pipeline = _pipeline(
        bundle,
        scanner,
        facade,
        egress_ledger,
        feasibility,
        classifier=_RaisingClassifier(bundle.repo_classification, facade),
    )
    ctx = user_turn("hello", session="fo")
    outcome = await pipeline.evaluate(ctx)
    assert outcome.unscanned and outcome.block is None and not outcome.pinned
    events = await facade.read_lineage_events(ctx.lineage_hmac, FAIL_OPEN_EVENT)
    assert len(events) == 1
    assert events[0].payload["pinned"] is False
    assert events[0].payload["failure_class"] == "gate_path"
    rows = egress_ledger.events_for_lineage(str(ctx.lineage_hmac), "fail_open")
    assert len(rows) == 1, rows
    verdicts = json.loads(str(rows[0]["gate_verdicts_json"]))
    assert verdicts[0]["pinned"] is False and verdicts[0]["failure_class"] == "gate_path"
