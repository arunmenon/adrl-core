"""Observe mode is observational: shadow findings never pin, narrow or shred (ADRL-SAF-001)."""

from __future__ import annotations

from adrl.core.enums import GateMode, Rung
from adrl.core.errors import GateFailure
from adrl.gates.pin import SHADOW_FINDING_EVENT, PinRegistry
from adrl.gates.pipeline import GatePipeline
from adrl.gates.suppression import LoggingSuppressionSink
from adrl.ledger.facade import PIN_EVENT, MemoryFacade
from tests.unit.gates.conftest import AWS_KEY, continuation_with_tool_result, user_turn


async def test_observe_mode_records_shadow_finding_without_pinning(
    pipeline: GatePipeline, facade: MemoryFacade, suppression: LoggingSuppressionSink
) -> None:
    pipeline._mode = GateMode.OBSERVE
    ctx = continuation_with_tool_result(f"AWS_ACCESS_KEY_ID={AWS_KEY}", session="obs")
    outcome = await pipeline.evaluate(ctx)
    assert outcome.would_pin and not outcome.pinned
    assert outcome.permitted.rungs == frozenset(Rung), "nothing narrowed"
    assert outcome.shadow_findings and outcome.block is None
    assert await facade.read_lineage_events(ctx.lineage_hmac, SHADOW_FINDING_EVENT)
    assert not await facade.read_lineage_events(ctx.lineage_hmac, PIN_EVENT)
    assert suppression.calls == [], "no embeddings shredded in observe mode"


async def test_switching_to_enforce_does_not_pin_from_historical_shadow_findings(
    pipeline: GatePipeline, suppression: LoggingSuppressionSink
) -> None:
    pipeline._mode = GateMode.OBSERVE
    await pipeline.evaluate(continuation_with_tool_result(f"key {AWS_KEY}", session="hist"))
    pipeline._mode = GateMode.ENFORCE
    later = await pipeline.evaluate(user_turn("no secret here", session="hist"))
    assert not later.pinned and later.permitted.rungs == frozenset(Rung)
    assert suppression.calls == []


async def test_promotion_is_the_only_path_from_shadow_to_pin(
    pipeline: GatePipeline, pins: PinRegistry, suppression: LoggingSuppressionSink
) -> None:
    pipeline._mode = GateMode.OBSERVE
    ctx = continuation_with_tool_result(f"key {AWS_KEY}", session="promo")
    outcome = await pipeline.evaluate(ctx)
    finding_id = outcome.shadow_findings[0].finding_id
    pipeline._mode = GateMode.ENFORCE
    record = await pins.promote_shadow(ctx.lineage_hmac, finding_id, "security-oncall")
    assert not record.released and record.finding_id == finding_id
    assert len(suppression.calls) == 1, "promotion applies the suppression a pin would have"
    after = await pipeline.evaluate(user_turn("next turn", session="promo"))
    assert after.pinned and after.permitted.rungs == frozenset({Rung.LOCAL})
    try:
        await pins.promote_shadow(ctx.lineage_hmac, "no-such-finding", "x")
    except GateFailure as exc:
        assert "no shadow finding" in exc.detail
    else:
        raise AssertionError("unknown shadow finding must be refused")
