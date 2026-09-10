"""Durable one-way pin (ADRL-SAF-002)."""

from __future__ import annotations

import pytest

from adrl.core.enums import DetectorTier, ReleaseReason
from adrl.core.errors import GateFailure
from adrl.core.ids import LineageId
from adrl.core.types import Finding
from adrl.gates.pin import PinRegistry, ReleaseRefused
from adrl.gates.suppression import LoggingSuppressionSink
from adrl.ledger.egress import EgressLedger
from tests.unit.gates.conftest import user_turn


def _finding(fid: str = "fnd_1") -> Finding:
    return Finding("aws_access_key", DetectorTier.HIGH_CONFIDENCE, "ab" * 32, fid, "tool_result")


async def test_pin_is_written_to_both_ledgers_and_suppression_called(
    pins: PinRegistry, egress_ledger: EgressLedger, suppression: LoggingSuppressionSink
) -> None:
    ctx = user_turn("hello")
    await pins.pin(ctx, _finding())
    assert await pins.is_pinned(ctx.lineage_hmac)
    assert egress_ledger.count() == 1
    assert suppression.calls and suppression.calls[0][0] == ctx.lineage_hmac


async def test_pin_survives_close_and_reopen(reopenable_store: dict) -> None:  # type: ignore[type-arg]
    store, facade, egress = reopenable_store["open"]()
    ctx = user_turn("hello")
    registry = PinRegistry(facade, egress, deployment_tag="t")
    await registry.pin(ctx, _finding())
    egress.close()
    store.close()

    store, facade, egress = reopenable_store["open"]()
    registry = PinRegistry(facade, egress, deployment_tag="t")
    assert await registry.is_pinned(ctx.lineage_hmac)
    assert (await registry.effective_pin(ctx)) is not None
    egress.close()
    store.close()


async def test_release_is_per_finding_and_new_finding_repins(pins: PinRegistry) -> None:
    ctx = user_turn("hello")
    await pins.pin(ctx, _finding("fnd_a"))
    await pins.release(
        ctx.lineage_hmac, "fnd_a", ReleaseReason.FALSE_POSITIVE, "alice", release_permitted=True
    )
    assert not await pins.is_pinned(ctx.lineage_hmac)
    await pins.pin(ctx, _finding("fnd_b"))
    assert await pins.is_pinned(ctx.lineage_hmac)
    assert [r.finding_id for r in pins.active_pins(ctx.lineage_hmac)] == ["fnd_b"]


async def test_release_refused_for_restricted_repo(pins: PinRegistry) -> None:
    ctx = user_turn("hello")
    await pins.pin(ctx, _finding())
    with pytest.raises(ReleaseRefused):
        await pins.release(
            ctx.lineage_hmac, "fnd_1", ReleaseReason.TEST_FIXTURE, "bob", release_permitted=False
        )
    assert await pins.is_pinned(ctx.lineage_hmac)


async def test_release_unknown_finding_fails(pins: PinRegistry) -> None:
    with pytest.raises(GateFailure):
        await pins.release(
            LineageId("nope"), "fnd_x", ReleaseReason.TEST_FIXTURE, "bob", release_permitted=True
        )


async def test_parent_pin_inherited_child_pin_not_propagated(pins: PinRegistry) -> None:
    parent = user_turn("parent")
    child = user_turn("child", agent_id="agent-1", parent_agent_id=None)
    pins.observe(parent)
    assert (await pins.effective_pin(child)) is None
    await pins.pin(parent, _finding("fnd_parent"))
    assert (await pins.effective_pin(child)) is not None

    other_parent = user_turn("p2", session="sess-2")
    other_child = user_turn("c2", session="sess-2", agent_id="agent-2")
    await pins.pin(other_child, _finding("fnd_child"))
    assert (await pins.effective_pin(other_child)) is not None
    assert (await pins.effective_pin(other_parent)) is None
