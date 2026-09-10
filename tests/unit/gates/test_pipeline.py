"""Gate pipeline (ADRL-SAF-001)."""

from __future__ import annotations

from collections.abc import Sequence

import pytest

from adrl.core.enums import GateMode, RequestClass, Rung, UtilityKind
from adrl.core.errors import ErrorCode
from adrl.core.ports import ContentBlock
from adrl.core.types import Finding
from adrl.gates.feasibility import StaticHealth
from adrl.gates.pipeline import GatePipeline
from adrl.ledger.egress import EgressLedger
from tests.unit.gates.conftest import (
    AWS_KEY,
    HMAC_KEY,
    continuation_with_tool_result,
    make_ctx,
    user_turn,
)


class _RaisingScanner:
    ruleset_version = "boom"

    def scan(self, blocks: Sequence[ContentBlock]) -> Sequence[Finding]:
        raise RuntimeError("scanner down")


async def test_clean_turn_permits_repo_ceiling(pipeline: GatePipeline) -> None:
    outcome = await pipeline.evaluate(user_turn("hello world"))
    assert outcome.block is None and not outcome.pinned and not outcome.unscanned
    assert outcome.permitted.rungs == frozenset(Rung)
    assert [v.gate for v in outcome.verdicts] == ["repo_class", "secret_scan", "feasibility"]
    assert outcome.repo_class == "open"


async def test_secret_in_tool_result_pins_that_request(
    pipeline: GatePipeline, egress_ledger: EgressLedger
) -> None:
    ctx = continuation_with_tool_result(f"AWS_ACCESS_KEY_ID={AWS_KEY}")
    outcome = await pipeline.evaluate(ctx)
    assert outcome.pinned and outcome.permitted.rungs == frozenset({Rung.LOCAL})
    assert outcome.block is None
    assert any(f.detector_id == "aws_access_key" for f in outcome.findings)
    kinds = [
        dict(r)["event_kind"]
        for r in egress_ledger._conn.execute("SELECT event_kind FROM egress_events")
    ]
    assert "pin" in kinds and "gate_verdict" in kinds
    later = await pipeline.evaluate(user_turn("next turn, no secret"))
    assert later.pinned and later.permitted.rungs == frozenset({Rung.LOCAL})


async def test_scanner_exception_unpinned_marks_unscanned_pinned_blocks(
    pipeline: GatePipeline,
) -> None:
    good_scanner = pipeline._scanner
    pipeline._scanner = _RaisingScanner()
    outcome = await pipeline.evaluate(user_turn("no secret"))
    assert outcome.unscanned and outcome.block is None
    assert outcome.permitted.rungs == frozenset(Rung), "unscanned never widens or narrows"

    pipeline._scanner = good_scanner
    await pipeline.evaluate(continuation_with_tool_result(f"key {AWS_KEY}", session="s2"))
    pipeline._scanner = _RaisingScanner()
    outcome2 = await pipeline.evaluate(user_turn("later", session="s2"))
    assert outcome2.block is ErrorCode.GATE_UNAVAILABLE and outcome2.pinned
    assert outcome2.block_response is not None and outcome2.block_response.status == 400


async def test_pinned_overflow_blocks_with_prompt_too_long(pipeline: GatePipeline) -> None:
    await pipeline.evaluate(continuation_with_tool_result(f"key {AWS_KEY}", session="s3"))
    big = user_turn("x" * (140_000 * 4), session="s3")
    outcome = await pipeline.evaluate(big)
    assert outcome.block is ErrorCode.CAPABILITY_REJECTED_PROMPT_TOO_LONG
    assert outcome.block_response is not None
    assert "prompt is too long" in outcome.block_response.body["error"]["message"]


async def test_pinned_local_unhealthy_blocks_loud(
    pipeline: GatePipeline, health: StaticHealth
) -> None:
    await pipeline.evaluate(continuation_with_tool_result(f"key {AWS_KEY}", session="s4"))
    health.set("adrl-local", False)
    health.set("adrl-local-large", False)
    outcome = await pipeline.evaluate(user_turn("hi", session="s4"))
    assert outcome.block is ErrorCode.PINNED_LOCAL_UNAVAILABLE


async def test_cosmetic_utility_on_pinned_lineage_served_empty_not_error(
    pipeline: GatePipeline, health: StaticHealth
) -> None:
    await pipeline.evaluate(continuation_with_tool_result(f"key {AWS_KEY}", session="s5"))
    health.set("adrl-local", False)
    health.set("adrl-local-large", False)
    ctx = make_ctx(
        {
            "model": "claude-haiku-4-5",
            "max_tokens": 64,
            "messages": [{"role": "user", "content": "t"}],
        },
        request_class=RequestClass.UTILITY,
        session="s5",
        utility_kind=UtilityKind.COSMETIC,
    )
    outcome = await pipeline.evaluate(ctx)
    assert outcome.block is None and outcome.serve_empty_utility


async def test_count_tokens_on_pinned_lineage_is_served_locally(pipeline: GatePipeline) -> None:
    await pipeline.evaluate(continuation_with_tool_result(f"key {AWS_KEY}", session="s6"))
    ctx = make_ctx(
        {"model": "claude-fable-5-1", "messages": [{"role": "user", "content": "count me"}]},
        request_class=RequestClass.PASSTHROUGH,
        path="/v1/messages/count_tokens",
        session="s6",
    )
    outcome = await pipeline.evaluate(ctx)
    assert outcome.serve_local_estimate and outcome.permitted.rungs == frozenset({Rung.LOCAL})


async def test_observe_mode_reports_would_block(pipeline: GatePipeline) -> None:
    # an authoritative pin taken under enforce still narrows in observe mode; the block that
    # would follow is reported, not returned
    await pipeline.evaluate(continuation_with_tool_result(f"key {AWS_KEY}", session="s7"))
    pipeline._mode = GateMode.OBSERVE
    outcome = await pipeline.evaluate(user_turn("x" * (140_000 * 4), session="s7"))
    assert outcome.block is None
    assert outcome.would_block is ErrorCode.CAPABILITY_REJECTED_PROMPT_TOO_LONG


async def test_restricted_repo_is_local_only_from_first_request(pipeline: GatePipeline) -> None:
    body = {
        "model": "m",
        "max_tokens": 10,
        "system": "git remote origin git@github.example.com:payments/core.git",
        "messages": [{"role": "user", "content": "hi"}],
    }
    outcome = await pipeline.evaluate(
        make_ctx(
            body,
            session="s8",
            repo_root="/tmp/payments",
            repo_remote="git@github.example.com:payments/core.git",
        )
    )
    assert outcome.permitted.rungs == frozenset({Rung.LOCAL})
    assert outcome.repo_class == "restricted" and not outcome.release_permitted


async def test_gate_latency_is_recorded(pipeline: GatePipeline) -> None:
    for i in range(5):
        await pipeline.evaluate(user_turn(f"turn {i}", session="s9"))
    p99 = pipeline.p99_latency()
    assert p99 is not None and p99 < 1.0


@pytest.mark.parametrize("request_class", list(RequestClass))
async def test_every_request_class_is_gated(
    pipeline: GatePipeline, request_class: RequestClass
) -> None:
    body = {"model": "m", "max_tokens": 1, "messages": [{"role": "user", "content": AWS_KEY}]}
    outcome = await pipeline.evaluate(
        make_ctx(body, request_class=request_class, session=f"rc-{request_class}")
    )
    assert outcome.pinned


async def test_finding_whose_pin_write_fails_is_blocked_not_unscanned(
    bundle, scanner, ledger_store, egress_ledger, feasibility
) -> None:  # type: ignore[no-untyped-def]
    """A scanner that finds a secret but cannot persist the pin fails closed (SAF-002)."""
    from adrl.gates.coverage import ScanCoverage
    from adrl.gates.egress import EgressWriter
    from adrl.gates.pin import PinRegistry
    from adrl.gates.repo_class import RepoClassifier
    from adrl.ledger.facade import PIN_EVENT, MemoryFacade
    from tests.unit.gates.test_pin_write_failure import FlakyOnceProvider

    facade = MemoryFacade(FlakyOnceProvider(ledger_store, fail_on=PIN_EVENT, times=99))
    pipeline = GatePipeline(
        classifier=RepoClassifier(bundle.repo_classification, facade),
        scanner=scanner,
        coverage=ScanCoverage(facade),
        pins=PinRegistry(facade, egress_ledger, deployment_tag="t"),
        feasibility=feasibility,
        egress=EgressWriter(egress_ledger, deployment_tag="t"),
        hmac_key=HMAC_KEY,
    )
    outcome = await pipeline.evaluate(
        continuation_with_tool_result(f"key {AWS_KEY}", session="pinfail")
    )
    assert outcome.pinned and not outcome.unscanned
    assert outcome.block is ErrorCode.GATE_UNAVAILABLE
    assert Rung.FRONTIER not in outcome.permitted and Rung.CHEAP_CLOUD not in outcome.permitted
