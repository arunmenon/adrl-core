"""Adversarial suite for the SAF gates (ADRL-SAF-001 follow-up).

Every case named in the SAF ADRs. Results are asserted where the ADR fixes the expected
behaviour; the remaining cases record what happened so the suite can be published.
"""

from __future__ import annotations

import base64

from adrl.core.enums import RequestClass, Rung
from adrl.gates.pipeline import GatePipeline
from tests.unit.gates.conftest import AWS_KEY, continuation_with_tool_result, make_ctx


async def test_aws_key_in_tool_result_pins_on_that_request(pipeline: GatePipeline) -> None:
    outcome = await pipeline.evaluate(
        continuation_with_tool_result(f"export K={AWS_KEY}", session="a1")
    )
    assert outcome.pinned and outcome.permitted.rungs == frozenset({Rung.LOCAL})


async def test_base64_encoded_key_pins(pipeline: GatePipeline) -> None:
    encoded = base64.b64encode(f"aws_access_key_id = {AWS_KEY}".encode()).decode()
    outcome = await pipeline.evaluate(
        continuation_with_tool_result(f"blob: {encoded}", session="a2")
    )
    assert outcome.pinned


async def test_key_split_across_two_reads_pins_on_second(pipeline: GatePipeline) -> None:
    first = continuation_with_tool_result(f"prefix {AWS_KEY[:8]}", session="a3")
    assert not (await pipeline.evaluate(first)).pinned
    body = dict(first.json)
    body["messages"] = [
        *first.json["messages"],
        {
            "role": "assistant",
            "content": [
                {"type": "tool_use", "id": "t2", "name": "Read", "input": {"file_path": "/x"}}
            ],
        },
        {
            "role": "user",
            "content": [
                {"type": "tool_result", "tool_use_id": "t2", "content": f"{AWS_KEY[8:]} suffix"}
            ],
        },
    ]
    second = make_ctx(body, request_class=RequestClass.CONTINUATION, session="a3")
    outcome = await pipeline.evaluate(second)
    assert outcome.pinned, "tail carry-over must see the joined token"


async def test_pem_header_inside_document_block_is_unscanned(pipeline: GatePipeline) -> None:
    body = {
        "model": "m",
        "max_tokens": 10,
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "document",
                        "source": {
                            "type": "base64",
                            "media_type": "application/pdf",
                            "data": "JVBERi0=",
                        },
                    }
                ],
            }
        ],
    }
    outcome = await pipeline.evaluate(make_ctx(body, session="a4"))
    assert outcome.unscanned and not outcome.pinned
    ceiling = pipeline.pins  # the repo ceiling is the only narrowing; unscanned adds none
    assert ceiling is not None
    assert outcome.permitted.rungs == frozenset(Rung), (
        "unscanned cannot widen or narrow beyond the repo ceiling (asserted open repo)"
    )


async def test_uncorroborated_high_entropy_is_shadow_only(pipeline: GatePipeline) -> None:
    outcome = await pipeline.evaluate(
        continuation_with_tool_result(
            "hash: Zm9vYmFyYmF6cXV4cXV1eHF1dXhxdXV4YWJjZGVm",
            path_hint="/repo/README.md",
            session="a5",
        )
    )
    assert not outcome.pinned
    assert any(f.shadow for f in outcome.findings)


async def test_secret_in_subagent_delegation_text_pins_child_only(pipeline: GatePipeline) -> None:
    child = make_ctx(
        {
            "model": "m",
            "max_tokens": 10,
            "messages": [{"role": "user", "content": f"use {AWS_KEY} to deploy"}],
        },
        request_class=RequestClass.SUBAGENT,
        session="a6",
        agent_id="agent-x",
    )
    outcome = await pipeline.evaluate(child)
    assert outcome.pinned
    parent = make_ctx(
        {"model": "m", "max_tokens": 10, "messages": [{"role": "user", "content": "hi"}]},
        session="a6",
    )
    assert not (await pipeline.evaluate(parent)).pinned


async def test_count_tokens_on_pinned_lineage_not_forwarded(pipeline: GatePipeline) -> None:
    await pipeline.evaluate(continuation_with_tool_result(f"k {AWS_KEY}", session="a7"))
    ctx = make_ctx(
        {"model": "m", "messages": [{"role": "user", "content": "x"}]},
        request_class=RequestClass.PASSTHROUGH,
        path="/v1/messages/count_tokens",
        session="a7",
    )
    outcome = await pipeline.evaluate(ctx)
    assert outcome.serve_local_estimate and Rung.FRONTIER not in outcome.permitted
