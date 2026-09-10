"""ADRL-SAF-002, ADRL-SEM-004, ADRL-SEM-006 pinned-lineage paths through the proxy."""

from __future__ import annotations

import json

from adrl.ledger.store import LedgerStore

from .conftest import EmptyPermittedGate, Harness, load_fixture


async def test_pinned_count_tokens_never_reaches_the_gateway(harness: Harness) -> None:
    await harness.pin(harness.lineage_of("count_tokens"))
    response = await harness.send("count_tokens")
    assert response.status_code == 200
    assert response.json()["input_tokens"] > 0
    assert harness.gateway_requests() == []
    assert harness.egress.lineage_left_machine(harness.lineage_of("count_tokens")) == []


async def test_pinned_user_turn_in_shadow_mode_is_served_locally(harness: Harness) -> None:
    lineage = harness.lineage_of("user_turn")
    await harness.pin(lineage)
    response = await harness.send("user_turn")
    assert response.status_code == 200
    body = harness.last_gateway_body()
    assert body["model"] == "local-qwen-7b"
    assert "thinking" not in body
    assert "cache_control" not in json.dumps(body)
    assert harness.egress.lineage_left_machine(lineage) == []
    decision = harness.decisions()[0]
    assert json.loads(decision["permitted_set"]) == ["local"]
    assert json.loads(decision["context_json"])["pinned"] is True


async def test_unpinned_user_turn_leaves_the_machine_and_the_ledger_says_so(
    harness: Harness,
) -> None:
    lineage = harness.lineage_of("user_turn")
    await harness.send("user_turn")
    rows = harness.egress.lineage_left_machine(lineage)
    assert rows and rows[0]["destination_rung"] == "frontier"
    assert harness.egress.verify_chain().ok


async def test_pinned_cosmetic_utility_without_local_gets_empty_valid_response(
    harness_factory,
) -> None:
    harness: Harness = await harness_factory()
    harness.pipeline._gate = EmptyPermittedGate(harness.facade)
    try:
        await harness.pin(harness.lineage_of("title"))
        response = await harness.send("title")
    finally:
        await harness.client.aclose()
    assert response.status_code == 200
    message = response.json()
    assert message["type"] == "message"
    assert message["stop_reason"] == "end_turn"
    assert message["content"] == [{"type": "text", "text": ""}]
    assert harness.gateway_requests() == []


async def test_pinned_cosmetic_utility_with_local_goes_local(harness: Harness) -> None:
    await harness.pin(harness.lineage_of("title"))
    response = await harness.send("title")
    assert response.status_code == 200
    assert harness.last_gateway_body()["model"] == "local-qwen-7b"


async def test_pinned_turn_blocked_when_local_unavailable(harness_factory) -> None:
    harness: Harness = await harness_factory()
    harness.pipeline._gate = EmptyPermittedGate(harness.facade)
    try:
        await harness.pin(harness.lineage_of("user_turn"))
        response = await harness.send("user_turn")
    finally:
        await harness.client.aclose()
    assert response.status_code == 400
    message = response.json()["error"]["message"]
    assert message.startswith("pinned_local_unavailable")
    assert "aws_access_key" in message
    assert "/compact" in message
    assert "ANTHROPIC_BASE_URL" not in message
    assert harness.gateway_requests() == []
    assert harness.lineage_events(harness.lineage_of("user_turn"), "block")


async def test_fork_of_pinned_parent_is_served_locally(harness: Harness) -> None:
    parent = harness.lineage_of("user_turn")
    await harness.pin(parent)
    response = await harness.send("fork_subagent")
    assert response.status_code == 200
    assert harness.last_gateway_body()["model"] == "local-qwen-7b"
    child = harness.lineage_of("fork_subagent")
    inherited = harness.lineage_events(child, "pinned")
    assert inherited and inherited[0]["payload"]["inherited_from"] == parent
    assert harness.egress.lineage_left_machine(child) == []


async def test_child_pin_does_not_pin_parent_but_pins_grandchild(harness: Harness) -> None:
    await harness.send("fork_subagent")
    child = harness.lineage_of("fork_subagent")
    await harness.pin(child, detector="private_key_block")
    parent_response = await harness.send("user_turn")
    assert parent_response.status_code == 200
    assert harness.last_gateway_body()["model"] == "claude-fable-5-1"
    grandchild_response = await harness.send("nested_subagent")
    assert grandchild_response.status_code == 200
    assert harness.last_gateway_body()["model"] == "local-qwen-7b"


async def test_unparseable_body_on_pinned_lineage_is_refused(harness: Harness) -> None:
    lineage = harness.lineage_of("user_turn")
    await harness.pin(lineage)
    response = await harness.send("user_turn", raw=b"\xff{broken")
    assert response.status_code == 400
    assert response.json()["error"]["message"].startswith("unclassifiable_pinned")
    assert harness.gateway_requests() == []


async def test_pin_survives_process_restart(harness_factory, ledger_store: LedgerStore) -> None:
    from adrl.ledger.facade import MemoryFacade, SqliteLedgerProvider

    first: Harness = await harness_factory()
    lineage = first.lineage_of("user_turn")
    await first.pin(lineage)
    await first.client.aclose()
    ledger_store.close()
    reopened = LedgerStore(ledger_store.path)
    reopened.open()
    second: Harness = await harness_factory(facade=MemoryFacade(SqliteLedgerProvider(reopened)))
    try:
        response = await second.send("user_turn")
    finally:
        await second.client.aclose()
        reopened.close()
        ledger_store.open()
    assert response.status_code == 200
    assert second.last_gateway_body()["model"] == "local-qwen-7b"


async def test_pinned_continuation_at_boundary_names_executed_tool(harness_factory) -> None:
    harness: Harness = await harness_factory()
    harness.pipeline._gate = EmptyPermittedGate(harness.facade)
    try:
        await harness.pin(harness.lineage_of("continuation"))
        response = await harness.send("continuation")
    finally:
        await harness.client.aclose()
    assert response.status_code == 400
    assert "toolu_01" in response.json()["error"]["message"]


def test_fixture_bodies_do_not_contain_real_secrets() -> None:
    for name in ("user_turn", "continuation", "compaction"):
        dumped = json.dumps(load_fixture(name))
        assert "AKIA" not in dumped and "BEGIN PRIVATE KEY" not in dumped
