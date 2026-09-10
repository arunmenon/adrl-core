"""ADRL-FND-004 fault-injection matrix, per failure class and pin state."""

from __future__ import annotations

import json
from typing import Any

import pytest

from adrl.core.enums import RoutingMode
from adrl.ledger.facade import MemoryFacade, NullProvider
from tests.conftest import FakeGatewayState

from .conftest import Harness, RaisingGate, RaisingRouter, load_fixture


class _BrokenProvider(NullProvider):
    async def read_lineage_events(self, lineage: Any, event_type: Any = None) -> Any:
        raise RuntimeError("database is locked")

    async def append_decision(self, decision: Any, context: Any) -> bool:
        raise RuntimeError("database is locked")

    async def append_event(self, event: Any) -> bool:
        raise RuntimeError("database is locked")

    async def append_lineage_event(self, event: Any) -> int:
        raise RuntimeError("database is locked")


async def test_scanner_exception_unpinned_fails_open_unscanned(harness_factory) -> None:
    harness: Harness = await harness_factory(gate=RaisingGate())
    try:
        response = await harness.send("user_turn")
    finally:
        await harness.client.aclose()
    assert response.status_code == 200
    raw = json.dumps(load_fixture("user_turn")["body"]).encode()
    assert harness.gateway_requests()[0]["raw"] == raw
    lineage = harness.lineage_of("user_turn")
    events = harness.lineage_events(lineage, "fail_open")
    assert events and events[0]["payload"]["failure_class"] == "gate_path"
    assert events[0]["payload"]["unscanned"] is True
    assert harness.events("request")[0]["payload"]["unscanned"] is True


async def test_scanner_exception_pinned_fails_closed(harness_factory) -> None:
    harness: Harness = await harness_factory(gate=RaisingGate())
    try:
        await harness.pin(harness.lineage_of("user_turn"))
        response = await harness.send("user_turn")
    finally:
        await harness.client.aclose()
    assert response.status_code == 400
    assert response.json()["error"]["message"].startswith("gate_unavailable")
    assert harness.gateway_requests() == []
    events = harness.lineage_events(harness.lineage_of("user_turn"), "fail_open")
    assert events[0]["payload"]["failure_class"] == "gate_path"
    assert events[0]["payload"]["action"] == "block"
    assert harness.egress.lineage_left_machine(harness.lineage_of("user_turn")) == []


async def test_classifier_timeout_unpinned_goes_upstream_with_original_body(
    harness_factory,
) -> None:
    harness: Harness = await harness_factory()
    harness.pipeline._router = RaisingRouter(harness.bundle)
    try:
        response = await harness.send("user_turn")
    finally:
        await harness.client.aclose()
    assert response.status_code == 200
    raw = json.dumps(load_fixture("user_turn")["body"]).encode()
    assert harness.gateway_requests()[0]["raw"] == raw
    events = harness.lineage_events(harness.lineage_of("user_turn"), "fail_open")
    assert events[0]["payload"]["failure_class"] == "routing_path"
    assert events[0]["payload"]["action"] == "forward_upstream"


async def test_classifier_timeout_pinned_goes_local(harness_factory) -> None:
    harness: Harness = await harness_factory()
    harness.pipeline._router = RaisingRouter(harness.bundle)
    try:
        await harness.pin(harness.lineage_of("user_turn"))
        response = await harness.send("user_turn")
    finally:
        await harness.client.aclose()
    assert response.status_code == 200
    body = harness.last_gateway_body()
    assert body["model"] == "local-qwen-7b"
    assert "thinking" not in body
    events = harness.lineage_events(harness.lineage_of("user_turn"), "fail_open")
    assert events[0]["payload"]["action"] == "forward_local"


async def test_ledger_unavailable_treats_unknown_pin_as_pinned(harness_factory) -> None:
    facade = MemoryFacade(_BrokenProvider())
    harness: Harness = await harness_factory(facade=facade)
    try:
        response = await harness.send("user_turn")
    finally:
        await harness.client.aclose()
    assert response.status_code == 200
    assert harness.last_gateway_body()["model"] == "local-qwen-7b"
    assert facade.degraded
    assert facade.degraded_count >= 1


async def test_state_provider_failure_fails_open_by_class(harness_factory) -> None:
    harness: Harness = await harness_factory()
    harness.state.fail = True
    try:
        response = await harness.send("user_turn")
    finally:
        await harness.client.aclose()
    assert response.status_code == 200
    raw = json.dumps(load_fixture("user_turn")["body"]).encode()
    assert harness.gateway_requests()[0]["raw"] == raw
    events = harness.lineage_events(harness.lineage_of("user_turn"), "fail_open")
    assert events[0]["payload"]["failure_class"] == "routing_path"


@pytest.mark.parametrize("status", [500, 429, 529])
@pytest.mark.parametrize("pinned", [False, True])
async def test_upstream_errors_relayed_once_never_retried(
    harness: Harness, gateway_state: FakeGatewayState, status: int, pinned: bool
) -> None:
    gateway_state.status_code = status
    gateway_state.error_body = {"type": "error", "error": {"type": "api_error", "message": "x"}}
    if pinned:
        await harness.pin(harness.lineage_of("user_turn"))
    response = await harness.send("user_turn")
    assert response.status_code == status
    assert json.loads(response.content) == gateway_state.error_body
    assert len(harness.gateway_requests()) == 1
    if pinned:
        assert harness.last_gateway_body()["model"] == "local-qwen-7b"


async def test_fallback_mode_off_surfaces_instead_of_failing_open(harness_factory) -> None:
    harness: Harness = await harness_factory(gate=RaisingGate(), fallback_mode=RoutingMode.OFF)
    try:
        response = await harness.send("user_turn")
    finally:
        await harness.client.aclose()
    assert response.status_code == 400
    assert harness.gateway_requests() == []


async def test_transient_provider_failure_then_recovery_keeps_the_pin_and_clears(
    harness_factory,
) -> None:
    """One transient provider error is not sticky and never weakens a pin (MEM-006, SAF-002)."""
    harness: Harness = await harness_factory()
    try:
        lineage = harness.lineage_of("user_turn")
        await harness.pin(lineage)
        harness.facade._note_degraded("OperationalError", "append_event")
        assert harness.facade.degraded and harness.facade.degraded_episodes == 1
        response = await harness.send("user_turn")
        assert response.status_code in (200, 400)
        assert not harness.facade.degraded, "the next successful provider call clears it"
        again = await harness.send("continuation")
        assert again.status_code in (200, 400)
    finally:
        await harness.client.aclose()
    for request in harness.gateway_requests():
        assert str(request["body"].get("model", "")).startswith("local-qwen-7b"), request[
            "body"
        ].get("model")
    assert harness.facade.degraded_episodes == 1 and harness.facade.recovered_count >= 1
