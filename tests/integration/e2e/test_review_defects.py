"""Conformance-review defects 5, 6, 7 and 9 through the composed system."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from adrl.core.enums import RoutingMode
from tests.integration.e2e.conftest import (
    AWS_KEY,
    E2E,
    build_e2e,
    continuation_with_result,
    load_fixture,
)

LOCAL_ALIASES = {"adrl-local", "adrl-local-large", "local-qwen-7b", "local-qwen-32b"}
GRANDCHILD = {
    "x-claude-code-agent-id": "agent-grand-0003",
    "x-claude-code-parent-agent-id": "agent-child-0002",
}


def _fork_body_with(text: str) -> dict[str, Any]:
    body = copy.deepcopy(load_fixture("fork_subagent")["body"])
    body["messages"] = [{"role": "user", "content": [{"type": "text", "text": text}]}]
    return body


def _all_ledger_text(live: E2E) -> str:
    rows = live.store.read("SELECT payload_json FROM events")
    rows += live.store.read("SELECT context_json, features_json FROM decisions")
    rows += live.store.read("SELECT payload_json FROM lineage_events")
    return "\n".join(json.dumps([str(v) for v in dict(r).values()]) for r in rows)


async def test_grandchild_lineage_and_inherited_pin_survive_a_restart(tmp_path: Path) -> None:
    live = await build_e2e(tmp_path, routing_mode=RoutingMode.LIVE)
    try:
        pinned = await live.send("fork_subagent", body=_fork_body_with(f"token {AWS_KEY}"))
        assert pinned.status_code in (200, 400)
        child = await live.send("nested_subagent")
        assert child.status_code == 200 and live.gateway_models()[-1] in LOCAL_ALIASES
        grand = await live.send("nested_subagent", headers=GRANDCHILD)
        assert grand.status_code == 200 and live.gateway_models()[-1] in LOCAL_ALIASES
        lineage_before = live.decisions()[-1]["lineage_hmac"]
        root_events = live.store.read(
            "SELECT payload_json FROM lineage_events WHERE event_type='agent_parent'"
        )
        assert len(root_events) >= 2, "parent links are persisted, not process-local"
    finally:
        await live.aclose()

    restarted = await build_e2e(tmp_path, routing_mode=RoutingMode.LIVE)
    try:
        again = await restarted.send("nested_subagent", headers=GRANDCHILD)
        assert again.status_code == 200
        assert restarted.gateway_models()[-1] in LOCAL_ALIASES, restarted.gateway_models()
        assert restarted.decisions()[-1]["lineage_hmac"] == lineage_before
    finally:
        await restarted.aclose()


async def test_events_after_a_restart_are_stored_not_dropped(tmp_path: Path) -> None:
    live = await build_e2e(tmp_path, routing_mode=RoutingMode.LIVE)
    try:
        assert (await live.send("user_turn")).status_code == 200
        route_id = live.decisions()[0]["route_id"]
        before = [e for e in live.events("served") if e["route_id"] == route_id]
        assert len(before) == 1
    finally:
        await live.aclose()
    restarted = await build_e2e(tmp_path, routing_mode=RoutingMode.LIVE)
    try:
        response = await restarted.send("continuation", body=continuation_with_result("fine"))
        assert response.status_code == 200
        after = [e for e in restarted.events("served") if e["route_id"] == route_id]
        assert len(after) == 2, "the restored route keeps its sequence; nothing is dropped"
        seqs = sorted(e["producer_seq"] for e in after)
        assert seqs[0] < seqs[1]
    finally:
        await restarted.aclose()


async def test_ledger_never_holds_error_wording_or_plain_input_hashes(live: E2E) -> None:
    marker = "SECRETMARKER123"
    live.gateway_state.status_code = 400
    live.gateway_state.error_body = {
        "type": "error",
        "error": {"type": "invalid_request_error", "message": f"prompt is too long: {marker}"},
    }
    response = await live.send("user_turn")
    assert response.status_code == 400
    assert marker in response.text, "the harness still sees the vendor wording verbatim"
    text = _all_ledger_text(live)
    assert marker not in text
    errors = [e for e in live.events("upstream_error")]
    assert errors and errors[-1]["payload"]["error"]["phrase"] == "prompt is too long"
    assert "message" not in errors[-1]["payload"]["error"]

    live.gateway_state.status_code = 200
    live.gateway_state.error_body = None
    live.gateway_state.stream_tool_use = True
    body = copy.deepcopy(load_fixture("user_turn")["body"])
    body["stream"] = False
    assert (await live.send("user_turn", body=body)).status_code == 200
    served = live.events("served")[-1]["payload"]
    tool_hash = served["tool_uses"][0]["input_hash"]
    plain = hashlib.sha256(
        json.dumps({"path": "x"}, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert not tool_hash.startswith("unkeyed:") and not plain.startswith(tool_hash)


class _RaiseOnSecondCall:
    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self.calls = 0

    async def evaluate(self, ctx: Any) -> Any:
        self.calls += 1
        if self.calls == 2:
            raise RuntimeError("scanner down")
        return await self._inner.evaluate(ctx)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


async def test_request_racing_the_pinning_request_resolves_its_gate_failure_as_pinned(
    live: E2E,
) -> None:
    assert (await live.send("user_turn")).status_code == 200
    live.components.pipeline._gate = _RaiseOnSecondCall(live.components.pipeline._gate)
    first, second = await asyncio.gather(
        live.send("continuation", body=continuation_with_result(f"AWS_KEY={AWS_KEY}\n")),
        live.send("continuation", body=continuation_with_result("racing request")),
    )
    assert first.status_code in (200, 400)
    assert second.status_code == 400, second.text
    assert "gate_unavailable" in second.text
    for model in live.gateway_models()[1:]:
        assert model in LOCAL_ALIASES, live.gateway_models()
