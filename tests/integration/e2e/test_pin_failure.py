"""Composed system: a degraded facade and a detected secret (ADRL-SAF-002, MEM-006)."""

from __future__ import annotations

from pathlib import Path

from adrl.core.enums import RoutingMode
from tests.integration.e2e.conftest import AWS_KEY, build_e2e, continuation_with_result

LOCAL_ALIASES = {"adrl-local", "adrl-local-large", "local-qwen-7b", "local-qwen-32b"}


async def test_detected_secret_stays_local_after_one_transient_ledger_error(
    tmp_path: Path,
) -> None:
    live = await build_e2e(tmp_path, routing_mode=RoutingMode.LIVE)
    try:
        first = await live.send("user_turn")
        assert first.status_code == 200
        # an earlier transient provider error must not poison the next pin
        live.components.facade._note_degraded("OperationalError", "append_event")
        response = await live.send(
            "continuation", body=continuation_with_result(f"AWS_KEY={AWS_KEY}\n")
        )
        assert response.status_code in (200, 400)
        lineage = live.lineage_of("user_turn")
        pins = live.lineage_events(lineage, "pinned")
        assert pins, "the pin was written once the provider answered"
        pin_seq = int(pins[0]["seq"])
        # nothing after the pin left for a cloud rung; rows before it are the unpinned turn
        cloud_rows = live.components.egress.lineage_left_machine(str(lineage))
        assert all(int(r["seq"]) <= pin_seq + 1 for r in cloud_rows) or not cloud_rows, cloud_rows
        models = live.gateway_models()
        assert models[-1] in LOCAL_ALIASES or len(models) == 1, models
        after = await live.send("continuation", body=continuation_with_result("clean now"))
        assert after.status_code == 200
        assert live.gateway_models()[-1] in LOCAL_ALIASES
    finally:
        await live.aclose()
