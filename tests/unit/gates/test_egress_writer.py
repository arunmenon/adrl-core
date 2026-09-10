"""Write-ahead egress recording (ADRL-SAF-009)."""

from __future__ import annotations

import pytest

from adrl.core.enums import FailureClass
from adrl.core.errors import LedgerAppendFailure
from adrl.core.ports import EgressEvent
from adrl.gates.egress import EgressWriter, audit_lineage
from adrl.ledger.egress import EgressLedger
from tests.unit.gates.conftest import user_turn


class _BrokenLedger:
    def append(self, event: EgressEvent) -> int:
        raise LedgerAppendFailure("disk full")

    def verify_chain(self):  # type: ignore[no-untyped-def]
        raise NotImplementedError

    def checkpoint(self) -> int:
        raise NotImplementedError


def test_append_failure_pinned_raises_unpinned_degrades() -> None:
    writer = EgressWriter(_BrokenLedger(), deployment_tag="t")
    ctx = user_turn("x")
    with pytest.raises(LedgerAppendFailure):
        writer.record_forward(ctx, destination_rung="local", bytes_out=1, pinned=True)
    assert (
        writer.record_forward(ctx, destination_rung="frontier", bytes_out=1, pinned=False) is False
    )
    assert writer.record_fail_open(ctx, FailureClass.GATE_PATH, "x", pinned=False) is False


def test_audit_answers_left_machine(egress_ledger: EgressLedger) -> None:
    writer = EgressWriter(egress_ledger, deployment_tag="dc-1")
    ctx = user_turn("x")
    writer.record_verdict(ctx, [], [], pinned=False, unscanned=False, block_code=None)
    assert audit_lineage(egress_ledger, str(ctx.lineage_hmac))["left_machine"] is False
    writer.record_forward(ctx, destination_rung="local", bytes_out=10, pinned=False)
    assert audit_lineage(egress_ledger, str(ctx.lineage_hmac))["left_machine"] is False
    writer.record_forward(ctx, destination_rung="frontier", bytes_out=10, pinned=False)
    report = audit_lineage(egress_ledger, str(ctx.lineage_hmac))
    assert report["left_machine"] is True and report["deployment_tags"] == ["dc-1"]
    assert egress_ledger.verify_chain().ok
