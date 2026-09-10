"""Egress ledger: chain verifies, tampering is detected, checkpoints sign."""

from __future__ import annotations

import sqlite3

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from adrl.core.ports import EgressEvent
from adrl.ledger.egress import EgressLedger


def _event(lineage: str = "lin", rung: str | None = "frontier") -> EgressEvent:
    return EgressEvent(
        lineage_hmac=lineage,
        request_class="continuation",
        content_bearing=True,
        destination_rung=rung,
        deployment_tag="dev-local",
        gate_verdicts=[
            {"gate": "secrets", "permitted_after": ["local", "cheap_cloud", "frontier"]}
        ],
        bytes_out=1234,
    )


def test_chain_verifies_and_survives_reopen(egress_ledger: EgressLedger) -> None:
    for _ in range(5):
        egress_ledger.append(_event())
    assert egress_ledger.verify_chain().ok
    path = egress_ledger._path
    egress_ledger.close()
    reopened = EgressLedger(path)
    reopened.open()
    seq = reopened.append(_event())
    assert seq == 6
    assert reopened.verify_chain().ok
    reopened.close()
    egress_ledger.open()


def test_tamper_is_detected(egress_ledger: EgressLedger) -> None:
    for _ in range(3):
        egress_ledger.append(_event())
    raw = sqlite3.connect(egress_ledger._path)
    raw.execute("UPDATE egress_events SET destination_rung='local' WHERE seq=2")
    raw.commit()
    raw.close()
    result = egress_ledger.verify_chain()
    assert not result.ok and result.first_bad_seq == 2


def test_deletion_is_detected_via_checkpoint(egress_ledger: EgressLedger) -> None:
    for _ in range(3):
        egress_ledger.append(_event())
    assert egress_ledger.checkpoint() == 1
    raw = sqlite3.connect(egress_ledger._path)
    raw.execute("DELETE FROM egress_events WHERE seq=3")
    raw.commit()
    raw.close()
    assert not egress_ledger.verify_chain().ok


def test_checkpoint_signature_verifies(tmp_path) -> None:  # type: ignore[no-untyped-def]
    key = Ed25519PrivateKey.generate()
    ledger = EgressLedger(tmp_path / "e.db", signing_key=key, key_id="t")
    ledger.open()
    assert ledger.checkpoint() == 0
    ledger.append(_event())
    assert ledger.checkpoint() == 1
    assert ledger.verify_checkpoints(key.public_key())
    assert not ledger.verify_checkpoints(Ed25519PrivateKey.generate().public_key())
    ledger.close()


def test_lineage_left_machine_query(egress_ledger: EgressLedger) -> None:
    egress_ledger.append(_event("a", "local"))
    egress_ledger.append(_event("a", "frontier"))
    egress_ledger.append(_event("b", None))
    assert len(egress_ledger.lineage_left_machine("a")) == 1
    assert egress_ledger.lineage_left_machine("b") == []
