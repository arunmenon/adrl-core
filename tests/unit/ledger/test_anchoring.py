"""SAF-009 anchoring: key separation, automatic checkpoints, shipping, anchor verification."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from typer.testing import CliRunner

from adrl.config.settings import Settings
from adrl.core.errors import ConfigError
from adrl.core.ports import EgressEvent
from adrl.ledger.anchoring import (
    AnchorRecord,
    FileAnchorShipper,
    checkpoint_key_from_settings,
    is_dev_key_path,
    key_id_for,
    load_public_keys,
    read_anchor_file,
    write_keypair,
)
from adrl.ledger.egress import EgressLedger


def _event(lineage: str = "lin", rung: str = "frontier") -> EgressEvent:
    return EgressEvent(
        lineage_hmac=lineage,
        request_class="continuation",
        content_bearing=True,
        destination_rung=rung,
        deployment_tag="dev-local",
        gate_verdicts=[{"gate": "secrets"}],
        bytes_out=10,
    )


class FailingShipper:
    destination = "https://anchor.invalid/fail"
    calls = 0

    def ship(self, record: AnchorRecord) -> str:
        self.calls += 1
        raise ConnectionError("anchor down")


@pytest.fixture
def keypair(tmp_path: Path) -> tuple[Path, Path]:
    private, public = tmp_path / "keys" / "prod" / "cp.key", tmp_path / "keys" / "prod" / "cp.pub"
    write_keypair(private, public)
    assert oct(private.stat().st_mode & 0o777) == "0o600"
    return private, public


def test_dev_key_refused_without_flag(tmp_path: Path) -> None:
    private, public = tmp_path / "keys" / "dev" / "cp.key", tmp_path / "keys" / "dev" / "cp.pub"
    write_keypair(private, public)
    assert is_dev_key_path(private)
    settings = Settings(checkpoint_signing_key_path=private)
    with pytest.raises(ConfigError, match="development key"):
        checkpoint_key_from_settings(settings)
    allowed = checkpoint_key_from_settings(settings.model_copy(update={"dev_keys_allowed": True}))
    assert allowed is not None and allowed.dev and allowed.key_id.startswith("ed25519:")


def test_production_key_loads_without_flag(keypair: tuple[Path, Path]) -> None:
    private, public = keypair
    key = checkpoint_key_from_settings(Settings(checkpoint_signing_key_path=private))
    assert key is not None and not key.dev
    assert key.key_id == next(iter(load_public_keys([public])))


def test_no_key_configured_is_none() -> None:
    assert checkpoint_key_from_settings(Settings()) is None


def test_automatic_checkpoint_fires_at_configured_count(tmp_path: Path) -> None:
    ledger = EgressLedger(
        tmp_path / "e.db", signing_key=Ed25519PrivateKey.generate(), checkpoint_every=3
    )
    ledger.open()
    for _ in range(2):
        ledger.append(_event())
    assert ledger.checkpoints() == []
    ledger.append(_event())
    cps = ledger.checkpoints()
    assert len(cps) == 1 and cps[0]["event_seq"] == 3
    for _ in range(3):
        ledger.append(_event())
    assert [c["event_seq"] for c in ledger.checkpoints()] == [3, 6]
    ledger.close()


def test_shipper_acknowledgement_recorded_and_failures_retried(tmp_path: Path) -> None:
    anchor = tmp_path / "off-device" / "anchors.jsonl"
    failing = FailingShipper()
    ledger = EgressLedger(
        tmp_path / "e.db",
        signing_key=Ed25519PrivateKey.generate(),
        checkpoint_every=2,
        shippers=[FileAnchorShipper(anchor), failing],
    )
    ledger.open()
    for _ in range(4):
        ledger.append(_event())
    report = ledger.ship_pending()
    assert report.shipped == 2 and report.failed == 2 and report.pending == 2
    records = read_anchor_file(anchor)
    assert [r.event_seq for r in records] == [2, 4]
    assert all(r.ledger_id == ledger.ledger_id for r in records)
    raw = sqlite3.connect(tmp_path / "e.db")
    rows = raw.execute(
        "SELECT destination, status FROM checkpoint_shipments ORDER BY seq"
    ).fetchall()
    raw.close()
    assert sorted(rows) == sorted(
        [
            (f"file:{anchor}", "acked"),
            (failing.destination, "failed"),
            (f"file:{anchor}", "acked"),
            (failing.destination, "failed"),
        ]
    )
    again = ledger.ship_pending()
    assert again.shipped == 0 and again.failed == 2 and failing.calls == 4
    status = ledger.anchor_status()
    assert status["unshipped_checkpoints"] == 2 and status["newest_anchored_seq"] == 4
    assert status["newest_anchor_age_s"] is not None and status["newest_anchor_age_s"] >= 0
    ledger.close()


def test_tamper_before_anchored_checkpoint_detected_with_anchor_file(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    anchor = tmp_path / "anchors.jsonl"
    ledger = EgressLedger(tmp_path / "e.db", signing_key=key, shippers=[FileAnchorShipper(anchor)])
    ledger.open()
    for _ in range(3):
        ledger.append(_event())
    ledger.checkpoint()
    ledger.ship_pending()
    keys = {key_id_for(key.public_key()): key.public_key()}
    assert ledger.verify_against_anchors(read_anchor_file(anchor), keys).ok
    ledger.close()

    raw = sqlite3.connect(tmp_path / "e.db")
    raw.execute("DELETE FROM egress_events WHERE seq=3")
    raw.execute("DELETE FROM checkpoints")
    raw.commit()
    raw.close()
    reopened = EgressLedger(tmp_path / "e.db")
    reopened.open()
    assert reopened.verify_chain().ok, "a clean truncation is invisible to the local chain"
    result = reopened.verify_against_anchors(read_anchor_file(anchor), keys)
    assert not result.ok and "truncated" in str(result.detail)
    reopened.close()


def test_edit_before_anchored_checkpoint_detected(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    anchor = tmp_path / "anchors.jsonl"
    ledger = EgressLedger(tmp_path / "e.db", signing_key=key, shippers=[FileAnchorShipper(anchor)])
    ledger.open()
    for _ in range(3):
        ledger.append(_event(rung="frontier"))
    ledger.checkpoint()
    ledger.ship_pending()
    ledger.close()
    raw = sqlite3.connect(tmp_path / "e.db")
    raw.execute("UPDATE egress_events SET destination_rung='local' WHERE seq=3")
    raw.commit()
    raw.close()
    reopened = EgressLedger(tmp_path / "e.db")
    reopened.open()
    keys = {key_id_for(key.public_key()): key.public_key()}
    result = reopened.verify_against_anchors(read_anchor_file(anchor), keys)
    assert not result.ok and "altered" in str(result.detail)
    reopened.close()


def test_checkpoint_signed_by_wrong_key_fails_and_key_set_supports_rotation(
    tmp_path: Path,
) -> None:
    old_key, new_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    ledger = EgressLedger(tmp_path / "e.db", signing_key=old_key)
    ledger.open()
    ledger.append(_event())
    ledger.checkpoint()
    ledger.close()
    rotated = EgressLedger(tmp_path / "e.db", signing_key=new_key)
    rotated.open()
    rotated.append(_event())
    rotated.checkpoint()
    only_new = {key_id_for(new_key.public_key()): new_key.public_key()}
    result = rotated.verify_checkpoints(only_new)
    assert not result.ok and "unknown key id" in str(result.detail)
    both = {**only_new, key_id_for(old_key.public_key()): old_key.public_key()}
    assert rotated.verify_checkpoints(both).ok
    wrong = Ed25519PrivateKey.generate().public_key()
    assert not rotated.verify_checkpoints(wrong)
    rotated.close()


def test_cli_verify_egress_exit_codes(tmp_path: Path, keypair: tuple[Path, Path]) -> None:
    from adrl.cli.main import app

    private, public = keypair
    anchor = tmp_path / "anchors.jsonl"
    key = checkpoint_key_from_settings(Settings(checkpoint_signing_key_path=private))
    assert key is not None
    db = tmp_path / "e.db"
    ledger = EgressLedger(db, signing_key=key.private, shippers=[FileAnchorShipper(anchor)])
    ledger.open()
    for _ in range(2):
        ledger.append(_event())
    ledger.checkpoint()
    ledger.ship_pending()
    ledger.close()
    runner = CliRunner()
    ok = runner.invoke(
        app,
        [
            "ledger",
            "verify-egress",
            "--path",
            str(db),
            "--public-key",
            str(public),
            "--anchors",
            str(anchor),
        ],
    )
    assert ok.exit_code == 0, ok.output
    assert "anchors 1 ok True" in ok.output
    unsigned = runner.invoke(app, ["ledger", "verify-egress", "--path", str(db)])
    assert unsigned.exit_code == 1 and "signatures not verified" in unsigned.output
    chain_only = runner.invoke(app, ["ledger", "verify-egress", "--path", str(db), "--chain-only"])
    assert chain_only.exit_code == 0 and "not an audit" in chain_only.output
    other = tmp_path / "other.pub"
    write_keypair(tmp_path / "other.key", other)
    bad = runner.invoke(
        app, ["ledger", "verify-egress", "--path", str(db), "--public-key", str(other)]
    )
    assert bad.exit_code == 1 and "unknown key id" in bad.output


def test_app_refuses_dev_checkpoint_key_without_flag(tmp_path: Path, settings: Settings) -> None:
    from adrl.app import build_components

    dev_private = tmp_path / "keys" / "dev" / "checkpoint-signing.key"
    write_keypair(dev_private, tmp_path / "keys" / "dev" / "checkpoint-signing.pub")
    with pytest.raises(ConfigError, match="development key"):
        build_components(settings.model_copy(update={"checkpoint_signing_key_path": dev_private}))


@pytest.mark.asyncio
async def test_app_accepts_dev_key_with_flag_and_reports_anchor_status(
    tmp_path: Path, settings: Settings
) -> None:
    from adrl.app import build_components

    dev_private = tmp_path / "keys" / "dev" / "checkpoint-signing.key"
    write_keypair(dev_private, tmp_path / "keys" / "dev" / "checkpoint-signing.pub")
    components = build_components(
        settings.model_copy(
            update={
                "checkpoint_signing_key_path": dev_private,
                "dev_keys_allowed": True,
                "egress_anchor_path": tmp_path / "anchors.jsonl",
                "egress_checkpoint_every": 1,
            }
        )
    )
    try:
        assert components.egress is not None
        components.egress.append(_event())
        status = components.egress.anchor_status()
        assert status["signing"] and status["unshipped_checkpoints"] == 1
        components.egress.ship_pending()
        assert components.egress.anchor_status()["unshipped_checkpoints"] == 0
    finally:
        await components.aclose()
