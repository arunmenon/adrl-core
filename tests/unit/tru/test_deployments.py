"""Deployment sets, receipts, inventory checks and the egress audit truth (ADRL-SAF-008/009)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from adrl.config.checks import check_endpoint_inventory, check_residency_reachable
from adrl.config.loaders import ConfigBundle, load_bundle
from adrl.config.models import Deployment, EndpointInventory, RepoClassificationManifest
from adrl.config.settings import Settings
from adrl.core.enums import Rung, ServedSource
from adrl.core.errors import ConfigError, PermittedSetWidened
from adrl.core.ports import EgressEvent
from adrl.core.types import LOCAL_HOST_ZONE, ServedIdentity, left_machine
from adrl.gates.deployments import DeploymentPolicy, egress_fields
from adrl.gates.egress import audit_lineage
from adrl.ledger.egress import EgressLedger
from tests.conftest import CONFIG_DIR


def _inventory(**overrides: object) -> EndpointInventory:
    data = json.loads((CONFIG_DIR / "endpoint-inventory-v1.json").read_text())
    data.update(overrides)
    return EndpointInventory.model_validate(data)


def _mislabelled_local() -> EndpointInventory:
    """A deployment that says rung local but lives on a public host: the review's attack."""
    data = json.loads((CONFIG_DIR / "endpoint-inventory-v1.json").read_text())
    data["deployments"].append(
        {
            "id": "local-exfil",
            "model_group": "adrl-local",
            "rung": "local",
            "provider": "openai_compatible",
            "model": "openai/anything",
            "api_base": "https://exfil.example.com/v1",
            "trust_zone": "public_cloud",
            "geo": "unknown",
            "attested_by": "nobody",
        }
    )
    return EndpointInventory.model_validate(data)


def test_deployment_set_only_tightens(bundle: ConfigBundle) -> None:
    policy = DeploymentPolicy(bundle.endpoint_inventory)
    everything = policy.universe()
    narrowed = everything.only_rungs({Rung.LOCAL})
    assert narrowed.rungs() == frozenset({Rung.LOCAL})
    with pytest.raises(PermittedSetWidened):
        narrowed.tighten(everything.ids)
    assert narrowed.local_host_only().ids == narrowed.ids
    assert everything.only_geo("eu").rungs() == frozenset({Rung.LOCAL}), (
        "residency keeps the local host and drops every out-of-geo cloud deployment"
    )


def test_pin_keeps_only_local_host_even_when_a_label_says_local() -> None:
    policy = DeploymentPolicy(_mislabelled_local())
    pinned = policy.permitted_for(permitted_rungs=frozenset(Rung), pinned=True, residency=None)
    assert "local-exfil" not in pinned
    assert all(policy.catalog[i].is_local_host for i in pinned.ids)
    chosen = policy.choose(pinned, Rung.LOCAL, rung_member_order=("adrl-local",))
    assert chosen is not None and chosen.trust_zone == LOCAL_HOST_ZONE


def test_residency_with_only_us_cloud_yields_local_only(bundle: ConfigBundle) -> None:
    policy = DeploymentPolicy(bundle.endpoint_inventory)
    permitted = policy.permitted_for(permitted_rungs=frozenset(Rung), pinned=False, residency="eu")
    assert permitted.rungs() == frozenset({Rung.LOCAL})
    assert policy.choose(permitted, Rung.CHEAP_CLOUD) is None
    assert policy.frontier_for_model(permitted, "claude-fable-5-1") is None


def test_receipt_maps_model_id_then_api_base_then_assumed(bundle: ConfigBundle) -> None:
    policy = DeploymentPolicy(bundle.endpoint_inventory)
    intended = policy.catalog["cheap-haiku-us"]
    base = ServedIdentity(Rung.CHEAP_CLOUD, "x", None, ServedSource.PROXY_OBSERVED)
    by_id = policy.served_identity(base, {"X-LiteLLM-Model-Id": "frontier-fable-us"}, intended)
    assert by_id.deployment_id == "frontier-fable-us" and by_id.rung is Rung.FRONTIER
    assert by_id.receipt_confirmed and by_id.trust_zone == "public_cloud"
    by_host = policy.served_identity(
        base, {"x-litellm-model-api-base": "http://127.0.0.1:8081/v1"}, intended
    )
    assert by_host.deployment_id == "local-qwen-32b" and by_host.rung is Rung.LOCAL
    unknown_host = policy.served_identity(
        base, {"x-litellm-model-api-base": "https://elsewhere.example.com"}, intended
    )
    assert unknown_host.deployment_id is None
    assert unknown_host.api_base_host == "elsewhere.example.com"
    assert unknown_host.source is ServedSource.GATEWAY_REPORTED
    assumed = policy.served_identity(base, {}, intended)
    assert assumed.deployment_id == "cheap-haiku-us" and not assumed.receipt_confirmed


def test_inventory_check_rejects_remote_local_and_bad_zones(bundle: ConfigBundle) -> None:
    from dataclasses import replace

    bad = replace(bundle, endpoint_inventory=_mislabelled_local())
    result = check_endpoint_inventory(bad)
    assert not result.ok and "local-exfil" in result.detail
    data = json.loads((CONFIG_DIR / "endpoint-inventory-v1.json").read_text())
    data["deployments"][0]["trust_zone"] = "public_cloud"
    zone = replace(bundle, endpoint_inventory=EndpointInventory.model_validate(data))
    assert "must be local_host" in check_endpoint_inventory(zone).detail
    data = json.loads((CONFIG_DIR / "endpoint-inventory-v1.json").read_text())
    data["deployments"][2]["trust_zone"] = "local_host"
    cloud = replace(bundle, endpoint_inventory=EndpointInventory.model_validate(data))
    assert "cannot claim trust_zone local_host" in check_endpoint_inventory(cloud).detail


def test_residency_check_fails_only_when_the_class_is_in_use(bundle: ConfigBundle) -> None:
    from dataclasses import replace

    unused = check_residency_reachable(bundle, Settings())
    assert unused.ok and "unused" in unused.detail
    data = json.loads((CONFIG_DIR / "repo-classification-v1.json").read_text())
    data["repos"].append({"repo_id": "eu", "match": "/repos/eu-data", "class_id": "residency-eu"})
    manifest = RepoClassificationManifest.model_validate(data)
    in_use = replace(bundle, repo_classification=manifest)
    strict = check_residency_reachable(in_use, Settings())
    assert not strict.ok and "no deployment there" in strict.detail
    lenient = check_residency_reachable(in_use, Settings(residency_unreachable_is_error=False))
    assert lenient.ok


def test_deployment_model_validates_loopback() -> None:
    base = {
        "id": "dep-1",
        "model_group": "g",
        "rung": "local",
        "provider": "p",
        "model": "m",
        "trust_zone": "local_host",
        "geo": "local",
        "attested_by": "t",
    }
    assert Deployment.model_validate({**base, "api_base": "http://localhost:1/v1"}).is_loopback
    assert Deployment.model_validate({**base, "api_base": "http://[::1]:1/v1"}).is_loopback
    assert Deployment.model_validate({**base, "api_base": "unix:///tmp/s.sock"}).is_loopback
    assert not Deployment.model_validate({**base, "api_base": "https://10.0.0.5/v1"}).is_loopback


def test_signed_inventory_is_required_and_tampering_is_refused(tmp_path: Path) -> None:
    for path in CONFIG_DIR.iterdir():
        if path.is_file():
            (tmp_path / path.name).write_bytes(path.read_bytes())
    (tmp_path / "keys" / "dev").mkdir(parents=True)
    for key in (CONFIG_DIR / "keys" / "dev").iterdir():
        (tmp_path / "keys" / "dev" / key.name).write_bytes(key.read_bytes())
    data = json.loads((tmp_path / "endpoint-inventory-v1.json").read_text())
    data["deployments"][0]["api_base"] = "https://exfil.example.com/v1"
    (tmp_path / "endpoint-inventory-v1.json").write_text(json.dumps(data))
    with pytest.raises(ConfigError, match="signature is invalid"):
        load_bundle(Settings(config_dir=tmp_path))
    (tmp_path / "endpoint-inventory-v1.sig").unlink()
    with pytest.raises(ConfigError, match="must be signed"):
        load_bundle(Settings(config_dir=tmp_path))


def test_egress_v2_audit_answers_from_trust_zone_not_label(tmp_path: Path) -> None:
    ledger = EgressLedger(tmp_path / "egress.db")
    ledger.open()
    try:
        mislabelled = DeploymentPolicy(_mislabelled_local()).catalog["local-exfil"]
        honest_local = DeploymentPolicy(_mislabelled_local()).catalog["local-qwen-7b"]
        base = dict(
            request_class="continuation",
            content_bearing=True,
            deployment_tag="dev",
            gate_verdicts=[],
        )
        # lineage A: label says local, zone says public cloud, only the write-ahead row exists
        ledger.append(
            EgressEvent(
                lineage_hmac="A",
                destination_rung="local",
                **base,
                **egress_fields(mislabelled, "intended"),
            )
        )
        # lineage B: honest local host, receipt confirmed
        ledger.append(
            EgressEvent(
                lineage_hmac="B",
                destination_rung="local",
                **base,
                **egress_fields(honest_local, "intended"),
            )
        )
        ledger.append(
            EgressEvent(
                lineage_hmac="B",
                destination_rung="local",
                event_kind="served_receipt",
                **base,
                **egress_fields(honest_local, "gateway_reported"),
            )
        )
        report_a = audit_lineage(ledger, "A")
        assert report_a["left_machine"] is True, "the label said local; the zone says otherwise"
        assert report_a["confirmed_by_receipt"] is False
        assert report_a["unconfirmed_count"] == 1
        assert report_a["trust_zones"] == ["public_cloud"]
        report_b = audit_lineage(ledger, "B")
        assert report_b["left_machine"] is False
        assert ledger.verify_chain().ok
        rows = ledger.events_for_lineage("A")
        assert rows[0]["schema_version"] == "egress-v2"
        assert rows[0]["api_base_host"] == "exfil.example.com"
    finally:
        ledger.close()
    assert left_machine(None, "local") is False
    assert left_machine(None, None) is None
    assert left_machine("private_cloud", "local") is True


def test_egress_v1_rows_still_verify_after_upgrade(tmp_path: Path) -> None:
    """A ledger written before egress-v2 keeps verifying; new rows carry the new columns."""
    import sqlite3

    from adrl.ledger import egress as egress_mod

    path = tmp_path / "old.db"
    ledger = EgressLedger(path)
    ledger.open()
    ledger.close()
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    row = {
        "prev_digest": egress_mod.GENESIS_DIGEST,
        "ts": "2026-09-01T00:00:00+00:00",
        "event_kind": "forward",
        "lineage_hmac": "L",
        "request_class": "user_turn",
        "content_bearing": 1,
        "destination_rung": "cheap_cloud",
        "deployment_tag": "dev",
        "gate_verdicts_json": "[]",
        "detector_tier": None,
        "span_hashes_json": "[]",
        "bytes_out": 1,
        "actor": "adrl",
        "reason": None,
        "schema_version": "egress-v1",
    }
    row["digest"] = egress_mod._digest(row)
    columns = ",".join(row)
    conn.execute(
        f"INSERT INTO egress_events ({columns}) VALUES ({','.join('?' for _ in row)})",
        tuple(row.values()),
    )
    conn.commit()
    conn.close()
    reopened = EgressLedger(path)
    reopened.open()
    try:
        assert reopened.verify_chain().ok
        reopened.append(
            EgressEvent(
                lineage_hmac="L",
                request_class="continuation",
                content_bearing=True,
                destination_rung="local",
                deployment_tag="dev",
                gate_verdicts=[],
                trust_zone="local_host",
                deployment_id="local-qwen-7b",
                receipt_source="gateway_reported",
                event_kind="served_receipt",
            )
        )
        assert reopened.verify_chain().ok
        report = audit_lineage(reopened, "L")
        assert report["left_machine"] is True and report["legacy_label_rows"] == 1
    finally:
        reopened.close()
