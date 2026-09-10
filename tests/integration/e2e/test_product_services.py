"""Product services against real composed controls. Primary: ADRL-SEM-007, ADRL-TRU-001."""

from __future__ import annotations

import asyncio
import json
import sqlite3
from collections.abc import AsyncIterator
from dataclasses import dataclass, replace
from typing import Any
from uuid import uuid4

import httpx
import pytest

from adrl.api.auth import ApiError
from adrl.api.contracts import SCHEMA_VERSION
from adrl.api.service import ProductService
from adrl.core.errors import LedgerAppendFailure
from adrl.core.ids import session_identity
from adrl.gates.workload import RepoInventory, sign_assertion
from adrl.proxy.asgi import build_asgi

from .conftest import E2E, load_fixture


@dataclass
class ProductHarness:
    system: E2E
    service: ProductService
    client: httpx.AsyncClient
    sid: str

    def headers(
        self, *, sid: str | None = None, root: str | None = None, ttl: int = 3600
    ) -> dict[str, str]:
        sid = sid or self.sid
        inventory = RepoInventory(
            root=root or "/Users/arunmenon/projects/adrl-core",
            remote=None,
            head=None,
            fingerprint="a" * 64,
            tracked_files=1,
        )
        token = sign_assertion(inventory, self.service.key, session_id=sid, ttl_s=ttl)
        return {
            "x-adrl-workload-assertion": token,
            "x-claude-code-session-id": sid,
            "x-adrl-session-id": sid,
        }

    async def bind(self, **changes: Any) -> httpx.Response:
        request = {
            "adapter": {"id": "claude-code", "version": "1"},
            "profile": {"id": "anthropic-messages-v1", "version": "1"},
            "workload_ref": "adrl-core",
        }
        return await self.client.post(
            "/adrl/v1/sessions", headers=self.headers(), json=request | changes
        )

    def event(self, seq: int = 0, **changes: Any) -> dict[str, Any]:
        return {
            "event_id": str(uuid4()),
            "session_id": self.sid,
            "producer_seq": seq,
            "occurred_at": "2026-09-07T00:00:00Z",
            "event_type": "tool.completed",
            "payload": {"tool_call_ref": "call_1", "outcome": "failed"},
            **changes,
        }


@pytest.fixture
async def product(shadow: E2E) -> AsyncIterator[ProductHarness]:
    service = ProductService(shadow.store, shadow.components.keystore, shadow.components.bundle)
    holder = ProductHarness(shadow, service, shadow.client, str(uuid4()))
    app = build_asgi(shadow.components.pipeline, product=lambda: holder.service)
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://adrl")
    holder.client = client
    try:
        yield holder
    finally:
        await client.aclose()


async def test_binding_is_idempotent_and_renewal_keeps_identity(product: ProductHarness) -> None:
    first = await product.bind()
    assert first.status_code == 200, first.text
    second = await product.bind()
    assert first.json()["session"] == second.json()["session"]
    assert first.json()["credential_ref"] != second.json()["credential_ref"]
    assert len(product.system.store.read("SELECT * FROM product_sessions")) == 1
    assert len(product.system.store.read("SELECT * FROM session_keys WHERE action='created'")) == 1
    status = first.json()["session"]
    assert status["coverage"][0]["status"] == "enforced"
    assert all(f["status"] == "unknown" for f in status["coverage"][1:])
    assert not product.system.gateway_requests()


@pytest.mark.parametrize(
    "case", ["missing", "bad_signature", "expired", "unregistered", "mismatch"]
)
async def test_binding_rejects_invalid_authority(product: ProductHarness, case: str) -> None:
    headers = product.headers()
    if case == "missing":
        headers.pop("x-adrl-workload-assertion")
    elif case == "bad_signature":
        headers["x-adrl-workload-assertion"] += "x"
    elif case == "expired":
        headers = product.headers(ttl=-1)
    elif case == "unregistered":
        headers = product.headers(root="/unregistered/repository")
    else:
        headers["x-claude-code-session-id"] = "other"
    response = await product.client.post("/adrl/v1/sessions", headers=headers, json={})
    assert response.status_code in {401, 403}, response.text
    assert not product.system.store.read("SELECT * FROM product_sessions")
    assert not product.system.gateway_requests()


@pytest.mark.parametrize(
    "change",
    [
        {"workload_ref": "another"},
        {"parent_session_id": "parent"},
        {"profile": {"id": "responses-v1", "version": "1"}},
        {"adapter": {"id": "opencode", "version": "1"}},
        {"policy": "unrestricted"},
        {"schema_version": "adrl-api-v1-preview.1"},
    ],
)
async def test_binding_rejects_unsupported_scope(
    product: ProductHarness, change: dict[str, Any]
) -> None:
    response = await product.bind(**change)
    assert response.status_code in {400, 403, 422}
    assert not product.system.store.read("SELECT * FROM product_sessions")


async def test_event_retry_conflict_sequence_and_restart(product: ProductHarness) -> None:
    assert (await product.bind()).status_code == 200
    event = product.event(0)
    responses = await asyncio.gather(
        *[
            product.client.post("/adrl/v1/events", headers=product.headers(), json=event)
            for _ in range(8)
        ]
    )
    assert all(r.status_code == 200 for r in responses)
    assert all(r.json() == responses[0].json() for r in responses)
    assert len(product.system.store.read("SELECT * FROM product_events")) == 1
    changed = event | {"payload": {"tool_call_ref": "call_1", "outcome": "completed"}}
    assert (
        await product.client.post("/adrl/v1/events", headers=product.headers(), json=changed)
    ).status_code == 409
    assert (
        await product.client.post(
            "/adrl/v1/events", headers=product.headers(), json=product.event(0)
        )
    ).status_code == 409
    for seq, ordering in [(2, "gap"), (1, "late"), (3, "next")]:
        response = await product.client.post(
            "/adrl/v1/events", headers=product.headers(), json=product.event(seq)
        )
        assert response.json()["sequence_status"] == ordering
    product.system.store.close()
    product.system.store.open()
    product.service = ProductService(
        product.system.store, product.system.components.keystore, product.system.components.bundle
    )
    retried = await product.client.post("/adrl/v1/events", headers=product.headers(), json=event)
    assert retried.json() == responses[0].json()
    assert not product.system.store.read("SELECT * FROM events")


async def test_cross_session_and_verifier_claims_are_denied(product: ProductHarness) -> None:
    await product.bind()
    other = product.headers(sid=str(uuid4()))
    status = await product.client.get(f"/adrl/v1/sessions/{product.sid}", headers=other)
    assert status.status_code == 403
    event = product.event(
        event_type="verification.completed",
        payload={
            "task_ref": "task",
            "snapshot_ref": "snapshot",
            "verifier": {"id": "trusted", "version": "1"},
            "result": "passed",
            "evidence_ref": "evidence",
        },
    )
    assert (
        await product.client.post("/adrl/v1/events", headers=product.headers(), json=event)
    ).status_code == 403
    assert (
        await product.client.post("/adrl/v1/events", headers=other, json=product.event())
    ).status_code == 403
    assert not product.system.store.read("SELECT * FROM product_events")


async def test_erasure_covers_observations_and_never_recreates_key(product: ProductHarness) -> None:
    await product.bind()
    private_ref = "sentinel_reference_that_must_be_encrypted"
    event = product.event(payload={"tool_call_ref": private_ref, "outcome": "completed"})
    assert (
        await product.client.post("/adrl/v1/events", headers=product.headers(), json=event)
    ).status_code == 200
    for path in product.system.settings.data_dir.glob("adrl.db*"):
        assert private_ref.encode() not in path.read_bytes()
        assert product.sid.encode() not in path.read_bytes()
    key_id = session_identity(product.sid, product.service.key)
    product.system.components.keystore.shred_session_key(key_id, "test erasure")
    page = await product.client.get(
        f"/adrl/v1/sessions/{product.sid}/timeline", headers=product.headers()
    )
    assert page.status_code == 200
    assert page.json()["entries"][0]["payload_state"] == "erased"
    assert page.json()["entries"][0]["observation"] is None
    assert (await product.bind()).status_code == 403
    assert (
        await product.client.post("/adrl/v1/events", headers=product.headers(), json=event)
    ).status_code == 403
    assert not product.system.components.keystore.has_session_key(key_id)


async def test_failed_shred_audit_still_erases_timeline_and_denies_rebinding(
    product: ProductHarness,
) -> None:
    await product.bind()
    event = product.event()
    assert (
        await product.client.post("/adrl/v1/events", headers=product.headers(), json=event)
    ).status_code == 200
    identity = session_identity(product.sid, product.service.key)
    keys = product.system.components.keystore
    path = keys.root / "sessions" / f"{identity}.key"
    wrapped = path.read_bytes()
    with sqlite3.connect(product.system.store.path) as conn:
        conn.execute(
            "CREATE TRIGGER deny_shred BEFORE INSERT ON session_keys "
            "WHEN NEW.action='shredded' BEGIN SELECT RAISE(ABORT,'synthetic audit failure'); END"
        )
    with pytest.raises(LedgerAppendFailure):
        keys.shred_session_key(identity, "fixture")
    path.write_bytes(wrapped)
    page = await product.client.get(
        f"/adrl/v1/sessions/{product.sid}/timeline", headers=product.headers()
    )
    assert page.status_code == 200 and page.json()["entries"][0]["payload_state"] == "erased"
    assert page.json()["entries"][0]["observation"] is None
    assert (await product.bind()).status_code == 403
    assert (
        await product.client.post("/adrl/v1/events", headers=product.headers(), json=event)
    ).status_code == 403


async def test_real_pipeline_bytes_credentials_and_evidence(product: ProductHarness) -> None:
    await product.bind()
    fixture = load_fixture("user_turn")
    raw = json.dumps(fixture["body"], indent=3).encode()
    headers = fixture["headers"] | product.headers() | {"authorization": "Bearer provider-test"}
    reply = await product.client.post("/v1/messages", headers=headers, content=raw)
    assert reply.status_code == 200, reply.text
    await product.system.components.pipeline.drain()
    forwarded = product.system.gateway_requests()[-1]
    assert forwarded["raw"] == raw
    assert "x-adrl-workload-assertion" not in forwarded["headers"]
    assert "x-adrl-session-id" not in forwarded["headers"]
    assert forwarded["headers"]["authorization"] == "Bearer provider-test"
    route = product.system.decisions()[0]["route_id"]
    event = product.event(route_id=route)
    assert (
        await product.client.post("/adrl/v1/events", headers=headers, json=event)
    ).status_code == 200
    explanation = await product.client.get(f"/adrl/v1/decisions/{route}", headers=headers)
    assert explanation.status_code == 200, explanation.text
    assert explanation.json()["profile"]["id"] == "anthropic-messages-v1"
    assert explanation.json()["decided_rung"]
    denied = await product.client.get(
        f"/adrl/v1/decisions/{route}", headers=product.headers(sid=str(uuid4()))
    )
    assert denied.status_code == 403
    seen = []
    cursor = None
    while True:
        params = {"limit": "1"} | ({"cursor": cursor} if cursor else {})
        page = await product.client.get(
            f"/adrl/v1/sessions/{product.sid}/timeline", headers=headers, params=params
        )
        assert page.status_code == 200, page.text
        seen.extend(page.json()["entries"])
        cursor = page.json()["next_cursor"]
        if cursor is None:
            break
    refs = [e["record_ref"] for e in seen]
    assert len(refs) == len(set(refs))
    assert {e["kind"] for e in seen} >= {"decision", "dispatch", "observation"}
    assert seen[-1]["observation"]["schema_version"] == SCHEMA_VERSION


@pytest.mark.parametrize("path", ["/v1/responses", "/v1/messages/unknown", "/unclassified"])
async def test_bound_unknown_endpoint_never_forwards(product: ProductHarness, path: str) -> None:
    await product.bind()
    response = await product.client.post(
        path, headers=product.headers(), json={"secret": "sentinel"}
    )
    assert response.status_code == 422
    assert response.json()["type"] == "error"
    assert not product.system.gateway_requests()


async def test_invalid_model_credential_does_not_enter_pipeline(product: ProductHarness) -> None:
    await product.bind()
    headers = product.headers()
    del headers["x-adrl-workload-assertion"]
    response = await product.client.post("/v1/messages", headers=headers, json={})
    assert response.status_code == 401
    assert not product.system.gateway_requests()


@pytest.mark.parametrize(
    "params", [{"limit": "0"}, {"limit": "101"}, {"limit": "no"}, {"cursor": "7:forged"}]
)
async def test_pagination_input_is_bounded(product: ProductHarness, params: dict[str, str]) -> None:
    await product.bind()
    response = await product.client.get(
        f"/adrl/v1/sessions/{product.sid}/timeline", headers=product.headers(), params=params
    )
    assert response.status_code == 400


async def test_storage_failure_never_acknowledges_or_forwards(product: ProductHarness) -> None:
    await product.bind()
    product.system.store.close()
    response = await product.client.post(
        "/adrl/v1/events", headers=product.headers(), json=product.event()
    )
    assert response.status_code == 503
    assert not product.system.gateway_requests()
    product.system.store.open()


async def test_input_errors_do_not_echo_private_values(product: ProductHarness) -> None:
    await product.bind()
    response = await product.client.post(
        "/adrl/v1/events", headers=product.headers(), json=product.event(prompt="PRIVATE_SENTINEL")
    )
    assert response.status_code == 400 and "PRIVATE_SENTINEL" not in response.text
    oversized = await product.client.post(
        "/adrl/v1/events", headers=product.headers(), content=b"x" * 65537
    )
    assert oversized.status_code == 400


async def test_erasure_before_binding_cannot_create_evidence_key(product: ProductHarness) -> None:
    session = session_identity(product.sid, product.service.key)
    await product.system.components.erasure.erase_session(session, "before binding")
    assert (await product.bind()).status_code == 403
    assert not product.system.components.keystore.has_session_key(session)


async def test_changed_policy_cannot_silently_rebind(product: ProductHarness) -> None:
    await product.bind()
    changed = product.system.components.bundle.policy.model_copy(
        update={"version": "policy-changed"}
    )
    bundle = replace(product.system.components.bundle, policy=changed)
    product.service = ProductService(
        product.system.store, product.system.components.keystore, bundle
    )
    assert (await product.bind()).status_code == 409
    response = await product.client.get(
        f"/adrl/v1/sessions/{product.sid}", headers=product.headers()
    )
    assert response.status_code == 409
    assert len(product.system.store.read("SELECT * FROM product_sessions")) == 1


async def test_nonlocal_product_client_is_rejected(product: ProductHarness) -> None:
    app = build_asgi(product.system.components.pipeline, product=lambda: product.service)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=("192.0.2.5", 1000)), base_url="http://adrl"
    ) as client:
        response = await client.post("/adrl/v1/sessions", headers=product.headers(), json={})
    assert response.status_code == 403
    assert not product.system.store.read("SELECT * FROM product_sessions")


async def test_duplicate_native_identity_headers_are_rejected(product: ProductHarness) -> None:
    await product.bind()
    headers = [*product.headers().items(), ("x-claude-code-session-id", "other")]
    response = await product.client.post("/v1/messages", headers=headers, json={})
    assert response.status_code == 400
    assert not product.system.gateway_requests()


@pytest.mark.parametrize("event_schema", ["adrl-api-v1-preview.2", "adrl-api-v1-preview.3"])
async def test_observation_mode_is_durable_and_cannot_dispatch(
    product: ProductHarness, event_schema: str
) -> None:
    response = await product.bind(integration_mode="observe")
    assert response.status_code == 200
    status = response.json()["session"]
    assert status["integration_mode"] == "observe"
    facts = {f["dimension"]: f["status"] for f in status["coverage"]}
    assert facts["identity_binding"] == "enforced"
    for dimension in (
        "request_interception",
        "content_inspection",
        "dispatch_enforcement",
        "served_destination",
    ):
        assert facts[dimension] == "unavailable"
    product.service = ProductService(
        product.system.store, product.system.components.keystore, product.system.components.bundle
    )
    renewed = await product.bind(integration_mode="observe")
    assert renewed.status_code == 200
    assert renewed.json()["session"] == status
    assert (await product.bind(integration_mode="gateway")).status_code == 409
    denied = await product.client.post(
        "/v1/messages", headers=product.headers(), json={"model": "not-dispatched"}
    )
    assert denied.status_code == 403
    assert not product.system.gateway_requests()
    event = product.event(schema_version=event_schema)
    ack = await product.client.post("/adrl/v1/events", headers=product.headers(), json=event)
    assert ack.status_code == 200
    timeline = await product.client.get(
        f"/adrl/v1/sessions/{product.sid}/timeline", headers=product.headers()
    )
    entries = timeline.json()["entries"]
    assert len(entries) == 1
    assert entries[0]["kind"] == "observation"
    assert entries[0]["observation"]["schema_version"] == event_schema
    assert entries[0]["observation"]["payload"]["outcome"] == "failed"


async def test_gateway_binding_cannot_be_relabelled_as_observation(product: ProductHarness) -> None:
    assert (await product.bind()).status_code == 200
    assert (await product.bind(integration_mode="observe")).status_code == 409
    status = product.service.status(product.headers(), product.sid)
    assert status.integration_mode == "gateway"


def verifier_plan(tmp_path: Any) -> Any:
    import hashlib

    from adrl.ledger.session_verification import SessionPlan

    artifact = tmp_path / "operator-check.py"
    artifact.write_text("print('verifier artifact')")
    return SessionPlan.model_validate(
        {
            "verifier": {"id": "unit-checks", "version": "1"},
            "task_ref": "task-1",
            "checks": [
                {"name": "suite", "argv": ["/bin/echo", "PRIVATE_ARG"], "failure_exit_codes": [1]}
            ],
            "artifacts": {
                "checks.py": {
                    "path": str(artifact),
                    "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                }
            },
        }
    )


class ReceiptRunner:
    def __init__(self, code: int | None = 0, available: bool = True, mutate: bool = False) -> None:
        self.code = code
        self.available = available
        self.mutate = mutate
        self.calls = 0

    @property
    def platform_id(self) -> str:
        return "test-runner"

    def run(self, argv: Any, snapshot_dir: str, allow_list: Any, *, timeout_s: float) -> Any:
        from pathlib import Path

        from adrl.core.ports import SandboxResult

        root = Path(snapshot_dir)
        assert (root / ".adrl-verifier/checks.py").read_text() == "print('verifier artifact')"
        assert "PRIVATE_ARG" in argv
        self.calls += 1
        if self.mutate:
            (root / "code.py").chmod(0o600)
            (root / "code.py").write_text("modified snapshot")
        return SandboxResult(
            available=self.available,
            exit_code=self.code,
            duration_s=0.1,
            stdout_tail="PRIVATE_OUTPUT",
            stderr_tail="PRIVATE_ERROR",
        )


@pytest.mark.parametrize(
    ("code", "available", "mutate", "expected"),
    [
        (0, True, False, "passed"),
        (1, True, False, "failed"),
        (2, True, False, "indeterminate"),
        (None, True, False, "indeterminate"),
        (0, False, False, "indeterminate"),
        (0, True, True, "indeterminate"),
    ],
)
async def test_local_verifier_preserves_provenance_and_never_creates_routes(
    product: ProductHarness,
    tmp_path: Any,
    code: int | None,
    available: bool,
    mutate: bool,
    expected: str,
) -> None:
    from adrl.ledger.session_verification import SessionVerifier

    assert (await product.bind(integration_mode="observe")).status_code == 200
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "code.py").write_text("original code")
    plan = verifier_plan(tmp_path)
    runner = ReceiptRunner(code, available, mutate)
    session = session_identity(product.sid, product.service.key)
    result = await SessionVerifier(product.service.data, runner).verify(session, workspace, plan)
    assert result.result == expected
    assert not result.eligible_for_learning
    assert result.source_snapshot_ref and result.executed_snapshot_ref
    assert result.sandbox_implementation.id == "test-runner"
    assert result.sandbox_implementation.version.startswith("sha256:")
    assert (workspace / "code.py").read_text() == "original code"
    assert not product.system.store.read("SELECT * FROM decisions")
    assert not product.system.store.read("SELECT * FROM events")
    product.service = ProductService(
        product.system.store, product.system.components.keystore, product.system.components.bundle
    )
    page = await product.client.get(
        f"/adrl/v1/sessions/{product.sid}/timeline", headers=product.headers(), params={"limit": 1}
    )
    assert page.json()["entries"][0]["verification"]["phase"] == "started"
    second = await product.client.get(
        f"/adrl/v1/sessions/{product.sid}/timeline",
        headers=product.headers(),
        params={"cursor": page.json()["next_cursor"]},
    )
    entry = second.json()["entries"][0]
    assert entry["kind"] == "verification"
    assert entry["verification"]["result"] == expected
    assert entry["verification"]["job_id"] == result.job_id
    assert entry["route_id"] is None
    for row in product.system.store.read("SELECT * FROM product_verifications"):
        assert not any(
            marker in bytes(row["ciphertext"]) for marker in [b"PRIVATE_ARG", b"PRIVATE_OUTPUT"]
        )
    key = product.system.components.keystore
    key.shred_session_key(session, "test")
    erased = await product.client.get(
        f"/adrl/v1/sessions/{product.sid}/timeline", headers=product.headers()
    )
    assert all(
        e["payload_state"] == "erased" and e["verification"] is None
        for e in erased.json()["entries"]
    )
    calls = runner.calls
    with pytest.raises(ApiError, match="key is unavailable"):
        await SessionVerifier(product.service.data, runner).verify(session, workspace, plan)
    assert runner.calls == calls


@pytest.mark.parametrize(
    "problem", ["artifact_tamper", "inside_workspace", "symlink", "reserved", "limit"]
)
async def test_verifier_preconditions_do_not_execute_commands(
    product: ProductHarness, tmp_path: Any, problem: str
) -> None:
    from adrl.ledger.session_verification import SessionPlan, SessionVerifier

    await product.bind(integration_mode="observe")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "code.py").write_text("original")
    plan = verifier_plan(tmp_path)
    if problem == "artifact_tamper":
        (tmp_path / "operator-check.py").write_text("tampered")
    elif problem == "inside_workspace":
        moved = workspace / "operator-check.py"
        moved.write_text((tmp_path / "operator-check.py").read_text())
        values = plan.model_dump(mode="json")
        values["artifacts"]["checks.py"]["path"] = str(moved)
        plan = SessionPlan.model_validate(values)
    elif problem == "symlink":
        (workspace / "linked.py").symlink_to(tmp_path / "operator-check.py")
    elif problem == "reserved":
        (workspace / ".adrl-verifier").mkdir()
    else:
        plan = SessionPlan.model_validate(plan.model_dump() | {"max_bytes": 1})
    runner = ReceiptRunner()
    receipt = await SessionVerifier(product.service.data, runner).verify(
        session_identity(product.sid, product.service.key), workspace, plan
    )
    assert receipt.result == "indeterminate"
    assert receipt.reason
    assert runner.calls == 0


async def test_harness_cannot_forge_local_verification_receipt(product: ProductHarness) -> None:
    await product.bind(integration_mode="observe")
    event = product.event(
        event_type="verification.completed",
        payload={
            "task_ref": "task-1",
            "snapshot_ref": "fake",
            "verifier": {"id": "fake", "version": "1"},
            "result": "passed",
            "evidence_ref": "fake",
        },
    )
    response = await product.client.post("/adrl/v1/events", headers=product.headers(), json=event)
    assert response.status_code == 403
    event["authority"] = "local_operator_verifier"
    assert (
        await product.client.post("/adrl/v1/events", headers=product.headers(), json=event)
    ).status_code == 400
    assert not product.system.store.read("SELECT * FROM product_verifications")


@pytest.mark.parametrize("mutation", ["source", "mode", "erase"])
async def test_verifier_detects_live_drift_and_erasure(
    product: ProductHarness, tmp_path: Any, mutation: str
) -> None:
    from adrl.ledger.session_verification import SessionVerifier

    await product.bind(integration_mode="observe")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    source = workspace / "code.py"
    source.write_text("original code")
    source.chmod(0o644)
    session = session_identity(product.sid, product.service.key)

    class MutatingRunner(ReceiptRunner):
        def run(self, *args: Any, **kwargs: Any) -> Any:
            result = super().run(*args, **kwargs)
            if mutation == "source":
                source.write_text("changed source")
            elif mutation == "mode":
                source.chmod(0o755)
            else:
                product.system.components.keystore.shred_session_key(session, "during check")
            return result

    verifier = SessionVerifier(product.service.data, MutatingRunner())
    if mutation == "erase":
        with pytest.raises(ApiError, match="key is unavailable"):
            await verifier.verify(session, workspace, verifier_plan(tmp_path))
        rows = product.system.store.read("SELECT * FROM product_verifications")
        assert len(rows) == 1 and rows[0]["phase"] == "started"
        assert product.service.data.verification(rows[0]) is None
    else:
        receipt = await verifier.verify(session, workspace, verifier_plan(tmp_path))
        assert receipt.result == "indeterminate"
        assert receipt.reason == "snapshot_or_workspace_changed"
        assert receipt.snapshot_unchanged is False


def test_snapshot_keeps_empty_directories_and_detects_permission_drift(tmp_path: Any) -> None:
    from adrl.ledger.session_verification import _tree

    plan = verifier_plan(tmp_path)
    workspace = tmp_path / "source"
    workspace.mkdir()
    (workspace / "empty").mkdir()
    source = workspace / "check"
    source.write_text("value")
    source.chmod(0o644)
    target = tmp_path / "snapshot"
    target.mkdir()
    before = _tree(workspace, plan, target)
    assert (target / "empty").is_dir()
    assert _tree(target, plan) == before
    source.chmod(0o755)
    assert _tree(workspace, plan) != before


@pytest.mark.parametrize(
    "missing", ["checks", "executed_snapshot_ref", "source_snapshot_ref", "snapshot_unchanged"]
)
def test_conclusive_receipt_requires_snapshot_and_checks(missing: str) -> None:
    from datetime import UTC, datetime

    from pydantic import ValidationError

    from adrl.api.contracts import SessionVerification

    fields: dict[str, Any] = dict(
        sandbox_implementation={"id": "test-runner", "version": "1"},
        job_id="job",
        task_ref="task",
        phase="finished",
        verifier={"id": "tests", "version": "1"},
        plan_ref="plan",
        source_snapshot_ref="source",
        executed_snapshot_ref="executed",
        snapshot_unchanged=True,
        result="passed",
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        checks=[{"name": "tests", "result": "passed", "command_ref": "command", "duration_s": 1}],
    )
    assert SessionVerification.model_validate(fields).result == "passed"
    del fields[missing]
    with pytest.raises(ValidationError):
        SessionVerification.model_validate(fields)
