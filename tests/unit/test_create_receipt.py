"""Original create receipt custody and transport bounds. Primary: ADRL-OPS-001.

Secondary: ADRL-MEM-001/002/003/005/010, ADRL-SAF-007, ADRL-TRU-001.
Offline HTTP faults run against an in-process Unix socket, never a Docker daemon.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import httpx
import pytest

from adrl.core.container_control import (
    ContainerControl,
    ContainerRequest,
    ResourceError,
    ResourcePolicy,
    TransportError,
)
from adrl.core.execution_control import ExecutionControl, ExecutionPolicy
from adrl.core.isolated_execution import IsolatedExecution
from adrl.core.resource_owner import StoppedResourceOwner
from adrl.ledger.attempts import AttemptJournal

from .test_attempts import start
from .test_capture import Fixture
from .test_capture import capture as capture
from .test_isolated_execution import IMAGE, Engine, prepared
from .test_isolated_execution import engine as engine


@pytest.mark.parametrize(
    ("reply", "code", "cause"),
    [
        ("disconnect", "engine_unavailable_or_uncertain", "http_transport"),
        ("invalid", "engine_response_invalid", None),
        ("missing", "create_identity_unavailable", None),
        ("oversized", "engine_response_limit", None),
        ("encoded", "engine_encoded_response_refused", None),
        ("drip", "engine_request_deadline", None),
    ],
)
def test_created_object_can_outlive_rejected_original_reply(
    engine: Engine, reply: str, code: str, cause: str | None
) -> None:
    control = engine.control()
    control.policy = ResourcePolicy(request_seconds=0.15, response_bytes=1024)
    engine.create_reply = reply
    name, body = control.prepare(ContainerRequest(image_id=IMAGE, argv=("/probe",)), "f" * 64)
    with pytest.raises(ResourceError, match=code) as failure:
        control.create(name, body)
    assert getattr(failure.value, "kind", None) == cause
    assert len(engine.resources) == 1 and engine.starts() == 0
    assert sum("/create?" in p for _m, p in engine.calls) == 1


@pytest.mark.parametrize("seconds", [2, 10])
def test_delayed_original_receipt_distinguishes_preparation_from_active_budget(
    engine: Engine, seconds: float
) -> None:
    engine.create_delay = 2.25
    control = engine.control()
    control.policy = ResourcePolicy(request_seconds=seconds)
    name, body = control.prepare(ContainerRequest(image_id=IMAGE, argv=("/probe",)), "e" * 64)
    if seconds == 2:
        with pytest.raises(TransportError) as failure:
            control.create(name, body)
        assert failure.value.kind == "read_timeout"
        assert str(failure.value) == "engine_unavailable_or_uncertain"
    else:
        identity = control.create(name, body)
        assert identity in engine.resources
        control.verify_created(control.inspect(identity), name, body)
        control.remove(identity)
        assert not engine.resources
    assert engine.starts() == 0
    assert sum("/create?" in p for _m, p in engine.calls) == 1


async def test_missing_create_receipt_keeps_fence_without_reissue_or_adoption(
    capture: Fixture, engine: Engine
) -> None:
    engine.create_delay = 0.3
    control = engine.control()
    control.policy = ResourcePolicy(request_seconds=0.1)
    journal = AttemptJournal(capture.data)
    task, operation = start(), uuid4()
    await journal.start(capture.principal, capture.workspace, task)
    owner = StoppedResourceOwner(journal, control)
    request = ContainerRequest(image_id=IMAGE, argv=("/probe", "forced_stop"))
    with pytest.raises(ResourceError, match="resource_create_uncertain"):
        await owner.create(capture.principal, operation, task.attempt_id, request)
    assert [e.phase for e in owner.read(operation)] == ["intent", "create_issued"]
    assert owner.read(operation)[-1].resource_id is None
    with pytest.raises(ResourceError, match="already_issued"):
        await owner.create(capture.principal, operation, task.attempt_id, request)
    with pytest.raises(ResourceError):
        owner.remove(operation)
    assert capture.store.read("SELECT * FROM product_execution_fences")
    assert not capture.store.read("SELECT * FROM product_launch_events")
    assert engine.starts() == 0 and len(engine.resources) == 1
    assert sum("/create?" in p for _m, p in engine.calls) == 1


async def test_cancelled_creation_drains_original_receipt_without_start(
    capture: Fixture, engine: Engine
) -> None:
    engine.create_delay = 0.3
    journal = AttemptJournal(capture.data)
    task, operation = start(), uuid4()
    await journal.start(capture.principal, capture.workspace, task)
    owner = StoppedResourceOwner(journal, engine.control())
    pending = asyncio.create_task(
        owner.create(
            capture.principal,
            operation,
            task.attempt_id,
            ContainerRequest(image_id=IMAGE, argv=("/probe", "forced_stop")),
        )
    )
    assert await asyncio.to_thread(engine.create_entered.wait, 2)
    pending.cancel()
    await asyncio.sleep(0.02)
    pending.cancel()
    with pytest.raises(asyncio.CancelledError):
        await pending
    assert owner.last_event and owner.last_event.phase == "bound"
    assert owner.read(operation)[-1].resource_id in engine.resources
    owner.remove(operation)
    assert not engine.resources and engine.starts() == 0


async def test_every_active_request_uses_its_own_budget(
    capture: Fixture, engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = AttemptJournal(capture.data)
    task, operation = start(), uuid4()
    await journal.start(capture.principal, capture.workspace, task)
    control = engine.control()
    control.policy = ResourcePolicy()
    owner = StoppedResourceOwner(journal, control)
    run = IsolatedExecution(owner, ExecutionPolicy(active_request_seconds=0.3, max_run_seconds=0.1))
    original = ContainerControl._request
    calls: list[tuple[str, str, float]] = []

    def recorded(self: ContainerControl, method: str, path: str, *args: Any, **kw: Any) -> Any:
        calls.append((method, path, self.policy.request_seconds))
        return original(self, method, path, *args, **kw)

    monkeypatch.setattr(ContainerControl, "_request", recorded)
    await owner.create(
        capture.principal,
        operation,
        task.attempt_id,
        ContainerRequest(image_id=IMAGE, argv=("/probe", "forced_stop")),
    )
    assert next(b for m, p, b in calls if "/create?" in p) == 10
    assert run.control.control is not owner.control
    assert run.control.control.socket == owner.control.socket
    assert run.control.control.profile_sha256 == owner.control.profile_sha256
    assert (await run.run(capture.principal, operation)).resource_state == "stopped"
    assert run.recover(operation).resource_state == "absent"
    started = next(i for i, (m, p, b) in enumerate(calls) if p.endswith("/start"))
    active = calls[started:]
    assert all(b == 0.3 for m, p, b in active)
    assert any(m == "DELETE" for m, p, b in active)
    assert any("/kill?" in p for m, p, b in active)
    assert any(p.endswith("/json") for m, p, b in active)
    assert owner.policy.request_seconds == owner.control.policy.request_seconds == 10
    assert run.read(operation)[-1].policy.schema_version == "isolated-fixture-execution-v2"


async def test_active_start_timeout_does_not_inherit_preparation_budget(
    capture: Fixture, engine: Engine
) -> None:
    run, operation = await prepared(capture, engine, active_request_seconds=0.1)
    engine.start_delay = 0.3
    report = await run.run(capture.principal, operation)
    assert report.execution_failed and report.resource_state == "absent"
    assert [e.phase for e in run.read(operation)] == [
        "claim",
        "sealed",
        "discard_issued",
        "discarded",
    ]
    assert run.owner.control.policy.request_seconds == 1
    assert engine.starts() == 1 and not engine.resources


@pytest.mark.parametrize("reopen_seconds", [1, 10])
async def test_legacy_signed_history_keeps_its_original_transport_meaning(
    capture: Fixture, engine: Engine, reopen_seconds: float
) -> None:
    run, operation = await prepared(capture, engine, schema_version="isolated-fixture-execution-v1")
    assert (await run.run(capture.principal, operation)).resource_state == "stopped"
    key = run.owner._operation(operation)

    def old_shape(conn: sqlite3.Connection) -> list[str]:
        rows = list(conn.execute("SELECT * FROM product_launch_events ORDER BY event_seq"))
        previous = rows[0]["prev_mac"]
        payloads = []
        for row in rows:
            value = json.loads(row["payload_json"])
            del value["policy"]["active_request_seconds"]
            payload = json.dumps(value)
            mac = run._ref("event", [previous, payload])
            conn.execute(
                "UPDATE product_launch_events SET payload_json=?,prev_mac=?,mac=? "
                "WHERE operation_key=? AND event_seq=?",
                (payload, previous, mac, key, row["event_seq"]),
            )
            previous = mac
            payloads.append(payload)
        return payloads

    original = await asyncio.wrap_future(capture.store.submit(old_shape))
    run.owner.control.policy = ResourcePolicy(request_seconds=reopen_seconds)
    reopened = IsolatedExecution(run.owner, ExecutionPolicy(active_request_seconds=0.1))
    assert reopened.read(operation)[-1].policy.schema_version == "isolated-fixture-execution-v1"
    report = reopened.recover(operation)
    assert report.resource_state == ("absent" if reopen_seconds == 1 else "uncertain")
    assert report.exact_close_eligible is False and report.eligible_for_learning is False
    rows = capture.store.read("SELECT payload_json FROM product_launch_events ORDER BY event_seq")
    assert [r["payload_json"] for r in rows[: len(original)]] == original
    assert engine.starts() == 1
    if reopen_seconds == 10:
        assert engine.resources and not any(m == "DELETE" for m, p in engine.calls)


@pytest.mark.parametrize("seconds", [float("nan"), 0, 2.1])
def test_invalid_active_budget_is_refused(engine: Engine, seconds: float) -> None:
    policy = ExecutionPolicy.model_construct(active_request_seconds=seconds)
    with pytest.raises(ValueError):
        ExecutionControl(engine.control(), policy)
    assert not engine.calls


def test_transport_view_cannot_widen_or_reinterpret_legacy(engine: Engine) -> None:
    control = engine.control()
    with pytest.raises(ResourceError, match="widening"):
        control.bounded(2)
    with pytest.raises(ValueError, match="legacy_execution_budget_fixed"):
        ExecutionPolicy(schema_version="isolated-fixture-execution-v1", active_request_seconds=0.5)
    control.policy = ResourcePolicy()
    with pytest.raises(ResourceError, match="profile_required"):
        ExecutionControl(control, ExecutionPolicy(schema_version="isolated-fixture-execution-v1"))
    assert control.policy.request_seconds == 10 and not engine.calls


@pytest.mark.parametrize(
    ("error", "cause"),
    [
        (httpx.ReadTimeout, "read_timeout"),
        (httpx.ConnectTimeout, "connect_timeout"),
        (httpx.WriteTimeout, "write_timeout"),
        (httpx.PoolTimeout, "pool_timeout"),
        (httpx.RemoteProtocolError, "http_transport"),
        (OSError, "socket_failure"),
    ],
)
def test_transport_causes_do_not_expose_raw_messages(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, error: type[Exception], cause: str
) -> None:
    def failed(*args: Any, **kw: Any) -> Any:
        raise error("sensitive-path-and-daemon-text")

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", failed)
    with pytest.raises(TransportError) as failure:
        engine.control().engine()
    assert failure.value.kind == cause
    assert str(failure.value) == "engine_unavailable_or_uncertain"
    assert failure.value.__suppress_context__ is True


def test_engine_guard_retains_safe_transport_cause_and_halts(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.integration.test_resource_engine import engine as fixture

    log = tmp_path / "receipts.jsonl"
    for key, value in {
        "ADRL_RESOURCE_DOCKER_SOCKET": str(engine.path),
        "ADRL_RESOURCE_FIXTURE_IMAGE": IMAGE,
        "ADRL_RESOURCE_SECCOMP_PATH": str(
            Path(__file__).parents[1] / "fixtures/seccomp-v27.3.1.json"
        ),
        "ADRL_RESOURCE_ACCEPTANCE_LOG": str(log),
    }.items():
        monkeypatch.setenv(key, value)
    context = fixture.__wrapped__(monkeypatch)
    control, _ = next(context)
    control.policy = ResourcePolicy(request_seconds=0.1)
    engine.create_delay = 0.3
    name, body = control.prepare(ContainerRequest(image_id=IMAGE, argv=("/probe",)), "c" * 64)
    with pytest.raises(TransportError):
        control.create(name, body)
    with pytest.raises(pytest.exit.Exception):
        next(context)
    records = [json.loads(line) for line in log.read_text().splitlines()]
    assert [r["event"] for r in records] == ["create_issued", "create_uncertain"]
    assert records[-1]["transport_cause"] == "read_timeout"
    assert records[-1]["safe_code"] == "engine_unavailable_or_uncertain"
    assert engine.starts() == 0


def test_empty_success_response_still_obeys_elapsed_budget(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    import adrl.core.container_control as transport

    control = engine.control()
    name, body = control.prepare(ContainerRequest(image_id=IMAGE, argv=("/probe",)), "b" * 64)
    identity = control.create(name, body)
    stamps = iter([0.0, 2.0])
    monkeypatch.setattr(transport, "time", SimpleNamespace(monotonic=lambda: next(stamps)))
    with pytest.raises(ResourceError, match="engine_request_deadline"):
        control.remove(identity)
    assert not engine.resources
