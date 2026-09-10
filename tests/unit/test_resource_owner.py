"""Unix-socket wire and ownership faults. Primary: ADRL-OPS-001, ADRL-MEM-010."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import socket
import socketserver
import sqlite3
import tempfile
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field, replace
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import pytest
from pydantic import ValidationError

from adrl.core.container_control import (
    ContainerControl,
    ContainerRequest,
    ResourceError,
    ResourcePolicy,
)
from adrl.core.errors import LedgerAppendFailure
from adrl.core.resource_owner import ResourceEvent, StoppedResourceOwner
from adrl.ledger.attempts import AttemptError, AttemptJournal
from adrl.ledger.capture import CaptureError
from adrl.ledger.migrations import load_migrations
from adrl.ledger.store import LedgerStore

from .test_attempts import start, transition
from .test_capture import Fixture, bind
from .test_capture import capture as capture

PROFILE = b'{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[]}'
IMAGE = "sha256:" + "a" * 64
DENIAL = (ResourceError, CaptureError, AttemptError, LedgerAppendFailure)


@dataclass
class Wire:
    path: Path
    engine_id: str = "fixture-engine-12345"
    image_config: dict[str, Any] = field(default_factory=dict)
    resources: dict[str, dict[str, Any]] = field(default_factory=dict)
    calls: list[tuple[str, str]] = field(default_factory=list)
    drop_create: bool = False
    drop_delete: bool = False
    create_error: bool = False
    pause_create: threading.Event | None = None
    created: threading.Event = field(default_factory=threading.Event)
    info_body: bytes | None = None
    info_delay: float = 0

    def control(self, **changes: Any) -> ContainerControl:
        return ContainerControl(
            self.path,
            PROFILE,
            hashlib.sha256(PROFILE).hexdigest(),
            ResourcePolicy.model_validate(changes),
        )


@pytest.fixture
def wire() -> Iterator[Wire]:
    # Keep Darwin's Unix socket path below its platform length limit.
    with tempfile.TemporaryDirectory(prefix="adrl-resource-wire-", dir="/tmp") as directory:
        fixture = Wire(Path(directory) / "engine.sock")

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                pass

            def send(self, status: int, value: Any = None, raw: bytes | None = None) -> None:
                body = raw if raw is not None else json.dumps(value).encode()
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def do_GET(self) -> None:
                fixture.calls.append(("GET", self.path))
                if self.path == "/v1.47/info":
                    if fixture.info_delay:
                        time.sleep(fixture.info_delay)
                    self.send(
                        200,
                        {
                            "ID": fixture.engine_id,
                            "OSType": "linux",
                            "CgroupVersion": "2",
                            "Architecture": "aarch64",
                        },
                        fixture.info_body,
                    )
                elif self.path.startswith("/v1.47/images/"):
                    self.send(
                        200,
                        {
                            "Id": IMAGE,
                            "Os": "linux",
                            "Architecture": "arm64",
                            "Config": fixture.image_config,
                        },
                    )
                else:
                    identity = self.path.split("/")[-2]
                    self.send(
                        200, copy.deepcopy(fixture.resources[identity])
                    ) if identity in fixture.resources else self.send(404, {"message": "absent"})

            def do_POST(self) -> None:
                fixture.calls.append(("POST", self.path))
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                name = parse_qs(urlsplit(self.path).query)["name"][0]
                if fixture.create_error:
                    self.send(503, {"message": "private daemon diagnostic"})
                    return
                if any(r["Name"] == "/" + name for r in fixture.resources.values()):
                    self.send(409, {"message": "conflict"})
                    return
                identity = uuid4().hex + uuid4().hex
                config = {k: v for k, v in body.items() if k != "HostConfig"}
                fixture.resources[identity] = {
                    "Id": identity,
                    "Name": "/" + name,
                    "Image": body["Image"],
                    "Platform": "linux",
                    "Path": body["Cmd"][0],
                    "Args": body["Cmd"][1:],
                    "Created": "2026-09-08T00:00:00.000000000Z",
                    "RestartCount": 0,
                    "State": {
                        "Status": "created",
                        "Running": False,
                        "Restarting": False,
                        "Paused": False,
                        "Dead": False,
                        "Pid": 0,
                        "StartedAt": "0001-01-01T00:00:00Z",
                        "FinishedAt": "0001-01-01T00:00:00Z",
                    },
                    "Config": copy.deepcopy(config),
                    "HostConfig": copy.deepcopy(body["HostConfig"]),
                    "Mounts": [],
                }
                fixture.created.set()
                if fixture.pause_create:
                    assert fixture.pause_create.wait(3)
                if fixture.drop_create:
                    self.connection.shutdown(socket.SHUT_RDWR)
                    self.connection.close()
                    return
                self.send(201, {"Id": identity, "Warnings": []})

            def do_DELETE(self) -> None:
                fixture.calls.append(("DELETE", self.path))
                assert parse_qs(urlsplit(self.path).query) == {"force": ["false"], "v": ["false"]}
                identity = urlsplit(self.path).path.split("/")[-1]
                if identity not in fixture.resources:
                    self.send(404, {"message": "absent"})
                    return
                if fixture.resources[identity]["State"]["Running"]:
                    self.send(409, {"message": "running"})
                    return
                del fixture.resources[identity]
                if fixture.drop_delete:
                    self.connection.shutdown(socket.SHUT_RDWR)
                    self.connection.close()
                    return
                self.send(204, raw=b"")

        server = socketserver.ThreadingUnixStreamServer(str(fixture.path), Handler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
        thread.start()
        try:
            yield fixture
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


def request(**changes: Any) -> ContainerRequest:
    return ContainerRequest.model_validate(
        {"image_id": IMAGE, "argv": ["/probe", "synthetic-private-canary"]} | changes
    )


def owner(capture: Fixture, wire: Wire, **changes: Any) -> StoppedResourceOwner:
    return StoppedResourceOwner(AttemptJournal(capture.data), wire.control(**changes))


async def test_create_retry_restart_erase_and_cleanup(capture: Fixture, wire: Wire) -> None:
    run, task, operation = owner(capture, wire), start(), uuid4()
    await run.journal.start(capture.principal, capture.workspace, task)
    first = await run.create(capture.principal, operation, task.attempt_id, request())
    assert first.phase == "bound" and first.resource_id in wire.resources
    assert not first.exact_close_eligible and not first.eligible_for_learning
    assert await run.create(capture.principal, operation, task.attempt_id, request()) == first
    capture.store.close()
    capture.store.open()
    recovered = owner(capture, wire)
    assert await asyncio.to_thread(recovered.inspect_owned, operation) == first
    capture.keys.shred_session_key(capture.principal.session_hmac, "fixture")
    with pytest.raises(CaptureError):
        await recovered.create(capture.principal, operation, task.attempt_id, request())
    done = await asyncio.to_thread(recovered.remove, operation)
    assert done.phase == "removed" and done.workspace_state == "blocked"
    assert await asyncio.to_thread(recovered.remove, operation) == done
    assert len([c for c in wire.calls if c[0] == "POST"]) == 1 and not wire.resources
    assert [e.phase for e in recovered.read(operation)] == [
        "intent",
        "create_issued",
        "bound",
        "remove_issued",
        "removed",
    ]
    rows = capture.store.read("SELECT payload_json FROM product_resource_events")
    text = str([dict(r) for r in rows])
    for private in [
        str(capture.workspace),
        str(operation),
        str(task.attempt_id),
        "synthetic-private-canary",
        "/probe",
    ]:
        assert private not in text
    assert capture.store.read("SELECT * FROM product_execution_fences")


@pytest.mark.parametrize("same_operation", [True, False])
async def test_concurrent_create_claim_is_single(
    capture: Fixture, wire: Wire, same_operation: bool
) -> None:
    run, task, operation = owner(capture, wire), start(), uuid4()
    await run.journal.start(capture.principal, capture.workspace, task)
    results = await asyncio.gather(
        *(
            owner(capture, wire).create(capture.principal, op, task.attempt_id, request())
            for op in [operation, operation if same_operation else uuid4()]
        ),
        return_exceptions=True,
    )
    assert sum(isinstance(r, ResourceEvent) for r in results) >= 1
    assert len(wire.resources) == 1 and len([c for c in wire.calls if c[0] == "POST"]) == 1


@pytest.mark.parametrize("fault", ["lost_create", "rejected_create", "bind_before", "bind_after"])
async def test_create_partial_failures_never_adopt_or_reissue(
    capture: Fixture, wire: Wire, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    run, task, operation = owner(capture, wire), start(), uuid4()
    await run.journal.start(capture.principal, capture.workspace, task)
    wire.drop_create = fault == "lost_create"
    wire.create_error = fault == "rejected_create"
    advance = run._advance

    def fail(operation: str, phase: Any, **kwargs: str) -> Any:
        if phase == "bound" and fault in {"bind_before", "bind_after"}:
            if fault == "bind_after":
                advance(operation, phase, **kwargs)
            raise LedgerAppendFailure("fixture binding failure")
        return advance(operation, phase, **kwargs)

    monkeypatch.setattr(run, "_advance", fail)
    with pytest.raises(ResourceError, match="create_uncertain"):
        await run.create(capture.principal, operation, task.attempt_id, request())
    recovered = owner(capture, wire)
    if fault == "bind_after":
        assert (
            await recovered.create(capture.principal, operation, task.attempt_id, request())
        ).phase == "bound"
    else:
        assert recovered.read(operation)[-1].phase == "create_issued"
        with pytest.raises(ResourceError, match="already_issued"):
            await recovered.create(capture.principal, operation, task.attempt_id, request())
        with pytest.raises(ResourceError, match="not_bound"):
            await asyncio.to_thread(recovered.remove, operation)
    assert len([c for c in wire.calls if c[0] == "POST"]) == 1
    assert not any("?name=" in path for method, path in wire.calls if method == "GET")


async def test_remove_lost_ack_reconciles_known_absence(capture: Fixture, wire: Wire) -> None:
    run, task, operation = owner(capture, wire), start(), uuid4()
    await run.journal.start(capture.principal, capture.workspace, task)
    await run.create(capture.principal, operation, task.attempt_id, request())
    wire.drop_delete = True
    with pytest.raises(ResourceError, match="uncertain"):
        await asyncio.to_thread(run.remove, operation)
    assert run.read(operation)[-1].phase == "remove_issued" and not wire.resources
    assert (await asyncio.to_thread(owner(capture, wire).remove, operation)).phase == "removed"
    assert len([c for c in wire.calls if c[0] == "DELETE"]) == 1


@pytest.mark.parametrize(
    "change",
    [
        "id",
        "image",
        "command",
        "label",
        "created",
        "running",
        "exited",
        "restarted",
        "engine",
        "mount",
    ],
)
async def test_changed_resource_refuses_cleanup(capture: Fixture, wire: Wire, change: str) -> None:
    run, task, operation = owner(capture, wire), start(), uuid4()
    await run.journal.start(capture.principal, capture.workspace, task)
    event = await run.create(capture.principal, operation, task.attempt_id, request())
    assert event.resource_id
    value = wire.resources[event.resource_id]
    if change == "id":
        value["Id"] = "b" * 64
    elif change == "image":
        value["Image"] = "sha256:" + "b" * 64
    elif change == "command":
        value["Config"]["Cmd"] = ["/different"]
    elif change == "label":
        value["Config"]["Labels"]["extra"] = "changed"
    elif change == "created":
        value["Created"] = "2026-09-08T01:00:00Z"
    elif change == "running":
        value["State"]["Running"] = True
        value["State"]["Status"] = "running"
    elif change == "exited":
        value["State"]["Status"] = "exited"
    elif change == "restarted":
        value["RestartCount"] = 1
    elif change == "engine":
        wire.engine_id = "another-engine-12345"
    else:
        value["Mounts"] = [{"Type": "bind", "Source": "/private-fixture"}]
    with pytest.raises(ResourceError):
        await asyncio.to_thread(run.remove, operation)
    assert not any(method == "DELETE" for method, _ in wire.calls)
    assert run.read(operation)[-1].phase == "bound"


@pytest.mark.parametrize(
    "fault", ["expired", "erased", "grant", "workspace", "closed", "foreign_fence"]
)
async def test_bad_admission_never_creates(capture: Fixture, wire: Wire, fault: str) -> None:
    run, task, operation = owner(capture, wire), start(), uuid4()
    await run.journal.start(capture.principal, capture.workspace, task)
    principal = capture.principal
    if fault == "expired":
        principal = replace(principal, assertion=replace(principal.assertion, expires_at=0))
    elif fault == "erased":
        capture.keys.shred_session_key(principal.session_hmac, "fixture")
    elif fault == "grant":
        await capture.store.write_through(
            lambda c: c.execute("UPDATE product_attempt_capacity SET reserved_bytes=2048")
        )
    elif fault == "workspace":
        principal = replace(
            principal,
            assertion=replace(
                principal.assertion,
                inventory=replace(principal.assertion.inventory, root=str(capture.scratch)),
            ),
        )
    elif fault == "closed":
        await run.journal.transition(principal, transition(task, "cancel"))
    else:
        await run.create(principal, uuid4(), task.attempt_id, request())
        wire.calls.clear()
    with pytest.raises(DENIAL):
        await run.create(principal, operation, task.attempt_id, request())
    assert not any(method == "POST" for method, _ in wire.calls)


@pytest.mark.parametrize("field", ["Env", "Entrypoint", "Volumes", "Healthcheck", "OnBuild"])
async def test_inherited_image_controls_refused(capture: Fixture, wire: Wire, field: str) -> None:
    run, task = owner(capture, wire), start()
    await run.journal.start(capture.principal, capture.workspace, task)
    wire.image_config[field] = ["inherited"]
    with pytest.raises(ResourceError, match="inherited_image"):
        await run.create(capture.principal, uuid4(), task.attempt_id, request())
    assert not wire.resources


@pytest.mark.parametrize("fault", ["mac", "gap", "payload", "fence", "host_key"])
async def test_history_corruption_never_authorizes_cleanup(
    capture: Fixture, wire: Wire, fault: str
) -> None:
    run, task, operation = owner(capture, wire), start(), uuid4()
    await run.journal.start(capture.principal, capture.workspace, task)
    await run.create(capture.principal, operation, task.attempt_id, request())
    if fault == "host_key":
        (capture.keys.root / "hmac.key").write_bytes(b"x" * 32)
    else:
        sql = {
            "mac": "UPDATE product_resource_events SET mac='wrong' WHERE event_seq=1",
            "gap": "DELETE FROM product_resource_events WHERE event_seq=1",
            "payload": "UPDATE product_resource_events SET payload_json='{}' WHERE event_seq=1",
            "fence": "UPDATE product_execution_fences SET policy_json='{}'",
        }[fault]
        await capture.store.write_through(lambda c: c.execute(sql))
    with pytest.raises(ResourceError):
        await asyncio.to_thread(run.remove, operation)
    assert not any(method == "DELETE" for method, _ in wire.calls)


async def test_quota_and_changed_retry_preserve_intent(capture: Fixture, wire: Wire) -> None:
    run, task, operation = owner(capture, wire, max_resources=1), start(), uuid4()
    await run.journal.start(capture.principal, capture.workspace, task)
    await run.create(capture.principal, operation, task.attempt_id, request())
    with pytest.raises(DENIAL, match="operation_conflict"):
        await run.create(capture.principal, operation, task.attempt_id, request(argv=["/changed"]))
    await asyncio.to_thread(run.remove, operation)
    other = await bind(capture.data, capture.scratch, str(uuid4()))
    second = start()
    await run.journal.start(other, capture.scratch, second)
    with pytest.raises(DENIAL, match="admission_limit"):
        await run.create(other, uuid4(), second.attempt_id, request())


async def test_cancellation_drains_inflight_create(capture: Fixture, wire: Wire) -> None:
    run, task, operation = owner(capture, wire), start(), uuid4()
    await run.journal.start(capture.principal, capture.workspace, task)
    wire.pause_create = threading.Event()
    pending = asyncio.create_task(
        run.create(capture.principal, operation, task.attempt_id, request())
    )
    try:
        assert await asyncio.to_thread(wire.created.wait, 3)
        pending.cancel()
        await asyncio.sleep(0)
        pending.cancel()
        assert not pending.done()
    finally:
        wire.pause_create.set()
    with pytest.raises(asyncio.CancelledError):
        await pending
    assert run.read(operation)[-1].phase == "bound" and len(wire.resources) == 1
    assert run.last_event and run.last_event.phase == "bound"


@pytest.mark.parametrize("fault", ["malformed", "oversized", "timeout"])
def test_transport_fails_closed(wire: Wire, fault: str) -> None:
    control = wire.control(response_bytes=1024, request_seconds=0.1)
    if fault == "malformed":
        wire.info_body = b"not json"
    elif fault == "oversized":
        wire.info_body = json.dumps({"padding": "X" * 2048}).encode()
    else:
        wire.info_delay = 0.3
    with pytest.raises(ResourceError):
        control.engine()


@pytest.mark.parametrize("changes", [{"max_resources": 33}, {"request_seconds": 16}, {"user": "0"}])
def test_policy_bounds(changes: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        ResourcePolicy.model_validate(changes)


@pytest.mark.parametrize("fault", ["erased", "closed", "grant"])
async def test_pending_intent_rechecks_authority_before_issue(
    capture: Fixture, wire: Wire, fault: str
) -> None:
    run, task, operation = owner(capture, wire), start(), uuid4()
    await run.journal.start(capture.principal, capture.workspace, task)
    wire.image_config["Env"] = ["refused"]
    with pytest.raises(ResourceError):
        await run.create(capture.principal, operation, task.attempt_id, request())
    assert run.read(operation)[-1].phase == "intent"
    wire.image_config.clear()
    if fault == "erased":
        capture.keys.shred_session_key(capture.principal.session_hmac, "fixture")
    elif fault == "closed":
        await run.journal.transition(capture.principal, transition(task, "cancel"))
    else:
        await capture.store.write_through(
            lambda c: c.execute("UPDATE product_attempt_capacity SET reserved_bytes=2048")
        )
    with pytest.raises(DENIAL):
        await run.create(capture.principal, operation, task.attempt_id, request())
    assert not any(method == "POST" for method, _ in wire.calls)
    assert run.read(operation)[-1].phase == "intent"


@pytest.mark.parametrize("fault", ["intent_insert", "claim_insert", "remove_insert"])
async def test_database_failure_does_not_cross_mutation_boundary(
    capture: Fixture, wire: Wire, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    run, task, operation = owner(capture, wire), start(), uuid4()
    await run.journal.start(capture.principal, capture.workspace, task)
    insert = run._insert

    def fail(conn: sqlite3.Connection, event: ResourceEvent, previous: str) -> None:
        phase = {
            "intent_insert": "intent",
            "claim_insert": "create_issued",
            "remove_insert": "remove_issued",
        }[fault]
        if event.phase == phase:
            raise sqlite3.OperationalError("fixture storage failure")
        insert(conn, event, previous)

    monkeypatch.setattr(run, "_insert", fail)
    if fault == "remove_insert":
        await run.create(capture.principal, operation, task.attempt_id, request())
        with pytest.raises(LedgerAppendFailure):
            await asyncio.to_thread(run.remove, operation)
        assert run.read(operation)[-1].phase == "bound"
        assert not any(method == "DELETE" for method, _ in wire.calls)
    else:
        with pytest.raises(LedgerAppendFailure):
            await run.create(capture.principal, operation, task.attempt_id, request())
        assert not any(method == "POST" for method, _ in wire.calls)
        if fault == "intent_insert":
            assert not capture.store.read("SELECT * FROM product_execution_fences")
            assert not capture.store.read("SELECT * FROM product_resource_events")
        else:
            assert run.read(operation)[-1].phase == "intent"


async def test_schema_ten_migration_preserves_fence_and_encrypted_attempt(
    capture: Fixture, wire: Wire
) -> None:
    run, task, operation = owner(capture, wire), start(), uuid4()
    await run.journal.start(capture.principal, capture.workspace, task)
    await run.create(capture.principal, operation, task.attempt_id, request())
    path = capture.scratch / "schema10.db"
    tables = [
        "product_sessions",
        "product_attempt_events",
        "product_attempt_capacity",
        "product_execution_fences",
    ]
    expected = {
        table: [dict(row) for row in capture.store.read(f"SELECT * FROM {table}")]
        for table in tables
    }
    with sqlite3.connect(path) as conn:
        for migration in load_migrations():
            if migration.version <= 10:
                conn.executescript(migration.sql)
        for table, rows in expected.items():
            for row in rows:
                conn.execute(
                    f"INSERT INTO {table} ({','.join(row)}) VALUES ({','.join('?' for _ in row)})",
                    tuple(row.values()),
                )
        conn.execute("PRAGMA user_version=10")
    store = LedgerStore(path)
    store.open()
    try:
        assert store.schema_user_version() == 12
        for table in tables:
            assert [dict(row) for row in store.read(f"SELECT * FROM {table}")] == expected[table]
        assert not store.read("SELECT * FROM product_resource_events")
    finally:
        store.close()
