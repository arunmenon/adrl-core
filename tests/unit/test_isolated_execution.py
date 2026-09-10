"""One-shot launch and recovery faults. Primary: ADRL-OPS-001.

Secondary: ADRL-MEM-001/002/003/005/010, ADRL-SAF-007, ADRL-TRU-001.
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import os
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field, replace
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit
from uuid import UUID, uuid4

import pytest

from adrl.core.container_control import (
    ContainerControl,
    ContainerRequest,
    ResourceError,
    ResourcePolicy,
)
from adrl.core.errors import LedgerAppendFailure
from adrl.core.execution_control import ExecutionPolicy
from adrl.core.isolated_execution import IsolatedExecution, LaunchEvent
from adrl.core.launch_markers import LaunchMarkers
from adrl.core.resource_owner import StoppedResourceOwner
from adrl.ledger.attempts import AttemptJournal

from .test_attempts import start, transition
from .test_capture import Fixture, bind
from .test_capture import capture as capture

IMAGE = "sha256:" + "a" * 64
PROFILE = (Path(__file__).parents[1] / "fixtures/seccomp-v27.3.1.json").read_bytes()


@dataclass
class Engine:
    path: Path
    resources: dict[str, Any] = field(default_factory=dict)
    calls: list[tuple[str, str]] = field(default_factory=list)
    drop_start: bool = False
    drop_remove: bool = False
    start_status: int = 204
    pause_start: threading.Event | None = None
    start_entered: threading.Event = field(default_factory=threading.Event)
    changed: dict[str, Any] = field(default_factory=dict)
    image_layer: str = ExecutionPolicy().archive_sha256
    engine_id: str = "launch-fixture-engine-id"
    info_status: int = 200
    create_delay: float = 0
    create_reply: str = "normal"
    create_entered: threading.Event = field(default_factory=threading.Event)
    start_delay: float = 0

    def control(self) -> ContainerControl:
        return ContainerControl(
            self.path,
            PROFILE,
            hashlib.sha256(PROFILE).hexdigest(),
            ResourcePolicy(request_seconds=1),
        )

    def starts(self) -> int:
        return sum(method == "POST" and path.endswith("/start") for method, path in self.calls)


@pytest.fixture
def engine() -> Iterator[Engine]:
    with tempfile.TemporaryDirectory(prefix="adrl-launch-test-", dir="/tmp") as directory:
        state = Engine(Path(directory) / "socket")

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                pass

            def send(self, status: int, value: Any = None) -> None:
                data = json.dumps(value).encode() if status != 204 else b""
                self.send_response(status)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                try:
                    self.wfile.write(data)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def do_GET(self) -> None:
                state.calls.append(("GET", self.path))
                if self.path == "/v1.47/version":
                    self.send(
                        200,
                        {
                            "Version": "27.3.1",
                            "ApiVersion": "1.47",
                            "Os": "linux",
                            "Arch": "arm64",
                            "KernelVersion": "6.10.11-linuxkit",
                        },
                    )
                elif self.path == "/v1.47/info":
                    self.send(
                        state.info_status,
                        {
                            "ID": state.engine_id,
                            "OSType": "linux",
                            "Architecture": "aarch64",
                            "CgroupVersion": "2",
                            "CgroupDriver": "cgroupfs",
                            "KernelVersion": "6.10.11-linuxkit",
                            "OomKillDisable": False,
                            "MemoryLimit": True,
                            "SwapLimit": True,
                            "PidsLimit": True,
                            "CpuCfsPeriod": True,
                            "CpuCfsQuota": True,
                            "SecurityOptions": ["name=seccomp,profile=unconfined", "name=cgroupns"],
                        }
                        | state.changed,
                    )
                elif "/images/" in self.path:
                    self.send(
                        200,
                        {
                            "Id": IMAGE,
                            "Os": "linux",
                            "Architecture": "arm64",
                            "Config": {},
                            "RootFS": {"Type": "layers", "Layers": ["sha256:" + state.image_layer]},
                        },
                    )
                else:
                    identity = self.path.split("/")[-2]
                    if identity in state.resources:
                        self.send(200, copy.deepcopy(state.resources[identity]))
                    else:
                        self.send(404, {"message": "absent"})

            def do_POST(self) -> None:
                state.calls.append(("POST", self.path))
                if "/create?" in self.path:
                    body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                    name = parse_qs(urlsplit(self.path).query)["name"][0]
                    identity = uuid4().hex + uuid4().hex
                    state.resources[identity] = {
                        "Id": identity,
                        "Name": "/" + name,
                        "Image": body["Image"],
                        "Platform": "linux",
                        "Path": body["Cmd"][0],
                        "Args": body["Cmd"][1:],
                        "Created": "2026-09-08T00:00:00.000000000Z",
                        "RestartCount": 0,
                        "Config": {k: v for k, v in body.items() if k != "HostConfig"},
                        "HostConfig": body["HostConfig"] | {"OomKillDisable": False},
                        "Mounts": [],
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
                    }
                    state.create_entered.set()
                    time.sleep(state.create_delay)
                    if state.create_reply == "disconnect":
                        self.connection.close()
                        return
                    if state.create_reply != "normal":
                        data = {
                            "invalid": b"not json",
                            "missing": b"{}",
                            "oversized": b" " * 2048,
                            "encoded": json.dumps({"Id": identity}).encode(),
                            "drip": json.dumps({"Id": identity}).encode(),
                        }[state.create_reply]
                        try:
                            self.send_response(201)
                            self.send_header("Content-Length", str(len(data)))
                            if state.create_reply == "encoded":
                                self.send_header("Content-Encoding", "gzip")
                            self.end_headers()
                            if state.create_reply == "drip":
                                for part in (data[:1], data[1:2], data[2:]):
                                    time.sleep(0.08)
                                    self.wfile.write(part)
                                    self.wfile.flush()
                            else:
                                self.wfile.write(data)
                        except (BrokenPipeError, ConnectionResetError):
                            pass
                        return
                    self.send(201, {"Id": identity})
                    return
                identity = self.path.split("/")[-2]
                if self.path.endswith("/start"):
                    state.start_entered.set()
                    if state.pause_start is not None:
                        assert state.pause_start.wait(2)
                    if identity not in state.resources:
                        self.send(404)
                        return
                    item = state.resources[identity]
                    item["State"].update(
                        Status="running",
                        Running=True,
                        Pid=42,
                        StartedAt="2026-09-08T01:00:00.000000000Z",
                    )
                    item["HostConfig"]["OomKillDisable"] = None
                    time.sleep(state.start_delay)
                    if state.drop_start:
                        self.connection.close()
                        return
                    self.send(state.start_status)
                    return
                if identity not in state.resources:
                    self.send(404)
                    return
                state.resources[identity]["State"].update(
                    Status="exited", Running=False, Pid=0, FinishedAt="2026-09-08T01:00:01Z"
                )
                self.send(204)

            def do_DELETE(self) -> None:
                state.calls.append(("DELETE", self.path))
                identity = self.path.split("/")[-1].split("?")[0]
                if identity not in state.resources:
                    self.send(404)
                    return
                del state.resources[identity]
                if state.drop_remove:
                    self.connection.close()
                    return
                self.send(204)

        server = socketserver.ThreadingUnixStreamServer(str(state.path), Handler)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
        thread.start()
        try:
            yield state
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


async def prepared(
    capture: Fixture, engine: Engine, **policy: Any
) -> tuple[IsolatedExecution, UUID]:
    journal = AttemptJournal(capture.data)
    task = start()
    operation = uuid4()
    await journal.start(capture.principal, capture.workspace, task)
    owner = StoppedResourceOwner(journal, engine.control())
    await owner.create(
        capture.principal,
        operation,
        task.attempt_id,
        ContainerRequest(image_id=IMAGE, argv=("/probe", "forced_stop")),
    )
    return IsolatedExecution(owner, ExecutionPolicy(max_run_seconds=0.1, **policy)), operation


async def test_known_stop_reopen_discard_and_no_relaunch(capture: Fixture, engine: Engine) -> None:
    run, op = await prepared(capture, engine)
    report = await run.run(capture.principal, op)
    assert (
        report.resource_state == "stopped"
        and not report.audit_failed
        and not report.execution_failed
    )
    assert [x.phase for x in run.read(op)] == ["claim", "acknowledged", "sealed", "stopped"]
    assert not report.exact_close_eligible and not report.eligible_for_learning
    assert len(engine.resources) == 1 and engine.starts() == 1
    capture.store.close()
    capture.store.open()
    reopened = IsolatedExecution(run.owner)
    assert reopened.recover(op).resource_state == "absent"
    with pytest.raises(ResourceError):
        await reopened.run(capture.principal, op)
    assert engine.starts() == 1 and not engine.resources
    assert capture.store.read("SELECT * FROM product_execution_fences")


@pytest.mark.parametrize(
    "phase", ["claim", "acknowledged", "sealed", "stopped", "discard_issued", "discarded"]
)
async def test_lost_event_ack(
    capture: Fixture, engine: Engine, monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    run, op = await prepared(capture, engine)
    lost = False

    # Inject above the committed submit boundary, not inside the transaction.
    if phase == "claim":
        claim = run._claim

        def dropped(*args: Any, **kwargs: Any) -> LaunchEvent:
            nonlocal lost
            result = claim(*args, **kwargs)
            if not lost:
                lost = True
                raise OSError("lost_claim_ack")
            return result

        monkeypatch.setattr(run, "_claim", dropped)
    else:
        append = run._append

        def missing(operation: str, value: Any, **kwargs: Any) -> LaunchEvent:
            nonlocal lost
            result = append(operation, value, **kwargs)
            if value == phase and not lost:
                lost = True
                raise OSError("lost_append_ack")
            return result

        monkeypatch.setattr(run, "_append", missing)
    if phase.startswith("discard"):
        engine.drop_start = True
    report = await run.run(capture.principal, op)
    assert report.resource_state == "absent" and not engine.resources
    assert engine.starts() <= 1
    assert lost and not report.exact_close_eligible
    assert run.recover(op).resource_state == "absent"
    with pytest.raises(ResourceError):
        await run.run(capture.principal, op)


@pytest.mark.parametrize("fault", ["start_reply", "remove_reply", "start_http_200"])
async def test_transport_uncertainty(capture: Fixture, engine: Engine, fault: str) -> None:
    run, op = await prepared(capture, engine)
    engine.drop_start = fault != "start_http_200"
    engine.drop_remove = fault == "remove_reply"
    if fault == "start_http_200":
        engine.start_status = 200
    report = await run.run(capture.principal, op)
    assert report.resource_state == "absent" and report.execution_failed and engine.starts() == 1
    assert [x.phase for x in run.read(op)] == ["claim", "sealed", "discard_issued", "discarded"]


async def test_competing_instances_do_not_abort_winner(capture: Fixture, engine: Engine) -> None:
    run, op = await prepared(capture, engine)
    other = IsolatedExecution(run.owner, run.policy)
    results = await asyncio.gather(
        run.run(capture.principal, op), other.run(capture.principal, op), return_exceptions=True
    )
    assert sum(isinstance(x, ResourceError) for x in results) == 1
    assert engine.starts() == 1 and len(engine.resources) == 1
    assert run.recover(op).resource_state == "absent"


@pytest.mark.parametrize(
    "fault", ["marker_only", "claim_only", "prefix_rollback", "corrupt", "host_key"]
)
async def test_recovery_never_resumes_launch(capture: Fixture, engine: Engine, fault: str) -> None:
    run, op = await prepared(capture, engine)
    event = await asyncio.to_thread(run._prepare, capture.principal, op)
    run.markers.publish(event.operation_key)
    if fault != "marker_only":
        await asyncio.to_thread(run._claim, capture.principal, event)
    if fault == "prefix_rollback":
        await asyncio.to_thread(
            capture.store.submit(lambda c: c.execute("DELETE FROM product_launch_events")).result
        )
    elif fault == "corrupt":
        await asyncio.to_thread(
            capture.store.submit(
                lambda c: c.execute("UPDATE product_launch_events SET mac='bad'")
            ).result
        )
    elif fault == "host_key":
        capture.keys.rotate_hmac_key()
    with pytest.raises((ResourceError, ValueError)):
        await run.run(capture.principal, op)
    result = await asyncio.to_thread(run.recover, op)
    assert engine.starts() == 0
    if fault in {"marker_only", "prefix_rollback"}:
        assert result.resource_state == "not_launched" and engine.resources
    elif fault in {"corrupt", "host_key"}:
        assert result.resource_state == "uncertain" and engine.resources
    else:
        assert result.resource_state == "absent"


@pytest.mark.parametrize("fault", ["engine", "configuration", "started_at", "missing_oom"])
async def test_changed_identity_blocks_cleanup(
    capture: Fixture, engine: Engine, fault: str
) -> None:
    run, op = await prepared(capture, engine)
    assert (await run.run(capture.principal, op)).resource_state == "stopped"
    item = next(iter(engine.resources.values()))
    if fault == "engine":
        engine.engine_id = "changed-engine-id"
    elif fault == "configuration":
        item["HostConfig"]["Privileged"] = True
    elif fault == "started_at":
        item["State"]["StartedAt"] = "2026-09-08T02:00:00Z"
    else:
        del item["HostConfig"]["OomKillDisable"]
    assert run.recover(op).resource_state == "uncertain" and engine.resources
    assert not any(m == "DELETE" for m, p in engine.calls)


@pytest.mark.parametrize("fault", ["erased", "expired", "wrong_session", "closed", "grant"])
async def test_authority_before_marker(capture: Fixture, engine: Engine, fault: str) -> None:
    run, op = await prepared(capture, engine)
    principal = capture.principal
    if fault == "erased":
        capture.keys.shred_session_key(principal.session_hmac, "test")
    elif fault == "expired":
        principal = replace(
            principal, assertion=replace(principal.assertion, expires_at=time.time() - 1)
        )
    elif fault == "wrong_session":
        principal = await bind(capture.data, capture.workspace, str(uuid4()))
    elif fault == "closed":
        rows = [
            dict(r)
            for r in capture.store.read("SELECT * FROM product_attempt_events ORDER BY attempt_seq")
        ]
        key = run.owner.journal.captures._key(principal)
        history = run.owner.journal._history(principal, key, rows)
        spec = start(**history[0].command.model_dump())
        await run.owner.journal.transition(principal, transition(spec, "mark_incomplete"))
    else:
        await asyncio.to_thread(
            capture.store.submit(lambda c: c.execute("DELETE FROM product_attempt_capacity")).result
        )
    with pytest.raises((ValueError, LedgerAppendFailure)):
        await run.run(principal, op)
    assert engine.starts() == 0 and not list(run.markers.root.glob("*.denied"))


async def test_repeated_cancel_drains_delayed_dispatch(capture: Fixture, engine: Engine) -> None:
    run, op = await prepared(capture, engine)
    engine.pause_start = threading.Event()
    task = asyncio.create_task(run.run(capture.principal, op))
    assert await asyncio.to_thread(engine.start_entered.wait, 2)
    task.cancel()
    await asyncio.sleep(0.02)
    task.cancel()
    engine.pause_start.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert run.last_report is not None and run.last_report.resource_state in {"stopped", "absent"}
    assert engine.starts() == 1
    assert run.recover(op).resource_state == "absent"


async def test_erasure_during_start_then_host_cleanup(capture: Fixture, engine: Engine) -> None:
    run, op = await prepared(capture, engine)
    engine.pause_start = threading.Event()
    task = asyncio.create_task(run.run(capture.principal, op))
    assert await asyncio.to_thread(engine.start_entered.wait, 2)
    capture.keys.shred_session_key(capture.principal.session_hmac, "active_test")
    engine.pause_start.set()
    report = await task
    assert report.resource_state == "absent" and engine.starts() == 1
    assert not capture.keys.has_session_key(capture.principal.session_hmac)


async def test_audit_failure_does_not_prevent_owned_discard(
    capture: Fixture, engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    run, op = await prepared(capture, engine)
    engine.drop_start = True
    original = run._append

    def fail(operation: str, phase: Any, **kwargs: Any) -> LaunchEvent:
        raise OSError("audit_unavailable")

    monkeypatch.setattr(run, "_append", fail)
    report = await run.run(capture.principal, op)
    assert report.resource_state == "absent" and report.audit_failed and report.execution_failed
    assert run.read(op)[-1].phase == "claim" and engine.starts() == 1
    monkeypatch.setattr(run, "_append", original)
    assert run.recover(op).resource_state == "absent"


@pytest.mark.parametrize(
    "fault", ["layer", "oom_supported", "memory_unsupported", "oom_numeric", "command"]
)
async def test_fixture_and_capability_refusals(
    capture: Fixture, engine: Engine, fault: str
) -> None:
    run, op = await prepared(capture, engine)
    if fault == "layer":
        engine.image_layer = "f" * 64
    elif fault == "oom_supported":
        engine.changed = {"OomKillDisable": True}
    elif fault == "memory_unsupported":
        engine.changed = {"MemoryLimit": False}
    elif fault == "oom_numeric":
        engine.changed = {"OomKillDisable": 0}
    else:
        next(iter(engine.resources.values()))["Args"] = ["other"]
    with pytest.raises(ResourceError):
        await run.run(capture.principal, op)
    assert engine.starts() == 0 and not list(run.markers.root.glob("*.denied"))


@pytest.mark.parametrize(
    "fault", ["partial", "malformed", "symlink", "capacity", "fsync", "root_mode"]
)
def test_marker_denial(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    root = tmp_path / "keys"
    root.mkdir(mode=0o700)
    markers = LaunchMarkers(root, ExecutionPolicy(max_histories=1))
    op = "a" * 64
    target = markers.root / (op + ".denied")
    if fault == "partial":
        target.touch()
    elif fault == "malformed":
        target.write_bytes(b"bad")
    elif fault == "symlink":
        target.symlink_to(root / "missing")
    elif fault == "capacity":
        (markers.root / ("b" * 64 + ".denied")).touch()
    elif fault == "root_mode":
        markers.root.chmod(0o755)
    else:

        def fail(fd: int) -> None:
            raise OSError("fsync_failed")

        monkeypatch.setattr(os, "fsync", fail)
    with pytest.raises((ResourceError, OSError)):
        markers.publish(op)
    if fault == "fsync":
        assert target.exists()


async def test_projection_no_other_normalization(capture: Fixture, engine: Engine) -> None:
    run, _op = await prepared(capture, engine)
    item = next(iter(engine.resources.values()))
    original = copy.deepcopy(item)
    before = run.control.projection(item, original=True)
    item["HostConfig"]["OomKillDisable"] = None
    assert run.control.projection(item) == before
    item["HostConfig"]["Privileged"] = 0
    assert json.dumps(run.control.projection(item), sort_keys=True) != json.dumps(
        before, sort_keys=True
    )
    assert original["HostConfig"]["OomKillDisable"] is False


async def test_engine_404_is_not_a_resource_absence_receipt(
    capture: Fixture, engine: Engine
) -> None:
    run, op = await prepared(capture, engine)
    assert (await run.run(capture.principal, op)).resource_state == "stopped"
    engine.info_status = 404
    assert run.recover(op).resource_state == "uncertain" and engine.resources
    assert run.read(op)[-1].phase != "discarded"
    assert not any(m == "DELETE" for m, p in engine.calls)


async def test_stopped_owner_engine_404_preserves_binding(capture: Fixture, engine: Engine) -> None:
    run, op = await prepared(capture, engine)
    engine.info_status = 404
    with pytest.raises(ResourceError):
        run.owner.remove(op)
    assert run.owner.read(op)[-1].phase == "bound" and engine.resources


@pytest.mark.parametrize(
    "field,value",
    [("Pid", 1), ("Pid", False), ("FinishedAt", "0001-01-01T00:00:00Z"), ("FinishedAt", None)],
)
async def test_malformed_exit_is_not_stopped(
    capture: Fixture, engine: Engine, field: str, value: Any
) -> None:
    run, op = await prepared(capture, engine)
    assert (await run.run(capture.principal, op)).resource_state == "stopped"
    next(iter(engine.resources.values()))["State"][field] = value
    assert run.recover(op).resource_state == "uncertain" and engine.resources


async def test_owner_process_death_leaves_claim_and_recovery_discards(
    capture: Fixture, engine: Engine
) -> None:
    run, op = await prepared(capture, engine)
    child = (Path(__file__).parents[1] / "fixtures/launch_owner.py").read_text()
    data = {
        "principal": asdict(capture.principal),
        "db": str(capture.workspace.parent / "ledger.db"),
        "keys": str(capture.keys.root),
        "profile": str(Path(__file__).parents[1] / "fixtures/seccomp-v27.3.1.json"),
        "socket": str(engine.path),
        "operation": str(op),
    }
    result = await asyncio.to_thread(
        subprocess.run,
        [sys.executable, "-c", child],
        input=json.dumps(data),
        text=True,
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert result.returncode == 17, result.stderr
    assert engine.starts() == 1 and next(iter(engine.resources.values()))["State"]["Running"]
    assert run.read(op)[-1].phase == "claim"
    assert run.recover(op).resource_state == "absent"
    with pytest.raises(ResourceError):
        await run.run(capture.principal, op)
    assert engine.starts() == 1


@pytest.mark.parametrize("change", [{"max_histories": 100}, {"fixture_argv": ("/bin/sh", "other")}])
async def test_policy_revalidated_before_admission(
    capture: Fixture, engine: Engine, change: dict[str, Any]
) -> None:
    run, _op = await prepared(capture, engine)
    policy = ExecutionPolicy.model_construct(**(run.policy.model_dump() | change))
    with pytest.raises(ValueError):
        IsolatedExecution(run.owner, policy)
    assert engine.starts() == 0


def test_marker_policy_revalidated_before_filesystem_mutation(tmp_path: Path) -> None:
    root = tmp_path / "keys"
    root.mkdir(mode=0o700)
    policy = ExecutionPolicy.model_construct(marker_directory="../outside")
    with pytest.raises(ValueError):
        LaunchMarkers(root, policy)
    assert not (tmp_path / "outside").exists()


async def test_issued_discard_is_not_reissued(
    capture: Fixture, engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    run, op = await prepared(capture, engine)
    engine.drop_start = True
    calls = []

    def uncertain(identity: str) -> None:
        calls.append(identity)
        raise ResourceError("discard_uncertain")

    monkeypatch.setattr(run.control, "discard", uncertain)
    assert (await run.run(capture.principal, op)).resource_state == "uncertain"
    assert run.read(op)[-1].phase == "discard_issued"
    assert run.recover(op).resource_state == "uncertain"
    assert len(calls) == 1 and engine.starts() == 1 and engine.resources


async def test_competing_recovery_cannot_send_second_discard(
    capture: Fixture, engine: Engine
) -> None:
    run, op = await prepared(capture, engine)
    assert (await run.run(capture.principal, op)).resource_state == "stopped"
    with run.markers.recovery(run.owner._operation(op)):
        other = IsolatedExecution(run.owner, run.policy)
        assert (await asyncio.to_thread(other.recover, op)).resource_state == "uncertain"
    assert engine.resources and not any(m == "DELETE" for m, p in engine.calls)
    assert run.recover(op).resource_state == "absent"


def test_engine_fixture_halts_after_unreceipted_create(
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
    control, _image = next(context)

    def missing(*args: Any, **kwargs: Any) -> Any:
        raise ResourceError("synthetic_no_receipt")

    monkeypatch.setattr(control, "_request", missing)
    with pytest.raises(ResourceError):
        control.create("specific-test-intent", {"Image": IMAGE})
    with pytest.raises(pytest.exit.Exception):
        next(context)
    events = [json.loads(line) for line in log.read_text().splitlines()]
    assert [e["event"] for e in events] == ["create_issued", "create_uncertain"]
    assert events[-1]["safe_code"] == "synthetic_no_receipt" and events[0]["at"]
    assert engine.starts() == 0
