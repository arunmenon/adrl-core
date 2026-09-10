"""Real coordination and partial-failure cases. Primary: ADRL-OPS-001, ADRL-MEM-010."""

from __future__ import annotations

import asyncio
import json
import sqlite3
import subprocess
import sys
import threading
import time
from dataclasses import asdict, replace
from typing import Any
from uuid import uuid4

import pytest
from pydantic import ValidationError

from adrl.api.store import ProductStore
from adrl.core.attempt_coordinator import (
    AttemptCoordinator,
    CoordinationPolicy,
    CoordinationReport,
)
from adrl.core.errors import LedgerAppendFailure
from adrl.core.ids import SessionId
from adrl.core.process_owner import ProcessPolicy
from adrl.ledger.attempts import AttemptError, AttemptJournal, LegacyAttemptPolicy
from adrl.ledger.capture import CaptureError
from adrl.ledger.erasure import ErasureService
from adrl.ledger.keystore import FileKeyStore, KeyStoreBusyError
from adrl.ledger.migrations import load_migrations
from adrl.ledger.store import LedgerStore

from .test_attempt_capacity import legacy_database
from .test_attempts import start, transition
from .test_capture import Fixture, bind
from .test_capture import capture as capture
from .test_process_owner import exists, spec

WAITING = "from pathlib import Path; import time; Path('ready').touch(); time.sleep(3)"
DENIAL = (AttemptError, CaptureError, LedgerAppendFailure)


def coordinator(capture: Fixture, **changes: Any) -> AttemptCoordinator:
    return AttemptCoordinator(
        AttemptJournal(capture.data),
        CoordinationPolicy.model_validate(
            {
                "poll_seconds": 0.01,
                "process": ProcessPolicy(runtime_seconds=2, launch_seconds=2, reap_seconds=2),
            }
            | changes
        ),
    )


def fences(capture: Fixture) -> list[dict[str, Any]]:
    return [dict(row) for row in capture.store.read("SELECT * FROM product_execution_fences")]


def blocked(report: CoordinationReport) -> None:
    assert report.workspace_state == "blocked"
    assert not report.exact_close_eligible and not report.eligible_for_learning
    if report.process:
        assert not report.process.exact_close_eligible and not report.process.eligible_for_learning


@pytest.mark.parametrize("code", [0, 7])
async def test_exit_terminal_record_and_restart_never_release(capture: Fixture, code: int) -> None:
    run, request = coordinator(capture), start()
    await run.journal.start(capture.principal, capture.workspace, request)
    report = await run.run(
        capture.principal, request.attempt_id, spec(capture.workspace, f"raise SystemExit({code})")
    )
    blocked(report)
    assert report.process and report.process.direct_child_returncode == code
    assert report.terminal_record == "recorded" and not report.process_error
    assert run.journal.read(capture.principal, request.attempt_id)[-1].phase == "incomplete"
    original = fences(capture)
    capture.store.close()
    capture.store.open()
    other = await bind(capture.data, capture.workspace, str(uuid4()))
    with pytest.raises(DENIAL, match="workspace_execution_blocked"):
        await AttemptJournal(capture.data).start(other, capture.workspace, start())
    with pytest.raises(DENIAL, match="workspace_execution_blocked"):
        await coordinator(capture).run(
            capture.principal, request.attempt_id, spec(capture.workspace, "pass")
        )
    assert fences(capture) == original and not capture.store.read("SELECT * FROM product_captures")


@pytest.mark.parametrize("trigger", ["direct", "service", "failed_audit", "expired", "key_missing"])
async def test_revocation_expiry_and_missing_authority_stop_owned_process(
    capture: Fixture, monkeypatch: pytest.MonkeyPatch, trigger: str
) -> None:
    run, request = coordinator(capture), start()
    principal = capture.principal
    if trigger == "expired":
        principal = replace(
            principal, assertion=replace(principal.assertion, expires_at=time.time() + 0.6)
        )
    await run.journal.start(principal, capture.workspace, request)
    task = asyncio.create_task(
        run.run(principal, request.attempt_id, spec(capture.workspace, WAITING))
    )
    await exists(capture.workspace / "ready")
    if trigger in {"direct", "failed_audit"}:
        if trigger == "failed_audit":

            def fail(*args: Any, **kwargs: Any) -> None:
                raise OSError("audit unavailable")

            monkeypatch.setattr(capture.keys, "_audit", fail)
        try:
            for attempt in range(3):
                try:
                    await asyncio.to_thread(
                        capture.keys.shred_session_key, principal.session_hmac, "fixture"
                    )
                    break
                except KeyStoreBusyError:
                    if attempt == 2:
                        raise
                    await asyncio.sleep(0.02)
        except OSError:
            assert trigger == "failed_audit"
    elif trigger == "service":
        for attempt in range(3):
            try:
                await ErasureService(capture.store, capture.keys).erase_session(
                    SessionId(principal.session_hmac), "fixture"
                )
                break
            except KeyStoreBusyError:
                if attempt == 2:
                    raise
                await asyncio.sleep(0.02)
    elif trigger == "key_missing":
        (capture.keys.root / "sessions" / (principal.session_hmac + ".key")).unlink()
    report = await asyncio.wait_for(task, 4)
    blocked(report)
    assert report.process and report.process.outcome == "stopped" and report.process.anchor_reaped
    assert report.terminal_record == "unavailable" and len(fences(capture)) == 1
    expected = (
        "expired"
        if trigger == "expired"
        else ("authority_unavailable" if trigger == "key_missing" else "revoked")
    )
    # A monitor can encounter the shredder's exclusive key lock before it observes the
    # published marker. That earlier authority loss is an honest, conservative stop cause.
    assert report.stop_cause in {expected, "authority_unavailable"}
    if trigger in {"direct", "service", "failed_audit"}:
        assert capture.keys.is_revoked(principal.session_hmac)


@pytest.mark.parametrize("kind", ["request_close", "cancel", "mark_incomplete"])
async def test_journal_transition_stops_but_cannot_release(capture: Fixture, kind: str) -> None:
    run, request = coordinator(capture), start()
    await run.journal.start(capture.principal, capture.workspace, request)
    other = await bind(capture.data, capture.workspace, str(uuid4()))
    task = asyncio.create_task(
        run.run(capture.principal, request.attempt_id, spec(capture.workspace, WAITING))
    )
    await exists(capture.workspace / "ready")
    await run.journal.transition(capture.principal, transition(request, kind))
    with pytest.raises(DENIAL, match="workspace_execution_blocked"):
        await run.journal.start(other, capture.workspace, start())
    report = await task
    blocked(report)
    assert report.stop_cause == "journal_closed"
    assert report.process and report.process.outcome == "stopped"
    assert report.terminal_record == ("recorded" if kind == "request_close" else "already_terminal")


@pytest.mark.parametrize("mode", ["cancel", "repeated", "explicit"])
async def test_cancellation_drains_process_and_retains_fence(capture: Fixture, mode: str) -> None:
    run, request, stop = coordinator(capture), start(), threading.Event()
    await run.journal.start(capture.principal, capture.workspace, request)
    task = asyncio.create_task(
        run.run(capture.principal, request.attempt_id, spec(capture.workspace, WAITING), stop=stop)
    )
    await exists(capture.workspace / "ready")
    if mode == "explicit":
        stop.set()
        await task
    else:
        task.cancel()
        if mode == "repeated":
            for _ in range(4):
                await asyncio.sleep(0)
                task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    report = run.last_report
    assert report is not None and report.process and report.process.anchor_reaped
    assert report.stop_cause == "requested" and report.terminal_record == "recorded"
    blocked(report)
    assert len(fences(capture)) == 1


async def test_timeout_and_bad_pin_keep_block(capture: Fixture) -> None:
    run, request = coordinator(capture, process=ProcessPolicy(runtime_seconds=0.1)), start()
    await run.journal.start(capture.principal, capture.workspace, request)
    report = await run.run(capture.principal, request.attempt_id, spec(capture.workspace, WAITING))
    assert report.process and report.process.outcome == "timed_out"
    blocked(report)
    other = await bind(capture.data, capture.scratch, str(uuid4()))
    second = start()
    await run.journal.start(other, capture.scratch, second)
    bad = await run.run(
        other, second.attempt_id, spec(capture.scratch, "pass", executable_sha256="0" * 64)
    )
    assert bad.process_error and bad.process is None and bad.terminal_record == "recorded"
    blocked(bad)
    assert len(fences(capture)) == 2


@pytest.mark.parametrize("fault", ["fence_insert", "terminal_insert", "corrupt_journal"])
async def test_database_faults_do_not_forge_completion(capture: Fixture, fault: str) -> None:
    run, request = coordinator(capture), start()
    await run.journal.start(capture.principal, capture.workspace, request)
    if fault == "fence_insert":
        await capture.store.write_through(
            lambda conn: conn.execute(
                "CREATE TRIGGER fail_fence BEFORE INSERT ON product_execution_fences "
                "BEGIN SELECT RAISE(ABORT,'fixture fence failure'); END;"
            )
        )
        with pytest.raises(LedgerAppendFailure, match="fixture fence failure"):
            await run.run(capture.principal, request.attempt_id, spec(capture.workspace, WAITING))
        assert not fences(capture) and not (capture.workspace / "ready").exists()
        return
    task = asyncio.create_task(
        run.run(capture.principal, request.attempt_id, spec(capture.workspace, WAITING))
    )
    await exists(capture.workspace / "ready")
    if fault == "terminal_insert":
        await capture.store.write_through(
            lambda conn: conn.execute(
                "CREATE TRIGGER fail_terminal BEFORE INSERT ON product_attempt_events "
                "BEGIN SELECT RAISE(ABORT,'fixture terminal failure'); END;"
            )
        )
    else:
        await capture.store.write_through(
            lambda conn: conn.execute("UPDATE product_attempt_events SET ciphertext=x'00'")
        )
    report = await task
    blocked(report)
    assert report.terminal_record == "unavailable" and len(fences(capture)) == 1
    if fault == "corrupt_journal":
        assert report.stop_cause == "authority_unavailable"
        assert report.process and report.process.outcome == "stopped"


@pytest.mark.parametrize(
    "fault", ["wrong_workspace", "other_session", "closed", "grant", "expired"]
)
async def test_invalid_admission_never_launches(capture: Fixture, fault: str) -> None:
    run, request = coordinator(capture), start()
    await run.journal.start(capture.principal, capture.workspace, request)
    principal, root = capture.principal, capture.workspace
    if fault == "wrong_workspace":
        root = capture.scratch
    elif fault == "other_session":
        principal = await bind(capture.data, root, str(uuid4()))
    elif fault == "closed":
        await run.journal.transition(principal, transition(request, "cancel"))
    elif fault == "grant":
        await capture.store.write_through(
            lambda conn: conn.execute("UPDATE product_attempt_capacity SET reserved_bytes=2048")
        )
    else:
        principal = replace(principal, assertion=replace(principal.assertion, expires_at=0))
    with pytest.raises(DENIAL):
        await run.run(principal, request.attempt_id, spec(root, WAITING))
    assert not fences(capture) and not (root / "ready").exists()


async def test_simultaneous_coordinators_and_instance_reentry(capture: Fixture) -> None:
    run, request = coordinator(capture), start()
    await run.journal.start(capture.principal, capture.workspace, request)
    command = spec(capture.workspace, WAITING)
    first = asyncio.create_task(run.run(capture.principal, request.attempt_id, command))
    await exists(capture.workspace / "ready")
    with pytest.raises(AttemptError, match="coordinator_already_active"):
        await run.run(capture.principal, request.attempt_id, command)
    with pytest.raises(DENIAL, match="workspace_execution_blocked"):
        await coordinator(capture).run(capture.principal, request.attempt_id, command)
    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first
    assert len(fences(capture)) == 1


async def test_lost_admission_ack_never_replays(
    capture: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    run, request = coordinator(capture), start()
    await run.journal.start(capture.principal, capture.workspace, request)
    original = run._admit

    def lose(*args: Any, **kwargs: Any) -> None:
        original(*args, **kwargs)
        raise TimeoutError("lost acknowledgement")

    monkeypatch.setattr(run, "_admit", lose)
    with pytest.raises(TimeoutError):
        await run.run(capture.principal, request.attempt_id, spec(capture.workspace, WAITING))
    assert len(fences(capture)) == 1 and not (capture.workspace / "ready").exists()
    with pytest.raises(DENIAL, match="workspace_execution_blocked"):
        await coordinator(capture).run(
            capture.principal, request.attempt_id, spec(capture.workspace, WAITING)
        )


async def test_fence_metadata_limits_and_key_rotation(
    capture: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    run, request = coordinator(capture, max_workspace_fences=1), start()
    await run.journal.start(capture.principal, capture.workspace, request)
    await run.run(capture.principal, request.attempt_id, spec(capture.workspace, "pass"))
    row = fences(capture)[0]
    for private in [str(capture.workspace), str(request.attempt_id), "code.txt", "task-one"]:
        assert private not in json.dumps(row)
    assert CoordinationPolicy.model_validate_json(row["policy_json"]) == run.policy
    other, second = await bind(capture.data, capture.scratch, str(uuid4())), start()
    await run.journal.start(other, capture.scratch, second)
    with pytest.raises(DENIAL, match="execution_fence_limit"):
        await run.run(other, second.attempt_id, spec(capture.scratch, "pass"))
    monkeypatch.setattr(capture.keys, "hmac_key_id", lambda: "different-host-key")
    with pytest.raises(DENIAL, match="execution_fence_key_changed"):
        await coordinator(capture).run(other, second.attempt_id, spec(capture.scratch, "pass"))
    await run.journal.transition(other, transition(second, "cancel"))
    with pytest.raises(DENIAL, match="execution_fence_key_changed"):
        await run.journal.start(other, capture.scratch, start())


async def test_legacy_attempt_is_readable_but_not_executable(capture: Fixture) -> None:
    policy = LegacyAttemptPolicy()
    path, request, event = await asyncio.to_thread(legacy_database, capture, policy)
    store = LedgerStore(path)
    store.open()
    try:
        journal = AttemptJournal(
            ProductStore(store, FileKeyStore(capture.keys.root, store=store)), policy
        )
        assert journal.read(capture.principal, request.attempt_id) == (event,)
        with pytest.raises(DENIAL, match="execution_requires_v2_attempt"):
            await AttemptCoordinator(journal).run(
                capture.principal, request.attempt_id, spec(capture.workspace, WAITING)
            )
        assert not store.read("SELECT * FROM product_execution_fences")
    finally:
        store.close()


async def test_schema_nine_migration_preserves_ciphertext_and_grant(capture: Fixture) -> None:
    run, request = coordinator(capture), start()
    expected = await run.journal.start(capture.principal, capture.workspace, request)
    path = capture.scratch / "v9.db"
    tables = ["product_sessions", "product_attempt_events", "product_attempt_capacity"]
    with sqlite3.connect(path) as conn:
        for migration in load_migrations():
            if migration.version <= 9:
                conn.executescript(migration.sql)
        for table in tables:
            for row in capture.store.read(f"SELECT * FROM {table}"):
                fields = dict(row)
                conn.execute(
                    f"INSERT INTO {table} ({','.join(fields)}) "
                    f"VALUES ({','.join('?' for _ in fields)})",
                    tuple(fields.values()),
                )
        conn.execute("PRAGMA user_version=9")
    store = LedgerStore(path)
    store.open()
    try:
        assert store.schema_user_version() == 12
        for table in tables:
            assert [dict(row) for row in store.read(f"SELECT * FROM {table}")] == [
                dict(row) for row in capture.store.read(f"SELECT * FROM {table}")
            ]
        data = ProductStore(store, FileKeyStore(capture.keys.root, store=store))
        assert AttemptJournal(data).read(capture.principal, request.attempt_id) == (expected,)
        assert not store.read("SELECT * FROM product_execution_fences")
    finally:
        store.close()


@pytest.mark.parametrize(
    "changes", [{"poll_seconds": 0}, {"poll_seconds": 2}, {"max_workspace_fences": 129}]
)
def test_policy_bounds(changes: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        CoordinationPolicy.model_validate(changes)


async def test_preexisting_stop_has_no_admission(capture: Fixture) -> None:
    run, request, stop = coordinator(capture), start(), threading.Event()
    await run.journal.start(capture.principal, capture.workspace, request)
    stop.set()
    with pytest.raises(DENIAL, match="execution_admission_stopped"):
        await run.run(
            capture.principal, request.attempt_id, spec(capture.workspace, WAITING), stop=stop
        )
    assert not fences(capture)


async def test_cancellation_after_commit_prevents_launch(
    capture: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    run, request = coordinator(capture), start()
    await run.journal.start(capture.principal, capture.workspace, request)
    admitted, proceed = threading.Event(), threading.Event()
    original = run._admit

    def pause(*args: Any, **kwargs: Any) -> None:
        original(*args, **kwargs)
        admitted.set()
        assert proceed.wait(3)

    monkeypatch.setattr(run, "_admit", pause)
    task = asyncio.create_task(
        run.run(capture.principal, request.attempt_id, spec(capture.workspace, WAITING))
    )
    try:
        assert await asyncio.to_thread(admitted.wait, 3)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done()
    finally:
        proceed.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert run.last_report and run.last_report.process
    assert run.last_report.process.group_signal == "not_launched"
    assert len(fences(capture)) == 1 and not (capture.workspace / "ready").exists()


async def test_racing_admissions_commit_only_one_fence(capture: Fixture) -> None:
    run, request = coordinator(capture), start()
    await run.journal.start(capture.principal, capture.workspace, request)
    results = await asyncio.gather(
        *(
            coordinator(capture).run(
                capture.principal, request.attempt_id, spec(capture.workspace, "pass")
            )
            for _ in range(2)
        ),
        return_exceptions=True,
    )
    assert sum(isinstance(result, CoordinationReport) for result in results) == 1
    assert sum(isinstance(result, LedgerAppendFailure) for result in results) == 1
    assert len(fences(capture)) == 1


async def test_cleanup_progresses_while_callers_erasure_audit_is_blocked(
    capture: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    run, request, terminal_done = coordinator(capture), start(), threading.Event()
    await run.journal.start(capture.principal, capture.workspace, request)
    terminal = run._terminal
    authority = run._authority
    pause, parked, observe = threading.Event(), threading.Event(), threading.Event()

    def observation(*args: Any, **kwargs: Any) -> Any:
        if pause.is_set():
            parked.set()
            assert observe.wait(3)
        return authority(*args, **kwargs)

    def record(*args: Any, **kwargs: Any) -> Any:
        result = terminal(*args, **kwargs)
        terminal_done.set()
        return result

    def audit(*args: Any, **kwargs: Any) -> None:
        observe.set()
        assert terminal_done.wait(2), "cleanup depended on blocked caller event loop"

    monkeypatch.setattr(run, "_terminal", record)
    monkeypatch.setattr(run, "_authority", observation)
    monkeypatch.setattr(capture.keys, "_audit", audit)
    task = asyncio.create_task(
        run.run(capture.principal, request.attempt_id, spec(capture.workspace, WAITING))
    )
    await exists(capture.workspace / "ready")
    # Park the observer without a key lock, then let it observe once the shredder has
    # entered its lock-free audit wait. This isolates the failure ordering under test.
    pause.set()
    try:
        assert await asyncio.to_thread(parked.wait, 2)
        capture.keys.shred_session_key(capture.principal.session_hmac, "fixture")
    finally:
        observe.set()
    report = await task
    assert report.stop_cause in {"revoked", "authority_unavailable"}
    assert report.terminal_record == "unavailable" and capture.keys.is_revoked(
        capture.principal.session_hmac
    )
    assert report.process and report.process.anchor_reaped


async def test_owner_death_keeps_durable_block_and_no_pid_recovery(capture: Fixture) -> None:
    run, request = coordinator(capture), start()
    await run.journal.start(capture.principal, capture.workspace, request)
    child = """
import asyncio, json, sys
from uuid import UUID
from pathlib import Path
from adrl.api.auth import Principal
from adrl.api.store import ProductStore
from adrl.gates.workload import RepoInventory, WorkloadAssertion
from adrl.ledger.store import LedgerStore
from adrl.ledger.keystore import FileKeyStore
from adrl.ledger.attempts import AttemptJournal
from adrl.core.attempt_coordinator import AttemptCoordinator
from adrl.core.process_owner import ProcessSpec
v=json.loads(sys.stdin.readline())
p=v['principal']; a=p.pop('assertion'); inv=a.pop('inventory')
principal=Principal(**p, assertion=WorkloadAssertion(**a, inventory=RepoInventory(**inv)))
store=LedgerStore(Path(v['database'])); store.open()
data=ProductStore(store, FileKeyStore(Path(v['keys']), store=store))
asyncio.run(AttemptCoordinator(AttemptJournal(data)).run(
 principal, UUID(v['attempt']), ProcessSpec.model_validate_json(v['spec'])))
store.close()
"""
    command = spec(
        capture.workspace,
        "from pathlib import Path; import time; Path('ready').touch(); "
        "time.sleep(.7); Path('late').touch()",
    )
    proc = await asyncio.to_thread(
        subprocess.Popen,
        [sys.executable, "-c", child],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    assert proc.stdin is not None
    try:
        proc.stdin.write(
            (
                json.dumps(
                    {
                        "principal": asdict(capture.principal),
                        "database": str(capture.keys.root.parent / "ledger.db"),
                        "keys": str(capture.keys.root),
                        "attempt": str(request.attempt_id),
                        "spec": command.model_dump_json(),
                    }
                )
                + "\n"
            ).encode()
        )
        proc.stdin.close()
        await exists(capture.workspace / "ready")
        proc.kill()
        await asyncio.to_thread(proc.wait, 3)
        await asyncio.sleep(0.9)
        assert not (capture.workspace / "late").exists()
        assert len(fences(capture)) == 1
        await run.journal.transition(capture.principal, transition(request, "cancel"))
        other = await bind(capture.data, capture.workspace, str(uuid4()))
        with pytest.raises(DENIAL, match="workspace_execution_blocked"):
            await run.journal.start(other, capture.workspace, start())
    finally:
        if proc.poll() is None:
            proc.kill()
            await asyncio.to_thread(proc.wait, 3)
