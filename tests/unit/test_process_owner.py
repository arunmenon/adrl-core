"""Real synthetic process fixtures for ADRL-OPS-001's limited cleanup boundary."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import signal
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from pydantic import ValidationError

from adrl.core import process_anchor, process_owner
from adrl.core.process_owner import ProcessError, ProcessOwner, ProcessPolicy, ProcessSpec

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX owned-group backend")
PYTHON = str(Path(sys.executable).resolve())
PYTHON_HASH = hashlib.sha256(Path(PYTHON).read_bytes()).hexdigest()


def spec(root: Path, code: str, **kwargs: object) -> ProcessSpec:
    return ProcessSpec.model_validate(
        {
            "argv": (PYTHON, "-c", code),
            "cwd": root,
            "executable_sha256": PYTHON_HASH,
            **kwargs,
        }
    )


def owner(**kwargs: object) -> ProcessOwner:
    return ProcessOwner(
        b"r" * 32,
        ProcessPolicy.model_validate(
            {
                "runtime_seconds": 2,
                "launch_seconds": 3,
                "reap_seconds": 2,
                **kwargs,
            }
        ),
    )


async def exists(path: Path) -> None:
    for _ in range(150):
        if await asyncio.to_thread(path.exists):
            return
        await asyncio.sleep(0.02)
    pytest.fail("fixture readiness deadline exceeded")


@pytest.mark.parametrize("exitcode", [0, 7])
async def test_exit_is_observed_not_verified(tmp_path: Path, exitcode: int) -> None:
    run = owner()
    report = await run.run(spec(tmp_path, f"raise SystemExit({exitcode})"))
    assert report.outcome == "exited"
    assert report.direct_child_returncode == exitcode
    assert report.group_signal == "sent" and report.anchor_reaped
    assert report.containment == "process_group_only"
    assert not report.exact_close_eligible and not report.eligible_for_learning
    assert (
        report.runner_sha256
        == hashlib.sha256(
            await asyncio.to_thread(Path(process_owner.__file__).read_bytes)
        ).hexdigest()
    )
    assert report.anchor_sha256 == hashlib.sha256(process_owner.ANCHOR.read_bytes()).hexdigest()
    assert report == run.last_report


async def test_same_group_descendant_is_stopped_after_leader_exit(tmp_path: Path) -> None:
    descendant = "import time; from pathlib import Path; time.sleep(.6); Path('late').touch()"
    command = f"import subprocess,sys; subprocess.Popen([sys.executable,'-c',{descendant!r}])"
    report = await owner().run(spec(tmp_path, command))
    assert report.outcome == "exited" and report.anchor_reaped
    await asyncio.sleep(0.8)
    assert not (tmp_path / "late").exists()


async def test_timeout_forces_cleanup_of_signal_ignoring_child(tmp_path: Path) -> None:
    command = (
        "import signal,time; from pathlib import Path; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); Path('ready').touch(); "
        "time.sleep(.7); Path('late').touch()"
    )
    report = await owner(runtime_seconds=0.2).run(spec(tmp_path, command))
    assert report.outcome == "timed_out" and report.anchor_reaped
    assert report.group_signal == "sent" and report.direct_child_returncode is None
    assert (tmp_path / "ready").exists()
    await asyncio.sleep(0.7)
    assert not (tmp_path / "late").exists()


async def test_explicit_stop_cleans_before_return(tmp_path: Path) -> None:
    stop = threading.Event()
    command = "from pathlib import Path; import time; Path('ready').touch(); time.sleep(3)"
    task = asyncio.create_task(owner().run(spec(tmp_path, command), stop=stop))
    await exists(tmp_path / "ready")
    stop.set()
    report = await task
    assert report.outcome == "stopped" and report.anchor_reaped


async def test_coroutine_cancellation_waits_for_cleanup(tmp_path: Path) -> None:
    run = owner()
    command = (
        "from pathlib import Path; import time; Path('ready').touch(); "
        "time.sleep(.6); Path('late').touch()"
    )
    task = asyncio.create_task(run.run(spec(tmp_path, command)))
    await exists(tmp_path / "ready")
    task.cancel()
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert run.last_report is not None and run.last_report.anchor_reaped
    assert run.last_report.outcome == "stopped"
    await asyncio.sleep(0.7)
    assert not (tmp_path / "late").exists()
    assert (await run.run(spec(tmp_path, "pass"))).outcome == "exited"


async def test_presignalled_stop_does_not_launch(tmp_path: Path) -> None:
    stop = threading.Event()
    stop.set()
    report = await owner().run(
        spec(tmp_path, "from pathlib import Path; Path('bad').touch()"), stop=stop
    )
    assert report.outcome == "stopped" and report.group_signal == "not_launched"
    assert not (tmp_path / "bad").exists()


async def test_environment_is_explicit_and_report_has_no_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    canary = "private-parent-environment-canary"
    monkeypatch.setenv("ADRL_TEST_PARENT_SECRET", canary)
    command = (
        "import os,json; from pathlib import Path; "
        "Path('env.json').write_text(json.dumps(dict(os.environ)))"
    )
    run = owner()
    report = await run.run(spec(tmp_path, command, environment={"EXPLICIT": "allowed"}))
    env = json.loads((tmp_path / "env.json").read_text())
    assert "ADRL_TEST_PARENT_SECRET" not in env and env["EXPLICIT"] == "allowed"
    assert env["PATH"] == "/usr/bin:/bin" and "HOME" not in env
    encoded = report.model_dump_json()
    assert canary not in encoded and command not in encoded and str(tmp_path) not in encoded
    assert report.request_ref.startswith("hmac:")
    changed = await run.run(spec(tmp_path, "pass"))
    assert changed.request_ref != report.request_ref


async def test_detached_writer_demonstrates_scope_limit(tmp_path: Path) -> None:
    # This deliberately escaped fixture terminates itself after its one bounded write.
    child = "import time; from pathlib import Path; time.sleep(.3); Path('detached').touch()"
    command = (
        f"import subprocess,sys; subprocess.Popen([sys.executable,'-c',{child!r}],"
        "start_new_session=True)"
    )
    report = await owner().run(spec(tmp_path, command))
    assert report.anchor_reaped and report.outcome == "exited"
    await exists(tmp_path / "detached")
    assert report.containment == "process_group_only" and not report.exact_close_eligible


async def test_concurrent_use_rejected_then_owner_reusable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run, stop = owner(), threading.Event()
    signals: list[int] = []
    killpg = os.killpg

    def signal_owned(pid: int, sig: int) -> None:
        signals.append(pid)
        killpg(pid, sig)

    monkeypatch.setattr(process_owner.os, "killpg", signal_owned)
    task = asyncio.create_task(
        run.run(
            spec(
                tmp_path,
                "import time; from pathlib import Path; Path('ready').touch(); time.sleep(3)",
            ),
            stop=stop,
        )
    )
    await exists(tmp_path / "ready")
    with pytest.raises(ProcessError, match="already_active"):
        await run.run(spec(tmp_path, "pass"))
    stop.set()
    first = await task
    second = await run.run(spec(tmp_path, "pass"))
    assert first.run_id != second.run_id
    assert len(signals) == 2 and len(set(signals)) == 2
    assert second.anchor_reaped


@pytest.mark.parametrize(
    "change,error",
    [
        ({"executable_sha256": "0" * 64}, "pin_mismatch"),
        ({"argv": ("/nonexistent/adrl-fixture-command",)}, "invalid_launch_input"),
    ],
)
async def test_invalid_executable_rejected(
    tmp_path: Path, change: dict[str, object], error: str
) -> None:
    with pytest.raises(ProcessError, match=error):
        await owner().run(spec(tmp_path, "from pathlib import Path; Path('bad').touch()", **change))
    assert not (tmp_path / "bad").exists()


async def test_executable_pin_rechecked_in_anchor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "command"
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o700)
    run = owner()
    original_send = run._send

    def change_before_send(fd: int, payload: bytes, stop: threading.Event, deadline: float) -> None:
        executable.write_text("#!/bin/sh\ntouch bad\n")
        original_send(fd, payload, stop, deadline)

    monkeypatch.setattr(run, "_send", change_before_send)
    report = await run.run(
        ProcessSpec(
            argv=(str(executable),),
            cwd=tmp_path,
            executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
        )
    )
    assert report.outcome == "launch_failed" and report.anchor_reaped
    assert not (tmp_path / "bad").exists()


async def test_invalid_workspace_and_size_rejected(tmp_path: Path) -> None:
    link = tmp_path / "link"
    link.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ProcessError, match="invalid_workspace"):
        await owner().run(spec(link, "pass"))
    with pytest.raises(ProcessError, match="too_large"):
        await owner(max_launch_bytes=100).run(spec(tmp_path, "pass"))


@pytest.mark.parametrize(
    "change",
    [
        {"argv": ("relative",)},
        {"argv": (PYTHON, "nul\0")},
        {"environment": {"": "empty"}},
        {"environment": {"a=b": "bad"}},
        {"environment": {"a": "bad\0"}},
        {"cwd": Path("relative")},
    ],
)
def test_invalid_spec(change: dict[str, object], tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        spec(tmp_path, "pass", **change)


@pytest.mark.parametrize(
    "change",
    [
        {"runtime_seconds": 61},
        {"launch_seconds": 11},
        {"reap_seconds": 6},
        {"max_launch_bytes": 8193},
        {"runtime_seconds": float("nan")},
    ],
)
def test_policy_cannot_widen_packet(change: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        owner(**change)


async def test_custom_child_reaper_is_rejected(tmp_path: Path) -> None:
    old = signal.signal(signal.SIGCHLD, signal.SIG_IGN)
    try:
        with pytest.raises(ProcessError, match="unsupported_child_ownership"):
            await owner().run(spec(tmp_path, "pass"))
    finally:
        signal.signal(signal.SIGCHLD, old)


@pytest.mark.parametrize("frame", [b"{bad}\n", b"x" * 300, b'{"phase":"exited","returncode":0}\n'])
async def test_failed_protocol_cleans_owned_launcher(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, frame: bytes
) -> None:
    fake = tmp_path / "protocol_fixture.py"
    fake.write_text(f"import os,sys,time\nos.write(int(sys.argv[2]),{frame!r})\ntime.sleep(2)\n")
    monkeypatch.setattr(process_owner, "ANCHOR", fake)
    report = await owner().run(spec(tmp_path, "pass"))
    assert report.outcome == "monitor_failed" and report.anchor_reaped
    assert report.group_signal == "sent" and not report.exact_close_eligible


async def test_launcher_handshake_timeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = tmp_path / "silent_fixture.py"
    fake.write_text("import time\ntime.sleep(2)\n")
    monkeypatch.setattr(process_owner, "ANCHOR", fake)
    report = await owner(launch_seconds=0.1).run(spec(tmp_path, "pass"))
    assert report.outcome == "timed_out" and report.anchor_reaped


async def test_owner_death_closes_private_pipe_and_stops_workload(tmp_path: Path) -> None:
    workload = (
        "from pathlib import Path; import time; Path('ready').touch(); "
        "time.sleep(.7); Path('late').touch()"
    )
    script = (
        "import asyncio\nfrom pathlib import Path\n"
        "from adrl.core.process_owner import ProcessOwner,ProcessSpec,ProcessPolicy\n"
        f"s=ProcessSpec(argv=({PYTHON!r},'-c',{workload!r}),cwd=Path({str(tmp_path)!r}),executable_sha256={PYTHON_HASH!r})\n"
        "asyncio.run(ProcessOwner(b'r'*32,ProcessPolicy(runtime_seconds=2)).run(s))\n"
    )
    parent = await asyncio.to_thread(
        subprocess.Popen,
        [sys.executable, "-c", script],
        env=process_owner.MINIMAL_ENV,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        await exists(tmp_path / "ready")
        parent.kill()  # The exact Popen child owned by this fixture, not a restored PID.
        await asyncio.to_thread(parent.wait, timeout=3)
        await asyncio.sleep(0.9)
        assert not (tmp_path / "late").exists()
    finally:
        if parent.poll() is None:
            parent.kill()
            await asyncio.to_thread(parent.wait, timeout=3)


async def test_anchor_watchdog_works_while_owner_pipe_stays_open(tmp_path: Path) -> None:
    control_read, control_write = os.pipe()
    status_read, status_write = os.pipe()
    anchor = await asyncio.to_thread(
        subprocess.Popen,
        [
            sys.executable,
            "-I",
            "-B",
            str(process_owner.ANCHOR),
            str(control_read),
            str(status_write),
        ],
        env=process_owner.MINIMAL_ENV,
        start_new_session=True,
        close_fds=True,
        pass_fds=(control_read, status_write),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    os.close(control_read)
    os.close(status_write)
    try:
        value = {
            "version": process_anchor.WIRE_VERSION,
            "argv": [
                PYTHON,
                "-c",
                "from pathlib import Path; import time; Path('ready').touch(); "
                "time.sleep(.7); Path('late').touch()",
            ],
            "cwd": str(tmp_path),
            "env": process_owner.MINIMAL_ENV,
            "executable_sha256": PYTHON_HASH,
            "watchdog": 0.2,
        }
        os.write(control_write, json.dumps(value).encode() + b"\n")
        await exists(tmp_path / "ready")
        assert await asyncio.to_thread(anchor.wait, timeout=2) == -signal.SIGKILL
        await asyncio.sleep(0.8)
        assert not (tmp_path / "late").exists()
    finally:
        os.close(control_write)
        os.close(status_read)
        # No group signal after wait has released its identity. EOF/watchdog own cleanup.
        if anchor.poll() is None:
            await asyncio.to_thread(anchor.wait, timeout=3)


async def test_mutated_nested_input_rejected_without_wedging_owner(tmp_path: Path) -> None:
    run, request = owner(), spec(tmp_path, "pass")
    request.environment["bad=key"] = "value"
    with pytest.raises(ValidationError):
        await run.run(request)
    assert (await run.run(spec(tmp_path, "pass"))).anchor_reaped


def test_no_api_to_restore_pid_authority() -> None:
    assert not any(
        hasattr(ProcessOwner, method) for method in ("attach", "restore", "kill", "signal")
    )
    with pytest.raises(ProcessError, match="too_short"):
        ProcessOwner(b"short")


async def test_failed_group_signal_uses_eof_and_poisoned_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def denied(pid: int, sig: int) -> None:
        raise PermissionError("synthetic signal failure")

    monkeypatch.setattr(process_owner.os, "killpg", denied)
    run = owner()
    report = await run.run(spec(tmp_path, "pass"))
    assert report.outcome == "exited" and report.group_signal == "failed"
    assert report.anchor_reaped and not report.exact_close_eligible
    with pytest.raises(ProcessError, match="cleanup_unresolved"):
        await run.run(spec(tmp_path, "pass"))


async def test_reap_timeout_retains_handle_and_blocks_reuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = subprocess.Popen.wait

    def timeout_once(self: subprocess.Popen[bytes], timeout: float | None = None) -> int:
        raise subprocess.TimeoutExpired("owned-launcher", timeout or 0)

    run = owner()
    monkeypatch.setattr(subprocess.Popen, "wait", timeout_once)
    try:
        report = await run.run(spec(tmp_path, "pass"))
        assert report.group_signal == "sent" and not report.anchor_reaped
        with pytest.raises(ProcessError, match="cleanup_unresolved"):
            await run.run(spec(tmp_path, "pass"))
    finally:
        monkeypatch.setattr(subprocess.Popen, "wait", original)
        assert run._unreaped is not None
        # Test teardown only reaps the retained exact handle. It does not signal again.
        await asyncio.to_thread(run._unreaped.wait, timeout=3)


async def test_missing_anchor_reports_failure_without_workload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A readable launcher that cannot start exercises status EOF with an owned process.
    broken = tmp_path / "broken.py"
    broken.write_text("raise SystemExit(3)\n")
    monkeypatch.setattr(process_owner, "ANCHOR", broken)
    report = await owner().run(spec(tmp_path, "from pathlib import Path; Path('bad').touch()"))
    assert report.outcome == "monitor_failed" and report.anchor_reaped
    assert not (tmp_path / "bad").exists()


async def test_loop_shutdown_does_not_abandon_owned_worker(tmp_path: Path) -> None:
    # A separate event loop's shutdown cancels all Tasks, including its caller. The worker
    # Future must survive that cancellation until cleanup finishes.
    def separate_loop() -> None:
        async def main() -> None:
            command = (
                "from pathlib import Path; import time; Path('shutdown-ready').touch(); "
                "time.sleep(.6); Path('shutdown-late').touch()"
            )
            task = asyncio.create_task(owner().run(spec(tmp_path, command)))
            await exists(tmp_path / "shutdown-ready")
            assert not task.done()

        asyncio.run(main())

    await asyncio.to_thread(separate_loop)
    await asyncio.sleep(0.7)
    assert not (tmp_path / "shutdown-late").exists()
