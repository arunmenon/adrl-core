"""Owned process-group execution and cleanup. Primary: ADRL-OPS-001.

Secondary: ADRL-SAF-007, ADRL-SEM-006, ADRL-MEM-003, ADRL-TRU-001.
Internal trusted-operator primitive. Every result is ineligible for exact task-close
attribution: detached and unrelated writers are outside this backend's scope.
"""

from __future__ import annotations

import asyncio
import contextvars
import hashlib
import hmac
import json
import os
import selectors
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from adrl.core import process_anchor

ANCHOR = Path(process_anchor.__file__).resolve()
MINIMAL_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C"}
Outcome = Literal["exited", "timed_out", "stopped", "launch_failed", "monitor_failed"]


class ProcessError(ValueError):
    """Admission failed; no workload was launched by this request."""


class ProcessPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    schema_version: Literal["owned-process-policy-v1"] = "owned-process-policy-v1"
    runtime_seconds: float = Field(default=30, ge=0.05, le=60)
    launch_seconds: float = Field(default=5, ge=0.05, le=10)
    reap_seconds: float = Field(default=2, ge=0.05, le=5)
    max_launch_bytes: int = Field(default=8192, ge=1, le=8192)


class ProcessSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    argv: tuple[str, ...] = Field(min_length=1, max_length=256, repr=False)
    cwd: Path = Field(repr=False)
    executable_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    environment: dict[str, str] = Field(default_factory=dict, repr=False)

    @model_validator(mode="after")
    def valid_inputs(self) -> ProcessSpec:
        if not Path(self.argv[0]).is_absolute() or not self.cwd.is_absolute():
            raise ValueError("absolute_paths_required")
        if any("\0" in arg for arg in self.argv) or "\0" in str(self.cwd):
            raise ValueError("invalid_argument")
        if any(
            not key or "=" in key or "\0" in key or "\0" in value
            for key, value in self.environment.items()
        ):
            raise ValueError("invalid_environment")
        return self


class ProcessReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["owned-process-report-v1"] = "owned-process-report-v1"
    run_id: UUID
    outcome: Outcome
    direct_child_returncode: int | None
    group_signal: Literal["not_launched", "sent", "absent", "failed"]
    anchor_reaped: bool
    containment: Literal["process_group_only"] = "process_group_only"
    exact_close_eligible: Literal[False] = False
    eligible_for_learning: Literal[False] = False
    policy: ProcessPolicy
    request_ref: str
    executable_sha256: str
    runner_sha256: str
    anchor_sha256: str
    elapsed_seconds: float


def _digest(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


class ProcessOwner:
    """One in-memory owner, no PID-based restore, attach or signal API.

    The embedding process must retain normal SIGCHLD handling and must not use a
    competing child reaper. A cleanup failure poisons this instance for further runs.
    """

    def __init__(self, reference_key: bytes, policy: ProcessPolicy | None = None) -> None:
        if len(reference_key) < 32:
            raise ProcessError("reference_key_too_short")
        self.policy = policy or ProcessPolicy()
        self._reference_key = bytes(reference_key)
        self._active = threading.Lock()
        self._unreaped: subprocess.Popen[bytes] | None = None
        self._poisoned = False
        self.last_report: ProcessReport | None = None

    async def run(self, spec: ProcessSpec, *, stop: threading.Event | None = None) -> ProcessReport:
        # Copy and revalidate mutable nested caller inputs before acquiring ownership.
        copied = ProcessSpec.model_validate(spec.model_dump())
        if not self._active.acquire(blocking=False):
            raise ProcessError("owner_already_active")
        stopping = stop if stop is not None else threading.Event()
        # An executor Future is not an independently cancellable asyncio Task. Loop shutdown
        # may cancel every Task; it must not mark our worker done while its thread still owns
        # the launcher. Shield the Future and drain it before releasing this instance.
        context = contextvars.copy_context()
        worker = asyncio.get_running_loop().run_in_executor(
            None, context.run, self._run, copied, stopping
        )
        try:
            try:
                return await asyncio.shield(worker)
            except asyncio.CancelledError:
                stopping.set()
                # Repeated cancellation cannot release this owner before its bounded cleanup.
                while not worker.done():
                    try:
                        await asyncio.shield(worker)
                    except asyncio.CancelledError:
                        stopping.set()
                    except Exception:
                        break
                # Retrieve exceptions to avoid abandoning a failed worker silently.
                if not worker.cancelled():
                    worker.exception()
                raise
        finally:
            self._active.release()

    def _prepare(self, spec: ProcessSpec) -> bytes:
        if os.name != "posix" or signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
            raise ProcessError("unsupported_child_ownership")
        if self._poisoned:
            raise ProcessError("owner_cleanup_unresolved")
        try:
            if spec.cwd.is_symlink() or not spec.cwd.is_dir():
                raise ProcessError("invalid_workspace")
            executable = Path(spec.argv[0]).resolve(strict=True)
            if not executable.is_file() or not os.access(executable, os.X_OK):
                raise ProcessError("invalid_executable")
            if not hmac.compare_digest(_digest(executable), spec.executable_sha256):
                raise ProcessError("executable_pin_mismatch")
            value = {
                "version": process_anchor.WIRE_VERSION,
                "argv": [str(executable), *spec.argv[1:]],
                "cwd": str(spec.cwd.resolve(strict=True)),
                "env": MINIMAL_ENV | spec.environment,
                "executable_sha256": spec.executable_sha256,
                "watchdog": self.policy.runtime_seconds
                + self.policy.launch_seconds
                + self.policy.reap_seconds
                + 2,
            }
            payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        except (OSError, ValueError) as exc:
            if isinstance(exc, ProcessError):
                raise
            raise ProcessError("invalid_launch_input") from None
        if len(payload) > self.policy.max_launch_bytes:
            raise ProcessError("launch_input_too_large")
        return payload

    def _send(self, fd: int, payload: bytes, stop: threading.Event, deadline: float) -> None:
        os.set_blocking(fd, False)
        with selectors.DefaultSelector() as selector:
            selector.register(fd, selectors.EVENT_WRITE)
            sent = 0
            while sent < len(payload):
                if stop.is_set() or time.monotonic() >= deadline:
                    raise TimeoutError("launch_interrupted")
                if selector.select(0.02):
                    try:
                        sent += os.write(fd, payload[sent:])
                    except BlockingIOError:
                        continue

    def _monitor(
        self, fd: int, stop: threading.Event, deadline: float
    ) -> tuple[Outcome, int | None]:
        data = bytearray()
        started = False
        with selectors.DefaultSelector() as selector:
            selector.register(fd, selectors.EVENT_READ)
            while True:
                if stop.is_set():
                    return "stopped", None
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return "timed_out", None
                if not selector.select(min(remaining, 0.02)):
                    continue
                chunk = os.read(fd, 257)
                if not chunk:
                    return "monitor_failed", None
                data.extend(chunk)
                if len(data) > 256:
                    return "monitor_failed", None
                while b"\n" in data:
                    line, rest = data.split(b"\n", 1)
                    data = bytearray(rest)
                    try:
                        frame = json.loads(line)
                    except (ValueError, UnicodeError):
                        return "monitor_failed", None
                    if frame == {"phase": "started"} and not started:
                        started = True
                        deadline = time.monotonic() + self.policy.runtime_seconds
                    elif frame == {"phase": "launch_failed"} and not started:
                        return "launch_failed", None
                    elif (
                        started
                        and isinstance(frame, dict)
                        and set(frame) == {"phase", "returncode"}
                        and frame["phase"] == "exited"
                        and type(frame["returncode"]) is int
                        and -(2**31) <= frame["returncode"] < 2**31
                        and not data
                    ):
                        return "exited", frame["returncode"]
                    else:
                        return "monitor_failed", None

    def _run(self, spec: ProcessSpec, stop: threading.Event) -> ProcessReport:
        started_at = time.monotonic()
        payload = self._prepare(spec)
        anchor_digest = _digest(ANCHOR)
        runner_digest = _digest(Path(__file__))
        request_ref = "hmac:" + hmac.new(self._reference_key, payload, "sha256").hexdigest()
        proc: subprocess.Popen[bytes] | None = None
        fds: set[int] = set()
        control_write: int | None = None
        outcome: Outcome = "launch_failed"
        code: int | None = None
        group_signal: Literal["not_launched", "sent", "absent", "failed"] = "not_launched"
        reaped = False
        try:
            if stop.is_set():
                outcome = "stopped"
            else:
                control_read, control_write = os.pipe()
                fds.update((control_read, control_write))
                status_read, status_write = os.pipe()
                fds.update((status_read, status_write))
                deadline = time.monotonic() + self.policy.launch_seconds
                proc = subprocess.Popen(
                    [sys.executable, "-I", "-B", str(ANCHOR), str(control_read), str(status_write)],
                    env=MINIMAL_ENV,
                    start_new_session=True,
                    close_fds=True,
                    pass_fds=(control_read, status_write),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                for fd in (control_read, status_write):
                    os.close(fd)
                    fds.remove(fd)
                self._send(control_write, payload, stop, deadline)
                outcome, code = self._monitor(status_read, stop, deadline)
        except TimeoutError:
            outcome = "stopped" if stop.is_set() else "timed_out"
        except OSError:
            outcome = "launch_failed" if proc is None else "monitor_failed"
        finally:
            if proc is not None:
                # Never poll/wait/reap this launcher before the LAST group signal. Its live
                # or unreaped PID reserves the identity. Never signal this group afterward.
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                    group_signal = "sent"
                except ProcessLookupError:
                    group_signal = "absent"
                except OSError:
                    group_signal = "failed"
                if control_write in fds:
                    os.close(control_write)
                    fds.remove(control_write)
                try:
                    proc.wait(timeout=self.policy.reap_seconds)
                    reaped = True
                except subprocess.TimeoutExpired:
                    # Retain the handle, refuse reuse, and expose failure. No stale PID retries.
                    self._unreaped = proc
                if not reaped or group_signal == "failed":
                    self._poisoned = True
            for fd in fds:
                os.close(fd)
        report = ProcessReport(
            run_id=uuid4(),
            outcome=outcome,
            direct_child_returncode=code,
            group_signal=group_signal,
            anchor_reaped=reaped,
            policy=self.policy,
            request_ref=request_ref,
            executable_sha256=spec.executable_sha256,
            runner_sha256=runner_digest,
            anchor_sha256=anchor_digest,
            elapsed_seconds=time.monotonic() - started_at,
        )
        self.last_report = report
        return report
