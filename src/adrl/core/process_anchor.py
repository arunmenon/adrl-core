"""Private process-group launcher. Primary: ADRL-OPS-001.

Secondary: ADRL-SAF-007, ADRL-SEM-006, ADRL-TRU-001.
Standalone stdlib program, launched only by process_owner in a fresh session. This is
cleanup plumbing for trusted commands, not a sandbox or an all-writer barrier.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import selectors
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

WIRE_VERSION = "owned-process-wire-v1"
FRAME_LIMIT = 8192
BOOTSTRAP_SECONDS = 10.0
WATCHDOG_LIMIT = 80.0


def _frame(fd: int, value: dict[str, Any]) -> None:
    payload = json.dumps(value, separators=(",", ":")).encode() + b"\n"
    if os.write(fd, payload) != len(payload):
        raise OSError("short_status_write")


def _request(fd: int) -> dict[str, Any]:
    deadline = time.monotonic() + BOOTSTRAP_SECONDS
    data = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(fd, selectors.EVENT_READ)
        while time.monotonic() < deadline:
            if not selector.select(max(0, deadline - time.monotonic())):
                break
            chunk = os.read(fd, FRAME_LIMIT + 1)
            if not chunk:
                raise ValueError("owner_lost")
            data.extend(chunk)
            if len(data) > FRAME_LIMIT:
                raise ValueError("oversized_request")
            if b"\n" in data:
                line, rest = data.split(b"\n", 1)
                if rest:
                    raise ValueError("extra_request")
                value: Any = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError("invalid_request")
                return value
    raise ValueError("bootstrap_timeout")


def _validate(value: dict[str, Any]) -> tuple[list[str], str, dict[str, str], float]:
    if set(value) != {"version", "argv", "cwd", "env", "executable_sha256", "watchdog"}:
        raise ValueError("invalid_request")
    argv, cwd, env, digest, watchdog = (
        value["argv"],
        value["cwd"],
        value["env"],
        value["executable_sha256"],
        value["watchdog"],
    )
    if value["version"] != WIRE_VERSION or not isinstance(argv, list) or not argv:
        raise ValueError("invalid_request")
    if not all(isinstance(arg, str) and "\0" not in arg for arg in argv):
        raise ValueError("invalid_request")
    if not isinstance(cwd, str) or not os.path.isabs(cwd) or not os.path.isabs(argv[0]):
        raise ValueError("invalid_request")
    if not isinstance(env, dict) or not all(
        isinstance(key, str)
        and key
        and "=" not in key
        and "\0" not in key
        and isinstance(item, str)
        and "\0" not in item
        for key, item in env.items()
    ):
        raise ValueError("invalid_request")
    if not isinstance(watchdog, (int, float)) or not math.isfinite(watchdog):
        raise ValueError("invalid_request")
    if not 0 < watchdog <= WATCHDOG_LIMIT:
        raise ValueError("invalid_request")
    with Path(argv[0]).open("rb") as handle:
        if hashlib.file_digest(handle, "sha256").hexdigest() != digest:
            raise ValueError("executable_changed")
    return argv, cwd, env, float(watchdog)


def _serve(control: int, status: int) -> None:
    try:
        argv, cwd, env, watchdog = _validate(_request(control))
        child = subprocess.Popen(
            argv,
            cwd=cwd,
            env=env,
            close_fds=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, ValueError, TypeError):
        _frame(status, {"phase": "launch_failed"})
        return
    deadline = time.monotonic() + watchdog
    _frame(status, {"phase": "started"})
    exit_sent = False
    with selectors.DefaultSelector() as selector:
        selector.register(control, selectors.EVENT_READ)
        while time.monotonic() < deadline:
            # Any further command bytes, or EOF, revoke this owner's run.
            if selector.select(min(0.02, max(0, deadline - time.monotonic()))):
                return
            if not exit_sent:
                code = child.poll()
                if code is not None:
                    _frame(status, {"phase": "exited", "returncode": code})
                    exit_sent = True
            # Stay alive after the workload exits: our PID/group identity is still owned.


def main() -> int:
    if os.name != "posix" or os.getpid() != os.getpgrp() or os.getsid(0) != os.getpid():
        return 2
    try:
        if len(sys.argv) != 3:
            return 2
        control, status = int(sys.argv[1]), int(sys.argv[2])
        _serve(control, status)
    except (OSError, ValueError):
        pass
    finally:
        # This process is still alive and is its own session/group leader. No saved PID.
        os.killpg(os.getpgrp(), signal.SIGKILL)
    return 2  # pragma: no cover - SIGKILL above does not return on this supported backend.


if __name__ == "__main__":
    raise SystemExit(main())
