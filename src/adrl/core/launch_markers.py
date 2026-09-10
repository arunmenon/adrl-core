"""Permanent one-shot denial markers. Primary: ADRL-OPS-001.

Secondary: ADRL-MEM-001/005/010, ADRL-TRU-001. Presence denies; never grants cleanup authority.
"""

from __future__ import annotations

import fcntl
import os
import re
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from adrl.core.container_control import ResourceError
from adrl.core.execution_control import ExecutionPolicy


def _directory(path: Path) -> None:
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise ResourceError("launch_marker_directory_unsafe")


def _sync(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class LaunchMarkers:
    def __init__(self, keystore_root: Path, policy: ExecutionPolicy) -> None:
        self.parent = keystore_root
        self.policy = ExecutionPolicy.model_validate(policy.model_dump())
        self.root = keystore_root / self.policy.marker_directory
        _directory(keystore_root)
        try:
            self.root.mkdir(mode=0o700)
        except FileExistsError:
            pass
        else:
            _sync(keystore_root)
        _directory(self.root)

    @contextmanager
    def recovery(self, operation: str) -> Iterator[None]:
        """Serialize cleanup callers; ledger callbacks never acquire this separate lock."""
        if not re.fullmatch(r"[a-f0-9]{64}", operation):
            raise ResourceError("launch_recovery_operation_invalid")
        _directory(self.parent)
        root = self.parent / self.policy.recovery_directory
        try:
            root.mkdir(mode=0o700)
        except FileExistsError:
            pass
        else:
            _sync(self.parent)
        _directory(root)
        fd = os.open(
            root / (operation + ".lock"),
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
            0o600,
        )
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise ResourceError("launch_recovery_lock_unsafe")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise ResourceError("launch_recovery_busy") from None
            yield
        finally:
            os.close(fd)

    def publish(self, operation: str) -> None:
        if not re.fullmatch(r"[a-f0-9]{64}", operation):
            raise ResourceError("launch_marker_operation_invalid")
        _directory(self.parent)
        _directory(self.root)
        lock = os.open(
            self.root / ".launch-denial.lock",
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
            0o600,
        )
        try:
            info = os.fstat(lock)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise ResourceError("launch_marker_lock_unsafe")
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise ResourceError("launch_marker_busy") from None
            marker = self.root / (operation + ".denied")
            if os.path.lexists(marker):
                raise ResourceError("launch_already_denied")
            entries = [p for p in self.root.iterdir() if p.name != ".launch-denial.lock"]
            if len(entries) >= self.policy.max_histories:
                raise ResourceError("launch_marker_capacity")
            data = self.policy.marker_contents.encode()
            if len(data) > self.policy.max_marker_bytes:
                raise ResourceError("launch_marker_size")
            fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                if os.write(fd, data) != len(data):
                    raise OSError("launch_marker_short_write")
                os.fsync(fd)
            finally:
                os.close(fd)
            _sync(self.root)
        finally:
            os.close(lock)
