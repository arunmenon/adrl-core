"""Opt-in stopped local engine acceptance. Primary: ADRL-OPS-001, ADRL-SAF-007."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from adrl.core.container_control import (
    ContainerControl,
    ContainerRequest,
    EngineError,
    ResourceError,
    ResourcePolicy,
    TransportError,
)
from adrl.core.resource_owner import StoppedResourceOwner
from adrl.ledger.attempts import AttemptJournal
from tests.unit.test_attempts import start
from tests.unit.test_capture import Fixture
from tests.unit.test_capture import capture as capture


@pytest.fixture
def engine(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[ContainerControl, str]]:
    names = (
        "ADRL_RESOURCE_DOCKER_SOCKET",
        "ADRL_RESOURCE_FIXTURE_IMAGE",
        "ADRL_RESOURCE_SECCOMP_PATH",
        "ADRL_RESOURCE_ACCEPTANCE_LOG",
    )
    if not all(os.environ.get(name) for name in names):
        pytest.skip("requires explicit local synthetic fixture and private resource accounting")
    endpoint, identity, profile_path, log_path = (os.environ[name] for name in names)
    profile = Path(profile_path).read_bytes()
    assert hashlib.sha256(profile).hexdigest() == (
        "9c1025c88ccaa517b648da571961838744ea2137f176bfe6a48b21294cae9c76"
    )
    control = ContainerControl(
        Path(endpoint), profile, hashlib.sha256(profile).hexdigest(), ResourcePolicy()
    )
    log = Path(log_path)
    assert log.is_absolute() and log.parent.is_dir()
    created: list[tuple[str, str]] = []
    uncertain: list[dict[str, str]] = []
    create = control.create

    def record(value: dict[str, Any]) -> None:
        with log.open("a") as output:
            output.write(
                json.dumps({"at": datetime.now(UTC).isoformat()} | value, sort_keys=True) + "\n"
            )
            output.flush()
            os.fsync(output.fileno())

    def tracked(name: str, body: dict[str, Any]) -> str:
        records = (
            [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
        )
        assert sum(r["event"] == "create_issued" for r in records) < 16
        assert body["Image"] == identity
        record({"event": "create_issued", "name": name, "image": identity, "body": body})
        try:
            result = create(name, body)
        except Exception as exc:
            code = str(exc)
            failure = {
                "event": "create_uncertain",
                "name": name,
                "error_type": type(exc).__name__,
                "safe_code": code if re.fullmatch(r"[a-z0-9_]{1,80}", code) else "unavailable",
                "transport_cause": exc.kind if isinstance(exc, TransportError) else None,
            }
            uncertain.append(failure)
            record(failure)
            raise
        created.append((result, name))
        record({"event": "create_receipt", "id": result, "name": name, "image": identity})
        return result

    monkeypatch.setattr(control, "create", tracked)
    try:
        yield control, identity
    finally:
        # Fixture ownership comes from the original create receipt, including deliberately
        # lost application acknowledgements. Never discover/adopt a resource by name.
        for resource, name in created:
            try:
                value = control.inspect(resource)
            except EngineError as exc:
                assert exc.status == 404
            else:
                control.never_started(value)
                assert value["Image"] == identity and value["Name"] == "/" + name
                control.remove(resource)
                with pytest.raises(EngineError) as missing:
                    control.inspect(resource)
                assert missing.value.status == 404
            record({"event": "absent", "id": resource})
        if uncertain:
            # Exit from fixture teardown, outside the runtime's exception wrapper. A failed
            # case must not allow another daemon mutation after an unreceipted create.
            pytest.exit("unreceipted synthetic create: engine batch halted", returncode=1)


@pytest.mark.parametrize("fault", ["none", "create_ack", "bind_ack", "remove_ack"])
async def test_real_engine_stopped_ownership(
    capture: Fixture,
    engine: tuple[ContainerControl, str],
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    control, image = engine
    journal = AttemptJournal(capture.data)
    task, operation = start(), uuid4()
    await journal.start(capture.principal, capture.workspace, task)
    run = StoppedResourceOwner(journal, control)
    request = ContainerRequest(image_id=image, argv=("/probe", "never-executed"))
    create, advance, remove = control.create, run._advance, control.remove

    def lost_create(name: str, body: dict[str, Any]) -> str:
        create(name, body)
        raise ResourceError("injected_create_ack_loss")

    def lost_bind(operation: str, phase: Any, **kwargs: Any) -> Any:
        result = advance(operation, phase, **kwargs)
        if phase == "bound":
            raise ResourceError("injected_bind_ack_loss")
        return result

    def lost_remove(identity: str) -> None:
        remove(identity)
        raise ResourceError("injected_remove_ack_loss")

    if fault == "create_ack":
        monkeypatch.setattr(control, "create", lost_create)
    if fault == "bind_ack":
        monkeypatch.setattr(run, "_advance", lost_bind)
    if fault in {"create_ack", "bind_ack"}:
        with pytest.raises(ResourceError, match="create_uncertain"):
            await run.create(capture.principal, operation, task.attempt_id, request)
    else:
        assert (
            await run.create(capture.principal, operation, task.attempt_id, request)
        ).phase == "bound"
    capture.store.close()
    capture.store.open()
    recovered = StoppedResourceOwner(journal, control)
    if fault == "create_ack":
        assert recovered.read(operation)[-1].phase == "create_issued"
        with pytest.raises(ResourceError, match="already_issued"):
            await recovered.create(capture.principal, operation, task.attempt_id, request)
        with pytest.raises(ResourceError, match="not_bound"):
            await asyncio.to_thread(recovered.remove, operation)
        return
    event = await recovered.create(capture.principal, operation, task.attempt_id, request)
    assert event.resource_id
    value = control.inspect(event.resource_id)
    control.never_started(value)
    assert value["Mounts"] == [] and value["HostConfig"]["NetworkMode"] == "none"
    assert value["HostConfig"]["SecurityOpt"][0] == "no-new-privileges:true"
    capture.keys.shred_session_key(capture.principal.session_hmac, "fixture")
    if fault == "remove_ack":
        monkeypatch.setattr(control, "remove", lost_remove)
        with pytest.raises(ResourceError):
            await asyncio.to_thread(recovered.remove, operation)
        assert recovered.read(operation)[-1].phase == "remove_issued"
        monkeypatch.setattr(control, "remove", remove)
    assert (await asyncio.to_thread(recovered.remove, operation)).phase == "removed"
    assert capture.store.read("SELECT * FROM product_execution_fences")
