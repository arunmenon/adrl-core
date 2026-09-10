"""Opt-in one-shot fixture engine acceptance. Primary: ADRL-OPS-001.

Secondary: ADRL-SAF-007, ADRL-MEM-002/005/010, ADRL-TRU-001.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path
from uuid import uuid4

import pytest

from adrl.core.container_control import (
    ContainerControl,
    ContainerRequest,
    ResourceError,
)
from adrl.core.errors import LedgerAppendFailure
from adrl.core.execution_control import ExecutionPolicy
from adrl.core.isolated_execution import IsolatedExecution
from adrl.core.resource_owner import StoppedResourceOwner
from adrl.ledger.attempts import AttemptJournal
from tests.unit.test_attempts import start
from tests.unit.test_capture import Fixture
from tests.unit.test_capture import capture as capture

from .test_resource_engine import engine as engine


@pytest.mark.parametrize("fault", ["none", "start_ack", "erasure", "owner_death"])
async def test_real_one_shot_launch(
    capture: Fixture,
    engine: tuple[ContainerControl, str],
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    control, image = engine
    journal = AttemptJournal(capture.data)
    task = start()
    operation = uuid4()
    await journal.start(capture.principal, capture.workspace, task)
    owner = StoppedResourceOwner(journal, control)
    await owner.create(
        capture.principal,
        operation,
        task.attempt_id,
        ContainerRequest(image_id=image, argv=("/probe", "forced_stop")),
    )
    run = IsolatedExecution(owner, ExecutionPolicy(max_run_seconds=0.1))
    try:
        if fault == "owner_death":
            data = {
                "principal": asdict(capture.principal),
                "db": str(capture.workspace.parent / "ledger.db"),
                "keys": str(capture.keys.root),
                "profile": str(Path(__file__).parents[1] / "fixtures/seccomp-v27.3.1.json"),
                "socket": str(control.socket),
                "operation": str(operation),
            }
            result = await asyncio.to_thread(
                subprocess.run,
                [sys.executable, str(Path(__file__).parents[1] / "fixtures/launch_owner.py")],
                input=json.dumps(data),
                text=True,
                capture_output=True,
                timeout=5,
                check=False,
            )
            assert result.returncode == 17, result.stderr
            assert run.read(operation)[-1].phase == "claim"
            assert control.inspect(owner.read(operation)[-1].resource_id)["State"]["Running"]
            assert run.recover(operation).resource_state == "absent"
        else:
            original = run.control.start

            def launch(identity: str) -> None:
                original(identity)
                if fault == "start_ack":
                    raise ResourceError("fixture_lost_start_ack")
                if fault == "erasure":
                    capture.keys.shred_session_key(
                        capture.principal.session_hmac, "fixture_active_erasure"
                    )

            monkeypatch.setattr(run.control, "start", launch)
            report = await run.run(capture.principal, operation)
            assert report.resource_state == ("stopped" if fault == "none" else "absent"), report
            assert not report.exact_close_eligible and not report.eligible_for_learning
            assert report.execution_failed == (fault != "none")
        assert run.recover(operation).resource_state == "absent"
        with pytest.raises((ValueError, LedgerAppendFailure)):
            await run.run(capture.principal, operation)
        assert len(list(run.markers.root.glob("*.denied"))) == 1
        assert capture.store.read("SELECT * FROM product_execution_fences")

        def persist() -> None:
            with Path(os.environ["ADRL_RESOURCE_ACCEPTANCE_LOG"]).open("a") as out:
                out.write(
                    json.dumps(
                        {
                            "event": "runtime_assertions_completed",
                            "fault": fault,
                            "operation": str(operation),
                            "history": [
                                event.model_dump(mode="json") for event in run.read(operation)
                            ],
                        }
                    )
                    + "\n"
                )
                out.flush()
                os.fsync(out.fileno())

        await asyncio.to_thread(persist)
    finally:
        history = run.read(operation)
        if history:
            assert run.recover(operation).resource_state == "absent"
        else:
            # A rejected fixture has never received runtime start authority.
            owner.remove(operation)
