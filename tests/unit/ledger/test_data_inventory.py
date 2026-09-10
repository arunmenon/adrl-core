"""No prompt-class material survives in clear, and erasure covers the sealed rest (ADRL-MEM-010)."""

from __future__ import annotations

import json
import shutil
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from adrl.core.ids import SessionId
from adrl.core.ports import SandboxResult
from adrl.ledger.erasure import ErasureService
from adrl.ledger.keystore import FileKeyStore
from adrl.ledger.store import LedgerStore
from adrl.ledger.verification import VerificationJobs, VerificationPlan
from tests.unit.ledger.conftest import write_decision

WORKSPACE_MARK = "wsmark7Q1"
TOUCHED_MARK = "touched_ZZ9.py"
ARGV_MARK = "--flag-marker-K3"
OUTPUT_MARK = "OUTPUT-MARKER-77"
TABLES = (
    "decisions",
    "events",
    "lineage_events",
    "embeddings",
    "session_keys",
    "projections",
    "verification_jobs",
    "instruction_hashes",
)


@dataclass
class ChattyRunner:
    """A fake sandbox whose output carries a marker that must never reach the ledger."""

    calls: list[tuple[str, ...]] = field(default_factory=list)

    def run(
        self, argv: Sequence[str], snapshot_dir: str, allow_list: Sequence[str], *, timeout_s: float
    ) -> SandboxResult:
        self.calls.append(tuple(argv))
        return SandboxResult(
            available=True, exit_code=0, duration_s=0.01, stdout_tail=f"ran {OUTPUT_MARK}"
        )

    @property
    def platform_id(self) -> str:
        return "fake"


def _dump(store: LedgerStore) -> str:
    chunks: list[str] = []
    for table in TABLES:
        for row in store.read(f"SELECT * FROM {table}"):
            chunks.append(
                json.dumps(
                    {k: (v.hex() if isinstance(v, bytes) else v) for k, v in dict(row).items()}
                )
            )
    return "\n".join(chunks)


def _workspace(tmp_path: Path) -> Path:
    ws = tmp_path / f"repo-{WORKSPACE_MARK}"
    (ws / ".git").mkdir(parents=True)
    (ws / ".git" / "HEAD").write_text("abc\n")
    (ws / "src").mkdir()
    (ws / "src" / TOUCHED_MARK).write_text("x = 1\n")
    return ws


def _snapshot(ws: Path) -> Path:
    snap = ws.parent / f"{ws.name}-snapshot"
    if snap.exists():
        shutil.rmtree(snap)
    shutil.copytree(ws, snap)
    return snap


async def test_verification_material_is_sealed_and_erasure_makes_it_unreadable(
    ledger_store: LedgerStore, tmp_path: Path
) -> None:
    keystore = FileKeyStore(tmp_path / "ks", store=ledger_store)
    session = SessionId("sess-inventory")
    route = write_decision(ledger_store, session=str(session), lineage=str(session))
    ws = _workspace(tmp_path)
    plan = VerificationPlan.model_validate(
        {
            "plan_version": "targeted-tests-v1",
            "command_checks": [{"name": "tests", "argv": ["pytest", ARGV_MARK], "timeout_s": 5}],
            "require_changes": False,
        }
    )
    jobs = VerificationJobs(
        ledger_store, ChattyRunner(), path_secret=b"path-secret", keystore=keystore
    )
    job_id = jobs.begin(
        route,
        ws,
        plan,
        served_rung="local",
        model="m",
        harness="claude-code",
        touched_paths=[f"src/{TOUCHED_MARK}"],
    )
    (ws / "src" / TOUCHED_MARK).write_text("x = 2\n")
    outcome = await jobs.finish(job_id, snapshot_dir=_snapshot(ws))
    assert outcome.result.value == "pass"

    before = _dump(ledger_store)
    for marker in (WORKSPACE_MARK, TOUCHED_MARK, ARGV_MARK, OUTPUT_MARK, "pytest"):
        assert marker not in before, f"{marker} reached the ledger in clear"

    # the sealed material is readable while the session key exists, then not
    begun = ledger_store.read(
        "SELECT payload_json FROM verification_jobs WHERE job_id=? AND status='begun'", (job_id,)
    )[0]
    payload = json.loads(str(begun["payload_json"]))
    assert payload["sealed"] is not None and payload["workspace_hash"]
    assert jobs._unseal(job_id, payload)["workspace"] == str(ws.resolve())

    receipt = await ErasureService(ledger_store, keystore).erase_session(session, "test")
    assert receipt.key_shredded
    with pytest.raises(ValueError, match="erased"):
        jobs._unseal(job_id, payload)
    after = _dump(ledger_store)
    for marker in (WORKSPACE_MARK, TOUCHED_MARK, ARGV_MARK, OUTPUT_MARK):
        assert marker not in after


async def test_job_without_keystore_is_process_local_not_plaintext(
    ledger_store: LedgerStore, tmp_path: Path
) -> None:
    session = SessionId("sess-nokeystore")
    route = write_decision(ledger_store, session=str(session), lineage=str(session))
    ws = _workspace(tmp_path)
    plan = VerificationPlan.model_validate(
        {
            "plan_version": "targeted-tests-v1",
            "command_checks": [{"name": "tests", "argv": ["pytest", ARGV_MARK], "timeout_s": 5}],
            "require_changes": False,
        }
    )
    jobs = VerificationJobs(ledger_store, ChattyRunner(), path_secret=b"s")
    job_id = jobs.begin(route, ws, plan, served_rung="local", model="m", harness="h")
    assert WORKSPACE_MARK not in _dump(ledger_store)
    outcome = await jobs.finish(job_id, snapshot_dir=_snapshot(ws))
    assert outcome.result.value == "pass"
    assert OUTPUT_MARK not in _dump(ledger_store)
