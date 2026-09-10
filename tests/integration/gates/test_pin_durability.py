"""Pin durability across a process restart (ADRL-SAF-002 clause 1)."""

from __future__ import annotations

from pathlib import Path

from adrl.config.loaders import ConfigBundle
from adrl.core.enums import Rung
from adrl.gates.coverage import ScanCoverage
from adrl.gates.egress import EgressWriter
from adrl.gates.feasibility import CharRatioTokenizer, FeasibilityFilter, StaticHealth
from adrl.gates.pin import PinRegistry
from adrl.gates.pipeline import GatePipeline
from adrl.gates.repo_class import RepoClassifier
from adrl.gates.secrets import TieredSecretScanner
from adrl.ledger.egress import EgressLedger
from adrl.ledger.facade import MemoryFacade, SqliteLedgerProvider
from adrl.ledger.store import LedgerStore
from tests.unit.gates.conftest import AWS_KEY, HMAC_KEY, continuation_with_tool_result, user_turn


def _boot(
    paths: dict[str, Path], bundle: ConfigBundle, scanner: TieredSecretScanner
) -> tuple[GatePipeline, LedgerStore, EgressLedger]:
    store = LedgerStore(paths["ledger"])
    store.open()
    facade = MemoryFacade(SqliteLedgerProvider(store))
    egress = EgressLedger(paths["egress"])
    egress.open()
    health = StaticHealth(
        {
            "adrl-local": True,
            "adrl-local-large": True,
            "adrl-cheap-cloud": True,
            "adrl-frontier": True,
        }
    )
    pipeline = GatePipeline(
        classifier=RepoClassifier(bundle.repo_classification, facade),
        scanner=scanner,
        coverage=ScanCoverage(facade),
        pins=PinRegistry(facade, egress, deployment_tag="t"),
        feasibility=FeasibilityFilter(
            bundle.rungs, {r: CharRatioTokenizer() for r in Rung}, health
        ),
        egress=EgressWriter(egress, deployment_tag="t"),
        hmac_key=HMAC_KEY,
    )
    return pipeline, store, egress


async def test_pin_survives_restart(
    ledger_paths: dict[str, Path], bundle: ConfigBundle, scanner: TieredSecretScanner
) -> None:
    pipeline, store, egress = _boot(ledger_paths, bundle, scanner)
    first = await pipeline.evaluate(
        continuation_with_tool_result(f"secret {AWS_KEY}", session="durable")
    )
    assert first.pinned
    egress.close()
    store.close()

    pipeline, store, egress = _boot(ledger_paths, bundle, scanner)
    try:
        after = await pipeline.evaluate(user_turn("continue with no secret", session="durable"))
        assert after.pinned and after.permitted.rungs == frozenset({Rung.LOCAL})
        assert egress.verify_chain().ok
    finally:
        egress.close()
        store.close()
