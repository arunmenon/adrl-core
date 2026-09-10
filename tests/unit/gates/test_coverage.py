"""Incremental scan coverage (ADRL-SAF-003)."""

from __future__ import annotations

from adrl.core.ids import LineageId
from adrl.gates.content import extract_blocks
from adrl.gates.coverage import ScanCoverage
from adrl.ledger.facade import MemoryFacade, SqliteLedgerProvider
from adrl.ledger.store import LedgerStore


async def test_coverage_persists_across_reopen(ledger_paths: dict) -> None:  # type: ignore[type-arg]
    lineage = LineageId("lin-1")
    body = {"messages": [{"role": "user", "content": "first"}]}
    blocks = extract_blocks(body, b"k")

    store = LedgerStore(ledger_paths["ledger"])
    store.open()
    coverage = ScanCoverage(MemoryFacade(SqliteLedgerProvider(store)))
    assert await coverage.new_blocks(lineage, blocks) == blocks
    await coverage.mark_scanned(lineage, blocks)
    assert await coverage.new_blocks(lineage, blocks) == []
    assert coverage.tail(lineage) == "first"
    store.close()

    store = LedgerStore(ledger_paths["ledger"])
    store.open()
    coverage = ScanCoverage(MemoryFacade(SqliteLedgerProvider(store)))
    assert await coverage.new_blocks(lineage, blocks) == []
    body2 = {"messages": [{"role": "user", "content": "first"}, {"role": "user", "content": "x"}]}
    new = await coverage.new_blocks(lineage, extract_blocks(body2, b"k"))
    assert [b.text for b in new] == ["x"]
    store.close()
