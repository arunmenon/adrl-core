"""Readiness report lists blockers and never averages them."""

from __future__ import annotations

from adrl.learning.pairs import pair_budget
from adrl.learning.readiness import build_report
from adrl.learning.tiers import TieredDataset


def test_report_lists_every_blocker(contract, good_precision, organic_examples) -> None:  # type: ignore[no-untyped-def]
    dataset = TieredDataset.build(organic_examples, contract, good_precision)
    report = build_report(
        dataset,
        pair_budgets=[pair_budget("slice-a", [], delta=0.10, discordance=0.2)],
        verifier_precision=good_precision,
        t1_required=300,
    )
    data = report.as_dict()
    assert data["ready"] is False
    assert any(b.startswith("organic_verifier_labels") for b in data["blockers"])
    assert any(b.startswith("pair_budget[slice-a]") for b in data["blockers"])
    assert any(b.startswith("learned_router_authority") for b in data["blockers"])
    assert data["diversity"]["met"] is True
    assert data["t1_count"] == 60
    assert "excluded_fraction" in data
