"""ADRL-LRN-004 leakage rules by construction."""

from __future__ import annotations

from collections.abc import Sequence

import pytest

from adrl.core.enums import Rung
from adrl.core.ids import RouteId, mint_route_id, route_id_timestamp_ms
from adrl.learning.dataset import (
    EMBEDDING_MISSING_FEATURE,
    FeatureEncoder,
    ForbiddenSplitError,
    LeakageError,
    NeighbourRecord,
    attach_neighbour_features,
    build_frame,
    split,
    temporal_session_split,
)
from adrl.learning.tiers import TieredDataset
from tests.unit.learning.conftest import make_example


def _frame(contract, good_precision, examples):  # type: ignore[no-untyped-def]
    dataset = TieredDataset.build(examples, contract, good_precision)
    return build_frame(dataset.objective_examples(), contract)


def test_deny_listed_feature_in_snapshot_is_rejected(contract, good_precision) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(LeakageError, match="served_rung"):
        _frame(contract, good_precision, [make_example(0, features={"served_rung": "local"})])
    with pytest.raises(LeakageError, match="outcome_type"):
        _frame(contract, good_precision, [make_example(0, features={"outcome_type": "x"})])


def test_only_the_snapshot_source_is_accepted(contract, good_precision) -> None:  # type: ignore[no-untyped-def]
    dataset = TieredDataset.build([make_example(0)], contract, good_precision)
    with pytest.raises(LeakageError):
        build_frame(dataset.objective_examples(), contract, feature_source="ledger_recompute")  # type: ignore[arg-type]
    with pytest.raises(LeakageError, match="snapshot version"):
        _frame(contract, good_precision, [make_example(0, features_version="features-v0")])


def test_embedding_missing_indicator(contract, good_precision) -> None:  # type: ignore[no-untyped-def]
    frame = _frame(contract, good_precision, [make_example(0)])
    assert frame.rows[0].features[EMBEDDING_MISSING_FEATURE] is True


def test_no_session_spans_train_and_holdout(contract, good_precision, organic_examples) -> None:  # type: ignore[no-untyped-def]
    frame = _frame(contract, good_precision, organic_examples)
    result = temporal_session_split(frame, holdout_fraction=0.3)
    assert result.train.rows and result.holdout.rows
    assert not (result.train.sessions() & result.holdout.sessions())
    assert max(r.ts for r in result.train.rows) < min(r.ts for r in result.holdout.rows)


def test_random_kfold_is_forbidden(contract, good_precision, organic_examples) -> None:  # type: ignore[no-untyped-def]
    frame = _frame(contract, good_precision, organic_examples)
    with pytest.raises(ForbiddenSplitError):
        split(frame, "random_kfold")


class _LaterNeighbourSource:
    def neighbours(self, route_id: RouteId, *, k: int) -> Sequence[NeighbourRecord]:
        later = mint_route_id(route_id_timestamp_ms(route_id) + 60_000)
        return [NeighbourRecord(later, Rung.LOCAL, True)]


class _EarlierNeighbourSource:
    def neighbours(self, route_id: RouteId, *, k: int) -> Sequence[NeighbourRecord]:
        earlier = mint_route_id(route_id_timestamp_ms(route_id) - 60_000)
        return [
            NeighbourRecord(earlier, Rung.LOCAL, True),
            NeighbourRecord(earlier, Rung.LOCAL, False),
        ]


def test_neighbour_later_than_query_is_never_returned(contract, good_precision) -> None:  # type: ignore[no-untyped-def]
    frame = _frame(contract, good_precision, [make_example(0)])
    with pytest.raises(LeakageError, match="not earlier"):
        attach_neighbour_features(frame, _LaterNeighbourSource())
    attached = attach_neighbour_features(frame, _EarlierNeighbourSource())
    assert attached.rows[0].features["neighbour_local_success_rate"] == pytest.approx(0.5)
    assert attached.rows[0].features[EMBEDDING_MISSING_FEATURE] is False


def test_encoder_is_deterministic_and_rejects_leaks(
    contract, good_precision, organic_examples
) -> None:  # type: ignore[no-untyped-def]
    frame = _frame(contract, good_precision, organic_examples)
    encoder = FeatureEncoder(contract).fit(frame)
    a = encoder.transform(frame)
    b = FeatureEncoder(contract).fit(frame).transform(frame)
    assert a.shape == b.shape and (a == b).all()
    assert "repo_class=repo-1" in encoder.columns
