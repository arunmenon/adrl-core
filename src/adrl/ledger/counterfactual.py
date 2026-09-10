"""Counterfactual evidence bound to an explicit route_id. Primary: ADRL-MEM-009.

Secondary: ADRL-LRN-001 (tier T5). The route_id arrives as an argument carried from the decision
event. There is no lookup by session or time proximity anywhere in this module.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import structlog

from adrl.core.ids import RouteId
from adrl.ledger.events import counterfactual_event, producer_seq_for
from adrl.ledger.store import LedgerStore

log = structlog.get_logger(__name__)


@dataclass(frozen=True, slots=True)
class CounterfactualReceipt:
    route_id: RouteId
    pair_id: str
    attached: bool
    reason: str | None


async def attach_counterfactual(
    store: LedgerStore, route_id: RouteId, pair_id: str, detail: Mapping[str, Any]
) -> CounterfactualReceipt:
    """Attach evidence to the given route_id, or reject with a logged reason."""
    if store.read_decision(str(route_id)) is None:
        log.warning(
            "counterfactual_rejected", route_id=str(route_id), reason="route_id_not_persisted"
        )
        return CounterfactualReceipt(route_id, pair_id, False, "route_id_not_persisted")
    if bool(detail.get("subagent")):
        log.warning("counterfactual_rejected", route_id=str(route_id), reason="subagent_excluded")
        return CounterfactualReceipt(route_id, pair_id, False, "subagent_excluded")
    event = counterfactual_event(route_id, pair_id, producer_seq_for(pair_id), detail)
    ok = bool(
        await store.write_through(
            LedgerStore.insert_event(
                event.route_id,
                event.event_type,
                event.producer,
                event.producer_seq,
                event.payload,
                event.schema_version,
            )
        )
    )
    return CounterfactualReceipt(route_id, pair_id, ok, None if ok else "duplicate")
