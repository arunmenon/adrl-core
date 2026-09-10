"""Proxy integration harness: real pipeline, real ledgers, fake gateway, swappable stages."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx
import pytest

from adrl.config.loaders import ConfigBundle, load_bundle
from adrl.config.settings import Settings
from adrl.core.enums import GateMode, PinLookup, RoutingMode, Rung
from adrl.core.errors import ErrorCode
from adrl.core.ids import LineageId, mint_route_id
from adrl.core.ports import LineageEvent, StickyState
from adrl.core.types import Decision, RequestContext
from adrl.ledger.egress import EgressLedger
from adrl.ledger.facade import PIN_EVENT, MemoryFacade, SqliteLedgerProvider
from adrl.ledger.store import LedgerStore
from adrl.proxy.asgi import build_asgi
from adrl.proxy.observe_only import (
    InheritOnlyRouter,
    ObserveOnlyGate,
    PassthroughCascade,
    PassthroughPlan,
    is_action_boundary,
)
from adrl.proxy.pipeline import Pipeline
from adrl.proxy.upstream import HttpxGatewayClient
from adrl.wire.identity import IdentityResolver, LineageLocks
from adrl.wire.parse import parse_request
from tests.conftest import CONFIG_DIR, FakeGatewayState

FIXTURE_DIR = Path(__file__).resolve().parents[2] / "fixtures" / "wire"
HMAC_KEY = b"integration-key-0123456789abcdef"


def load_fixture(name: str) -> dict[str, Any]:
    return json.loads((FIXTURE_DIR / f"{name}.json").read_text(encoding="utf-8"))


class DictStateProvider:
    """In-memory StateProvider for tests; the ledger builder ships the SQLite one."""

    def __init__(self) -> None:
        self.sticky: dict[str, StickyState] = {}
        self.pins: dict[str, str] = {}
        self.fail = False

    async def get_sticky(self, lineage: LineageId) -> StickyState | None:
        if self.fail:
            raise RuntimeError("state provider unavailable")
        return self.sticky.get(lineage)

    async def set_sticky(self, state: StickyState) -> None:
        if self.fail:
            raise RuntimeError("state provider unavailable")
        self.sticky[state.lineage_hmac] = state

    async def get_pin(self, lineage: LineageId) -> PinLookup:
        return PinLookup.PINNED if lineage in self.pins else PinLookup.UNPINNED

    async def set_pin(self, lineage: LineageId, finding_id: str, detector_id: str) -> None:
        self.pins[lineage] = finding_id

    async def load_all(self) -> int:
        return len(self.sticky)


class RaisingGate:
    async def evaluate(self, ctx: RequestContext) -> Any:
        raise RuntimeError("scanner exploded")


class EmptyPermittedGate(ObserveOnlyGate):
    """Pinned lineage whose local rung is unhealthy: nothing permitted."""

    async def evaluate(self, ctx: RequestContext) -> Any:
        outcome = await super().evaluate(ctx)
        if outcome.pinned:
            from adrl.core.types import PermittedSet

            return type(outcome)(
                permitted=PermittedSet(frozenset()),
                verdicts=outcome.verdicts,
                pinned=True,
                unscanned=outcome.unscanned,
                findings=(),
                block=ErrorCode.PINNED_LOCAL_UNAVAILABLE
                if ctx.request_class.value != "utility"
                else None,
                repo_class=None,
                residency=None,
                latency_s=outcome.latency_s,
            )
        return outcome


class RaisingRouter(InheritOnlyRouter):
    async def decide(self, ctx: RequestContext, gate: Any, sticky: StickyState | None) -> Decision:
        raise TimeoutError("classifier timed out")


class FixedRouter(InheritOnlyRouter):
    def __init__(self, bundle: ConfigBundle, rung: Rung) -> None:
        super().__init__(bundle)
        self._rung = rung

    async def decide(self, ctx: RequestContext, gate: Any, sticky: StickyState | None) -> Decision:
        base = await super().decide(ctx, gate, sticky)
        rung = self._rung if self._rung in gate.permitted else base.rung
        return Decision(
            route_id=mint_route_id(),
            rung=rung,
            permitted=gate.permitted,
            estimator="fixed",
            estimator_version="test-v1",
            policy_version=base.policy_version,
            objective_version=base.objective_version,
            cascade_feasible=True,
            cascade_reason=None,
            features=base.features,
            features_version=base.features_version,
        )


class EscalatingCascade(PassthroughCascade):
    """Escalates every continuation at a boundary to the frontier rung (test double for CAS)."""

    async def plan(
        self, ctx: RequestContext, decision: Decision, gate: Any, sticky: StickyState | None
    ) -> PassthroughPlan:
        base = await super().plan(ctx, decision, gate, sticky)
        if is_action_boundary(ctx.json) and Rung.FRONTIER in gate.permitted:
            return PassthroughPlan(
                rung=Rung.FRONTIER,
                is_boundary=True,
                escalated=True,
                from_rung=base.rung,
                handoff=None,
                pair_rule=None,
                block=None,
                sticky=StickyState(
                    lineage_hmac=base.sticky.lineage_hmac,
                    route_id=base.sticky.route_id,
                    rung=Rung.FRONTIER,
                    escalated=True,
                    served_model=None,
                    served_provider=None,
                    served_source="assumed_intended",
                    turn_index=base.sticky.turn_index,
                    last_served_at=None,
                ),
            )
        return base


@dataclass
class Harness:
    settings: Settings
    bundle: ConfigBundle
    store: LedgerStore
    facade: MemoryFacade
    egress: EgressLedger
    pipeline: Pipeline
    client: httpx.AsyncClient
    gateway_state: FakeGatewayState
    resolver: IdentityResolver
    state: DictStateProvider
    sent: list[dict[str, Any]] = field(default_factory=list)

    def lineage_of(self, name: str, **headers: str) -> LineageId:
        data = load_fixture(name)
        parsed = parse_request(
            data["method"],
            data["path"],
            {**data["headers"], **headers},
            json.dumps(data["body"]).encode(),
        )
        return self.resolver.resolve(parsed, None).lineage_hmac

    async def pin(self, lineage: LineageId, detector: str = "aws_access_key") -> None:
        await self.facade.append_lineage_event(
            LineageEvent(
                lineage_hmac=lineage,
                event_type=PIN_EVENT,
                payload={"finding_id": f"f-{detector}", "detector_id": detector},
            )
        )

    async def send(
        self,
        name: str,
        *,
        headers: dict[str, str] | None = None,
        body: dict[str, Any] | None = None,
        raw: bytes | None = None,
    ) -> httpx.Response:
        data = load_fixture(name)
        merged_headers = {**data["headers"], **(headers or {})}
        payload = raw if raw is not None else json.dumps(body or data["body"]).encode("utf-8")
        response = await self.client.request(
            data["method"], data["path"], content=payload, headers=merged_headers
        )
        await self.pipeline.drain()
        self.sent.append({"headers": merged_headers, "raw": payload})
        return response

    def gateway_requests(self) -> Sequence[dict[str, Any]]:
        return self.gateway_state.requests

    def last_gateway_body(self) -> dict[str, Any]:
        return dict(self.gateway_state.requests[-1]["body"])

    def lineage_events(
        self, lineage: LineageId, event_type: str | None = None
    ) -> list[dict[str, Any]]:
        rows = self.store.read_lineage_events(lineage, event_type)
        return [dict(r) | {"payload": json.loads(r["payload_json"])} for r in rows]

    def decisions(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self.store.read("SELECT * FROM decisions ORDER BY ts")]

    def events(self, event_type: str | None = None) -> list[dict[str, Any]]:
        if event_type is None:
            rows = self.store.read("SELECT * FROM events ORDER BY seq")
        else:
            rows = self.store.read(
                "SELECT * FROM events WHERE event_type=? ORDER BY seq", (event_type,)
            )
        return [dict(r) | {"payload": json.loads(r["payload_json"])} for r in rows]


async def make_harness(
    *,
    gateway_client: httpx.AsyncClient,
    gateway_state: FakeGatewayState,
    ledger_store: LedgerStore,
    egress_ledger: EgressLedger,
    tmp_path: Path,
    gate: Any | None = None,
    router: Any | None = None,
    cascade: Any | None = None,
    state: DictStateProvider | None = None,
    routing_mode: RoutingMode = RoutingMode.SHADOW,
    gate_mode: GateMode = GateMode.ENFORCE,
    fallback_mode: RoutingMode = RoutingMode.SHADOW,
    facade: MemoryFacade | None = None,
    bundle: ConfigBundle | None = None,
) -> Harness:
    settings = Settings(
        config_dir=CONFIG_DIR,
        data_dir=tmp_path,
        ledger_path=ledger_store.path,
        egress_ledger_path=egress_ledger._path,
        keystore_path=tmp_path / "keystore",
        gate_mode=gate_mode,
        routing_mode=routing_mode,
        fallback_mode=fallback_mode,
        gateway_base_url="http://fake-gateway",
    )
    # Live routing is tested against the dev config, which carries no evidence_ref by design.
    load_settings = settings.model_copy(update={"routing_mode": RoutingMode.SHADOW})
    bundle = bundle or load_bundle(load_settings)
    facade = facade or MemoryFacade(SqliteLedgerProvider(ledger_store))
    state = state or DictStateProvider()
    resolver = IdentityResolver(HMAC_KEY)
    pipeline = Pipeline(
        settings=settings,
        bundle=bundle,
        ledger=facade,
        egress=egress_ledger,
        gateway=HttpxGatewayClient("http://fake-gateway", client=gateway_client),
        gate=gate or ObserveOnlyGate(facade),
        router=router or InheritOnlyRouter(bundle),
        cascade=cascade or PassthroughCascade(),
        state=state,
        identity=resolver,
        locks=LineageLocks(),
    )
    app = build_asgi(pipeline)
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://adrl")
    return Harness(
        settings=settings,
        bundle=bundle,
        store=ledger_store,
        facade=facade,
        egress=egress_ledger,
        pipeline=pipeline,
        client=client,
        gateway_state=gateway_state,
        resolver=resolver,
        state=state,
    )


@pytest.fixture
async def harness(
    gateway_client: httpx.AsyncClient,
    gateway_state: FakeGatewayState,
    ledger_store: LedgerStore,
    egress_ledger: EgressLedger,
    tmp_path: Path,
) -> AsyncIterator[Harness]:
    built = await make_harness(
        gateway_client=gateway_client,
        gateway_state=gateway_state,
        ledger_store=ledger_store,
        egress_ledger=egress_ledger,
        tmp_path=tmp_path,
    )
    yield built
    await built.client.aclose()


@pytest.fixture
def harness_factory(
    gateway_client: httpx.AsyncClient,
    gateway_state: FakeGatewayState,
    ledger_store: LedgerStore,
    egress_ledger: EgressLedger,
    tmp_path: Path,
) -> Any:
    async def build(**kwargs: Any) -> Harness:
        return await make_harness(
            gateway_client=gateway_client,
            gateway_state=gateway_state,
            ledger_store=ledger_store,
            egress_ledger=egress_ledger,
            tmp_path=tmp_path,
            **kwargs,
        )

    return build


def now() -> datetime:
    from datetime import UTC

    return datetime.now(UTC)
