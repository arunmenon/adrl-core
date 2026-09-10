"""Composition root. Primary: ADRL-FND-002.

Builds settings, config, both ledgers, the memory facade, the keystore, the gateway client and
the pipeline stages with their real adapters. A package that exists but fails to build raises
ConfigError; only a genuinely absent package is replaced by the observe-only stages, which are
real implementations (ADRL-FND-001 removal posture), never mocks. Learning is imported here
only to load a graduated exploration artifact (ADRL-LRN-007); routing never imports it.
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass
from typing import Any

import httpx
import structlog
from starlette.applications import Starlette

from adrl.api.service import ProductService
from adrl.config.loaders import ConfigBundle, load_bundle
from adrl.config.settings import Settings
from adrl.core.enums import GateMode
from adrl.core.errors import ConfigError
from adrl.core.ports import StateProvider, Tokenizer
from adrl.ledger.anchoring import (
    CheckpointShipper,
    FileAnchorShipper,
    HttpAnchorShipper,
    checkpoint_key_from_settings,
)
from adrl.ledger.egress import EgressLedger
from adrl.ledger.facade import MemoryFacade, SqliteLedgerProvider
from adrl.ledger.store import LedgerStore
from adrl.proxy.asgi import build_asgi
from adrl.proxy.observe_only import InheritOnlyRouter, ObserveOnlyGate, PassthroughCascade
from adrl.proxy.pipeline import Pipeline, ProxyResponse
from adrl.proxy.stages import CascadeStage, GateStage, RouteStage, TranscriptTransform
from adrl.proxy.upstream import HttpxGatewayClient
from adrl.telemetry.logging import configure_logging
from adrl.wire.identity import IdentityResolver, LineageLocks

log = structlog.get_logger(__name__)

SIGNING_PUB_FILE = "keys/dev/manifest-signing.pub"


@dataclass
class Components:
    settings: Settings
    bundle: ConfigBundle
    store: LedgerStore
    facade: MemoryFacade
    egress: EgressLedger | None
    gateway: HttpxGatewayClient
    pipeline: Pipeline
    gate: GateStage
    router: RouteStage
    cascade: CascadeStage
    state: StateProvider | None
    installed: dict[str, bool]
    keystore: Any | None = None
    erasure: Any | None = None
    background: list[asyncio.Task[None]] | None = None
    stop_event: asyncio.Event | None = None

    def start_background(self) -> None:
        """Interval checkpoints and anchor shipment for the egress ledger (ADRL-SAF-009)."""
        if self.egress is None or self.background:
            return
        self.stop_event = asyncio.Event()
        task = asyncio.create_task(
            self.egress.run_periodic(self.settings.egress_checkpoint_interval_s, self.stop_event)
        )
        self.background = [task]

    async def aclose(self) -> None:
        if self.stop_event is not None:
            self.stop_event.set()
        for task in self.background or []:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await asyncio.wait_for(task, timeout=5.0)
        await self.pipeline.drain()
        await self.gateway.aclose()
        if self.egress is not None:
            self.egress.close()
        self.store.close()


def _optional(module: str) -> Any | None:
    """Import a package that may be absent from this build; never swallow its own errors."""
    try:
        return importlib.import_module(module)
    except ModuleNotFoundError as exc:
        if exc.name is not None and exc.name.startswith(module.split(".")[0]):
            return None
        raise


def _build(name: str, factory: Any, **kwargs: Any) -> Any:
    try:
        return factory(**kwargs)
    except Exception as exc:
        raise ConfigError(f"{name} failed to build: {type(exc).__name__}: {exc}") from exc


def _keystore(settings: Settings, store: LedgerStore) -> Any | None:
    module = _optional("adrl.ledger.keystore")
    if module is None:
        return None
    return _build("keystore", module.FileKeyStore, root=settings.keystore_path, store=store)


def _hmac_key(settings: Settings, keystore: Any | None) -> bytes:
    """Per-deployment HMAC key. The keystore owns it when present; else a 0600 file."""
    if keystore is not None:
        return bytes(keystore.hmac_key())
    path = settings.keystore_path / f"{settings.hmac_key_id}.hmac"
    if path.exists():
        return path.read_bytes()
    import os

    path.parent.mkdir(parents=True, exist_ok=True)
    key = os.urandom(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(key)
    return key


def _explorer(settings: Settings, bundle: ConfigBundle) -> Any | None:
    """A graduated exploration artifact, or nothing (ADRL-LRN-007, ADRL-LRN-008)."""
    if settings.exploration_artifact_path is None:
        return None
    from adrl.routing.features import FEATURES_VERSION

    if bundle.learning_contract.feature_schema_version != FEATURES_VERSION:
        raise ConfigError(
            "exploration learning contract does not match live feature semantics; "
            "qualify a compatible contract and artifact before enabling exploration"
        )
    artifacts = _optional("adrl.learning.artifacts")
    explore = _optional("adrl.learning.explore")
    if artifacts is None or explore is None:
        raise ConfigError("exploration_artifact_path set but adrl.learning is not installed")
    pub_path = settings.config_dir / SIGNING_PUB_FILE
    if not pub_path.exists():
        raise ConfigError(f"graduation public key missing: {pub_path}")
    loaded = _build(
        "exploration artifact",
        artifacts.load_graduated,
        manifest_path=settings.exploration_artifact_path,
        bundle=bundle,
        public_key_pem=pub_path.read_bytes(),
    )
    manifest = loaded.manifest
    thresholds = dict(getattr(manifest, "thresholds", {}) or {})
    epsilon = thresholds.get("epsilon_by_rung") or {
        r.value: e for r, e in bundle.policy.exploration_epsilon_by_rung.items()
    }
    policy = explore.exploration_policy_from_manifest(
        epsilon, str(manifest.artifact_version), graduated=True
    )
    return explore.RoutingExplorerAdapter(policy)


def build_components(
    settings: Settings | None = None,
    *,
    bundle: ConfigBundle | None = None,
    gateway_client: httpx.AsyncClient | None = None,
    egress_enabled: bool = True,
) -> Components:
    settings = settings or Settings()
    bundle = bundle or load_bundle(settings)
    if settings.gate_mode is GateMode.OBSERVE:
        log.warning("gates_observe_only", detail="pins and blocks are logged, not enforced")

    store = LedgerStore(settings.ledger_path, busy_timeout_ms=settings.ledger_busy_timeout_ms)
    store.open()
    facade = MemoryFacade(SqliteLedgerProvider(store))

    egress: EgressLedger | None = None
    if egress_enabled:
        egress = _egress_ledger(settings)

    gateway = HttpxGatewayClient(
        settings.gateway_base_url, client=gateway_client, timeout_s=settings.gateway_timeout_s
    )
    installed: dict[str, bool] = {}

    keystore = _keystore(settings, store)
    installed["ledger.keystore"] = keystore is not None
    hmac_key = _hmac_key(settings, keystore)

    erasure: Any | None = None
    erasure_mod = _optional("adrl.ledger.erasure")
    if erasure_mod is not None and keystore is not None:
        erasure = _build("erasure", erasure_mod.ErasureService, store=store, keystore=keystore)
    installed["ledger.erasure"] = erasure is not None

    state: StateProvider | None = None
    ledger_state = _optional("adrl.ledger.state")
    if ledger_state is not None:
        provider: Any = _build("ledger.state", ledger_state.SqliteStateProvider, store=store)
        log.info("sticky_state_loaded", lineages=provider.load_now())
        state = provider
        installed["ledger.state"] = True
    else:
        installed["ledger.state"] = False

    tokenizer: Tokenizer | None = None
    gates = _optional("adrl.gates.pipeline")
    gate: GateStage
    if gates is not None:
        if egress is None:
            raise ConfigError("gates require the egress ledger (ADRL-SAF-009); it is disabled")
        health: Any | None = None
        if settings.gateway_health_enabled:
            feasibility_mod = importlib.import_module("adrl.gates.feasibility")
            health = feasibility_mod.LiteLLMHealth(gateway.client)
        gate_impl: Any = _build(
            "gates",
            gates.GatePipeline.from_components,
            bundle=bundle,
            settings=settings,
            ledger=facade,
            egress=egress,
            hmac_key=hmac_key,
            suppression=erasure,
            health=health,
            state=state,
        )
        tokenizer = gate_impl.feasibility.tokenizer(_local_rung())
        gate = gate_impl
        installed["gates"] = True
    else:
        gate = ObserveOnlyGate(facade)
        installed["gates"] = False

    routing = _optional("adrl.routing.router")
    router: RouteStage
    if routing is not None:
        router = _build(
            "routing",
            routing.Router.from_components,
            bundle=bundle,
            settings=settings,
            ledger=store,
            explorer=_explorer(settings, bundle),
        )
        installed["routing"] = True
    else:
        router = InheritOnlyRouter(bundle)
        installed["routing"] = False

    cascade_mod = _optional("adrl.cascade.controller")
    cascade: CascadeStage
    transform: TranscriptTransform | None = None
    if cascade_mod is not None:
        cascade = _build(
            "cascade",
            cascade_mod.CascadeController.from_components,
            bundle=bundle,
            settings=settings,
            ledger=facade,
            state=state,
        )
        handoff = importlib.import_module("adrl.cascade.handoff")
        transform = handoff.transform_transcript
        installed["cascade"] = True
    else:
        cascade = PassthroughCascade()
        installed["cascade"] = False

    pipeline = Pipeline(
        settings=settings,
        bundle=bundle,
        ledger=facade,
        egress=egress,
        gateway=gateway,
        gate=gate,
        router=router,
        cascade=cascade,
        state=state,
        identity=IdentityResolver(hmac_key),
        locks=LineageLocks(),
        transcript_transform=transform,
        tokenizer=tokenizer,
    )
    log.info("adrl_components_built", installed=installed, modes=_modes(settings))
    return Components(
        settings=settings,
        bundle=bundle,
        store=store,
        facade=facade,
        egress=egress,
        gateway=gateway,
        pipeline=pipeline,
        gate=gate,
        router=router,
        cascade=cascade,
        state=state,
        installed=installed,
        keystore=keystore,
        erasure=erasure,
    )


def _egress_ledger(settings: Settings) -> EgressLedger:
    """Egress ledger with its own checkpoint key and off-device shippers (ADRL-SAF-009).

    A development key is refused unless dev_keys_allowed is set; with no key configured the
    ledger still chains but cannot checkpoint, which the health view reports.
    """
    checkpoint_key = checkpoint_key_from_settings(settings)
    if checkpoint_key is None:
        log.warning(
            "egress_checkpoints_unsigned",
            detail="no checkpoint_signing_key_path; tamper evidence stops at the hash chain",
        )
    elif checkpoint_key.dev:
        log.warning(
            "egress_dev_key_in_use",
            key_id=checkpoint_key.key_id,
            path=str(checkpoint_key.path),
            detail="development checkpoint key; anchors signed by it have no audit value",
        )
    shippers: list[CheckpointShipper] = []
    if settings.egress_anchor_path is not None:
        shippers.append(FileAnchorShipper(settings.egress_anchor_path))
    if settings.egress_anchor_url is not None:
        shippers.append(HttpAnchorShipper(settings.egress_anchor_url))
    if checkpoint_key is not None and not shippers:
        log.warning(
            "egress_anchor_missing",
            detail="checkpoints are signed but no anchor is configured; set "
            "ADRL_EGRESS_ANCHOR_PATH or ADRL_EGRESS_ANCHOR_URL",
        )
    ledger = EgressLedger(
        settings.egress_ledger_path,
        signing_key=checkpoint_key.private if checkpoint_key else None,
        key_id=checkpoint_key.key_id if checkpoint_key else None,
        checkpoint_every=settings.egress_checkpoint_every,
        shippers=shippers,
    )
    ledger.open()
    return ledger


def _local_rung() -> Any:
    from adrl.core.enums import Rung

    return Rung.LOCAL


def _modes(settings: Settings) -> dict[str, str]:
    return {
        "gates": settings.gate_mode.value,
        "routing": settings.routing_mode.value,
        "fallback": settings.fallback_mode.value,
    }


def build_app(settings: Settings | None = None) -> Starlette:
    """ASGI app with a lifespan that owns every component."""
    settings = settings or Settings()
    configure_logging()
    holder: dict[str, Components] = {}
    products: dict[str, ProductService] = {}

    @contextlib.asynccontextmanager
    async def lifespan(_: Starlette) -> AsyncIterator[None]:
        components = build_components(settings)
        holder["components"] = components
        if components.keystore is not None:
            products["service"] = ProductService(
                components.store, components.keystore, components.bundle
            )
        app.state.components = components
        components.start_background()
        try:
            yield
        finally:
            await components.aclose()

    async def health() -> dict[str, object]:
        components = holder.get("components")
        if components is None:
            return {"components": "starting"}
        return {
            "installed": components.installed,
            "gateway": await components.gateway.health(),
            "ledger": (await components.facade.health()).available,
            "modes": _modes(settings),
            "egress": (
                components.egress.anchor_status() if components.egress is not None else None
            ),
        }

    app = build_asgi(
        _LazyPipeline(holder),
        lifespan=lifespan,
        health=health,
        product=lambda: products.get("service"),
    )
    return app


class _LazyPipeline:
    """RequestHandler resolved after lifespan startup."""

    def __init__(self, holder: dict[str, Components]) -> None:
        self._holder = holder

    async def handle(
        self,
        method: str,
        path: str,
        headers: Mapping[str, str],
        body: bytes,
        peer: tuple[str, int] | None,
        *,
        query: str = "",
    ) -> ProxyResponse:
        components = self._holder.get("components")
        if components is None:
            raise RuntimeError("components not built; lifespan has not started")
        return await components.pipeline.handle(method, path, headers, body, peer, query=query)


def serve(settings: Settings | None = None) -> None:
    import uvicorn

    settings = settings or Settings()
    uvicorn.run(
        build_app(settings), host=settings.listen_host, port=settings.listen_port, log_level="info"
    )
