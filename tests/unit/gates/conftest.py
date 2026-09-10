"""Fixtures for the gates package tests."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Mapping
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from adrl.config.loaders import ConfigBundle, load_bundle
from adrl.config.settings import Settings
from adrl.core.enums import GateMode, InteractionMode, RequestClass, Rung, UtilityKind
from adrl.core.ids import LineageId, SessionId
from adrl.core.types import RequestContext
from adrl.gates.coverage import ScanCoverage
from adrl.gates.detectors import DetectorsConfig, load_detectors
from adrl.gates.egress import EgressWriter
from adrl.gates.feasibility import CharRatioTokenizer, FeasibilityFilter, StaticHealth
from adrl.gates.pin import PinRegistry
from adrl.gates.pipeline import GatePipeline
from adrl.gates.repo_class import RepoClassifier
from adrl.gates.secrets import TieredSecretScanner
from adrl.gates.suppression import LoggingSuppressionSink
from adrl.gates.workload import (
    HEADER_WORKLOAD_ASSERTION,
    AssertionVerifier,
    RepoInventory,
    sign_assertion,
)
from adrl.ledger.egress import EgressLedger
from adrl.ledger.facade import MemoryFacade, SqliteLedgerProvider
from adrl.ledger.store import LedgerStore
from tests.conftest import CONFIG_DIR

HMAC_KEY = b"test-hmac-key"
OPEN_REPO_ROOT = "/Users/arunmenon/projects/adrl-core"
RESTRICTED_REMOTE = "git@github.example.com:payments/core.git"


def inventory(root: str = OPEN_REPO_ROOT, remote: str | None = None) -> RepoInventory:
    return RepoInventory(
        root=root, remote=remote, head="deadbeef", fingerprint="f" * 64, tracked_files=3
    )


def assertion_header(
    root: str = OPEN_REPO_ROOT, remote: str | None = None, *, key: bytes = HMAC_KEY
) -> dict[str, str]:
    """A valid signed workload assertion, as the launcher would inject it."""
    return {HEADER_WORKLOAD_ASSERTION: sign_assertion(inventory(root, remote), key)}


AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
FAKE_GITHUB = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"


@pytest.fixture
def bundle(settings: Settings) -> ConfigBundle:
    return load_bundle(settings)


@pytest.fixture
def detectors() -> DetectorsConfig:
    return load_detectors(CONFIG_DIR / "detectors.yaml")


@pytest.fixture
def scanner(detectors: DetectorsConfig) -> TieredSecretScanner:
    return TieredSecretScanner(detectors, span_key=HMAC_KEY)


@pytest.fixture
def facade(ledger_store: LedgerStore) -> MemoryFacade:
    return MemoryFacade(SqliteLedgerProvider(ledger_store))


@pytest.fixture
def health() -> StaticHealth:
    return StaticHealth(
        {
            "adrl-local": True,
            "adrl-local-large": True,
            "adrl-cheap-cloud": True,
            "adrl-frontier": True,
        }
    )


@pytest.fixture
def feasibility(bundle: ConfigBundle, health: StaticHealth) -> FeasibilityFilter:
    return FeasibilityFilter(
        bundle.rungs,
        {r: CharRatioTokenizer() for r in Rung},
        health,
        safety_margin_tokens=bundle.policy.cascade_safety_margin_tokens,
    )


@pytest.fixture
def suppression() -> LoggingSuppressionSink:
    return LoggingSuppressionSink()


@pytest.fixture
def pins(
    facade: MemoryFacade, egress_ledger: EgressLedger, suppression: LoggingSuppressionSink
) -> PinRegistry:
    return PinRegistry(facade, egress_ledger, deployment_tag="test", suppression=suppression)


@pytest.fixture
def egress_writer(egress_ledger: EgressLedger) -> EgressWriter:
    return EgressWriter(egress_ledger, deployment_tag="test")


@pytest.fixture
def pipeline(
    bundle: ConfigBundle,
    scanner: TieredSecretScanner,
    facade: MemoryFacade,
    pins: PinRegistry,
    feasibility: FeasibilityFilter,
    egress_writer: EgressWriter,
) -> GatePipeline:
    return GatePipeline(
        classifier=RepoClassifier(
            bundle.repo_classification,
            facade,
            assertions=AssertionVerifier(HMAC_KEY),
            path_secret=HMAC_KEY,
        ),
        scanner=scanner,
        coverage=ScanCoverage(facade),
        pins=pins,
        feasibility=feasibility,
        egress=egress_writer,
        hmac_key=HMAC_KEY,
        mode=GateMode.ENFORCE,
    )


def make_ctx(
    body: Mapping[str, Any],
    *,
    request_class: RequestClass = RequestClass.USER_TURN,
    session: str = "sess-1",
    agent_id: str | None = None,
    parent_agent_id: str | None = None,
    path: str = "/v1/messages",
    utility_kind: UtilityKind | None = None,
    content_bearing: bool = True,
    repo_root: str | None = OPEN_REPO_ROOT,
    repo_remote: str | None = None,
    extra_headers: Mapping[str, str] | None = None,
) -> RequestContext:
    """A request context; by default it carries a valid assertion for the open dev repo.

    Pass repo_root=None to model a harness launched without ``adrl launch``.
    """
    raw = json.dumps(body).encode()
    session_hmac = SessionId(f"sess:{session}")
    lineage = LineageId(session_hmac if agent_id is None else f"{session_hmac}/{agent_id}")
    headers: dict[str, str] = {"x-claude-code-session-id": session}
    if repo_root is not None or repo_remote is not None:
        headers.update(assertion_header(repo_root or "/tmp/asserted-repo", repo_remote))
    if extra_headers:
        headers.update(extra_headers)
    return RequestContext(
        body=raw,
        json=body,
        headers=headers,
        path=path,
        request_class=request_class,
        content_bearing=content_bearing,
        interaction_mode=InteractionMode.INTERACTIVE,
        session_hmac=session_hmac,
        lineage_hmac=lineage,
        requested_model=str(body.get("model", "claude-fable-5-1")),
        is_stream=bool(body.get("stream", False)),
        max_tokens=body.get("max_tokens"),
        agent_id=agent_id,
        parent_agent_id=parent_agent_id,
        utility_kind=utility_kind,
    )


def user_turn(text: str, **kwargs: Any) -> RequestContext:
    body = {
        "model": "claude-fable-5-1",
        "max_tokens": 1024,
        "system": "You are Claude Code. Primary working directory: /Users/dev/adrl-core",
        "messages": [{"role": "user", "content": [{"type": "text", "text": text}]}],
    }
    return make_ctx(body, **kwargs)


def continuation_with_tool_result(
    result_text: str,
    *,
    tool_name: str = "Read",
    path_hint: str = "/Users/dev/adrl-core/x.py",
    **kwargs: Any,
) -> RequestContext:
    body = {
        "model": "claude-fable-5-1",
        "max_tokens": 1024,
        "system": "You are Claude Code. Primary working directory: /Users/dev/adrl-core",
        "messages": [
            {"role": "user", "content": [{"type": "text", "text": "read the file"}]},
            {
                "role": "assistant",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "toolu_01",
                        "name": tool_name,
                        "input": {"file_path": path_hint},
                    }
                ],
            },
            {
                "role": "user",
                "content": [
                    {"type": "tool_result", "tool_use_id": "toolu_01", "content": result_text}
                ],
            },
        ],
    }
    return make_ctx(body, request_class=RequestClass.CONTINUATION, **kwargs)


@pytest.fixture
def reopenable_store(ledger_paths: dict[str, Path]) -> AsyncIterator[dict[str, Any]]:
    """Helper returning factories so a test can close and reopen the same ledger files."""

    def open_all() -> tuple[LedgerStore, MemoryFacade, EgressLedger]:
        store = LedgerStore(ledger_paths["ledger"])
        store.open()
        facade = MemoryFacade(SqliteLedgerProvider(store))
        egress = EgressLedger(ledger_paths["egress"], signing_key=Ed25519PrivateKey.generate())
        egress.open()
        return store, facade, egress

    yield {"open": open_all}  # type: ignore[misc]
