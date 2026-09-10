"""Repository and data-class gate on verified workload identity (ADRL-SAF-008)."""

from __future__ import annotations

import time

from adrl.config.loaders import ConfigBundle
from adrl.core.enums import Rung
from adrl.gates.content import extract_blocks
from adrl.gates.repo_class import (
    SOURCE_ASSERTION,
    SOURCE_ASSERTION_DEFAULT,
    SOURCE_UNKNOWN,
    RepoClassifier,
)
from adrl.gates.workload import HEADER_WORKLOAD_ASSERTION, AssertionVerifier, sign_assertion
from adrl.ledger.facade import MemoryFacade
from tests.unit.gates.conftest import (
    HMAC_KEY,
    OPEN_REPO_ROOT,
    RESTRICTED_REMOTE,
    inventory,
    make_ctx,
)


def _body(system: str, tool_path: str | None = None) -> dict:  # type: ignore[type-arg]
    messages: list[dict] = [{"role": "user", "content": "hi"}]  # type: ignore[type-arg]
    if tool_path:
        messages.append(
            {
                "role": "assistant",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "t",
                        "name": "Read",
                        "input": {"file_path": tool_path},
                    }
                ],
            }
        )
    return {"model": "m", "max_tokens": 10, "system": system, "messages": messages}


def _classifier(bundle: ConfigBundle, facade: MemoryFacade) -> RepoClassifier:
    return RepoClassifier(
        bundle.repo_classification,
        facade,
        assertions=AssertionVerifier(HMAC_KEY),
        path_secret=HMAC_KEY,
    )


async def test_spoofed_prompt_without_assertion_is_local_only(
    bundle: ConfigBundle, facade: MemoryFacade
) -> None:
    classifier = _classifier(bundle, facade)
    ctx = make_ctx(_body(f"Primary working directory: {OPEN_REPO_ROOT}"), repo_root=None)
    result = await classifier.classify(ctx, extract_blocks(ctx.json, b"k"))
    assert result.class_id == "unknown" and result.source == SOURCE_UNKNOWN
    assert result.allowed_rungs == frozenset({Rung.LOCAL})
    assert not result.identity_verified
    payload = (await facade.read_lineage_events(ctx.lineage_hmac, "classified"))[0].payload
    assert OPEN_REPO_ROOT not in str(payload), "no raw path in the ledger"


async def test_forged_and_expired_assertions_are_rejected(
    bundle: ConfigBundle, facade: MemoryFacade
) -> None:
    classifier = _classifier(bundle, facade)
    forged = sign_assertion(inventory(OPEN_REPO_ROOT), b"attacker-key")
    ctx = make_ctx(
        _body("hi"), repo_root=None, extra_headers={HEADER_WORKLOAD_ASSERTION: forged}, session="f"
    )
    result = await classifier.classify(ctx, extract_blocks(ctx.json, b"k"))
    assert result.source == SOURCE_UNKNOWN and result.allowed_rungs == frozenset({Rung.LOCAL})

    expired = sign_assertion(inventory(OPEN_REPO_ROOT), HMAC_KEY, ttl_s=10, now=time.time() - 60)
    ctx2 = make_ctx(
        _body("hi"), repo_root=None, extra_headers={HEADER_WORKLOAD_ASSERTION: expired}, session="e"
    )
    result2 = await classifier.classify(ctx2, extract_blocks(ctx2.json, b"k"))
    assert result2.source == SOURCE_UNKNOWN and result2.allowed_rungs == frozenset({Rung.LOCAL})


async def test_valid_assertion_for_open_repo_and_default_for_unlisted(
    bundle: ConfigBundle, facade: MemoryFacade
) -> None:
    classifier = _classifier(bundle, facade)
    ctx = make_ctx(_body(f"Primary working directory: {OPEN_REPO_ROOT}"))
    result = await classifier.classify(ctx, extract_blocks(ctx.json, b"k"))
    assert result.class_id == "open" and result.source == SOURCE_ASSERTION
    assert result.identity_verified and result.corroborated

    other = make_ctx(_body("hi"), repo_root="/tmp/unlisted-but-launched", session="u")
    result2 = await classifier.classify(other, extract_blocks(other.json, b"k"))
    assert result2.class_id == "default" and result2.source == SOURCE_ASSERTION_DEFAULT
    assert Rung.FRONTIER not in result2.allowed_rungs


async def test_valid_assertion_for_restricted_repo_tightens_to_local(
    bundle: ConfigBundle, facade: MemoryFacade
) -> None:
    classifier = _classifier(bundle, facade)
    ctx = make_ctx(_body("hi"), repo_root="/tmp/payments", repo_remote=RESTRICTED_REMOTE)
    result = await classifier.classify(ctx, extract_blocks(ctx.json, b"k"))
    assert result.class_id == "restricted"
    assert result.allowed_rungs == frozenset({Rung.LOCAL})
    assert not result.release_permitted
    payload = (await facade.read_lineage_events(ctx.lineage_hmac, "classified"))[0].payload
    assert "github.example.com" not in str(payload) and payload["evidence_hashes"]


async def test_prompt_cannot_widen_and_exact_match_only(
    bundle: ConfigBundle, facade: MemoryFacade
) -> None:
    classifier = _classifier(bundle, facade)
    # a substring of the restricted remote inside an asserted root must not match anything
    ctx = make_ctx(_body("hi"), repo_root="/tmp/payments/core-lookalike", session="x")
    result = await classifier.classify(ctx, extract_blocks(ctx.json, b"k"))
    assert result.class_id == "default"


async def test_unknown_then_asserted_takes_class_but_restricted_never_widens(
    bundle: ConfigBundle, facade: MemoryFacade
) -> None:
    classifier = _classifier(bundle, facade)
    first = make_ctx(_body("hi"), repo_root=None, session="m")
    r1 = await classifier.classify(first, extract_blocks(first.json, b"k"))
    assert r1.allowed_rungs == frozenset({Rung.LOCAL})
    second = make_ctx(_body("hi"), session="m")
    r2 = await classifier.classify(second, extract_blocks(second.json, b"k"))
    assert r2.class_id == "open", "an unknown ceiling yields to the first verified assertion"
    third = make_ctx(_body("hi"), repo_root="/tmp/p", repo_remote=RESTRICTED_REMOTE, session="m")
    r3 = await classifier.classify(third, extract_blocks(third.json, b"k"))
    assert r3.allowed_rungs == frozenset({Rung.LOCAL})
    fourth = make_ctx(_body("hi"), session="m")
    r4 = await classifier.classify(fourth, extract_blocks(fourth.json, b"k"))
    assert r4.allowed_rungs == frozenset({Rung.LOCAL}), "restricted ceiling never widens"
