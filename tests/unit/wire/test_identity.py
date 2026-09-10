"""ADRL-SEM-002 and ADRL-SEM-006 identity tests."""

from __future__ import annotations

import asyncio
import json

from adrl.wire.identity import (
    SOURCE_CONNECTION,
    SOURCE_HEADER,
    SOURCE_METADATA,
    IdentityResolver,
    LineageLocks,
)
from adrl.wire.parse import parse_request

from .conftest import load_fixture, parsed_fixture

KEY = b"k" * 32


def _parsed(name: str, **header_overrides: str):
    data = load_fixture(name)
    headers = {**data["headers"], **header_overrides}
    return parse_request("POST", data["path"], headers, json.dumps(data["body"]).encode())


def test_header_preferred_and_only_hmac_stored() -> None:
    resolver = IdentityResolver(KEY)
    identity = resolver.resolve(parsed_fixture("user_turn"), ("127.0.0.1", 5000))
    assert identity.source == SOURCE_HEADER
    assert "sess-fixture-0001" not in identity.session_hmac
    assert len(identity.session_hmac) == 64
    assert identity.lineage_hmac == identity.session_hmac
    assert identity.ancestor_lineages == ()


def test_metadata_session_id_used_when_header_absent() -> None:
    resolver = IdentityResolver(KEY)
    identity = resolver.resolve(parsed_fixture("metadata_only_user_turn"), None)
    assert identity.source == SOURCE_METADATA
    assert "11111111" not in identity.session_hmac


def test_metadata_session_cut_on_system_prefix_change() -> None:
    resolver = IdentityResolver(KEY)
    first = resolver.resolve(parsed_fixture("metadata_only_user_turn"), None)
    data = load_fixture("metadata_only_user_turn")
    data["body"]["system"] = "cc_entrypoint=sdk\nA different conversation entirely."
    parsed = parse_request(
        "POST", "/v1/messages", data["headers"], json.dumps(data["body"]).encode()
    )
    second = resolver.resolve(parsed, None)
    assert first.session_hmac != second.session_hmac


def test_two_keyless_connections_never_share_a_key() -> None:
    resolver = IdentityResolver(KEY)
    body = json.dumps(
        {"model": "m", "max_tokens": 10, "messages": [{"role": "user", "content": "x"}]}
    )
    a = resolver.resolve(parse_request("POST", "/v1/messages", {}, body.encode()), ("10.0.0.1", 1))
    b = resolver.resolve(parse_request("POST", "/v1/messages", {}, body.encode()), ("10.0.0.1", 2))
    assert a.source == SOURCE_CONNECTION
    assert a.session_hmac != b.session_hmac


def test_parent_and_two_subagents_are_three_identities_under_one_session() -> None:
    resolver = IdentityResolver(KEY)
    parent = resolver.resolve(parsed_fixture("user_turn"), None)
    child_a = resolver.resolve(_parsed("user_turn", **{"x-claude-code-agent-id": "a"}), None)
    child_b = resolver.resolve(_parsed("user_turn", **{"x-claude-code-agent-id": "b"}), None)
    assert parent.session_hmac == child_a.session_hmac == child_b.session_hmac
    assert len({parent.lineage_hmac, child_a.lineage_hmac, child_b.lineage_hmac}) == 3
    assert child_a.ancestor_lineages == (parent.lineage_hmac,)
    assert child_b.ancestor_lineages == (parent.lineage_hmac,)


def test_nested_subagent_chain_resolves_grandparent() -> None:
    resolver = IdentityResolver(KEY)
    parent = resolver.resolve(parsed_fixture("user_turn"), None)
    fork = resolver.resolve(parsed_fixture("fork_subagent"), None)
    nested = resolver.resolve(parsed_fixture("nested_subagent"), None)
    assert nested.agent_chain == ("agent-fork-0001", "agent-child-0002")
    assert nested.ancestor_lineages == (parent.lineage_hmac, fork.lineage_hmac)


def test_stable_teammate_ids_reconnect_to_same_lineage() -> None:
    resolver = IdentityResolver(KEY)
    first = resolver.resolve(
        _parsed("user_turn", **{"x-claude-code-agent-id": "teammate-alpha"}), None
    )
    again = resolver.resolve(
        _parsed("user_turn", **{"x-claude-code-agent-id": "teammate-alpha"}), None
    )
    assert first.lineage_hmac == again.lineage_hmac


async def test_lineage_locks_serialise_per_lineage_only() -> None:
    locks = LineageLocks()
    parent = IdentityResolver(KEY).resolve(parsed_fixture("user_turn"), None)
    order: list[str] = []

    async def worker(name: str, lineage: str) -> None:
        async with locks.get(lineage):  # type: ignore[arg-type]
            order.append(f"{name}:in")
            await asyncio.sleep(0.01)
            order.append(f"{name}:out")

    await asyncio.gather(
        worker("a", parent.lineage_hmac), worker("b", parent.lineage_hmac), worker("c", "other")
    )
    a_in, a_out = order.index("a:in"), order.index("a:out")
    b_in = order.index("b:in")
    assert not (a_in < b_in < a_out)
    assert len(locks) == 2
