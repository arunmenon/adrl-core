"""Profile and adapter invariants. Primary: ADRL-SEM-007. Secondary: ADRL-SEM-002."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

import pytest

from adrl.core.enums import RequestClass
from adrl.wire.adapters import ClaudeCodeAdapter
from adrl.wire.identity import IdentityResolver
from adrl.wire.profiles.messages import MessagesProfile
from tests.conftest import CONFIG_DIR

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "wire"


def test_messages_profile_does_not_claim_responses_or_chat_completions() -> None:
    profile = MessagesProfile()
    for path in ["/v1/responses", "/v1/chat/completions", "/adrl/v1/events"]:
        assert not profile.handles("POST", path, {})
    assert set(profile.endpoints) == {"/v1/messages", "/v1/messages/count_tokens"}


@pytest.mark.parametrize("name", ["user_turn", "continuation", "count_tokens", "fork_subagent"])
def test_identity_extraction_keeps_original_bytes_and_hmac_identity(name: str) -> None:
    data = json.loads((FIXTURES / f"{name}.json").read_text())
    raw = json.dumps(data["body"], indent=3).encode() + b"\n"
    headers = {key.upper(): value for key, value in data["headers"].items()}
    request = MessagesProfile().parse(data["method"], data["path"], headers, raw)
    signals = ClaudeCodeAdapter().identity_signals(request)
    key = b"profile-test-identity-key"
    salt = b"fixed-test-salt"
    golden_path = FIXTURES.parent / "profiles" / "identity-v1.json"
    expected = json.loads(golden_path.read_text())["identities"][name]
    extracted = IdentityResolver(key, process_salt=salt).resolve_signals(
        signals, ("127.0.0.1", 9000)
    )
    assert json.loads(json.dumps(asdict(extracted))) == expected
    assert request.body is raw
    assert request.json == data["body"]


@pytest.mark.parametrize(
    "name, expected",
    [
        ("parallel_tools_partial", False),
        ("parallel_tools_full", True),
        ("user_turn", False),
    ],
)
def test_boundary_requires_all_outstanding_tool_results(name: str, expected: bool) -> None:
    data = json.loads((FIXTURES / f"{name}.json").read_text())
    assert MessagesProfile().is_action_boundary(data["body"]) is expected


def test_orphan_tool_result_is_not_an_action_boundary() -> None:
    assert not MessagesProfile().is_action_boundary(
        {
            "messages": [
                {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "missing"}]}
            ]
        }
    )


def test_profile_keeps_pinned_unclassifiable_failure() -> None:
    from adrl.config.loaders import load_bundle
    from adrl.config.settings import Settings
    from adrl.wire.classify import UnclassifiableError

    config = load_bundle(Settings(config_dir=CONFIG_DIR)).utility_fingerprints
    profile = MessagesProfile()
    request = profile.parse("POST", "/v1/messages", {}, b"not valid JSON")
    with pytest.raises(UnclassifiableError):
        profile.classify(request, config, pinned=True)
    assert profile.classify(request, config, pinned=False).request_class is RequestClass.PASSTHROUGH
