"""Preview contracts reject ambiguous authority. Primary: ADRL-SEM-007. Secondary: ADRL-TRU-001."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from adrl.api.contracts import EventRequest, SessionRequest, distribution_capabilities
from adrl.api.schema import openapi_document


def event() -> dict[str, Any]:
    return {
        "event_id": "e1e58ab1-dc2f-4450-92e2-25120cc9fa41",
        "session_id": "session_123",
        "producer_seq": 1,
        "occurred_at": "2026-09-07T10:00:00Z",
        "event_type": "tool.completed",
        "payload": {"tool_call_ref": "call_123", "outcome": "failed"},
    }


@pytest.mark.parametrize(
    "extra",
    [
        {"producer_id": "trusted-verifier"},
        {"policy": "unrestricted"},
        {"verified": True},
        {"prompt": "content that does not belong in event metadata"},
    ],
)
def test_event_cannot_smuggle_authority_or_untyped_content(extra: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        EventRequest.model_validate(event() | extra)


@pytest.mark.parametrize("sequence", [-1, True, "1", 1.2])
def test_event_sequence_is_a_nonnegative_integer(sequence: Any) -> None:
    with pytest.raises(ValidationError):
        EventRequest.model_validate(event() | {"producer_seq": sequence})


def test_event_timestamp_requires_timezone() -> None:
    with pytest.raises(ValidationError):
        EventRequest.model_validate(event() | {"occurred_at": "2026-09-07T10:00:00"})


def test_reported_closure_cannot_become_verification_by_changing_event_type() -> None:
    report = event() | {
        "event_type": "session.closed",
        "payload": {"task_ref": "task_1", "reported_outcome": "accepted"},
    }
    assert EventRequest.model_validate(report).root.event_type == "session.closed"
    with pytest.raises(ValidationError):
        EventRequest.model_validate(report | {"event_type": "verification.completed"})


def test_event_roundtrip_retains_identity_and_preserves_unknown_outcome() -> None:
    request = event()
    request["payload"]["outcome"] = "unknown"
    validated = EventRequest.model_validate(request)
    assert EventRequest.model_validate_json(validated.model_dump_json()) == validated
    assert validated.root.payload.model_dump()["outcome"] == "unknown"


def test_session_request_cannot_self_assign_policy() -> None:
    request = {
        "adapter": {"id": "claude-code", "version": "1"},
        "profile": {"id": "anthropic-messages-v1", "version": "1"},
        "workload_ref": "registered_repo_1",
    }
    SessionRequest.model_validate(request)
    with pytest.raises(ValidationError):
        SessionRequest.model_validate(request | {"policy": "unrestricted"})


def test_distribution_discovery_does_not_claim_other_harnesses_or_enforcement() -> None:
    capabilities = distribution_capabilities()
    assert [p.profile.id for p in capabilities.profiles] == ["anthropic-messages-v1"]
    assert [a.adapter.id for a in capabilities.adapters] == ["claude-code"]
    assert capabilities.adapters[0].tested_harness_versions == ()
    assert capabilities.adapters[0].identity == "authenticated_binding"
    assert capabilities.adapters[0].tool_events == "implemented"
    assert capabilities.effective_enforcement == "requires_session_and_runtime_checks"


def test_openapi_export_has_resolvable_refs_and_matches_checked_in_artifact() -> None:
    document = openapi_document()
    schemas = document["components"]["schemas"]

    def check_refs(value: Any) -> None:
        if isinstance(value, dict):
            if "$ref" in value:
                prefix = "#/components/schemas/"
                assert value["$ref"].startswith(prefix)
                assert value["$ref"][len(prefix) :] in schemas
            for child in value.values():
                check_refs(child)
        elif isinstance(value, list):
            for child in value:
                check_refs(child)

    check_refs(document)
    artifact = Path(__file__).resolve().parents[2] / "api" / "adrl-api-v1-preview.json"
    assert json.loads(artifact.read_text()) == document
    implemented = [
        path
        for path, methods in document["paths"].items()
        for operation in methods.values()
        if operation["x-adrl-implementation"] == "implemented"
    ]
    assert len(implemented) == 6
    assert document["paths"]["/adrl/v1/sessions"]["post"]["security"] == [{"adrlWorkload": []}]


@pytest.mark.parametrize(
    "code",
    [
        "from adrl.api.contracts import distribution_capabilities; "
        "assert distribution_capabilities().profiles[0].profile.id == 'anthropic-messages-v1'",
        "from adrl.wire.profiles.messages import MessagesProfile; "
        "assert MessagesProfile().profile_id == 'anthropic-messages-v1'",
        "from adrl.proxy import Pipeline, ProxyResponse; "
        "from adrl.api.schema import openapi_document; "
        "assert openapi_document()['openapi'] == '3.1.0'",
    ],
)
def test_public_entry_points_work_in_a_fresh_process(code: str) -> None:
    root = Path(__file__).resolve().parents[2]
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(root / "src")
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr
