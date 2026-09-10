"""Synthetic routing workbench. Primary: ADRL-EVL-005.

Secondary: ADRL-RTG-002, ADRL-MEM-001, ADRL-SEM-007. Real composed stages,
synthetic Messages client and endpoint, disposable ledgers, no learned authority.
This developer tool deliberately has no real endpoint, credential or harness option.
"""

from __future__ import annotations

import argparse
import asyncio
import copy
import hashlib
import json
import logging
import os
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Literal
from uuid import uuid4

import httpx
import structlog
from pydantic import BaseModel, ConfigDict, Field, model_validator
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from adrl.app import build_components
from adrl.config.loaders import load_bundle
from adrl.config.settings import Settings
from adrl.core.enums import RoutingMode
from adrl.gates.workload import HEADER_WORKLOAD_ASSERTION, RepoInventory, sign_assertion
from adrl.proxy.asgi import build_asgi
from check_all import ROOT, source_manifest

FIXTURE = ROOT / "tests/fixtures/wire/user_turn.json"


class Case(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    id: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    family: str = Field(min_length=1, max_length=80)
    session: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    prompt: str = Field(min_length=1, max_length=2000)
    context_chars: int = Field(default=0, ge=0, le=700_000)
    tool_repeats: int = Field(default=0, ge=0, le=4)
    tool_result: Literal["clean", "secret", "oversize"] = "clean"
    endpoint: Literal["reported", "missing_identity", "error"] = "reported"
    profile: Literal["messages_fixture", "responses_unqualified"] = "messages_fixture"
    stream: bool = True


class Suite(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    schema_version: Literal["adrl-routing-lab-suite-v1"]
    evidence_origin: Literal["curated_synthetic"]
    question: str = Field(min_length=1, max_length=1000)
    cases: tuple[Case, ...] = Field(min_length=1, max_length=24)

    @model_validator(mode="after")
    def unique_ids(self) -> Suite:
        if len({c.id for c in self.cases}) != len(self.cases):
            raise ValueError("case IDs must be unique")
        return self


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def append_event(out: Path, event: dict[str, Any]) -> None:
    """Durable append; manifest supplies the denominator after interruption."""
    with (out / "events.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"at": datetime.now(UTC).isoformat(), **event}) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def write_new(path: Path, value: Any) -> None:
    with path.open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(value, indent=2) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def summary(out: Path) -> dict[str, Any]:
    manifest = json.loads((out / "manifest.json").read_text())
    rows = {
        c["id"]: {"case_id": c["id"], "state": "not_started"} for c in manifest["suite"]["cases"]
    }
    truncated = False
    journal = out / "events.jsonl"
    if journal.exists():
        lines = journal.read_text().splitlines()
        for index, line in enumerate(lines):
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                if index != len(lines) - 1:
                    raise ValueError("corrupt non-tail journal record") from None
                truncated = True
                break
            if event["type"] == "started":
                rows[event["case_id"]] = {"case_id": event["case_id"], "state": "indeterminate"}
            elif event["type"] == "finished":
                rows[event["case_id"]] = event["result"]
    counts = dict(Counter(row["state"] for row in rows.values()))
    return {
        "experiment_id": manifest["experiment_id"],
        "execution_mode": "simulation",
        "source": "synthetic",
        "evidence_tier": "T4",
        "evidence_origin": "curated_synthetic",
        "eligible_for_learning": False,
        "planned": len(rows),
        "counts": counts,
        "truncated_tail": truncated,
        "rows": list(rows.values()),
        "model_calls": 0,
        "task_success": None,
        "measured_provider_cost": None,
    }


def make_body(case: Case) -> dict[str, Any]:
    body = copy.deepcopy(json.loads(FIXTURE.read_text())["body"])
    body["stream"] = case.stream
    body["messages"] = [{"role": "user", "content": [{"type": "text", "text": case.prompt}]}]
    if case.context_chars:
        body["system"].append({"type": "text", "text": "x" * case.context_chars})
    for index in range(case.tool_repeats):
        result = {
            "clean": "same synthetic file content",
            "secret": "AWS_KEY=AKIAIOSFODNN7EXAMPLE",
            "oversize": "x" * 700_000,
        }[case.tool_result]
        body["messages"].extend(
            [
                {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": f"lab-{index}",
                            "name": "Read",
                            "input": {"file_path": "README.md"},
                        }
                    ],
                },
                {
                    "role": "user",
                    "content": [
                        {"type": "tool_result", "tool_use_id": f"lab-{index}", "content": result}
                    ],
                },
            ]
        )
    return body


class SyntheticEndpoint:
    """Controlled in-process response source; records actual received request bytes."""

    def __init__(self) -> None:
        self.mode = "reported"
        self.received: list[dict[str, Any]] = []

    async def messages(self, request: Request) -> Response:
        raw = await request.body()
        body = json.loads(raw)
        self.received.append(
            {
                "body_sha256": digest(raw),
                "model": body.get("model"),
                "stream": body.get("stream"),
                "path": request.url.path,
            }
        )
        if self.mode == "error":
            return JSONResponse(
                {
                    "type": "error",
                    "error": {"type": "api_error", "message": "Synthetic upstream failure"},
                },
                status_code=503,
            )
        model = str(body["model"]) if self.mode == "reported" else None
        headers = {"x-litellm-model-id": str(model)} if model else {}
        message = {
            "id": "msg_lab",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "Synthetic response; no task executed."}],
            "stop_reason": "end_turn",
            "stop_sequence": None,
            "usage": {"input_tokens": 0, "output_tokens": 0},
        }
        if model:
            message["model"] = model
        if not body.get("stream"):
            return JSONResponse(message, headers=headers)
        start = {**message, "content": [], "stop_reason": None}
        events = [
            ("message_start", {"type": "message_start", "message": start}),
            (
                "content_block_start",
                {
                    "type": "content_block_start",
                    "index": 0,
                    "content_block": {"type": "text", "text": ""},
                },
            ),
            (
                "content_block_delta",
                {
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": "text_delta", "text": "Synthetic response."},
                },
            ),
            ("content_block_stop", {"type": "content_block_stop", "index": 0}),
            (
                "message_delta",
                {
                    "type": "message_delta",
                    "delta": {"stop_reason": "end_turn"},
                    "usage": {"output_tokens": 0},
                },
            ),
            ("message_stop", {"type": "message_stop"}),
        ]
        payload = "".join(f"event: {name}\ndata: {json.dumps(data)}\n\n" for name, data in events)
        return Response(payload, media_type="text/event-stream", headers=headers)


def lab_settings(directory: Path) -> Settings:
    # Supply every field explicitly so environment cannot enable a classifier,
    # remote anchor, live ledger, tokenizer download or alternative configuration.
    defaults = {
        name: field.get_default(call_default_factory=True)
        for name, field in Settings.model_fields.items()
    }
    return Settings(
        **(
            defaults
            | {
                "config_dir": ROOT / "config",
                "data_dir": directory,
                "ledger_path": directory / "synthetic.db",
                "egress_ledger_path": directory / "egress.db",
                "keystore_path": directory / "keys",
                "gateway_base_url": "http://lab.invalid",
                "gateway_health_enabled": False,
                "routing_mode": RoutingMode.LIVE,
                "fallback_mode": RoutingMode.LIVE,
            }
        )
    )


async def execute(suite: Suite, out: Path) -> None:
    endpoint = SyntheticEndpoint()
    app = Starlette(routes=[Route("/v1/messages", endpoint.messages, methods=["POST"])])
    with TemporaryDirectory(prefix="adrl-synthetic-lab-") as directory:
        settings = lab_settings(Path(directory))
        # Existing integration-test pattern; impossible to select a network transport here.
        bundle = load_bundle(settings.model_copy(update={"routing_mode": RoutingMode.SHADOW}))
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://lab.invalid", trust_env=False
        ) as gateway:
            components = build_components(settings, bundle=bundle, gateway_client=gateway)
            try:
                if not all(components.installed.values()):
                    raise RuntimeError("required real component missing")
                inventory = RepoInventory(
                    root=str(ROOT),
                    remote=None,
                    head="synthetic-only",
                    fingerprint="e" * 64,
                    tracked_files=1,
                )
                assertion = sign_assertion(inventory, components.keystore.hmac_key())
                write_new(
                    out / "environment.json",
                    {
                        "config_versions": bundle.versions,
                        "installed": components.installed,
                        "harness_binary_version": None,
                        "model_revision": None,
                        "repo_snapshot": None,
                        "client": "synthetic Claude Code Messages fixture; no harness executed",
                        "endpoint": "in-process synthetic ASGI",
                        "health": "static fixture health",
                        "workload_assertion": "synthetic development-repository identity",
                        "live_config_admitted": False,
                        "config_load_mode": "shadow",
                        "pipeline_mode": "live inside in-process simulation only",
                        "config_evidence_bypass": "test-only bundle; no provider transport",
                    },
                )
                async with httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=build_asgi(components.pipeline)),
                    base_url="http://adrl.invalid",
                    trust_env=False,
                ) as client:
                    for case in suite.cases:
                        append_event(out, {"type": "started", "case_id": case.id})
                        result: dict[str, Any] = {"case_id": case.id, "state": "unsupported"}
                        if case.profile == "responses_unqualified":
                            result["reason"] = (
                                "Responses and a real Codex harness are unqualified here"
                            )
                            append_event(
                                out, {"type": "finished", "case_id": case.id, "result": result}
                            )
                            continue
                        before = len(endpoint.received)
                        last_seq = components.store.read(
                            "SELECT COALESCE(MAX(seq),0) AS n FROM events"
                        )[0]["n"]
                        raw = json.dumps(make_body(case)).encode()
                        endpoint.mode = case.endpoint
                        try:
                            response = await asyncio.wait_for(
                                client.post(
                                    "/v1/messages",
                                    content=raw,
                                    headers={
                                        "content-type": "application/json",
                                        "anthropic-version": "2023-06-01",
                                        "x-claude-code-session-id": f"lab-{case.session}",
                                        HEADER_WORKLOAD_ASSERTION: assertion,
                                    },
                                ),
                                timeout=30,
                            )
                            await components.pipeline.drain()
                            events = [
                                {**dict(row), "payload": json.loads(row["payload_json"])}
                                for row in components.store.read(
                                    "SELECT * FROM events WHERE seq>? ORDER BY seq", (last_seq,)
                                )
                            ]
                            for event in events:
                                event.pop("payload_json")
                            route_ids = sorted({e["route_id"] for e in events if e["route_id"]})
                            decisions = [
                                dict(row)
                                for route_id in route_ids
                                for row in components.store.read(
                                    "SELECT * FROM decisions WHERE route_id=?", (route_id,)
                                )
                            ]
                            dispatched = endpoint.received[before:]
                            result.update(
                                state=(
                                    "responded"
                                    if response.status_code < 400
                                    else "upstream_error"
                                    if dispatched
                                    else "blocked"
                                ),
                                http_status=response.status_code,
                                input_sha256=digest(raw),
                                response_sha256=digest(response.content),
                                decisions=decisions,
                                events=events,
                                dispatched=dispatched,
                                synthetic_receipt=True,
                                eligible_for_learning=False,
                            )
                        except Exception as exc:
                            result.update(
                                state="indeterminate",
                                error_type=type(exc).__name__,
                                dispatched=endpoint.received[before:],
                            )
                            append_event(
                                out, {"type": "finished", "case_id": case.id, "result": result}
                            )
                            # State may be inconsistent. Leave remaining planned cases not_started.
                            raise
                        append_event(
                            out, {"type": "finished", "case_id": case.id, "result": result}
                        )
            finally:
                await components.aclose()


def write_report(out: Path, report: dict[str, Any]) -> None:
    """Readable view keeps original selection separate from current dispatch."""
    lines = [
        "# Routing lab: actual choices, synthetic execution",
        "",
        "Real ADRL stages ran against a controlled in-process endpoint. No harness or model",
        "executed a coding task. Receipt identity is synthetic. No quality or savings measured.",
        "",
        "A continuation keeps its original route ID and initial choice. Its dispatched tier",
        "can change through cascade or privacy enforcement. Read both columns together.",
        "",
        "| Case | Initial choice | Dispatched tier | Endpoint received | Identity source | State |",
        "|---|---|---|---|---|---|",
    ]
    for row in report["rows"]:
        decisions = row.get("decisions", [])
        requests = [e["payload"] for e in row.get("events", []) if e["event_type"] == "request"]
        served = [e["payload"] for e in row.get("events", []) if e["event_type"] == "served"]
        received = row.get("dispatched", [])
        values = [
            row["case_id"],
            decisions[0]["decided_rung"] if decisions else "-",
            requests[-1]["target_rung"] if requests else "-",
            str(received[-1]["model"]) if received else "no dispatch",
            served[-1]["served_source"] if served else "-",
            row["state"],
        ]
        lines.append("| " + " | ".join(values) + " |")
    lines.extend(
        [
            "",
            f"Planned cells: {report['planned']}. Accounting: {json.dumps(report['counts'])}.",
            "",
            "Task definitions: [manifest](manifest.json). Every event: [journal](events.jsonl).",
            "Full decisions/features and receipts: [results](results.json).",
            "Fixture/config qualifications: [environment](environment.json).",
            "",
            "These exports are curated synthetic T4 diagnostics, ineligible for learning.",
            "The manifest retains planned cells; --inspect reports interrupted work.",
        ]
    )
    with (out / "report.md").open("x", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument(
        "--inspect", type=Path, help="Read all planned attempts, including interrupted ones"
    )
    args = parser.parse_args()
    if args.inspect:
        if args.suite or args.out:
            parser.error("--inspect cannot be combined with --suite or --out")
        print(json.dumps(summary(args.inspect), indent=2))
        return 0
    if args.suite is None or args.out is None:
        parser.error("--suite and --out are required")
    data = args.suite.read_bytes()
    suite = Suite.model_validate_json(data)
    out = args.out.resolve()
    if out == ROOT or ROOT in out.parents:
        parser.error("output must be outside the runtime repository")
    os.umask(0o077)
    out.mkdir(parents=True, mode=0o700, exist_ok=False)
    before = source_manifest(ROOT)
    write_new(
        out / "manifest.json",
        {
            "schema_version": "adrl-routing-lab-run-v1",
            "experiment_id": str(uuid4()),
            "created_at": datetime.now(UTC).isoformat(),
            "suite": suite.model_dump(mode="json"),
            "suite_sha256": digest(data),
            "source_manifest": before,
            "eligible_for_learning": False,
            "execution_mode": "simulation",
            "source": "synthetic",
            "evidence_tier": "T4",
            "evidence_origin": "curated_synthetic",
        },
    )
    structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.CRITICAL))
    failed = False
    try:
        asyncio.run(execute(suite, out))
    except (Exception, KeyboardInterrupt) as exc:
        failed = True
        append_event(out, {"type": "run_interrupted", "error_type": type(exc).__name__})
    after = source_manifest(ROOT)
    report = summary(out)
    report["source_unchanged_during_run"] = before == after
    report["run_completed"] = not failed and before == after
    write_new(out / "results.json", report)
    write_report(out, report)
    print(
        json.dumps({k: report[k] for k in ("experiment_id", "counts", "run_completed")}, indent=2)
    )
    return 1 if failed or before != after else 0


if __name__ == "__main__":
    raise SystemExit(main())
