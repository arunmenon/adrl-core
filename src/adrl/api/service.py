"""Local product service. Primary: ADRL-SEM-007. Secondary: ADRL-TRU-001, ADRL-MEM-001.

Bindings reuse launcher assertions; observation authority never implies verifier authority.
Reads expose typed observations and references, never arbitrary internal event payloads.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from adrl.api.auth import PRODUCT_SESSION_HEADER, ApiError, Principal, authenticate
from adrl.api.contracts import (
    CoverageFact,
    DecisionExplanation,
    DispatchEvidence,
    EventAcknowledgement,
    EventRequest,
    IntegrationMode,
    SessionBinding,
    SessionRequest,
    SessionStatus,
    TimelineEntry,
    TimelinePage,
    VersionRef,
)
from adrl.api.store import ProductStore
from adrl.config.loaders import ConfigBundle
from adrl.core.ids import session_identity
from adrl.gates.workload import HEADER_SESSION_ID
from adrl.ledger.keystore import FileKeyStore
from adrl.ledger.store import LedgerStore
from adrl.wire.profiles.messages import MessagesProfile


class ProductService:
    def __init__(self, store: LedgerStore, keys: FileKeyStore, bundle: ConfigBundle) -> None:
        self.data = ProductStore(store, keys)
        self.bundle = bundle
        self.key = keys.hmac_key()
        # Include actual contents, not just reusable version labels.
        encoded = json.dumps(
            {
                "repo": bundle.repo_classification.model_dump(mode="json"),
                "policy": bundle.policy.model_dump(mode="json"),
                "inventory": bundle.endpoint_inventory.model_dump(mode="json"),
            },
            sort_keys=True,
        ).encode()
        self.config_digest = hashlib.sha256(encoded).hexdigest()

    def principal(self, headers: Mapping[str, str]) -> Principal:
        if not self.bundle.manifest_signature_verified:
            raise ApiError(
                503, "temporarily_unavailable", "A verified repository manifest is required."
            )
        return authenticate(headers, self.key, self.bundle.repo_classification)

    def _binding(self, principal: Principal, session_id: str) -> dict[str, Any]:
        if principal.session_id != session_id:
            raise ApiError(403, "forbidden", "This credential does not authorize that session.")
        row = self.data.binding(principal.session_hmac)
        if row is None or row["workload_ref"] != principal.workload_ref:
            raise ApiError(403, "forbidden", "A matching product session binding is required.")
        if row["config_digest"] != self.config_digest:
            raise ApiError(
                409, "event_conflict", "Configuration changed; operator reconciliation is required."
            )
        return row

    def _status(self, principal: Principal, row: dict[str, Any]) -> SessionStatus:
        return SessionStatus(
            session_id=principal.session_id,
            workload_ref=principal.workload_ref,
            integration_mode=row["integration_mode"],
            policy=VersionRef(id="adrl-policy", version=row["policy_version"]),
            adapter=VersionRef(id=row["adapter_id"], version=row["adapter_version"]),
            profile=VersionRef(id=row["profile_id"], version=row["profile_version"]),
            coverage=(
                CoverageFact(dimension="identity_binding", status="enforced"),
                CoverageFact(
                    dimension="request_interception",
                    status="unavailable" if row["integration_mode"] == "observe" else "unknown",
                ),
                CoverageFact(
                    dimension="content_inspection",
                    status="unavailable" if row["integration_mode"] == "observe" else "unknown",
                ),
                CoverageFact(
                    dimension="dispatch_enforcement",
                    status="unavailable" if row["integration_mode"] == "observe" else "unknown",
                ),
                CoverageFact(dimension="tool_events", status="unknown"),
                CoverageFact(dimension="lineage", status="unknown"),
                CoverageFact(
                    dimension="served_destination",
                    status="unavailable" if row["integration_mode"] == "observe" else "unknown",
                ),
                CoverageFact(dimension="outcome_verification", status="unknown"),
            ),
        )

    async def bind(self, headers: Mapping[str, str], request: SessionRequest) -> SessionBinding:
        principal = self.principal(headers)
        if request.workload_ref != principal.workload_ref:
            raise ApiError(403, "forbidden", "The credential does not authorize that workload.")
        if (
            request.adapter != VersionRef(id="claude-code", version="1")
            or request.profile != VersionRef(id="anthropic-messages-v1", version="1")
            or request.parent_session_id is not None
        ):
            raise ApiError(
                422,
                "unsupported_capability",
                "Only root Claude Code Messages binding is supported.",
            )
        if self.data.was_erased(principal.session_hmac):
            raise ApiError(403, "forbidden", "An erased evidence session cannot be rebound.")
        prior = self.data.binding(principal.session_hmac)
        if prior is not None:
            self._binding(principal, principal.session_id)
            if not self.data.keys.has_session_key(principal.session_hmac):
                raise ApiError(403, "forbidden", "The existing evidence key is unavailable.")
        else:
            self.data.keys.create_session_key(principal.session_hmac)
        row = await self.data.bind(
            principal, request, self.bundle.policy.version, self.config_digest
        )
        return SessionBinding(
            session=self._status(principal, row),
            credential_ref="assertion:" + principal.assertion.assertion_id,
            expires_at=datetime.fromtimestamp(principal.assertion.expires_at, UTC),
        )

    def status(self, headers: Mapping[str, str], session_id: str) -> SessionStatus:
        principal = self.principal(headers)
        return self._status(principal, self._binding(principal, session_id))

    async def append(self, headers: Mapping[str, str], event: EventRequest) -> EventAcknowledgement:
        principal = self.principal(headers)
        self._binding(principal, event.root.session_id)
        if event.root.event_type == "verification.completed":
            raise ApiError(
                403, "forbidden", "Harness credentials cannot submit trusted verification."
            )
        if event.root.route_id is not None:
            self._decision(principal, event.root.route_id)
        return await self.data.append(principal, event)

    def _decision(self, principal: Principal, route_id: str) -> dict[str, Any]:
        row = self.data.ledger.read_decision(route_id)
        if row is None or row["session_hmac"] != principal.session_hmac:
            raise ApiError(403, "forbidden", "This credential does not authorize that decision.")
        return dict(row)

    def guard_model(self, headers: Mapping[str, str], method: str, path: str) -> None:
        """Reject inconsistent or unsupported traffic for explicitly bound product sessions.

        Unbound traffic keeps its separately documented legacy scope. Omitting all identity
        signals does not create a globally enforcing listener; that remains release work.
        """
        sid = headers.get(PRODUCT_SESSION_HEADER) or headers.get(HEADER_SESSION_ID)
        if not sid:
            return
        bound = self.data.binding(session_identity(sid, self.key))
        if bound is None and PRODUCT_SESSION_HEADER not in headers:
            return
        principal = self.principal(headers)
        row = self._binding(principal, sid)
        if row["integration_mode"] == IntegrationMode.OBSERVE:
            raise ApiError(403, "forbidden", "Observation-only sessions cannot dispatch models.")
        if headers.get(HEADER_SESSION_ID) != sid:
            raise ApiError(
                403, "forbidden", "Bound model requests require the matching session header."
            )
        if method != "POST" or path not in MessagesProfile().endpoints:
            raise ApiError(
                422, "unsupported_capability", "This endpoint is outside the bound profile."
            )

    def _cursor(self, session: str, seq: int) -> str:
        body = str(seq)
        tag = hmac.new(self.key, f"timeline:{session}:{body}".encode(), hashlib.sha256).hexdigest()[
            :32
        ]
        return body + ":" + tag

    def _position(self, session: str, cursor: str | None) -> int:
        if cursor is None:
            return 0
        try:
            body, _tag = cursor.split(":")
            seq = int(body)
            valid = 0 <= seq <= 2**63 - 1 and hmac.compare_digest(
                cursor, self._cursor(session, seq)
            )
        except (ValueError, TypeError):
            valid = False
            seq = 0
        if not valid:
            raise ApiError(400, "invalid_request", "Invalid timeline cursor.")
        return seq

    async def timeline(
        self, headers: Mapping[str, str], session_id: str, *, cursor: str | None, limit: int
    ) -> TimelinePage:
        principal = self.principal(headers)
        self._binding(principal, session_id)
        if not 1 <= limit <= 100:
            raise ApiError(400, "invalid_request", "Limit must be between 1 and 100.")
        position = self._position(principal.session_hmac, cursor)
        await self.data.index_timeline(principal.session_hmac)
        rows = self.data.ledger.read(
            "SELECT * FROM product_timeline WHERE session_hmac=? AND seq>? ORDER BY seq LIMIT ?",
            (principal.session_hmac, position, limit + 1),
        )
        entries: list[TimelineEntry] = []
        for row in rows[:limit]:
            source = row["source"]
            ref = f"{source}:{row['source_seq']}"
            material: dict[str, Any] = {
                "ledger_sequence": row["seq"],
                "record_ref": ref,
                "route_id": row["route_id"],
                "evidence_ref": ref,
                "recorded_at": row["ts"],
                "kind": "decision" if source == "decision" else "observation",
            }
            if source == "observation":
                event_row = dict(
                    self.data.ledger.read(
                        "SELECT * FROM product_events WHERE seq=?", (row["source_seq"],)
                    )[0]
                )
                observation = self.data.observation(event_row)
                material.update(
                    event_type=event_row["event_type"],
                    observation=observation,
                    payload_state="erased" if observation is None else "available",
                )
            elif source == "local_verification":
                event_row = dict(
                    self.data.ledger.read(
                        "SELECT * FROM product_verifications WHERE seq=?", (row["source_seq"],)
                    )[0]
                )
                receipt = self.data.verification(event_row)
                material.update(
                    kind="verification",
                    event_type="verification." + event_row["phase"],
                    verification=receipt,
                    payload_state="erased" if receipt is None else "available",
                )
            elif source == "internal":
                event_row = dict(
                    self.data.ledger.read(
                        "SELECT event_type FROM events WHERE seq=?", (row["source_seq"],)
                    )[0]
                )
                event_type = event_row["event_type"]
                material["event_type"] = event_type
                if event_type in {"served", "upstream_error"}:
                    material["kind"] = "dispatch"
                elif event_type == "verification":
                    material["kind"] = "verification"
            entries.append(TimelineEntry.model_validate(material))
        next_cursor = (
            self._cursor(principal.session_hmac, rows[limit - 1]["seq"])
            if len(rows) > limit
            else None
        )
        return TimelinePage(session_id=session_id, entries=tuple(entries), next_cursor=next_cursor)

    def explain(self, headers: Mapping[str, str], route_id: str) -> DecisionExplanation:
        principal = self.principal(headers)
        self._binding(principal, principal.session_id)
        decision = self._decision(principal, route_id)
        context = json.loads(decision["context_json"])
        attempts: list[DispatchEvidence] = []
        gaps: list[str] = []
        for row in self.data.ledger.read_events(route_id):
            if row["event_type"] not in {"served", "upstream_error"}:
                continue
            payload = json.loads(row["payload_json"])
            intended = payload.get("intended_deployment_id")
            if intended is None:
                gaps.append("intended_deployment_unknown")
                continue
            source = payload.get("served_source", "unknown")
            confidence = {
                "gateway_reported": "gateway_reported",
                "proxy_observed": "model_reported",
                "assumed_intended": "assumed_intended",
            }.get(source, "unknown")
            # A receipt flag cannot be inferred from the requested alias.
            served = (
                payload.get("served_deployment_id") if payload.get("receipt_confirmed") else None
            )
            attempts.append(
                DispatchEvidence.model_validate(
                    {
                        "attempt_id": f"event:{row['seq']}",
                        "intended_deployment_ref": intended,
                        "served_deployment_ref": served,
                        "confidence": confidence,
                        "evidence_ref": f"internal:{row['seq']}",
                    }
                )
            )
        if not attempts:
            gaps.append("dispatch_evidence_unavailable")
        if not context.get("protocol_profile_id") or not context.get("harness_adapter_id"):
            gaps.append("historical_profile_or_adapter_unknown")
        reasons = ["recorded_decision", "estimator:" + decision["estimator"]]
        if decision["no_rung_met_threshold"]:
            reasons.append("no_rung_met_threshold")
        return DecisionExplanation(
            route_id=route_id,
            session_id=principal.session_id,
            policy=VersionRef(id="adrl-policy", version=decision["policy_version"]),
            profile=VersionRef(
                id=context.get("protocol_profile_id") or "unknown",
                version=context.get("protocol_profile_version") or "unknown",
            ),
            adapter=VersionRef(
                id=context.get("harness_adapter_id") or "unknown",
                version=context.get("harness_adapter_version") or "unknown",
            ),
            reason_codes=tuple(reasons),
            attempts=tuple(attempts),
            decided_rung=decision["decided_rung"],
            evidence_gaps=tuple(sorted(set(gaps))),
        )
