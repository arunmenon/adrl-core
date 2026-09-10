"""Export the product API preview. Primary: ADRL-SEM-007. Secondary: ADRL-FND-001."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel
from pydantic.json_schema import models_json_schema

from adrl.api.contracts import (
    SCHEMA_VERSION,
    Capabilities,
    DecisionExplanation,
    EventAcknowledgement,
    EventRequest,
    ProductError,
    SessionBinding,
    SessionRequest,
    SessionStatus,
    TimelinePage,
)


def openapi_document() -> dict[str, Any]:
    """Export executable schemas without implying that planned operations have handlers."""
    models: tuple[type[BaseModel], ...] = (
        Capabilities,
        SessionRequest,
        SessionBinding,
        SessionStatus,
        EventRequest,
        EventAcknowledgement,
        ProductError,
        TimelinePage,
        DecisionExplanation,
    )
    _, definitions = models_json_schema(
        [(model, "validation") for model in models], ref_template="#/components/schemas/{model}"
    )

    def response(name: str, description: str) -> dict[str, Any]:
        return {
            "description": description,
            "content": {"application/json": {"schema": {"$ref": f"#/components/schemas/{name}"}}},
        }

    def operation(
        name: str,
        result: str,
        *,
        body: str | None = None,
        implemented: bool = True,
        parameter: str | None = None,
        pagination: bool = False,
    ) -> dict[str, Any]:
        item: dict[str, Any] = {
            "operationId": name,
            "x-adrl-implementation": "implemented" if implemented else "planned",
            "security": [] if name == "getCapabilities" else [{"adrlWorkload": []}],
            "responses": {"200": response(result, "Success")},
        }
        if name != "getCapabilities":
            item["description"] = (
                "Loopback preview using an expiring signed launcher assertion. Root Claude Code "
                "Messages sessions only. Harness observations cannot submit trusted verification."
            )
            for status, description in {
                "400": "Invalid request",
                "401": "Unauthenticated",
                "403": "Forbidden",
                "409": "Conflicting event identity",
                "422": "Unsupported capability",
                "501": "Not implemented",
                "503": "Temporarily unavailable",
            }.items():
                item["responses"][status] = response("ProductError", description)
        if body:
            item["requestBody"] = {
                "required": True,
                "content": {
                    "application/json": {"schema": {"$ref": f"#/components/schemas/{body}"}}
                },
            }
        parameters: list[dict[str, Any]] = []
        if parameter:
            parameters.append(
                {
                    "name": parameter,
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string", "minLength": 1},
                }
            )
        if pagination:
            parameters.extend(
                [
                    {"name": "cursor", "in": "query", "schema": {"type": "string"}},
                    {
                        "name": "limit",
                        "in": "query",
                        "schema": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 100,
                            "default": 50,
                        },
                    },
                ]
            )
        if parameters:
            item["parameters"] = parameters
        return item

    return {
        "openapi": "3.1.0",
        "info": {
            "title": "ADRL product API preview",
            "version": SCHEMA_VERSION,
            "description": "Local session binding and encrypted observation services. "
            "Native model APIs remain defined by their protocol profiles. "
            "Timeline sequence is index order, not tool execution order.",
        },
        "paths": {
            "/adrl/v1/capabilities": {
                "get": operation(
                    "getCapabilities",
                    "Capabilities",
                    implemented=True,
                )
            },
            "/adrl/v1/sessions": {
                "post": operation(
                    "bindSession",
                    "SessionBinding",
                    body="SessionRequest",
                )
            },
            "/adrl/v1/sessions/{session_id}": {
                "get": operation(
                    "getSession",
                    "SessionStatus",
                    parameter="session_id",
                )
            },
            "/adrl/v1/events": {
                "post": operation(
                    "appendEvent",
                    "EventAcknowledgement",
                    body="EventRequest",
                )
            },
            "/adrl/v1/sessions/{session_id}/timeline": {
                "get": operation(
                    "getTimeline",
                    "TimelinePage",
                    parameter="session_id",
                    pagination=True,
                )
            },
            "/adrl/v1/decisions/{route_id}": {
                "get": operation(
                    "getDecision",
                    "DecisionExplanation",
                    parameter="route_id",
                )
            },
        },
        "components": {
            "schemas": definitions["$defs"],
            "securitySchemes": {
                "adrlWorkload": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "x-adrl-workload-assertion",
                    "description": "Expiring assertion from the trusted local launcher, "
                    "bound to the registered workload and explicit session. "
                    "Provider credentials remain separate. Remote issuance is not implemented.",
                }
            },
        },
    }
