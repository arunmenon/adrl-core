"""Local product HTTP boundary. Primary: ADRL-SEM-007. Secondary: ADRL-TRU-001.

No product operation can fall through to the model gateway. Invalid input errors never echo
request bodies, credentials or validation details that may contain private data.
"""

from __future__ import annotations

import ipaddress
import sqlite3
from collections.abc import Callable

from cryptography.exceptions import InvalidTag
from pydantic import BaseModel, ValidationError
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from adrl.api.auth import ApiError
from adrl.api.contracts import EventRequest, ProductError, SessionRequest
from adrl.api.service import ProductService
from adrl.core.errors import LedgerAppendFailure

BODY_LIMIT = 65536


def error_response(error: ApiError) -> JSONResponse:
    return JSONResponse(
        error.error.model_dump(mode="json"),
        status_code=error.status,
        headers={"Cache-Control": "no-store"},
    )


class ProductHttp:
    def __init__(self, service: Callable[[], ProductService | None]) -> None:
        self.service = service

    async def handle(self, request: Request) -> JSONResponse:
        try:
            try:
                local = (
                    request.client is not None
                    and ipaddress.ip_address(request.client.host).is_loopback
                )
            except ValueError:
                local = False
            if not local:
                raise ApiError(403, "forbidden", "This product API supports loopback clients only.")
            if len(request.headers.getlist("x-adrl-workload-assertion")) != 1:
                raise ApiError(401, "unauthenticated", "One workload assertion is required.")
            service = self.service()
            if service is None:
                raise ApiError(
                    503, "temporarily_unavailable", "The product service is unavailable."
                )
            headers = dict(request.headers)
            service.principal(headers)
            path = request.url.path
            result: BaseModel
            if request.method == "POST":
                body = bytearray()
                async for chunk in request.stream():
                    body.extend(chunk)
                    if len(body) > BODY_LIMIT:
                        raise ApiError(
                            400, "invalid_request", "Product request exceeds the size limit."
                        )
                try:
                    if path == "/adrl/v1/sessions":
                        binding = SessionRequest.model_validate_json(bytes(body))
                    else:
                        event = EventRequest.model_validate_json(bytes(body))
                except ValidationError as exc:
                    raise ApiError(400, "invalid_request", "Invalid product request.") from exc
                if path == "/adrl/v1/sessions":
                    result = await service.bind(headers, binding)
                else:
                    result = await service.append(headers, event)
            elif path.endswith("/timeline"):
                try:
                    limit = int(request.query_params.get("limit", "50"))
                except ValueError as exc:
                    raise ApiError(400, "invalid_request", "Invalid page limit.") from exc
                result = await service.timeline(
                    headers,
                    request.path_params["session_id"],
                    cursor=request.query_params.get("cursor"),
                    limit=limit,
                )
            elif "route_id" in request.path_params:
                result = service.explain(headers, request.path_params["route_id"])
            else:
                result = service.status(headers, request.path_params["session_id"])
            return JSONResponse(
                result.model_dump(mode="json"), headers={"Cache-Control": "no-store"}
            )
        except ApiError as exc:
            return error_response(exc)
        except (LedgerAppendFailure, sqlite3.Error, OSError, InvalidTag, ValueError):
            error = ProductError(
                code="temporarily_unavailable", message="Product evidence is unavailable."
            )
            return JSONResponse(
                error.model_dump(mode="json"),
                status_code=503,
                headers={"Cache-Control": "no-store"},
            )

    def routes(self) -> list[Route]:
        return [
            Route("/adrl/v1/sessions", self.handle, methods=["POST"]),
            Route("/adrl/v1/sessions/{session_id}/timeline", self.handle, methods=["GET"]),
            Route("/adrl/v1/sessions/{session_id}", self.handle, methods=["GET"]),
            Route("/adrl/v1/events", self.handle, methods=["POST"]),
            Route("/adrl/v1/decisions/{route_id}", self.handle, methods=["GET"]),
        ]
