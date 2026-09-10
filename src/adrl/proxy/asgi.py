"""Starlette application exposing the proxy. Primary: ADRL-FND-001.

Raw routes only: no framework body model touches the request. /v1/messages and
/v1/messages/count_tokens go through the pipeline; /metrics, /healthz and /adrl/v1 are local.
Other paths retain legacy forwarding.
The product namespace rejects unimplemented operations instead of relaying their payloads.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from contextlib import AbstractAsyncContextManager
from typing import Protocol

from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from starlette.applications import Starlette
from starlette.background import BackgroundTask
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from adrl.api.auth import ApiError
from adrl.api.contracts import ProductError, distribution_capabilities
from adrl.api.http import ProductHttp
from adrl.api.service import ProductService
from adrl.core.errors import LedgerAppendFailure
from adrl.proxy.pipeline import ProxyResponse
from adrl.telemetry.metrics import REGISTRY


class RequestHandler(Protocol):
    async def handle(
        self,
        method: str,
        path: str,
        headers: Mapping[str, str],
        body: bytes,
        peer: tuple[str, int] | None,
        *,
        query: str = "",
    ) -> ProxyResponse: ...


PASSTHROUGH_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]


def _peer(request: Request) -> tuple[str, int] | None:
    client = request.client
    if client is None:
        return None
    return (client.host, client.port)


def _to_starlette(result: ProxyResponse) -> Response:
    if result.stream is not None:

        async def body() -> AsyncIterator[bytes]:
            async for chunk in result.stream:  # type: ignore[union-attr]
                yield chunk

        task = BackgroundTask(result.after) if result.after is not None else None
        return StreamingResponse(
            body(), status_code=result.status, headers=result.headers, background=task
        )
    task = BackgroundTask(result.after) if result.after is not None else None
    return Response(
        content=result.body or b"",
        status_code=result.status,
        headers=result.headers,
        background=task,
    )


def build_asgi(
    pipeline: RequestHandler,
    *,
    lifespan: Callable[[Starlette], AbstractAsyncContextManager[None]] | None = None,
    health: Callable[[], Awaitable[dict[str, object]]] | None = None,
    product: Callable[[], ProductService | None] | None = None,
) -> Starlette:
    def model_guard(request: Request) -> Response | None:
        if product is None:
            return None
        try:
            service = product()
            if service is None:
                raise ApiError(503, "temporarily_unavailable", "The product service is starting.")
            for header in (
                "x-adrl-workload-assertion",
                "x-adrl-session-id",
                "x-claude-code-session-id",
            ):
                if len(request.headers.getlist(header)) > 1:
                    raise ApiError(
                        400, "invalid_request", "Duplicate session or credential header."
                    )
            service.guard_model(dict(request.headers), request.method, request.url.path)
        except (ApiError, LedgerAppendFailure) as exc:
            status = exc.status if isinstance(exc, ApiError) else 503
            return JSONResponse(
                {
                    "type": "error",
                    "error": {
                        "type": {
                            401: "authentication_error",
                            403: "permission_error",
                            503: "api_error",
                        }.get(status, "invalid_request_error"),
                        "message": str(exc)
                        if isinstance(exc, ApiError)
                        else "Session state is unavailable.",
                    },
                },
                status_code=status,
            )
        return None

    async def messages(request: Request) -> Response:
        refused = model_guard(request)
        if refused is not None:
            return refused
        body = await request.body()
        result = await pipeline.handle(
            request.method,
            request.url.path,
            dict(request.headers),
            body,
            _peer(request),
            query=request.url.query,
        )
        return _to_starlette(result)

    async def metrics(_: Request) -> Response:
        return Response(generate_latest(REGISTRY), media_type=CONTENT_TYPE_LATEST)

    async def healthz(_: Request) -> Response:
        payload: dict[str, object] = {"ok": True}
        if health is not None:
            payload.update(await health())
        return JSONResponse(payload)

    async def capabilities(_: Request) -> Response:
        return JSONResponse(distribution_capabilities().model_dump(mode="json"))

    async def product_unavailable(_: Request) -> Response:
        # Preview contracts never fall through to a provider with session/event payloads.
        error = ProductError(
            code="not_implemented", message="This ADRL product operation is not implemented."
        )
        return JSONResponse(error.model_dump(mode="json"), status_code=501)

    async def passthrough(request: Request) -> Response:
        refused = model_guard(request)
        if refused is not None:
            return refused
        body = await request.body()
        result = await pipeline.handle(
            request.method,
            request.url.path,
            dict(request.headers),
            body,
            _peer(request),
            query=request.url.query,
        )
        return _to_starlette(result)

    routes = [
        Route("/v1/messages", messages, methods=["POST"]),
        Route("/v1/messages/count_tokens", messages, methods=["POST"]),
        Route("/metrics", metrics, methods=["GET"]),
        Route("/healthz", healthz, methods=["GET"]),
        Route("/adrl/v1/capabilities", capabilities, methods=["GET"]),
        *(ProductHttp(product).routes() if product is not None else []),
        Route("/adrl/v1", product_unavailable, methods=PASSTHROUGH_METHODS),
        Route("/adrl/v1/{path:path}", product_unavailable, methods=PASSTHROUGH_METHODS),
        Route("/{path:path}", passthrough, methods=PASSTHROUGH_METHODS),
    ]
    return Starlette(routes=routes, lifespan=lifespan)
