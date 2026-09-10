"""Gateway client: one attempt, verbatim relay. Primary: ADRL-CAS-007. Secondary: ADRL-FND-001.

httpx performs no retries here. Response bytes are yielded exactly as received while the observer
reads the same chunks; nothing is buffered or re-encoded.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping
from typing import Any

import httpx

from adrl.core.enums import Rung
from adrl.core.errors import AdrlError, ErrorCode
from adrl.wire.profiles.base import StreamObserver


class UpstreamUnreachableError(AdrlError):
    """Transport-level failure before any byte was received (ADRL-CAS-007)."""

    code = ErrorCode.TERMINAL_FAILURE


class HttpxStreamingResponse:
    """StreamingResponse port over an httpx streaming response."""

    def __init__(self, response: httpx.Response) -> None:
        self._response = response

    @property
    def status_code(self) -> int:
        return self._response.status_code

    @property
    def headers(self) -> Mapping[str, str]:
        return dict(self._response.headers.items())

    def aiter_raw(self) -> AsyncIterator[bytes]:
        return self._response.aiter_raw()

    async def aclose(self) -> None:
        await self._response.aclose()


class HttpxGatewayClient:
    """GatewayClient port. Exactly one HTTP attempt per call; no retries, no fallbacks."""

    def __init__(
        self,
        base_url: str,
        *,
        client: httpx.AsyncClient | None = None,
        timeout_s: float = 600.0,
        health_path: str = "/health",
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout_s
        self._health_path = health_path
        self._owned = client is None
        self._client = client or httpx.AsyncClient(
            base_url=self._base_url,
            timeout=httpx.Timeout(timeout_s, connect=10.0),
            transport=httpx.AsyncHTTPTransport(retries=0),
        )

    @property
    def client(self) -> httpx.AsyncClient:
        """The underlying client, shared with the gateway health reader (ADRL-FND-002)."""
        return self._client

    async def send(
        self,
        body: bytes,
        headers: Mapping[str, str],
        *,
        path: str,
        rung: Rung,
        timeout_s: float | None = None,
    ) -> HttpxStreamingResponse:
        request = self._client.build_request(
            "POST",
            path,
            content=body,
            headers=dict(headers),
            timeout=httpx.Timeout(timeout_s or self._timeout, connect=10.0),
        )
        try:
            response = await self._client.send(request, stream=True)
        except httpx.TransportError as exc:
            raise UpstreamUnreachableError(
                f"gateway unreachable for rung {rung.value}: {exc}"
            ) from exc
        return HttpxStreamingResponse(response)

    async def forward(
        self, method: str, path: str, headers: Mapping[str, str], body: bytes
    ) -> HttpxStreamingResponse:
        """Non-API passthrough with the original method (ADRL-SEM-001 non_api class)."""
        request = self._client.build_request(method, path, content=body, headers=dict(headers))
        try:
            response = await self._client.send(request, stream=True)
        except httpx.TransportError as exc:
            raise UpstreamUnreachableError(f"gateway unreachable: {exc}") from exc
        return HttpxStreamingResponse(response)

    async def health(self) -> Mapping[str, Any]:
        try:
            response = await self._client.get(self._health_path, timeout=5.0)
        except httpx.TransportError as exc:
            return {"available": False, "error": str(exc)}
        try:
            data = response.json()
        except ValueError:
            data = {}
        return {"available": response.status_code < 500, "status": response.status_code, **data}

    async def aclose(self) -> None:
        if self._owned:
            await self._client.aclose()


async def relay(response: HttpxStreamingResponse, observer: StreamObserver) -> AsyncIterator[bytes]:
    """Yield upstream chunks verbatim while feeding the observer the same bytes."""
    try:
        async for chunk in response.aiter_raw():
            observer.feed(chunk)
            yield chunk
    finally:
        await response.aclose()


async def read_all(response: HttpxStreamingResponse) -> bytes:
    chunks: list[bytes] = []
    try:
        async for chunk in response.aiter_raw():
            chunks.append(chunk)
    finally:
        await response.aclose()
    return b"".join(chunks)
