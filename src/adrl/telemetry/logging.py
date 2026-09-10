"""structlog JSON logging with contextvars. Primary: ADRL-OPS-001 (referenced by gloss)."""

from __future__ import annotations

import logging
import sys

import structlog


def configure_logging(*, json_output: bool = True, level: int = logging.INFO) -> None:
    logging.basicConfig(stream=sys.stderr, level=level, format="%(message)s")
    renderer: structlog.types.Processor = (
        structlog.processors.JSONRenderer() if json_output else structlog.dev.ConsoleRenderer()
    )
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=False,
    )


def bind_request(
    *, route_id: str | None = None, lineage: str | None = None, request_class: str | None = None
) -> None:
    """Bind per-request identifiers; never bind raw session keys or content."""
    structlog.contextvars.clear_contextvars()
    fields: dict[str, str] = {}
    if route_id:
        fields["route_id"] = route_id
    if lineage:
        fields["lineage"] = lineage
    if request_class:
        fields["request_class"] = request_class
    structlog.contextvars.bind_contextvars(**fields)
