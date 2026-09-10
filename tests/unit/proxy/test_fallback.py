"""ADRL-FND-004 resolution table tests."""

from __future__ import annotations

import pytest

from adrl.core.enums import FailureClass, RoutingMode, Rung
from adrl.core.errors import ErrorCode
from adrl.proxy.fallback import FallbackAction, resolve_failure


@pytest.mark.parametrize("mode", [RoutingMode.SHADOW, RoutingMode.LIVE])
def test_unpinned_routing_failure_fails_open_upstream(mode: RoutingMode) -> None:
    res = resolve_failure(FailureClass.ROUTING_PATH, pinned=False, mode=mode)
    assert res.action is FallbackAction.FORWARD_UPSTREAM
    assert res.unscanned is False
    assert res.rung is None


def test_unpinned_gate_failure_is_marked_unscanned() -> None:
    res = resolve_failure(FailureClass.GATE_PATH, pinned=False, mode=RoutingMode.SHADOW)
    assert res.action is FallbackAction.FORWARD_UPSTREAM
    assert res.unscanned is True
    assert Rung.FRONTIER in res.permitted


def test_pinned_routing_failure_goes_local_only() -> None:
    res = resolve_failure(FailureClass.ROUTING_PATH, pinned=True, mode=RoutingMode.LIVE)
    assert res.action is FallbackAction.FORWARD_LOCAL
    assert res.rung is Rung.LOCAL
    assert res.permitted.rungs == frozenset({Rung.LOCAL})


def test_pinned_gate_failure_fails_closed() -> None:
    res = resolve_failure(FailureClass.GATE_PATH, pinned=True, mode=RoutingMode.LIVE)
    assert res.action is FallbackAction.BLOCK
    assert res.code is ErrorCode.GATE_UNAVAILABLE


def test_proxy_path_has_no_in_process_fallback() -> None:
    res = resolve_failure(FailureClass.PROXY_PATH, pinned=False, mode=RoutingMode.LIVE)
    assert res.action is FallbackAction.SURFACE


def test_mode_off_surfaces_instead_of_failing_open() -> None:
    res = resolve_failure(FailureClass.ROUTING_PATH, pinned=False, mode=RoutingMode.OFF)
    assert res.action is FallbackAction.SURFACE


def test_unscanned_never_widens_beyond_pin_state() -> None:
    res = resolve_failure(FailureClass.GATE_PATH, pinned=True, mode=RoutingMode.LIVE)
    assert Rung.FRONTIER not in res.permitted
