"""Identity minting and hashing. Primary: ADRL-MEM-001. Secondary: ADRL-SEM-002.

route_id is time-ordered so ledger sequences and route ids sort together. Session and lineage
identities are HMACs under a per-deployment key; raw harness values never reach a ledger.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time
from typing import NewType

RouteId = NewType("RouteId", str)
SessionId = NewType("SessionId", str)
LineageId = NewType("LineageId", str)

HMAC_KEY_ID_PREFIX = "hmac-"


def mint_route_id(now_ms: int | None = None) -> RouteId:
    """Mint a UUIDv7-shaped, time-ordered route id.

    Layout: 48-bit unix milliseconds, 4-bit version (7), 12 random bits, 2-bit variant,
    62 random bits, rendered as the canonical 36-character UUID string.
    """
    ms = int(time.time() * 1000) if now_ms is None else now_ms
    rand = os.urandom(10)
    rand_a = int.from_bytes(rand[:2], "big") & 0x0FFF
    rand_b = int.from_bytes(rand[2:], "big") & 0x3FFFFFFFFFFFFFFF
    value = (ms << 80) | (0x7 << 76) | (rand_a << 64) | (0b10 << 62) | rand_b
    hex_str = f"{value:032x}"
    return RouteId(
        f"{hex_str[:8]}-{hex_str[8:12]}-{hex_str[12:16]}-{hex_str[16:20]}-{hex_str[20:]}"
    )


def route_id_timestamp_ms(route_id: RouteId) -> int:
    """Recover the millisecond timestamp embedded in a route id."""
    return int(route_id.replace("-", "")[:12], 16)


def hmac_identity(raw: str, key: bytes) -> str:
    """HMAC-SHA256 of a raw identity under a per-deployment key, hex encoded."""
    return hmac.new(key, raw.encode("utf-8"), hashlib.sha256).hexdigest()


def hmac_key_id(key: bytes) -> str:
    """Stable, non-secret identifier for an HMAC key so rotations can be recorded."""
    return HMAC_KEY_ID_PREFIX + hashlib.sha256(key).hexdigest()[:12]


def session_identity(raw_session_key: str, key: bytes) -> SessionId:
    return SessionId(hmac_identity("session:" + raw_session_key, key))


def lineage_identity(session: SessionId, agent_chain: tuple[str, ...], key: bytes) -> LineageId:
    """Lineage = session plus ordered agent chain; the parent lineage has an empty chain."""
    if not agent_chain:
        return LineageId(session)
    return LineageId(hmac_identity("lineage:" + session + ":" + "/".join(agent_chain), key))
