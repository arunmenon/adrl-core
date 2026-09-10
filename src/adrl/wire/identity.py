"""Session key and lineage identity. Primary: ADRL-SEM-002. Secondary: ADRL-SEM-006.

Preference: x-claude-code-session-id header, then the session_id inside metadata.user_id, then a
per-connection anonymous key. Only HMACs reach the ledger. Lineage is the session plus the agent
chain resolved from the agent-id and parent-agent-id headers.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
from collections import OrderedDict
from collections.abc import Iterable
from dataclasses import dataclass

from adrl.core.ids import LineageId, SessionId, lineage_identity, session_identity
from adrl.wire.adapters import ClaudeCodeAdapter, IdentitySignals
from adrl.wire.adapters import metadata_session_id as metadata_session_id
from adrl.wire.parse import ParsedRequest

SOURCE_HEADER = "header"
SOURCE_METADATA = "metadata"
SOURCE_CONNECTION = "connection"

_MAX_TRACKED = 4096


@dataclass(frozen=True, slots=True)
class Identity:
    session_hmac: SessionId
    lineage_hmac: LineageId
    source: str
    agent_id: str | None
    parent_agent_id: str | None
    agent_chain: tuple[str, ...]
    ancestor_lineages: tuple[LineageId, ...]
    """Ancestor lineages ordered root first; the pin of any ancestor binds this lineage."""

    @property
    def is_subagent(self) -> bool:
        return self.agent_id is not None


def _system_prefix_hash(signals: IdentitySignals, chars: int = 500) -> str:
    return hashlib.sha256(signals.system_text[:chars].encode("utf-8")).hexdigest()[:16]


class _BoundedDict(OrderedDict[str, str]):
    def __init__(self, cap: int) -> None:
        super().__init__()
        self._cap = cap

    def remember(self, key: str, value: str) -> None:
        self[key] = value
        self.move_to_end(key)
        while len(self) > self._cap:
            self.popitem(last=False)


class IdentityResolver:
    """Resolves session and lineage identity for one process.

    Process-local state (metadata epoch cuts, parent map) is declared as such: it feeds only the
    fallback paths and never the pin, which lives in the ledger (ADRL-MEM-006).
    """

    def __init__(self, hmac_key: bytes, *, process_salt: bytes | None = None) -> None:
        self._key = hmac_key
        self._salt = process_salt or os.urandom(16)
        self._metadata_prefix: _BoundedDict = _BoundedDict(_MAX_TRACKED)
        self._metadata_epoch: dict[str, int] = {}
        self._parents: _BoundedDict = _BoundedDict(_MAX_TRACKED)
        self._primed_roots: set[LineageId] = set()

    @property
    def hmac_key(self) -> bytes:
        return self._key

    def session_root(
        self, parsed: ParsedRequest, peer: tuple[str, int] | None, *, is_pre_warm: bool = False
    ) -> LineageId:
        return self.session_root_from_signals(
            ClaudeCodeAdapter().identity_signals(parsed), peer, is_pre_warm=is_pre_warm
        )

    def session_root_from_signals(
        self, signals: IdentitySignals, peer: tuple[str, int] | None, *, is_pre_warm: bool = False
    ) -> LineageId:
        """The session's root lineage, where agent parent relationships are persisted."""
        raw_session, _source = self._raw_session_key(signals, peer, is_pre_warm=is_pre_warm)
        session = session_identity(raw_session, self._key)
        return lineage_identity(session, (), self._key)

    def needs_priming(self, root: LineageId) -> bool:
        return root not in self._primed_roots

    def prime_parents(self, root: LineageId, pairs: Iterable[tuple[str, str]]) -> None:
        """Load persisted (agent_id, parent_agent_id) pairs so the chain survives a restart."""
        for agent_id, parent_id in pairs:
            if agent_id and parent_id and agent_id not in self._parents:
                self._parents.remember(agent_id, parent_id)
        self._primed_roots.add(root)

    def knows_parent(self, agent_id: str) -> bool:
        return agent_id in self._parents

    def resolve(
        self, parsed: ParsedRequest, peer: tuple[str, int] | None, *, is_pre_warm: bool = False
    ) -> Identity:
        return self.resolve_signals(
            ClaudeCodeAdapter().identity_signals(parsed), peer, is_pre_warm=is_pre_warm
        )

    def resolve_signals(
        self, signals: IdentitySignals, peer: tuple[str, int] | None, *, is_pre_warm: bool = False
    ) -> Identity:
        """Resolve correlation signals; workload authorization remains in the gates."""
        raw_session, source = self._raw_session_key(signals, peer, is_pre_warm=is_pre_warm)
        session = session_identity(raw_session, self._key)
        agent_id = signals.agent_id
        parent_id = signals.parent_agent_id
        if agent_id and parent_id:
            self._parents.remember(agent_id, parent_id)
        chain = self._chain(agent_id)
        lineage = lineage_identity(session, chain, self._key)
        ancestors = tuple(
            lineage_identity(session, chain[:i], self._key) for i in range(len(chain))
        )
        return Identity(
            session_hmac=session,
            lineage_hmac=lineage,
            source=source,
            agent_id=agent_id,
            parent_agent_id=parent_id,
            agent_chain=chain,
            ancestor_lineages=ancestors,
        )

    def _chain(self, agent_id: str | None) -> tuple[str, ...]:
        if agent_id is None:
            return ()
        chain: list[str] = [agent_id]
        seen = {agent_id}
        current = agent_id
        while (parent := self._parents.get(current)) is not None and parent not in seen:
            chain.append(parent)
            seen.add(parent)
            current = parent
        chain.reverse()
        return tuple(chain)

    def _raw_session_key(
        self, signals: IdentitySignals, peer: tuple[str, int] | None, *, is_pre_warm: bool
    ) -> tuple[str, str]:
        header = signals.header_session_id
        if header:
            return header, SOURCE_HEADER
        metadata = signals.metadata_session_id
        if metadata:
            return self._metadata_key(metadata, signals, is_pre_warm=is_pre_warm), SOURCE_METADATA
        host, port = peer if peer is not None else ("unknown", 0)
        digest = hashlib.sha256(self._salt + f"{host}:{port}".encode()).hexdigest()[:32]
        return f"conn:{digest}", SOURCE_CONNECTION

    def _metadata_key(self, session_id: str, signals: IdentitySignals, *, is_pre_warm: bool) -> str:
        """Cut a metadata-only session on system-prefix change or a fresh pre-warm burst."""
        prefix = _system_prefix_hash(signals)
        previous = self._metadata_prefix.get(session_id)
        epoch = self._metadata_epoch.get(session_id, 0)
        if previous is None:
            epoch = 0
        elif previous != prefix and not is_pre_warm:
            epoch += 1
        elif is_pre_warm and previous != prefix:
            epoch += 1
        self._metadata_prefix.remember(session_id, prefix)
        self._metadata_epoch[session_id] = epoch
        return f"{session_id}#e{epoch}"


class LineageLocks:
    """One asyncio lock per lineage so gate, route and ledger writes serialise per lineage."""

    def __init__(self, cap: int = _MAX_TRACKED) -> None:
        self._locks: OrderedDict[LineageId, asyncio.Lock] = OrderedDict()
        self._cap = cap

    def get(self, lineage: LineageId) -> asyncio.Lock:
        lock = self._locks.get(lineage)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[lineage] = lock
        self._locks.move_to_end(lineage)
        while len(self._locks) > self._cap:
            oldest, old_lock = next(iter(self._locks.items()))
            if old_lock.locked():
                break
            self._locks.pop(oldest)
        return lock

    def __len__(self) -> int:
        return len(self._locks)
