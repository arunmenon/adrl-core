"""Static repository and data-class gate. Primary: ADRL-SAF-008.
Also implements: ADRL-TRU-001 (register additions of 2026-09-03).

Repository identity comes from a verified workload assertion (``adrl.gates.workload``); prompt
text, CLAUDE.md mentions and tool inputs can only corroborate it, never establish it, because
everything in the prompt is attacker-shaped. A lineage without a verified assertion is an
unknown workload and stays on the local rung until an assertion arrives
(``unknown_identity_policy: local_only`` in the signed manifest). Manifest lookup is an exact
match on the normalised remote URL or root path. The ceiling tightens monotonically on first
touch of a restricted path prefix. Every classification is a lineage event whose evidence is
keyed hashes only (ADRL-MEM-005): no path, remote or working directory is stored in clear.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import structlog

from adrl.config.models import RepoClass, RepoClassificationManifest, RepoEntry
from adrl.core.enums import Rung
from adrl.core.ids import LineageId
from adrl.core.ports import LedgerPort, LineageEvent
from adrl.core.types import RequestContext
from adrl.gates.content import ScanBlock, touched_paths
from adrl.gates.workload import AssertionVerifier, WorkloadAssertion, normalise_identity

log = structlog.get_logger(__name__)

CLASSIFIED_EVENT = "classified"
UNKNOWN_CLASS_ID = "unknown"
SOURCE_ASSERTION = "assertion"
SOURCE_ASSERTION_DEFAULT = "assertion_default_class"
SOURCE_UNKNOWN = "unknown_identity"
SOURCE_UNVERIFIED_DEFAULT = "default_class_unverified"
SOURCE_RESTRICTED_PREFIX = "restricted_path_prefix"

_WORKDIR = re.compile(
    r"(?:Primary working directory|Working directory|cwd)\s*[:=]\s*([^\s\n]+)", re.IGNORECASE
)
_CLAUDE_MD = re.compile(r"Contents of (\S+?)/(?:CLAUDE|AGENTS)\.md", re.IGNORECASE)
_REMOTE = re.compile(
    r"((?:git@|https?://|ssh://)[A-Za-z0-9._-]+[:/][A-Za-z0-9._/-]+?(?:\.git)?)(?=[\s\"')]|$)"
)


def _keyed(secret: bytes | None, text: str) -> str | None:
    if secret is None:
        return None
    return hmac.new(secret, text.encode(), hashlib.sha256).hexdigest()


@dataclass(frozen=True, slots=True)
class RepoClassification:
    repo_id: str | None
    class_id: str
    allowed_rungs: frozenset[Rung]
    residency: str | None
    restricted: bool
    release_permitted: bool
    source: str
    evidence: tuple[str, ...]
    restricted_prefix_hit: bool = False
    assertion_id: str | None = None
    corroborated: bool = False

    @property
    def identity_verified(self) -> bool:
        return self.assertion_id is not None

    def as_payload(self) -> dict[str, Any]:
        """Lineage-event payload: identifiers, policy outcome and keyed evidence only."""
        return {
            "repo_id": self.repo_id,
            "class_id": self.class_id,
            "allowed_rungs": sorted(r.value for r in self.allowed_rungs),
            "residency": self.residency,
            "restricted": self.restricted,
            "release_permitted": self.release_permitted,
            "source": self.source,
            "evidence_hashes": list(self.evidence),
            "restricted_prefix_hit": self.restricted_prefix_hit,
            "assertion_id": self.assertion_id,
            "corroborated": self.corroborated,
        }


class RepoClassifier:
    """Resolves and remembers the classification ceiling per lineage."""

    def __init__(
        self,
        manifest: RepoClassificationManifest,
        ledger: LedgerPort,
        *,
        assertions: AssertionVerifier | None = None,
        path_secret: bytes | None = None,
    ) -> None:
        self._manifest = manifest
        self._ledger = ledger
        self._assertions = assertions
        self._path_secret = path_secret
        self._ceiling: dict[LineageId, RepoClassification] = {}
        self._loaded: set[LineageId] = set()
        self._entries: dict[str, RepoEntry] = {
            normalise_identity(entry.match): entry for entry in manifest.repos
        }

    @property
    def manifest(self) -> RepoClassificationManifest:
        return self._manifest

    # evidence collection -----------------------------------------------------------------

    @staticmethod
    def candidate_identities(body: Mapping[str, Any], blocks: Sequence[ScanBlock]) -> list[str]:
        """Prompt-derived identities: untrusted, used only to corroborate an assertion."""
        found: dict[str, None] = {}
        system_text = _system_text(body)
        for match in _WORKDIR.finditer(system_text):
            found.setdefault(match.group(1).rstrip("/"), None)
        for match in _CLAUDE_MD.finditer(system_text):
            found.setdefault(match.group(1).rstrip("/"), None)
        for match in _REMOTE.finditer(system_text):
            found.setdefault(match.group(1), None)
        for block in blocks:
            if block.content_type in {"tool_use", "tool_result"} and block.text:
                for match in _REMOTE.finditer(block.text[:4000]):
                    found.setdefault(match.group(1), None)
        for path in touched_paths(blocks):
            found.setdefault(path, None)
        return list(found)

    def _entry_for(self, identities: Sequence[str]) -> tuple[RepoEntry, str] | None:
        for identity in identities:
            entry = self._entries.get(normalise_identity(identity))
            if entry is not None:
                return entry, identity
        return None

    def _class(self, class_id: str) -> RepoClass:
        return self._manifest.class_by_id(class_id)

    def _unknown_class(self) -> RepoClass:
        default = self._class(self._manifest.default_class_id)
        return RepoClass(
            class_id=UNKNOWN_CLASS_ID,
            allowed_rungs=(Rung.LOCAL,),
            residency=None,
            release_permitted=default.release_permitted,
            restricted=False,
        )

    def _evidence(self, *items: str | None) -> tuple[str, ...]:
        out: list[str] = []
        for item in items:
            if item:
                keyed = _keyed(self._path_secret, item)
                if keyed is not None:
                    out.append(keyed)
        return tuple(out)

    # resolution ------------------------------------------------------------------------

    def resolve(
        self,
        body: Mapping[str, Any],
        blocks: Sequence[ScanBlock],
        assertion: WorkloadAssertion | None,
    ) -> RepoClassification:
        prompt_identities = self.candidate_identities(body, blocks)
        if assertion is None:
            if self._manifest.unknown_identity_policy == "default_class":
                cls = self._class(self._manifest.default_class_id)
                source = SOURCE_UNVERIFIED_DEFAULT
            else:
                cls = self._unknown_class()
                source = SOURCE_UNKNOWN
            return RepoClassification(
                repo_id=None,
                class_id=cls.class_id,
                allowed_rungs=frozenset(cls.allowed_rungs),
                residency=cls.residency,
                restricted=cls.restricted,
                release_permitted=cls.release_permitted,
                source=source,
                evidence=self._evidence(*prompt_identities[:3]),
            )

        asserted = assertion.identities()
        corroborated = any(
            normalise_identity(candidate) in {normalise_identity(a) for a in asserted}
            for candidate in prompt_identities
        )
        matched = self._entry_for(asserted)
        if matched is None:
            default = self._class(self._manifest.default_class_id)
            return RepoClassification(
                repo_id=None,
                class_id=default.class_id,
                allowed_rungs=frozenset(default.allowed_rungs),
                residency=default.residency,
                restricted=default.restricted,
                release_permitted=default.release_permitted,
                source=SOURCE_ASSERTION_DEFAULT,
                evidence=self._evidence(*asserted),
                assertion_id=assertion.assertion_id,
                corroborated=corroborated,
            )
        entry, identity = matched
        cls = self._class(entry.class_id)
        prefix_hit: str | None = None
        if entry.restricted_path_prefixes:
            for path in touched_paths(blocks):
                for prefix in entry.restricted_path_prefixes:
                    if path.startswith(prefix):
                        prefix_hit = prefix
                        break
                if prefix_hit:
                    break
        if prefix_hit is not None:
            restricted_cls = next(
                (c for c in self._manifest.classes if c.restricted), self._class("restricted")
            )
            return RepoClassification(
                repo_id=entry.repo_id,
                class_id=restricted_cls.class_id,
                allowed_rungs=frozenset(restricted_cls.allowed_rungs),
                residency=cls.residency or restricted_cls.residency,
                restricted=True,
                release_permitted=False,
                source=SOURCE_RESTRICTED_PREFIX,
                evidence=self._evidence(identity, prefix_hit),
                restricted_prefix_hit=True,
                assertion_id=assertion.assertion_id,
                corroborated=corroborated,
            )
        return RepoClassification(
            repo_id=entry.repo_id,
            class_id=cls.class_id,
            allowed_rungs=frozenset(cls.allowed_rungs),
            residency=cls.residency,
            restricted=cls.restricted,
            release_permitted=cls.release_permitted,
            source=SOURCE_ASSERTION,
            evidence=self._evidence(identity),
            assertion_id=assertion.assertion_id,
            corroborated=corroborated,
        )

    # monotone lineage ceiling ---------------------------------------------------------------

    async def _load(self, lineage: LineageId) -> None:
        if lineage in self._loaded:
            return
        for event in await self._ledger.read_lineage_events(lineage, CLASSIFIED_EVENT):
            payload = event.payload
            self._ceiling[lineage] = RepoClassification(
                repo_id=payload.get("repo_id"),
                class_id=str(payload.get("class_id")),
                allowed_rungs=frozenset(Rung(r) for r in payload.get("allowed_rungs", [])),
                residency=payload.get("residency"),
                restricted=bool(payload.get("restricted")),
                release_permitted=bool(payload.get("release_permitted", True)),
                source=str(payload.get("source", "ledger")),
                evidence=tuple(payload.get("evidence_hashes", [])),
                restricted_prefix_hit=bool(payload.get("restricted_prefix_hit", False)),
                assertion_id=payload.get("assertion_id"),
                corroborated=bool(payload.get("corroborated", False)),
            )
        self._loaded.add(lineage)

    def _assertion_for(self, ctx: RequestContext) -> WorkloadAssertion | None:
        if self._assertions is None:
            return None
        return self._assertions.resolve(ctx).assertion

    async def classify(
        self, ctx: RequestContext, blocks: Sequence[ScanBlock]
    ) -> RepoClassification:
        """Resolve for this request and combine with the lineage's existing ceiling.

        The ceiling only tightens, with one stated exception: a lineage whose only prior
        classification was ``unknown_identity`` (absence of evidence, not a finding) takes the
        asserted class when a verified assertion first arrives. Restricted and assertion-backed
        ceilings never widen. Pins are separate and never affected here.
        """
        await self._load(ctx.lineage_hmac)
        fresh = self.resolve(ctx.json, blocks, self._assertion_for(ctx))
        prior = self._ceiling.get(ctx.lineage_hmac)
        if prior is None:
            combined = fresh
        elif (
            prior.source == SOURCE_UNKNOWN
            and fresh.identity_verified
            and not prior.restricted
            and not prior.restricted_prefix_hit
        ):
            combined = fresh
        else:
            allowed = prior.allowed_rungs & fresh.allowed_rungs
            if fresh.restricted and not prior.restricted:
                allowed = fresh.allowed_rungs
            combined = RepoClassification(
                repo_id=fresh.repo_id or prior.repo_id,
                class_id=fresh.class_id if fresh.restricted else prior.class_id,
                allowed_rungs=allowed,
                residency=prior.residency or fresh.residency,
                restricted=prior.restricted or fresh.restricted,
                release_permitted=prior.release_permitted and fresh.release_permitted,
                source=fresh.source if fresh.restricted else prior.source,
                evidence=prior.evidence if not fresh.restricted else fresh.evidence,
                restricted_prefix_hit=prior.restricted_prefix_hit or fresh.restricted_prefix_hit,
                assertion_id=prior.assertion_id or fresh.assertion_id,
                corroborated=prior.corroborated or fresh.corroborated,
            )
        changed = (
            prior is None
            or combined.allowed_rungs != prior.allowed_rungs
            or combined.source != prior.source
        )
        if changed:
            self._ceiling[ctx.lineage_hmac] = combined
            await self._ledger.append_lineage_event(
                LineageEvent(
                    lineage_hmac=ctx.lineage_hmac,
                    event_type=CLASSIFIED_EVENT,
                    payload=combined.as_payload(),
                )
            )
            log.info(
                "lineage_classified",
                class_id=combined.class_id,
                source=combined.source,
                verified=combined.identity_verified,
                allowed=sorted(r.value for r in combined.allowed_rungs),
            )
        return combined

    async def current(self, lineage: LineageId) -> RepoClassification | None:
        await self._load(lineage)
        return self._ceiling.get(lineage)


def _system_text(body: Mapping[str, Any]) -> str:
    system = body.get("system")
    if isinstance(system, str):
        return system
    if isinstance(system, list):
        parts = []
        for block in system:
            if isinstance(block, Mapping):
                parts.append(str(block.get("text", "")))
            else:
                parts.append(str(block))
        return "\n".join(parts)
    return ""
