"""Load-time configuration checks. Primary: ADRL-FND-002.
Also implements: ADRL-OPS-003 (register additions of 2026-09-03).

Secondary: ADRL-RTG-001 (evidence before live), ADRL-SAF-005 (compaction feasibility),
ADRL-LRN-004 (deny-list), ADRL-CAS-002 (enum version).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from adrl.config.loaders import ConfigBundle
from adrl.config.settings import Settings
from adrl.core.enums import FAILURE_TYPES_VERSION, RoutingMode, Rung
from adrl.core.errors import ConfigError


@dataclass(frozen=True, slots=True)
class CheckResult:
    name: str
    ok: bool
    detail: str = ""


def check_rung_closed_membership(bundle: ConfigBundle) -> CheckResult:
    seen: dict[str, Rung] = {}
    for rung, spec in bundle.rungs.rungs.items():
        for member in spec.members:
            if member in seen:
                return CheckResult(
                    "rung_closed_membership",
                    False,
                    f"model group {member!r} is in both {seen[member].value} and {rung.value}",
                )
            seen[member] = rung
    return CheckResult("rung_closed_membership", True)


def check_fallback_groups_within_rung(bundle: ConfigBundle) -> CheckResult:
    group_to_rung = bundle.rungs.group_to_rung
    for group in bundle.rungs.fallback_groups:
        if group.primary not in group_to_rung:
            return CheckResult(
                "fallback_within_rung", False, f"fallback primary {group.primary!r} is in no rung"
            )
        rung = group_to_rung[group.primary]
        for fallback in group.fallbacks:
            if group_to_rung.get(fallback) is not rung:
                return CheckResult(
                    "fallback_within_rung",
                    False,
                    f"fallback group {group.primary!r} spans rungs via {fallback!r}",
                )
    return CheckResult("fallback_within_rung", True)


def check_live_rung_has_evidence(bundle: ConfigBundle, settings: Settings) -> CheckResult:
    if settings.routing_mode is not RoutingMode.LIVE:
        return CheckResult("live_rung_has_evidence", True, "routing not live")
    for rung, spec in bundle.rungs.rungs.items():
        if spec.enabled and spec.boundary.evidence_ref is None:
            return CheckResult(
                "live_rung_has_evidence",
                False,
                f"rung {rung.value} is enabled in live mode without an evidence_ref",
            )
    return CheckResult("live_rung_has_evidence", True)


def check_compaction_feasibility(bundle: ConfigBundle) -> CheckResult:
    local = bundle.rungs.rungs.get(Rung.LOCAL)
    if local is None or not local.enabled:
        return CheckResult("compaction_feasibility", True, "no local rung")
    needed = bundle.rungs.compaction_window_tokens + bundle.rungs.compaction_overhead_tokens
    if local.boundary.context_ceiling < needed:
        return CheckResult(
            "compaction_feasibility",
            False,
            "pinned lineages will deadlock: largest local context "
            f"{local.boundary.context_ceiling} < {needed} (compaction window plus overhead)",
        )
    return CheckResult("compaction_feasibility", True)


def check_policy_references(bundle: ConfigBundle) -> CheckResult:
    for rung in Rung:
        if rung not in bundle.policy.tau_by_rung:
            return CheckResult("policy_references", False, f"tau_by_rung missing {rung.value}")
        if rung not in bundle.prices.by_rung:
            return CheckResult("policy_references", False, f"prices missing {rung.value}")
        if rung not in bundle.tripwires.by_rung:
            return CheckResult("policy_references", False, f"tripwires missing {rung.value}")
    ambiguous = [b for b in bundle.policy.bands if b.rung is None]
    if len(ambiguous) != 1:
        return CheckResult("policy_references", False, "exactly one ambiguous band is required")
    if bundle.prices.by_rung[Rung.LOCAL].input <= 0:
        return CheckResult(
            "policy_references", False, "local rung must carry a non-zero latency-equivalent cost"
        )
    return CheckResult("policy_references", True)


def check_learning_contract(bundle: ConfigBundle) -> CheckResult:
    contract = bundle.learning_contract
    if contract.failure_types_version != FAILURE_TYPES_VERSION:
        return CheckResult(
            "learning_contract",
            False,
            f"learning contract cites {contract.failure_types_version}, "
            f"code is {FAILURE_TYPES_VERSION}",
        )
    required_denied = {"served_rung", "served_model", "escalated"}
    missing = required_denied - set(contract.deny_list)
    if missing:
        return CheckResult("learning_contract", False, f"deny-list missing {sorted(missing)}")
    for feature in contract.features:
        if feature.name in contract.deny_list:
            return CheckResult(
                "learning_contract", False, f"feature {feature.name!r} is on the deny-list"
            )
    if (
        "served_rung" not in contract.forbidden_targets
        or "decision" not in contract.forbidden_targets
    ):
        return CheckResult(
            "learning_contract", False, "forbidden_targets must include served_rung and decision"
        )
    return CheckResult("learning_contract", True)


def check_repo_classification(bundle: ConfigBundle) -> CheckResult:
    manifest = bundle.repo_classification
    ids = {c.class_id for c in manifest.classes}
    if manifest.default_class_id not in ids:
        return CheckResult("repo_classification", False, "default class is not defined")
    default = manifest.class_by_id(manifest.default_class_id)
    if Rung.FRONTIER in default.allowed_rungs and not default.restricted:
        pass
    for entry in manifest.repos:
        if entry.class_id not in ids:
            return CheckResult(
                "repo_classification", False, f"repo {entry.repo_id} cites unknown class"
            )
    for cls in manifest.classes:
        if cls.restricted and cls.allowed_rungs != (Rung.LOCAL,):
            return CheckResult(
                "repo_classification",
                False,
                f"restricted class {cls.class_id} must be local-only",
            )
        if cls.restricted and cls.release_permitted:
            return CheckResult(
                "repo_classification",
                False,
                f"restricted class {cls.class_id} must not permit pin release",
            )
    return CheckResult("repo_classification", True)


def check_endpoint_inventory(bundle: ConfigBundle) -> CheckResult:
    """Deployments, not labels: the local rung is loopback-only and trust zones are coherent.

    This is the substitution experiment from the 2026-09-03 review: a local group pointed at
    a remote host must fail here, at load, not be discovered in the egress ledger.
    """
    from adrl.config.models import TRUST_ZONE_ORDER

    inventory = bundle.endpoint_inventory
    group_to_rung = bundle.rungs.group_to_rung
    zones_by_rung: dict[Rung, set[str]] = {}
    for dep in inventory.deployments:
        expected = group_to_rung.get(dep.model_group)
        if expected is None:
            return CheckResult(
                "endpoint_inventory",
                False,
                f"deployment {dep.id} names group {dep.model_group!r} that is in no rung",
            )
        if expected is not dep.rung:
            return CheckResult(
                "endpoint_inventory",
                False,
                f"deployment {dep.id} claims rung {dep.rung.value} but its group is in "
                f"{expected.value}",
            )
        if dep.rung is Rung.LOCAL:
            if dep.trust_zone != "local_host":
                return CheckResult(
                    "endpoint_inventory",
                    False,
                    f"local deployment {dep.id} has trust_zone {dep.trust_zone}; "
                    "must be local_host",
                )
            if not dep.is_loopback:
                return CheckResult(
                    "endpoint_inventory",
                    False,
                    f"local deployment {dep.id} api_base {dep.api_base!r} is not loopback or a "
                    "unix socket; a local label on a remote host would leave the machine",
                )
        elif dep.trust_zone == "local_host":
            return CheckResult(
                "endpoint_inventory",
                False,
                f"cloud deployment {dep.id} cannot claim trust_zone local_host",
            )
        zones_by_rung.setdefault(dep.rung, set()).add(dep.trust_zone)
    for spec in bundle.rungs.rungs.values():
        if not spec.enabled:
            continue
        for member in spec.members:
            if not inventory.for_group(member):
                return CheckResult(
                    "endpoint_inventory", False, f"rung member {member!r} has no deployment"
                )
    ranks = {r: max(TRUST_ZONE_ORDER[z] for z in zs) for r, zs in zones_by_rung.items()}
    for lower, higher in zip(Rung.ordered(), Rung.ordered()[1:], strict=False):
        if lower in ranks and higher in ranks and ranks[lower] > ranks[higher]:
            return CheckResult(
                "endpoint_inventory",
                False,
                f"rung {lower.value} reaches a less trusted zone than rung {higher.value}",
            )
    return CheckResult("endpoint_inventory", True)


def check_residency_reachable(
    bundle: ConfigBundle, settings: Settings | None = None
) -> CheckResult:
    """A residency class in use must have an in-geo deployment on every cloud rung it allows."""
    manifest = bundle.repo_classification
    inventory = bundle.endpoint_inventory
    in_use = {entry.class_id for entry in manifest.repos} | {manifest.default_class_id}
    for cls in manifest.classes:
        if cls.residency is None:
            continue
        cloud_rungs = [r for r in cls.allowed_rungs if r.is_cloud]
        missing = [
            r.value
            for r in cloud_rungs
            if not any(d.geo == cls.residency for d in inventory.for_rung(r))
        ]
        if missing and cls.class_id in in_use:
            strict = settings is None or settings.residency_unreachable_is_error
            return CheckResult(
                "residency_reachable",
                not strict,
                f"class {cls.class_id} requires geo {cls.residency} but rungs "
                f"{missing} have no deployment there",
            )
        if missing:
            return CheckResult(
                "residency_reachable",
                True,
                f"class {cls.class_id} is unused; rungs {missing} have no {cls.residency} "
                "deployment, so lineages in that class would be local-or-block",
            )
    return CheckResult("residency_reachable", True)


def all_checks(bundle: ConfigBundle, settings: Settings) -> Sequence[CheckResult]:
    return (
        check_rung_closed_membership(bundle),
        check_fallback_groups_within_rung(bundle),
        check_live_rung_has_evidence(bundle, settings),
        check_compaction_feasibility(bundle),
        check_policy_references(bundle),
        check_learning_contract(bundle),
        check_repo_classification(bundle),
        check_endpoint_inventory(bundle),
        check_residency_reachable(bundle, settings),
    )


def run_checks(bundle: ConfigBundle, settings: Settings) -> None:
    failures = [c for c in all_checks(bundle, settings) if not c.ok]
    if failures:
        raise ConfigError("; ".join(f"{c.name}: {c.detail}" for c in failures))
