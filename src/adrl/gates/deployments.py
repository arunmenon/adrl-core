"""Permitted deployment sets and destination receipts. Primary: ADRL-SAF-008.
Also implements: ADRL-TRU-002 (register additions of 2026-09-03).

Secondary: ADRL-SAF-001 (monotone constraint), ADRL-FND-002 (rung-closed execution),
ADRL-RTG-008 (served identity), ADRL-SAF-009 (actual destination in the egress ledger).

The object ADRL constrains is the set of attested deployments a request may reach. A rung is a
projection of that set. The pin keeps only ``local_host`` deployments; residency keeps only
deployments in the lineage's geo plus the local host; the repository ceiling keeps only the
rungs the class allows. Nothing here reads a label off a deployment the inventory has not
attested, and every dispatch is expected to come back with a receipt naming the deployment
that actually served it.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from adrl.config.models import EndpointInventory
from adrl.core.enums import Rung, ServedSource
from adrl.core.types import (
    DeploymentInfo,
    DeploymentSet,
    ServedIdentity,
)

RECEIPT_HEADER_MODEL_ID = "x-litellm-model-id"
RECEIPT_HEADER_API_BASE = "x-litellm-model-api-base"
RECEIPT_HEADER_GROUP = "x-litellm-model-group"


def catalog_from_inventory(inventory: EndpointInventory) -> dict[str, DeploymentInfo]:
    return {
        dep.id: DeploymentInfo(
            deployment_id=dep.id,
            rung=dep.rung,
            model_group=dep.model_group,
            provider=dep.provider,
            trust_zone=dep.trust_zone,
            geo=dep.geo,
            api_base_host=dep.api_base_host,
            data_use_profile=dep.data_use_profile,
            model=dep.model,
        )
        for dep in inventory.deployments
    }


@dataclass(frozen=True, slots=True)
class DeploymentReceipt:
    """What the gateway said it served, mapped back onto the attested inventory."""

    deployment: DeploymentInfo | None
    source: ServedSource
    api_base_host: str | None
    raw_model_id: str | None


class DeploymentPolicy:
    """Derive the permitted deployment set from gate facts and pick the dispatch target."""

    def __init__(self, inventory: EndpointInventory) -> None:
        self._inventory = inventory
        self._catalog = catalog_from_inventory(inventory)
        self._order: dict[str, int] = {}
        position = 0
        for dep in inventory.deployments:
            self._order[dep.id] = position
            position += 1

    @property
    def inventory(self) -> EndpointInventory:
        return self._inventory

    @property
    def catalog(self) -> Mapping[str, DeploymentInfo]:
        return self._catalog

    def universe(self) -> DeploymentSet:
        return DeploymentSet.all_of(self._catalog)

    def permitted_for(
        self,
        *,
        permitted_rungs: frozenset[Rung],
        pinned: bool,
        residency: str | None,
    ) -> DeploymentSet:
        """Monotone derivation: rung ceiling, then residency, then the pin (ADRL-SAF-001)."""
        deployments = self.universe().only_rungs(permitted_rungs)
        if residency is not None:
            deployments = deployments.only_geo(residency, keep_local_host=True)
        if pinned:
            deployments = deployments.local_host_only()
        return deployments

    def choose(
        self,
        deployments: DeploymentSet,
        rung: Rung,
        *,
        preferred_group: str | None = None,
        rung_member_order: tuple[str, ...] = (),
    ) -> DeploymentInfo | None:
        """First permitted deployment of ``rung``, honouring the rung's member order."""
        candidates = list(deployments.for_rung(rung))
        if not candidates:
            return None
        if preferred_group is not None:
            for dep in candidates:
                if dep.model_group == preferred_group:
                    return dep
        rank = {group: i for i, group in enumerate(rung_member_order)}
        candidates.sort(
            key=lambda d: (rank.get(d.model_group, len(rank)), self._order[d.deployment_id])
        )
        return candidates[0]

    def frontier_for_model(
        self, deployments: DeploymentSet, requested_model: str
    ) -> DeploymentInfo | None:
        """The deployment a frontier passthrough reaches; aliases resolve to the frontier group."""
        target_group = self._inventory.frontier_aliases_to
        for dep in deployments.for_rung(Rung.FRONTIER):
            if target_group is None or dep.model_group == target_group:
                return dep
        first = deployments.for_rung(Rung.FRONTIER)
        return first[0] if first else None

    # ------------------------------------------------------------------ receipts

    def receipt(
        self, headers: Mapping[str, str], intended: DeploymentInfo | None
    ) -> DeploymentReceipt:
        """Map the gateway's response headers to an attested deployment.

        Order: an ``x-litellm-model-id`` equal to a deployment id (the generator sets
        ``model_info.id`` to the deployment id); else ``x-litellm-model-api-base`` whose host
        matches a deployment; else assumed intended.
        """
        lowered = {k.lower(): v for k, v in headers.items()}
        raw_id = lowered.get(RECEIPT_HEADER_MODEL_ID)
        api_base = lowered.get(RECEIPT_HEADER_API_BASE)
        host = _host_of(api_base) if api_base else None
        if raw_id is not None:
            head = raw_id.split("/", 1)[0]
            if head in self._catalog:
                dep = self._catalog[head]
                return DeploymentReceipt(
                    dep, ServedSource.GATEWAY_REPORTED, dep.api_base_host, raw_id
                )
        if host is not None:
            found = self._inventory.by_host(host)
            if found is not None:
                dep = self._catalog[found.id]
                return DeploymentReceipt(dep, ServedSource.GATEWAY_REPORTED, host, raw_id)
            return DeploymentReceipt(None, ServedSource.GATEWAY_REPORTED, host, raw_id)
        return DeploymentReceipt(intended, ServedSource.ASSUMED_INTENDED, None, raw_id)

    def served_identity(
        self, base: ServedIdentity, headers: Mapping[str, str], intended: DeploymentInfo | None
    ) -> ServedIdentity:
        """Enrich a served identity with the receipt; never downgrade a confirmed source."""
        receipt = self.receipt(headers, intended)
        dep = receipt.deployment
        if receipt.source is ServedSource.GATEWAY_REPORTED:
            return ServedIdentity(
                rung=dep.rung if dep else base.rung,
                model=(dep.model if dep and dep.model else base.model),
                provider=dep.provider if dep else base.provider,
                source=ServedSource.GATEWAY_REPORTED,
                deployment_id=dep.deployment_id if dep else None,
                api_base_host=receipt.api_base_host,
                trust_zone=dep.trust_zone if dep else None,
                geo=dep.geo if dep else None,
            )
        return ServedIdentity(
            rung=base.rung,
            model=base.model,
            provider=base.provider if base.provider else (dep.provider if dep else None),
            source=base.source,
            deployment_id=dep.deployment_id if dep else None,
            api_base_host=dep.api_base_host if dep else None,
            trust_zone=dep.trust_zone if dep else None,
            geo=dep.geo if dep else None,
        )


def _host_of(url: str) -> str | None:
    parts = urlsplit(url)
    if parts.scheme in ("unix", "http+unix"):
        return "unix"
    if parts.hostname is None:
        return None
    return f"{parts.hostname}:{parts.port}" if parts.port else parts.hostname


def egress_fields(deployment: DeploymentInfo | None, receipt_source: str) -> dict[str, Any]:
    return {
        "deployment_id": deployment.deployment_id if deployment else None,
        "trust_zone": deployment.trust_zone if deployment else None,
        "geo": deployment.geo if deployment else None,
        "api_base_host": deployment.api_base_host if deployment else None,
        "receipt_source": receipt_source,
    }
