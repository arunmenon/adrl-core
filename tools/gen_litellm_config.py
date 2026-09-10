"""Generate the LiteLLM proxy config from rungs.yaml and the signed endpoint inventory.

Primary: ADRL-FND-002. Secondary: ADRL-RTG-008, ADRL-CAS-007, ADRL-SAF-004, ADRL-SAF-008.

Every attested deployment becomes a LiteLLM entry whose ``model_name`` is the deployment id
and whose ``model_info.id`` is the same id, so the gateway's ``x-litellm-model-id`` response
header is a destination receipt ADRL can map back to the inventory. Group names remain as
aliases for the frontier passthrough and the pinned alias. Fallback lists are rung-closed and,
for local deployments, never leave the local host.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from adrl.config.loaders import ConfigBundle, load_bundle  # noqa: E402
from adrl.config.models import EndpointInventory  # noqa: E402
from adrl.config.settings import Settings  # noqa: E402
from adrl.core.enums import Rung  # noqa: E402

GENERATOR_VERSION = "litellm-config-gen-v2"


def load_endpoints(path: Path) -> EndpointInventory:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle) if path.suffix == ".json" else yaml.safe_load(handle)
    return EndpointInventory.model_validate(data)


def _entry(name: str, dep: Any, rung: Rung, extra: dict[str, Any]) -> dict[str, Any]:
    params: dict[str, Any] = {"model": dep.model}
    if dep.api_base is not None:
        params["api_base"] = dep.api_base
    if dep.api_key_env is not None:
        params["api_key"] = "os.environ/" + dep.api_key_env
    info: dict[str, Any] = {
        "id": dep.id,
        "adrl_rung": rung.value,
        "adrl_group": dep.model_group,
        "adrl_trust_zone": dep.trust_zone,
        "geo": dep.geo,
        "data_use_profile": dep.data_use_profile,
        **extra,
    }
    if dep.max_input_tokens is not None:
        info["max_input_tokens"] = dep.max_input_tokens
    return {"model_name": name, "litellm_params": params, "model_info": info}


def generate(bundle: ConfigBundle, inventory: EndpointInventory) -> dict[str, Any]:
    group_to_rung = bundle.rungs.group_to_rung
    model_list: list[dict[str, Any]] = []
    for dep in inventory.deployments:
        rung = group_to_rung.get(dep.model_group)
        if rung is None:
            raise SystemExit(f"deployment {dep.id} group {dep.model_group!r} is in no rung")
        # the deployment itself, addressed by id (what ADRL sends for non-frontier rungs)
        model_list.append(_entry(dep.id, dep, rung, {"adrl_addressed_by": "deployment_id"}))
        # the group alias, kept for the pinned alias and frontier alias fan-out
        model_list.append(_entry(dep.model_group, dep, rung, {"adrl_addressed_by": "group"}))
    if inventory.frontier_aliases_to:
        target = inventory.for_group(inventory.frontier_aliases_to)
        for name in bundle.rungs.frontier_model_names:
            for dep in target:
                model_list.append(
                    _entry(name, dep, dep.rung, {"adrl_alias_of": inventory.frontier_aliases_to})
                )
    fallbacks: list[dict[str, list[str]]] = []
    for fg in bundle.rungs.fallback_groups:
        fallbacks.append({fg.primary: list(fg.fallbacks)})
    # deployment-id fallbacks stay inside the local host; cloud deployments get one attempt
    local_ids = [d.id for d in inventory.for_rung(Rung.LOCAL)]
    for index, dep_id in enumerate(local_ids):
        rest = local_ids[index + 1 :]
        if rest:
            fallbacks.append({dep_id: rest})
    local_members = (
        list(bundle.rungs.rungs[Rung.LOCAL].members) if Rung.LOCAL in bundle.rungs.rungs else []
    )
    if inventory.pinned_alias and local_members:
        for dep in inventory.for_group(local_members[0]):
            model_list.append(
                _entry(inventory.pinned_alias, dep, Rung.LOCAL, {"adrl_pinned": True})
            )
        fallbacks.append({inventory.pinned_alias: local_members[1:]})
    retry = bundle.policy.gateway_retry_budget
    return {
        "_adrl": {
            "generator": GENERATOR_VERSION,
            "rung_membership": bundle.rungs.version,
            "endpoint_inventory": inventory.version,
            "policy": bundle.policy.version,
            "note": "generated; do not edit by hand. Fallbacks are rung-closed by construction.",
        },
        "model_list": model_list,
        "router_settings": {
            "fallbacks": fallbacks,
            "context_window_fallbacks": [],
            "content_policy_fallbacks": [],
            "num_retries": max(0, retry.max_attempts_per_turn - 1),
            "timeout": retry.wall_clock_cap_s,
            "retry_after": 0,
            "allowed_fails": 1,
            "enable_pre_call_checks": True,
        },
        "litellm_settings": {
            "drop_params": True,
            "request_timeout": 600,
            "num_retries": max(0, retry.max_attempts_per_turn - 1),
            "return_response_headers": True,
        },
        "general_settings": {
            "forward_client_headers_to_llm_api": False,
        },
    }


def rung_closed(config: dict[str, Any], group_to_rung: dict[str, str]) -> list[str]:
    """Return violations: any fallback list that leaves the primary's rung or trust zone."""
    problems: list[str] = []
    rung_of: dict[str, str | None] = {}
    zone_of: dict[str, str | None] = {}
    for m in config["model_list"]:
        rung_of[m["model_name"]] = m["model_info"].get("adrl_rung")
        zone_of[m["model_name"]] = m["model_info"].get("adrl_trust_zone")
    for entry in config["router_settings"]["fallbacks"]:
        for primary, targets in entry.items():
            rung = rung_of.get(primary) or group_to_rung.get(primary)
            for target in targets:
                target_rung = rung_of.get(target) or group_to_rung.get(target)
                if target_rung != rung:
                    problems.append(f"{primary} -> {target} crosses rung {rung} -> {target_rung}")
                if rung == "local" and zone_of.get(target) not in (None, "local_host"):
                    problems.append(f"{primary} -> {target} leaves the local host")
    for m in config["model_list"]:
        info = m["model_info"]
        base = str(m["litellm_params"].get("api_base") or "")
        if info.get("adrl_rung") == "local" and info.get("adrl_trust_zone") != "local_host":
            problems.append(
                f"{m['model_name']} is local but trust zone {info.get('adrl_trust_zone')}"
            )
        if info.get("adrl_rung") == "local" and not _loopback(base):
            problems.append(f"{m['model_name']} is local but api_base {base!r} is not loopback")
    if config["router_settings"].get("context_window_fallbacks"):
        problems.append("context_window_fallbacks must be empty")
    if config["router_settings"].get("content_policy_fallbacks"):
        problems.append("content_policy_fallbacks must be empty")
    return problems


def _loopback(api_base: str) -> bool:
    import ipaddress
    from urllib.parse import urlsplit

    parts = urlsplit(api_base)
    if parts.scheme in ("unix", "http+unix"):
        return True
    host = parts.hostname
    if host is None:
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config-dir", type=Path, default=Path("config"))
    parser.add_argument("--endpoints", type=Path, default=None)
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    settings = Settings(config_dir=args.config_dir)
    bundle = load_bundle(settings)
    inventory = load_endpoints(args.endpoints) if args.endpoints else bundle.endpoint_inventory
    config = generate(bundle, inventory)
    problems = rung_closed(config, {g: r.value for g, r in bundle.rungs.group_to_rung.items()})
    if problems:
        for problem in problems:
            sys.stderr.write(f"FAIL {problem}\n")
        return 1
    text = json.dumps(config, indent=2) if args.json else yaml.safe_dump(config, sort_keys=False)
    if args.out:
        args.out.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
