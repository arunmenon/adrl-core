"""Pinned synthetic execution transport. Primary: ADRL-OPS-001.

Secondary: ADRL-SAF-007, ADRL-TRU-001, ADRL-MEM-005.
Internal fixture only; callers must supply authenticated ownership and one-shot admission.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Literal
from urllib.parse import quote

from pydantic import BaseModel, ConfigDict, Field, model_validator

from adrl.core.container_control import ContainerControl, ResourceError, canonical


class ExecutionPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    schema_version: Literal["isolated-fixture-execution-v1", "isolated-fixture-execution-v2"] = (
        "isolated-fixture-execution-v2"
    )
    active_request_seconds: float = Field(default=2, ge=0.1, le=2)
    max_histories: int = Field(default=32, ge=1, le=32)
    max_events: Literal[8] = 8
    max_event_bytes: Literal[4096] = 4096
    max_marker_bytes: Literal[64] = 64
    marker_directory: Literal["launch-denials-v1"] = "launch-denials-v1"
    recovery_directory: Literal["launch-recovery-locks-v1"] = "launch-recovery-locks-v1"
    marker_contents: Literal["adrl-launch-denial-v1\n"] = "adrl-launch-denial-v1\n"
    poll_seconds: float = Field(default=0.05, ge=0.01, le=0.5)
    max_run_seconds: float = Field(default=8, ge=0.1, le=8)
    stop_seconds: float = Field(default=2, ge=0.1, le=2)
    ledger_seconds: Literal[15] = 15
    fixture_lifetime_seconds: Literal[7] = 7
    engine_version: Literal["27.3.1"] = "27.3.1"
    api_version: Literal["1.47"] = "1.47"
    kernel_version: Literal["6.10.11-linuxkit"] = "6.10.11-linuxkit"
    cgroup_driver: Literal["cgroupfs"] = "cgroupfs"
    seccomp_sha256: Literal["9c1025c88ccaa517b648da571961838744ea2137f176bfe6a48b21294cae9c76"] = (
        "9c1025c88ccaa517b648da571961838744ea2137f176bfe6a48b21294cae9c76"
    )
    archive_sha256: Literal["6e555bb7c8d3457826f87d1146b43a5c8b490490986eba69b82247e467dadd7b"] = (
        "6e555bb7c8d3457826f87d1146b43a5c8b490490986eba69b82247e467dadd7b"
    )
    executable_sha256: Literal[
        "74085cef493ac7e62755cdcc650ef9f1c3856d05a5b9016e2cc8978eb4949e07"
    ] = "74085cef493ac7e62755cdcc650ef9f1c3856d05a5b9016e2cc8978eb4949e07"
    fixture_argv: tuple[Literal["/probe"], Literal["forced_stop"]] = ("/probe", "forced_stop")

    @model_validator(mode="after")
    def legacy_transport(self) -> ExecutionPolicy:
        if (
            self.schema_version == "isolated-fixture-execution-v1"
            and self.active_request_seconds != 2
        ):
            raise ValueError("legacy_execution_budget_fixed")
        return self


class ExecutionControl:
    """No public API export. Stable projection and changing lifecycle are checked separately."""

    def __init__(self, control: ContainerControl, policy: ExecutionPolicy) -> None:
        self.policy = ExecutionPolicy.model_validate(policy.model_dump())
        if control.profile_sha256 != self.policy.seccomp_sha256:
            raise ResourceError("execution_transport_profile_required")
        if self.policy.schema_version == "isolated-fixture-execution-v1":
            if control.policy.request_seconds > 2:
                raise ResourceError("execution_transport_profile_required")
            self.control = control
        else:
            self.control = control.bounded(
                min(control.policy.request_seconds, self.policy.active_request_seconds)
            )

    def profile(self) -> dict[str, Any]:
        p = self.policy
        version = self.control._request("GET", "/version")
        info = self.control._request("GET", "/info")
        if not isinstance(version, dict) or not isinstance(info, dict):
            raise ResourceError("execution_engine_profile_invalid")
        expected = {
            "Version": p.engine_version,
            "ApiVersion": p.api_version,
            "Os": "linux",
            "Arch": "arm64",
            "KernelVersion": p.kernel_version,
        }
        if any(version.get(k) != v for k, v in expected.items()):
            raise ResourceError("execution_engine_profile_unsupported")
        if (
            info.get("OSType") != "linux"
            or info.get("Architecture") != "aarch64"
            or info.get("CgroupVersion") != "2"
            or info.get("CgroupDriver") != p.cgroup_driver
            or info.get("KernelVersion") != p.kernel_version
            or info.get("OomKillDisable") is not False
            or info.get("SecurityOptions") != ["name=seccomp,profile=unconfined", "name=cgroupns"]
        ):
            raise ResourceError("execution_capability_profile_unsupported")
        for key in ("MemoryLimit", "SwapLimit", "PidsLimit", "CpuCfsPeriod", "CpuCfsQuota"):
            if info.get(key) is not True:
                raise ResourceError("execution_required_limit_unsupported")
        engine = self.control.engine()
        if info.get("ID") != engine["id"]:
            raise ResourceError("execution_engine_changed")
        keys = (
            "ID",
            "OSType",
            "Architecture",
            "CgroupVersion",
            "CgroupDriver",
            "KernelVersion",
            "OomKillDisable",
            "MemoryLimit",
            "SwapLimit",
            "PidsLimit",
            "CpuCfsPeriod",
            "CpuCfsQuota",
            "SecurityOptions",
        )
        return {
            "engine": engine,
            "version": expected,
            "capabilities": {k: info[k] for k in keys},
            "seccomp": self.control.profile_sha256,
            "version_id": p.schema_version,
        }

    def fixture(self, value: dict[str, Any]) -> dict[str, Any]:
        p = self.policy
        if value["Path"] != p.fixture_argv[0] or value["Args"] != list(p.fixture_argv[1:]):
            raise ResourceError("execution_fixture_command_required")
        image = self.control._request("GET", "/images/" + quote(value["Image"], safe="") + "/json")
        if (
            not isinstance(image, dict)
            or image.get("Id") != value["Image"]
            or image.get("Os") != "linux"
            or image.get("Architecture") != "arm64"
            or image.get("RootFS") != {"Type": "layers", "Layers": ["sha256:" + p.archive_sha256]}
        ):
            raise ResourceError("execution_fixture_layer_required")
        return {
            "image": image["Id"],
            "archive": p.archive_sha256,
            "executable": p.executable_sha256,
            "argv": p.fixture_argv,
        }

    def projection(self, value: dict[str, Any], *, original: bool = False) -> dict[str, Any]:
        config = self.control.configuration(value)
        host = config.get("HostConfig")
        if not isinstance(host, dict) or "OomKillDisable" not in host:
            raise ResourceError("execution_oom_field_required")
        oom = host["OomKillDisable"]
        if (original and oom is not False) or (oom is not False and oom is not None):
            raise ResourceError("execution_oom_field_invalid")
        result: dict[str, Any] = json.loads(
            canonical(config | {"Id": value["Id"], "Created": value["Created"]})
        )
        result["HostConfig"]["OomKillDisable"] = False
        return result

    def started(self, value: dict[str, Any], expected: str | None = None) -> str:
        state = value.get("State")
        if not isinstance(state, dict):
            raise ResourceError("execution_state_invalid")
        stamp = state.get("StartedAt")
        if (
            not isinstance(stamp, str)
            or len(stamp) > 64
            or stamp.startswith("0001-")
            or state.get("Status") not in {"running", "exited"}
            or state.get("Paused") is not False
            or state.get("Dead") is not False
            or state.get("Restarting") is not False
            or type(value.get("RestartCount")) is not int
            or value.get("RestartCount") != 0
            or (expected is not None and stamp != expected)
            or state.get("Running") is not (state.get("Status") == "running")
        ):
            raise ResourceError("execution_launch_identity_changed")
        try:
            if datetime.fromisoformat(stamp.replace("Z", "+00:00")).tzinfo is None:
                raise ValueError
            pid = state.get("Pid")
            if type(pid) is not int or pid < 0:
                raise ValueError
            if state["Status"] == "exited":
                finished = state.get("FinishedAt")
                if (
                    pid != 0
                    or not isinstance(finished, str)
                    or len(finished) > 64
                    or finished.startswith("0001-")
                    or datetime.fromisoformat(finished.replace("Z", "+00:00")).tzinfo is None
                ):
                    raise ValueError
            elif pid == 0:
                raise ValueError
        except ValueError:
            raise ResourceError("execution_started_time_invalid") from None
        return stamp

    def start(self, identity: str) -> None:
        self.control._request("POST", f"/containers/{identity}/start", expected_status=204)

    def kill(self, identity: str) -> None:
        self.control._request(
            "POST", f"/containers/{identity}/kill?signal=KILL", expected_status=204
        )

    def discard(self, identity: str) -> None:
        self.control._request(
            "DELETE", f"/containers/{identity}?force=true&v=false", expected_status=204
        )
