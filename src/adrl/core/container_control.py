"""Create-only local container transport. Primary: ADRL-OPS-001.

Secondary: ADRL-SAF-007, ADRL-TRU-001, ADRL-MEM-005.
Internal synthetic preparation only. No start, exec, kill, restart, pull or adoption API.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from copy import copy
from pathlib import Path
from typing import Any, Literal, cast
from urllib.parse import quote

import httpx
from pydantic import BaseModel, ConfigDict, Field, model_validator

ENVIRONMENT = ["PATH=/", "LANG=C", "GOMAXPROCS=2"]
RESOURCE_ID = re.compile(r"^[a-f0-9]{64}$")


class ResourceError(ValueError):
    """Preparation/recovery refused or uncertain; never a successful workload outcome."""


class EngineError(ResourceError):
    """Bounded local engine request failed without exposing raw daemon error text."""

    def __init__(self, status: int) -> None:
        super().__init__(f"engine_http_{status}")
        self.status = status


class TransportError(ResourceError):
    """Safe transient diagnosis; raw transport exceptions never enter the product ledger."""

    def __init__(
        self,
        kind: Literal[
            "read_timeout",
            "connect_timeout",
            "write_timeout",
            "pool_timeout",
            "http_transport",
            "socket_failure",
        ],
    ) -> None:
        super().__init__("engine_unavailable_or_uncertain")
        self.kind = kind


class ResourcePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    schema_version: Literal["stopped-resource-policy-v1"] = "stopped-resource-policy-v1"
    api_version: Literal["1.47"] = "1.47"
    max_resources: int = Field(default=32, ge=1, le=32)
    max_event_bytes: Literal[4096] = 4096
    request_seconds: float = Field(default=10, ge=0.1, le=15)
    response_bytes: int = Field(default=131072, ge=1024, le=131072)
    command_bytes: int = Field(default=8192, ge=1, le=8192)
    memory_bytes: int = Field(default=100663296, ge=16777216, le=100663296)
    pids_limit: int = Field(default=32, ge=8, le=32)
    nano_cpus: int = Field(default=500000000, ge=100000000, le=500000000)
    user: Literal["65532:65532"] = "65532:65532"


class ContainerRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    image_id: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    argv: tuple[str, ...] = Field(min_length=1, max_length=64, repr=False)

    @model_validator(mode="after")
    def command(self) -> ContainerRequest:
        if not self.argv[0].startswith("/") or any("\0" in arg for arg in self.argv):
            raise ValueError("absolute_container_command_required")
        return self


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


class ContainerControl:
    """Local Engine API 1.47 transport; endpoint and profile stay in operator memory."""

    def __init__(
        self, socket_path: Path, profile: bytes, profile_sha256: str, policy: ResourcePolicy
    ) -> None:
        if not socket_path.is_absolute():
            raise ResourceError("absolute_engine_socket_required")
        self.socket = socket_path.resolve(strict=True)
        if not self.socket.is_socket():
            raise ResourceError("engine_socket_required")
        if len(profile) > 32768 or hashlib.sha256(profile).hexdigest() != profile_sha256:
            raise ResourceError("seccomp_pin_mismatch")
        try:
            value = json.loads(profile)
            if not isinstance(value, dict) or value.get("defaultAction") != "SCMP_ACT_ERRNO":
                raise ResourceError("explicit_seccomp_required")
            if not isinstance(value.get("syscalls"), list):
                raise ResourceError("invalid_seccomp_profile")
        except (ValueError, UnicodeError):
            raise ResourceError("invalid_seccomp_profile") from None
        self.profile = canonical(value).decode()
        self.profile_sha256 = profile_sha256
        self.policy = ResourcePolicy.model_validate(policy.model_dump())

    def bounded(self, request_seconds: float) -> ContainerControl:
        """Independent tighter I/O view; preserve the original endpoint and profile custody."""
        original = ResourcePolicy.model_validate(self.policy.model_dump())
        requested = ResourcePolicy.model_validate(
            original.model_dump() | {"request_seconds": request_seconds}
        )
        if requested.request_seconds > original.request_seconds:
            raise ResourceError("engine_request_budget_widening_refused")
        result = copy(self)
        result.policy = requested
        return result

    def _request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        expected_status: int | None = None,
    ) -> Any:
        payload = canonical(body) if body is not None else None
        if payload is not None and len(payload) > 65536:
            raise ResourceError("engine_request_limit")
        try:
            started = time.monotonic()
            transport = httpx.HTTPTransport(uds=str(self.socket), retries=0)
            with httpx.Client(
                transport=transport,
                trust_env=False,
                follow_redirects=False,
                timeout=self.policy.request_seconds,
            ) as client:
                with client.stream(
                    method,
                    f"http://localhost/v{self.policy.api_version}{path}",
                    content=payload,
                    headers={"Content-Type": "application/json", "Accept-Encoding": "identity"},
                ) as response:
                    if response.headers.get("Content-Encoding", "identity") != "identity":
                        raise ResourceError("engine_encoded_response_refused")
                    chunks = bytearray()
                    for chunk in response.iter_raw():
                        if time.monotonic() - started > self.policy.request_seconds:
                            raise ResourceError("engine_request_deadline")
                        chunks.extend(chunk)
                        if len(chunks) > self.policy.response_bytes:
                            raise ResourceError("engine_response_limit")
                    if time.monotonic() - started > self.policy.request_seconds:
                        raise ResourceError("engine_request_deadline")
                    if response.status_code not in {200, 201, 204} or (
                        expected_status is not None and response.status_code != expected_status
                    ):
                        raise EngineError(response.status_code)
                    if response.status_code == 204:
                        return None
                    return json.loads(chunks)
        except httpx.ReadTimeout:
            raise TransportError("read_timeout") from None
        except httpx.ConnectTimeout:
            raise TransportError("connect_timeout") from None
        except httpx.WriteTimeout:
            raise TransportError("write_timeout") from None
        except httpx.PoolTimeout:
            raise TransportError("pool_timeout") from None
        except httpx.HTTPError:
            raise TransportError("http_transport") from None
        except OSError:
            raise TransportError("socket_failure") from None
        except (UnicodeError, json.JSONDecodeError):
            raise ResourceError("engine_response_invalid") from None

    def engine(self) -> dict[str, str]:
        value = self._request("GET", "/info")
        if (
            not isinstance(value, dict)
            or value.get("OSType") != "linux"
            or str(value.get("CgroupVersion")) != "2"
            or not isinstance(value.get("ID"), str)
            or not 8 <= len(value["ID"]) <= 256
            or value.get("Architecture") not in {"aarch64", "arm64"}
        ):
            raise ResourceError("unsupported_engine_identity")
        return {"id": value["ID"], "endpoint": str(self.socket), "api": self.policy.api_version}

    def prepare(self, request: ContainerRequest, operation_key: str) -> tuple[str, dict[str, Any]]:
        if len(canonical(request.argv)) > self.policy.command_bytes:
            raise ResourceError("container_command_limit")
        image = self._request("GET", f"/images/{quote(request.image_id, safe='')}/json")
        if (
            not isinstance(image, dict)
            or image.get("Id") != request.image_id
            or image.get("Os") != "linux"
            or image.get("Architecture") != "arm64"
            or not isinstance(image.get("Config"), dict)
        ):
            raise ResourceError("fixture_image_mismatch")
        config = image["Config"]
        if any(
            config.get(key) for key in ("Env", "Entrypoint", "Volumes", "Healthcheck", "OnBuild")
        ):
            raise ResourceError("inherited_image_control_refused")
        labels = config.get("Labels") or {}
        if not isinstance(labels, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in labels.items()
        ):
            raise ResourceError("image_labels_invalid")
        name = "adrl-resource-" + operation_key
        body = {
            "Image": request.image_id,
            "Cmd": list(request.argv),
            "Entrypoint": [],
            "Env": ENVIRONMENT,
            "User": self.policy.user,
            "WorkingDir": "/work",
            "NetworkDisabled": True,
            "Tty": False,
            "OpenStdin": False,
            "AttachStdin": False,
            "AttachStdout": False,
            "AttachStderr": False,
            "Labels": labels
            | {"adrl.resource.operation": operation_key, "adrl.resource.version": "1"},
            "HostConfig": {
                "NetworkMode": "none",
                "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
                "CapDrop": ["ALL"],
                "CapAdd": [],
                "Privileged": False,
                "SecurityOpt": ["no-new-privileges:true", "seccomp=" + self.profile],
                "Memory": self.policy.memory_bytes,
                "MemorySwap": self.policy.memory_bytes,
                "NanoCpus": self.policy.nano_cpus,
                "PidsLimit": self.policy.pids_limit,
                "LogConfig": {"Type": "none", "Config": {}},
                "AutoRemove": False,
                "CgroupnsMode": "private",
                "IpcMode": "private",
                "PidMode": "",
                "UTSMode": "",
                "UsernsMode": "",
                "Runtime": "runc",
                "ReadonlyRootfs": False,
                "PublishAllPorts": False,
            },
        }
        return name, body

    def create(self, name: str, body: dict[str, Any]) -> str:
        value = self._request("POST", "/containers/create?name=" + quote(name, safe=""), body)
        if not isinstance(value, dict) or not isinstance(value.get("Id"), str):
            raise ResourceError("create_identity_unavailable")
        identity = value["Id"]
        if not RESOURCE_ID.fullmatch(identity):
            raise ResourceError("create_identity_unavailable")
        return cast(str, identity)

    def inspect(self, identity: str) -> dict[str, Any]:
        if not RESOURCE_ID.fullmatch(identity):
            raise ResourceError("full_resource_identity_required")
        value = self._request("GET", f"/containers/{identity}/json")
        if not isinstance(value, dict) or value.get("Id") != identity:
            raise ResourceError("resource_identity_mismatch")
        return value

    @staticmethod
    def never_started(value: dict[str, Any]) -> None:
        state = value.get("State")
        if (
            not isinstance(state, dict)
            or state.get("Status") != "created"
            or state.get("Running") is not False
            or state.get("Restarting") is not False
            or state.get("Paused") is not False
            or state.get("Dead") is not False
            or state.get("Pid") != 0
            or value.get("RestartCount") != 0
            or state.get("StartedAt") != "0001-01-01T00:00:00Z"
            or state.get("FinishedAt") != "0001-01-01T00:00:00Z"
        ):
            raise ResourceError("resource_not_never_started")

    @staticmethod
    def configuration(value: dict[str, Any]) -> dict[str, Any]:
        keys = ("Config", "HostConfig", "Mounts", "Image", "Path", "Args", "Platform", "Name")
        if any(key not in value for key in keys) or not isinstance(value.get("Created"), str):
            raise ResourceError("resource_configuration_incomplete")
        return {key: value[key] for key in keys}

    def verify_created(self, value: dict[str, Any], name: str, body: dict[str, Any]) -> None:
        self.never_started(value)
        self.configuration(value)
        if value["Name"] != "/" + name or value["Image"] != body["Image"] or value["Mounts"]:
            raise ResourceError("resource_configuration_mismatch")
        config, host = value["Config"], value["HostConfig"]
        if not isinstance(config, dict) or not isinstance(host, dict):
            raise ResourceError("resource_configuration_mismatch")
        for key, expected in body.items():
            if key == "HostConfig":
                continue
            actual = config.get(key)
            if key == "Entrypoint":
                actual = actual or []
            if actual != expected:
                raise ResourceError("resource_configuration_mismatch")
        for key, expected in body["HostConfig"].items():
            actual = host.get(key)
            if key == "CapAdd":
                actual = actual or []
            if actual != expected:
                raise ResourceError("resource_configuration_mismatch")
        for key in (
            "Binds",
            "Mounts",
            "VolumesFrom",
            "Links",
            "Devices",
            "DeviceRequests",
            "DeviceCgroupRules",
            "PortBindings",
            "CgroupParent",
            "Init",
        ):
            if host.get(key):
                raise ResourceError("unexpected_resource_control")
        if any(config.get(key) for key in ("Volumes", "Healthcheck", "ExposedPorts")):
            raise ResourceError("unexpected_resource_control")
        if value["Path"] != body["Cmd"][0] or value["Args"] != body["Cmd"][1:]:
            raise ResourceError("resource_command_mismatch")

    def remove(self, identity: str) -> None:
        if not RESOURCE_ID.fullmatch(identity):
            raise ResourceError("full_resource_identity_required")
        self._request("DELETE", f"/containers/{identity}?force=false&v=false")
