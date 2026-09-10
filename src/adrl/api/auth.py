"""Local session authority. Primary: ADRL-TRU-001. Secondary: ADRL-SEM-002.

The existing trusted launcher signs expiring assertions. A native session header is only
correlation. This module requires a signed, explicit session and an exact manifest match.
It does not create a remote or multi-tenant credential authority.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import get_args

from adrl.api.contracts import ProductError
from adrl.config.models import RepoClassificationManifest
from adrl.core.ids import SessionId, session_identity
from adrl.gates.workload import (
    HEADER_SESSION_ID,
    HEADER_WORKLOAD_ASSERTION,
    AssertionInvalid,
    WorkloadAssertion,
    normalise_identity,
    verify_assertion,
)

PRODUCT_SESSION_HEADER = "x-adrl-session-id"
_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        if code not in get_args(ProductError.model_fields["code"].annotation):
            raise ValueError("unknown product error code")
        self.status = status
        self.error = ProductError.model_validate({"code": code, "message": message})
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class Principal:
    session_id: str
    session_hmac: SessionId
    workload_ref: str
    assertion: WorkloadAssertion


def authenticate(
    headers: Mapping[str, str],
    key: bytes,
    manifest: RepoClassificationManifest,
    *,
    now: float | None = None,
) -> Principal:
    token = headers.get(HEADER_WORKLOAD_ASSERTION, "")
    if len(token) > 16384:
        raise ApiError(401, "unauthenticated", "Invalid workload credential.")
    try:
        assertion = verify_assertion(token, key, now=now)
    except (AssertionInvalid, ValueError, TypeError, OverflowError) as exc:
        raise ApiError(401, "unauthenticated", "A valid workload assertion is required.") from exc
    sid = assertion.session_id
    if (
        not sid
        or _ID.fullmatch(sid) is None
        or not math.isfinite(assertion.expires_at)
        or not math.isfinite(assertion.issued_at)
        or assertion.expires_at <= assertion.issued_at
    ):
        raise ApiError(401, "unauthenticated", "The assertion must bind an explicit session.")
    for header in (HEADER_SESSION_ID, PRODUCT_SESSION_HEADER):
        if headers.get(header, sid) != sid:
            raise ApiError(403, "forbidden", "Session identity does not match the credential.")
    identities = set(assertion.identities())
    matches = {
        entry.repo_id for entry in manifest.repos if normalise_identity(entry.match) in identities
    }
    if len(matches) != 1:
        raise ApiError(403, "forbidden", "The workload must match one registered repository.")
    return Principal(sid, session_identity(sid, key), matches.pop(), assertion)
