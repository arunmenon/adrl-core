"""Authenticated workload identity (ADRL-SAF-008)."""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

import pytest

from adrl.gates.workload import (
    HEADER_WORKLOAD_ASSERTION,
    AssertionInvalid,
    AssertionVerifier,
    inventory_repo,
    mint_launch,
    sign_assertion,
    verify_assertion,
)
from tests.unit.gates.conftest import HMAC_KEY, inventory, make_ctx

BODY = {"model": "m", "max_tokens": 10, "messages": [{"role": "user", "content": "hi"}]}


def test_sign_and_verify_roundtrip() -> None:
    token = sign_assertion(inventory("/repo/a", "git@host:org/a.git"), HMAC_KEY, session_id="s1")
    assertion = verify_assertion(token, HMAC_KEY)
    assert assertion.inventory.root == "/repo/a"
    assert assertion.identities() == ("git@host:org/a", "/repo/a")
    assert assertion.session_id == "s1" and assertion.assertion_id


@pytest.mark.parametrize(
    "mutate",
    [
        lambda t: t[:-4] + ("0000" if not t.endswith("0000") else "1111"),
        lambda t: t.replace("adrlwa1.", "adrlwa2."),
        lambda t: "garbage",
    ],
)
def test_tampered_tokens_are_rejected(mutate) -> None:  # type: ignore[no-untyped-def]
    token = sign_assertion(inventory(), HMAC_KEY)
    with pytest.raises(AssertionInvalid):
        verify_assertion(mutate(token), HMAC_KEY)


def test_wrong_key_expired_and_future_tokens_are_rejected() -> None:
    with pytest.raises(AssertionInvalid, match="signature"):
        verify_assertion(sign_assertion(inventory(), b"other"), HMAC_KEY)
    expired = sign_assertion(inventory(), HMAC_KEY, ttl_s=5, now=time.time() - 100)
    with pytest.raises(AssertionInvalid, match="expired"):
        verify_assertion(expired, HMAC_KEY)
    future = sign_assertion(inventory(), HMAC_KEY, now=time.time() + 3600)
    with pytest.raises(AssertionInvalid, match="future"):
        verify_assertion(future, HMAC_KEY)


def test_verifier_prefers_header_then_session_file(tmp_path: Path) -> None:
    verifier = AssertionVerifier(HMAC_KEY, tmp_path)
    header_ctx = make_ctx(BODY)
    resolved = verifier.resolve(header_ctx)
    assert resolved.assertion is not None and resolved.source == "header"

    (tmp_path / "sess-9.token").write_text(
        sign_assertion(inventory("/repo/file"), HMAC_KEY, session_id="sess-9")
    )
    file_ctx = make_ctx(BODY, session="sess-9", repo_root=None)
    resolved_file = verifier.resolve(file_ctx)
    assert resolved_file.assertion is not None and resolved_file.source == "session_file"
    assert resolved_file.assertion.inventory.root == "/repo/file"

    absent = verifier.resolve(make_ctx(BODY, session="nobody", repo_root=None))
    assert absent.assertion is None and absent.source == "absent"


def test_assertion_bound_to_another_session_is_refused(tmp_path: Path) -> None:
    verifier = AssertionVerifier(HMAC_KEY, tmp_path)
    token = sign_assertion(inventory(), HMAC_KEY, session_id="other-session")
    ctx = make_ctx(
        BODY,
        session="this-session",
        repo_root=None,
        extra_headers={HEADER_WORKLOAD_ASSERTION: token},
    )
    resolved = verifier.resolve(ctx)
    assert resolved.assertion is None and "another session" in str(resolved.reason)


def _git_repo(path: Path) -> Path:
    path.mkdir()
    (path / "a.py").write_text("print('a')\n")
    (path / "b.txt").write_text("b\n")
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    subprocess.run(["git", "-C", str(path), "add", "."], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(path),
            "-c",
            "user.email=t@t",
            "-c",
            "user.name=t",
            "commit",
            "-q",
            "-m",
            "i",
        ],
        check=True,
    )
    return path


def test_inventory_and_launch_material(tmp_path: Path) -> None:
    repo = _git_repo(tmp_path / "repo")
    inv = inventory_repo(repo)
    assert inv.tracked_files == 2 and inv.head and len(inv.fingerprint) == 64
    same = inventory_repo(repo)
    assert same.fingerprint == inv.fingerprint, "fingerprint is deterministic"
    lookalike = tmp_path / "repo-lookalike"
    lookalike.mkdir()
    (lookalike / "a.py").write_text("print('b')\n")
    assert inventory_repo(lookalike).fingerprint != inv.fingerprint

    material = mint_launch(repo, HMAC_KEY, assertion_dir=tmp_path / "assertions", ttl_s=60)
    assert material.token_path is not None and material.token_path.exists()
    assert oct(material.token_path.stat().st_mode & 0o777) == oct(0o600)
    assert os.path.basename(material.token_path) == f"{material.session_id}.token"
    assert HEADER_WORKLOAD_ASSERTION in material.env_exports()["ANTHROPIC_CUSTOM_HEADERS"]
    assertion = verify_assertion(material.token, HMAC_KEY)
    assert assertion.session_id == material.session_id
    assert assertion.inventory.root == str(repo.resolve())
