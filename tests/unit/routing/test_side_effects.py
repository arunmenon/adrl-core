"""Side-effect classification goldens (ADRL-CAS-003, review defect P1: untrusted MCP hints)."""

from __future__ import annotations

from pathlib import Path

from adrl.core.enums import SideEffectClass
from adrl.routing.side_effects import (
    HINT_CONTRADICTION_TOTAL,
    TrustPolicy,
    classify_command,
    classify_tool,
    executed_side_effects_since_turn_start,
    load_trust_policy,
)

RO = SideEffectClass.READ_ONLY
IDEM = SideEffectClass.IDEMPOTENT
DESTR = SideEffectClass.DESTRUCTIVE


def test_redirect_is_never_read_only() -> None:
    assert classify_tool("Bash", {"command": "echo $TOKEN > /tmp/leak"}) is DESTR
    assert classify_command("cat secrets.env >> out.txt") is DESTR
    assert classify_command("git status > status.txt") is DESTR


def test_compound_command_takes_the_most_severe_part() -> None:
    cls = classify_tool("Bash", {"command": "git status && touch owned"})
    assert cls is not RO
    assert cls in {IDEM, DESTR}
    assert classify_command("ls; rm -rf build") is DESTR
    assert classify_command("cat a | tee b") is DESTR
    assert classify_command("echo hi || git push origin main") is DESTR
    assert classify_command("ls\nmkdir out") is IDEM


def test_plain_read_only_commands_still_read_only() -> None:
    assert classify_command("git status") is RO
    assert classify_command("ls -la src") is RO
    assert classify_command("grep -rn foo . | head") is RO
    assert classify_command("sed -n 1,20p file.py") is RO


def test_write_class_verbs_and_installs() -> None:
    assert classify_command("pip install requests") is DESTR
    assert classify_command("npm install") is DESTR
    assert classify_command("git commit -m x") is DESTR
    assert classify_command("git checkout -- file.py") is DESTR
    assert classify_command("curl -X POST https://x") is DESTR
    assert classify_command("curl -o out.bin https://x") is DESTR
    assert classify_command("sudo ls") is DESTR
    assert classify_command("echo $(cat ~/.aws/credentials)") is DESTR
    assert classify_command("pytest -q") is IDEM
    assert classify_command("cp a b") is IDEM


def test_unparseable_command_is_destructive() -> None:
    assert classify_command("echo 'unterminated") is DESTR
    assert classify_command(None) is DESTR
    assert classify_command("   ") is DESTR


def test_untrusted_server_read_only_hint_on_mutation_tool_is_destructive() -> None:
    before = HINT_CONTRADICTION_TOTAL.labels(server="evil")._value.get()
    cls = classify_tool("mcp__evil__delete", {}, {"annotations": {"readOnlyHint": True}})
    assert cls is DESTR
    assert HINT_CONTRADICTION_TOTAL.labels(server="evil")._value.get() == before + 1


def test_untrusted_server_hints_are_ignored_even_when_benign() -> None:
    assert classify_tool("mcp__x__list", {}, {"annotations": {"readOnlyHint": True}}) is DESTR
    assert classify_tool("mcp__x__y", {}, {"annotations": {"destructiveHint": False}}) is DESTR
    assert classify_tool("unknown_tool", {}) is DESTR


def test_trusted_server_hints_are_honoured() -> None:
    trust = TrustPolicy(servers=frozenset({"filesystem"}))
    ro = {"annotations": {"readOnlyHint": True}}
    idem = {"annotations": {"destructiveHint": False}}
    assert classify_tool("mcp__filesystem__list", {}, ro, trust=trust) is RO
    assert classify_tool("mcp__filesystem__write", {}, idem, trust=trust) is IDEM
    assert classify_tool("mcp__filesystem__rm", {}, {}, trust=trust) is DESTR
    assert classify_tool("mcp__other__list", {}, ro, trust=trust) is DESTR


def test_builtin_names_ignore_hints() -> None:
    assert (
        classify_tool("Read", {"file_path": "x"}, {"annotations": {"destructiveHint": True}}) is RO
    )
    assert (
        classify_tool("Edit", {"file_path": "x"}, {"annotations": {"readOnlyHint": True}}) is IDEM
    )


def test_trust_policy_loads_from_config_and_missing_file_trusts_nobody(tmp_path: Path) -> None:
    assert load_trust_policy(tmp_path).servers == frozenset()
    (tmp_path / "trusted-tool-servers.yaml").write_text(
        "version: trusted-tool-servers-v1\nservers:\n  - name: fs\n  - plain\n", encoding="utf-8"
    )
    policy = load_trust_policy(tmp_path)
    assert policy.servers == frozenset({"fs", "plain"})
    repo_policy = load_trust_policy(Path(__file__).resolve().parents[3] / "config")
    assert repo_policy.version == "trusted-tool-servers-v1"


def _transcript(n_reads: int, mutations: list[tuple[str, dict[str, str]]]) -> dict[str, object]:
    blocks = []
    results = []
    for i in range(n_reads):
        blocks.append(
            {"type": "tool_use", "id": f"r{i}", "name": "Read", "input": {"file_path": f"f{i}.py"}}
        )
        results.append({"type": "tool_result", "tool_use_id": f"r{i}", "content": "ok"})
    for j, (name, inp) in enumerate(mutations):
        blocks.append({"type": "tool_use", "id": f"m{j}", "name": name, "input": inp})
        results.append({"type": "tool_result", "tool_use_id": f"m{j}", "content": "ok"})
    return {
        "messages": [
            {"role": "user", "content": "fix it"},
            {"role": "assistant", "content": blocks},
            {"role": "user", "content": results},
        ]
    }


def test_read_only_calls_appear_in_the_record_with_mutations_first() -> None:
    body = _transcript(
        27,
        [
            ("Edit", {"file_path": "a.py"}),
            ("Bash", {"command": "rm -rf build"}),
            ("Write", {"file_path": "b.py"}),
        ],
    )
    records = executed_side_effects_since_turn_start(body)
    assert len(records) == 30
    assert records[0].side_effect_class is DESTR
    assert records[0].tool == "Bash"
    assert {r.side_effect_class for r in records[1:3]} == {IDEM}
    assert all(r.side_effect_class is RO for r in records[3:])
    assert all(r.status == "ok" for r in records)


def test_record_is_bounded_and_truncation_drops_read_only_first() -> None:
    body = _transcript(60, [("Bash", {"command": "git push"})])
    records = executed_side_effects_since_turn_start(body, limit=10)
    assert len(records) == 10
    assert records[0].side_effect_class is DESTR
    assert sum(1 for r in records if r.side_effect_class is RO) == 9


def test_file_mentions_count_paths_not_extensions() -> None:
    from adrl.routing.features import FILE_MENTION

    text = " ".join(f"src/pkg/mod{i}.py" for i in range(10)) + " and docs/a.md"
    assert len(set(FILE_MENTION.findall(text))) == 11
    assert "src/pkg/mod3.py" in FILE_MENTION.findall(text)
