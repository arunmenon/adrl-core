"""Mechanical side-effect classification of tool calls. Primary: ADRL-CAS-003.
Also implements: ADRL-CAS-009 (register additions of 2026-09-03).

Secondary: ADRL-RTG-004. Class is derived from tool name, the trust status of the tool's
server, and, for shell tools, a parsed command line. Model-authored text is never consulted.

Trust model (MCP specification, tools: annotations are hints and MUST be treated as untrusted
unless the server is trusted): a hint is honoured only when the tool's server is listed in
`config/trusted-tool-servers.yaml`. Harness built-ins are trusted for their names only. Any
tool that is neither a known built-in nor an MCP tool from a trusted server is destructive.
Shell commands are split on operators and classified by the most severe part; an unparseable
command is destructive.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from prometheus_client import Counter

from adrl.core.enums import SideEffectClass
from adrl.core.types import SideEffectRecord
from adrl.telemetry.metrics import REGISTRY

SIDE_EFFECT_TABLE_VERSION = "side-effects-v2"
TRUSTED_SERVERS_FILE = "trusted-tool-servers.yaml"
HANDOFF_RECORD_LIMIT = 40

HINT_CONTRADICTION_TOTAL = Counter(
    "adrl_hint_contradiction_total",
    "MCP readOnlyHint on a mutation-named tool from an untrusted server (ADRL-CAS-003)",
    ["server"],
    registry=REGISTRY,
)

_SEVERITY: dict[SideEffectClass, int] = {
    SideEffectClass.READ_ONLY: 0,
    SideEffectClass.IDEMPOTENT: 1,
    SideEffectClass.DESTRUCTIVE: 2,
}

READ_ONLY_TOOLS: frozenset[str] = frozenset(
    {
        "read",
        "read_file",
        "readfile",
        "view",
        "view_file",
        "cat",
        "open_file",
        "glob",
        "grep",
        "ls",
        "list_files",
        "websearch",
        "webfetch",
        "todoread",
        "taskoutput",
        "listagents",
        "toolsearch",
        "notebookread",
    }
)
IDEMPOTENT_TOOLS: frozenset[str] = frozenset(
    {
        "edit",
        "multiedit",
        "write",
        "str_replace",
        "str_replace_editor",
        "str_replace_based_edit_tool",
        "apply_patch",
        "create_file",
        "notebookedit",
        "todowrite",
        "taskcreate",
        "taskupdate",
    }
)
SHELL_TOOLS: frozenset[str] = frozenset({"bash", "shell", "run_command", "execute", "terminal"})

MUTATION_NAME_WORDS: tuple[str, ...] = (
    "delete",
    "remove",
    "write",
    "deploy",
    "migrate",
    "push",
    "reset",
    "drop",
    "destroy",
    "truncate",
    "purge",
    "wipe",
)

# Shell parsing. Segments are split on control operators; each segment is classified by its
# first word (after stripping env assignments and privilege wrappers), its flags, and any
# redirect to a path.
_OPERATOR_SPLIT = re.compile(r"\s*(?:&&|\|\||;|\||\n)\s*")
_SUBSHELL = re.compile(r"\$\(|`|\(\s*\w")
_REDIRECT = re.compile(r"(?<![<>])(?:>>|>|\d>)(?!&)")
_ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

READ_ONLY_VERBS: frozenset[str] = frozenset(
    {
        "ls",
        "cat",
        "head",
        "tail",
        "grep",
        "rg",
        "find",
        "wc",
        "pwd",
        "echo",
        "printf",
        "which",
        "env",
        "printenv",
        "stat",
        "file",
        "tree",
        "awk",
        "sort",
        "uniq",
        "cut",
        "diff",
        "less",
        "more",
        "true",
        "date",
        "whoami",
        "id",
        "uname",
        "type",
    }
)
READ_ONLY_GIT_SUBCOMMANDS: frozenset[str] = frozenset(
    {"status", "diff", "log", "show", "branch", "rev-parse", "ls-files", "blame", "describe"}
)
IDEMPOTENT_VERBS: frozenset[str] = frozenset(
    {"touch", "mkdir", "cp", "mv", "ln", "chmod", "chown", "sed", "python", "python3"}
)
DESTRUCTIVE_VERBS: frozenset[str] = frozenset(
    {"rm", "rmdir", "mkfs", "dd", "shred", "truncate", "kill", "pkill", "killall", "reboot", "tee"}
)
DESTRUCTIVE_GIT_SUBCOMMANDS: frozenset[str] = frozenset(
    {"push", "reset", "rebase", "filter-branch", "commit", "clean", "stash", "merge", "am"}
)
DESTRUCTIVE_COMMAND_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"\bgit\s+checkout\s+--(\s|$)",
        r"\bgit\s+branch\s+-[dD]\b",
        r"\bdrop\s+(table|database)\b",
        r"\b(deploy|kubectl\s+(apply|delete)|terraform\s+(apply|destroy))\b",
        r"\bhelm\s+(install|upgrade|uninstall)\b",
        r"\b(alembic\s+upgrade|rails\s+db:migrate|prisma\s+migrate|django-admin\s+migrate)\b",
        r"\bmanage\.py\s+migrate\b",
        r"\b(pip|pip3|npm|pnpm|yarn|cargo|gem|brew|apt|apt-get)\s+(install|uninstall|remove|add)\b",
        r"\buv\s+pip\s+(install|uninstall)\b",
        r"\bcurl\b.*(\s-X\s*(POST|PUT|DELETE|PATCH)\b|\s-[oO]\b|\s--output\b|\s-d\s|\s--data\b)",
        r"\bwget\b",
        r"\bsudo\b|\bdoas\b",
    )
)

RESOURCE_KEYS: tuple[str, ...] = ("file_path", "path", "filename", "notebook_path", "file")
COMMAND_KEYS: tuple[str, ...] = ("command", "cmd", "argv")


@dataclass(frozen=True)
class TrustPolicy:
    """Servers whose MCP annotations are honoured (trusted-tool-servers-v1)."""

    version: str = "trusted-tool-servers-v1"
    servers: frozenset[str] = field(default_factory=frozenset)

    def trusts(self, server: str | None) -> bool:
        return bool(server) and server in self.servers

    @classmethod
    def load(cls, path: Path) -> TrustPolicy:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        entries = raw.get("servers") or []
        names: set[str] = set()
        for entry in entries:
            if isinstance(entry, Mapping) and isinstance(entry.get("name"), str):
                names.add(entry["name"])
            elif isinstance(entry, str):
                names.add(entry)
        return cls(version=str(raw.get("version", cls.version)), servers=frozenset(names))


UNTRUSTED = TrustPolicy()


def load_trust_policy(config_dir: Path) -> TrustPolicy:
    """Load the allow-list; a missing file trusts nobody."""
    path = config_dir / TRUSTED_SERVERS_FILE
    if not path.exists():
        return UNTRUSTED
    return TrustPolicy.load(path)


def _annotations(tool_def: Mapping[str, Any] | None) -> Mapping[str, Any]:
    if not tool_def:
        return {}
    annotations = tool_def.get("annotations")
    return annotations if isinstance(annotations, Mapping) else {}


def mcp_server_of(name: str) -> str | None:
    """Server segment of `mcp__<server>__<tool>`, else None."""
    if not name.startswith("mcp__"):
        return None
    parts = name.split("__")
    return parts[1] if len(parts) >= 3 and parts[1] else None


def _looks_like_mutation(name: str) -> bool:
    lowered = name.lower()
    return any(word in lowered for word in MUTATION_NAME_WORDS)


def _class_from_hints(annotations: Mapping[str, Any]) -> SideEffectClass:
    """MCP defaults: destructiveHint true, readOnlyHint false, idempotentHint false."""
    if annotations.get("readOnlyHint") is True:
        return SideEffectClass.READ_ONLY
    if annotations.get("destructiveHint") is False:
        return SideEffectClass.IDEMPOTENT
    if annotations.get("idempotentHint") is True and annotations.get("destructiveHint") is not True:
        return SideEffectClass.IDEMPOTENT
    return SideEffectClass.DESTRUCTIVE


def classify_tool(
    name: str,
    tool_input: Mapping[str, Any] | None = None,
    tool_def: Mapping[str, Any] | None = None,
    *,
    trust: TrustPolicy = UNTRUSTED,
) -> SideEffectClass:
    """Classify one tool call. Names decide built-ins; hints count only from trusted servers."""
    lowered = name.lower()
    if lowered in READ_ONLY_TOOLS:
        return SideEffectClass.READ_ONLY
    if lowered in IDEMPOTENT_TOOLS:
        return SideEffectClass.IDEMPOTENT
    if lowered in SHELL_TOOLS:
        return classify_command(_command_text(tool_input))
    server = mcp_server_of(name)
    annotations = _annotations(tool_def)
    if server is not None and trust.trusts(server):
        return _class_from_hints(annotations)
    if annotations.get("readOnlyHint") is True and _looks_like_mutation(name):
        HINT_CONTRADICTION_TOTAL.labels(server=server or "unknown").inc()
    return SideEffectClass.DESTRUCTIVE


def _strip_prefix_words(words: list[str]) -> tuple[list[str], bool]:
    """Drop env assignments and wrappers; report whether a privilege wrapper was present."""
    privileged = False
    while words:
        head = words[0]
        if _ENV_ASSIGN.match(head):
            words = words[1:]
            continue
        if head in {"sudo", "doas"}:
            privileged = True
            words = words[1:]
            continue
        if head in {"time", "nice", "nohup", "exec", "command", "builtin"}:
            words = words[1:]
            continue
        break
    return words, privileged


def _classify_segment(segment: str) -> SideEffectClass:
    text = segment.strip()
    if not text:
        return SideEffectClass.READ_ONLY
    for pattern in DESTRUCTIVE_COMMAND_PATTERNS:
        if pattern.search(text):
            return SideEffectClass.DESTRUCTIVE
    if _SUBSHELL.search(text):
        return SideEffectClass.DESTRUCTIVE
    try:
        words = shlex.split(text, posix=True)
    except ValueError:
        return SideEffectClass.DESTRUCTIVE
    words, privileged = _strip_prefix_words(words)
    if privileged or not words:
        return SideEffectClass.DESTRUCTIVE
    redirect = bool(_REDIRECT.search(text))
    verb = Path(words[0]).name.lower()
    if verb == "git":
        sub = words[1].lower() if len(words) > 1 else ""
        if sub in DESTRUCTIVE_GIT_SUBCOMMANDS:
            return SideEffectClass.DESTRUCTIVE
        if sub in READ_ONLY_GIT_SUBCOMMANDS:
            return SideEffectClass.DESTRUCTIVE if redirect else SideEffectClass.READ_ONLY
        return SideEffectClass.IDEMPOTENT
    if verb in DESTRUCTIVE_VERBS:
        return SideEffectClass.DESTRUCTIVE
    if redirect:
        return SideEffectClass.DESTRUCTIVE
    if verb in READ_ONLY_VERBS:
        return SideEffectClass.READ_ONLY
    if verb == "sed" and "-n" in words[1:] and not any(w.startswith("-i") for w in words[1:]):
        return SideEffectClass.READ_ONLY
    if verb in IDEMPOTENT_VERBS:
        return SideEffectClass.IDEMPOTENT
    return SideEffectClass.IDEMPOTENT


def classify_command(command: str | None) -> SideEffectClass:
    """Most severe class over the operator-split segments; unparseable is destructive."""
    if command is None:
        return SideEffectClass.DESTRUCTIVE
    text = command.strip()
    if not text:
        return SideEffectClass.DESTRUCTIVE
    worst = SideEffectClass.READ_ONLY
    segments = [s for s in _OPERATOR_SPLIT.split(text) if s.strip()]
    if not segments:
        return SideEffectClass.DESTRUCTIVE
    for segment in segments:
        cls = _classify_segment(segment)
        if _SEVERITY[cls] > _SEVERITY[worst]:
            worst = cls
        if worst is SideEffectClass.DESTRUCTIVE:
            break
    return worst


def _command_text(tool_input: Mapping[str, Any] | None) -> str | None:
    if not tool_input:
        return None
    for key in COMMAND_KEYS:
        value = tool_input.get(key)
        if isinstance(value, str):
            return value
        if isinstance(value, list):
            return " ".join(str(v) for v in value)
    return None


def target_of(name: str, tool_input: Mapping[str, Any] | None) -> str:
    """Target path or command for the handoff note; never model prose."""
    if not tool_input:
        return name
    for key in RESOURCE_KEYS:
        value = tool_input.get(key)
        if isinstance(value, str) and value:
            return value
    command = _command_text(tool_input)
    if command:
        return command[:200]
    return name


def tool_definitions(body: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    tools = body.get("tools")
    out: dict[str, Mapping[str, Any]] = {}
    if isinstance(tools, list):
        for tool in tools:
            if isinstance(tool, Mapping) and isinstance(tool.get("name"), str):
                out[tool["name"]] = tool
    return out


def max_available_side_effect(
    body: Mapping[str, Any], *, trust: TrustPolicy = UNTRUSTED
) -> SideEffectClass:
    """Highest side-effect class among the tools the harness offered this turn."""
    worst = SideEffectClass.READ_ONLY
    for name, tool in tool_definitions(body).items():
        cls = classify_tool(name, {}, tool, trust=trust)
        if _SEVERITY[cls] > _SEVERITY[worst]:
            worst = cls
    return worst


def turn_start_index(messages: Sequence[Mapping[str, Any]]) -> int:
    """Index of the last developer-authored user message (no tool_result block)."""
    for index in range(len(messages) - 1, -1, -1):
        message = messages[index]
        if message.get("role") != "user":
            continue
        content = message.get("content")
        if isinstance(content, str) and content.strip():
            return index
        if (
            isinstance(content, list)
            and content
            and not any(isinstance(b, Mapping) and b.get("type") == "tool_result" for b in content)
            and any(isinstance(b, Mapping) and b.get("type") == "text" for b in content)
        ):
            return index
    return 0


def _ordered(records: Iterable[SideEffectRecord], limit: int) -> tuple[SideEffectRecord, ...]:
    """Non-read-only first (most severe first), then read-only, bounded by count."""
    ranked = sorted(
        enumerate(records),
        key=lambda item: (-_SEVERITY[item[1].side_effect_class], item[0]),
    )
    return tuple(record for _, record in ranked[:limit])


def executed_side_effects_since_turn_start(
    body: Mapping[str, Any],
    *,
    trust: TrustPolicy = UNTRUSTED,
    limit: int = HANDOFF_RECORD_LIMIT,
) -> tuple[SideEffectRecord, ...]:
    """Enumerate every tool call executed since the turn began (ADRL-CAS-003 cl. 3).

    Read-only calls are included: the record enumerates what ran, and a call the classifier
    believed read-only is still evidence for the next rung. The list is bounded and ordered
    most severe first so truncation drops read-only entries before mutations.
    """
    messages = body.get("messages")
    if not isinstance(messages, list):
        return ()
    defs = tool_definitions(body)
    start = turn_start_index(messages)
    results: dict[str, Mapping[str, Any]] = {}
    for message in messages[start:]:
        if message.get("role") != "user" or not isinstance(message.get("content"), list):
            continue
        for block in message["content"]:
            if isinstance(block, Mapping) and block.get("type") == "tool_result":
                tool_use_id = block.get("tool_use_id")
                if isinstance(tool_use_id, str):
                    results[tool_use_id] = block
    records: list[SideEffectRecord] = []
    for message in messages[start:]:
        if message.get("role") != "assistant" or not isinstance(message.get("content"), list):
            continue
        for block in message["content"]:
            if not isinstance(block, Mapping) or block.get("type") != "tool_use":
                continue
            name = str(block.get("name") or "")
            tool_input = block.get("input") if isinstance(block.get("input"), Mapping) else {}
            cls = classify_tool(name, tool_input, defs.get(name), trust=trust)
            tool_use_id = str(block.get("id") or "")
            result = results.get(tool_use_id)
            if result is None:
                status = "unanswered"
            elif result.get("is_error"):
                status = "error"
            else:
                status = "ok"
            records.append(
                SideEffectRecord(
                    tool=name,
                    target=target_of(name, tool_input),
                    status=status,
                    side_effect_class=cls,
                )
            )
    return _ordered(records, limit)
