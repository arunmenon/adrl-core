# adrl-core engineering rules

These rules apply to every change in this repository. The architecture source of truth is the ADR
register in `../adrl-world-class/adr/<BUCKET>/ADRL-<BUCKET>-NNN.md` (reviewed 2026-09-02). The stack
proposal that this repository implements is `../adrl-world-class/design/implementation-stack.md`.

## Ownership

- Every module docstring names its primary ADRL ID on the first line, for example
  `"""Secret detection on new content. Primary: ADRL-SAF-003."""`. Secondary IDs are listed only for
  real cross-cutting contracts.
- Packages map to buckets: `wire` (SEM), `gates` (SAF), `routing` (RTG), `cascade` (CAS), `ledger`
  (MEM), `learning` (LRN). `core`, `config`, `proxy`, `telemetry` and `cli` are shared plumbing.
- A task implements an indexed decision. It does not need a new decision merely because it adds a
  file. If no decision fits, stop and propose one in the register; do not invent behaviour.

## Invariants the code must keep

- Never rewrite a request body on the frontier or passthrough path. The bytes the harness sent are
  the bytes the gateway receives, and response bytes (SSE `ping` events, upstream error wording)
  are relayed unmodified. Body rewrites exist only for non-Claude rungs (ADRL-FND-001).
  One carve-out (ADRL-CAS-004): after an escalation whose source turn carried no thinking
  blocks, the `thinking` parameter is stripped from frontier-bound requests until the next user
  turn, and the plan records `thinking_suppressed`.
- No `UPDATE` or `DELETE` SQL anywhere under `src/`. The evidence ledger and the egress ledger are
  append-only. Corrections are new events; erasure is key deletion plus an `erased` event
  (ADRL-MEM-001, ADRL-MEM-010). `tools/check_ledger_discipline.py` enforces this in CI.
- Every "versioned policy constant" named in an ADR is a field on a versioned config model, and the
  config version is recorded on the decision row it influenced. Changing a threshold is a config
  version bump, never a literal in code.
- Shadow code never imports into live routing. Nothing under `adrl.learning` and no module whose
  name starts with `shadow_` may be imported by `adrl.routing` or `adrl.proxy` (ADRL-MEM-008).
- A privacy pin can only be released by the audited human path (ADRL-SAF-002). No code path in
  routing, cascade, fallback or episode handling may clear pin state.
- Gate outcomes only tighten the permitted rung set within a lineage. `PermittedSet.tighten`
  raises on any attempt to widen (ADRL-SAF-001).
- Terminal failures are rendered as Anthropic Messages API error objects, never as synthetic
  assistant content (ADRL-CAS-007).

## Code quality

- No mock implementations. Write the real thing, or leave a `TODO(ADRL-XXX-NNN):` comment naming
  the owning decision and raise `NotImplementedError` with the same text.
- Type hints on every public function; `mypy --strict` must pass.
- No em dashes in any file, including docs, docstrings and log messages.
- Descriptive names. No adjectives in file names.
- `structlog` for logging, never `print` in `src/`.
- Pydantic v2 at config and record boundaries; frozen dataclasses for internal value objects.

## Running checks

```bash
.venv/bin/python -m ruff check src tests tools
.venv/bin/python -m ruff format --check src tests tools
.venv/bin/python -m mypy
.venv/bin/python -m pytest -q
.venv/bin/python tools/check_ledger_discipline.py
.venv/bin/python -m adrl.cli.main config check
```

All six must pass before a change is considered done. Use `uv sync --all-extras` to refresh the
virtual environment; the lockfile is checked in and only binary wheels are used.
