# Local engineering evidence

Primary: ADRL-FND-005. Secondary: ADRL-EVL-009, ADRL-SEM-007.

From the repository, use the existing Python 3.12 environment:

```bash
.venv/bin/python tools/check_all.py --out /absolute/private/new-run-directory
```

The output directory must be new and outside the repository. The runner makes it private and
records each check's exit status, elapsed time and log. `manifest.json` is saved as work proceeds.
A killed runner may leave `running`; that is incomplete evidence, never a pass. The default
timeout is ten minutes per command, configurable with `--timeout` (1-1800 seconds). A timed-out
or cancelled command's process group is killed. No retries or model-service calls are added.

The command runs the six checks in AGENTS.md, the data inventory, learning contract, exact API
export comparison, ADR map freshness/ownership and register/index coverage. Any failure prevents
a passing result. Unimplemented register decisions may remain unmapped and are reported by name;
this is different from a module citing a nonexistent decision or having no ADR ownership.

Source/config/docs/API/artifact hashes are recorded before and after. Added, removed or changed
declared inputs invalidate the combined result. The Python/platform and installed package
versions are recorded. Private keys, `.env` files, runtime payloads and caches are excluded.
The inherited process environment and installed binaries are not fully frozen. This is drift
detection for a trusted local engineering run, not an atomic workspace snapshot, hostile-code
sandbox, independent review, reproducible deployment image or release/maturity authorization.

To deliberately refresh generated artifacts, inspect the change and run:

```bash
.venv/bin/python tools/adr_module_map.py
.venv/bin/python tools/export_api_contract.py --out api/adrl-api-v1-preview.json
```

The check runner itself never refreshes either artifact. An API diff needs an explicit compatible
change or preview revision; regenerating JSON does not establish compatibility. The local
runner can later be used by CI, but no hosted workflow currently exists. Keep private run logs
locally; publish scoped summaries and hashes in the register rather than assuming logs are safe
to publish. Source backups exclude ignored runtime data and are a separate W0 artifact.
