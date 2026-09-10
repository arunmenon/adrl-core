# Protocol boundary and API preview

Update 2026-09-07: [product services](product-services.md) now serve the session/event/read
operations below. Bound product sessions reject unknown endpoints and conflicting credentials.
Unbound traffic retains the legacy forwarding limitation. This update does not add Responses.

Primary: ADRL-SEM-007. Secondary: ADRL-FND-001, ADRL-SEM-002, ADRL-MEM-001, ADRL-TRU-001.

## Implemented in this work package

The pipeline selects its installed profile before classification. `MessagesProfile` owns
Messages parsing/classification, rewrite serialization, stream observation, native errors,
utility responses, token-count rendering and the pipeline's boundary interpretation.
`ClaudeCodeAdapter` extracts correlation signals. The shared identity resolver consumes those
signals, preserving existing header, metadata, anonymous and parent-chain behavior. Old resolver
entry points remain compatible. Neither the adapter nor a native session header authenticates a
repository; existing workload gates still own that check.

The request context and decision context record the profile and adapter IDs and versions. Native
JSON remains an inspection view beside the original bytes. On the unchanged path, the gateway
receives those original bytes. Protocol ports do not imply arbitrary profiles are safe to install.

`GET /adrl/v1/capabilities` describes the shipped implementation. It reports Messages, the
Claude Code adapter, authenticated identity binding and implemented tool-event intake. Profile
validation remains `offline_fixtures`; its tested harness-version list is deliberately empty
because the observation pilot did not qualify the model profile. It does not attest runtime
enforcement or provider health.

Session binding, event ingestion and evidence reads in `api/adrl-api-v1-preview.json` are
implemented; see [product services](product-services.md) for the preview-4 contract. The entire
`/adrl/v1` namespace is reserved locally, so product payloads cannot be forwarded to a provider
by the legacy catch-all route. Re-export the contract:

```bash
PYTHONPATH=src .venv/bin/python tools/export_api_contract.py --out api/adrl-api-v1-preview.json
```

## Deliberately remaining work

The gates, feature extraction, transcript transformation and cascade still inspect Messages
JSON. They must gain explicit profile coverage before Responses admission. A second parser alone
is insufficient. Claude Code utility fingerprints also require a separate corpus/configuration
for another harness. No OpenCode or Codex integration is claimed by this extraction.

Unknown provider paths keep their existing forwarding behavior. Legacy Messages-prefix suffixes
also retain their old classifier behavior; only the two advertised endpoints are supported
operations. The decision context marks whether its operation is supported. Unknown endpoint
rejection on an enforcing listener is a separate FND/SEM change required before product release.
The Responses admission document does not activate that policy on the current listener.

Binding uses existing signed local launcher assertions; renewal preserves the binding identity.
Durable event ingestion derives producer identity from the assertion, acknowledges only committed
appends and handles identical retries and conflicting event IDs. Late events and sequence gaps
remain visible. Harness credentials cannot submit trusted verification. Operator session checks
now execute on temporary snapshots, but retained output at a trusted task-close boundary remains
W3 work. Remote identity issuance/revocation, child binding and automatic credential refresh with
outbox resume remain unsupported. These limits differ from unimplemented session/event services.

The first API version is a preview. Compatibility can change with explicit preview revision bumps
until two harnesses and two protocols validate the boundary. See `responses-admission.md` for the
second protocol's current scope decision and admission blockers.
