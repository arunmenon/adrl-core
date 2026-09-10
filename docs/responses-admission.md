# Responses profile admission decision

Primary: ADRL-SEM-007. Secondary: ADRL-FND-001, ADRL-SAF-002, ADRL-CAS-004.

Status: candidate scope selected for the compatibility spike, 7 September 2026. Not registered
in the runtime. No real Codex corpus or provider execution was collected in this work package.

## Initial scope

Investigate HTTP with native Responses streaming and client-carried input, initially bound to one
approved compatible deployment. Do not introduce server-state retrieval or cross-profile handoff
in the first profile. Codex documents the Responses wire API and a separate WebSocket capability
setting; these configuration options alone do not prove a particular CLI version works in this
scope. [Codex configuration](https://learn.chatgpt.com/docs/config-file/config-reference)

For a future gated profile, reject non-null `previous_response_id` and conversation references
until a state resolver is explicitly designed and tested. Do not strip them or silently continue
with an incomplete transcript. Require `store=false` for the candidate request mode; this controls
response-object storage and is not a claim about all provider retention. Responses can refer to
previous state that is absent from the current request, which is why request-local scanning alone
does not establish full history coverage. [Conversation state](https://developers.openai.com/api/docs/guides/conversation-state)

Opaque reasoning and compaction items need custody and lineage rules before admission. Preserve
their bytes and provider pairing when supported; do not turn them into text or discard them to
make a test pass. Initially reject opaque state without an established, policy-compatible custody
chain. If Codex requires these items, that is an admission blocker requiring implementation, not
permission to downgrade its behavior. A pin must still cause local-or-block behavior; opaque
provider-bound state cannot be handed to an incompatible local model. [Reasoning guide](https://developers.openai.com/api/docs/guides/reasoning)

## Required corpus and conformance work

| Case | Candidate treatment | Evidence required before registration |
|---|---|---|
| Explicit input messages | Interpret by native item/role rules, preserve raw bytes | Real CLI capture plus request/response comparison |
| Function-call output | Map tool call IDs and complete/partial boundaries | Parallel calls, partial outputs, interruption and retry fixtures |
| Referenced server state | Reject before dispatch | No stripping, fetching or unclassified fallback |
| Opaque reasoning or compaction | Admit only with tested custody/pairing; otherwise reject | Continuation, restart, pin and foreign-lineage cases |
| Images, files, hosted tools or external references | Unsupported until a content/egress rule exists | Content visibility and dispatch-coverage evidence |
| Streaming and cancellation | Preserve events, errors and cancellation; never replay side effects | Fragmented streams, missing completion, disconnect and retry cases |
| WebSocket transport | Outside the initial candidate scope | Either establish a working HTTP CLI configuration or explicitly implement transport support |
| Child and resumed sessions | Preserve authoritative binding and restrictions | Real CLI identities plus restart/parent-return scenarios |

These are acceptance cases, not claims that fixtures have been captured or that Codex always emits
these fields. Use scrubbed captures from the selected CLI version. Test existing gates and cascade
against the native view, record the request classes and content-bearing rules, render native error
shapes, and complete all SEM-007 prerequisites. Cross-profile handoff remains forbidden.

If the selected Codex build cannot run under this candidate scope, expand the profile through a
reviewed state/transport design and tests. Do not advertise Codex support until it actually works.
