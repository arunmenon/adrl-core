# Cascade outcome contract

9 September 2026. Owning ADRs: MEM-001/002/004, CAS-003/007 and FND-003.

The cascade now uses the existing `outcome_event` constructor: event type `outcome`,
state in `payload.state`, schema `events-v1`, failure taxonomy version retained.
Pending and closed-turn transitions carry session/lineage HMACs, existing diagnostic
facts and unknown harness success. Terminal failure cause survives subsequent turns.
The proxy forwards returned LedgerEvent objects without replacing their route,
producer, sequence or schema. Normal composition supplies the controller's ledger;
without that ledger, plan-phase events are not persisted. Observe-phase forwarding
is tested with a pre-seeded counter, not a replacement for required plan-phase ledger
wiring or a qualification of cold-start forwarding without ledger sequence visibility.

The integration test connects the composed proxy/cascade/store to explicitly invoked
Closer and readiness projection. It proves a closed count, not verified success or
learning eligibility. No background closer is installed by this repair. Shared E2E
fixtures use synthetic ASGI responses and SHADOW-loaded bundles with LIVE pipeline
settings. This is not production admission, real-harness or lab portability evidence.

Historical state-valued event types are left untouched. They do not enter canonical
readiness counts, even as censored rows; recovery needs a separately reviewed replay.
No schema migration, historical relabeling or maturity promotion is performed.

Other review findings remain: rule-health event shape/refresh, correction consumption,
verifier calibration, learning features-v2 admission, estimator selection, lab portability
and live-config admission. Thus RV-01 repair does not establish a complete learning loop.
