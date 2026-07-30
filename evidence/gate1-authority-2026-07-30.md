# Gate One serializable authority acceptance — 2026-07-30

## Claim boundary

This receipt supports the following synthetic CockroachDB Cloud claim:

> Across 100 independent races of 50 concurrent database sessions, Tideproof
> committed exactly one authority winner, 49 durable denial receipts, one
> fence increment, and one outbox intent per race. No race recorded an effect.
> Concurrent operation and semantic replays changed authority once. The
> protected synthetic effect boundary rejected stale, future, expired, and
> cross-scope fences, then recorded the current effect exactly once under
> 50-way replay. CockroachDB produced a real `40001`, and the whole
> serializable callback retried to a correct final value.

This does **not** prove exactly-once behavior in an external system, production
availability, regional survival, or emergency readiness. The protected effect
is a synthetic CockroachDB table boundary. Ambiguous COMMIT handling is a
separate gate.

## Source and environment

- Source commit:
  `55892bf25a5286af30e30908ab5711e24f106629`
- Database: `tideproof`
- CockroachDB Cloud cluster:
  `4bd5f0c9-729a-468e-b47c-5c5ed9cd41f9`
- Plan/region: Basic, AWS `us-east-1`
- Previously observed CockroachDB version: CCL v26.2.1
- Proof label: `gate1-84b838d8-e522-417b-a5fe-f75aeac41b31`
- Secrets: macOS Keychain only; no database credential was written to this
  repository or receipt

## Acceptance command

```sh
DATABASE_URL="<primary URL from Keychain>" \
RACE_RUNS=100 \
CONTENDERS=50 \
npm run gate1:authority
```

Exit status: 0.

Top-level receipt:

```json
{
  "gate": "serializable-authority-core",
  "passed": true,
  "proofLabel": "gate1-84b838d8-e522-417b-a5fe-f75aeac41b31",
  "database": "tideproof",
  "raceRuns": 100,
  "contenderCount": 50,
  "totalContenders": 5000,
  "raceInvariantViolations": 0
}
```

Every race asserted:

- 50 distinct initial CockroachDB backend session IDs;
- actual `SHOW TRANSACTION ISOLATION LEVEL` equal to `serializable`;
- exactly one `resource_reserved` result and 49
  `resource_held_denied` results;
- exactly 50 durable terminal receipts;
- exactly one outbox intent and no protected effect;
- current fence exactly `1`;
- holder operation equal to the winning receipt;
- a denied request remained denied after lease expiry;
- the same semantic request under a new operation ID returned the original
  denial;
- the original operation ID with changed input was rejected.

## Independent persisted-row reconciliation

A new strongly consistent read after the gate returned:

```json
{
  "resources": "100",
  "fence_sum": "100",
  "holders": "100",
  "receipts": "5000",
  "winners": "100",
  "denials": "4900",
  "outboxes": "100",
  "effects": "0"
}
```

Grouping by each of the 100 resources returned:

```json
{
  "min_receipts": "50",
  "max_receipts": "50",
  "min_winners": "1",
  "max_winners": "1",
  "min_denials": "49",
  "max_denials": "49",
  "min_outboxes": "1",
  "max_outboxes": "1",
  "min_effects": "0",
  "max_effects": "0",
  "min_fence": "1",
  "max_fence": "1"
}
```

## Concurrent replay proof

Two additional 50-way races used identical semantics:

```json
{
  "sameOperation": {
    "reserved": 1,
    "operationReplays": 49,
    "durableReceipts": 1,
    "outboxes": 1,
    "effects": 0,
    "fence": "1"
  },
  "differentOperationsSameSemantics": {
    "reserved": 1,
    "semanticReplays": 49,
    "durableReceipts": 1,
    "outboxes": 1,
    "effects": 0,
    "fence": "1"
  },
  "exactWinnerReplay": "operation_replay",
  "changedFieldsDenied": [
    "agentId",
    "effectKey",
    "payload"
  ]
}
```

## Fencing and synthetic effect proof

The first lease received fence `1`; after expiry, a fresh authorized operation
received fence `2`.

The protected effect boundary rejected:

- stale fence `1`;
- future fence `3`;
- wrong actor;
- wrong tenant;
- wrong incident;
- wrong resource;
- wrong run;
- expired current fence.

The valid current fence recorded one synthetic protected effect. Its exact
replay returned `effect_already_recorded`. Under 50 concurrent calls, one
reported `protected_effect_recorded`, 49 reported replay, and one effect row
remained.

## Admissibility and retry proof

Each inadmissible request left fence `0`, one durable denial receipt, and zero
outbox rows:

```json
[
  ["invalid-provenance", "verification_receipt_missing"],
  ["unresolved-conflict", "unresolved_conflict"],
  ["future-observation", "future_observation"],
  ["expired", "expired"],
  ["out-of-scope", "out_of_scope"]
]
```

The retry probe produced a real CockroachDB `40001`. One contender retried the
entire callback once under the same inputs, and the committed values advanced
from `0` to `1` to `2`; the final value was `2`.

## Remaining gates

- Complete the repeated process-death/COMMIT-ambiguity acceptance receipt.
- Deploy separate AWS runtime identities and prove that only the authorizer
  can spend authority and only the dispatcher can attempt the synthetic
  effect.
- Keep the public claim limited to a synthetic database-protected effect; do
  not call any external side effect exactly once.
