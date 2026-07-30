# Gate One COMMIT ambiguity acceptance — 2026-07-30

## Claim boundary

This receipt supports the following synthetic CockroachDB Cloud claim:

> Tideproof survived 100 process deaths at each of three transaction
> boundaries without exposing partial authority or blindly replaying an
> ambiguous COMMIT. Pre-COMMIT deaths were retried only after fresh strong
> reads observed no terminal state. COMMIT-dispatched deaths resolved to
> either one complete transaction or `UNKNOWN_DO_NOT_ACT`. Acknowledged
> commits always reconciled to one complete transaction.

This does **not** prove that CockroachDB received every COMMIT whose bytes were
flushed by the client, exactly-once external effects, regional survival, or
production availability. A response-dropping TCP proxy would be a stronger
future network-boundary proof. Tideproof deliberately preserves uncertainty
rather than treating absence as proof of abort at the ambiguous boundary.

## Source and environment

- Source commit:
  `55892bf25a5286af30e30908ab5711e24f106629`
- Database: `tideproof`
- CockroachDB Cloud cluster:
  `4bd5f0c9-729a-468e-b47c-5c5ed9cd41f9`
- Plan/region: Basic, AWS `us-east-1`
- Proof label: `ambiguity-78c662d8-e845-4566-aac9-c4154d897ae7`
- Secrets: macOS Keychain only; no credential was written to this repository
  or receipt

## Acceptance command

The full script executed every assertion, while `jq` reduced only the final
console receipt:

```sh
DATABASE_URL="<primary URL from Keychain>" \
AMBIGUITY_RUNS=100 \
node scripts/gate1-ambiguity.js |
jq "<summary projection requiring passed == true>"
```

Pipeline exit status: 0.

## Receipt

```json
{
  "gate": "commit-ambiguity",
  "passed": true,
  "proofLabel": "ambiguity-78c662d8-e845-4566-aac9-c4154d897ae7",
  "database": "tideproof",
  "runsPerBoundary": 100,
  "beforeCommit": {
    "count": 100,
    "unknownDoNotAct": 100,
    "safeExactRetries": 100,
    "partialStates": 0
  },
  "commitDispatched": {
    "count": 100,
    "committed": 94,
    "unknownDoNotAct": 6,
    "partialStates": 0
  },
  "afterCommitBeforeResponse": {
    "count": 100,
    "committed": 100,
    "completeStates": 100
  },
  "invariantViolations": 0,
  "blindRetries": 0
}
```

Each child process wrote its boundary marker through a dedicated file
descriptor and was then terminated with `SIGKILL`:

- `dml_staged_commit_not_sent`
- `commit_bytes_flushed_ack_unread`
- `commit_acknowledged_response_not_sent`

Every reconciliation used a new database connection and a strongly consistent
serializable read of the exact operation ID and canonical request digest.

## Boundary behavior

### Before COMMIT

All 100 children died after the receipt, fence, and outbox DML was staged but
before COMMIT was sent. Bounded reconciliation returned
`UNKNOWN_DO_NOT_ACT`; a snapshot then showed:

- zero receipt rows;
- zero outbox rows;
- zero effect rows;
- fence `0`.

Only after that pre-COMMIT boundary and empty strong-read state were both
established did the harness retry the exact same operation ID and digest. All
100 retries produced one complete authority transaction.

### COMMIT dispatched, acknowledgement unread

All 100 children died after the PostgreSQL stream reported the COMMIT bytes
flushed but before the client received the database result:

- 94 reconciled `COMMITTED`;
- 6 remained `UNKNOWN_DO_NOT_ACT`;
- 0 were blindly retried;
- 0 exposed a partial transaction.

The six unknown cases are accepted fail-closed outcomes. This boundary marker
does not assert that CockroachDB received those six COMMIT messages.

### COMMIT acknowledged, application response unsent

All 100 children died after `COMMIT` returned successfully but before the
application could return its operation result. Every request reconciled
`COMMITTED` with exactly one receipt, one outbox, fence `1`, and zero effects.

## Independent persisted-row reconciliation

A new strong read after the gate returned:

```json
{
  "before_commit": {
    "resources": "100",
    "complete": "100",
    "empty": "0",
    "partial": "0"
  },
  "commit_dispatched": {
    "resources": "100",
    "complete": "94",
    "empty": "6",
    "partial": "0"
  },
  "after_commit_before_response": {
    "resources": "100",
    "complete": "100",
    "empty": "0",
    "partial": "0"
  }
}
```

The before-COMMIT resources are complete in this final snapshot because the
gate safely retried the exact request only after verifying their pre-retry
empty state.

## Remaining gates

- Keep `UNKNOWN_DO_NOT_ACT` as a first-class terminal API response until
  strong reconciliation observes a terminal receipt.
- Add a response-dropping proxy test if Tideproof later makes a stronger
  network-delivery claim.
- Prove the same no-blind-replay behavior behind separate deployed AWS
  identities.
- Do not claim exactly-once behavior for an external system unless that
  system independently enforces the request digest, idempotency key, and
  fencing token.
