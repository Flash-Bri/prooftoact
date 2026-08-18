# Database commit reconciliation contract

Status: `SOURCE_RUNTIME_BOUND_PROVIDER_VALIDATION_PENDING`

ProofToAct treats a lost database acknowledgement as an unknown observation,
not permission to repeat a logical act. The source-level authority, signed
ingest, DVI preparation, recovery publication, and recovery-audit paths now
return one nested `tideproof.database-commit-result.v1` envelope after either a
direct `COMMIT` acknowledgement or an exact durable-state reconciliation. This
is primarily source evidence. Final23 installed the bound predecessor on a
fresh-zero local QEMU-TCG x86-64 CockroachDB CCL v26.2.0 guest and exercised a
narrow direct-ack authority/protected-effect path plus simple recovery
resolution. It did not inject acknowledgment loss or run the reconciliation
negative matrix. Cross-operation compatibility, real transport-loss behavior,
and provider-backed concurrency remain unproved.

## Frozen result envelope

Every envelope has exactly these fields:

- `schemaVersion`, `status`, `operation`, and `operationDigest` identify the
  contract and the exact logical database operation.
- `observation` is `direct_ack` or `read_reconciled`; it never changes the
  operation identity.
- `databaseNow` is an ISO timestamp returned by CockroachDB. Unknown results
  carry `null`; client time is rejected by the shared constructor.
- `outcome` is the durable database outcome, or `null` when no exact terminal
  receipt was observed.
- `authority.current` is `true`, `false`, or `null` for non-authority
  operations. Any value other than `true` requires fresh authorization.
- `reason` is the durable denial reason, an exact reconciliation failure
  reason, or `null`.

`COMMITTED` means the exact durable terminal state was observed. It does not
mean that a historical capability is current. A formerly positive authority
receipt becomes `COMMITTED_BUT_NO_LONGER_CURRENT` when database time, proposal
expiry, fencing, lease, or holder state no longer permits its use.
`UNKNOWN_DO_NOT_ACT` never contains an invented database time or outcome.

## Exact identities and resolvers

| Operation | Operation digest | Exact reconciliation binding |
| --- | --- | --- |
| Authority | durable committed-request digest | proposal, logical action, epoch, authority key, authorization binding, request/operation identity, receipt, canonical outbox payload, fence, holder, proposal expiry, and database time |
| Signed ingest | verification-request digest | tenant, evidence ID, verification-request digest, evidence digest, verified receipt, and evidence row |
| DVI preparation | canonical preparation-request digest | tenant, retrieval, incident, agency, policy, TTL-derived interval, candidate count, and candidate rows |
| Recovery publication | bundle digest | tenant, recovery session, snapshot version, bundle digest, and durable bundle presence |
| Recovery audit | event digest | event ID, tenant, event digest, stored outcome, and database time |

Least-privilege reconciliation uses purpose-built `SECURITY DEFINER` readers
whose bodies require the exact runtime `session_user`. After an ambiguous
commit or unsafe transport error, the broken connection is discarded and a
fresh bounded connection performs the exact read. Zero rows, multiple rows,
identity drift, partial state, or a mismatched digest does not become a
commit. The caller receives or propagates an unknown result and must stop.

The DVI provider proof runner applies the same preparation resolver, rechecks
the replacement session's database, cluster, version, and principal identity,
and records the nested preparation commit before ranking.
Reconciliation never
invents overlap, ordering, current authority, or a successful selection.
Recovery reconciliation likewise reports only `bundle_present`; it cannot
infer whether the ambiguous transaction appended the row or replayed a row
that was already present.

## Fresh-authorization boundary

Denied receipts and expired or superseded positive receipts are durable
history, not reusable authority. They set
`authority.requiresFreshAuthorization` to `true`. The database-owned epoch
cannot be supplied, incremented, or reset by a client. ProofToAct still has no
later-epoch transition: an independently authenticated explicit
new-authorization receipt must be designed, reviewed, and proven before any
epoch after one can exist.

## Accepted finding records

### Divergent direct and reconciled responses

- Root cause: each database path returned its own success object, so an
  acknowledgement-loss read could omit identity, freshness, or time fields.
- Why it was missed: tests checked each operation independently and did not
  compare response topology across observation modes.
- Earliest detection: deep-compare the direct and reconciled key sets before
  any provider run.
- Repair: one strict shared constructor and one schema version, with the AWS
  authority runtime carrying the same envelope.
- Regression/preventive control: schema-shape, authority-state, client-clock,
  and direct-versus-reconciled tests; hash-bound release surfaces.
- Verification: focused source tests pass for all five operation classes.
- Residual risk: the Lambda copy must remain byte-contract compatible until a
  generated shared runtime module replaces it.
- Claim impact: only source-level schema parity is claimed.

### Blind retry after lost commit acknowledgement

- Root cause: transport failure was treated like a failed attempt even when
  the database might already have committed.
- Why it was missed: happy-path and pre-commit serialization tests did not
  sever the connection after `COMMIT` dispatch.
- Earliest detection: inject `ECONNRESET` after dispatch and require one exact
  durable row with no second write.
- Repair: discard the connection, query a least-privilege exact resolver, and
  return `read_reconciled` only for one matching terminal state.
- Regression/preventive control: ACK-loss tests for authority, ingest, both DVI
  preparation entrypoints, recovery publication, and recovery audit.
- Verification: focused synthetic transport-loss tests pass without rollback
  or duplicate mutation.
- Residual risk: Final23 did not exercise ACK loss; exact-version ACK-loss and
  network-fault evidence remain pending.
- Claim impact: no live exactly-once or provider-concurrency claim is added.

### Client-time capability freshness

- Root cause: a caller clock could be confused with the database transaction
  time that owns proposal, lease, and fence currentness.
- Why it was missed: fixtures used synchronized timestamps.
- Earliest detection: pass a numeric client timestamp into the commit envelope
  and require rejection.
- Repair: direct writes return or select `transaction_timestamp()` before commit;
  resolvers return their own database time; a reviewed driver-bound normalizer
  converts PostgreSQL `TIMESTAMPTZ` `Date` values to ISO, and the shared
  constructor still accepts only that normalized string.
- Regression/preventive control: client-clock rejection, real `Date`-valued
  driver fixtures, and exact expiry-boundary tests.
- Verification: source tests pass; target-version execution remains open.
- Residual risk: a string's provenance is established by the reviewed SQL call
  path, not cryptographically by the JavaScript constructor.
- Claim impact: currentness remains source-bound until live receipts exist.

### Historical denial treated as reusable replay

- Root cause: replay identity and terminal durability were conflated with
  current authorization.
- Why it was missed: replay tests emphasized identity preservation after a
  positive receipt.
- Earliest detection: read a denied or expired receipt through both direct and
  reconciliation paths and inspect its fresh-authorization flag.
- Repair: normalize denied history to a durable denial, re-evaluate positive
  history against database time and current holder state, and require fresh
  authorization whenever authority is not currently true.
- Regression/preventive control: stale, denial, and contradictory-authority
  schema tests plus the existing expiry/replacement negatives.
- Verification: focused authority and shared-schema tests pass.
- Residual risk: the authenticated later-epoch authorization transition is
  intentionally absent.
- Claim impact: ProofToAct claims a fail-closed stop, not automatic renewal.

### PostgreSQL timestamp decoder mismatch

- Root cause: the shared constructor required a string while `pg` decodes
  `TIMESTAMPTZ` columns as JavaScript `Date` objects by default.
- Why it was missed: database mocks returned ISO strings, so successful live
  commits could throw only after `COMMIT` while source tests remained green.
- Earliest detection: pass an actual `Date` from each mocked driver row into
  the commit path before any live canary.
- Repair: normalize only reviewed database-driver values with
  `databaseTimestampFromDriver`, then pass the resulting ISO string to the
  strict constructor.
- Regression/preventive control: direct and reconciled authority, ingest, DVI,
  recovery-publication, and audit fixtures now include `Date` values.
- Verification: focused commit and operation tests accept driver `Date` values
  while continuing to reject numeric or raw client clocks.
- Residual risk: Final23 exercised the local driver against CockroachDB v26.2.0
  only for its narrow direct gate. Provider execution and the other operation
  paths are still required to confirm deployed driver behavior.
- Claim impact: this closes a source/runtime type mismatch, not live provider
  evidence.

### Transport identity confused with logical authority identity

- Root cause: ACK-loss resolvers searched and validated only the incoming
  operation ID and request digest even though direct replay accepts one prior
  positive receipt through the stable logical-action identity.
- Why it was missed: ambiguous-commit tests reused the original transport
  identifiers and never replaced every operation, request, proposal, run,
  evidence, intent, and effect identifier.
- Earliest detection: after a synthetic lost ACK, submit a fully replaced
  transport request with the same logical-action digest and require the one
  durable positive receipt rather than an unknown result or a second effect.
- Repair: resolvers select one operation replay first, one prior positive
  logical-action replay second, or one semantic replay third; they recompute
  the stored epoch/key/binding and return the stored committed identities.
- Regression/preventive control: end-to-end AWS ACK-loss tests cover semantic
  denial and full-identity logical replay, and static controls bind the local
  resolver to the same precedence.
- Verification: the replacement path reports the stored operation/request
  digest, one logical authority act, and `read_reconciled`.
- Residual risk: provider concurrency and network-loss validation remain
  pending, and later explicit authorization epochs remain intentionally absent.
- Claim impact: source direct/reconciled equivalence is claimed; live
  exactly-once behavior is not.

### Under-bound authority outbox reconciliation

- Root cause: the AWS resolver proved only that an outbox intent ID existed.
- Why it was missed: the local resolver had exact field checks but the Lambda
  fixture modeled only holder identity and outbox presence.
- Earliest detection: drift each durable outbox binding independently after a
  synthetic lost ACK and require reconciliation rejection.
- Repair: the database resolver returns the exact outbox operation, request,
  proposal, logical-action, epoch, authority key/binding, run, incident,
  resource, fence, effect, intent-kind, payload object, and payload-digest
  bindings; Lambda compares every value with the stored receipt, proposal, and
  canonical payload digest.
- Regression/preventive control: one negative matrix changes every outbox
  binding field, and release-security markers cover the resolver and tests.
- Verification: every modeled drift returns
  `AUTHORITY_RECONCILIATION_REJECTED`.
- Residual risk: Final23 installed and exercised the exact local authority
  outbox happy path on CockroachDB v26.2.0, but not this reconciliation drift
  matrix. The provider-backed schema/function and negative matrix remain
  pending.
- Claim impact: the source no longer labels a partial or drifted outbox an
  exact committed AWS authority result.

### Denial reason drift across observation modes

- Root cause: direct replay combined the durable receipt outcome with a
  synthesized fresh-authorization reason while reconciliation returned the
  stored reason.
- Why it was missed: tests asserted fail-closed behavior but not exact reason
  parity.
- Earliest detection: deep-compare a denied durable receipt's nested commit
  envelope under direct ACK and read reconciliation.
- Repair: direct envelopes preserve the durable receipt reason; freshness is
  represented only by the explicit authority flag.
- Regression/preventive control: denied ACK-loss and shared-envelope tests
  assert both the durable reason and fresh-authorization requirement.
- Verification: both modes return the stored denial reason without renewing
  authority.
- Residual risk: older external consumers must use the versioned nested
  envelope rather than infer authorization from free-text reason values.
- Claim impact: schema parity is strengthened without changing the fail-closed
  authorization boundary.

### Broken connection retained during reconciliation

- Root cause: several paths opened their fresh resolver before releasing or
  closing the connection that had failed after commit dispatch.
- Why it was missed: unconstrained test pools had spare connections and could
  not expose slot exhaustion or deadlock.
- Earliest detection: record lifecycle order and require the broken client to
  be discarded before reconciliation begins.
- Repair: AWS authority, signed ingest, integrated DVI preparation, recovery
  publication, recovery store, and recovery audit release or close the failed
  client first; the DVI provider proof already did so.
- Regression/preventive control: lifecycle-order tests cover authority,
  recovery publication, pooled DVI/ingest, and raw recovery-audit paths.
- Verification: synthetic ACK-loss tests observe discard before resolver
  start, with no rollback on the unsafe connection.
- Residual risk: real pool pressure and network teardown remain provider-test
  obligations.
- Claim impact: this prevents a source-level reconciliation deadlock; it is
  not a throughput or availability claim.

### Classifier-dependent rollback after COMMIT dispatch

- Root cause: authority, signed-ingest, DVI-preparation, and recovery paths used
  a connection-error classifier to decide whether rollback or reconciliation
  was safe, even after `COMMIT` had already been dispatched. The DVI paths also
  invoked their mutating preparation function without an explicit transaction,
  leaving no locally observable commit boundary.
- Why it was missed: ACK-loss fixtures used known transport codes, so an
  unclassified server error such as `XX000` followed the rollback branch.
- Earliest detection: make `COMMIT` throw an unclassified error, return zero or
  one exact resolver row, and assert that `ROLLBACK` is never issued.
- Repair: every explicit post-dispatch error is ambiguous and forces client
  discard plus exact reconciliation. A `40001` retry is permitted only before
  dispatch. Both DVI entrypoints now wrap preparation in an explicit
  SERIALIZABLE transaction and track `COMMIT` dispatch.
- Regression/preventive control: generic post-dispatch negatives cover local
  and AWS authority, signed ingest, both DVI preparation entrypoints, recovery
  publication, and recovery audit; zero, multiple, and drifted resolver rows
  are fail-closed.
- Verification: modeled `XX000` paths close or release before reconciliation,
  emit no rollback, and never retry a dispatched logical act.
- Residual risk: real CockroachDB and network fault behavior remains a live
  canary obligation.
- Claim impact: source no longer claims a failed transaction merely because an
  error code was absent from a transport allowlist.

### Direct replay currentness omitted the outbox

- Root cause: direct replay currentness joined receipt, resource, and proposal
  but did not require the durable dispatch intent.
- Why it was missed: outbox drift was tested only through the read resolver.
- Earliest detection: remove or drift the outbox before direct replay and
  compare `authorityCurrent` with read reconciliation.
- Repair: both SQL and local currentness checks require the exact outbox
  identity, canonical payload, digest, proposal, fence, and holder bindings.
- Regression/preventive control: source tests inspect both currentness
  implementations and the protected-effect join.
- Verification: missing or mismatched outbox state can no longer evaluate as
  current authority in either runtime.
- Residual risk: provider-backed mutation negatives remain pending.
- Claim impact: direct/read source parity now includes outbox-bound
  currentness; no administrator-exclusion claim is added.

### Digest label without durable payload verification

- Root cause: reconciliation trusted the stored `payload_digest` column but
  did not return and canonicalize the JSONB payload it purported to name.
- Why it was missed: the drift matrix changed digest fields, not payload bytes
  while leaving the label unchanged.
- Earliest detection: change only the durable outbox payload and require exact
  reconciliation and protected dispatch to fail.
- Repair: resolvers return outbox and proposal payloads; runtimes compare their
  canonical JSON and recompute SHA-256; protected-effect SQL binds proposal
  payload and its canonical digest to the outbox.
- Regression/preventive control: payload-only and proposal-payload drift join
  the per-field outbox matrix.
- Verification: modeled payload drift returns reconciliation rejection.
- Residual risk: JSONB/canonical-string behavior still requires CockroachDB
  v26.2 execution.
- Claim impact: “exact outbox” means canonical payload content as well as its
  asserted digest at the source boundary.

### Invocation identity projected as committed replay identity

- Root cause: a logical-authority replay returned current invocation proposal
  and evidence fields beside an authorization binding created for the prior
  committed proposal.
- Why it was missed: replay tests checked the stored binding but did not require
  the public response to carry enough stored fields to recompute it.
- Earliest detection: replace proposal and evidence transport identity, then
  independently derive the returned authorization binding.
- Repair: direct and reconciled decisions carry committed proposal digest and
  committed selected-evidence ID/digest separately from invocation build
  bindings; race validation recomputes the logical key and authorization
  binding.
- Regression/preventive control: full-identity replacement tests assert both
  invocation/committed separation and independent binding recomputation.
- Verification: replay returns proposal/evidence A as committed identity while
  retaining proposal/evidence B only as invocation configuration.
- Residual risk: deployed consumers must be validated against the expanded
  versioned response before live use.
- Claim impact: the source response is independently verifiable for logical
  replay; no deployed-response claim is added.

### Non-durable denial mislabeled as committed

- Root cause: early missing, expired, or superseded proposal branches returned
  before receipt insertion, while their JavaScript wrappers always constructed
  a committed envelope from invocation fields.
- Why it was missed: direct-path tests checked the denial reason but did not
  sever the acknowledgement or require the same result to be resolvable.
- Earliest detection: lose the direct response for each early denial and query
  the exact durable resolver; zero rows must never become `COMMITTED`.
- Repair: early denials return `DENIED_NOT_DURABLE` with no committed identity
  fields. Only a persisted terminal receipt may produce `COMMITTED`.
- Regression/preventive control: missing, expired, and superseded direct/retry
  tests plus an ACK-loss negative that requires `UNKNOWN_DO_NOT_ACT`.
- Verification: focused local and Lambda tests preserve the attempted request
  identity without inventing a receipt, database time, or durable outcome.
- Residual risk: live provider behavior and later durable-denial policy remain
  pending.
- Claim impact: source claims distinguish a direct semantic observation from a
  durable database commit.

### Local resolver accepted under-bound history

- Root cause: the local authority resolver validated fewer receipt, proposal,
  replay, and outbox fields than the Lambda resolver.
- Why it was missed: drift tests exercised the deployed-copy normalizer while
  local fixtures supplied internally consistent rows.
- Earliest detection: alter one stored request payload/digest, replay identity,
  denial reason, fence/lease, proposal, or outbox binding at a time.
- Repair: one exported local normalizer recomputes the stored canonical request
  digest and validates the complete receipt/proposal/outbox/currentness shape.
- Regression/preventive control: a per-field tamper matrix and static source
  control bind every returned column to the normalizer.
- Verification: one exact row reconciles; every modeled drift throws and maps
  to `UNKNOWN_DO_NOT_ACT`.
- Residual risk: the local and packaged runtime copies are still independently
  maintained and require provider-backed parity evidence.
- Claim impact: source parity is strengthened; no live exactly-once claim is
  added.

### Resource contention conflated with logical replay

- Root cause: the AWS race sent two contenders with one logical-action and
  proposal identity, but expected one resource winner and one held denial even
  though the database correctly treats the second request as logical replay.
- Why it was missed: the unit fixture fabricated two terminal rows instead of
  exercising the PR #40 uniqueness state machine.
- Earliest detection: derive both contender requests and compare their logical
  keys before invoking the database.
- Repair: the resource race now uses two independently authorized proposals and
  distinct logical actions for one resource. Same-logical-action replacement
  remains a separate one-receipt/one-effect replay proof.
- Regression/preventive control: configuration rejects equal contender
  proposal or logical digests; receipt validation requires two distinct keys
  and bindings while preserving direct-ACK overlap.
- Verification: focused Lambda, template, and race-receipt tests pass with one
  reserved outcome and one durable resource-held denial.
- Residual risk: real CockroachDB scheduling and overlap remain provider-canary
  obligations.
- Claim impact: the two proofs now test different invariants and neither is
  represented as live provider evidence.

### Reconciliation trusted a coordinated false proposal

- Root cause: receipt reconciliation selected only part of the durable DVI
  proposal and therefore could accept coordinated changes to the asserted
  proposal digest, evidence digest, and request payload without independently
  deriving the proposal identity from the stored proposal bytes.
- Why it was missed: the original drift matrix changed one returned field at a
  time; it did not construct a self-consistent but false row spanning request,
  receipt, and proposal aliases.
- Earliest detection: replace the stored proposal payload and every matching
  digest/identity label together, then require the resolver to recompute the
  logical-action and DVI-proposal identities rather than trust those labels.
- Repair: both local and packaged resolvers return the complete proposal
  identity, canonical payload, authorization epoch, authority key, and binding;
  they recompute both identity digests and bind the held-denial observer/fence.
- Regression/preventive control: complete per-field proposal matrices,
  coordinated false-row negatives, held-denial observation negatives, and
  release-security source markers cover both runtime copies and the SQL return
  contract.
- Verification: focused local, Lambda, and static reconciliation tests accept
  one exact row and reject every modeled field drift and coordinated false row.
- Residual risk: Final23 covered only narrow proposal-alias and request-digest
  negatives on local CockroachDB v26.2.0. The complete coordinated-false-row
  matrix remains source-level until provider-backed CockroachDB runs it against
  returned rows.
- Claim impact: a source reconciliation result is now independently bound to
  the durable proposal bytes; no live or cluster-atomic claim is added.

### Recovery publisher schema repair runbook

The existing-cluster publisher repair is a one-statement exception, not a
general migration lane. Before either `--apply` or `--verify-applied`, the
operator must bind the exact recovery cluster ID, hostname, database, source
commit/tree, database-posture digest, and cluster-wide pre-repair posture
digest. The administrator must also establish an exclusive maintenance window:
no other administrator may alter users, roles, memberships, grants, default
privileges, or either recovery function until the final receipt is retained.

`--apply` dispatches the reviewed `GRANT USAGE` statement at most once. After
the COMMIT call, whether its acknowledgement succeeds or is lost, the mutation
connection is closed. A fresh administrator connection then classifies the
exact posture as `CONFIRMED_PRESENT`, `CONFIRMED_ABSENT`, or unresolved. It
also re-reads and hashes both stored function definitions and the cluster-wide
grant posture. `CONFIRMED_ABSENT` is a terminal HOLD for that invocation, not
permission to retry. Any drift, connection failure, probe failure, or
contradictory state is unresolved and must not trigger another mutation.

`--verify-applied` is the recovery path after an applied-but-unconfirmed or
post-COMMIT verification failure. It dispatches no DDL and authorizes no
repair. It reopens the target, reclassifies grants, re-hashes stored function
definitions, and uses rollback-only publisher capability probes. A present
result is labeled by its observation (`read_only_verification` or
`read_reconciled`); an absent result remains HOLD. Preserve the nonsecret JSON
receipt and source identity, but never persist database URLs or passwords.

This source runbook does not establish a live CockroachDB v26.2 canary,
exclusive-maintenance-window evidence, or provider enforcement. Those remain
separate live gates.
