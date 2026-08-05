# Authority identity contract

Status: `SOURCE_RUNTIME_BOUND_PROVIDER_VALIDATION_PENDING`

This contract fixes the identity layers used by the source-level primary and
AWS authority paths. The source now persists a structured DVI selection
receipt and a separate proposal receipt, initializes one database-owned
authorization epoch, derives the logical-authority key in CockroachDB, and
carries the resulting binding through the request, decision, outbox intent,
protected effect, snapshots, and current Gate One drills. A new retrieval
cannot advance an already-spent logical action; a future epoch-advance surface
remains deliberately absent until an independently authenticated explicit
new-authorization receipt is implemented. This remains a source boundary, not
evidence that a live provider enforces it. Credentialed database bootstrap,
Gate Two deployment, and provider evidence acceptance remain blocked until the
exact CockroachDB version and the remaining review gates pass their negative
tests.

## Identity layers

1. `tideproof.authority.logical-action.v1` names the business effect. Its
   fields are tenant, incident, resource, agency, action kind, and payload
   digest. It deliberately excludes run, retrieval, caller, attempt, lease,
   race, and source-build identifiers.
2. `tideproof.authority.dvi-selection-receipt.v1` durably binds source commit,
   tree, proof spec, tenant/run/incident/retrieval, snapshot interval, ranked
   sequence, policy, and exact selected evidence ID and digest. The proposal
   transition resolves and recomputes this binding inside its SERIALIZABLE
   transaction.
3. `tideproof.authority.dvi-proposal-identity.v1` binds that exact DVI
   selection, selected evidence, policy, and logical action. A new retrieval
   changes the proposal identity but does not create a new logical action or
   authority key.
4. `tideproof.authority.logical-authority-key.v1` binds the logical-action
   digest to one positive database-owned authorization epoch. Only an explicit
   durable database transition may create a later epoch.
5. `tideproof.authority.authorization-binding.v1` binds the proposal identity
   to that logical-authority key. Operation IDs and other attempt identifiers
   remain outside this identity and may only describe retries or contenders.

## Frozen invariants

- Changing `operationId`, `agentId`, `intentNonce`, `effectKey`, `leaseMs`,
  `raceId`, or caller identity cannot create a new logical action or logical
  authority key.
- Changing run, retrieval, DVI evidence binding, policy, rank, or snapshot time
  creates a different proposal identity, not a fresh authority epoch.
- Changing a logical effect field creates a different logical-action digest.
- Repeating the same logical action at the same authorization epoch produces
  the same logical-authority key, regardless of caller or attempt identity.
- A later epoch is valid only after a separate durable database authorization
  transition. Client input cannot select, increment, or reset the epoch.
- Every durable proposal, request, decision, outbox intent, recovery record,
  audit record, and drill receipt carries its applicable identity digests on
  the current source paths. Direct acknowledgements and exact read
  reconciliation share the commit envelope documented in
  `docs/COMMIT_RECONCILIATION.md`.

The executable identity contract is `src/cloud/authority-identity.js`.
`src/cloud/dvi-selection.js` supplies the shared selection-receipt binding and
uses UTF-16 code-unit ordering without Unicode normalization; canonically
equivalent but distinct JSON keys therefore remain distinct and cannot inherit
insertion order.
`src/cloud/authority-store.js` owns the explicit proposal-authorization
transition and primary runtime binding. `src/cloud/primary-security.js` and
`infra/aws/lambda/authority.cjs` require the same database-owned identity on
their least-privilege spend path. The database spend surface hashes the stored
canonical payload and derives the logical-action and request digests again
before mutation; all replay branches return stored receipt identity. The AWS
response separates invocation proposal/evidence bindings from
`committedProposalDigest`, `committedSelectedEvidenceId`, and
`committedSelectedEvidenceDigest`, so a logical replay's authorization binding
can be independently recomputed from the durable identity. Direct currentness,
read reconciliation, and protected-effect dispatch all require the same exact
outbox and canonical proposal payload. Focused
tests lock canonical encoding, strict schemas, field separation, and epoch
behavior. The Gate One authority drill also contains failure-first cases for a
DVI binding A/evidence B forgery, a selected-evidence request mismatch, a new
retrieval after spend, and a post-expiry replacement that changes all transport
identity while reusing the existing logical authority. It additionally races a
pre-expiry spend against post-expiry authorization and denies protected-effect
recording at the exact database-time proposal-expiry boundary.

The AWS resource-contention proof is intentionally different from the
same-logical-action replacement proof. Its two contenders carry distinct
logical-action and proposal digests but target one resource, so a held denial
is meaningful. A replacement retry keeps one logical action and must resolve
to one receipt and one protected effect; it is never counted as the losing
contender in the resource race.

## Accepted finding records

### Opaque DVI selection binding

- Root cause: selection ID/digest were caller fields beside an opaque binding.
- Missed because: the first negative changed only the spend request, not the
  authorization selection under an unchanged binding.
- Earliest detection: proposal A binding with evidence B before any spend.
- Repair/control: durable structured DVI selection receipt, shared recomputed
  binding, selected evidence in proposal identity, and a zero-mutation A/B
  negative.
- Verification/residual/claim: source tests and Gate One drill are required;
  CockroachDB v26.2 execution remains pending and no live-DVI claim is added.

### Automatic proposal-to-epoch remint

- Root cause: the least-privilege SQL path retained automatic
  `current_epoch + 1` advancement while the JS path only initialized epoch 1
  and then depended on proposal uniqueness. The two runtimes therefore treated
  an expired, unspent proposal differently.
- Missed because: replacement tests either reused the first proposal or first
  committed a positive spend; they did not expire an unspent proposal and
  compare both authorization implementations.
- Earliest detection: authorize proposal 1 without spending it, expire it at
  database time, then authorize a new retrieval for the same logical action.
- Repair/control: both paths permit only the database transition from epoch 0
  to epoch 1. Any different proposal for an initialized logical action is
  denied as `explicit_new_authorization_required`; no later epoch can exist
  until a separate authenticated durable transition is implemented.
- Verification/residual/claim: source controls reject arithmetic epoch advance,
  and the Gate One drill requires one proposal, epoch 1, and zero authority
  receipt/outbox/effect/fence mutation after the expired-unspent replacement.
  CockroachDB v26.2 execution remains pending, so no live epoch claim is added.

### Caller-asserted least-privilege spend identity

- Root cause: the SECURITY DEFINER surface compared copied JSON fields but did
  not bind the proposal to canonical action/payload or return stored replay
  identity.
- Missed because: JS/Lambda tests never invoked proposal A with payload B as the
  least-privilege SQL user.
- Earliest detection: direct `tp_authorizer_user` action/payload substitution
  before the first receipt.
- Repair/control: proposal rows persist canonical action/payload fields; SQL
  hashes stored canonical payload, derives logical/request digests, rejects
  lowercase-hex violations, and returns stored identity on every replay.
- Verification/residual/claim: direct SQL negatives must show zero receipt,
  outbox, effect, or fence mutation; provider SQL compatibility remains open.

### Locale-sensitive canonical JSON

- Root cause: `localeCompare` can equate distinct composed/decomposed keys and
  let stable sort preserve caller insertion order.
- Missed because: fixtures used ASCII keys only.
- Earliest detection: reverse insertion order for `é` and `e\u0301` keys.
- Repair/control: one shared code-unit comparator, no Unicode normalization,
  and digest-equality regressions across insertion order.
- Verification/residual/claim: source tests cover the authority/DVI paths; a
  wider recovery/evidence canonicalization review remains a separate gate.

### Cross-epoch positive double spend

- Root cause: positive-spend uniqueness used the epoch-derived logical-authority
  key, so two epochs for the same logical action had independent uniqueness
  domains; spend did not lock the database-owned epoch row.
- Missed because: replacement coverage was sequential and did not overlap an
  old-epoch spend with post-expiry proposal authorization.
- Earliest detection: hold epoch N's spend transaction open across proposal
  expiry while proposal N+1 attempts authorization for the same logical action.
- Repair/control: spend and authorization serialize on the same logical-action
  epoch row; stale epochs fail closed; positive receipts, outbox intents, and
  protected effects each have tenant/logical-action uniqueness; replay resolves
  by logical action rather than by the epoch-derived key alone.
- Verification/residual/claim: source tests require the lock and three database
  uniqueness controls, and the Gate One drill carries the overlap negative.
  CockroachDB v26.2 execution remains pending, so no live concurrency claim is
  added.

### Protected effect after proposal expiry

- Root cause: the least-privilege SQL dispatch function joined the resource,
  outbox, and spend receipt but omitted the exact proposal and its expiry.
- Missed because: the JS path checked proposal currentness and the existing SQL
  negative expired only the resource lease.
- Earliest detection: retain a live resource lease, set the bound proposal to
  the exact database-time expiry boundary, then attempt the protected effect.
- Repair/control: both SQL and JS insert paths join the exact proposal identity
  through proposal, logical action, epoch, authority key, binding, run,
  incident, resource, and payload. The stored dispatch function uses live
  `clock_timestamp()` checks on admission, then—after any uniqueness or intent
  wait—reads the exact receipt/resource/proposal expiries, captures a fresh
  database clock, and deletes its own just-inserted row before returning if
  any authority is no longer current.
- Verification/residual/claim: focused source controls and the Gate One boundary
  drill require zero protected effects at equality and after expiry. The
  provider runner now includes an uncommitted uniqueness occupant held through
  expiry, but execution on the target CockroachDB version remains pending, so
  post-wait currentness is still a source-only claim.

### Transaction-start time froze current authority

- Root cause: proposal expiry, receipt/resource currentness, lease creation,
  reconciliation, and protected-effect admission mixed database statement time
  with `transaction_timestamp()`, which is fixed when a transaction begins.
- Missed because: equality tests expired rows before opening the consuming
  transaction; they did not hold an already-open transaction across expiry.
- Earliest detection: begin an authority spend while its proposal is current,
  pause after evidence admission until database time reaches the proposal
  expiry, then resume acquisition. The spend must finish denied with no fence,
  outbox, or effect.
- Repair/control: the stored spend refreshes `clock_timestamp()` after each
  blocking lock and couples the exact still-current proposal to the
  lease-creating update. Every stored replay branch refreshes database time
  after its candidate query and evaluates exact receipt currentness through a
  helper that completes its structural receipt/resource/outbox/proposal read
  before capturing one clock, rather than inheriting the outer statement
  timestamp. That helper returns the boolean and reported decision time from
  the same row and clock, so proposal expiry cannot cross an unreported gap
  between the replay decision and its timestamp. Reconciliation projects both
  values from that same helper row. Direct spend queries refresh statement
  time, recheck currentness after an awaited pre-commit observer, reconcile expiry
  to a durable denial, and recheck protected-effect currentness before commit.
  Recovery export no longer inherits temporal admissibility from the outer
  statement: its original candidate read captures the selected evidence's
  observation and validity interval plus every structurally verified
  conflicting-evidence interval, then one post-wait database clock decides
  selected-evidence validity and active conflicts without another table read.
  Proposal authorization also refreshes after the epoch lock and removes a
  newly inserted proposal while restoring the unspent epoch if it expires
  before its final currentness check.
- Verification: red-before-green source controls reject transaction-start time
  in the spend/currentness/reconciliation/effect chain. Gate One includes
  exact-equality denial, a direct transaction held past expiry, the reconciled
  cross-epoch case, and provider-only stored-function resource-lock, replay
  outbox-intent, protected-effect uniqueness-wait, and recovery receipt-intent
  drills. Each held-wait drill first awaits a fail-closed query-ready signal
  emitted after `BEGIN` and immediately before the tested SQL, so connection
  setup latency cannot impersonate a database wait. Failure cleanup expires
  the synthetic proposal before releasing a held blocker and drains the
  pending query, preventing a late background effect. A separate amplified,
  deterministic counterfactual captures a current replay at database clock A,
  keeps that transaction open across exact proposal expiry, and then captures
  clock B to prove that pairing A's boolean with B's timestamp would
  contradict. A fresh real replay at clock C must return a same-clock expired
  pair within one second of the boundary. This does not claim that the old
  production micro-gap itself was reproduced. The recovery lane separately holds that receipt intent while the
  selected evidence expires and while a pre-captured conflicting claim becomes
  active; both require the receipt, resource, and proposal authority to remain
  live while recovery returns no row.
- Residual risk and claim impact: CockroachDB v26.2 must still execute the held
  transaction and equality drills. No live authority, concurrency, or
  exactly-once claim is added by the source repair.

### Non-current DVI authorization replay

- Root cause: the initial and post-epoch-lock replay branches did not share one
  currentness decision. The raced SQL branch checked only proposal expiry, the
  local replay branch omitted the positive-spend census, and the runtime client
  accepted a replay even when the database marked it non-current.
- Missed because: prior controls proved spend uniqueness and fresh proposal
  denial, but did not replay the already-durable proposal after its logical act
  had committed or force authorization to wait behind the shared epoch lock.
  The synthetic diagnostic helper also had only a static default-rejection
  check, so its `allowDenied` path could return caller-constructed authority
  material after a denial.
- Earliest detection: commit `resource_reserved` for an unexpired proposal,
  then replay that proposal both directly and after an authorize-versus-spend
  epoch-lock interleaving.
- Repair/control: every initial, raced, and new authorization path now performs
  the positive-spend census; both replay branches deny expired history; local
  branches share one currentness decision; and runtime plus synthetic callers
  refuse to release authorization identity unless database currentness is
  exactly true. `allowDenied` now suppresses only the diagnostic exception and
  strips DVI authorization, proposal, and identity material, with a behavioral
  regression for that exact return shape.
- Verification/residual/claim: focused controls bind all replay branches and
  prove that spent denial returns no reusable DVI authorization. Provider-backed
  CockroachDB v26.2 replay and epoch-lock interleavings remain required before
  any live current-authority claim or credentialed component canary.
