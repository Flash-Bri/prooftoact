# Full high-water drill evidence contract

Status: **provider-backed batch pending**.

The frozen project goal requires 100 full drills. Existing receipts prove
important components independently—100 fifty-contender CockroachDB races,
100 ambiguity injections at each COMMIT boundary, isolated Distributed Vector
Index mechanics, and one Managed MCP recovery run—but they do not share one
drill identity. They cannot be added together or relabeled as 100 end-to-end
drills.

## Non-interchangeable evidence classes

A local specification batch may repeat the in-memory three-act scenario 100
times to detect deterministic invariant regressions. Its receipt must identify
itself as local and synthetic. It cannot satisfy, substitute for, or unlock the
provider-backed claim.

The accepted release artifact must be a fresh
`tideproof.highwater-drill-live-batch.v1` receipt from the exact clean release
commit and exact deployed configuration. It must contain exactly 100 unique,
ordered, consecutive drill bindings. A partial, resumed, skipped, ambiguous,
99-run, or 101-run batch fails closed.

## Per-drill binding

Every accepted run must carry one synthetic drill binding through all three
acts:

1. CockroachDB produces a short-lived snapshot from the full provenance,
   validity, revocation, scope, and conflict predicate. DVI ranks only that
   snapshot. The semantically closest inadmissible row is excluded, ranked IDs
   are a subset of the snapshot, the selected top-ranked evidence is bound to
   the exact drill run without disclosing its identifier, and current
   admissibility is rechecked before authority is spent.
2. Two genuinely overlapping AWS Lambda invocations use that evidence and one
   bounded race binding. CockroachDB commits exactly one winner, one durable
   denial, two terminal receipts, one outbox intent, fence one, and zero
   protected external effects. The model supplies no operation ID, effect key,
   fence, or authorization.
3. Recovery selects the exact winning receipt by tenant, run, incident,
   evidence, resource, operation, request digest, and outcome—not by recency.
   One fixed-query Managed MCP read follows a committed pre-read audit; a
   result-bound terminal audit commits before sanitized context is released.
   No operational capability is returned, an unbound principal is denied
   before MCP, exact replay returns the original decision, and changed inputs
   under the operation ID are rejected.

The snapshot is retired after each run without deleting evidence or authority
receipts. An uncertain authority attempt is reconciled and never blindly
replayed.

## Batch acceptance

Acceptance additionally requires:

- exact clean public `main`, tree, lockfile, artifacts, configuration, caller
  binding, primary cluster, and recovery cluster digests;
- exactly 100 unique passing run digests and zero invariant violations;
- a fresh `EXPLAIN (VERBOSE)` receipt naming
  `g1_vector_candidates_embedding_idx`, `vector search`, and exact
  tenant/retrieval prefix spans;
- current cost controls and the exact AWS account, CloudFormation-managed role,
  and observed STS caller triple validated before any Lambda invocation;
- private raw provider evidence retained, while public receipts contain only
  bounded facts and digests—never credentials, account IDs, ARNs, caller IDs,
  endpoints, or MCP keys; and
- fresh ambiguity/failpoint evidence for the exact release implementation, or
  an explicit historical-only boundary.

The 100 × 50 race and COMMIT-ambiguity receipts remain separate controls. They
may be referenced by digest, but they are not counted as full drills.

## Present release boundary

The source tree now contains stronger replay, recovery, DVI-snapshot, AWS
evidence, timeout, and resource-bound controls. The DVI proof candidate binds
its selected top-ranked evidence to one exact synthetic drill run. The source
path now consumes database-authorized DVI proposal identities and the exact
selected-evidence digest, but no provider-backed receipt yet proves the live
DVI-to-AWS handoff. The provider-backed batch harness, bounded multi-race
deployment shape, and live receipt do not yet exist. The exact cross-act
recovery lookup now has a locally tested source control, but no provider-backed
receipt. Public claims and final release readiness must therefore remain
partial and blocked.

The sanitized `tideproof.aws-authority-race-receipt.v6` source contract carries
the exact configured active-run UUID and validates each contender's configured
proposal identity and selected-evidence digest against the committed database
response. Both durable contender results must now carry the same selected
evidence identity and the same non-reversible
`authorityEvidenceBindingSha256`; the sanitized receipt publishes that shared
DVI binding plus a digest of the selected evidence identity. Its durable proof
rejects a database observation for any other run. This closes source-level
prerequisites for joining the authority race to one per-drill DVI snapshot. It
does not prove the live authorizer, exact retrieval prefixes, provider
concurrency, the 100-run harness, or any live evidence.

### Race receipt omitted the shared DVI snapshot identity

- Root cause: each Lambda response validated its own database-authorized DVI
  proposal, but the race aggregator retained only the configured run and
  deployment digest. Two otherwise-valid contenders could therefore describe
  different selected evidence or different DVI snapshots.
- Why it was missed: focused tests varied proposal identities and authority
  outcomes, but used matching synthetic evidence without asserting a shared
  snapshot binding in the sanitized receipt. The first repair then injected
  the new binding into Lambda mock rows without proving that the actual Gate
  Two SQL wrapper returned the same column.
- Earliest detection: give the second contender a valid but different selected
  evidence ID, evidence digest, or authority-evidence binding and require the
  race to fail before durable proof acceptance.
- Repair: the Gate Two SQL wrapper joins each durable receipt to its exact
  committed proposal and returns that proposal's authority-evidence binding;
  direct and ACK-loss-reconciled Lambda decisions return the committed
  binding. The race validator requires one shared binding and one shared
  selected evidence identity, then publishes only the shared non-reversible
  binding and a selected-evidence binding digest.
- Regression/preventive control: per-field cross-contender negatives cover all
  three bindings. A provider-surface test binds the SQL return column and the
  tenant/proposal/committed-decision join to the Lambda response contract, and
  release-security markers bind the response, validator, receipt schema, and
  evidence contract.
- Verification: focused Lambda and race tests exercise direct and reconciled
  decisions plus cross-contender drift. Provider execution remains pending.
- Residual risk: a source-equal binding is not live DVI-to-AWS evidence until
  the exact provider receipt matches the accepted DVI proof and batch.
- Claim impact: Tideproof may claim source-level shared DVI identity across the
  two race contenders; no live handoff, concurrency, or exactly-once claim is
  added.

## Exact cross-act recovery lookup

The recovery broker no longer selects a bundle by principal, session, and
recency. `recoverySourceBindingDigestFor` creates one canonical SHA-256 binding
over the exact tenant, run, incident, admitted evidence digest, resource,
winning operation, authority request digest, and outcome. The signed bundle,
session resolver, pre-read audit digest, fixed Managed MCP query, returned row,
and terminal audit must all carry that same digest.

The fixed query includes `source_digest` as an equality predicate and contains
no `ORDER BY` or `LIMIT`. Zero rows and duplicate rows both fail closed at the
broker's exact-one cardinality check. This prevents a newer bundle, another
operation in the same recovery session, or a resolver/query mismatch from
being treated as the requested winner. The digest does not disclose the bound
identifiers in the public receipt.

This is a source-level prerequisite only. It does not prove a Managed MCP
call, a live database row, the exact 100-run batch, AWS behavior, or final
release readiness until a fresh provider-backed receipt binds it to the exact
official release.

## Precommitted recovery-publisher trust root

The recovery evidence runners no longer generate a publisher key and then
trust that same key in-process. During primary-cluster security bootstrap, the
database owner immutably inserts the expected trust-root commitment and
publisher-key-set digest. The runtime `tp_recovery_audit_user` receives only
the exact resolver function, not table write access. Before either runner
signs, publishes, bootstraps recovery state, or reaches Managed MCP, it must
match its canonical root and P-256 signing key against that database-owned
row. A coordinated replacement of the root, adjacent hash, and signing key
therefore fails unless the separately privileged primary bootstrap commitment
already matches. Receipts expose only digests and the database commit time;
they never expose the private key.

- Root cause: the earlier proof runner created an ephemeral signer, published
  its bundle, and injected the same signer's public key into the broker. That
  proved signature self-consistency but not publisher authenticity.
- Why it was missed: row validation and broker audit digests correctly bound
  the caller-supplied key set, while tests reused the publisher's key map and
  never replaced signer and trust map together.
- Earliest detection: replace both publisher signer and broker key with one
  attacker-controlled pair; a valid signature must still fail unless the key
  matches the independently recorded commitment.
- Repair and preventive control: the bootstrap owner inserts once with
  `ON CONFLICT DO NOTHING` and fails on any mismatch. The evidence runners
  load the key separately, verify its cryptographic match, resolve the exact
  database-owned commitment through a session-user-guarded function, and pass
  only that key map to the broker. Static controls forbid the synthetic signer.
- Verification: focused tests cover coordinated root/hash/key replacement,
  commitment drift, replacement signing keys, noncanonical base64, missing
  inputs, immutable SQL, least-privilege resolver access, and runner ordering.
- Residual risk and claim impact: source excludes the evidence-runner principal
  from rewriting the commitment; it does not exclude a CockroachDB
  administrator or prove human independence and private-key custody. Provider
  evidence must prove the committed row predates publication, the runtime
  principal lacks table writes, and custody remained separate. No live
  recovery-authenticity or administrator-exclusion claim is added.

## Integrated DVI acceptance harness

`npm run gate1:admissible-vector:proof` is the owner-run acceptance lane for
the first per-drill requirement. It is deliberately excluded from CI and must
not be run without the reviewed synthetic fixture and separate credential
bindings.

The lane requires a clean official `main` checkout that matches a freshly
fetched public `origin/main`, a `tp_authorizer_user` connection through
`DATABASE_URL`, a distinct owner/auditor connection through
`TIDEPROOF_AUDITOR_DATABASE_URL`, and one canonical
`TIDEPROOF_ADMISSIBLE_VECTOR_PROOF_SPEC` JSON object.

The source guard disables replacement objects and filesystem-monitor shortcuts
and rejects replacement refs plus any skip-worktree or assume-unchanged index
entry before and after the public-main fetch.

The spec binds:

- one exact synthetic drill-run UUID;
- exactly 10,000 admissible candidate evidence IDs by sorted-set SHA-256;
- one exact tenant, incident, retrieval, agency, three-dimensional query,
  ten-result limit, and 60-second snapshot TTL;
- exactly one expected case for each of `verification_binding_mismatch`,
  `verification_key_revoked`, `future_observation`, `not_yet_valid`,
  `expired`, `out_of_scope`, and `unresolved_conflict`; and
- which excluded row must be closer to the query than every returned ranked
  row.

The authorizer session creates the snapshot only through
`tp_api.g1_prepare_vector_set_v1`, observes every required exclusion from the
persisted snapshot through `tp_api.g1_observe_vector_exclusion_v1`, ranks only through
`tp_api.g1_rank_vector_set_v1`, and retires only through
`tp_api.g1_delete_vector_set_v1`. The auditor session reads the private
candidate IDs, validates the expected set digest, captures
`EXPLAIN (VERBOSE)`, and requires `vector search`,
`g1_vector_candidates_embedding_idx`, and the exact tenant/retrieval prefix
spans. The auditor then executes that exact ranked query and requires its
ordered results to match the authorizer function byte-for-byte. It also proves
the designated inadmissible row is semantically closer than the first returned
candidate and verifies zero candidate or private exclusion rows remain after
retirement. The sanitized receipt retains only a non-reversible digest of the
seven required snapshot-bound observations, bounding private row retention to
the live snapshot and its expiry purge.

The emitted `tideproof.gate1.admissible-vector-proof.v2` receipt contains the
synthetic drill-run UUID plus a non-reversible authority-evidence binding over
the exact source, tree, canonical proof spec, snapshot interval, ranked
sequence, and selected rank-one evidence ID and digest. It also contains
fixture, plan, ranked-set, database cluster, version, and session digests;
snapshot and cleanup timestamps; counts; reason labels; and an order-sensitive
ranked-result digest. It does not emit credentials, usernames, endpoints, raw
plans, tenant, incident, retrieval, or evidence IDs, or query vectors.

Both database sessions must report the same CockroachDB cluster. Retirement is
attempted only after an exact direct or read-reconciled prepare receipt has
validated the snapshot identity; an uncommitted or unresolved prepare never
deletes by the caller-supplied retrieval ID. A cleanup failure is preserved
alongside the primary failure. Pool shutdown must also succeed before the
`PASS` receipt is emitted. A `PASS` remains subject to independent acceptance
review and does not prove that AWS consumed the binding or satisfy the
100-drill, authorization, production-safety, or final-release gates by itself.

No provider-backed receipt from this lane exists yet.

## Snapshot-bound exclusion finding

- Root cause: the proof prepared an immutable admissible candidate snapshot,
  but re-evaluated each expected inadmissible row through the current-policy
  observer in later transactions. A reason could therefore drift after
  snapshot admission without being attributable to the snapshot that was
  ranked.
- Why it was missed: the original tests changed the returned reason, but their
  mock represented both preparation and observation with one fixed clock.
  They did not make a later current-policy observation disagree with the
  snapshot admission instant.
- Earliest detection: require every exclusion observation to carry the exact
  retrieval ID and `admitted_at`, then reject an otherwise-correct reason from
  any other instant before ranking or selection publication.
- Repair: `g1_prepare_vector_set_v1` now persists every bounded inadmissible
  evidence identity, available digest, and reason beside the retrieval ID at
  the database-owned snapshot time. The authorizer reads those records only
  through `g1_observe_vector_exclusion_v1`, whose exact retrieval, incident, agency,
  policy, evidence, and admission-time joins do not re-run current policy.
  Snapshot retirement or expiry purge removes both vector candidates and the
  private exclusion rows; only the sanitized receipt's non-reversible digest
  of the seven required observations survives cleanup.
- Regression and preventive control: source tests require the private table,
  ownership and least-privilege function grant, exact bounded cleanup behavior,
  and an exact session-user guard. The integrated proof rejects current-policy
  fallback, a changed reason, or a changed snapshot time and publishes only a
  non-reversible digest of the seven private observations.
- Verification: local source and integrated proof tests exercise the direct
  path and ACK-loss preparation reconciliation. Provider-backed CockroachDB
  v26.2 execution remains pending.
- Residual risk: the persisted source contract does not prove a live DVI plan,
  the actual provider authorizer, AWS consumption, the 100-drill batch, or
  cluster-wide inherited-capability exclusion.
- Claim impact: source can claim persisted snapshot-bound exclusion reasons;
  live and release claims remain blocked until the fresh provider receipt and
  independent acceptance review pass.
