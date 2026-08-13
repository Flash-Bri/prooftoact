# Full high-water drill evidence contract

Status: **one exact-release integrated provider drill pending**.

Brian approved a 100+1 acceptance target on 2026-08-06: one already completed
batch of 100 deterministic offline specification runs plus exactly one fresh,
exact-release provider-backed integrated live drill. Existing historical
receipts prove important components independently—100 fifty-contender
CockroachDB races, 100 ambiguity injections at each COMMIT boundary, isolated
Distributed Vector Index mechanics, and one Managed MCP recovery run—but they
do not share one drill identity and cannot substitute for the +1 drill.

## Non-interchangeable evidence classes

A local specification batch repeats the in-memory three-act scenario exactly
100 times to detect deterministic invariant regressions. Its receipt must
identify itself as local and synthetic. It satisfies only the offline half of
the 100+1 target and cannot satisfy, substitute for, or unlock the +1
provider-backed claim.

## Deterministic offline harness

Use `npm run --silent full-drill:local -- --output evidence/local-full-drill-100-2026-08-04.json`
for canonical file generation. The command executes the exact local scenario
100 times and writes one canonical `tideproof.highwater-drill-local-batch.v1`
receipt only to the allowlisted checked-in path at
[`evidence/local-full-drill-100-2026-08-04.json`](../evidence/local-full-drill-100-2026-08-04.json).
`npm run full-drill:local:verify -- evidence/local-full-drill-100-2026-08-04.json`
recomputes all 100 scenarios through the same `buildLocalFullDrillReceipt` and
`runScenario` shared local implementation used by the generator, then requires
byte-for-byte agreement with the receipt. This detects drift or tampering
against the current shared implementation; it is not an independent oracle,
and common-mode defects remain possible.

The local acceptance control requires:

- exactly 100 ordered run numbers with 100 unique domain-separated run
  digests and no skipped or extra run;
- the exact 11-invariant and 13-step local scenario contract on every run,
  zero false invariants, one fixed scenario time, and one deterministic
  scenario digest across the batch;
- an allowlisted source digest covering the scenario, protocol, canonical JSON
  helper, harness, runner, validator, package files, public-demo runtime, and
  candidate AWS Demo entry;
- exact two-space JSON bytes with one trailing newline, strict object shapes,
  finite unambiguous JSON values, and recomputation of every source, run, and
  batch digest; and
- explicit `false` values for provider backing, CockroachDB execution, AWS
  Lambda concurrency proof, Managed MCP execution, and deployed-artifact
  proof.

This installs the cheapest durable controls for the main offline pre-mortem
failures: canonicalization or schema drift, digest substitution, reordered or
partial replay, wall-clock nondeterminism, local sequential execution being
misrepresented as provider concurrency, and tested-source/deployed-artifact
divergence. The AWS Demo entry and local harness are bound to the same
`src/scenario.js` source path, but a source hash is not build or deployment
evidence. The source-hash control assumes a clean, quiescent, controlled worktree
throughout generation and validation. It reads bound files sequentially and
does not lock or snapshot the filesystem. It is not a hostile-host or concurrent-filesystem immutability proof:
mutation between source reads,
scenario execution, validation, or later receipt use remains a TOCTOU residual.
The receipt remains a local regression control only.

The accepted +1 artifact must be one fresh
`tideproof.highwater-drill-live.v1` receipt from the exact clean release commit
and exact deployed configuration. A partial, resumed, mixed-release,
component-only, or second selected provider run fails closed; one independently
accepted integrated receipt is the complete provider target.

The current source runner emits only a
`tideproof.highwater-drill-live-candidate.v2` receipt with status
`INCOMPLETE_LIVE_GATES_PENDING`. It cannot emit the accepted schema or `PASS`.
The exact Gate Two v9 build now emits nine content-addressed live-drill ESM
bundles, a content-addressed manifest, the reviewed launcher, and a Node
v22.23.1 executable whose byte digest must match one pinned official
nodejs.org release for the exact `linux-x64` or `darwin-arm64` target. A
Homebrew thin launcher, an unpinned Node executable, a different platform, or
a changed digest fails the build. The build receipt inventories all 21
generated files, scans the 20 non-Node outputs for the repository's bounded
privacy signatures, and separately records the byte count of the one pinned
official toolchain object; it does not mislabel that exemption as scanned.
The outer builder checks all 21 staged paths, sizes, and digests before copying
them into the release checkout. The DVI bundle replaces `pg`'s optional
`pg-native` lookup with a tracked fail-closed module, preventing an ambient
native peer from entering the reviewed runtime.
After release verification and before the first provider component, the runner
creates a source-local owner-only journal and durably publishes a run-intent
digest. It then writes create-only, fsynced hash-chain entries for each observed
component, the private bundle receipt, and post-release verification. Before
recovery publication, the recovery child create-only writes an owner-only
canonical envelope containing the exact normalized signed bundle, syncs and
rereads it, and on a later invocation with the same unsigned bundle reuses the
first persisted signature bytes instead of a new randomized P-256 signature.
Before candidate composition, a source-local helper writes the canonical raw
component bundle through an owner-only temporary file in a canonical mode-0700
directory outside the Git checkout, links the final run-specific name, syncs
the directory entry, and rereads the mode-0600 file byte-for-byte. The final
clean-release check runs after that write. The public candidate carries only
the bundle and source-control-receipt digests. Because that receipt is unkeyed
and reconstructible from current bytes, neither the journal, signed-bundle, nor
private-bundle receipt
independently proves the historical write protocol, durable retention, or crash
continuity. The
candidate remains blocked until a separate reviewed finalizer validates a
signed pre/post deployment-attestation pair around the drill, independently
attests and recomputes the private evidence, and proves crash-safe recovery
without a second Managed MCP read for the same canonical attempt.

The live command must not execute any runtime byte directly from the checkout
or `dist/runtime`. This acceptance lane is Linux/systemd-only. Before a
credential exists, a root operator runs
`scripts/install-integrated-live-drill-stage.js` with the exact independently
accepted build-receipt SHA-256, a UUID run ID, and the accepted checkout root.
The installer walks each source component below an open root descriptor without
following symlinks, verifies every receipt digest, atomically publishes the
twelve runtime files and two-file verifier root, installs the eight exact
systemd units, reloads the system manager, and emits one root-owned v4 receipt
binding source commit, tree, lockfile, toolchain, accepted build receipt,
inodes, owners, modes, link counts, and complete ancestor chains. A separate
non-root verifier, executed by the installed official Node binary, reopens and
recomputes the accepted build receipt, runtime, itself, its Node binary, and
the installed unit files before PREPARE.

Only the root-owned systemd units may invoke `/usr/bin/perl`. They explicitly
construct the first dynamic interpreter environment and unset every reviewed
Node, Perl, and loader injection variable before exec; `/usr/bin/env -i` and
direct shell/CLI launch are not accepted substitutes. The Perl launcher then
opens the manifest, component, and Node executable with `O_NOFOLLOW`, verifies
them, and executes Node through the retained `/proc/self/fd/<fd>` descriptor.
The controller, contenders, losers, worker, and reconciler never receive the
MCP bearer. Only after the global database state commits `EXECUTING` may the
socket-activated provider-operation unit receive it through systemd
`LoadCredential=` for one bound sequence. These controls trust root, the
kernel, systemd, the system loader, Perl, and system libraries; they do not
claim resistance to a malicious administrator or compromised host.

The live runner requires
`TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_PATH` to be one canonical
absolute path named `<run-id>.private-evidence.json` whose parent exactly
matches `TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_ROOT`. That
precreated, canonical, process-owned mode-0700 root must be outside the Git
checkout and must be the sole child of its own canonical, process-owned
mode-0700 guard directory. The guard directory must not be a shared temporary
directory; its device, inode, owner, mode, path digest, and baseline namespace
change time are bound across PREPARE and RESUME so unrelated activity outside
the guard cannot create false root-swap alarms. This namespace-change-time
check is accepted only for the exact local filesystem exercised by the test
suite; it is not claimed to be a portable generation counter or protection
against a hostile same-UID process, a copied ledger, another host, or another
filesystem implementation. It also requires
`TIDEPROOF_INTEGRATED_LIVE_DRILL_JOURNAL_PATH` to
be the sibling canonical absolute path `<run-id>.journal`. Neither final path
may already exist. The orchestrator supplies the recovery child one additional
sibling canonical path named `<run-id>.signed-recovery-bundle.json`, the
mode-0700 root, the exact integrated spec, and the forbidden checkout root.
No raw private bytes or path is included in the public candidate; only bounded
digests and source-control receipt facts leave the child.

Packet B's source-wired provider path is split into Managed-MCP-credential-free
`PREPARE`, durable `HOLD`, and separately authorized `RESUME`. `PREPARE` still
processes configured database endpoints and the recovery-publisher private
signing key while building frozen evidence; it does not receive the Managed MCP
API key. Before `RESUME` can expose the credential-isolated worker, Gate2 and
the supervisor independently reread and rebind the exact persisted context,
dispatch-preparation receipt, human signing payload, decision-ledger binding,
source commit, and tree digest. The signed payload also binds a canonical
non-secret audit-target identity; the worker recomputes that identity from the
credentialed audit URL before constructing either provider or database clients.

PREPARE persists only provider-free evidence. RESUME validates the signed
authorization and writes a provider-free dispatch request, but does not create
a permanent local admission. A dedicated broker uses separate claim-only and
begin-only database identities. It boundedly retries only pre-effect `40001`,
`08xxx`, and equivalent transport failures; after the database returns one
`DISPATCH_GRANTED`, it durably seals a random execution capability, commits
`GRANTED -> EXECUTING`, and only then publishes the local execution grant.
Local decisions bind the database grant ID and capability hash, never raw
provider authority. A crash before the global claim therefore leaves no local
state that can suppress a safe fresh claim.

The worker receives the global grant but no MCP credential or provider client.
It creates one create-only provider-execution-attempt artifact, then connects
over a nonce-bound Unix socket. The separately isolated provider-operation
broker has the MCP bearer, redeem-only database identity, and finalize-only
identity. It atomically moves `EXECUTING -> CREDENTIAL_REDEEMED` before the
first provider request, performs exactly one fixed initialize/notification/
tools-call/close sequence, durably records the transcript, and completes the
exact result. A crash or ambiguity after redemption can only finalize the same
result or become `UNKNOWN_DO_NOT_ACT`; it cannot redeem or dispatch again.

The reconciler has a separate resolve-only database URL and imports only
`ProviderDispatchResolver`. It cannot claim, begin, redeem, complete, mark
unknown, read base tables, or receive an execution/completion capability. The
legacy polymorphic v1 control is hard-disabled in JavaScript and explicitly
dropped during the v2 migration; exact-version live privilege probes must
show `42501` or `42883` for every forbidden operation and no nonce/capability
columns in resolve output. Local OS-process tests cover concurrent claim,
pre-row failure, restart, execution fencing, and provider-operation delivery.
They remain simulation until the exact CockroachDB v26.2, two-host, systemd,
and provider-backed receipts are independently accepted.

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
   evidence, DVI proposal and selected-evidence digests, resource, operation,
   request digest, and outcome—not by recency.
   The tenant, caller, durable source digest, and committed source time derive
   one canonical recovery attempt and signed bundle identity. One fixed-query
   Managed MCP read follows a committed pre-read audit within one continuously
   negotiated session; canonical request, response, and result digests bind
   every RPC through session close. A result-bound terminal audit commits
   before sanitized context is released. No operational capability is
   returned, an unbound principal is denied before MCP, exact replay returns
   the original decision and signed bundle, and changed inputs under the
   operation ID are rejected. These controls do not turn local receipt fields
   into an independent provider signature.

The snapshot is retired after each run without deleting evidence or authority
receipts. An uncertain authority attempt is reconciled and never blindly
replayed.

## Integrated-live acceptance

Acceptance additionally requires:

- an exact v9 build receipt whose 21-file output inventory and privacy boundary
  recompute, followed by a v4 root-stage receipt for the accepted build
  receipt, twelve runtime files, independent verifier, eight installed systemd
  units, and successful daemon reload; each live process is non-root and may
  begin only through the reviewed systemd environment;
- one signed pre/post deployment-attestation pair whose exact expectation
  binds the source commit, tree, configuration, Authority numeric-version ARN,
  code hash, execution role, revisions, and alias target around the drill;
- an atomic mode-restricted private evidence bundle that is reread before
  acceptance and lets an independent reviewer recompute every component digest;
- crash/failpoint evidence that retry after pre-read audit, Managed MCP response,
  terminal-audit COMMIT dispatch/ACK loss, or receipt-publication loss reconciles
  the same canonical recovery attempt without issuing a second MCP read;
- a database receipt for the global provider-dispatch control showing exactly
  one `DISPATCH_GRANTED` transition for the canonical effect key, its matching
  terminal state, and no second provider call across concurrent hosts and
  restart; the count-bound clean-commit two-OS-process broker stress receipt
  against the shared file-backed fake global control is a local prerequisite,
  not a live CockroachDB or provider substitute;
- exact clean public `main`, tree, lockfile, artifacts, configuration, caller
  binding, primary cluster, and recovery cluster digests;
- exactly one passing integrated run digest, all enumerated invariants true,
  and zero invariant violations;
- one source-derived canonical recovery attempt whose replay returns the same
  signed bundle, whose exact first signature bytes are durably available for
  restart reuse, plus one continuous Managed MCP session with canonical
  request, response, and result digests through a successful close;
- a fresh `EXPLAIN (VERBOSE)` receipt naming
  `g1_vector_candidates_embedding_idx`, `vector search`, and exact
  tenant/retrieval prefix spans;
- current cost controls and the exact AWS account, CloudFormation-managed role,
  and observed STS caller triple validated before any Lambda invocation;
- an exact top-level operation ledger for one STS identity read, one
  CloudFormation role-resource read, five Lambda invokes, one DVI component
  run, one authority-race component run, one recovery-broker component run,
  and the Managed MCP initialize, initialized notification, tool call, and
  close requests. This ledger does not enumerate every database statement or
  provider-internal request and therefore does not prove pricing, billing,
  spend authorization, or compliance with an operator-declared dollar cap;
  those remain separate fail-closed evidence gates;
- private raw provider evidence retained, while public receipts contain only
  bounded facts and digests—never credentials, account IDs, ARNs, caller IDs,
  endpoints, or MCP keys; and
- fresh ambiguity/failpoint evidence for the exact release implementation, or
  an explicit historical-only boundary.

The 100 × 50 race and COMMIT-ambiguity receipts remain separate controls. They
may be referenced by digest, but they are not the +1 integrated live drill.

## Present release boundary

The source tree now contains stronger replay, recovery, DVI-snapshot, AWS
evidence, timeout, and resource-bound controls. The DVI proof candidate binds
its selected top-ranked evidence to one exact synthetic drill run. The source
path now consumes database-authorized DVI proposal identities and the exact
selected-evidence digest, but no provider-backed receipt yet proves the live
DVI-to-AWS handoff. The deterministic offline 100-run harness and its
recomputing receipt validator now exist. The source now also contains a
single-run integrated orchestrator, database-global dispatch-control source,
content-addressed nine-component runtime, pinned official Node target,
root-stage installer/verifier, build-output inventory/privacy receipt,
count-bound RESUME
stress runner, owner-restricted external private-evidence source control,
current-byte reread verifier, and strict sanitized candidate composer,
but the provider-backed execution and accepted live receipt do not. The
candidate explicitly records that deployment attestation, independently
attested private-evidence retention/recomputation, pre-provider crash journaling,
root-stage execution, provider-backed global dispatch, crash-safe recovery, and
provider pricing/billing are unproven. The exact
cross-act recovery lookup now has a locally tested source control, but no
provider-backed receipt. Public claims and final release readiness must
therefore remain partial and blocked.

The sanitized `tideproof.aws-authority-race-receipt.v7` source contract carries
the exact configured active-run UUID and validates each contender's configured
proposal identity and selected-evidence digest against the committed database
response. Both durable contender results must now carry the same selected
evidence identity and the same non-reversible
`authorityEvidenceBindingSha256`; the sanitized receipt publishes that shared
DVI binding plus a digest of the selected evidence identity. Its durable proof
rejects a database observation for any other run.
This closes source-level prerequisites for joining the authority race to one
per-drill DVI snapshot. The race lane also requires an exact operation replay
and a changed-input denial before its v7 receipt can pass. The changed-input
probe first resolves and normalizes the exact original durable receipt inside
the same serializable transaction, treats only the spend call's typed digest
mismatch as the expected denial, and rolls back before commit if the probe
unexpectedly returns. The receipt requires five distinct Lambda invocation IDs
and five distinct AWS Invoke request IDs across the contenders, replay, changed
input, and proof. It does not prove the live authorizer, exact retrieval
prefixes, provider concurrency, or any live evidence.

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
- Claim impact: ProofToAct may claim source-level shared DVI identity across the
  two race contenders; no live handoff, concurrency, or exactly-once claim is
  added.

## Exact cross-act recovery lookup

The recovery broker no longer selects a bundle by principal, session, and
recency. `recoverySourceBindingDigestFor` creates one canonical SHA-256 binding
over the exact tenant, run, incident, admitted evidence digest, resource,
winning operation, authority request digest, DVI proposal binding,
selected-evidence binding, and outcome. The signed bundle,
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
  release readiness until the +1 provider-backed receipt binds it to the exact
official release.

### Raw integrated component evidence disappeared after composition

- Root cause: the runner held DVI, authority-race, and recovery receipts only in
  process memory and emitted a sanitized digest summary without first creating
  a durable private source for independent recomputation.
- Why it was missed: component and privacy tests correctly rejected raw public
  identifiers, but did not require a separate private evidence lifecycle before
  sanitization.
- Earliest detection point: terminate the runner after candidate composition
  and require another process to recompute all three component digests from one
  immutable, mode-restricted bundle.
- Repair: candidate v2 is unreachable until the canonical raw bundle is written
  through a mode-0600 source-local temporary file in an approved canonical
  mode-0700 owner directory outside the Git checkout, directory-synced, and
  reread byte-for-byte. Candidate composition rereads it again and binds the
  current bundle plus source-control-receipt digests without exposing its path
  or raw identifiers. The final clean-release check now follows persistence.
- Regression/preventive control: focused tests reject permissive or
  non-canonical parents, preexisting destinations, post-write byte drift,
  component drift, and any candidate path that lacks the verified private
  file.
- Verification: the focused suite and exact-source release gates must pass on
  the repaired head; no provider execution is implied.
- Residual risk and claim impact: the unkeyed receipt is forgeable from current
  bytes and therefore proves neither historical atomic operations nor off-host
  retention. The source-local journal described below now preserves a durable
  pre-provider intent and chained current-state result digests, but it is also
  unkeyed. Independent journal attestation, reviewer recomputation, signed
  deployment identity, and crash-safe Managed MCP recovery remain required.
  The public claim remains a non-accepting component candidate.

### Provider actions began before a durable run intent existed

- Root cause: the integrated runner verified source bytes and then immediately
  invoked the DVI component, leaving no durable record of the intended run or
  the last completed boundary if the process died before final evidence
  persistence.
- Why it was missed: the first private-evidence repair protected completed raw
  component bytes, while its tests began only after all provider components had
  returned.
- Earliest detection point: inspect the evidence root from inside the first
  component callback and require a create-only, fsynced intent entry before the
  callback can observe control.
- Repair: after exact-release verification and before the first component call,
  the runner creates an owner-only journal outside the Git checkout and writes
  a mode-0600 intent entry through a same-filesystem temporary inode, hard-link
  publication, file fsync, and directory fsync. It then adds create-only,
  canonical entries for DVI, authority race, recovery, private-evidence, and
  post-release digests. Every entry binds the exact release/run identity and
  the preceding entry digest.
- Regression/preventive control: focused tests require the intent to be the
  only journal entry visible before the first provider component, reject phase
  reordering and reuse, and detect entry-byte tampering. Candidate composition
  rereads all six entries and verifies the complete hash chain and expected
  payload digests.
- Verification: the focused integrated-drill suite plus the release security,
  privacy, claims, proof, and exact-source gates must pass on the exact head.
  No provider execution is implied.
- Residual risk and claim impact: the journal is source-local and unkeyed, so
  current bytes do not independently prove when or by whom entries were
  created, off-host retention, or successful recovery across a real crash.
  Independent pre/post attestation, an external evidence finalizer, and the
  provider-backed crash drill remain mandatory. The candidate stays
  non-accepting.

### A restart could re-sign one canonical recovery bundle

- Root cause: P-256 signing is randomized. The recovery runner signed the
  canonical bundle in memory and immediately appended it twice, so a process
  restart could produce different signature bytes for the same unsigned bundle
  even though the bundle digest remained stable.
- Why it was missed: the idempotency tests compared the database bundle digest
  and reused one in-memory object; none constructed a second signer invocation
  against a durable first-signature artifact.
- Earliest detection point: sign the same canonical unsigned bundle twice,
  persist the first result, and require the second invocation to return the
  byte-exact first normalized signed bundle. Changed unsigned input, signature
  tamper, permissive paths, and noncanonical bytes must fail before publication.
- Repair: before the first recovery publication, the runner normalizes and
  verifies the signature, create-only publishes a canonical signed-bundle
  envelope in the owner-only evidence root through a synced temporary inode and
  hard link, syncs the directory entry, and rereads the final file. A later
  invocation verifies the persisted signature and exact release/run envelope
  and reuses those bytes when the unsigned bundle digest matches. Reuse fsyncs
  the validated file and parent again, verifies that the pathname still names
  the opened inode, and marks the original create/link protocol unobserved
  rather than inventing historical durability.
- Regression/preventive control: focused tests cover separate randomized
  signatures, exact first-byte reuse, changed canonical input, altered
  authority markers, unknown nested fields, equivalent timestamps, uppercase
  digests, noncanonical base64 padding, byte tamper, pre-existing exact bytes,
  pathname replacement, mode-0600 output, mode-0700 parent ownership, and the
  recovery-child path allowlist. Candidate composition requires the bounded
  persistence receipt.
- Verification: focused recovery-store, persistence, and integrated-drill tests
  plus release security, proof, privacy, and claim gates must pass on the exact
  repaired head. No provider execution is implied.
- Residual risk and claim impact: current bytes and source behavior still do
  not prove a real restart occurred, that the host retained them across a
  crash, or that reconciliation avoided a second Managed MCP call. Provider
  failpoints, independent attestation, and crash-safe orchestration remain
  mandatory; the candidate stays non-accepting.

### Unattested components were accepted as an exact-release receipt

- Root cause: the integrated composer trusted self-reported source/configuration
  digests and an observed numeric Lambda version without consuming the existing
  signed pre/post deployment-attestation contract.
- Why it was missed: tests mocked valid DVI, race, and recovery outputs and
  asserted `PASS`; none required an attestation expectation or pair.
- Earliest detection point: omit deployment attestation from an otherwise valid
  component set and require that the accepted schema and `PASS` remain
  unreachable.
- Repair: the current runner now emits only a non-accepting candidate, removes
  exact-release invariants, and publishes explicit acceptance blockers.
- Regression/preventive control: focused tests and the release-security verifier
  bind the candidate schema, incomplete status, and blocker fields.
- Verification: source tests and release gates must pass on the exact repaired
  head; provider execution remains prohibited and pending.
- Residual risk and claim impact: a reviewed attestation-aware finalizer,
  independent retention/recomputation of the private evidence, and crash-safe
  recovery repair are still required. Until then, ProofToAct may claim only a
  source-level component candidate, not an accepted exact-release +1 drill.

### Recovery binding stopped before the DVI proposal

- Root cause: the recovery source resolver joined the winning authority
  receipt to evidence and its outbox intent, but did not join the exact DVI
  proposal or carry the proposal's authority-evidence binding into the signed
  recovery source digest.
- Why it was missed: the earlier cross-act negatives varied authority and
  recovery identifiers, while all fixtures reused one synthetic DVI proposal.
  Static controls checked receipt-to-outbox equality but not
  proposal-to-receipt equality.
- Earliest detection point: keep the same winning operation and request while
  substituting either accepted race-receipt DVI digest; resolution must fail
  before signing, recovery publication, bootstrap, or MCP.
- Repair: the resolver joins the exact proposal across proposal,
  logical-action, authorization, run, incident, resource, agency, policy,
  selected-evidence, and payload identities. The runtime recomputes the
  selected-evidence digest and compares both accepted race-receipt DVI
  digests. Version 3 of the signed source digest includes both.
- Regression and preventive control: focused mismatch tests cover both DVI
  digests; a static SQL control binds every proposal join; both runners require
  the nine-field operator binding; and the source-digest test is an exact
  hash-bound release-security surface.
- Verification: 447 local tests, the security/proof/claims/submission gates,
  zero-vulnerability audit, deterministic build, exact provenance, and two
  independent reviews must pass on the exact commit. Provider execution
  remains pending.
- Residual risk and claim impact: source now preserves one DVI identity through
  recovery publication and lookup, but no live CockroachDB, AWS, or Managed MCP
  receipt proves that handoff. No live, batch, concurrency, or exactly-once
  claim is added.

### Recovery export accepted stale or replaced authority

- Root cause: the v2 recovery source resolver bounded receipt age but did not
  require the receipt lease, current resource holder and fence, resource lease,
  and DVI proposal expiry to remain current at database statement time. Its
  nested admissibility helper also evaluated the selected evidence interval
  and conflicting-evidence windows with the outer statement timestamp before
  or across a receipt-intent wait.
- Why it was missed: earlier controls bound durable identities across receipt,
  outbox, and proposal rows, but treated freshness as a separate authorization
  concern and did not carry its canonical currentness contract into recovery.
- Earliest detection point: replace the resource holder, advance its fence, or
  set any lease or proposal expiry equal to database time; the resolver must
  return no row before recovery signing or publication.
- Repair: the resolver now joins the exact resource holder across tenant,
  resource, run, incident, operation, agent, proposal, logical-authority key,
  and fence. Its original candidate read now captures all static evidence and
  verification bindings, the selected evidence observation/validity interval,
  and every structurally valid conflicting-evidence observation/validity
  interval. Only after that complete read and any intent wait does it capture
  one `clock_timestamp()` and evaluate receipt age, receipt/resource/proposal
  expiry, selected-evidence validity, and active conflicts from those captured
  values. No second protected-table read follows the clock. Its contract is
  current at that post-read database decision point; it does not claim
  currentness when a remote client later receives or uses the row. Stored spend likewise refreshes
  database time after blocking locks and before every replay return. Its
  exact-currentness helper completes the structural read, captures one
  `clock_timestamp()`, and returns both the boolean and reported decision time
  from that same clock. Reconciliation projects that same helper row rather
  than combining it with an outer statement clock. Direct
  acquisition rechecks the exact proposal in the lease-creating statement and
  reports final currentness after an awaited pre-commit observer. Stored
  protected-effect admission rechecks exact receipt/resource/proposal expiries
  with fresh post-insert database time and removes its own row if currentness
  fails.
- Regression and preventive control: focused source controls check every
  holder equality, all post-wait strict database-time predicates, and the coupled
  observer, snapshot, authorization, spend, replay, reconciliation, and effect
  clocks. Gate One includes exact-equality spend denial, a direct transaction
  held past proposal expiry, a reconciled cross-epoch wait, and a provider-only
  call to `tp_api.g1_spend_authority_v1` held behind the resource lock. The
  provider runner also carries a stored replay whose currentness helper is held
  behind an outbox intent and must return a same-clock result within one second
  of the exact proposal-expiry boundary. A separate amplified deterministic
  control captures a current replay at clock A, keeps that transaction open
  across expiry, proves that pairing A's boolean with later clock B would
  contradict, then requires a fresh real replay at clock C to return an aligned
  expired pair. It does not claim literal reproduction of the old production
  micro-gap. The runner also carries a
  protected-effect insert held behind an uncommitted uniqueness occupant, and
  a recovery resolver held behind a receipt intent. Two additional recovery
  drills hold that same intent until the selected evidence expires or a
  structurally verified conflicting claim becomes active, while independently
  requiring the receipt, resource lease, and proposal to remain live. All
  expiry/conflict cases require no newly released authority or protected
  effect. Every held-wait probe awaits a bounded query-ready signal emitted
  after `BEGIN` and immediately before the tested SQL before starting its
  expiry or conflict timing; connection setup therefore cannot satisfy the
  wait assertion. Failure cleanup first expires the synthetic proposal, then
  releases the blocker and drains the pending query, so no test transaction is
  left running in the background. The reviewed 38-statement SQL batch digest also changes
  whenever the emitted SQL changes.
- Verification: the focused control and the complete local release gate set
  must pass on the exact commit; provider-backed CockroachDB v26.2 execution is
  still required.
- Residual risk and claim impact: source rejects stale and replaced recovery
  authority, but no live provider receipt or exactly-once claim is added.

### Resolver return-shape upgrade initially used destructive migration DDL

- Root cause: adding an output column under the unchanged function signature
  used `CREATE OR REPLACE FUNCTION`, which cannot change an existing
  CockroachDB/PostgreSQL return type.
- Why it was missed: clean-bootstrap tests inspected the final SQL definition
  but did not model upgrade from the prior installed return shape.
- Earliest detection point: compare each unchanged function signature's old
  and new return tables before accepting a bootstrap change.
- Repair and preventive control: the expanded return contract now has the
  versioned `g1_resolve_recovery_source_receipt_v2` name. Bootstrap creates v2
  before ownership and least-privilege grants, never drops v1, and grants only
  v2 after the managed-principal privilege scrub. The two preflight censuses
  admit only the exact historical v1 and current v2 signatures for the source
  role while allowing capabilities to be missing; the final census returns to
  the strict v2-only policy. Existing v1 installations therefore remain
  recoverable as database objects but inaccessible to the runtime. Static and
  upgrade-state controls require that exact transitional policy, v2-only final
  policy, v2 production call, an exact emitted-SQL batch pin, and a v1
  denial-or-absence probe. Before the bootstrap issues any function DDL, it
  materializes the exact 37 statements produced by `createFunctions` and
  rejects the entire batch unless its framed SHA-256 digest matches the
  reviewed batch. This control evaluates emitted SQL bytes, not JavaScript
  source spelling; any SQL change therefore requires an explicit review and
  digest update before the first database query.
- Cutover procedure: this is an explicitly quiesced, roll-forward-only
  migration, not a zero-downtime or rollback-compatible change. Stop the
  recovery evidence runners, run bootstrap to completion, require v2 success
  plus either SQLSTATE `42501` for a retained v1 object or `42883` for a clean
  install, then deploy only the exact v2 runner bytes. Do not restart an older
  runner after the privilege scrub. Any failed bootstrap or probe keeps
  recovery publication stopped until the v2 path is repaired and reverified.
- Verification: focused resolver/bootstrap tests exercise direct literal,
  concatenated, Unicode-whitespace, computed-name, and split-identifier DDL
  constructions and require rejection while the fake database client still
  records zero queries; benign JavaScript comments, regular expressions, and
  dollar-quoted source-only decoys do not affect the emitted batch. The
  hash-bound release security gate also passes. Provider-backed CockroachDB
  v26.2 upgrade execution and privilege census, including retained-v1 owner
  and denial checks, remain required.
- Residual risk and claim impact: source migration is non-destructive and the
  weaker resolver is not granted after convergence, but the cutover requires
  an outage and has no application rollback window. This is not a live upgrade
  receipt and does not close the provider gate.

### Recovery publication trusted process time after canonical insertion

- Root cause: the production publisher normalized a signed bundle without the
  process-time freshness validator, while the database append routine checked
  only source-relative TTL. A stale, future-dated, or already expired bundle
  could therefore occupy the canonical recovery identity. The fixed MCP read
  checked only expiry, and the direct Gate One read delegated the remaining
  freshness checks to the host clock.
- Why it was missed: freshness negatives exercised row validation after a row
  was returned. They did not prove that database time rejected the row before
  canonical lookup and insertion, nor that both database read paths used the
  same predicates. Initial repair review also used transaction-start time,
  which a held publisher transaction could age before invoking the routine.
- Earliest detection point: submit expired, source-stale, source-future, and
  overlong-expiry inputs to the append routine and require rejection before
  its first canonical lookup or insert. Then inspect both fixed and direct
  reads for one shared statement-time filter.
- Repair: the SECURITY DEFINER append routine now enforces the one-hour source
  age, one-minute future skew, current expiry, and 24-hour remaining-expiry
  bounds using `statement_timestamp()` before any canonical lookup or insert.
  The fixed MCP query and direct Gate One query consume one shared SQL filter
  with the same boundaries.
- Regression and preventive control: a red-before-green static control binds
  all four append predicates ahead of canonical occupancy, a shared-filter
  control requires both read paths, and a publisher negative requires SQLSTATE
  `22023` to roll back without commit or retry.
- Verification: focused freshness, database-bootstrap, publication, and query
  tests pass. Full local tests, audit, release gates, deterministic build,
  independent review, and exact-main CI remain required on the final commit.
- Residual risk and claim impact: provider-backed CockroachDB v26.2 execution
  must confirm `statement_timestamp()` behavior and the rejection boundaries.
  No live recovery, availability, or exactly-once claim is added.

## Precommitted recovery-publisher trust root

The recovery evidence runners no longer generate a publisher key and then
trust that same key in-process. During primary-cluster security bootstrap, the
database owner inserts the expected trust-root commitment and publisher-key-set
digest once in the bootstrap flow (`ON CONFLICT DO NOTHING`, with mismatch
rejected). The runtime `tp_recovery_source_user` receives only
the exact, database-time-current authority-receipt resolver; the separate
`tp_recovery_audit_user` receives only the exact audit-event and trust-root
resolvers plus the append-only audit surface. Neither receives base-table
access. Before either runner reads source state or the trust root, it executes
six rollback-bounded privilege-pure write probes and 20 managed-table read
probes, requiring SQLSTATE `42501` from both primary credentials for each. The
broker re-reads its two audit events only by their
committed event IDs and digests. No recovery runner accepts
`PRIMARY_DATABASE_URL`.

Before either runner signs, publishes, bootstraps recovery state, or reaches
Managed MCP, it must match its canonical root and P-256 signing key against
that database-owned row. A coordinated replacement of the root, adjacent
hash, and signing key therefore fails unless the separately privileged primary
bootstrap commitment already matches. Receipts expose only digests and the
database commit time; they never expose the private key.

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

An independent review then found that both runner processes still carried the
primary administrator URL for exact source and audit reads. That credential
could rewrite the new row, so the row-level grant test did not establish an
independent runtime trust root.

- Root cause: the trust-root repair narrowed the new resolver but preserved the
  older runner connection used for direct joins and final audit-table reads.
- Why it was missed: tests proved `tp_recovery_audit_user` lacked table writes
  but did not inventory every credential present in the two runner processes.
- Earliest detection point: statically forbid `PRIMARY_DATABASE_URL` in both
  runners and require a live write-denial probe for every primary credential
  before any source, trust-root, signing, publication, or MCP action.
- Repair and preventive control: a dedicated NOLOGIN capability role and
  login-bound `tp_recovery_source_user` expose one exact source resolver. The
  audit user exposes exact audit/trust resolvers. Shared helpers validate one
  row, database time, IDs, digests, outcome, admissibility, and durable intent;
  both scripts prove trust-root write denial before proceeding.
- Verification: focused controls cover source/audit cross-denial, base-table
  denial, trust-root write denial, exact source resolution, exact audit
  resolution, and the absence of the administrator variable in both runners.
- Residual risk and claim impact: provider-backed CockroachDB v26.2 grants,
  resolver execution, and denial receipts remain required. A database
  administrator can still alter grants or the committed row; no administrator
  exclusion or live recovery-authenticity claim is added.

### Recovery operator input contract

The operator must prepare the publisher root before primary security bootstrap.
Generate one P-256 key pair in the approved private custody boundary. Encode the
public key as canonical DER SPKI base64 and the private key as canonical DER
PKCS8 base64. The canonical public root is the byte-exact JSON object
`{"schemaVersion":"tideproof.recovery-publisher-trust-root.v1","publisherKeyId":"<key-id>","publicKeySpkiBase64":"<canonical-base64>"}`.
`TIDEPROOF_RECOVERY_PUBLISHER_TRUST_ROOT_COMMITMENT` is SHA-256 over the UTF-8
bytes of `tideproof-recovery-publisher-trust-root-commitment-v1\n` followed by
that exact JSON. `TIDEPROOF_RECOVERY_PUBLISHER_KEY_SET_DIGEST` is the
`trustedPublisherKeysDigest` of the one-entry key map. Supply those two digests
to `npm run gate1:security`; keep the JSON and
`RECOVERY_PUBLISHER_PRIVATE_KEY_PKCS8_BASE64` outside the database and supply
them only to the two recovery runners. Never record the private key, database
passwords, or MCP key in a shell transcript or evidence artifact.

Both runners require these exact shared private inputs:

| Input | Required source |
| --- | --- |
| `PRIMARY_RECOVERY_SOURCE_DATABASE_URL` | URL whose login is exactly `tp_recovery_source_user`; same reviewed primary host, port, and `tideproof` database as the audit URL |
| `PRIMARY_AUDIT_DATABASE_URL` | URL whose login is exactly `tp_recovery_audit_user`; never an owner or administrator URL |
| `RECOVERY_SOURCE_TENANT_ID` | Tenant UUID from the same private provider race configuration bound by the accepted race receipt |
| `RECOVERY_SOURCE_RUN_ID` | Exact accepted race receipt `runId` |
| `RECOVERY_SOURCE_INCIDENT_ID` | Incident UUID from that same bound race configuration |
| `RECOVERY_SOURCE_EVIDENCE_ID` | Exact selected evidence UUID from that same bound DVI proposal |
| `RECOVERY_SOURCE_RESOURCE_ID` | Exact resource ID from that same bound race configuration |
| `RECOVERY_SOURCE_OPERATION_ID` | Accepted race receipt `winner.operationId` |
| `RECOVERY_SOURCE_REQUEST_DIGEST` | Accepted race receipt `winner.requestDigest` |
| `RECOVERY_SOURCE_AUTHORITY_EVIDENCE_BINDING_SHA256` | Accepted race receipt `dvi.authorityEvidenceBindingSha256` |
| `RECOVERY_SOURCE_SELECTED_EVIDENCE_BINDING_SHA256` | Accepted race receipt `dvi.selectedEvidenceBindingSha256` |
| `PRIMARY_CLUSTER_ID`, `RECOVERY_CLUSTER_ID` | Exact provider cluster UUIDs from the frozen deployment inventory |
| `EXPECTED_PRIMARY_HOSTNAME`, `EXPECTED_RECOVERY_HOSTNAME` | Exact provider hostnames from that inventory; wildcards, aliases, proxies, and localhost are invalid |
| `TIDEPROOF_RECOVERY_PUBLISHER_TRUST_ROOT` | The canonical public-root JSON prepared before bootstrap |
| `TIDEPROOF_RECOVERY_PUBLISHER_TRUST_ROOT_COMMITMENT` | The same commitment inserted during primary security bootstrap |
| `RECOVERY_PUBLISHER_PRIVATE_KEY_PKCS8_BASE64` | The separately held matching P-256 private key |
`npm run gate1:recovery` additionally requires the recovery administrator URL
as `RECOVERY_DATABASE_URL` and `RECOVERY_PUBLISHER_PASSWORD` because that
component creates and narrows the disposable recovery database. Optional
`RECOVERY_SESSION_ID` and `SNAPSHOT_VERSION` values, when supplied, must be
recorded as private operator inputs; otherwise the runner derives them.
`npm run gate1:recovery-broker` instead requires the already narrowed
`RECOVERY_PUBLISHER_DATABASE_URL`, `MCP_API_KEY`, and the exact immutable
`SOURCE_BUILD_IDENTITY`. When that broker is invoked by the integrated-live
orchestrator, it alone also requires these source-controlled persistence
bindings; `gate1:recovery` does not consume them:

| Broker-only integrated input | Required source |
| --- | --- |
| `TIDEPROOF_INTEGRATED_LIVE_DRILL_SPEC` | Exact canonical integrated spec supplied by the source-controlled orchestrator |
| `TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_ROOT` | Canonical process-owned mode-0700 root outside the Git checkout and sole child of a dedicated canonical process-owned mode-0700 guard directory |
| `TIDEPROOF_INTEGRATED_LIVE_DRILL_RECOVERY_BUNDLE_PATH` | Exact sibling `<run-id>.signed-recovery-bundle.json` path under that root |
| `TIDEPROOF_INTEGRATED_LIVE_DRILL_FORBIDDEN_ROOT` | Canonical Git checkout root that the private path must not enter |

The nine `RECOVERY_SOURCE_*` values are one indivisible binding. Do not copy
the winner operation and request digest onto tenant, incident, evidence, or
resource values or DVI digests from another run, and do not reconstruct missing
fields from a latest-row query. Before any resolver, signing, publication, recovery
bootstrap, or MCP call, both primary credentials must independently return
SQLSTATE `42501` for all six privilege-pure trust-root write probes and all 20
managed base-table read probes. The source resolver then joins the authority receipt
to its outbox intent and exact DVI proposal across request, proposal,
logical-action, authorization, run, incident, resource, agency, policy,
selected evidence, fence, effect, and payload identities. The runtime also
recomputes the selected-evidence binding digest and compares both DVI digests
to the accepted race receipt before signing or publication. Any mismatch or
non-singleton result fails closed.

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
receipt is emitted.
`PASS` remains subject to independent acceptance review and does not prove that
AWS consumed the binding or satisfy the +1 integrated, authorization,
production-safety, or final-release gates by itself.

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
  the actual provider authorizer, AWS consumption, the +1 integrated drill, or
  cluster-wide inherited-capability exclusion.
- Claim impact: source can claim persisted snapshot-bound exclusion reasons;
  live and release claims remain blocked until the fresh provider receipt and
  independent acceptance review pass.
