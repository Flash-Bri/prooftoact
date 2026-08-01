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
   are a subset of the snapshot, and current admissibility is rechecked before
   authority is spent.
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
evidence, timeout, and resource-bound controls. The provider-backed batch
harness, bounded multi-race deployment shape, and live receipt do not yet
exist. The exact cross-act recovery lookup now has a locally tested source
control, but no provider-backed receipt. Public claims and final release
readiness must therefore remain partial and blocked.

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

- exactly 10,000 admissible candidate evidence IDs by sorted-set SHA-256;
- one exact tenant, incident, retrieval, agency, three-dimensional query,
  ten-result limit, and 60-second snapshot TTL;
- exactly one expected case for each of `verification_binding_mismatch`,
  `verification_key_revoked`, `future_observation`, `not_yet_valid`,
  `expired`, `out_of_scope`, and `unresolved_conflict`; and
- which excluded row must be closer to the query than every returned ranked
  row.

The authorizer session creates the snapshot only through
`tp_api.g1_prepare_vector_set_v1`, observes every exclusion through
`tp_api.g1_observe_admissibility_v2`, ranks only through
`tp_api.g1_rank_vector_set_v1`, and retires only through
`tp_api.g1_delete_vector_set_v1`. The auditor session reads the private
candidate IDs, validates the expected set digest, captures
`EXPLAIN (VERBOSE)`, and requires `vector search`,
`g1_vector_candidates_embedding_idx`, and the exact tenant/retrieval prefix
spans. The auditor then executes that exact ranked query and requires its
ordered results to match the authorizer function byte-for-byte. It also proves
the designated inadmissible row is semantically closer than the first returned
candidate and verifies zero candidate rows remain after retirement.

The emitted receipt contains source, tree, fixture, plan, ranked-set, database
cluster, version, and session digests; snapshot and cleanup timestamps; counts;
reason labels; and an order-sensitive ranked-result digest. It does not emit
credentials, usernames, endpoints, raw plans, fixture IDs, or query vectors.
Both database sessions must report the same CockroachDB cluster, any prepare
attempt still attempts retirement, and a cleanup failure is preserved
alongside the primary failure. Pool shutdown must also succeed before the
`PASS` receipt is emitted. A `PASS` remains subject to independent acceptance
review and does not satisfy the 100-drill, AWS, authorization,
production-safety, or final-release gates by itself.

No provider-backed receipt from this lane exists yet.
