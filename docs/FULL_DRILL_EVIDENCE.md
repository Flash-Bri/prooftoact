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
harness, bounded multi-race deployment shape, exact cross-act recovery lookup,
and live receipt do not yet exist. Public claims and final release readiness
must therefore remain partial and blocked.
