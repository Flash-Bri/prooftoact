# Tideproof

**Private clean-room build. Not yet a contest submission.**

Tideproof is an admissibility-memory demonstration for high-stakes agents.
Its “Highwater Drill” is a synthetic multi-agency response exercise: shared
memory preserves attributable evidence, filters what is no longer admissible,
exposes conflicts, gives exactly one local contender a scarce resource, lets a
successor reconstruct prior state, and refuses to replay an operation.

The thesis is deliberately narrower than “AI remembers better”:

> Most memory systems optimize what an agent should remember. Tideproof governs
> what an agent is still allowed to believe and act upon.

## What exists now

This repository contains a deterministic local vertical slice plus a
credential-gated CockroachDB Cloud Gate One candidate:

- provenance, validity-window, and scope checks before vector ranking;
- unresolved-conflict detection and fail-closed authorization;
- CockroachDB-backed signed evidence, validity, revocation, scope, and conflict
  checks before vector ranking and inside authorization;
- serializable one-winner resource reservation with durable denial receipts,
  semantic replay protection, monotonic fencing tokens, and a transactional
  outbox;
- a protected synthetic effect boundary that rejects stale, future, expired,
  cross-scope, and changed-payload requests;
- CockroachDB Distributed Vector Indexing with named-index plan evidence and
  fail-closed dimension validation;
- an isolated CockroachDB recovery cluster and deterministic Managed MCP
  fixed-query broker with signed context-only bundles;
- separate pre-read and terminal recovery-audit events on the primary cluster;
- a local browser demonstration and deterministic unit tests.

It does **not** yet contain or claim:

- AWS deployment or Bedrock model use;
- production caller authentication, KMS-backed signing, or deployed IAM
  separation;
- full 100-run concurrency and ambiguity acceptance;
- exactly-once external effects, regional survival, or disaster readiness;
- production security, availability, or suitability for real emergencies.

Those are explicit build gates, not implied capabilities.

## Run locally

Requires Node.js 22 or newer. Local tests and the browser demo need no cloud
credentials. Live Gate One scripts use the `pg` dependency and explicit
project credentials supplied through the environment; secrets must remain in
a secret store and never enter the repository.

```sh
npm test
npm run demo
npm run dev
```

Then open `http://127.0.0.1:4173`. The scenario and all identities are
synthetic.

## Contest target

The intended entry is for CockroachDB × AWS “Build with Agentic Memory.”
The implementation uses or is planned to use:

1. CockroachDB Distributed Vector Indexing for relevance ranking after
   admissibility filters;
2. CockroachDB Managed MCP through a deterministic context-only recovery
   broker;
3. CockroachDB serializable transactions, immutable-shaped receipts, fencing,
   and transactional outbox;
4. AWS Lambda/API Gateway, KMS, and Amazon Bedrock for separated bounded
   runtime roles.

See `CLAIMS.md`, `evidence/`, `docs/CONTEST_MATRIX.md`,
`docs/ARCHITECTURE.md`, `docs/PRIOR_ART.md`, and `docs/WINNING_PLAN.md`.

## Safety and provenance

Tideproof is a synthetic demonstration, not operational emergency software.
No Conversate source, proprietary Northstar engine, private customer data, or
OpenClaw OAuth credential may enter this project. See `CLEAN_ROOM.md`.
