# Tideproof

**Public clean-room source. Not yet a contest submission or live AWS claim.**

Tideproof is an admissibility-memory demonstration for high-stakes agents.
Its “Highwater Drill” is a synthetic multi-agency response exercise: shared
memory preserves attributable evidence, filters what is no longer admissible,
exposes conflicts, gives exactly one local contender a scarce resource, lets a
successor reconstruct prior state, and refuses to replay an operation.

The thesis is deliberately narrower than “AI remembers better”:

> Most memory systems optimize what an agent should remember. Tideproof governs
> what an agent is still allowed to believe and act upon.

![Tideproof trust boundaries: evidence is admitted before vector ranking, agents propose without authority, CockroachDB commits one fenced receipt, and Managed MCP returns context only.](docs/media/architecture.svg)

The diagram is synthetic and claim-bounded. Its accessible text counterpart
and the fuller Gate One and Gate Two topology are in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## What exists now

This repository contains a deterministic local vertical slice, an accepted
CockroachDB Cloud Gate One proof, and a locally tested AWS Gate Two candidate:

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
- 100 live 50-contender races and 100 ambiguity runs at each transaction
  boundary, with no invariant violation;
- a generated AWS CloudFormation candidate with private versioned artifacts,
  a signed-out content-only judge surface, IAM-separated Lambda roles, one bounded
  Amazon Nova Micro proposal path, P-256 KMS receipt signing with independently
  pinned public-key evidence, exact Lambda code hashes, a dedicated exact-route
  caller, private API access logs, an isolated two-concurrency CockroachDB
  authority candidate that derives capability fields outside the model and
  calls only least-privilege `SECURITY DEFINER` surfaces, then requires a
  separate read-only durable-state observation of both receipts, the winner's
  outbox and fence, and zero protected effects, plus opt-in temporary
  same-role capability probes;
- an exact-head signed-out demo verifier that compares every static and
  dynamic public response with the clean checkout, binds the health receipt to
  the built Demo artifact, checks strict browser headers, and probes route and
  advisory denials without treating reachability as advisory-path proof;
- a keyboard-operable three-act local browser demonstration with persistent
  proof-state labels, exact evidence details, receipt links, safe reset, and
  deterministic unit tests.

It does **not** yet contain or claim:

- a deployed public AWS judge URL;
- live AWS deployment, Bedrock inference, KMS signatures, or IAM denial
  evidence;
- a live CockroachDB-to-AWS handoff or overlapping Lambda authority race;
- exactly-once external effects, regional survival, or disaster readiness;
- production security, availability, or suitability for real emergencies.

Those are explicit build gates, not implied capabilities.

## Run locally

Requires Node.js 22 or newer. Local tests and the browser demo need no cloud
credentials. Live Gate One scripts use the `pg` dependency and explicit
project credentials supplied through the environment; secrets must remain in
a secret store and never enter the repository.

```sh
npm run proof:verify
npm run dependencies:verify
npm run licenses:verify
npm test
npm run generate:gate2
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
4. AWS Lambda/API Gateway for a capability-free signed-out judge surface plus
   separated IAM-authenticated proposal roles, KMS, and Amazon Bedrock; the
   local candidate is not a live-cloud claim.

The machine-checked [`PROOF_MANIFEST.json`](PROOF_MANIFEST.json) maps every
current claims-ledger row to exact evidence bytes and leaves incomplete live
gates explicit. Run `npm run proof:verify` to reject changed evidence, missing
claim coverage, unsafe paths, or a stale hash.

The deterministic
[`docs/DEPENDENCY_INVENTORY.md`](docs/DEPENDENCY_INVENTORY.md) enumerates all
locked runtime and development packages, their package-lock license
identifiers, optional state, and install-script flag. Run
`npm run dependencies:verify` to reject drift, unreviewed license identifiers,
non-registry sources, missing SHA-512 integrity, or non-exact direct versions.
The generated [`THIRD_PARTY_NOTICES.txt`](THIRD_PARTY_NOTICES.txt) separately
binds the 42-package union whose source is actually present in the six Gate
Two bundles, including exact license-text hashes and five explicit fallbacks
for published packages that omit a standalone license file. Run
`npm run licenses:verify` to rebuild the esbuild input graph and reject package,
version, integrity, license-source, fallback, or notice-byte drift. Every Gate
Two ZIP embeds that verified notice file byte-for-byte. On official `main`,
`npm run release:provenance` now binds the full single-root Git ancestry,
tracked file modes, clean installed package identities, dependency inventory,
and bundle notice inputs to the exact public checkout. The final release must
rerun that control with the zero-vulnerability and exact-head build gates, then
bind the uploaded object versions and deployed Lambda `CodeSha256` values.

See `CLAIMS.md`, `evidence/`, `docs/CONTEST_MATRIX.md`,
`docs/ARCHITECTURE.md`, `docs/AWS_GATE2.md`, `docs/PRIOR_ART.md`, and
`docs/WINNING_PLAN.md`. The fail-closed Devpost copy and release checklist
live in `docs/SUBMISSION_PACKET.md`. The canonical cross-surface design,
asset, rights, and publish gates live in `docs/VISUAL_RELEASE_SYSTEM.md`;
final marketing art has not been produced or approved.

## Safety and provenance

Tideproof is a synthetic demonstration, not operational emergency software.
No Conversate source, proprietary Northstar engine, private customer data, or
OpenClaw OAuth credential may enter this project. See `CLEAN_ROOM.md`.
Report security concerns privately through GitHub's security-advisory flow;
see `SECURITY.md`.
