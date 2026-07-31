# Devpost submission packet

**Status: DRAFT — NOT READY TO SUBMIT**

This is the canonical copy and release-gate packet for Tideproof's CockroachDB
× AWS “Build with Agentic Memory” entry. It is deliberately fail-closed:
bracketed stop tokens must not be copied into Devpost, and no live AWS, demo,
video, or visual-rights claim may be published until its named evidence exists.

The official competition overview, rules, and resources were rechecked on
2026-07-30:

- https://cockroachdb-ai.devpost.com/
- https://cockroachdb-ai.devpost.com/rules
- https://cockroachdb-ai.devpost.com/resources

The official submission period ends on 2026-08-18 at 5:00 PM ET. Tideproof's
internal deadline is 2026-08-16 at 5:00 PM ET, preserving a 48-hour correction
window. The free, unrestricted judge build must remain available through the
end of judging on 2026-09-15 at 5:00 PM ET.

## Submission coordinates

| Field | Release value |
| --- | --- |
| Project name | `Tideproof` |
| Subtitle | `Admissibility memory for high-stakes agents` |
| Public source | https://github.com/Flash-Bri/tideproof |
| License | MIT |
| Source commit | `[[FINAL_RELEASE_COMMIT_REQUIRED]]` |
| Functional demo | `[[PUBLIC_SIGNED_OUT_DEMO_URL_REQUIRED]]` |
| Public video | `[[PUBLIC_YOUTUBE_OR_VIMEO_URL_REQUIRED]]` |
| Entrant / authorized representative | `[[OWNER_CONFIRMATION_REQUIRED]]` |

Do not substitute a localhost URL, private preview, repository page, AWS
console URL, or credentialed environment for the functional demo.

## Hard publish gate

Every item must have a dated receipt tied to the final release commit:

- [ ] The public repository, MIT license, README, dependency lockfile, example
  configuration, and local setup path are visible in a signed-out browser.
- [ ] Hosted CI passes at the exact final source commit.
- [ ] The AWS application is deployed from freshly built exact-head artifacts
  only after `npm run gate2:aws-readiness` emits a combined exact-head and
  read-only AWS `PASS` receipt in the authenticated lane.
- [ ] Live evidence proves the named AWS services actually used, their
  least-privilege boundaries, the one bounded model call, KMS verification,
  exact API traversal, direct-Lambda denial, one genuinely overlapping
  two-Lambda CockroachDB authority race, a later read-only durable-state
  reconciliation proving two terminal receipts, the denial observed the
  winner's fence, one winner-bound outbox, and zero protected effects, cost
  controls, and teardown path.
- [ ] The live demo is free, stable, signed-out, resettable, synthetic-only,
  and available without credentials through 2026-09-15 at 5:00 PM ET; the
  exact-head public-demo verifier has a preserved `PASS` receipt.
- [ ] A separate signed-out reviewer completes the complete three-act judge
  path on desktop and mobile at the final URL.
- [ ] The video is under three minutes, public on YouTube or Vimeo, shows the
  functioning project and CockroachDB memory layer, and matches the final
  application and claim state.
- [ ] Every visual, font, trademark, music track, voice, and other media item
  has a complete row in `docs/media/RIGHTS.md`; no third-party material is used
  without the required permission.
- [ ] The architecture diagram, screenshots, README, website, video, and
  submission use one reviewed visual system and the same verified vocabulary.
- [ ] `CLAIMS.md`, `CLEAN_ROOM.md`, the evidence matrix, dependency inventory,
  bundled third-party notices, `PROOF_MANIFEST.json`, and pre-existing-work
  disclosure receive a final exact-commit and deployed-bundle audit;
  `npm run proof:verify`, `npm run privacy:verify`,
  `npm run claims:verify`, `npm run dependencies:verify`, and
  `npm run licenses:verify` pass, and
  official `main` emits a
  `npm run release:provenance` `PASS` receipt.
- [ ] The Devpost preview contains no secrets, personal data, internal URLs,
  unsupported superlatives, operational-emergency implication, or unresolved
  stop token.
- [ ] Brian or the authorized entrant confirms eligibility, entrant identity,
  team or organization representation, Devpost registration, and final
  submission authority.
- [ ] A private preview is approved before the entry is made public.
- [ ] A final timestamped receipt records every submitted URL and field.

The TrustAgentic.ai homepage link is not part of this gate until the public
demo, repository, claims, rights, and release receipts are all green.

## Official requirement mapping

| Official requirement | Tideproof response | Current state |
| --- | --- | --- |
| New project built during the submission period | Clean-room repository, dated provenance, pre-existing-work disclosure, and exact-checkout history control | Verified; final freeze rerun pending |
| Agentic application with CockroachDB as persistent memory, deployed on AWS | CockroachDB stores evidence, vector memory, authority state, receipts, and recovery state; AWS hosts the bounded agent path | CockroachDB verified; live AWS pending |
| At least two meaningfully integrated CockroachDB tools | Distributed Vector Indexing and Managed MCP Server | Gate One verified |
| At least one meaningfully integrated AWS service | Final entry will name only services proven by live receipts | `[[LIVE_AWS_EVIDENCE_REQUIRED]]` |
| Public open-source repository with license and runnable source | Public MIT repository with Node.js setup and lockfile | Verified at public-source checkpoint; final commit pending |
| Functional demo URL | Free signed-out synthetic drill | `[[PUBLIC_DEMO_REQUIRED]]` |
| Text description | Reviewed copy blocks below | Drafted |
| Public video under three minutes | 175-second evidence-led demonstration | Script drafted; recording pending |
| Video shows the project and CockroachDB memory layer functioning | Browser drill plus recorded provider evidence, visibly distinguished | Pending |
| Identify CockroachDB tools and what the agent did | Exact tool copy below | Drafted from Gate One evidence |
| Identify AWS services and what they did | Exact tool copy must be generated from live receipts | Blocked by live AWS gate |
| Free unrestricted judging access through 2026-09-15 | Low-volume public environment, no login | Not deployed |
| Original work and authorized third-party material | Clean-room, privacy, and rights ledgers plus dependency, bundle-notice, full-history, and installed-tree controls | Automated technical controls current; final private, deployed-bundle, and rights audits pending |
| English submission materials | English copy, captions, and testing instructions | Planned |

## Internal evidence map

These are claim sources for copy review, not a substitute for the final public
demo:

| Submission claim | Controlling source |
| --- | --- |
| Distributed vector plan and admissibility order | `evidence/gate1-vector-2026-07-29.md` and `evidence/gate1-authority-2026-07-30.md` |
| 100 × 50 one-winner races and protected synthetic effect | `evidence/gate1-authority-2026-07-30.md` |
| 100 runs at each ambiguous-commit boundary | `evidence/gate1-ambiguity-2026-07-30.md` |
| Fixed-query context-only Managed MCP recovery | `evidence/gate1-recovery-broker-2026-07-30.md` |
| Public MIT source and hosted CI | `evidence/public-source-release-081b580-2026-07-30.md` |
| Claim limitations | `CLAIMS.md` |
| Live AWS services and behavior | `[[ACCEPTED_LIVE_AWS_RECEIPT_REQUIRED]]` |
| Overlapping AWS Lambda/CockroachDB authority race | `[[ACCEPTED_LIVE_AUTHORITY_RACE_RECEIPT_REQUIRED]]` |
| Visual, trademark, and media permission | `docs/media/RIGHTS.md`; `[[ALL_REQUIRED_ROWS_RELEASE_CLEARED]]` |

`PROOF_MANIFEST.json` is the machine-checked index for the current claims and
exact evidence bytes. Its `INCOMPLETE_LIVE_GATES_PENDING` status is a stop
state, not a publish authorization.

## One-sentence pitch

Tideproof is admissibility memory for high-stakes agents: CockroachDB preserves
evidence and spent authority so an agent can retrieve what is relevant without
mistaking what it remembers for what it is still allowed to believe or do.

## Short description

Most agent memory systems optimize recall. Tideproof governs admissibility.
Its synthetic Highwater Drill preserves attributable evidence, filters stale,
revoked, out-of-scope, and conflicting memory before semantic ranking, commits
exactly one winner for a scarce synthetic resource, and lets a replacement
agent recover context without inheriting already-spent authority.

CockroachDB is the system of record for evidence, vector search, transactional
authority, receipts, fencing, and audited recovery. Amazon Bedrock may propose
a bounded interpretation, but deterministic policy and CockroachDB decide.
The scenario is synthetic and does not claim production emergency suitability
or exactly-once real-world effects.

The second paragraph may be used only after the live AWS receipt proves the
final implementation. Until then, the submission remains blocked.

## Devpost story draft

### Inspiration

An agent can remember the most semantically similar report and still be wrong
to act on it. The report may be stale, revoked, outside the current incident,
contradicted by another trusted source, or tied to authority that another
agent already spent. That turns memory from a retrieval problem into a
distributed-systems and safety problem.

Tideproof explores a narrower question: what should an agent still be allowed
to believe and act upon after evidence, time, concurrency, failure, and agent
identity have changed?

### What it does

The synthetic Highwater Drill has three acts:

1. A responder receives fresh, stale, invalid-provenance, out-of-scope, and
   contradictory reports. SQL admissibility checks run before vector ranking,
   and unresolved trusted conflict fails closed.
2. Fifty contenders race for one synthetic resource. One serializable
   CockroachDB transaction commits one lease, one monotonic fence, one durable
   winning receipt, and one outbox intent; denials are durable too.
3. The winning process disappears. A successor recovers only sanitized,
   signed context through an audited fixed-query Managed MCP path, receives no
   authority, and cannot create a second effect by replaying the old
   operation.

The browser makes each state transition and its evidence visible. It labels
local deterministic replay separately from recorded cloud proof.

### How we built it

CockroachDB stores verified evidence, revocation and conflict state, vector
embeddings, resource leases, fencing tokens, operation receipts, checkpoints,
recovery bundles, and audit events.

Distributed Vector Indexing ranks only candidates that pass provenance,
valid-time, incident-scope, and conflict gates. Serializable transactions,
unique operation semantics, monotonic fencing, and a transactional outbox
make authority spending explicit and replay-safe inside the synthetic
database boundary.

The Managed MCP Server is reached through a deterministic recovery broker. It
commits a primary-cluster pre-read audit, performs one exact read-only query
against a physically separate recovery cluster, validates a fresh signed
context-only bundle, commits a result-bound terminal audit, and only then
releases context. Operation IDs, effect keys, and fences are never returned.

`[[FINAL_AWS_ARCHITECTURE_COPY_REQUIRED_FROM_LIVE_RECEIPT]]`

The final AWS paragraph must name only deployed services and behavior proven
by the exact release evidence. The local candidate currently separates ten
exact signed-out read-only demo routes and a logs-only Demo Lambda from
an IAM-authenticated advisory boundary, proposal-only Bedrock path, KMS signer,
and separately invoked two-concurrency authority Lambda. The authority
candidate derives all operation-bearing fields outside the model and calls
only least-privilege CockroachDB authorizer surfaces; its race verifier also
requires a later read-only durable-state proof before `PASS`. None of that is
yet a live-cloud or live-database claim.

### Challenges

The hardest failure was ambiguity around transaction commit: after a
connection loss, retrying blindly can spend authority twice. Tideproof
classifies the result as empty, complete, or unknown and refuses to invent
certainty. The proof exercises connection loss before commit, after commit is
dispatched, and after acknowledgement.

A second challenge was making recovery useful without turning “read-only
memory” into inherited operational capability. The recovery path therefore
binds identity, query shape, source cluster, freshness, signatures, source
watermark, and two audit phases before returning sanitized context.

### Accomplishments

- A named CockroachDB vector index appears in a real `vector search` plan only
  after admissibility predicates.
- One hundred live 50-contender races produced one authority winner each, with
  no invariant violation.
- One hundred live runs at each ambiguous-commit boundary produced no partial
  transaction and no blind replay.
- A machine-authenticated Managed MCP fixed-query recovery read returned
  signed context only after its pre-read and terminal audits committed.
- The public MIT repository has deterministic tests, exact dependency
  versions, bundle-derived third-party notices, claim boundaries, security
  guidance, and reproducible Gate Two artifacts.

Do not add AWS accomplishments until a live exact-commit receipt exists.

### What we learned

Semantic similarity is a proposal mechanism, not an authorization mechanism.
Persistent memory needs explicit provenance, time, scope, conflict, identity,
and authority semantics. Agent replacement also changes the trust boundary:
the successor may inherit evidence, but it should acquire fresh authority.

We also learned that read-only access is necessary but not sufficient. A
bounded recovery path needs exact query shape, result binding, source
freshness, audit ordering, and a clear statement of what operational
capabilities it refuses to return.

### What's next

`[[REPLACE_WITH_POST_RELEASE_ROADMAP_AFTER_FINAL_SCOPE_AUDIT]]`

Potential work must be framed as future work, not current capability:
provider-attested identities, durable publisher-key rotation, broader failure
injection, and independently reviewed production hardening. Tideproof will
remain a synthetic research demonstration unless those separate claims are
actually proved.

## CockroachDB tools — exact submission copy

### Distributed Vector Indexing

Tideproof stores embeddings beside structured evidence in CockroachDB. The
agent does not run nearest-neighbor search over everything it remembers.
Provenance, revocation, valid time, incident scope, and unresolved conflict are
checked first; the surviving candidates are then ranked through a named
CockroachDB distributed vector index. The Gate One receipt includes a real
plan containing `vector search` and the named index.

### CockroachDB Cloud Managed MCP Server

When an agent is replaced, a deterministic Tideproof broker performs one
machine-authenticated Managed MCP `select_query` against an isolated recovery
cluster. The exact cluster, database, tool, protocol version, and query
template are pinned. A primary-cluster pre-read audit must commit before MCP;
the signed result, freshness, tenant, session, principal, source watermark,
and digest are validated; then a terminal result-bound audit must commit
before context is released. The bundle contains no operation ID, effect key,
or fencing token, so the successor must acquire fresh authority.

## AWS services — blocked copy

Do not paste the local candidate into the Devpost “AWS services” field.
Generate this section from the accepted live receipt and include:

- the exact AWS services that were actually deployed;
- what request the agent sent to each service;
- the model ID and bounded proposal schema, if Bedrock was used;
- which deterministic component accepted or rejected the proposal;
- the API caller and route binding;
- the KMS key type and local signature-verification boundary;
- the least-privilege role separation and direct-invocation denials;
- the cost alarms, retention, and teardown boundary; and
- the exact release commit and artifact hashes.

`[[LIVE_AWS_SERVICE_COPY_REQUIRED]]`

## Judge testing instructions

### Public path

1. Open `[[PUBLIC_SIGNED_OUT_DEMO_URL_REQUIRED]]` in a signed-out browser.
2. Confirm the page says the scenario is synthetic.
3. Use **Next** or **Play** through all three acts; no login or credentials are
   required.
4. In Act One, inspect why stale, invalid-provenance, out-of-scope, and
   conflicting memory cannot authorize.
5. In Act Two, inspect the single winning lease, fence, receipt, and denial
   evidence.
6. In Act Three, inspect context-only successor recovery and replay denial.
7. Open the linked evidence details and confirm whether each item is a local
   replay or recorded provider proof.
8. Use **Restart** and verify the drill returns to its initial state without
   mutating shared evidence.

### Local fallback

Requires Node.js 22 or newer:

```sh
git clone https://github.com/Flash-Bri/tideproof.git
cd tideproof
npm ci
npm test
npm run demo
```

Open `http://127.0.0.1:4173`. No cloud credential is required for the local
synthetic replay. Live-gate scripts require separate project credentials and
are not part of judge setup.

## Optional CockroachDB feedback draft

CockroachDB's strongest fit for Tideproof was keeping semantic and
transactional memory in one consistency domain: the same system could filter
admissibility, rank vectors, spend authority serializably, fence stale
callers, and preserve durable receipts.

Managed MCP's read-only tool and auditability made a bounded recovery path
possible. The implementation also exposed a useful product opportunity:
provider-visible service-account scope, deterministic fixed-query profiles,
and result/source attestations would make noninteractive least-privilege MCP
brokers easier to prove without relying as heavily on application-side
pinning and physical cluster isolation.

This feedback must be reviewed against the final provider behavior before
submission.

## Final copy audit

Before Devpost submission, search this file and every public surface for:

- `[[` — unresolved stop tokens;
- `pending`, `planned`, `candidate`, or `local` where a live claim is implied;
- “exactly once” without the words `synthetic database boundary`;
- “truth”, “safe”, “production-ready”, “disaster-ready”, or “zero data loss”
  unless an exact accepted receipt supports the precise sentence;
- internal hostnames, account IDs, cluster credentials, console links, or
  private preview URLs; and
- third-party marks or media absent from the final rights ledger.

The submitted entry must remain accurate if a judge watches only the video or
reads only the Devpost page.
