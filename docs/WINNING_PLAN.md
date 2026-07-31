# Winning plan

## Submission concept

**Tideproof — Admissibility Memory for High-Stakes Agents**

Tideproof uses a synthetic multi-agency “Highwater Drill” to prove that
autonomous agents can coordinate a scarce resource without trusting shared
memory blindly. Tideproof preserves attributable evidence, admits only what is
current, scoped, and authorized, resolves one contested resource
transactionally, lets a successor recover durable context, and rejects replay.

## Why this can stand out

The crowded category is an assistant with embeddings, chat history, or a
generic “memory” label. Tideproof makes four less common memory failures
visible in one short story:

1. a highly similar report can still be stale or forged;
2. contradictory memory should survive retrieval without silently becoming
   actionable truth;
3. shared memory carries authority and therefore must prevent double spend;
4. a successor needs context but must not inherit already-spent authority.

## Work stages

### Gate 0 — local invariant proof

- deterministic fixtures and three-act browser proof;
- provenance, validity, scope, conflict, race, recovery, and replay tests;
- clean-room, claim, cost, and teardown boundaries.

### Gate 1 — CockroachDB feasibility

- create the minimal schema and migrations;
- implement SQL admissibility predicates before vector ranking;
- prove one winner with real serializable transactions and retries;
- inject connection loss at every transaction transition;
- prove a meaningful Managed MCP recovery/audit path;
- stop if two named CockroachDB tools are not technically central.

### Gate 2 — AWS agent path

- deploy a bounded Lambda/API Gateway runtime;
- use Bedrock only to interpret a synthetic request or summarize admitted
  evidence;
- invoke two isolated Authority Lambda contenders against the least-privilege
  CockroachDB authorizer and require overlapping database intervals with one
  serializable winner;
- keep every decision gate deterministic and server-side;
- add quotas, alarms, structured receipts, and fail-closed outage behavior.

### Gate 3 — product proof

- build the three-act judge interface, evidence drill-down, and safe reset;
- run accessibility, browser, security, abuse, and concurrency checks;
- capture real database and AWS evidence;
- implement the canonical `VISUAL_RELEASE_SYSTEM.md` across the product,
  README, video, icons, and submission without weakening proof readability;
- complete a dependency/license/provenance audit.

### Gate 4 — submission

- publish only after brand, legal, secret, and claim review;
- record a human-paced video under three minutes;
- require a complete visual-rights ledger and explicit private-review and
  publish-readiness receipts;
- verify unrestricted judge access in a signed-out browser;
- add the restrained TrustAgentic.ai launch link only after Tideproof's public
  destination and repository are exact and every release gate is green;
- freeze the evidence matrix and submit at least 48 hours before deadline.

## Internal odds

These are planning estimates, not statistical forecasts:

- concept or checkbox implementation: first place roughly 1–5%;
- polished but imperfect implementation: podium roughly 12–25%, first 4–10%;
- exceptional proof with real failure injection, meaningful MCP, excellent
  pacing, and no claim gaps: podium roughly 20–35%, first 7–15%.

The winning strategy is to maximize demonstrable proof, not feature count.
