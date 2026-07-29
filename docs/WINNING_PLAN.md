# Winning plan

## Submission concept

**Highwater — a BlackBox Evidence Memory Protocol demonstration**

Highwater is a synthetic multi-agency response exercise proving that
autonomous agents can coordinate a scarce resource without trusting shared
memory blindly. BlackBox preserves attributable evidence, admits only what is
current, scoped, and authorized, resolves one contested resource
transactionally, lets a successor recover durable context, and rejects replay.

## Why this can stand out

The crowded category is an assistant with embeddings, chat history, or a
generic “memory” label. Highwater makes four less common memory failures
visible in one short story:

1. a highly similar report can still be stale or forged;
2. contradictory memory should survive retrieval without silently becoming
   actionable truth;
3. shared memory carries authority and therefore must prevent double spend;
4. a successor needs context but must not inherit already-spent authority.

## Work stages

### Gate 0 — local invariant proof

- deterministic fixtures and browser timeline;
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
- keep every decision gate deterministic and server-side;
- add quotas, alarms, structured receipts, and fail-closed outage behavior.

### Gate 3 — product proof

- build the single-timeline interface and judge-safe reset;
- run accessibility, browser, security, abuse, and concurrency checks;
- capture real database and AWS evidence;
- complete a dependency/license/provenance audit.

### Gate 4 — submission

- publish only after brand, legal, secret, and claim review;
- record a human-paced video under three minutes;
- verify unrestricted judge access in a signed-out browser;
- freeze the evidence matrix and submit at least 48 hours before deadline.

## Internal odds

These are planning estimates, not statistical forecasts:

- concept or checkbox implementation: first place roughly 1–5%;
- polished but imperfect implementation: podium roughly 12–25%, first 4–10%;
- exceptional proof with real failure injection, meaningful MCP, excellent
  pacing, and no claim gaps: podium roughly 20–35%, first 7–15%.

The winning strategy is to maximize demonstrable proof, not feature count.
