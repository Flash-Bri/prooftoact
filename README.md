# Tideproof

**Working title. Private, local clean-room build. Not yet a contest submission.**

Tideproof is an admissibility-memory demonstration for high-stakes agents.
Its “Highwater Drill” is a synthetic multi-agency response exercise: shared
memory preserves attributable evidence, filters what is no longer admissible,
exposes conflicts, gives exactly one local contender a scarce resource, lets a
successor reconstruct prior state, and refuses to replay an operation.

The thesis is deliberately narrower than “AI remembers better”:

> Most memory systems optimize what an agent should remember. Tideproof governs
> what an agent is still allowed to believe and act upon.

## What exists now

This repository currently contains a deterministic local vertical slice:

- provenance, validity-window, and scope checks before vector ranking;
- unresolved-conflict detection and fail-closed authorization;
- one-winner resource reservation with monotonic fencing tokens;
- durable-shaped receipts, checkpoints, successor recovery, and replay denial;
- an intentionally in-memory vector adapter and local browser demonstration;
- tests for every claim above.

It does **not** yet contain or claim:

- a CockroachDB deployment or distributed transaction proof;
- CockroachDB Managed MCP or Distributed Vector Index integration;
- AWS deployment or Bedrock model use;
- exactly-once external effects, regional survival, or disaster readiness;
- production security, availability, or suitability for real emergencies.

Those are explicit build gates, not implied capabilities.

## Run locally

Requires Node.js 22 or newer. There are no package dependencies and no
credentials are needed.

```sh
npm test
npm run demo
npm run dev
```

Then open `http://127.0.0.1:4173`. The scenario and all identities are
synthetic.

## Contest target

The intended entry is for CockroachDB × AWS “Build with Agentic Memory.”
The target implementation will use:

1. CockroachDB Distributed Vector Indexing for relevance ranking after
   admissibility filters;
2. CockroachDB Managed MCP as a meaningful recovery/audit path, subject to an
   early feasibility gate;
3. AWS Lambda/API Gateway and Amazon Bedrock for a bounded agent runtime.

See `docs/CONTEST_MATRIX.md`, `docs/ARCHITECTURE.md`,
`docs/PRIOR_ART.md`, and `docs/WINNING_PLAN.md`.

## Safety and provenance

Tideproof is a synthetic demonstration, not operational emergency software.
No Conversate source, proprietary Northstar engine, private customer data, or
OpenClaw OAuth credential may enter this project. See `CLEAN_ROOM.md`.
