# Architecture

## Product claim

Highwater demonstrates that an agent can retrieve useful memory without
treating retrieval as authority. The BlackBox protocol separates four steps:

1. Preserve evidence and its provenance.
2. Filter by validity, scope, and unresolved conflict.
3. Rank the remaining evidence for relevance.
4. authorize a bounded operation transactionally and issue a replay-safe
   receipt.

The model may propose; deterministic policy and the database decide.

## Local proof

```text
Synthetic event stream
        |
        v
BlackBoxMemory
  - provenance and time gates
  - scope gate
  - conflict gate
  - vector adapter (in memory)
  - resource lease + fencing token
  - operation receipt
  - agent checkpoint
        |
        +--> deterministic scenario JSON
        |
        +--> local timeline UI
```

The in-memory implementation is a behavioral specification. Its one-process
race result is not evidence of distributed correctness.

## Target contest architecture

```text
Static web demonstration
        |
        v
Amazon API Gateway
        |
        v
AWS Lambda agent orchestrator ----> Amazon Bedrock
        |                              proposal only
        |
        v
CockroachDB
  - append-only evidence and receipts
  - SQL admissibility predicates
  - Distributed Vector Index
  - SERIALIZABLE reservation transaction
  - fencing token and unique operation key
        |
        v
Managed MCP recovery/audit agent
```

The Managed MCP path must do real work visible in the demonstration—ideally
recovering the successor's incident context and verifying the committed
receipt. If that is not feasible or safe, the team must either implement a
meaningful CockroachDB Agent Skill as the second named tool or stop the entry;
checkbox integration is not acceptable.

## Minimal data model

- `evidence`: immutable claim, issuer, provenance verdict, valid time, scope,
  confidence, embedding, and conflict key/value.
- `resource_leases`: incident/resource key, current holder, expiry, and
  monotonic fencing token.
- `operation_receipts`: unique operation ID, decision, evidence IDs, holder,
  resource, and outcome.
- `agent_checkpoints`: agent/incident state pointer and last observed evidence.

## Safety boundaries

- Synthetic data only.
- No arbitrary public SQL, MCP prompt, or model-selected query.
- Least-privilege database and AWS identities.
- Deterministic checks run before any proposed action.
- Database unavailable means authorization unavailable.
- AWS/model unavailable means no new action; the interruption is recorded.
- Successor agents reconstruct context but do not inherit spent authority.
