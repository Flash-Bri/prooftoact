# Architecture

## Product claim

Tideproof demonstrates that an agent can retrieve useful memory without
treating retrieval as authority. Its admissibility-memory protocol separates
four steps:

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
TideproofMemory
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
        +--> local three-act judge UI
```

The in-memory implementation is a behavioral specification. Distributed
correctness is supported separately by the accepted CockroachDB Gate One
evidence; the local model alone is not that evidence.

## Accepted CockroachDB Gate One

```text
Primary CockroachDB cluster
  - verified evidence + revocation/conflict state
  - SQL admissibility before Distributed Vector Index ranking
  - SERIALIZABLE authority transaction + monotonic fence
  - durable winner/denial receipts + transactional outbox
  - protected synthetic database effect
        |
        +--> sanitized signed recovery bundles
                 |
                 v
Separate recovery cluster --> fixed-query Managed MCP broker
                                context only; no authority transfer
```

## Local AWS Gate Two candidate

```text
IAM-signed HTTP request
        |
        v
API Gateway --> Boundary Lambda
                  | exact request/caller binding
                  +--> Agent Lambda --> Amazon Nova Micro
                  |                  proposal only
                  +--> Signer Lambda --> KMS P-256
                  |                   signed advisory receipt
                  X--> Authority Lambda (isolated fail-closed placeholder)
```

Gate Two currently uses one Gate One digest-bound synthetic fixture. It proves
the intended software and IAM shape locally, not a live CockroachDB-to-AWS
handoff. The boundary independently validates the model proposal and signer
envelope, verifies the P-256 signature locally, and rejects direct or
authority-bearing output.

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

The Managed MCP path already performs one fixed-query, context-only recovery
read through a deterministic broker. The final integration must replace the
Gate Two fixture with a freshly validated recovery bundle and route any
proposed operation through the real CockroachDB authorizer. Bedrock must never
receive or mint operation IDs, fences, effect keys, or database credentials.

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
