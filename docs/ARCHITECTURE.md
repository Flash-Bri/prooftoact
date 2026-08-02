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
Signed-out GET requests
        |
        +--> API Gateway --> Demo Lambda
        |                     bundled deterministic replay only
        |                     logs only; no model, signer, secret,
        |                     database, MCP, or authority capability
        |
IAM-signed POST /advisory
        |
        +--> API Gateway --> Boundary Lambda
                              | exact request/caller binding
                              +--> Agent Lambda --> Amazon Nova Micro
                              |                  proposal only
                              +--> Signer Lambda --> KMS P-256
                              |                   signed advisory receipt

Private authority-race proof caller
        |
        +-- concurrent reserve x2 --> Authority Lambda
        |                              | exact race + contender schema
        |                              | derives operation/effect IDs itself
        |                              | reads one exact project secret
        |                              v
        |                         CockroachDB
        |                         tp_api.g1_spend_authority_v1
        |
        +-- after both return: proof --> Authority Lambda
                                       | one read-only transaction
                                       v
                                  CockroachDB
                                  tp_api.g1_observe_authority_race_v1
                                  2 receipts · 1 outbox · 0 effects
```

Gate Two currently uses one Gate One digest-bound synthetic fixture. It proves
the intended software and IAM shape locally, not live AWS hosting or a live
CockroachDB-to-AWS handoff. The signed-out route set is read-only and
enumerated; it never connects to the advisory integration. The boundary
independently validates the model proposal and signer envelope, verifies the
P-256 signature locally, and rejects direct or authority-bearing output.
The authority proof path is separately invokable only through its exact numeric
version; its monitored alias is not invocation authority, and the advisory
Boundary does not call it. Its local candidate accepts
only two named contenders for one configured synthetic race, derives every
operation-bearing field without model input, reads only one exact
Tideproof-owned Secrets Manager ARN, and calls only the CockroachDB
authorizer's typed `SECURITY DEFINER` functions. None of those cloud or
database boundaries are proven live until the accepted race receipt includes
the later durable-state observation and its private database evidence.

## Target contest architecture

```text
Signed-out judge browser --> API Gateway --> read-only Demo Lambda

Authenticated agent request --> API Gateway --> agent orchestrator
                                            |
                                            +--> Amazon Bedrock
                                            |    proposal only
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
