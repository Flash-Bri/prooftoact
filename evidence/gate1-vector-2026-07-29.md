# Gate One — Distributed Vector Index

Date: 2026-07-29 ET / 2026-07-30 UTC  
Environment: CockroachDB Cloud Basic, AWS `us-east-1`  
Database version: CockroachDB CCL v26.2.1  
Fixture: 10,000 deterministic three-dimensional embeddings  
Index: `gate1_vector_embedding_idx`

## Acceptance result

**PASS**

- The isolated fixture contained exactly 10,000 rows.
- `SHOW INDEXES` returned the named vector index.
- The physical `EXPLAIN (VERBOSE)` plan contained `vector search`.
- The vector-search operator named `gate1_vector_embedding_idx`.
- The operator used equality prefix spans for tenant, incident, and the
  materialized admissibility flag.
- The target nearest-neighbor count was five.

## Physical plan

```text
distribution: local
vectorized: true

• project
│ columns: (evidence_id, ordinal)
│
└── • top-k
    │ columns: (column11, evidence_id, ordinal)
    │ estimated row count: 5
    │ order: +column11
    │ k: 5
    │
    └── • render
        │ columns: (column11, evidence_id, ordinal)
        │ render column11: embedding <=> '[0.49448344,0.7840565,0.08036623]'
        │ render evidence_id: evidence_id
        │ render ordinal: ordinal
        │
        └── • lookup join (inner)
            │ columns: (tenant_id, incident_id, evidence_id, ordinal, admitted, embedding)
            │ table: gate1_vector_evidence@gate1_vector_evidence_pkey
            │ equality: (tenant_id, incident_id, evidence_id) = (tenant_id, incident_id, evidence_id)
            │ equality cols are key
            │ parallel
            │
            └── • vector search
                  columns: (tenant_id, incident_id, evidence_id)
                  table: gate1_vector_evidence@gate1_vector_embedding_idx
                  target count: 5
                  prefix spans: tenant / incident / admitted
                  query vector: '[0.49448344,0.7840565,0.08036623]'
```

## Failed first attempt and correction

The first physical plan used a primary-key scan because the query filtered on
`admitted = true` while the vector index prefix contained only tenant and
incident. Tideproof treated this as a failed gate. The index was corrected to:

```sql
CREATE VECTOR INDEX gate1_vector_embedding_idx
ON gate1_vector_evidence
  (tenant_id, incident_id, admitted, embedding vector_cosine_ops);
```

The rerun passed. This correction is part of the design evidence: an
eligibility predicate that is expected to precede semantic ranking must be
represented in the indexable admissibility boundary rather than added as an
unplanned post-filter.

## Reproduction

```sh
DATABASE_URL="<credential-store value>" npm run gate1:vector
```

The live connection URL and password are not written to the repository.

