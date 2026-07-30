# Gate One — Managed MCP

Date: 2026-07-29 ET / 2026-07-30 UTC  
Environment: CockroachDB Cloud Basic, AWS `us-east-1`  
Database: `tideproof`  
Fixture: `public.gate1_vector_evidence`, 10,000 rows

## Acceptance result

**PASS for Gate One machine access and read-only authority.**

- Codex authenticated to the CockroachDB Managed MCP endpoint with only the
  `mcp:read` OAuth scope.
- The connection is pinned to the Tideproof cluster with the MCP cluster
  header.
- A fresh ephemeral Codex process used Managed MCP to list the live databases
  and table, then returned a row count of exactly 10,000.
- Managed MCP `explain_query` returned a physical `vector search` plan using
  `gate1_vector_embedding_idx`, with target count 10 and the tenant, incident,
  and admitted prefix span.
- A controlled call to `insert_rows` reached CockroachDB and failed with:

  ```text
  insufficient permissions: write access required
  ```

- The attempted row was an exact duplicate of an existing primary-key row, so
  it could not have added durable state even if authorization had been
  misconfigured.
- A subsequent Managed MCP count remained exactly 10,000.

## Client-side defense in depth

The production Codex MCP configuration exposes only these tools:

```text
list_clusters
list_databases
list_tables
get_table_schema
show_statement
select_query
explain_query
show_running_queries
```

The following mutation tools are explicitly denied:

```text
create_database
create_table
insert_rows
```

OAuth credentials use the operating-system credential store. The cluster
header is present in configuration, while the database password, connection
URL, and OAuth tokens are not stored in this repository.

## Read evidence

```text
databases: defaultdb, tideproof
table: public.gate1_vector_evidence
row_count: 10000
plan operator: vector search
index: gate1_vector_embedding_idx
target count: 10
prefix: tenant / incident / admitted
```

## Scope boundary

This receipt proves meaningful Managed MCP access and two independent read-only
controls:

1. CockroachDB rejects writes for the OAuth identity.
2. Codex does not expose mutation tools in the normal Tideproof MCP profile.

It does **not** yet prove the complete successor-recovery claim. The full build
must add a recovery-only SQL surface, exact query templates or digests,
immutable recovery audit receipts, and a test showing that a replacement agent
can recover admissible context while remaining unable to spend or recreate
authority.

`select_query` is intentionally treated as a high-sensitivity read capability:
the final demo path must not give an untrusted agent unrestricted access to
arbitrary application tables.
