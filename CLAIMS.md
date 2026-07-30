# Tideproof claims ledger

Every public claim must remain **unverified** until the listed artifact exists
and its acceptance condition passes. Synthetic scenarios are always labeled
synthetic and non-operational.

| Claim | Current status | Required artifact | Acceptance condition |
| --- | --- | --- | --- |
| CockroachDB Distributed Vector Indexing retrieves eligible memory candidates. | Gate One verified | [`evidence/gate1-vector-2026-07-29.md`](evidence/gate1-vector-2026-07-29.md) | A real CockroachDB 26.2 Cloud plan contains `vector search` and the named vector index. |
| CockroachDB Managed MCP can inspect live Tideproof state without write authority. | Gate One verified | [`evidence/gate1-managed-mcp-2026-07-29.md`](evidence/gate1-managed-mcp-2026-07-29.md) | An OAuth `mcp:read` session reads the fixture and vector plan; a controlled write probe is denied by CockroachDB and the client exposes only allowlisted read tools. |
| SQL admissibility precedes semantic ranking. | Local behavior only | Cloud integration test and query receipt | Tenant, incident, provenance, validity, scope, and conflict predicates are enforced before ranking. |
| Concurrent contenders produce one authority winner. | Unverified | Independent-connection barrier test | Exactly one lease, receipt, fence, and outbox intent commit for every race. |
| Ambiguous commits never trigger blind replay. | Unverified | Before/after-commit failure-injection receipts | Unknown outcomes resolve by request digest; no duplicate intent or effect occurs. |
| A successor recovers context without inheriting authority. | Local behavior only | Read-only Managed MCP recovery transcript | Recovery exposes admissible context and committed receipts but cannot spend or recreate authority. |
| Stale fencing tokens cannot produce protected effects. | Unverified | Delayed-old-holder integration test | An effect carrying a token below the current committed fence is rejected. |
| Tideproof fails closed when its memory or recovery path is unavailable. | Local behavior only | Database and MCP outage tests | State remains `UNKNOWN / DO NOT ACT`; no SQL or authorization bypass exists. |

The repository does not claim invention of provenance-aware memory, temporal
memory, fencing, replay protection, or exactly-once real-world effects.
