# Tideproof claims ledger

Every public claim must remain **unverified** until the listed artifact exists
and its acceptance condition passes. Synthetic scenarios are always labeled
synthetic and non-operational.

| Claim | Current status | Required artifact | Acceptance condition |
| --- | --- | --- | --- |
| CockroachDB Distributed Vector Indexing retrieves eligible memory candidates. | Gate One verified | [`evidence/gate1-vector-2026-07-29.md`](evidence/gate1-vector-2026-07-29.md) | A real CockroachDB 26.2 Cloud plan contains `vector search` and the named vector index. |
| CockroachDB Managed MCP can inspect sanitized recovery state without transferring operational authority. | Gate One verified, synthetic scope | [`evidence/gate1-recovery-broker-2026-07-30.md`](evidence/gate1-recovery-broker-2026-07-30.md) | A durable pre-read event precedes one machine Managed MCP fixed-query read; signature, freshness, tenant/session/principal, result digest, and source watermark validate; the terminal audit commits before context release; no operation ID, effect key, or fence is returned. |
| SQL admissibility precedes semantic ranking and authority. | Gate One verified, synthetic scope | [`evidence/gate1-authority-2026-07-30.md`](evidence/gate1-authority-2026-07-30.md) | Signed provenance, validity, scope, and conflict checks deny authority without changing the fence or creating an outbox; vector-plan evidence remains separately verified. |
| Concurrent contenders produce one authority winner. | Gate One verified, 100 × 50 live races | [`evidence/gate1-authority-2026-07-30.md`](evidence/gate1-authority-2026-07-30.md) | Exactly one lease, winning receipt, fence increment, and outbox intent commit for every race; all 49 denials remain durable and sticky. |
| Process death around COMMIT never triggers blind replay in the synthetic authority gate. | Gate One verified, 100 runs per boundary | [`evidence/gate1-ambiguity-2026-07-30.md`](evidence/gate1-ambiguity-2026-07-30.md) | Before-COMMIT, COMMIT-dispatched, and acknowledged-COMMIT boundaries produce only empty, complete, or fail-closed unknown state; no partial transaction or blind retry occurs. |
| A successor recovers context without inheriting authority. | Gate One verified, synthetic broker | [`evidence/gate1-recovery-broker-2026-07-30.md`](evidence/gate1-recovery-broker-2026-07-30.md) | Recovery exposes only signed, fresh, sanitized context; an unbound principal never reaches MCP; authority must be freshly acquired through a separate capability. |
| Stale fencing tokens cannot produce a protected synthetic effect. | Gate One verified, database sink only | [`evidence/gate1-authority-2026-07-30.md`](evidence/gate1-authority-2026-07-30.md) | Stale, future, expired, wrong-actor, wrong-tenant, wrong-incident, wrong-resource, and wrong-run requests are rejected atomically; the current token records one row under 50-way replay. |
| Tideproof fails closed when its memory or recovery path is unavailable. | Local broker behavior verified; deployed outage proof pending | Database and MCP outage receipts | State remains `UNKNOWN_DO_NOT_ACT`; no context is released without committed pre-read and terminal audit events; no authorization bypass exists. |

The repository does not claim invention of provenance-aware memory, temporal
memory, fencing, replay protection, or exactly-once real-world effects.
