# Demonstration script — target 175 seconds

The visual language stays calm and technical. A persistent label reads:
“Synthetic scenario — not operational emergency software.”

- **0–12 seconds:** A responder agent receives shared memory. Explain that
  retrieved memory is evidence, not truth.
- **12–27:** Show the compact architecture: AWS agent runtime, CockroachDB
  evidence memory and vector index, deterministic authorization.
- **27–50:** Ingest fresh, stale, invalid-provenance, and out-of-scope reports.
  Show the exclusions before similarity ranking.
- **50–68:** Show two current but contradictory road reports. Retrieval
  preserves both; action authorization fails closed.
- **68–96:** Two agents concurrently request the last synthetic rescue unit.
  Freeze on the transaction boundary.
- **96–116:** Show exactly one committed lease and its fencing token and
  receipt in CockroachDB.
- **116–134:** Terminate the winning agent after its checkpoint.
- **134–155:** A successor reconstructs evidence, receipt, and lease state
  through the bounded recovery path, but receives no inherited authority.
- **155–166:** Replay the original operation ID. The external action is not
  repeated; the original receipt is returned as the reason.
- **166–175:** Show named CockroachDB/AWS integrations, public repository,
  tests, cost controls, synthetic-data disclosure, and live link.

No narration should claim truth detection, exactly-once external effects,
regional survival, disaster readiness, or production safety unless the final
build independently proves the precise claim.
