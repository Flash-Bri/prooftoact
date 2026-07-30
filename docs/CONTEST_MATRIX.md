# Contest conformance matrix

Checked against the official competition pages on 2026-07-29:

- https://cockroachdb-ai.devpost.com/
- https://cockroachdb-ai.devpost.com/rules
- https://cockroachdb-ai.devpost.com/resources

Deadline: 2026-08-18 at 5:00 PM ET.

## Requirements

| Requirement | Planned proof | Current status |
| --- | --- | --- |
| New project during submission period | Clean-room repository and provenance receipts | Verified locally; private |
| Agentic memory application | Evidence memory controls retrieval and action authority | Gate One verified, synthetic scope |
| At least two named CockroachDB tools | Distributed Vector Index + meaningful Managed MCP recovery/audit path | Gate One verified |
| At least one AWS service | Lambda/API Gateway, KMS, and bounded Bedrock use | Local candidate passed; live deployment pending |
| Functional AWS-hosted demo | Judge-accessible synthetic scenario | Not deployed |
| Public open-source repository and license | MIT-licensed repository with reproducible setup | Local/private only |
| Public video under three minutes | 175-second evidence-led demonstration | Script drafted |
| Free judge access through judging | Budgeted low-volume environment through 2026-09-15 | Not provisioned |
| Pre-existing work disclosed | Clean-room statement and dependency inventory | Maintained; final audit pending |

## Judging alignment

The five published criteria are equally weighted. Agentic Memory Design is
also the first tie-breaker.

- **Agentic Memory Design:** memory preserves evidence, uncertainty, revocation,
  conflicts, scope, and spent authority instead of storing unqualified facts.
- **Technological Implementation:** the final proof must show a real
  serializable CockroachDB race, SQL-before-vector filtering, a meaningful
  second Cockroach tool, AWS runtime evidence, and reproducible tests. Gate
  One is accepted; live AWS evidence remains pending.
- **Real-World Impact:** the synthetic response scenario makes stale or
  contradictory shared memory legible without claiming operational readiness.
- **Product Readiness:** one-command fixtures, judge-safe reset, cost alarms,
  observability, accessibility, threat model, and teardown plan.
- **Creativity and Originality:** the core demonstration is admissibility,
  authority transfer, and replay denial—not another RAG assistant.

## Fail gates

The project pauses if any of these remain unresolved:

1. Managed MCP cannot be made a meaningful, bounded part of the recovery path
   and no legitimate second named Cockroach tool replaces it.
2. A real CockroachDB transaction does not preserve the one-winner invariant
   under concurrency and injected failures.
3. The cloud build needs a NAT Gateway, always-on compute, unbounded model
   loop, or spending beyond the approved cap.
4. The build would reuse proprietary work or slow Conversate/Northstar/XPRIZE
   operations.
5. The three-minute demonstration cannot prove the differentiator visibly.
