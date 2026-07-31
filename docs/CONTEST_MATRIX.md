# Contest conformance matrix

Checked against the official competition pages on 2026-07-30:

- https://cockroachdb-ai.devpost.com/
- https://cockroachdb-ai.devpost.com/rules
- https://cockroachdb-ai.devpost.com/resources

Deadline: 2026-08-18 at 5:00 PM ET.
Internal submission target: 2026-08-16 at 5:00 PM ET.

## Requirements

| Requirement | Planned proof | Current status |
| --- | --- | --- |
| New project during submission period | Clean-room repository and provenance receipts | Verified; public source and automated exact-checkout history control |
| Agentic memory application | Evidence memory controls retrieval and action authority | Gate One verified, synthetic scope |
| At least two named CockroachDB tools | Distributed Vector Index + meaningful Managed MCP recovery/audit path | Gate One verified |
| At least one AWS service | Lambda/API Gateway, KMS, bounded Bedrock use, and an isolated Lambda-to-CockroachDB authority race with a later durable-state proof | Local candidates passed; live deployment and race pending |
| Functional AWS-hosted demo | Ten exact signed-out API Gateway `GET` routes to a logs-only Demo Lambda serving the deterministic scenario | Local candidate passed; not deployed |
| Public open-source repository and license | MIT-licensed repository with reproducible setup | Public source and hosted CI verified |
| Public video under three minutes | 175-second evidence-led demonstration | Script drafted |
| English text description and testing instructions | Fail-closed submission packet with reviewed copy blocks | Drafted; final URLs and AWS copy blocked |
| Free judge access through judging | Budgeted low-volume environment through 2026-09-15 | Not provisioned |
| Pre-existing work disclosed | Clean-room statement, dependency inventory, bundle-derived third-party notices, and full-history/installed-tree audit | Automated control current; final freeze and deployed-bundle audit pending |

The canonical field copy and no-submit gates live in
`docs/SUBMISSION_PACKET.md`.

On official `main`, `npm run release:provenance` rejects shallow or replaced
history, legacy grafts or alternate object databases, an unexpected clean-room
root, tracked symlinks or submodules, Git object-integrity failure, lock/install
identity drift, and stale dependency or bundle-notice inventories. Its receipt
is a technical provenance control, not independent originality or
legal-clearance evidence, and must be rerun at the final source and
deployed-bundle freeze.

## Judging alignment

The five published criteria are equally weighted. Agentic Memory Design is
also the first tie-breaker.

- **Agentic Memory Design:** memory preserves evidence, uncertainty, revocation,
  conflicts, scope, and spent authority instead of storing unqualified facts.
- **Technological Implementation:** the final proof must show a real
  serializable CockroachDB race, SQL-before-vector filtering, a meaningful
  second Cockroach tool, a genuinely overlapping AWS Lambda-to-CockroachDB
  authority race, a later CockroachDB receipt/outbox/fence/effect
  reconciliation, AWS runtime evidence, and reproducible tests. Gate One and
  the local Gate Two candidate are accepted; live AWS evidence remains pending.
- **Real-World Impact:** the synthetic response scenario makes stale or
  contradictory shared memory legible without claiming operational readiness.
- **Product Readiness:** one-command fixtures, judge-safe reset, cost alarms,
  observability, enumerated signed-out routes, accessibility, threat model,
  and teardown plan.
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
