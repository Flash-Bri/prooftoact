# Release cost control

Status: **CURRENT COST GUARDS PASS — LIVE SPEND AND FINAL REVIEW PENDING**

This control binds Tideproof's current source, budget prerequisites, recorded
non-AWS spend, and deployment stop conditions. A
`CURRENT_COST_GUARDS_PASS` receipt is a current-source result only. It does
not assert current AWS spend, authorize an upload or deployment, validate a
registrar receipt, or approve publication or submission.

## Fixed limits

- Approved AWS budget notification boundary: **$15.00 USD monthly**.
- Recorded non-AWS spend: **$11.86 USD** for the owner-authorized
  `tideproof.net` registration.
- Approved total Tideproof exposure: **$25.00 USD**.
- Effective AWS spend ceiling: **$13.14 USD**, reduced dollar for dollar by
  any later non-AWS Tideproof expense.
- Expected metered contest-period spend: **$3–$12 USD** through
  2026-09-15.
- Stop new cloud work if daily cost exceeds **$5 USD** or unexplained spend
  exceeds **$3 USD**.
- Cost Explorer is accumulated account-wide from **2026-07-01** through the
  current UTC day. It does not reset at a month boundary for this gate.

The `$15` AWS Budget is an alert boundary, not a hard service cap and not the
effective remaining project envelope. The read-only preflight must reject
budget-reported, Cost Explorer, or conservative observed AWS spend at or
above `$13.14`, and it must reject total conservative exposure at or above
`$25.00`.

## Required alert and architecture bounds

The prerequisite bootstrap must expose one account-wide monthly unblended
cost budget with absolute-dollar `GREATER_THAN` alerts at `$1`, `$5`, and
`$10` actual spend and `$15` forecast spend. The artifact bucket depends on
that budget, retains replacement/deletion state, and expires noncurrent
artifact versions after 45 days.

The reviewed Gate Two template uses only bounded Lambda memory, timeouts, and
reserved concurrency, seven-day log retention, a throttled HTTP API, and one
project-owned Secrets Manager credential. It also creates two no-action
semantic-failure alarms and can publish at most two stack/service custom
metric series when the boundary or authority fails closed. Their exact live
regional price remains part of the final price recheck; the current `$3–$12`
forecast retains contingency for them. It contains no NAT Gateway,
always-on EC2 or ECS service, load balancer, or RDS instance. Adding any such
resource, provisioned capacity, another paid domain, a renewal or auto-renew
change, a paid DNS/hosting add-on, or other unnecessary persistent
infrastructure requires fresh approval.

## Current evidence boundary

The sanitized budget receipt records the prerequisite budget and four alerts
and explicitly makes no current-spend claim. The console stop receipt records
`DataUnavailableException`, blocked CloudShell creation, an absent main
stack, and `UNKNOWN_DO_NOT_ACT`. The domain record is owner-reported input;
the registrar receipt and renewal-state export have not been independently
inspected.

Therefore AWS preflight remains `NOT_RUN` for release purposes. No artifact
upload, change set, main-stack deployment, DNS change, domain purchase,
renewal, or submission action is authorized by this control.

## Final release requirements

1. Run the exact clean official checkout in an authenticated AWS lane and
   retain a machine-verifiable preflight `PASS` receipt showing current
   account-wide spend below `$13.14` and the main stack absent.
2. Recheck exact-release AWS, CockroachDB, Bedrock, Secrets Manager, DNS, and
   logging price assumptions and bind the conservative forecast to the final
   architecture and deployed hashes.
3. Privately inspect the registrar receipt and a dated auto-renew-off export
   while protecting personal and payment data; keep public evidence
   sanitized.
4. After the judged keep-alive window, bind the final complete spend ledger
   and teardown or explicitly approved keep-alive receipt to the release.
