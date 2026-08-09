# Release cost control

Status: **CURRENT COST GUARDS PASS — LIVE SPEND AND FINAL REVIEW PENDING**

This control binds ProofToAct's current source, budget prerequisites, recorded
non-AWS spend, and deployment stop conditions. A
`CURRENT_COST_GUARDS_PASS` receipt is a current-source result only. It does
not assert current AWS spend, authorize an upload or deployment, validate a
registrar receipt, or approve publication or submission.

## Fixed limits

- Approved AWS budget notification boundary: **$15.00 USD monthly**.
- Recorded non-AWS spend: **$11.86 USD** for the owner-authorized
  `tideproof.net` registration.
- Approved total ProofToAct exposure: **$25.00 USD**.
- Effective AWS spend ceiling: **$13.14 USD**, reduced dollar for dollar by
  any later non-AWS ProofToAct expense.
- Expected metered contest-period spend: **$3–$12 USD** through
  2026-09-15.
- Stop new cloud work if daily cost exceeds **$5 USD** or unexplained spend
  exceeds **$3 USD**.
- Cost Explorer is accumulated account-wide from **2026-07-01** through the
  current UTC day. It does not reset at a month boundary for this gate.

The `$15` AWS Budget is an alert boundary, not a hard service cap and not the
effective remaining project envelope. The read-only preflight must reject
budget-reported, Cost Explorer, or conservative observed AWS spend unless the
greater observation plus the full `$0.02` approved preflight allowance remains
strictly below `$13.14`. It must also require `$11.86 + observed AWS + $0.02`
to remain strictly below `$25.00`. Thus an observation at exactly `$13.12`
cannot produce a preflight `PASS`, and no subsequent provider action may
proceed; arithmetic is conservative to the micro-dollar. The Cost Explorer
read used to obtain that observation may itself already have occurred under
the separate price recheck and maximum `$0.02` run authorization.

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

Blocked CloudShell creation remains historical stop evidence, but CloudShell is
not itself a cost or release requirement. The source-only lane in
`docs/AWS_OIDC_PREFLIGHT.md` provides a separately protected read-only route to
the same account-safety gate. It preserves the exact account digest,
900-second temporary role session, non-root runner, `us-east-1`, one-request
Cost Explorer bound, `$0.02` preflight approval cap, sanitized encrypted
receipt, exact official-main source, and no-upload/no-deployment boundary. Its
v6 receipt contract records and reserves the full `$0.02` before the receipt
can pass or any subsequent provider action may proceed, not merely the spend
already observed. Its
role and workflow remain unconfigured and unrun for release purposes, and the
required protected `AWS_APPROVED_ACCOUNT_ID_SHA256` value remains a human
provider-setup gate rather than source data.

Therefore AWS preflight remains `NOT_RUN` for release purposes. No artifact
upload, change set, main-stack deployment, DNS change, domain purchase,
renewal, or submission action is authorized by this control.

## Final release requirements

1. Run the exact clean official checkout in an authenticated AWS lane,
   including the separately protected OIDC read-only lane if CloudShell remains
   unavailable, and
   retain a machine-verifiable preflight `PASS` receipt showing current
   account-wide spend plus the full `$0.02` allowance strictly below the
   `$13.14` AWS and `$25.00` total-exposure ceilings, with the main stack
   absent.
2. Recheck exact-release AWS, CockroachDB, Bedrock, Secrets Manager, DNS, and
   logging price assumptions and bind the conservative forecast to the final
   architecture and deployed hashes.
3. Privately inspect the registrar receipt and a dated auto-renew-off export
   while protecting personal and payment data; keep public evidence
   sanitized.
4. After the judged keep-alive window, bind the final complete spend ledger
   and teardown or explicitly approved keep-alive receipt to the release.
