# Release cost control

Status: **CURRENT COST GUARDS PASS — LIVE SPEND AND FINAL REVIEW PENDING**

This control binds ProofToAct's current source, budget prerequisites, recorded
non-AWS spend, and deployment stop conditions. A
`CURRENT_COST_GUARDS_PASS` receipt is a current-source result only. It does
not assert current AWS spend, authorize an upload or deployment, validate a
registrar receipt, or approve publication or submission.

## A1/A2 RETAINED ACTIVATION AUTHORIZATION PENDING

Activation is blocked because the exact retained monthly authorization is
requested but not evidenced as approved. The reviewed posture is seven A1
secrets (`admin`, `auditor`, `cloudApi`, `credential`, `mcp`, `publisher`, and
`signer`) plus one A2 secret: **8 retained Secrets Manager secrets** total.
At **$0.40 per secret-month**, Secrets Manager is estimated at **$3.20**. The
retained CockroachDB Basic cap is **$1.50**, with **$0.30** explicit headroom,
for the exact worst-case arithmetic **$3.20 + $1.50 + $0.30 = $5.00** per
month. The seven A1 secrets remain required; this control does not authorize
deleting them.

The public OSS lifecycle is cost-neutral. Publishing or retaining the source
adds **$0.00** to this monthly live-resource posture and grants no authority to
activate, expand, purchase, delete, or alter provider resources.

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
  current UTC day, grouped by `RECORD_TYPE`, with only positive
  `UnblendedCost` record-type aggregates counted toward exposure. Negative
  offsets never create headroom. The gate does not reset at a month boundary.

The `$15` AWS Budget is an alert boundary, not a hard service cap and not the
effective remaining project envelope. The read-only preflight must reject
unless the greater of its current budget-reported actual spend and
conservative positive record-type Cost Explorer exposure, plus the full
`$0.02` allowance for that run, remains strictly below `$13.14`. It must
also require `$11.86 + provider-observed AWS exposure + $0.02` to remain
strictly below `$25.00`. Thus a current provider observation at exactly
`$13.12` cannot produce a
preflight `PASS`, and no subsequent provider action may proceed; positive
amounts round upward to the micro-dollar, while negative groups are excluded
rather than used as credits. This grouped aggregate is not an invoice,
realized net bill, or line-item gross-spend proof. The Cost Explorer read used
to obtain it may itself already have occurred under the separate price
recheck and maximum `$0.02` run authorization. This v7 receipt does not
reconcile pending or previous preflight attempts, delayed provider charges,
or the separate `$5.00` aggregate preflight authorization. The operator's
conservative attempt ledger remains an additional pre-dispatch gate and may
never be used to create headroom.

## Required alert and architecture bounds

The prerequisite bootstrap must expose one account-wide monthly unblended
cost budget with absolute-dollar `GREATER_THAN` alerts at `$1`, `$5`, and
`$10` actual spend and `$15` forecast spend. The artifact bucket depends on
that budget, retains replacement/deletion state, and expires noncurrent
artifact versions after 45 days.

The reviewed Gate Two template uses only bounded Lambda memory, timeouts, and
reserved concurrency, seven-day log retention, a throttled HTTP API, and its
one A2 Secrets Manager secret within the exact eight-secret combined posture.
It also creates two no-action
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
v7 receipt contract records and reserves the full `$0.02` before the receipt
can pass or any subsequent provider action may proceed, not merely the spend
already observed. Its provider configuration and execution remain external
evidence gates that this source cannot attest, and the required protected
`AWS_APPROVED_ACCOUNT_ID_SHA256` secret remains human-reviewed provider state
rather than source data.

Therefore no accepted AWS read-only preflight receipt exists for release
purposes. No artifact
upload, change set, main-stack deployment, DNS change, domain purchase,
renewal, or submission action is authorized by this control.

## Final release requirements

1. Obtain explicit owner authorization for the exact retained **$5.00 monthly
   maximum** before activation. A request is not approval.
2. Run the exact clean official checkout in an authenticated AWS lane,
   including the separately protected OIDC read-only lane if CloudShell remains
   unavailable, and
   retain a machine-verifiable preflight `PASS` receipt showing that the
   greater of budget-reported spend and conservative account-wide positive
   record-type exposure, plus the full `$0.02` allowance, remains strictly
   below the `$13.14` AWS and `$25.00` total-exposure ceilings, with the main
   stack absent.
3. Recheck exact-release AWS, CockroachDB, Bedrock, Secrets Manager, DNS, and
   logging price assumptions and bind the conservative forecast to the final
   architecture and deployed hashes.
4. Privately inspect the registrar receipt and a dated auto-renew-off export
   while protecting personal and payment data; keep public evidence
   sanitized.
5. After the judged keep-alive window, bind the final complete spend ledger
   and teardown or explicitly approved keep-alive receipt to the release.
