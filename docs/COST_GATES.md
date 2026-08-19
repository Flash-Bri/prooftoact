# Cost and resource gates

The active ProofToAct goal authorizes only the bounded resources described
here. Any higher cap, fixed-charge service, purchase, or unrelated resource
requires new approval.

## Expected contest-period cost

Target architecture: CockroachDB Basic, AWS Lambda, API Gateway, bounded
Bedrock calls, the exact retained Secrets Manager posture below, a bundled
signed-out read-only demo, and short-retention CloudWatch logs.

- Local scaffold and tests: **$0**
- Low case with applicable free allowances: **$0–$3**
- Expected metered spend through 2026-09-15: **$3–$12**
- Approved AWS project ceiling: **$15**
- Approved total ProofToAct ceiling: **$25**
- Recorded non-AWS spend: **$11.86** for the owner-authorized
  `tideproof.net` registration
- Remaining total-project envelope before AWS or any other new spend:
  **$13.14**
- The A1/A2 retained activation posture is separately bounded to **$5.00 per
  month** as detailed below. It is not yet authorized for activation.

The domain purchase is a sunk project cost and is included in the $25 total
ceiling. Auto-renew is owner-reported as disabled. The sanitized owner record
is `evidence/domain-cost-owner-record-2026-07-30.md`; no registrar receipt or
renewal-state export has been independently inspected. The account-wide $15
AWS Budget remains a useful alert boundary, but it no longer represents the
effective amount available to spend. The live preflight must reject observed
AWS spend unless the observation plus the full **$0.02** preflight allowance
is strictly below **$13.14**. It separately requires the recorded non-AWS spend
plus observed AWS spend plus that allowance to remain strictly below **$25**.
An observation at exactly **$13.12** therefore fails, and any later non-AWS
expense reduces the effective AWS ceiling dollar for dollar.

## A1/A2 retained activation posture

Status: **AUTHORIZATION REQUESTED BUT NOT EVIDENCED AS APPROVED**. Activation
must remain blocked until the owner explicitly authorizes this exact monthly
maximum. The authorization is requested but not evidenced as approved.

- A1 retains exactly seven Secrets Manager secrets: `admin`, `auditor`,
  `cloudApi`, `credential`, `mcp`, `publisher`, and `signer`. All seven remain
  required by the reviewed custody and proof design; this cost record does not
  authorize deleting any of them.
- A2 retains one additional secret, for **8 retained Secrets Manager secrets**
  in total.
- Eight secrets at **$0.40 per secret-month** are estimated at **$3.20**.
- The retained CockroachDB Basic cluster is capped at **$1.50** per month.
- Explicit contingency headroom is **$0.30**.
- Exact arithmetic: **$3.20 + $1.50 + $0.30 = $5.00 per month**.

This is a conservative monthly ceiling, not an observed invoice or a claim
that trial credits will apply. The public OSS lifecycle is cost-neutral:
publishing or retaining source code adds **$0.00** to this monthly posture and
does not change the live-resource authorization boundary.

Price inputs checked on 2026-07-29:

- CockroachDB Basic includes 50 million RUs and 10 GiB storage free monthly.
- Lambda includes 1 million requests and 400,000 GB-seconds free monthly.
- API Gateway HTTP APIs start at $1 per million requests; its one-million-call
  free tier is account-age dependent.
- Amazon Nova Micro was listed at $0.035 per million input tokens and $0.14 per
  million output tokens. Final model availability, region, and pricing must be
  rechecked before provisioning.

Sources:

- https://www.cockroachlabs.com/pricing/
- https://aws.amazon.com/lambda/pricing/
- https://aws.amazon.com/api-gateway/pricing/
- https://aws.amazon.com/bedrock/pricing/

## Operator stop conditions

Stop new cloud work and investigate if:

- daily cost exceeds $5;
- conservative account-wide AWS spend approaches the current effective
  **$13.14** project envelope;
- total ProofToAct spend approaches $25;
- unexplained spend exceeds $3;
- a free allowance is exhausted unexpectedly;
- a loop, public abuse, or log-volume anomaly appears;
- any architecture change introduces NAT Gateway, always-on EC2/ECS, an
  Application Load Balancer, or another material fixed charge.
- another domain purchase or `tideproof.net` renewal is proposed without
  fresh approval.

## Controls before first deployment

1. Confirm official price inputs for the selected region and Bedrock model.
   Recheck the exact eight-secret retained posture and its bounded read calls
   in the conservative forecast. The local Gate Two template's one secret is
   only one member of the combined A1/A2 posture; the remaining retained
   secrets are external custody prerequisites.
2. Create project-specific least-privilege identities; never reuse OpenClaw
   OAuth or another product credential.
3. Update the prerequisite bootstrap stack first and verify its account-wide
   $15 AWS Budget reaches `CREATE_COMPLETE`, with absolute-dollar
   notifications at $1, $5, and $10 actual spend and $15 forecast spend,
   before deploying the main Gate Two stack. This is a monthly, account-wide
   unblended-cost alert boundary, not a project ledger or hard service cap.
   The live preflight rejects filters, billing views, auto-adjustment, planned
   limits, inactive periods, and periods ending before September 16, 2026.
   CloudFormation uses `GREATER_THAN`, so notifications trigger after—not
   at—the listed amounts. The application has no runtime budget check or
   automatic shutdown.
   Because the domain registration consumed $11.86 of the separate $25 total
   exposure envelope, the preflight applies a stricter **$13.14** ceiling to
   both budget-reported spend and Cost Explorer's conservative positive
   record-type `UnblendedCost` exposure after reserving the complete
   **$0.02** approved preflight allowance. Both
   `observed AWS + $0.02 < $13.14` and
   `$11.86 + observed AWS + $0.02 < $25.00` must hold using conservative
   micro-dollar arithmetic. Cost Explorer is grouped by `RECORD_TYPE` and
   summed account-wide from 2026-07-01 through the current UTC day rather than
   resetting at a month boundary. Only positive record-type aggregates count;
   negative credits, refunds, discounts, and negations never create headroom.
   The result is conservative exposure, not invoice-final gross or net cost,
   because Cost Explorer can be delayed, estimated, and internally netted
   within one record type.
   The live bootstrap verification is recorded in
   `evidence/gate2-cost-guard-2026-07-30.json`; it intentionally makes no AWS
   spend claim while first-use cost data is still maturing. It cannot evidence
   the hardened live preflight or the main-stack candidate.
4. Cap model requests, input size, output tokens, retries, and concurrency.
   The local Gate Two candidate also caps its public demo at eight reserved
   Lambda executions, a stage-default burst of eight, and a sustained rate of
   `0.05` requests per second; the advisory route retains burst one and rate
   `0.1`. These settings require live verification and are cost bounds, not an
   availability or abuse-prevention claim.
5. Use short log retention and synthetic data only.
6. Record every temporary resource, owner, creation time, cost class, and
   teardown command.
7. Set a teardown or keep-alive decision for the end of judging.

The domain registration does not authorize a second domain, paid DNS or
hosting add-on, privacy upsell, transfer, renewal, or auto-renew change.
Public DNS mutation remains a separate launch action.
