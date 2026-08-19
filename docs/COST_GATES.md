# Cost and resource gates

The active ProofToAct goal authorizes only the bounded resources described
here. Any higher cap, fixed-charge service, purchase, or unrelated resource
requires new approval.

## Expected contest-period cost

Target architecture: CockroachDB Basic, AWS Lambda, API Gateway, bounded
Bedrock calls, one project-owned Secrets Manager credential for the
least-privilege CockroachDB authorizer, a bundled signed-out read-only demo,
and short-retention CloudWatch logs.

- Local scaffold and tests: **$0**
- Low case with applicable free allowances: **$0–$3**
- Expected metered spend through 2026-09-15: **$3–$12**
- Approved AWS project ceiling: **$15**
- Approved total ProofToAct ceiling: **$25**
- Recorded non-AWS spend: **$11.86** for the owner-authorized
  `tideproof.net` registration
- Remaining total-project envelope before AWS or any other new spend:
  **$13.14**
- Private-recovery CockroachDB: one Basic cluster capped at **$1.50 per
  month**. Any legacy or separately retained cluster remains outside this
  lane's forecast until an exact provider inventory prices it.

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

## Private recovery lane retained-cost posture

The private AWS-to-Managed-MCP recovery lane has a narrower recurring-cost
forecast that is source-bound here but is not yet provider-observed or
authorized for activation:

- A1 defines seven retained Secrets Manager secrets and A2 defines one, for
  eight retained secrets before any separately governed cleanup. At the
  current planning input of **$0.40 per secret-month**, that is **$3.20 per
  month**.
- One CockroachDB Basic cluster is capped at **$1.50 per month**.
- The recurring base before cleanup is therefore **$4.70 per month**. A
  proposed **$5.00 monthly** private-recovery ceiling would leave only
  **$0.30** for bounded Lambda calls, one-day CloudWatch logs, DynamoDB and
  Secrets Manager requests, and retained S3 object storage. That proposed
  ceiling remains pending explicit authorization and fresh provider price
  readback; it is not granted by this document.
- The application stack owns one 256 MiB Lambda with reserved concurrency one
  and one one-day log group. Governed teardown deletes that exact stack and
  log group only after signed POST evidence and a durable terminal receipt.
- Deployment stores one content-addressed, versioned ZIP in the retained
  artifact bucket. Application-stack teardown does not delete that object
  version. The bucket expires noncurrent versions after 45 days, but a current
  version can remain and must be included in observed variable spend.
- The A2 Managed MCP secret is intentionally retained by its bootstrap stack.
  The seven A1 secrets likewise remain retained unless an independent,
  reviewed deletion workflow produces exact deletion and absence receipts.
  Only after those seven receipts exist does the modeled recurring base fall
  to **$1.90 per month**: one A2 secret plus the CockroachDB Basic cap. That is
  a conditional target, not the current source-proven posture.

Open-source users supply and pay for their own AWS and CockroachDB accounts,
credentials, protected environments, and provider usage. The repository does
not provide shared paid-service access or a public provider proxy.

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
   Recheck and include one Secrets Manager secret plus its bounded read calls
   in the conservative forecast before creating it; the local template does
   not create or price that external secret.
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
