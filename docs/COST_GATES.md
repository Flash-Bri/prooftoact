# Cost and resource gates

No cloud resource is authorized by this document. It is a planning envelope.

## Expected contest-period cost

Target architecture: CockroachDB Basic, AWS Lambda, API Gateway, bounded
Bedrock calls, static assets, and short-retention CloudWatch logs.

- Local scaffold and tests: **$0**
- Low case with applicable free allowances: **$0–$3**
- Expected metered spend through 2026-09-15: **$3–$12**
- Conservative operating envelope: **$25–$35**
- Hard monthly planning cap before separate approval: **$50**
- High-risk ceiling for estimating exposure, not authorization: **$125**

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

## Automatic stop conditions

Stop new cloud work and investigate if:

- daily cost exceeds $5;
- cumulative Bedrock cost exceeds $20;
- unexplained spend exceeds $10;
- a free allowance is exhausted unexpectedly;
- a loop, public abuse, or log-volume anomaly appears;
- any architecture change introduces NAT Gateway, always-on EC2/ECS, an
  Application Load Balancer, or another material fixed charge.

## Controls before first deployment

1. Confirm official price inputs for the selected region and Bedrock model.
2. Create project-specific least-privilege credentials.
3. Set $10, $25, and $40 budget notifications.
4. Cap model requests, input size, output tokens, retries, and concurrency.
5. Use short log retention and synthetic data only.
6. Record every temporary resource, owner, creation time, cost class, and
   teardown command.
7. Set a teardown or keep-alive decision for the end of judging.
