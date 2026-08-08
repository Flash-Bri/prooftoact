# AWS OIDC read-only preflight source lane

Status: **SOURCE SCAFFOLD VERIFIED — PROVIDER SETUP, EXECUTION, AND REVIEW PENDING**

This lane makes AWS CloudShell optional. CloudShell availability is not a
release gate. The AWS identity, account, region, cost, exact-source, evidence,
rollback, and separate-authorization gates remain mandatory regardless of the
authenticated operator surface.

Nothing in this source lane applies an IAM template, creates or changes a
GitHub environment, assumes a role, calls AWS, uploads an artifact, deploys,
spends, publishes, or submits. A source-verifier `PASS` is not a provider
receipt.

## Three deliberately separate authority lanes

| Lane | Protected environment | Exact role/session | Permitted work | Current state |
| --- | --- | --- | --- | --- |
| Identity-only bootstrap | `aws-preflight` | `ProofToActPreflight/release-proof` | GitHub OIDC `AssumeRoleWithWebIdentity`, then STS `GetCallerIdentity` only; no checkout and no account reads | Existing manual workflow preserved and hardened; provider rerun pending |
| Read-only account preflight | `aws-read-only-preflight` | `ProofToActReadOnlyPreflight/read-only-preflight` | The exact account, region, cost, bootstrap, bucket, Bedrock catalog, quota-metadata, and main-stack-absence reads below | New source template/workflow; provider setup and run pending |
| Deployment and evidence | A different, future protected environment | A different, future deployment/evidence role | Upload, change set, stack create, probes, live drill, attestation, and teardown only after separate authorization | Deliberately absent and pending |

The read-only role cannot be reused as a deployment role. Its template has one
inline allow policy for the enumerated reads and an explicit deny for every
other AWS action. It grants no `iam:PassRole`, object write, secret read,
Bedrock invocation, CloudFormation mutation, Lambda invocation, KMS signing,
deployment, or teardown action.

## Human and provider setup gates

The committed files are inert until an authorized human completes and reviews
all provider-side setup. Applying
`infra/aws/oidc-read-only-preflight-role-template.json` is itself an IAM and
CloudFormation provider mutation and is not authorized by this source change.
It requires the exact existing artifact-bucket name as a private deployment
parameter and assumes the account already has the GitHub OIDC provider for
`token.actions.githubusercontent.com` with audience `sts.amazonaws.com`.

For each GitHub environment, a human must independently verify required
reviewers, deployment-branch restriction to `main`, protection against
approval bypass, secret access, and the exact workflow binding. Source cannot
prove those settings exist or remain unchanged.

The protected environment value `AWS_APPROVED_ACCOUNT_ID_SHA256` is still a
known missing setup gate. Do not embed an AWS account ID or its digest in the
repository. An authorized human must compute the SHA-256 of the exact
12-digit approved account ID in a private lane, place only the lowercase
64-character digest in each applicable protected environment, and independently
review it against the separately stored `AWS_ACCOUNT_ID` secret. Until that
value exists and is reviewed, both workflows must fail closed before OIDC or
AWS activity.

The identity environment also requires `AWS_ROLE_ARN`, `AWS_ACCOUNT_ID`, and
`RECEIPT_ENCRYPTION_PASSPHRASE` secrets. The read-only environment requires
`AWS_READ_ONLY_PREFLIGHT_ROLE_ARN`, `AWS_ACCOUNT_ID`, and
`RECEIPT_ENCRYPTION_PASSPHRASE`. The passphrase must be at least 20 characters,
must remain outside source and logs, and must be delivered separately to the
private evidence reviewer.

Every manual dispatch requires an explicit 40-character
`official_main_commit` input. The workflow, GitHub event, checked-out `HEAD`,
and OIDC `sha` and `workflow_sha` claims must all match that same commit at
`refs/heads/main` in repository ID `1317716765`. A branch SHA, moving ref,
dirty tree, or different workflow/environment subject fails closed.

## Exact read-only call boundary

The identity-only workflow checks out no source and makes exactly two STS
calls: `AssumeRoleWithWebIdentity` for a 900-second `ASIA` session and
`GetCallerIdentity`. It runs only on a non-root GitHub-hosted Linux runner and
encrypts the exact validated caller receipt before a one-day artifact upload.
It does not run the account preflight.

The separate read-only workflow obtains its own 900-second `ASIA` session,
requires the non-root runner and account digest again, and then performs only:

- STS `GetCallerIdentity` before any account-specific read;
- Account `GetRegionOptStatus` for `us-east-1`, requiring
  `ENABLED_BY_DEFAULT`;
- Service Quotas `ListServiceQuotas` for Bedrock with one non-paginated
  service response, used only to prove bounded quota-metadata readability;
- CloudFormation `DescribeStacks` for the preserved
  `tideproof-gate2-artifacts` bootstrap stack and account-wide `ListStacks` to
  prove both `prooftoact-gate2` and legacy `tideproof-gate2` are absent;
- Budgets reads for the exact account-wide `$15` budget and its four
  subscriber-backed alerts;
- one non-paginated Cost Explorer `GetCostAndUsage` request for the existing
  project window, with both account-wide spend observations below `$13.14`;
- the six existing-bucket control reads for versioning, encryption, public
  access, ownership, policy status, and the exact TLS-only policy; and
- Bedrock `GetFoundationModel` for
  `amazon.nova-micro-v1:0` in `us-east-1`.

All AWS CLI calls use one SDK attempt, 10-second connect and 20-second read
timeouts, an isolated credential/configuration environment, and an outer
process timeout. The complete credentialed step and GitHub job are separately
bounded. Endpoint, profile, proxy, CA, metadata, tokenless credential, static
`AKIA`, IAM-user, wrong-account, wrong-role, wrong-session, or wrong-region
inputs fail closed.

The Bedrock catalog and service-quota reads do not prove model invocation
access, quota sufficiency for a live drill, availability, or current price.
The Cost Explorer request may be metered. Before any live run, the operator
must recheck current prices and receive separate authorization under the
existing maximum `$0.02` complete-preflight cap. This source change grants no
spend authority.

## Evidence and release boundary

The read-only workflow wraps the existing sanitized preflight receipt with the
exact repository, commit, tree, protected environment, region, temporary
session duration, and source-context checks. Raw OIDC, STS, account, quota,
bucket, subscriber, and credential material remains in owner-only temporary
files. The wrapper rejects the exact account and caller identifiers, is
encrypted with AES-256 before upload, is retained for one day, and is removed
from the runner after the upload step.

Any future receipt remains private pending decryption, independent review,
cost reconciliation, and acceptance against the exact final official-main
commit. The workflow performs no provider mutation and cannot establish
deployment, IAM-denial, model-invocation, live-drill, rollback, teardown,
publication, submission, or final-release proof.

The existing live acceptance and rollback contract remains unchanged: no
artifact upload follows a failed read; a deployed candidate still requires a
fresh separately authorized create-only probe/main sequence, exact signed
attestation, negative controls, complete teardown, and residual-resource and
final-spend receipts. CloudShell recovery does not waive or replace any of
those gates.
