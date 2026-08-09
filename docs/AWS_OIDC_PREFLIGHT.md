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

The role trust conditions use only keys documented by AWS for GitHub OIDC:
`aud`, `sub`, `repository`, immutable `repository_id`, immutable
`repository_owner_id`, `workflow`, `ref`, and `environment`. The template pins
all eight to this owner/repository and their IDs, workflow name, `main`, and
`aws-read-only-preflight`. This support decision was checked against the
official AWS IAM OIDC condition-key reference and GitHub OIDC guidance on
2026-08-08:

- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html#condition-keys-wif
- https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html#idp_oidc_Create_GitHub
- https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-aws
- https://docs.github.com/en/actions/reference/security/oidc#immutable-subject-claims

GitHub's AWS guide still says customized OIDC claims are unavailable in AWS;
this template does not customize the subject or invent a claim mapping. It
uses only the default GitHub token claims that the current AWS IAM reference
explicitly maps. GitHub documents that repositories created after July 15,
2026 use an immutable default subject containing both owner and repository
IDs. The public repository API reported on 2026-08-08 that this repository's
`created_at` is `2026-07-30T22:07:23Z`, repository ID is `1317716765`, and
owner ID is `252500266`:

- https://api.github.com/repos/Flash-Bri/prooftoact

The public repository OIDC settings API also reported `use_default: true`,
`use_immutable_subject: false`, and exact `sub_claim_prefix`
`repo:Flash-Bri@252500266/prooftoact@1317716765`:

- https://api.github.com/repos/Flash-Bri/prooftoact/actions/oidc/customization/sub

The template therefore pins the exact current read-only subject
`repo:Flash-Bri@252500266/prooftoact@1317716765:environment:aws-read-only-preflight`.
The identity workflow validates the corresponding `aws-preflight` subject.
Public API metadata is corroboration, not a live OIDC token or IAM receipt.
Before applying the inert read-only template, provider setup must re-fetch
both metadata responses and inspect an actual protected-environment token to
confirm the exact committed subject. The existing identity role is outside
this source template; an authorized human must separately verify or update its
trust to the immutable `aws-preflight` subject before running that lane. A
repository transfer, rename, owner/ID change, or OIDC subject customization
must fail closed until both source and provider trust receive separate review
and authorization.

AWS documents `job_workflow_ref` only for jobs that call a reusable workflow;
this direct workflow does not do that. AWS does not document the direct
`workflow_ref` claim as an IAM condition key. The general
`sts:RoleSessionName` reference does not unambiguously promise that condition
key for `AssumeRoleWithWebIdentity`, so the template does not invent either
condition. The runner still checks the exact token `workflow_ref`, source SHA,
and resulting `read-only-preflight` session before accepting evidence, but
those checks do not strengthen IAM before assumption. Required reviewers,
`main`-only deployment branches, disabled approval bypass, and human review of
the exact workflow and official commit therefore remain a deliberate
provider-side gate and residual trust boundary.

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
`RECEIPT_ENCRYPTION_PASSPHRASE`. An authorized human must generate a different
value independently for each protected environment with a trusted CSPRNG, for
example:

```sh
openssl rand -base64 32 | tr -d '=\n' | tr '+/' '-_'
```

The exact accepted format is canonical unpadded Base64URL for 32 bytes: 43
characters matching `^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$`. Both workflows
reject every other length, alphabet, padding, or noncanonical final character.
The value must remain outside source and logs and must be delivered separately
to the private evidence reviewer. Source can enforce the exact encoding but
cannot prove that a human used a CSPRNG or kept the value private; those remain
setup-review gates.

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
requires the non-root runner and account digest again, and makes exactly 20 AWS
CLI calls on a successful run: three fixed wrapper calls plus the 17-call
ordered account-safety inventory. The exact calls are:

- one STS `AssumeRoleWithWebIdentity`; its returned assumed-role identity is
  validated before any account-specific read;
- one Account `GetRegionOptStatus` for `us-east-1`, requiring
  `ENABLED_BY_DEFAULT`;
- one Service Quotas `ListServiceQuotas` for Bedrock with one non-paginated
  service response, used only to prove bounded quota-metadata readability;
- one nested STS `GetCallerIdentity` before the nested account-safety reads;
- one CloudFormation `DescribeStacks` for the preserved
  `tideproof-gate2-artifacts` bootstrap stack;
- one Budgets `DescribeBudget` for the exact account-wide `$15` budget, one
  `DescribeNotificationsForBudget`, and exactly four
  `DescribeSubscribersForNotification` calls after the returned notification
  set is proven to contain exactly the four required alerts;
- one non-paginated Cost Explorer `GetCostAndUsage` request for the existing
  project window;
- exactly six existing-bucket control reads for versioning, encryption, public
  access, ownership, policy status, and the exact TLS-only policy;
- one account-wide CloudFormation `ListStacks` proving both `prooftoact-gate2`
  and legacy `tideproof-gate2` are absent; and
- one Bedrock `GetFoundationModel` for
  `amazon.nova-micro-v1:0` in `us-east-1`.

The runtime consumes that inventory in order, rejects a wrong service,
operation, region, missing call, or extra call, and cannot turn an oversized
notification response into extra subscriber reads. The independent source
verifier parses the declared inventory and requires the exact 14 operation
groups and 17 nested calls; the fixed wrapper adds exactly three calls.

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

The full declared `$0.02` allowance is reserved before the receipt can pass or
any subsequent provider action may proceed. The gate conservatively rounds
each account-wide spend amount upward to the nearest micro-dollar, takes the
greater of Budget and Cost Explorer observed spend, and requires both
`observed AWS + $0.02 < $13.14` and
`$11.86 + observed AWS + $0.02 < $25.00`. Strict inequality means an observed
value of exactly `$13.12` fails; `$13.119999` is the highest six-decimal value
that can pass. Receipt schema `tideproof.gate2.aws-preflight.v6` records the
allowance, reserved AWS exposure, reserved total exposure, and remaining
exposure after the allowance. The Cost Explorer request needed to learn the
observation happens before receipt validation and may itself be metered, which
is why the prior price recheck and separate maximum `$0.02` run authorization
remain mandatory; a failed receipt authorizes nothing further.

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
