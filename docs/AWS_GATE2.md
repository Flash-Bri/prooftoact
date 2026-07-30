# AWS Gate Two

## Current status

Gate Two is a locally tested deployment candidate. It is not yet evidence of
live AWS behavior.

The exact `4acafa9` release build and the current AWS account-verification
handoff block are recorded in
`evidence/gate2-release-build-4acafa9-2026-07-30.md`. No main Gate Two stack
or live-service claim resulted from that check.

The candidate deliberately keeps Amazon Bedrock outside the authority
boundary:

- API Gateway accepts only an AWS IAM-signed `POST /advisory` request.
- A dedicated short-lived caller role can invoke only that exact route and is
  explicitly denied direct Lambda invocation.
- Boundary Lambda binds the API request ID, API request time, and a hash of
  the authenticated principal to the receipt.
- Private, seven-day API access logs record the corresponding request ID,
  request time, route, status, and caller ARN. A receipt is accepted as
  API-path evidence only after reconciliation with that independent log.
- Agent Lambda invokes only `amazon.nova-micro-v1:0` over one exact,
  Gate-One-digest-bound synthetic fixture.
- The model may return only a proposal requesting fresh authorization.
- Boundary Lambda independently validates the proposal and recomputes its
  digest.
- Signer Lambda signs one exact advisory-receipt schema with one KMS P-256 key.
- Boundary Lambda independently calls `kms:GetPublicKey` on the exact receipt
  key, compares that DER key with the signer envelope, and verifies the P-256
  signature. The key ARN and DER-key SHA-256 are inside the signed receipt.
- Authority Lambda is an isolated fail-closed placeholder with no model,
  database, MCP, secret, signing, or IAM-granted operational capability.

The strongest current claim is that this software and generated
CloudFormation passed local review. Do not claim live Bedrock inference,
KMS-backed evidence, IAM denial, API authentication, or CockroachDB-to-AWS
handoff until their cloud receipts exist.

The Lambda event alone cannot prove that API Gateway created it: a separate
same-account principal with direct `lambda:InvokeFunction` permission could
fabricate API-shaped fields. The intended caller role is explicitly denied
that permission, and final evidence must pair the receipt with the API access
log. A missing or mismatched log means `UNVERIFIED`, not proof of the API
path.

## Proof limits

- None of the Lambda functions has a VPC or egress restriction. The claim is
  limited to the reviewed immutable code and IAM policy; it is not a claim
  that arbitrarily altered or compromised code could cause no network effect.
- Execution roles have no permissions boundary. Final evidence must include
  live policy capture and drift inspection; a later administrator can change
  account policy outside this template.
- A KMS signature proves use of the evidence key, not exclusive execution of
  the receipt validator. Probe-phase signatures are non-final because the
  signer-role probe can sign a fixed test digest.
- CloudFormation enforces each Lambda Version's ZIP through `CodeSha256`, but
  source hashes, commit/tree IDs, artifact hex hashes, and configuration
  digests are deployment parameters. Acceptance therefore requires the
  independent clean-build and versioned-upload receipts.
- The Boundary Lambda has a 25-second timeout behind a 29-second HTTP API
  integration. At external-service tail latency, the caller may receive a
  transport timeout instead of Tideproof's structured signed failure body.
  A timeout or missing receipt is still `UNKNOWN_DO_NOT_ACT`; the project does
  not claim that every fail-closed path produces a signed receipt.
- The caller-principal SHA-256 is pseudonymous, not anonymous. Keep the raw
  access log and full signed receipt private; publish a redacted evidence
  anchor rather than a dictionary-testable identity binding.

## Build boundary

`npm run generate:gate2` regenerates reviewed CloudFormation while the source
tree is under development. It emits no Lambda artifact and labels its receipt
unbound.

`npm run build:gate2` refuses to create artifacts unless Git is clean and
rechecks cleanliness after regenerating the tracked templates. On a clean
commit it bundles each runtime role separately into a single-file, stored ZIP
with fixed metadata, so artifact bytes are independent of host timezone. It
records:

- Git commit and tree;
- package-lock digest;
- source SHA-256;
- ZIP SHA-256 in hexadecimal and base64;
- immutable S3 key recommendation;
- template formatted and canonical digests.

Each Lambda Version uses CloudFormation `CodeSha256`, so a version cannot be
published when the deployed code hash differs from the reviewed artifact.
The build rechecks Git cleanliness after template generation but does not lock
the repository against a concurrent edit during bundling. Run accepted builds
in an isolated one-writer checkout and preserve the emitted source and
artifact digests.

The reviewed JSON is pretty printed for auditability and is larger than
CloudFormation's 51,200-byte inline `TemplateBody` limit. Deploy it through a
private, versioned S3 `TemplateURL` and preserve that object version and
digest. Compact JSON currently fits inline, but ad hoc minification is not the
accepted evidence path.

## Read-only live preflight

Run the account-safety preflight from a clean checkout in an authenticated
AWS CloudShell before any repaired-candidate upload or main-stack mutation:

```sh
npm run gate2:aws-preflight
```

The command is read-only and fail closed. It binds the observation to the
clean Git commit and tree, omits the AWS account, caller ARN, private bucket
name, and alert addresses from its output, and accepts only:

- `us-east-1` and active on-demand catalog metadata for
  `amazon.nova-micro-v1:0`;
- the stable `tideproof-gate2-artifacts` bootstrap stack;
- its exact fixed, account-wide monthly `$15` unblended-cost budget, with no
  legacy or modern filter, billing view, auto-adjustment, or planned limits;
- a budget period active at observation time and extending through
  September 15, 2026, plus `$1`/`$5`/`$10` actual alerts, a `$15` forecast
  alert, and at least one email subscriber per alert;
- both the budget-reported actual spend and Cost Explorer's cumulative
  account-wide unblended cost from 2026-07-01 through the current UTC day
  below the stricter `$13.14` effective AWS ceiling left by the recorded
  `$11.86` domain expense under the `$25` total-project cap;
- an encrypted, versioned, bucket-owner-enforced private artifact bucket with
  all public-access blocks and exactly the reviewed TLS-only deny policy,
  with no additional delegated bucket-policy statements; and
- no active `tideproof-gate2` main stack.

A `PASS` receipt is necessary but deliberately insufficient. The catalog call
does not prove model invocation access or current Nova pricing, Cost Explorer
data may be estimated and delayed, and the command does not upload, deploy,
invoke, sign, or prove IAM denial. Recheck official Nova pricing separately
and keep the receipt private until its release redaction is reviewed.
The total-exposure calculation relies on the owner-reported domain-cost and
auto-renew state recorded in
`evidence/domain-cost-owner-record-2026-07-30.md`; it does not independently
verify registrar billing or renewal settings.

The budget read explicitly requests modern `FilterExpression` visibility.
Absence of that request is not equivalent evidence because AWS can otherwise
omit modern service, tag, region, or linked-account filters from the response.
The bootstrap uses AWS's documented account-wide cost-budget defaults; the
preflight accepts either an omitted `CostTypes` response or the exact complete
default object, whose nonblended, nonamortized settings bind the
`UnblendedCost` basis. Any custom cost-type value or partial object fails.
The sanitized manual console observation and its mandatory stop are recorded
in `evidence/gate2-console-stop-receipt-2026-07-30.md`.

## Live acceptance sequence

1. Re-run all local tests, syntax checks, dependency audit, secret scan,
   CloudFormation lint, and generated-template equality.
2. Commit the accepted local candidate.
3. Build from that clean commit.
4. Create or update the prerequisite bootstrap stack. Verify its account-wide
   $15 budget and $1/$5/$10 actual plus $15 forecast notifications are present
   before its private, encrypted, versioned artifact bucket is accepted.
5. Run `npm run gate2:aws-preflight` and require `PASS`; independently
   revalidate current Nova Micro pricing. If CloudShell, billing data, or any
   required read is unavailable, stop without uploading.
6. Upload each artifact once and record its exact S3 version ID and both
   digests.
7. Hash the full effective nonsecret deployment configuration.

The sanitized historical receipt in
`evidence/gate2-historical-upload-receipt-0ef4dba-2026-07-30.json` anchors the
private receipt for the superseded `0ef4dba` upload without publishing AWS
account, bucket, notification, or object-version identifiers. It is historical
evidence only and must not be used to deploy the repaired candidate.
8. Upload the reviewed template to the private versioned bucket and deploy the
   main stack from its exact `TemplateURL` with probes left at their default
   `false`.
9. Verify every Lambda version's reported `CodeSha256`, alias target, role,
   reserved concurrency, and access-log destination.
10. Temporarily update `EnableProbeFunctions` to `true`. Prove the exact allowed
   capability and required denials for every role. Probe concurrency is one;
   the probe canary and functions exist only during this phase. Label all
   probe-phase receipts non-final because the signer-role probe uses the
   evidence key outside the receipt schema.
11. Update probes back to `false`; verify all probe functions, probe log
    groups, and the canary secret are removed. Recompute the final
    configuration digest and reverify aliases and roles.
12. Assume only the dedicated advisory caller role. Record a denied direct
    invocation attempt for every Lambda, then invoke the exact IAM-signed API
    route.
13. Preserve and reconcile the signed receipt with the asynchronous API access
    log by request ID, request time, route, status, and caller. Preserve the
    model, KMS key ARN/public-key fingerprint, signature, source, artifact,
    configuration, token, and latency bindings.
14. Re-run Gate One state hashes to prove Bedrock changed no authority,
    outbox, fence, or protected synthetic-effect state.

Ambiguous, malformed, unsigned, or unavailable application state returns
`UNKNOWN_DO_NOT_ACT`. Cost limits are operator stop gates and AWS Budget
alerts; this software does not implement a runtime budget check or shutdown.

## Stop conditions

Stop instead of weakening the proof if:

- the new AWS account cannot create a required service safely;
- Nova Micro is unavailable in the reviewed region or request schema;
- a runtime role obtains an undeclared capability;
- a public or unsigned path reaches a receipt;
- a Lambda version's code hash differs;
- a model response can introduce an operation ID, fencing token, effect key,
  or authority-bearing field;
- live cost approaches the approved AWS or total-project ceiling;
- another non-AWS expense would reduce the recorded `$13.14` effective AWS
  envelope without a corresponding reviewed preflight update.

## Teardown

Capability probes are temporary and must be removed after evidence capture.
CloudFormation owns Gate Two resources. Before deleting the main stack,
preserve the signed receipts, KMS public key DER/fingerprint, access-log
records, template object version, and exact artifact versions outside the
stack. Main-stack deletion removes log groups and schedules the KMS key for
deletion after seven days.

The bootstrap artifact bucket is intentionally retained, but its TLS-only
bucket policy and the account budget are not retained if the bootstrap stack
is deleted. Inventory exact object versions and restore equivalent bucket
protection before any bootstrap-stack teardown. Versioning is evidence
retention, not Object Lock: an authorized principal can still delete exact
versions.
