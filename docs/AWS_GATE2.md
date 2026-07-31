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

- API Gateway exposes ten exact signed-out `GET` routes for the read-only
  browser proof and one separate AWS IAM-signed `POST /advisory` route.
- Demo Lambda serves only bundled HTML, JavaScript, CSS, the deterministic
  scenario, approved Gate One evidence, claims, favicon, and a nonsecret health
  binding. Its role can write only its exact log groups and explicitly denies
  Bedrock, Lambda invocation, KMS signing, secrets, and privilege escalation.
- Demo Lambda validates the API ID, `$default` stage, exact route key, method,
  path, and empty body before serving anything. It returns strict
  content-security, transport-security, framing, referrer, permissions,
  cross-domain-policy, and MIME headers; it exposes no CORS policy and has no
  path to the advisory integration.
- The signed-out health response binds source commit, tree, config, demo
  source, demo artifact, package lock, and immutable Lambda version without
  exposing account, role, bucket, or notification identifiers.
- A dedicated short-lived caller role can invoke only that exact route and is
  explicitly denied direct Lambda invocation; this applies only to
  `POST /advisory`, never to the public read-only routes.
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
- The post-deployment verifier rebuilds the exact clean head, compares every
  public static response byte-for-byte with that checkout, reconciles the
  health and scenario bindings, checks browser headers, and probes unknown,
  non-GET, and signed-out advisory denials. It emits a sanitized receipt but
  cannot prove availability, route throttling, IAM policy shape, or advisory
  traversal by itself.

The strongest current claim is that this software, the bundled public-demo
artifact path, and generated CloudFormation passed local review. Do not claim
live public hosting, Bedrock inference, KMS-backed evidence, IAM denial, API
authentication, or CockroachDB-to-AWS handoff until their cloud receipts
exist.

The Lambda event alone cannot prove that API Gateway created it: a separate
same-account principal with direct `lambda:InvokeFunction` permission could
fabricate API-shaped fields. The intended caller role is explicitly denied
that permission, and final evidence must pair the receipt with the API access
log. A missing or mismatched log means `UNVERIFIED`, not proof of the API
path.

## Proof limits

- A reachable public demo URL would prove only that the read-only AWS host
  responded with the bound artifact. It would not prove that Bedrock, KMS, the
  IAM advisory route, or CockroachDB handoff ran.
- Public routes create an abuse and cost surface. The stage defaults to a burst
  of eight and a sustained rate of `0.05` requests per second, Demo Lambda
  reserved concurrency is eight, and the account budget remains the operator
  stop. These controls are limits, not a DDoS or availability claim.
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
commit it bundles each runtime role separately into six single-file, stored
ZIPs with fixed metadata, so artifact bytes are independent of host timezone.
The Demo artifact embeds the exact reviewed browser source, scenario
implementation, claims ledger, and Gate One evidence through build-time raw
imports. The receipt records:

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

After deployment, `npm run gate2:verify-public-demo` accepts only an HTTPS
origin and a 64-character expected configuration digest. It requires a clean
checkout, performs a fresh deterministic Gate Two build, verifies the local
Demo ZIP and source hashes, then makes exactly fifteen signed-out requests:
the ten positive routes plus unknown-route, `HEAD`, non-GET scenario,
wrong-method advisory, and unauthenticated advisory probes. A pass binds the
served public bytes, browser headers, health receipt, scenario host receipt,
immutable function version, and denials to the exact checkout. It remains a
host-surface receipt, not Bedrock, KMS, CockroachDB handoff, or authenticated
API-path evidence. To stay within the reviewed stage throttle, it uses the
initial burst of eight and then waits 21 seconds before each of the seven
remaining requests; a normal run therefore takes at least 147 seconds.

## Read-only live preflight

The release-level entrypoint is:

```sh
npm run gate2:aws-readiness
```

Run it only from a fresh official checkout in the authenticated AWS lane,
before any candidate upload or main-stack mutation. It is read-only with
respect to AWS. The gate:

- requires the exact public Tideproof origin, `main`, a clean tree, and
  `HEAD == origin/main`, fetching `origin/main` again before and after the
  checks so a moving release target fails closed;
- performs a lockfile install with dependency lifecycle scripts disabled,
  the full test suite, and a zero-vulnerability dependency audit;
- creates a fresh exact-head Gate Two build and independently rechecks the
  package lock, tracked templates, six source files, six artifact hashes,
  Lambda `CodeSha256` values, sizes, immutable key recommendations, and
  one-entry stored-ZIP structure;
- invokes the account-safety preflight below and binds its `PASS` receipt to
  the same commit and tree; and
- rechecks the official upstream and clean tree before emitting
  `tideproof.gate2.aws-readiness.v1` with status `PASS`.

It executes only reviewed `git` and `npm` command families. The nested AWS
preflight uses read-only service calls; the readiness gate cannot upload,
create a change set, deploy, invoke, sign, or delete. A failed command emits a
bounded error code rather than forwarding command output that could contain
private account context. The install, tests, audit, build, and Git checks run
with AWS and application credentials removed and AWS credential-file and
metadata discovery disabled. Only the exact nested preflight receives the
authenticated AWS environment, and unrelated application credentials remain
removed there too.

Local maintainers can exercise every non-AWS part with:

```sh
npm run gate2:aws-readiness:local
```

That mode emits `LOCAL_ONLY_PASS`, records `awsPreflight: NOT_RUN`, and is
never authorization to upload or deploy.

The underlying account-safety command remains independently runnable from a
clean checkout:

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
5. Run `npm run gate2:aws-readiness` and require the combined
   `tideproof.gate2.aws-readiness.v1` `PASS`; independently revalidate current
   Nova Micro pricing. If CloudShell, billing data, the official upstream, or
   any required read is unavailable, stop without uploading.
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
12. From a signed-out browser, request only the ten enumerated public `GET`
    routes. From the exact clean deployment checkout, run:

    ```sh
    npm run gate2:verify-public-demo -- \
      --url "$PUBLIC_DEMO_URL" \
      --config-digest "$CONFIG_DIGEST"
    ```

    Preserve its `PASS` receipt, reconcile the health binding to the deployed
    Demo version and artifact, independently verify route throttles, and
    complete the three-act path plus reset on desktop and mobile. A failed or
    missing verifier receipt blocks publication.
13. Assume only the dedicated advisory caller role. Record a denied direct
    invocation attempt for every Lambda, then invoke the exact IAM-signed API
    route.
14. Preserve and reconcile the signed receipt with the asynchronous API access
    log by request ID, request time, route, status, and caller. Preserve the
    model, KMS key ARN/public-key fingerprint, signature, source, artifact,
    configuration, token, and latency bindings.
15. Re-run Gate One state hashes to prove Bedrock changed no authority,
    outbox, fence, or protected synthetic-effect state.

Ambiguous, malformed, unsigned, or unavailable application state returns
`UNKNOWN_DO_NOT_ACT`. Cost limits are operator stop gates and AWS Budget
alerts; this software does not implement a runtime budget check or shutdown.

## Stop conditions

Stop instead of weakening the proof if:

- the new AWS account cannot create a required service safely;
- Nova Micro is unavailable in the reviewed region or request schema;
- a runtime role obtains an undeclared capability;
- a public or unsigned path reaches the advisory Boundary/Signer execution
  path or a live signed advisory receipt;
- an unexplained public-route or log-volume anomaly appears;
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
records, signed-out health binding, route inventory, reviewed browser captures,
template object version, and exact artifact versions outside the stack.
Main-stack deletion removes the public demo, log groups, and API routes and
schedules the KMS key for deletion after seven days.

The bootstrap artifact bucket is intentionally retained, but its TLS-only
bucket policy and the account budget are not retained if the bootstrap stack
is deleted. Inventory exact object versions and restore equivalent bucket
protection before any bootstrap-stack teardown. Versioning is evidence
retention, not Object Lock: an authorized principal can still delete exact
versions.
