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
  scenario, approved Gate One evidence, claims, and a nonsecret health
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
  explicitly denied direct Lambda invocation. Boundary Lambda additionally
  accepts only the same-account STS `assumed-role` ARN derived from that exact
  role; another same-account principal with generic `execute-api:Invoke` is
  rejected before Bedrock or signing. This applies only to `POST /advisory`,
  never to the public read-only routes.
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
- Authority Lambda is isolated from the advisory Boundary and model. Its
  local candidate accepts only `alpha` or `bravo` for one configured synthetic
  race, derives operation IDs, intent nonces, effect keys, payloads, and
  digests internally, reads one exact Tideproof-owned Secrets Manager ARN at
  one exact `AWSCURRENT` VersionId, verifies the exact CockroachDB Cloud host
  and port in the URL, and calls only `tp_api.g2_spend_authority_race_v1` and
  `tp_api.g1_resolve_request_v1` as `tp_gate2_authorizer_user`. After both
  contenders return, the verifier makes one separate read-only proof request
  through the same exact numeric Authority version; that path calls only
  `tp_api.g1_observe_authority_race_v1`.
- The authority role is allowed only its exact log group and
  `secretsmanager:GetSecretValue` on that one ARN. It explicitly denies other
  secret reads and enumeration, secret mutation, Bedrock, KMS signing, Lambda
  invocation, IAM mutation, and role assumption.
- A separate short-lived human-assumed race-caller role can invoke only the
  exact numeric Authority version. The function has reserved concurrency two so the
  two proof contenders can genuinely overlap; no public API route reaches it.
- Authority transactions explicitly request `SERIALIZABLE`, retry only
  pre-commit `40001` restarts, and reconcile any COMMIT-dispatched or
  transport-ambiguous result through the typed read-only resolver instead of
  blindly spending again. Every spend, proof, and reconciliation client has
  bounded connection, client-query, server-statement, and idle-transaction
  timeouts. Any malformed secret, endpoint/version mismatch, response, timeout,
  or unresolved state returns `UNKNOWN_DO_NOT_ACT` without echoing credentials.
- A race cannot emit `PASS` from the two contender responses alone. The
  follow-up CockroachDB observation must be a separate serializable read-only
  transaction after both contender intervals and must find exactly two
  terminal receipts, one reservation, one held denial that observed that
  winner at the same fence, one matching outbox intent, the winner as current
  holder at that fence, no pending receipt, and zero protected effects. Any
  extra or mismatched state fails closed.
- The post-deployment verifier rebuilds the exact clean head, compares every
  public static response byte-for-byte with that checkout, reconciles the
  health and scenario bindings, checks browser headers, and probes unknown,
  non-GET, and signed-out advisory denials. It emits a sanitized receipt but
  cannot prove availability, route throttling, IAM policy shape, or advisory
  traversal by itself.
- A bounded deployment-evidence collector trusts one exact IAM user or role.
  Its source validator binds signed pre/post provider snapshots to the exact
  raw build receipt, configuration, stack, template, commit, tree, numeric
  Lambda versions, code hashes, layers and other security-relevant
  configuration for the five primary runtime functions, their shared role
  policy censuses, both evidence roles, concurrency, revisions,
  monitored alias targets, alias/function-URL/event-source/tag censuses,
  stable role IDs, the exact API/integration/route/stage and explicit
  active-deployment census, the exact API access-log destination, 37
  drift-supported resources, two directly attested integration resources that
  CloudFormation drift does not support, and the directly attested explicit
  API deployment. The stage has auto-deploy disabled and must name the exact
  CloudFormation deployment physical ID created after every declared route.
  Attestation accepts only a never-updated `CREATE_COMPLETE` stack, requires
  that deployment to have been created during that stack creation, be the
  newest observed deployment, report `DEPLOYED`, and carry no status warning.
  Any application or configuration change therefore requires teardown and a
  fresh stack create; an in-place stack update is deliberately fail-closed. Each
  snapshot requires two identical complete observations. A dedicated
  alternate role whose only positive permission targets the collector must
  receive `AccessDenied`. These controls are unrun and do not exclude
  administrators or the independently protected receipt-key custodian.
  AWS requires `lambda:ListEventSourceMappings` to use `Resource: "*"`; this
  is one explicit read-only collector exception, while reviewed code queries
  the five exact primary function names and accepts no mappings for them.
  Conditional probe-function configurations remain outside this stage-three
  census and require separate stage-four provider evidence.

The strongest current claim is that this software, the bundled public-demo
artifact path, the isolated CockroachDB authority candidate, and generated
CloudFormation passed local review. Do not claim live public hosting, Bedrock
inference, KMS-backed evidence, IAM denial, API authentication, an overlapping
Lambda race, or CockroachDB-to-AWS handoff until their cloud receipts exist.

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
- The local authority tests use injected secret and database clients. They
  prove request derivation, transaction control, bounded retry,
  ambiguous-commit reconciliation, strict durable-proof validation, and
  response validation in software; they do not prove Secrets Manager, Lambda
  concurrency, CockroachDB reachability, IAM enforcement, or live database
  state. The new observation function must be migrated and exercised through
  the reviewed owner lane before the AWS race can run.
- The authority connection is intentionally outside a VPC to avoid a NAT
  Gateway. Final review must confirm the exact public CockroachDB endpoint,
  port, `verify-full` TLS, `tp_gate2_authorizer_user`, exact secret VersionId still
  carrying `AWSCURRENT`, and the absence of any broader database grant. Secret
  rotation intentionally makes the old deployment fail closed until the new
  VersionId and configuration digest are reviewed. The connection secret must
  never enter source, build output, logs, receipts, or the configuration
  digest.
- The database bootstrap preserves `tp_authorizer_role` / `tp_authorizer_user`
  for Gate One and creates a separate `tp_gate2_authorizer_role` /
  `tp_gate2_authorizer_user` for AWS. Gate One receives direct execute on
  `g1_spend_authority_v1` but not the Gate Two wrapper. Gate Two receives only
  `g2_spend_authority_race_v1` plus the exact read-only request resolver and
  durable race observer, never direct execute on the Gate One spend function.
  Explicit function and cross-membership revocations make rerunning the
  bootstrap remove the superseded privilege. The Gate One implementation
  accepts the Gate Two session identity only when called inside the owner-run
  `SECURITY DEFINER` wrapper; SQL `EXECUTE` privilege prevents the Gate Two
  role from calling it directly. The wrapper itself requires
  `session_user = 'tp_gate2_authorizer_user'` and permits only
  `aws-authority-alpha` or `aws-authority-bravo`. Each credential remains an
  authority capability within its granted surface, not per-agent
  authentication. Credential isolation, grants, and live session identity
  therefore remain acceptance evidence, not assumptions.
- CockroachDB v26.2 does not document PostgreSQL function-level
  `SET search_path`, so this candidate does not add unsupported syntax. Every
  application relation and nested application function referenced by the
  primary and recovery `SECURITY DEFINER` bodies is schema-qualified and
  statically regression-tested. Built-in name resolution and the absence of a
  server-supported per-function search-path pin remain explicit residual
  boundaries for live database review.
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
rechecks cleanliness after regenerating the tracked templates. Every project
input is then read as a regular tracked blob from the exact `HEAD` commit;
replacement refs, legacy grafts, alternate object databases, shallow history,
path escape, untracked inputs, and unsupported loaders fail closed. On that
commit it bundles each runtime role separately into six two-entry, stored ZIPs
with fixed metadata, so artifact bytes are independent of host timezone. Every
ZIP contains `index.js` plus the exact verified `THIRD_PARTY_NOTICES.txt` for
the 46-package union present across the six Lambda graphs and the separately
content-addressed evidence-provider runtime graph. Over-inclusion in each ZIP
is intentional so every independently distributed ZIP carries the complete
reviewed notice set.
The Demo artifact embeds the exact reviewed browser source, scenario
implementation, claims ledger, and Gate One evidence through build-time raw
imports. The receipt records:

- Git commit and tree;
- package-lock digest;
- bundled-package sets and the notice-file digest, size, source fallbacks, and
  normalized license-text counts;
- source SHA-256;
- every bundled project input's path, Git blob ID, and SHA-256;
- ZIP SHA-256 in hexadecimal and base64;
- immutable S3 key recommendation;
- template formatted and canonical digests.

Each Lambda Version uses CloudFormation `CodeSha256`, so a version cannot be
published when the deployed code hash differs from the reviewed artifact.
All runtime roles, API integrations, permissions, probes, and authority-race
calls target numeric Lambda versions. The `proof` aliases are monitored
pointers for inspection and metadata only, not invocation authority. Run
accepted builds in an isolated one-writer checkout and preserve the emitted
source, blob, and artifact digests. The receipt measures but does not
independently certify the local Node/npm/esbuild/Git toolchain. Component-walk
checks reject symlinked artifact parents, but a same-identity hostile host is
still outside the claim and requires independent exact-release reproduction.

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
  then runs the exact-release provenance control over the full single-root Git
  ancestry, object integrity, replacement refs, legacy grafts, alternate object
  databases, tracked file modes, installed package identities, dependency
  inventory, bundle notice inputs, the current-surface rights receipt, and the
  bounded static accessibility receipt;
- runs the full test suite and a zero-vulnerability dependency audit;
- creates a fresh exact-head Gate Two build and independently rechecks the
  package lock, tracked templates, six source files, six artifact hashes,
  Lambda `CodeSha256` values, sizes, immutable key recommendations, exact
  bundled-package union, notice bytes, and two-entry stored-ZIP structure;
- invokes the account-safety preflight below and binds its `PASS` receipt to
  the same commit and tree; and
- rechecks the official upstream and clean tree before emitting
  `tideproof.gate2.aws-readiness.v1` with status `PASS`.

It executes only reviewed `git` and `npm` command families. The nested AWS
preflight uses read-only service calls; the readiness gate cannot upload,
create a change set, deploy, invoke, sign, or delete. A failed command emits a
bounded error code rather than forwarding command output that could contain
private account context. The install, release-provenance, tests, audit, build,
and Git checks run with AWS and application credentials removed and AWS
credential-file and metadata discovery disabled. Git, Node, npm, dynamic
loader, and shell-startup environment overrides are removed before child
commands. Only the exact nested preflight receives the authenticated AWS
environment, and unrelated application credentials remain removed there too.

Local maintainers can exercise every non-AWS part with:

```sh
npm run gate2:aws-readiness:local
```

That mode includes the hash-bound public claim-surface control, emits
`LOCAL_ONLY_PASS`, records `awsPreflight: NOT_RUN`, and is never authorization
to upload or deploy.

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

1. Re-run all local tests, syntax checks, dependency audit,
   `npm run privacy:verify`,
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
6. Prepare one fresh synthetic Gate Two tenant/run/incident/evidence/resource
   tuple through the reviewed CockroachDB owner lane. Create one
   Tideproof-owned Secrets Manager secret whose JSON has exactly the
   `connectionString` key, whose URL names only `tp_gate2_authorizer_user` and the
   `tideproof` database, whose host and port exactly match the reviewed
   parameters, and whose TLS mode is `verify-full`. Record the exact
   `AWSCURRENT` VersionId, secret metadata, database grants, rotation state, and
   the updated conservative cost forecast privately; never record the
   credential value.
7. Upload each artifact once and record its exact S3 version ID and both
   digests.
8. Hash the full effective nonsecret deployment configuration, including the
   secret ARN, exact VersionId, expected database host and port, and synthetic
   fixture identifiers plus the one exact IAM user or role allowed to assume
   the deployment-evidence role, but excluding all secret values.

The sanitized historical receipt in
`evidence/gate2-historical-upload-receipt-0ef4dba-2026-07-30.json` anchors the
private receipt for the superseded `0ef4dba` upload without publishing AWS
account, bucket, notification, or object-version identifiers. It is historical
evidence only and must not be used to deploy the repaired candidate.
9. Upload the reviewed template to the private versioned bucket and create the
   disposable `tideproof-gate2-probe` stack from its exact `TemplateURL` with
   `EnableProbeFunctions=true` in the initial create. Never update this stack.
   Prove the exact allowed capability and required denials for every role.
   Probe concurrency is one; the probe canary and functions exist only in this
   disposable stack. Label every probe-phase receipt non-final because the
   signer-role probe uses the evidence key outside the receipt schema and the
   probe stack is not eligible for deployment attestation.
10. Delete the disposable probe stack and require stack `DELETE_COMPLETE`.
    Verify its endpoints, functions, aliases, log groups, canary secret, API,
    stage, deployment, and every other reusable CloudFormation-owned resource
    are absent. The one expected residue is `ReceiptSigningKey` in KMS
    `PendingDeletion` for its seven-day window: record its exact ARN, key ID,
    scheduled deletion date, and removed alias. That deletion must not be
    canceled or reused. Do not reuse the probe receipts, configuration digest,
    or any physical ID for the final stack.
11. Recompute the final configuration digest with probes disabled, then create
    a fresh `tideproof-gate2` main stack from the exact `TemplateURL` with
    `EnableProbeFunctions=false` in the initial create. This attested stack
    must never be updated—not for parameters, tags, metadata, artifacts, or
    configuration. Any correction or change requires complete teardown and a
    fresh create. Verify every Lambda version's reported `CodeSha256`, numeric
    version ARN, monitored alias target, execution role and inline policy,
    environment, timeout, reserved concurrency, revisions, access-log
    destination, CloudFormation resource drift, and absence of every
    conditional probe resource.
12. Create one private exact deployment expectation from the reviewed
    build/upload receipts and fresh main-stack outputs. The configuration must
    bind three distinct Ed25519 public keys; the matching private key files
    must remain outside the repository, regular, and mode `0600`. As the
    generated bounded deployment-evidence collector, run:

    ```sh
    npm run gate2:aws-attest -- \
      --phase pre \
      --expectation "$EXPECTATION_PATH" \
      --configuration "$CONFIGURATION_PATH" \
      --build-receipt "$BUILD_RECEIPT_PATH" \
      --receipt-key "$PRE_RECEIPT_KEY_PATH"
    ```

    Preserve the signed private `PRE_ATTESTATION_PASS` receipt. Assume the
    generated alternate role and run:

    ```sh
    npm run gate2:aws-alternate-denial -- \
      --expectation "$EXPECTATION_PATH" \
      --build-receipt "$BUILD_RECEIPT_PATH" \
      --receipt-key "$ALTERNATE_DENIAL_KEY_PATH"
    ```

    Require a signed provider `AccessDenied` receipt bound to the exact build
    receipt and its content-addressed provider runtime. Either command failing
    is a stop. This proves neither administrator exclusion nor application
    correctness.
13. Assume only `AuthorityRaceCallerRole`. From the exact clean deployment
    checkout, run `npm run gate2:authority-race` with the numeric Authority
    version ARN, configured active-run UUID, configured race UUID, exact source
    commit, and final
    configuration digest. The evidence runner rejects endpoint, profile,
    proxy, custom-CA, Git replacement/graft/alternate, shallow-checkout, and
    tree-digest contamination; it resolves the expected role from the exact
    CloudFormation stack resource and validates the exact account plus the
    precommitted observed STS caller ARN/UserId triple before invoking Lambda.
    This binds the observed caller but does not prove a globally unique
    AssumeRole issuance when a session name can be reused. Require the later
    durable proof to report the exact configured active-run UUID. Require two
    distinct Lambda request bindings, two
    distinct CockroachDB session digests, overlapping database-clock
    intervals with positive duration and a positive intersection,
    `SERIALIZABLE` on both contenders, exactly one
    `resource_reserved`, and exactly one `resource_held_denied`. Then require
    the command's third, read-only proof invocation to observe exactly those
    two durable receipts, the denial's observed holder/fence bound to the
    winner, an initial fence of one, one winner-bound outbox intent, the same
    current holder and fence, no pending receipt, and zero protected effects
    after both database intervals but before the winner's canonical lease
    expires. The proof must consume the exact unmodified in-process race
    observation; a reconstructed observation is rejected. Preserve the
    private invocations and database receipts;
    require both durable contender results to carry one shared selected
    evidence identity and one shared non-reversible DVI authority-evidence
    binding; publish only the reviewed sanitized
    `tideproof.aws-authority-race-receipt.v6`. Any wrong-run, cross-DVI,
    sequential, ambiguous, replayed, expanded, stale, extra, or unresolved
    result is not evidence.
14. From a signed-out browser, request only the ten enumerated public `GET`
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
15. Assume only the dedicated advisory caller role. Record a denied direct
    invocation attempt for every Lambda, prove a different same-account IAM
    principal is rejected by the Boundary, then invoke the exact IAM-signed API
    route through the dedicated STS assumed-role session.
16. Preserve and reconcile the signed receipt with the asynchronous API access
    log by request ID, request time, route, status, and caller. Preserve the
    model, KMS key ARN/public-key fingerprint, signature, source, artifact,
    configuration, token, and latency bindings.
17. Re-run Gate One state hashes to prove Bedrock changed no authority,
    outbox, fence, or protected synthetic-effect state.
18. Re-assume only the deployment-evidence collector and run:

    ```sh
    npm run gate2:aws-attest -- \
      --phase post \
      --expectation "$EXPECTATION_PATH" \
      --configuration "$CONFIGURATION_PATH" \
      --build-receipt "$BUILD_RECEIPT_PATH" \
      --receipt-key "$POST_RECEIPT_KEY_PATH" \
      --pre-receipt "$PRE_RECEIPT_PATH" \
      --alternate-denial "$ALTERNATE_DENIAL_PATH"
    ```

    Require signed `PASS`, identical pre/post stack and function deployment
    digests, all five numeric versions and revisions unchanged, all monitored
    alias targets unchanged, stable function/evidence/alternate role IDs,
    exact zero-extra policy censuses, and fresh stack/resource drift status
    `IN_SYNC`; also require the exact route/integration/stage census and newest
    active API deployment to remain stable and `DEPLOYED`. A stable attestation
    does not prove administrator exclusion, canary
    correctness, CockroachDB concurrency, or public-release readiness.

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
