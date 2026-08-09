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
  digests internally, reads one exact ProofToAct-owned Secrets Manager ARN at
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
  transport timeout instead of ProofToAct's structured signed failure body.
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
partial-clone or promisor configuration and markers, an incomplete reachable
object closure, path escape, untracked inputs, and unsupported loaders fail
closed. The source closure is bundled only after those checks. The bundle is
verified in a fresh empty repository before local import, and the imported
checkout must remain full, standalone, remote-free, alternate-free, and byte
identical. Only this Git bundle materialization and import path is network-free;
the later `npm ci --ignore-scripts` may contact the pinned
`registry.npmjs.org` registry. Registry availability and integrity
remain outside this local source claim. On that commit it bundles each runtime
role separately into six two-entry, stored ZIPs
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

- requires the raw local Git configuration to match a narrow fresh-clone
  allowlist, the exact public ProofToAct origin, `main`, a clean single-root
  tree, and `HEAD == origin/main`; each readiness fetch names the pinned HTTPS
  URL and exact refspec directly, and repeats before and after the checks so a
  moving release target fails closed;
- performs a lockfile install with dependency lifecycle scripts disabled,
  then runs the exact-release provenance control in a caller-bound no-fetch
  mode over the full single-root Git ancestry, object integrity, replacement
  refs, legacy grafts, alternate object databases, tracked file modes,
  installed package identities, dependency inventory, bundle notice inputs,
  the current-surface rights receipt, and the bounded static accessibility
  receipt;
- runs the full test suite and a zero-vulnerability dependency audit;
- creates a fresh exact-head Gate Two build and independently rechecks the
  package lock, tracked templates, six source files, six artifact hashes,
  Lambda `CodeSha256` values, sizes, immutable key recommendations, exact
  bundled-package union, notice bytes, and two-entry stored-ZIP structure;
- invokes the account-safety preflight below and binds its `PASS` receipt to
  the same commit and tree; and
- rechecks the official upstream and clean tree before emitting
  `tideproof.gate2.aws-readiness.v1` with status `PASS`.

The readiness wrapper passes its already-fetched exact commit and tree through
`--readiness-fetched-official-main`. The nested provenance process must verify
that binding before and after its work, perform zero network fetches, and emit
the distinct `READINESS_FETCH_BOUND_PASS` status; an ordinary standalone
`npm run release:provenance` still performs its own before-and-after fetches and
emits `PASS`. The readiness validator rejects that standalone status, so only
the wrapper's two explicitly pinned and sanitized fetches can establish
upstream freshness for this combined gate.

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
It does not inherit the invoking shell's `PATH`: unauthenticated children use
only `/usr/bin:/bin`, while the authenticated macOS child additionally allows
`/opt/homebrew/bin` so the reviewed Homebrew AWS CLI can be located (Linux
allows `/usr/local/bin`). These directories are a fixed platform allowlist;
caller-provided path entries are never retained.

The readiness Git runner disables system, global, environment-provided, and
replacement-object configuration. It rejects unreviewed repository-local or
worktree configuration, requires the checkout root, Git directory, common
directory, object directory, and index to resolve to the one ordinary clone,
and rejects replacement refs, legacy grafts, alternate object databases,
sparse checkout, assume-unchanged or skip-worktree entries, transformed tracked
bytes, and hidden untracked files. Fetches do not use the configurable `origin`
transport: they name `https://github.com/Flash-Bri/prooftoact.git` directly,
clear credential helpers, askpass, proxy, and extra-header settings, require
certificate verification with TLS 1.2 or newer, disable submodule recursion,
and update only the reviewed `origin/main` tracking ref.

The standalone preflight also resolves Git independently of caller `PATH`.
Only the root-owned `/usr/bin/git` system executable (or the same approved
Linux package target) is accepted; it must be a regular executable with no
group/world write bits. Git receives a fixed `/usr/bin:/bin` path, no system or
global or command-environment configuration, no terminal prompting, disabled
hooks, file-system monitoring, checkout transforms, and untracked cache, plus
an explicit all-untracked status request. Its source binding then runs the same
single-root layout, local-config, replacement, graft, alternate-object, index-
flag, tracked-byte, and sparse-checkout invariants used by the exact build. A
caller-supplied Git wrapper, configuration, alternate index, or repository
indirection cannot provide the accepted checkout identity used by this gate.

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

Before the command makes any AWS call, the authenticated operator lane must
provide four independently reviewed, nonsecret expectations:

- `AWS_EVIDENCE_EXPECTED_ACCOUNT_ID`;
- `AWS_EVIDENCE_EXPECTED_PREFLIGHT_PRINCIPAL_ARN`;
- `AWS_EVIDENCE_EXPECTED_PREFLIGHT_CALLER_ARN`; and
- `AWS_EVIDENCE_EXPECTED_PREFLIGHT_CALLER_USER_ID`.

The same lane must use temporary STS assumed-role credentials: an
`AWS_ACCESS_KEY_ID` beginning with `ASIA`, `AWS_SECRET_ACCESS_KEY`, and a
nonempty `AWS_SESSION_TOKEN`. Static `AKIA` credentials, tokenless
credentials, IAM-user principal expectations, and IAM-user caller identities
are rejected before the first AWS request. The standalone command also
ignores caller `PATH`, resolves the AWS CLI from a fixed platform allowlist,
and executes only the trusted absolute package real path. A direct regular
wrapper in a bin directory is rejected. On the current macOS lane,
`/opt/homebrew/bin/aws` must be a symlink into Homebrew's `awscli` Cellar; the
resolved executable must be owned by the current user, be a regular executable,
and have no group/world write bits. The Linux lane requires the corresponding
root-owned `/usr/local/aws-cli` package target. This is an owner, mode, and
location control, not a byte hash or independent package-signature attestation.

The Cost Explorer census is bounded to exactly one CLI request: automatic CLI
pagination is disabled, SDK retries are capped at one total attempt, and the
response is rejected if a `NextPageToken` property is present, including an
empty one. The explicitly priced Cost Explorer portion is therefore bounded to
one `GetCostAndUsage` request. The operational approval cap for the complete
preflight is at most `$0.02`; operators must reconfirm current pricing for that
request and the fixed read-only control-plane census before a live run. The
gate reserves that full allowance and requires observed AWS spend plus `$0.02`
to remain strictly below both the effective AWS and total-project ceilings;
exactly `$13.12` observed AWS spend therefore fails. The source contract bounds
the complete runtime call inventory and Cost Explorer call count but does not freeze or
independently verify AWS pricing or claim every metadata request is unmetered.

The manual-only `AWS OIDC Identity Bootstrap` workflow provides a separate
short-lived identity bootstrap for the protected `aws-preflight` environment.
It checks out no repository code, requests a GitHub OIDC token directly,
requires the exact `Flash-Bri/prooftoact` repository, protected-environment
subject, `refs/heads/main`, manual event, workflow reference, and GitHub-hosted
runner claims before STS. The human-supplied exact official-main commit must
also equal the GitHub event SHA and both OIDC source-SHA claims. The runner must
be non-root. The decoded OIDC header and payload stay in `0600`
temporary files and are validated locally without logging the token. The
configured account secret must match the independently stored protected
environment variable `AWS_APPROVED_ACCOUNT_ID_SHA256`; this separates the
approved account binding from the role/account secret pair, although an
environment administrator can still change that variable. The role is exactly
the pathless `ProofToActPreflight` role and the 900-second session is exactly
`release-proof`.

The workflow accepts only the root-owned GitHub-runner AWS CLI symlink whose
real path is an executable, non-group/world-writable official
`/usr/local/aws-cli/v2/<version>/dist/aws` package file. It makes only the two
STS identity calls, validates the exact assumed-role ARN and session, and
requires the `AssumedRoleId` returned by `AssumeRoleWithWebIdentity` to equal
the `UserId` returned by `GetCallerIdentity`. It then symmetrically encrypts
the caller-only JSON receipt before uploading it as a one-day artifact. OIDC
and AWS credentials, the account, role, ARN, token, passphrase, and raw receipt
are never intended for logs or artifacts. This workflow proves only that the
configured GitHub environment can obtain the expected temporary identity; it
does not run the account-safety preflight, call paid AWS services, upload a
deployment artifact, or authorize deployment.

Both OIDC receipt lanes accept only canonical unpadded Base64URL encoding of
exactly 32 CSPRNG-generated bytes as the environment-scoped encryption secret;
the generation, custody, and residual human-review gates are specified in
`docs/AWS_OIDC_PREFLIGHT.md`.

The separate source-only OIDC account-preflight lane is specified in
`docs/AWS_OIDC_PREFLIGHT.md`. It uses a different protected environment,
`aws-read-only-preflight`, and the exact pathless
`ProofToActReadOnlyPreflight/read-only-preflight` identity. Its role template
allows only the existing preflight reads plus bounded region and Bedrock
service-quota metadata checks, then explicitly denies every other AWS action.
The workflow rechecks the account digest, non-root runner, 900-second temporary
credentials, exact official-main commit and clean tree, `us-east-1`, cost
limits, stack absence, encrypted sanitized evidence, and bounded timeouts. It
does not create the OIDC provider or role, configure GitHub, mutate AWS, deploy,
invoke a model, or grant deployment authority. Provider setup and execution
remain separate human gates, and the still-missing protected environment value
`AWS_APPROVED_ACCOUNT_ID_SHA256` must not be embedded in source.

CloudShell is therefore an optional authenticated operator surface, not a
release dependency. An accepted CloudShell run or the separately protected
OIDC read-only run may supply the same underlying account-safety evidence only
when every identity, account, region, cost, source, privacy, and receipt gate
passes. Neither surface changes the separate upload/deployment authorization,
live evidence, rollback, teardown, or final-review requirements.

Do not discover or infer these values inside the preflight. The command first
rejects a missing, malformed, or internally inconsistent expectation set. It
then makes exactly one STS `GetCallerIdentity` request and validates that
response against the precommitted set before any CloudFormation, Budgets,
Cost Explorer, S3, or Bedrock read. A mismatch stops the run without gathering
account-specific evidence. Credentials and these expectations belong only in
the explicitly authenticated operator lane; they must not be written to
`.env`, source, logs, receipts, or shell history.

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
  whose greater value plus the full `$0.02` preflight allowance remains
  strictly below the `$13.14` effective AWS ceiling, while the recorded
  `$11.86` domain expense plus observed AWS plus that allowance remains
  strictly below the `$25` total-project cap;
- an encrypted, versioned, bucket-owner-enforced private artifact bucket with
  all public-access blocks and exactly the reviewed TLS-only deny policy,
  with no additional delegated bucket-policy statements; and
- no active `prooftoact-gate2` main stack and no active former-working-name
  `tideproof-gate2` main stack. The dual absence check prevents a rename from
  creating two independent authority deployments.

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

### Caller identity was validated after account-specific reads

- Root cause: the collector fetched STS identity first but deferred exact
  caller validation to final receipt validation, after CloudFormation, budget,
  cost, bucket, and model reads.
- Why it was missed: snapshot fixtures proved that the final validator rejected
  the wrong identity, but no control observed the provider-call sequence.
- Earliest detection: return a mismatched STS caller from an injected provider
  and require that the request log contain only `GetCallerIdentity`.
- Repair: validate the four precommitted expectations before STS, then validate
  the actual STS response immediately before any account-specific read.
- Regression/preventive control: the preflight exposes injectable command and
  provider readers only for deterministic tests; the focused test requires a
  wrong-account caller to stop after the single STS request.
- Verification: focused source tests exercise a self-consistent role session,
  a cross-account expectation, and a wrong-account STS response. Live AWS
  execution remains pending.
- Residual risk: operator-supplied expectations and credentials still require
  an independently controlled authenticated lane; this change does not prove
  their provenance or any AWS service state.
- Claim impact: ProofToAct may claim source-level fail-closed caller ordering.
  It adds no live AWS, identity, spend, deployment, or availability claim.

### IAM-user expectations accepted non-AWS syntax

- Root cause: the shared caller validator allowed any nonempty IAM-user ARN
  suffix and any 8-to-256-character user ID.
- Why it was missed: existing positive fixtures exercised only simple user
  names, while negative controls concentrated on roles, accounts, and exact
  post-STS identity mismatches.
- Earliest detection: submit a user ARN containing a space or a user ID that
  lacks the AWS IAM-user principal-ID prefix before the injected AWS reader.
- Repair: constrain IAM-user paths and names to bounded AWS syntax and require
  an `AIDA` uppercase-alphanumeric principal ID of 16 to 128 characters.
- Regression/preventive control: malformed ARN and user-ID variants must fail
  with an injected AWS-call count of zero.
- Verification: focused source tests cover both malformed variants and the
  existing exact IAM-user success case. Live AWS execution remains pending.
- Residual risk: source validation cannot prove that operator expectations
  came from an independent trusted channel or remain current.
- Claim impact: the source may claim syntactic expectation rejection before
  STS; it adds no live identity or authorization claim.

### Call-order regression test was outside exact receipts

- Root cause: the preflight source was hash-bound, but its new focused test was
  covered only by the broad `test/*.test.js` runner.
- Why it was missed: a passing aggregate count showed the test ran, but deleting
  a whole test file would silently reduce the glob without invalidating either
  the proof or security receipt.
- Earliest detection: compare the new control path with the exact security and
  proof inventories before accepting its receipt.
- Repair: inventory the preflight and shared identity tests in the security
  manifest and bind the preflight test directly in the proof manifest.
- Regression/preventive control: any byte change or removal now invalidates an
  exact manifest hash and the proof artifact-count control.
- Verification: focused tests plus proof and security verifiers must pass from
  the same clean commit.
- Residual risk: test execution still depends on hosted and local runner
  integrity; exact release provenance remains a main-only gate.
- Claim impact: the receipt may claim the named regression controls were the
  reviewed bytes, not that source or tests are exhaustive.

### Repository-local Git metadata could falsify source binding

- Root cause: the standalone preflight disabled ambient system and global Git
  configuration but still accepted repository-local worktree, index, and
  object indirection, while readiness fetched the configurable `origin` and
  requested a short status without forcing all untracked paths. A later hosted
  runner failure exposed a narrower compatibility case: Git 2.54 writes
  `.git/config.worktree` while `actions/checkout` disables sparse checkout,
  then checkout removes `extensions.worktreeConfig` but leaves exactly three
  inactive false-valued settings behind. The generic object-path rejection
  first stopped the nested brand verifier, then a hosted rerun exposed the same
  strict-layout failure at the rights verifier. Rights was only the first of
  several strict callers: privacy, the exact build, main-only provenance, and
  readiness would have failed serially on the same residue. The proof wrapper
  also discarded the brand verifier's exact bounded error code. The first
  diagnostic repair accepted any short
  uppercase-and-underscore token, which could reflect an AWS-shaped identifier
  or arbitrary attacker-controlled token that happened to match that syntax.
- Why it was missed: executable and process-environment isolation tests covered
  caller-selected wrappers and environment variables, but not hostile
  `.git/config`, replacement refs, grafts, alternates, index flags, or transport
  settings stored inside an otherwise ordinary-looking checkout. The original
  fresh-clone fixture also modeled only GitHub's `.git`-suffixed canonical HTTPS
  spelling, while an official Actions clone records the same origin without the
  suffix. The first runner correction did not yet reproduce the exact
  `gc.auto=0` entry that `actions/checkout` leaves after its temporary credential
  configuration is removed. The next correction still did not reproduce the
  runner's ordered `git sparse-checkout disable` and
  `extensions.worktreeConfig` removal on Linux Git 2.54. Its diagnostic test
  covered control characters and overlength text but not an untrusted
  regex-shaped token within the length bound. Treating each downstream verifier
  as a separate compatibility exception would also have weakened strict local,
  build, provenance, readiness, and provider lanes.
- Earliest detection: set `status.showUntrackedFiles=no`, add an untracked file,
  mark a tracked file skip-worktree or assume-unchanged, use a linked worktree
  or alternate object database, or add a proxy, credential helper, TLS override,
  or URL rewrite to local configuration. For the hosted compatibility case,
  execute the exact checkout cleanup sequence and run the complete ordered CI
  command sequence, including rights, privacy, tests, and the exact build. Pass an
  AWS-shaped uppercase token through the nested diagnostic boundary as a
  negative control; any reflection is a release blocker.
- Repair: require one exact ordinary repository layout and index, validate
  tracked worktree bytes, reject every listed metadata and index indirection,
  allow only the expected fresh-clone local configuration, accept exactly the
  two official public HTTPS origin spellings with and without `.git` (without
  normalization), optionally accept only the conservative no-network checkout
  setting `gc.auto=0`, and fetch the explicit official HTTPS URL with sanitized
  credential, header, proxy, and TLS options. Credential, `includeIf`, proxy,
  header, URL-rewrite, and every other local configuration remain rejected.
  Default brand, proof, rights, privacy, exact-source, readiness, preflight, and
  build validation all reject every `.git/config.worktree`. A single dedicated
  GitHub-hosted Linux CI step runs directly through Node after pinned Node setup
  and before dependency installation or any verifier. It requires the exact
  repository ID, repository name, official server/API URLs, CI workflow/job,
  PR-merge or main-push ref, real workspace, and `GITHUB_SHA == HEAD`, while
  clearing and rejecting Node preload/search-path inputs and disabling optional
  Git locks. If the checkout is already strict, the step performs no mutation
  and still proves a clean exact checkout. Otherwise it accepts only the exact
  observed LF-terminated Git 2.54 bytes for the three false-valued settings in
  an effective-UID/effective-GID-owned, one-link, non-symlink `0600` or `0644`
  regular file. The repository root and `.git` directory must have that same
  effective identity. It rejects
  an active extension, sparse file, include, extra entry, noncanonical bytes,
  unsafe mode, object indirection, non-stage-zero index, non-`H` index flag,
  dirty or hidden untracked path, or changed source identity. With a no-follow
  descriptor held open, it rechecks device, inode, size, bytes, owner, mode,
  link count, common config, index, status, `HEAD`, and tree after the testable
  pre-unlink boundary and immediately before unlinking only
  `.git/config.worktree`; any tracked-byte, index-flag, staged-index, ref, tree,
  ownership, or common-config drift fails while preserving the residue path.
  The held descriptor must report zero links afterward. Default strict layout
  and the complete clean-checkout control then run again and every pre/post
  state digest must match. The nested proof
  wrapper exposes only an exact member of a fixed reviewed brand/exact-Git
  error-code allowlist or `UNCLASSIFIED`; syntax, length, or a broad prefix can
  never grant reflection.
- Regression/preventive control: exact-Git, standalone-preflight, readiness,
  proof, cost, claims, and security controls hash-bind the implementation and
  adversarial tests; readiness repeats both exact checkout verification and the
  explicit official fetch before accepting its final receipt. The compatibility
  parser appears at one production call site, the pre-verification normalizer;
  no release, build, readiness, preflight, brand, proof, or provider caller can
  opt into it.
- Verification: focused tests cover both accepted official origin spellings;
  accept only `gc.auto=0` while rejecting alternate or duplicate garbage-
  collection settings; reject credentialed, rewritten, and near-miss origins;
  and cover hidden untracked files, both hidden index flags, linked worktrees,
  replacement refs, alternates, local transport overrides, and the exact fetch
  arguments. Dedicated residue tests reject every missing field, duplicates,
  true or other wrong values, extras, includes, symlinks, an active extension,
  and an active sparse-checkout file while preserving every rejected target's
  path identity and bytes. PR and main-push context tests cover mutation and
  strict no-op paths; wrong repository, job, ref, SHA, runner, mode, link, and
  Node environment inputs fail before deletion, and a pathname replacement is
  detected by the device/inode recheck. Deterministic pre-unlink tests mutate a
  tracked byte, index flag, staged index, `HEAD`/ref/tree, and common config;
  every case fails before deletion with the candidate inode, bytes, and path
  preserved. Workflow tests require the exact order
  checkout, Node setup, normalization, dependency install, then proof, with no
  continue-on-error and no other production opt-in. Diagnostic tests retain one valid bounded
  brand code and one valid bounded exact-Git code while proving an AWS-shaped
  uppercase identifier, arbitrary uppercase-and-underscore text, forty `A`
  characters, control-character text, and overlength text all become
  `UNCLASSIFIED`. The exact Linux Git 2.54 pull-request merge sequence must pass
  the direct normalization step followed by the complete CI command sequence.
  Live GitHub execution remains an exact-main acceptance gate.
- Residual risk: these controls do not establish a hostile-kernel boundary,
  independently certify the installed Git/libcurl/CA toolchain, or eliminate a
  same-UID process or kernel race outside the held-descriptor, inode, byte, and
  pre/post state checks. The workflow step reduces but cannot eliminate that
  hostile-host boundary; it is not safe for self-hosted runners. The narrow
  parser trusts only the reviewed bytes and semantic meaning of the three false
  values in the tested Git version; every other worktree-local shape remains
  fail-closed. New diagnostic codes require an explicit reviewed allowlist
  change; unknown codes intentionally lose detail as `UNCLASSIFIED`.
- Claim impact: source may claim bounded fail-closed checkout and fetch
  invariants, not universal host integrity or live upstream availability.

### Nested provenance repeated a less constrained fetch

- Root cause: readiness invoked the standalone provenance command after its
  own hardened fetch, so provenance silently repeated two older fetches through
  the configurable `origin` transport.
- Why it was missed: the readiness integration runner treated the nested npm
  command as opaque and counted only the wrapper's visible Git calls, while the
  provenance tests verified standalone behavior in isolation.
- Earliest detection: run the complete provenance function with the exact
  commit/tree binding used by readiness and assert that its injected command
  log contains no fetch, while the wrapper still contains exactly two fetches.
- Repair: add a canonical readiness-only already-fetched mode, bind it to the
  wrapper-verified commit and tree, skip both nested fetches, and require the
  distinct `READINESS_FETCH_BOUND_PASS` status and bounded claim text.
- Regression/preventive control: provenance tests exercise the complete bound
  path with zero fetches and retain the two-fetch standalone check; readiness
  tests require the exact bound invocation and only the two pinned, sanitized
  wrapper fetch argument sets.
- Verification: focused source tests and the hash-bound proof and security
  receipts cover both sides of the delegation. No live GitHub fetch was run in
  this repair worktree.
- Residual risk: standalone provenance deliberately retains its independent
  fetch behavior, and these process-level controls do not establish a
  hostile-kernel or compromised Git/toolchain boundary.
- Claim impact: readiness may claim that every fetch in its combined flow uses
  its reviewed official transport; this adds no live upstream-availability or
  hosted-runner claim.

### Release Git children inherited caller selection and repository hooks

- Root cause: standalone provenance and the authenticated authority-race
  runner still launched Git through a name selected by caller `PATH`; several
  related release and evidence paths also omitted the shared invariant that
  disables repository hooks. A repository-local `reference-transaction` hook
  could therefore run during a ref update even after earlier source checks.
- Why it was missed: prior adversarial coverage proved exact checkout content,
  rejected ambient Git object indirection, and hardened the readiness wrapper,
  but did not execute the standalone provenance or authority-race Git child
  with both a hostile `PATH` and a harmless executable reference hook.
- Earliest detection: prepend a sentinel Git wrapper to caller `PATH`, install
  a sentinel `.git/hooks/reference-transaction`, perform a bounded ref update
  through each runner, and require both sentinels to remain absent.
- Repair: all inventoried release/evidence Git children now resolve the shared
  trusted absolute Git executable, use the fixed sanitized Git environment,
  prepend the complete shared invariant argument set, and validate the exact
  repository layout before source-sensitive work. Fetching uses the explicit
  official HTTPS URL, a fixed refspec, no tags, and no submodule recursion.
- Regression/preventive control: dedicated provenance and authority-race tests
  prove that hostile `PATH` lookup and `reference-transaction` hooks are never
  invoked. Complete provenance still performs exactly two standalone official
  fetches, while readiness-bound provenance performs zero nested fetches.
- Verification: the hostile-path/hook tests, complete provenance fetch-count
  tests, focused source suites, full suite, exact build, and hash-bound proof
  and security verifiers must pass at one clean candidate commit.
- Residual risk: trusted-path and hook suppression are process controls, not a
  hostile-kernel boundary or independent certification of Git, the filesystem,
  DNS, TLS, or the upstream host. Same-identity mutation between repeated
  checks remains outside the claim.
- Claim impact: the source gates may claim reviewed executable selection and
  hook suppression for these bounded Git children. This grants no AWS,
  CockroachDB, deployment, publication, or final-release authority.

### Exact builder used a now-forbidden linked worktree

- Root cause: the exact artifact bootstrap still created its isolated checkout
  with `git worktree add`, while the shared exact-Git control now correctly
  rejects linked worktrees whose Git directory, common directory, object store,
  and index do not belong to one ordinary repository root.
- Why it was missed: focused source tests exercised the new layout rejection
  and the outer builder's post-build ordering separately, but no test executed
  the complete builder after the single-root invariant was introduced.
- Earliest detection: run `npm run build:gate2` from the clean rebased source
  candidate before any provider credential, upload, deployment, or public
  action. The child stops at `EXACT_GIT_SOURCE_LAYOUT` before artifact output.
- Repair: materialize a private, full-history Git bundle from the repeatedly
  validated and closure-complete source, initialize a fresh repository under
  the trusted temporary root, verify the bundle there before import, fetch only
  that local bundle, detach the exact source commit, and apply the full
  single-root, object-store, config, index, byte, closure, and tree validation
  before dependency installation or generation. The Git bundle
  materialization and import perform no network fetch, clone, hardlink,
  alternate-object, or linked-worktree operation. The subsequent pinned
  `npm ci --ignore-scripts` step may use the npm registry and is not part of
  that network-free Git claim.
- Regression/preventive control: the integration test uses a source repository
  that rejects unapproved URL, helper, partial-clone, and promisor
  configuration; verifies the bundle in the empty destination before import;
  proves the destination has no remote, alternate, promisor, or shallow state
  and has exact bytes; rejects a group/world-readable temporary root; and
  forbids reintroducing `worktree add` in the outer builder.
- Verification: privacy runs first on the final history; the exact build and
  reproduction, focused exact-Git/AWS/provenance/security tests, full suite,
  hash-bound release verifiers, syntax checks, and strict object/topology checks
  must then pass from the same clean commit.
- Residual risk: the control trusts the reviewed root-owned Git, Node, and npm
  toolchain plus the host kernel and filesystem. It is not a hostile-host proof
  and does not validate AWS, CockroachDB, registry integrity, deployment, or
  public behavior.
- Claim impact: this restores a local source/artifact gate without adding any
  live AWS, provider, deployment, publication, or submission claim.

### Partial-clone state could lazily hydrate missing source history

- Root cause: the exact-source boundary rejected shallow repositories and
  alternate object stores but did not reject partial-clone/promisor
  configuration or pack markers, disable lazy fetching, or prove that every
  object reachable from the exact source commit already existed locally. A
  later object read or bundle creation could therefore ask a configured helper
  or transport to hydrate a missing historical object.
- Why it was missed: the prior adversarial fixtures covered replacement refs,
  grafts, alternates, linked worktrees, local URL rewrites, and index flags but
  always began with a complete ordinary object database.
- Earliest detection: delete a historical reachable blob from a two-commit
  fixture, add partial-clone/promisor configuration plus a sentinel upload-pack
  helper and `.promisor` marker, then run the exact-checkout control before any
  blob, tree, history, build, readiness, or provenance read.
- Repair: set `GIT_NO_LAZY_FETCH=1` in every sanitized Git child environment;
  read the literal local config file with includes disabled before the first
  object read; accept only the exact ordinary-clone keys and values; reject
  promisor markers, shallow state, alternates, grafts, and object-store
  indirection; and prove the complete unique reachable object closure with
  `rev-list`, batched `cat-file`, and strict `fsck` before bundle creation.
  The bundle must verify inside a fresh empty repository before local import,
  after which the destination repeats closure, no-remote, no-alternate,
  no-promisor, non-shallow, exact-tree, index, and worktree-byte checks.
- Regression/preventive control: the missing-blob fixture asserts fail-closed
  rejection at configuration, promisor-marker, and closure layers while the
  sentinel helper remains uninvoked, the missing blob remains absent, and the
  object inventory remains byte-for-byte unhydrated. Security and proof
  manifests bind the implementation, fixture, and bounded documentation.
- Verification: privacy must run first after the final commit, followed by the
  exact build, two-run reproduction, focused and full suites, all release
  verifiers, syntax checks, dependency audit, and strict Git fsck/topology from
  the same clean exact commit.
- Residual risk: these controls trust the reviewed Git executable, process
  environment semantics, host kernel, and filesystem against same-identity
  races. The later `npm ci --ignore-scripts` may contact the pinned npm
  registry; registry availability and integrity are not established here.
- Claim impact: only Git bundle materialization/import may be described as
  network-free and locally closure-complete. This adds no live provider,
  deployment, publication, or final-release claim.

## Live acceptance sequence

1. Re-run all local tests, syntax checks, dependency audit,
   `npm run privacy:verify`,
   CloudFormation lint, and generated-template equality.
2. Commit the accepted local candidate.
3. Build from that clean commit.
4. Reuse the prerequisite bootstrap stack under its preserved legacy physical
   name. Do not update it merely to change descriptions or tags. Verify its
   account-wide $15 budget and $1/$5/$10 actual plus $15 forecast notifications
   are present before its private, encrypted, versioned artifact bucket is
   accepted.
5. Run `npm run gate2:aws-readiness` through either an accepted authenticated
   operator lane or the separately protected read-only OIDC lane and require
   the combined `tideproof.gate2.aws-readiness.v1` `PASS`; independently
   revalidate current Nova Micro pricing. CloudShell availability is optional.
   If the selected authenticated lane, billing data, the official upstream, or
   any required read is unavailable, stop without uploading. A read-only OIDC
   receipt still requires private review and does not authorize step 6 or any
   later provider mutation.
6. Prepare one fresh synthetic Gate Two tenant/run/incident/evidence/resource
   tuple through the reviewed CockroachDB owner lane. Create one
   ProofToAct-owned Secrets Manager secret whose JSON has exactly the
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
   disposable `prooftoact-gate2-probe` stack from its exact `TemplateURL` with
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
    a fresh `prooftoact-gate2` main stack from the exact `TemplateURL` with
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
    `tideproof.aws-authority-race-receipt.v7`. Before the durable proof, invoke
    the winning contender once more and require an exact `operation_replay`,
    then invoke the dedicated changed-input probe under that same operation ID.
    In one `SERIALIZABLE` transaction, the probe must first resolve and
    normalize the exact original durable receipt, then require only the spend
    call's SQLSTATE `22000` digest mismatch to become the sanitized
    `OPERATION_DIGEST_MISMATCH` denial. A missing or drifted original receipt
    fails before spend; an unexpected spend return rolls back before commit.
    Require five distinct Lambda request IDs and five distinct AWS Invoke
    request IDs across both contenders, replay, changed input, and proof. Any
    wrong-run, cross-DVI, sequential,
    ambiguous, replay-drifted, changed-input-accepted, expanded, stale, extra,
    or unresolved result is not evidence.
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
