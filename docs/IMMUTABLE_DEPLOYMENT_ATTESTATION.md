# Immutable deployment and attestation boundary

Status: `SOURCE_CLOSED_PROVIDER_VALIDATION_PENDING`

This control closes a source-level deployment identity gap. It does not prove
that an AWS deployment exists, that an administrator cannot change the
account, or that any live provider behavior passed. Credentialed pre/post
attestation, the alternate-principal denial, component canaries, drift review,
and private human review remain required.

## Accepted finding

- **Root cause:** a clean-worktree check and source hashes did not make the
  builder itself or every bundler read immutable, and invoking a stable Lambda
  alias left a mutable routing pointer in the runtime path. The first
  attestation draft also trusted unsigned local JSON, inspected only one named
  inline policy, omitted managed policies, permissions boundaries, role IDs,
  Lambda layers and other configuration surfaces, and collected a sequential
  provider snapshot without a revision fence. The first exact-worktree repair
  still copied mutable ambient dependencies, the first live runner accepted a
  shallow self-consistent build receipt, and stack drift was not sufficient to
  prove that separately queried function ARNs were the stack's physical
  resources.
- **Why it was missed:** the original controls checked the repository before
  and after generation and published immutable Lambda versions, but treated
  the clean checkout and `proof` alias as sufficient deployment identity.
  They did not model a concurrent local edit during bundling, an import that
  escaped to the host filesystem, an alias or role replacement between
  observations, an expectation rewritten independently of the reviewed build,
  a fabricated pre/denial receipt, a symlinked ignored output parent, or an
  API control plane whose desired routes had not reached the active stage as
  separate substitution paths. Tests
  also omitted tampered dependency bytes, a fabricated-but-hash-bound receipt,
  and a same-account shadow function substituted for one stack resource.
- **Earliest detection point:** the deterministic artifact builder and
  generated-template contract. Both can reject mutable inputs before upload;
  a provider snapshot can then reject deployment drift before any canary.
- **Repair:** the public build command rejects a dirty or contaminated source
  checkout, creates a detached exact-commit worktree, executes the committed
  builder there, runs `npm ci --ignore-scripts` from the lockfile with a new
  isolated cache and distinct empty user/global npm configuration paths,
  rejects installed-tree symlinks outside npm's unused root `.bin` shims,
  excludes those shims under a fixed `/usr/bin:/bin` build `PATH`, hashes every
  remaining installed file byte and mode, and records the Git/Node/npm
  toolchain plus every build-control and project blob.
  The distinct paths prevent npm from rejecting a duplicated configuration
  source while still excluding ambient npm configuration. The esbuild
  loader rejects every non-dependency path outside that worktree and gives
  raw Git inputs repository-relative virtual identities so temporary worktree
  names cannot change bundle bytes. Runtime
  roles, API integrations, permissions, probe targets, and authority-race
  invocation target numeric Lambda versions. `proof` aliases remain monitored
  pointers only. Three distinct Ed25519 public keys are committed into the
  configuration digest before deployment; their separately protected private
  keys authenticate the pre snapshot, post snapshot/final pair, and
  alternate-principal denial. The validator recomputes caller/context
  bindings, fully validates and reproduces the raw build receipt byte-for-byte
  from the exact clean commit in both provider-credentialed runners before any
  provider query, rejects symlinked path components before copying or loading
  ignored artifacts, and binds the
  expectation to that receipt and the configuration hashes. It enumerates
  every inline and attached role policy plus permissions
  boundary, preserves role IDs, binds security-relevant Lambda configuration,
  binds each attested function, version, alias, and role to its exact
  CloudFormation physical resource. It directly enumerates the API,
  integrations, routes, stage, paginated deployments, and the stage's active
  deployment; requires auto-deploy to be disabled and the stage to name the
  exact CloudFormation deployment physical ID created after every route, then
  requires a never-updated `CREATE_COMPLETE` stack and proves that explicit
  deployment was created during that stack creation and is the newest
  successful deployment with no status warning; rejects CORS, shadow routes,
  integrations, stages, request/response rewrites, and a substituted access-log
  destination; enumerates aliases, function URLs, event-source mappings, and
  function/role tags; and requires two identical full provider observations
  per snapshot.
- **Preventive controls:** the build receipt records every exact Git input's
  path, Git blob ID, and SHA-256, including the outer and inner builders. Its
  dependency-tree and toolchain snapshots make ambient changes receipt-visible,
  while the live runner independently reproduces the exact receipt. A
  bounded evidence-collector role trusts one exact IAM principal and has no
  invoke, model, secret-read, or signing capability. A dedicated alternate
  role's only positive permission is `sts:AssumeRole` on that collector; its
  complete policy is attested before its provider `AccessDenied` can count.
  Every role must have exactly one expected inline policy, zero attached
  managed policies, no permissions boundary, the expected trust, and the same
  stable role ID before and after canaries. Layers, filesystem mounts, VPC,
  KMS environment encryption, dead letters, runtime, handler, logging,
  tracing, signing metadata, concurrency, revisions, versions, and aliases are
  bound or rejected. AWS does not expose resource scoping for
  `lambda:ListEventSourceMappings`, so the collector has one explicitly
  reviewed account-wide read for that action; reviewed code supplies each of
  the five exact function names and the signed snapshot accepts no mapping for
  those functions. This is a read-capability exception, not an account-wide
  Lambda inventory claim.
- **Verification:** focused tests substitute dirty working-tree bytes, reject
  untracked and escaped paths, tamper an installed dependency, reject an
  installed-tree symlink outside the unused root shim boundary, prove that
  boundary excludes only `.bin`, reject temporary-worktree path leakage, reject alias
  invocation targets, fabricate or stale the exact build receipt, substitute a
  shadow function, shadow access-log destination, permissive CORS, pending or
  failed/newer API deployment, hidden alias, function URL, event source, tag,
  or fabricated provider runtime; fabricate unsigned
  receipts, attach `AdministratorAccess`, add an extra inline policy and
  Lambda layer, replace the evidence role, break the observation fence, and
  mutate every attested deployment field. The full source security, proof,
  provenance, readiness, artifact-integrity, and hosted CI gates must still
  pass on the exact merged commit.
- **Residual risk:** AWS evidence collection and its deny control are not yet
  run. CloudFormation drift support, IAM/Lambda response shapes, the external
  Ed25519 key-custody procedure, and provider runtime-version behavior must be
  verified in the approved account. The collector and signature keys are
  evidence trust roots, not administrator-exclusion boundaries; account
  administrators and higher-level policy owners remain outside this claim. A
  stage-three census covers the five primary runtime functions, their shared
  roles, and the two evidence roles; conditional probe-function configuration
  remains stage-four provider evidence. A stable pre/post snapshot does not prove
  application correctness, CockroachDB concurrency, availability, or release
  safety. The build receipt measures the selected Node, npm, esbuild, Git, and
  installed dependency bytes, but does not independently certify those local
  binaries. A process with the same operating-system identity could still
  attempt a transient edit-and-restore between checks; detached exact-Git blob
  reads, component-walk path checks, receipt reproduction, and two provider
  observations narrow that risk but do not create a hostile-host boundary.
- **Claim impact:** source wording may say that the candidate builds project
  inputs from exact Git blobs, invokes numeric Lambda versions, and contains a
  fail-closed pre/post attestation contract. It must not say that live AWS
  deployment identity, alternate-principal denial, administrator exclusion,
  canary stability, or production security has been proven.

## Accepted nested provenance runner finding

- **Root cause:** the official-main readiness wrapper launched its child npm
  process through the exact invoking npm CLI and a sanitized `/usr/bin:/bin`
  `PATH`, but the nested release-provenance runner later spawned `npm` by name.
  On hosts where npm is outside that path, provenance stopped at its installed
  dependency query even though the same command passed from the ambient shell.
- **Why it was missed:** readiness unit tests injected a successful provenance
  receipt instead of exercising the real nested runner, and the provenance
  environment test checked credential removal without asserting executable
  identity. Pull-request CI correctly skips official-main-only provenance and
  readiness, so the first real nested execution occurred only after merge.
- **Earliest detection point:** the exact-main local-readiness gate immediately
  after merge and before any authenticated provider preflight, upload, or cloud
  mutation.
- **Repair:** release provenance now resolves the invoking npm CLI through the
  same exact-CLI contract as the artifact builder, invokes it with the current
  Node executable, restores only the canonical npm executable bindings for
  that child, and rejects command families other than Git and npm.
- **Regression and preventive controls:** a focused test supplies a sanitized
  path and a synthetic absolute npm CLI, then proves that provenance bypasses
  PATH lookup, preserves the exact Node/npm pair, and rejects an unreviewed
  command family. The merged exact-main readiness command remains the final
  integration control.
- **Verification:** the focused provenance and readiness suites, full source
  suite, release security/proof/provenance gates, exact build, artifact
  integrity, and hosted exact-head CI must pass together. The identical
  official-main readiness command that exposed the defect must pass after the
  repair merges.
- **Residual risk:** this repair proves deterministic executable selection for
  the nested local provenance query. It does not validate AWS, CockroachDB,
  network availability, registry integrity, or hostile-host resistance.
- **Claim impact:** no live or deployment claim changes. The fix restores a
  required local source gate and does not authorize provider mutation.

## Accepted sanitized test-runtime finding

- **Root cause:** once nested provenance could complete, the exact-main
  readiness wrapper reached the full test suite with its intentionally minimal
  child environment. Removing `TMPDIR` made macOS resolve fixture paths through
  the `/tmp` symlink while path-security assertions required canonical bytes,
  and one npm-bootstrap test still selected `npm` through `PATH` even though
  production runners had already adopted the exact invoking CLI contract.
- **Why it was missed:** ordinary full-suite runs inherited the ambient
  canonical temporary directory and npm path, readiness unit tests injected a
  successful test command, and pull-request CI correctly skipped the
  official-main-only wrapper. The earlier nested-provenance failure also
  prevented readiness from reaching this stage.
- **Earliest detection point:** the unchanged exact-main local-readiness command
  immediately after the nested-runner repair merged and before any
  authenticated provider action.
- **Repair:** readiness now obtains the canonical fixed system temporary
  directory through the shared root-owned, sticky-bit trust validator while
  continuing to reject a caller-provided `TMPDIR`. The npm-bootstrap regression
  resolves and validates the current Node installation's npm CLI independently
  of an outer npm process, then invokes it with the current Node executable
  instead of searching `PATH`.
- **Regression and preventive controls:** the environment-isolation test proves
  hostile temporary-directory input is discarded, the focused readiness and
  exact-Git suites pass when launched directly by Node, and those suites
  exercise the shared temporary-root trust contract, canonical fixture roots,
  and exact executable identity. The merged official-main readiness command
  remains the end-to-end integration control.
- **Verification:** focused tests, the full suite under the real sanitized
  readiness child, release security/proof/provenance/cost gates, exact build,
  artifact integrity, and hosted exact-head CI must all pass. The identical
  command that exposed the failure must be rerun successfully after merge.
- **Residual risk:** the canonical system temporary directory remains a shared
  host facility; randomized fixture directories and existing path, symlink,
  exact-byte, and clean-checkout controls bound its use. Host compromise and
  npm/Node binary compromise remain outside scope.
- **Claim impact:** no provider, deployment, or hostile-host claim changes. The
  repair restores deterministic local verification only.

## Accepted create-only lifecycle finding

- **Root cause:** one stable `ApiDeployment` logical ID let CloudFormation
  update only the deployment description without replacing the immutable API
  Gateway snapshot. The old snapshot could therefore carry current source and
  configuration labels. The probe runbook also instructed operators to toggle
  `EnableProbeFunctions` on that same stack, which necessarily made the final
  stack updated and incompatible with the corrected attestation invariant.
- **Why it was missed:** source review bound the description, routes, stage,
  and physical deployment ID, but did not model CloudFormation update
  semantics for `AWS::ApiGatewayV2::Deployment.Description` or reconcile the
  operational probe sequence against the new never-updated stack rule.
- **Earliest detection point:** template update-semantics review and the live
  runbook, before a change set, upload, or provider mutation.
- **Repair:** final evidence accepts only an initially created, never-updated
  `CREATE_COMPLETE` stack whose exact active deployment was created during the
  initial stack creation. Capability probes run only in a distinct disposable
  stack created with probes enabled; that stack is fully deleted before a
  fresh final stack is created with probes disabled. Any final-stack change
  requires teardown and a new create.
- **Regression and preventive controls:** negative tests reject the
  same-physical-ID metadata relabel on an updated stack, validate initial
  stack/deployment timestamps, and bind the stage to the exact CloudFormation
  deployment physical ID. A separate runbook/template test requires the
  disposable-probe-to-fresh-final lifecycle and rejects instructions to toggle
  the probe parameter in place.
- **Verification:** the focused template and deployment-attestation suites,
  full source suite, generated-template equality, security gate, and proof gate
  must pass together. Provider-backed API Gateway and CloudFormation behavior
  remains unverified until the approved live lane produces accepted receipts.
- **Residual risk:** the create-only rule deliberately gives up in-place
  updates; every correction requires complete teardown and fresh creation.
  Probe-stack deletion schedules its KMS signing key for deletion after seven
  days rather than erasing it immediately; its exact pending-deletion identity
  and date must be recorded, its alias must be absent, and cancellation or
  reuse is forbidden. Provider propagation, teardown completeness, and
  same-account administrator behavior remain live or human-review boundaries.
- **Claim impact:** source may claim a fail-closed create-only deployment
  contract. It must not claim update-safe API snapshot replacement, live
  provider validation, or administrator exclusion.

## Required live sequence

1. Before deployment, generate three distinct Ed25519 key pairs outside the
   repository. Protect each private key as a regular `0600` file. Bind the
   three public keys, every function configuration digest, every function-role
   policy digest, and the collector/alternate-role policy digests into the
   private nonsecret configuration and its `ConfigDigest`.
2. From the authorized clean AWS lane, bind a private expectation to the exact
   build-receipt bytes, configuration bytes, commit, tree, generated template,
   uploaded object versions, numeric Lambda versions, code hashes, the exact
   five-primary-function configuration census, their shared-role census, both
   evidence roles, concurrency, exact API route/integration/stage and explicit
   active-deployment census, and trusted evidence principal. The default stage
   must have auto-deploy disabled and reference the exact create-time
   CloudFormation deployment physical ID. The attestation rejects every
   updated stack; changes require teardown and a fresh create. Conditional
   probe-function configuration remains a separate stage-four requirement.
3. Assume the generated evidence role as that trusted principal and run the
   `pre` attestation. A failure is a stop.
4. Assume the generated alternate role, whose exact identity policy allows
   only the target collector role, and run the denial probe
   against the evidence role and require a provider `AccessDenied` receipt.
5. Run only the separately approved failure-first component canaries.
6. Re-assume the evidence role and run the `post` attestation with the exact
   pre receipt and alternate-denial receipt. Require identical deployment and
   stack digests with all resources `IN_SYNC`.
7. Preserve private raw inputs and publish only a separately reviewed,
   sanitized evidence anchor. Any drift or unresolved observation keeps
   deployment, public release, and submission blocked.
