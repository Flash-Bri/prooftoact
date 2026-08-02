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
  or a fabricated pre/denial receipt as separate substitution paths. Tests
  also omitted tampered dependency bytes, a fabricated-but-hash-bound receipt,
  and a same-account shadow function substituted for one stack resource.
- **Earliest detection point:** the deterministic artifact builder and
  generated-template contract. Both can reject mutable inputs before upload;
  a provider snapshot can then reject deployment drift before any canary.
- **Repair:** the public build command rejects a dirty or contaminated source
  checkout, creates a detached exact-commit worktree, executes the committed
  builder there, runs `npm ci --ignore-scripts` from the lockfile with a new
  isolated cache and distinct empty user/global npm configuration paths,
  rejects installed-tree symlinks, hashes every installed file byte and mode,
  and records the Node/npm toolchain plus every build-control and project blob.
  The distinct paths prevent npm from rejecting a duplicated configuration
  source while still excluding ambient npm configuration. The esbuild
  loader rejects every non-dependency path outside that worktree. Runtime
  roles, API integrations, permissions, probe targets, and authority-race
  invocation target numeric Lambda versions. `proof` aliases remain monitored
  pointers only. Three distinct Ed25519 public keys are committed into the
  configuration digest before deployment; their separately protected private
  keys authenticate the pre snapshot, post snapshot/final pair, and
  alternate-principal denial. The validator recomputes caller/context
  bindings, fully validates and reproduces the raw build receipt byte-for-byte
  from the exact clean commit before any provider query, and binds the
  expectation to that receipt and the configuration hashes. It enumerates
  every inline and attached role policy plus permissions
  boundary, preserves role IDs, binds security-relevant Lambda configuration,
  binds each attested function, version, alias, and role to its exact
  CloudFormation physical resource, and requires two identical full provider
  observations per snapshot.
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
  bound or rejected.
- **Verification:** focused tests substitute dirty working-tree bytes, reject
  untracked and escaped paths, tamper an installed dependency, reject an
  installed-tree symlink, reject alias invocation targets, fabricate or stale
  the exact build receipt, substitute a shadow function, fabricate unsigned
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
  safety.
- **Claim impact:** source wording may say that the candidate builds project
  inputs from exact Git blobs, invokes numeric Lambda versions, and contains a
  fail-closed pre/post attestation contract. It must not say that live AWS
  deployment identity, alternate-principal denial, administrator exclusion,
  canary stability, or production security has been proven.

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
   evidence roles, concurrency, and trusted evidence principal. Conditional
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
