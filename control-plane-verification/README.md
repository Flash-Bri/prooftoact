# ProofToAct control-plane verification

This additive verifier is deliberately separate from the frozen application
package, lock, notices, manifests, and historical proof. It inventories and
hash-binds the later release-control surface without rewriting earlier facts.

It produces one deterministic candidate with independent sections for:

- exact/glob source inventory and proof;
- both nested `release-control` and `release-provider` dependency locks and
  generated inventories;
- installed license-text coverage and generated third-party notices for both
  hermetic packages;
- the three sealed provider bundle capability surfaces, with credential-chain
  packages excluded and external imports limited to Node builtins;
- source security invariants;
- the cumulative $20 cost boundary and retained controller state;
- six workflow files mapped to seven protected environments (including both
  credential-isolated coordinator jobs), plus separately supplied live proof;
- clean standalone dual-package install/build provenance and separately
  supplied evidence.

The inventory also discovers every file under `release-provider/` except
generated `dist/` and installed `node_modules/`, plus every matching root
provider test and the release-control bootstrap planner/test. A discovered file
that is not tracked by Git is an explicit local finding. Missing package
metadata, lock drift, notice drift, omitted workflow/environment/job mappings,
or absent clean-checkout evidence keeps the candidate on `HOLD`.

The PREPARE workflow is source-checked as four exact jobs: a no-OIDC diagnostic
default, coordinator reserve, provider dispatch, and coordinator finalization.
Both coordinator jobs must bind `aws-release-coordination`; provider dispatch
must bind `aws-release-deployment`. The three live jobs may carry job-level OIDC
permission, but the workflow input defaults to diagnostic-only and the source
candidate never turns that dormant path into provider authority. The remaining
five workflows must still be diagnostic-only.

The bootstrap readback verifier is provider-I/O-free. It validates caller-
supplied AWS read-only responses against the exact reviewed bootstrap template,
ten-resource inventory, retained DynamoDB identity, permissions boundary, eight
role trust/policy documents, and sixteen source-owned IAM simulation vectors.
Only after every check passes does it derive the five nonsecret PREPARE
environment values. That receipt proves the release-control bootstrap only; it
grants no provider, deployment, publication, or submission authority.
It validates response semantics and exact source equality, but does not
independently prove collector execution, read-only behavior, or principal
independence.
The sole accepted drift is DynamoDB's AWS-managed KMS normalization: source
`ExpectedProperties` must still contain `alias/aws/dynamodb`, and the summary
field must byte-match either that alias or the one source-owned CloudFormation
KMS-ARN-pattern sentinel observed in the retained provider response.

Generate the exact read-only IAM simulation plan or shell commands without
calling AWS:

```text
node scripts/release-provider-bootstrap-readback.js \
  --simulation-plan 123456789012 private-versioned-artifact-bucket

node scripts/release-provider-bootstrap-readback.js \
  --simulation-commands 123456789012 private-versioned-artifact-bucket
```

The accepted input schema is
`prooftoact.release-control-bootstrap-readback-input.v1`. Its exact top-level
keys are `schemaVersion`, `accountId`, `artifactBucketName`, `observedAt`,
`providerMutationAbsenceCallerAsserted`, `readOnlyCollectionCallerAsserted`,
`region`, and `responses`. Those two collection statements remain caller
assertions, not independent proof. The exact response set is `boundary`,
`callerIdentity`, `deployedTemplate`,
`describeKmsKey`, `describeTable`, `listStackResourceDrifts`,
`listStackResources`, `listTableTags`, `roles`, `simulations`, and `stack`;
nested response shapes are fail-closed in the
verifier and exercised by synthetic fixtures.

Verify one assembled, absolute-path JSON input. Output is written only after
full acceptance:

```text
node scripts/release-provider-bootstrap-readback.js \
  --verify-input /absolute/private/bootstrap-readback-input.json
```

On an already authenticated AWS CloudShell, the source-owned collector creates
one new local evidence directory, performs only read-only provider calls, then
assembles and verifies the exact schema without hand-editing JSON:

```text
bash scripts/release-provider-bootstrap-readback-collector.sh \
  123456789012 private-versioned-artifact-bucket \
  /absolute/new/private/bootstrap-readback
```

It calls only STS `get-caller-identity`; CloudFormation `describe`, `get`, and
`list`; DynamoDB `describe-table` and `list-tags-of-resource`; KMS
`describe-key`; and IAM `get`, `list`, and `simulate-principal-policy`. It does
not detect drift, mutate a stack, write a table, modify IAM, or authorize a
later phase. The receipt binds the local collector and verifier source digests,
labels collector execution as unproven, and requires the raw collector bundle
to accompany any publication. The accepted receipt and five-value output are
written beside the raw directory only after the verifier succeeds.

Missing source or provider evidence is represented as `HOLD`. A verified
candidate never authorizes deployment, provider access, spending, publication,
or submission. Provider truth is accepted only through the dedicated sanitized
governance and provenance evidence schemas; it is never inferred from source.

The operator-authorized $20 cumulative ProofToAct control-plane envelope is a
separate later control. It does not rewrite the frozen application's historical
$13.14-era manifest, calculations, or receipts.

Generate a create-only candidate:

```text
node control-plane-verification/generate-control-plane-candidate.js \
  --root /absolute/clean/control-plane \
  --output /absolute/private/output/control-plane-candidate.json
```

Verify the exact current bytes:

```text
node control-plane-verification/verify-control-plane-candidate.js \
  --root /absolute/clean/control-plane \
  --candidate /absolute/private/output/control-plane-candidate.json
```

When sanitized governance evidence is supplied during generation, supply the
same file during verification. Provenance is stricter: a caller-authored JSON
summary is never accepted. It must first be generated from two separate exact
standalone roots and then independently reproduced from those roots.

Add `--require-ready` only at the final local gate. Even a ready candidate still
requires the separate signed approval and provider authority path.

The two build-bound metadata files are generated separately from the frozen
application and verified byte-for-byte:

```text
node control-plane-verification/generate-release-control-metadata.js \
  --root /absolute/control-plane \
  --inventory-output /absolute/output/DEPENDENCY_INVENTORY.json \
  --notices-output /absolute/output/THIRD_PARTY_NOTICES.txt

node control-plane-verification/verify-release-control-metadata.js \
  --root /absolute/control-plane
```

The provider package owns its build-derived metadata generator because bundle
membership comes from esbuild metafiles. The additive verifier independently
reopens and validates those bytes against the exact package, lock, installed
license texts, permitted capability set, and runtime-set digest:

```text
node release-provider/generate-release-provider-metadata.js \
  --inventory-output /absolute/output/DEPENDENCY_INVENTORY.json \
  --notices-output /absolute/output/THIRD_PARTY_NOTICES.txt

node control-plane-verification/verify-release-provider-metadata.js \
  --root /absolute/control-plane
```

## Two-root clean provenance gate

The control-plane root must be a clean standalone checkout at its exact current
commit and tree. The application root must be a different, non-nested clean
standalone checkout at frozen application commit
`963937a9873f0199b91897fe88da1b91bc84b5e3` and tree
`a330e0d57328e63a568be73c523b2cae6338f26c`. Both roots must use the official
origin and have a local, complete, non-shallow object store with no grafts,
replacement refs, alternates, hidden index flags, or dirty bytes.

Run both commands with an official Node.js v22.23.1 distribution whose
executable digest is pinned by `official-node-runtime-contract.js`. The
`--npm-cli` path must be the adjacent npm 10.9.8 package shipped inside that
same official distribution; the verifier hashes all 1,964 npm package files
and rejects an ambient, Homebrew, copied, or caller-supplied substitute.

Generate the evidence into an existing owner-only output directory that is
outside both checkout roots:

```text
/absolute/official-node/bin/node \
  control-plane-verification/generate-control-plane-provenance-evidence.js \
  --control-root /absolute/standalone/control-plane \
  --application-root /absolute/standalone/frozen-application \
  --npm-cli /absolute/official-node/lib/node_modules/npm/bin/npm-cli.js \
  --output /absolute/owner-only/provenance-evidence.json
```

The generator itself runs `npm ci --ignore-scripts` and the exact package
`test` script for the control-plane root, both hermetic packages, and the
frozen application root. It runs production dependency audits, rebuilds each
control/provider runtime twice, reopens every tracked package/lock byte and
build input/output, and embeds the exact stdout/stderr and full build receipts
under canonical digests.

Reproduce the evidence independently before it can enter a candidate:

```text
/absolute/official-node/bin/node \
  control-plane-verification/verify-control-plane-provenance-evidence.js \
  --control-root /absolute/standalone/control-plane \
  --application-root /absolute/standalone/frozen-application \
  --npm-cli /absolute/official-node/lib/node_modules/npm/bin/npm-cli.js \
  --evidence /absolute/owner-only/provenance-evidence.json
```

The verifier first reopens and reparses the owner-only, non-symlink evidence
file, embedded command outputs, and raw build receipts. It then reruns the
installs, exact package test scripts, audits, and two-build reproducibility
checks against the same two roots. Both roots are re-inspected after the long
gate, including filesystem identity. A structurally valid JSON file without
that reproduction fails closed.

This local receipt intentionally does not claim hosted-CI parity or execution
of the separately privileged root-stage tests. Those remain independent,
required hosted-workflow evidence at the exact control-plane commit; a local
provenance receipt cannot substitute for them.

Only after reproduction may the same evidence be supplied to candidate
generation/verification, together with `--frozen-application-root` and
`--npm-cli`. Even then the result states only
`LOCAL_PROVENANCE_REPRODUCED`; it always returns
`providerExecutionAuthorized: false`. It does not authorize OIDC, credentials,
AWS or CockroachDB access, deployment, spending, publication, or submission.

Provider build provenance binds exactly three runtimes, their runtime-set
digest, complete source inventory, full receipts, and the union of external
imports; every external import must be a `node:` builtin.

## Hosted dual-root source verification

`ProofToAct Hosted Dual Root Verification` is a manually dispatched,
main-only GitHub-hosted lane with repository contents read permission only. It
has no environment binding, OIDC permission, provider credential input, or
provider client action. It checks out the exact current control-plane SHA and
the frozen application commit into separate roots, normalizes both, and uses
the official Node.js 22.23.1 and npm 10.9.8 distributions already required by
the provenance verifier.

The lane requires all four package test scripts to finish with zero failures,
zero cancellations, zero skips, and zero todos. It additionally runs the
explicit crash/replay/concurrency/spend/teardown test inventory, the complete
source-security inventory and verifier, both installed-process boundary
verifiers, and the privileged installed-stage suite. The frozen application is
built twice through the isolated exact-Git builder and every output digest,
template digest, build receipt, 45-key template parameter schema, and
build-derived parameter input digest must match. Release-control and
release-provider runtimes are also built twice and their complete executable
manifests must match.

The result is one canonical `manifest.json` plus hash-inventoried nonsecret
logs and receipts. The workflow independently reopens the set, rejects any
missing or extra file, and uploads it with 90-day retention. The manifest is
deliberately non-authorizing: it records no AWS or CockroachDB access, no OIDC,
no deployment, and no provider facts. Private/provider-resolved values in the
45-value deployment parameter manifest are explicitly
`SOURCE_CONTRACT_ONLY_NO_PROVIDER_CONFIGURATION`; this lane proves the complete
source-owned parameter contract and build-derived inputs, not live parameter
values or an executable change set.
