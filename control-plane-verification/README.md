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

When sanitized governance and provenance evidence files are supplied during
generation, supply those exact same files during verification. The candidate
binds their canonical digests and rejects substitution.

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

Clean-checkout provenance evidence must separately bind `npm ci
--ignore-scripts`, the lock and package bytes, and reproducible build receipts
for both hermetic packages. Provider provenance additionally binds exactly
three runtimes, their runtime-set digest, source inventory, and the union of
external imports; every external import must be a `node:` builtin.
