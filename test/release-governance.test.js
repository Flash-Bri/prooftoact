import assert from "node:assert/strict";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  __test,
  validateManifest,
  validateSnapshot,
  verifyReleaseGovernance
} from "../scripts/verify-release-governance.js";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const HEX = "a".repeat(64);

function fixtureManifest(overrides = {}) {
  return {
    schema: __test.MANIFEST_SCHEMA,
    status: __test.MANIFEST_STATUS,
    reviewedOn: "2026-08-01",
    claimBoundary: __test.EXPECTED_MANIFEST_BOUNDARY,
    repository: structuredClone(__test.EXPECTED_REPOSITORY),
    surfaces: Object.entries(__test.EXPECTED_SURFACES).map(
      ([id, surface]) => ({
        id,
        path: surface.path,
        role: surface.role,
        sha256: HEX
      })
    ),
    finalReleaseRequirements: [
      ...__test.EXPECTED_FINAL_RELEASE_REQUIREMENTS
    ],
    finalReleaseReady: false,
    ...overrides
  };
}

function fixtureSnapshot(overrides = {}) {
  return {
    schema: __test.SNAPSHOT_SCHEMA,
    status: __test.SNAPSHOT_STATUS,
    observedAt: "2026-08-01T01:45:38Z",
    source: structuredClone(__test.EXPECTED_SOURCE),
    repository: structuredClone(__test.EXPECTED_SNAPSHOT_REPOSITORY),
    branchProtection: structuredClone(__test.EXPECTED_BRANCH_PROTECTION),
    security: structuredClone(__test.EXPECTED_SECURITY),
    continuousIntegration: structuredClone(
      __test.EXPECTED_CONTINUOUS_INTEGRATION
    ),
    claimBoundary: __test.EXPECTED_SNAPSHOT_BOUNDARY,
    finalReleaseRequirements: [
      ...__test.EXPECTED_FINAL_RELEASE_REQUIREMENTS
    ],
    finalReleaseReady: false,
    ...overrides
  };
}

test("current repository governance snapshot matches its non-final boundary", () => {
  const receipt = verifyReleaseGovernance({ rootDir: ROOT });
  assert.equal(receipt.status, "CURRENT_REPOSITORY_GOVERNANCE_PASS");
  assert.equal(receipt.finalReleaseReady, false);
  assert.equal(receipt.surfaceCount, 7);
  assert.equal(receipt.requiredCheckCount, 1);
  assert.equal(receipt.requiredApprovingReviewCount, 0);
  assert.equal(receipt.finalReleaseRequirements.length, 3);
  assert.equal(
    Object.values(receipt.checks).every((value) => value === true),
    true
  );
});

test("governance manifest rejects final approval or changed source coordinates", () => {
  assert.equal(validateManifest(fixtureManifest()).finalReleaseReady, false);
  assert.throws(
    () => validateManifest(fixtureManifest({ finalReleaseReady: true })),
    /RELEASE_GOVERNANCE_MANIFEST_BOUNDARY/
  );

  const changedRepository = fixtureManifest();
  changedRepository.repository.fullName = "other/repository";
  assert.throws(
    () => validateManifest(changedRepository),
    /RELEASE_GOVERNANCE_MANIFEST_BOUNDARY/
  );
});

test("governance snapshot rejects overstated human-review protection", () => {
  const changed = fixtureSnapshot();
  changed.branchProtection.requiredApprovingReviewCount = 1;
  assert.throws(
    () => validateSnapshot(changed),
    /RELEASE_GOVERNANCE_SNAPSHOT_BOUNDARY/
  );
});

test("governance snapshot rejects weakened branch or secret protections", () => {
  const forcePush = fixtureSnapshot();
  forcePush.branchProtection.forcePushAllowed = true;
  assert.throws(
    () => validateSnapshot(forcePush),
    /RELEASE_GOVERNANCE_SNAPSHOT_BOUNDARY/
  );

  const pushProtection = fixtureSnapshot();
  pushProtection.security.secretScanningPushProtection = "disabled";
  assert.throws(
    () => validateSnapshot(pushProtection),
    /RELEASE_GOVERNANCE_SNAPSHOT_BOUNDARY/
  );
});

test("governance snapshot rejects changed required CI identity", () => {
  const changed = fixtureSnapshot();
  changed.continuousIntegration.requiredCheck = "different-check";
  assert.throws(
    () => validateSnapshot(changed),
    /RELEASE_GOVERNANCE_SNAPSHOT_BOUNDARY/
  );
});
