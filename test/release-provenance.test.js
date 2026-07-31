import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  __test,
  runReleaseProvenance,
  validateInstalledTree,
  validateTrackedTree,
  verifyRepositoryHistory
} from "../scripts/verify-release-provenance.js";

const SOURCE_COMMIT = "a".repeat(40);
const TREE_DIGEST = "b".repeat(40);
const PACKAGE_LOCK_SHA = /^[0-9a-f]{64}$/;

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function writePackage(root, location, name, version) {
  const packageRoot = path.join(root, location);
  fs.mkdirSync(packageRoot, { recursive: true });
  fs.writeFileSync(
    path.join(packageRoot, "package.json"),
    `${JSON.stringify({ name, version })}\n`
  );
  return packageRoot;
}

function dependencyFixture() {
  const projectRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "tideproof-release-provenance-")
  );
  const packageLock = {
    name: "fixture",
    version: "1.0.0",
    lockfileVersion: 3,
    packages: {
      "": { name: "fixture", version: "1.0.0" },
      "node_modules/required": {
        version: "2.0.0",
        resolved: "https://registry.npmjs.org/required/-/required-2.0.0.tgz",
        integrity: "sha512-fixture",
        license: "MIT"
      },
      "node_modules/@platform/optional": {
        version: "3.0.0",
        resolved:
          "https://registry.npmjs.org/@platform/optional/-/optional-3.0.0.tgz",
        integrity: "sha512-fixture",
        license: "MIT",
        optional: true,
        dev: true
      }
    }
  };
  fs.writeFileSync(
    path.join(projectRoot, "package-lock.json"),
    `${JSON.stringify(packageLock, null, 2)}\n`
  );
  const requiredRoot = writePackage(
    projectRoot,
    "node_modules/required",
    "required",
    "2.0.0"
  );
  const query = [
    {
      name: "fixture",
      version: "1.0.0",
      location: "",
      path: projectRoot,
      realpath: projectRoot
    },
    {
      name: "required",
      version: "2.0.0",
      location: "node_modules/required",
      path: requiredRoot,
      realpath: requiredRoot,
      resolved: "https://registry.npmjs.org/required/-/required-2.0.0.tgz",
      inBundle: false,
      overridden: false
    }
  ];
  return {
    projectRoot,
    packageLock,
    query,
    cleanup() {
      fs.rmSync(projectRoot, { recursive: true, force: true });
    }
  };
}

function rightsReceipt() {
  return {
    schemaVersion: "tideproof.release-rights-verification.v1",
    status: "CURRENT_SURFACES_PASS",
    finalReleaseReady: false,
    reviewedOn: "2026-07-31",
    manifestPath: "docs/media/RIGHTS_MANIFEST.json",
    manifestSha256: "3".repeat(64),
    ledgerSha256: "4".repeat(64),
    distributedFileCount: 5,
    currentClearedFileCount: 5,
    interimOnlyFileCount: 0,
    repositoryMediaFileCount: 2,
    trackedFileCount: 120,
    prohibitedSourceDigestCount: 3,
    finalReleaseRequirements: [
      "Exact-release private rights review receipt.",
      "Final-production asset decision recorded as cleared exact hashes or deliberate omission."
    ],
    checks: {
      canonicalManifest: true,
      exactFileHashes: true,
      ledgerBindings: true,
      completeRepositoryMediaInventory: true,
      blockedPlannedPathsAbsent: true,
      prohibitedReferenceBytesAbsent: true,
      remoteEmbeddedMediaAbsent: true,
      redistributedFontsAbsent: true,
      localServerBindingsExact: true,
      awsDistributionBindingsExact: true,
      publicDemoCspRejectsDataImages: true
    },
    claimBoundary: "Fixture current-surface rights only."
  };
}

function privacyReceipt() {
  return {
    schemaVersion: "tideproof.release-privacy-verification.v1",
    status: "CURRENT_PUBLIC_HISTORY_PASS",
    finalReleaseReady: false,
    reviewedOn: "2026-07-31",
    sourceCommit: SOURCE_COMMIT,
    treeDigest: TREE_DIGEST,
    manifestPath: "RELEASE_PRIVACY_MANIFEST.json",
    manifestSha256: "2".repeat(64),
    commitCount: 50,
    commitIdentityCount: 3,
    trackedFileCount: 120,
    reachableBlobCount: 300,
    scannedBytes: 1_000_000,
    findingCount: 10,
    allowanceCount: 4,
    checks: { fixturePrivacyPass: true },
    finalReleaseRequirements: [
      "Rerun on the exact final official-main commit and bind the PASS receipt to hosted CI and deployed artifact hashes.",
      "Complete a private human review for secrets, personal data, internal URLs, metadata, screenshots, video, and submission fields."
    ],
    claimBoundary: "Fixture bounded privacy review only."
  };
}

function claimsReceipt() {
  return {
    schemaVersion: "tideproof.release-claims-verification.v1",
    status: "CURRENT_PUBLIC_CLAIMS_PASS",
    finalReleaseReady: false,
    reviewedOn: "2026-07-31",
    manifestPath: "RELEASE_CLAIMS_MANIFEST.json",
    manifestSha256: "7".repeat(64),
    proofManifestSha256: "8".repeat(64),
    claimCount: 11,
    claimStates: { VERIFIED: 7, PARTIAL: 4, PENDING: 0 },
    surfaceCount: 13,
    stopTokenCount: 13,
    uncheckedGateCount: 14,
    externalUrls: [
      "http://127.0.0.1:4173",
      "https://cockroachdb-ai.devpost.com/",
      "https://cockroachdb-ai.devpost.com/resources",
      "https://cockroachdb-ai.devpost.com/rules",
      "https://github.com/Flash-Bri/tideproof",
      "https://github.com/Flash-Bri/tideproof.git"
    ],
    finalReleaseRequirements: [
      "Accepted live AWS, public-demo, video, and submission receipts bound to the exact final release.",
      "Exact-release private human review of every public claim surface and submitted field."
    ],
    checks: {
      canonicalManifest: true,
      exactSurfaceHashes: true,
      claimsLedgerMatchesProofManifest: true,
      currentDraftStateExplicit: true,
      localAndHostedAwsBoundariesExplicit: true,
      syntheticScopeExplicit: true,
      submissionStopTokensPreserved: true,
      publicLinksConstrained: true
    },
    claimBoundary: "Fixture current public claim surfaces only."
  };
}

function accessibilityReceipt() {
  return {
    schemaVersion: "tideproof.accessibility-static.v1",
    status: "STATIC_SOURCE_PASS",
    finalReleaseReady: false,
    standardTarget: "WCAG_2_2_AA",
    rightsManifestSha256: "3".repeat(64),
    reviewedFiles: [
      "architecture-svg",
      "browser-app",
      "browser-document",
      "browser-styles"
    ].map((id, index) => ({
      id,
      path: `fixture/${id}`,
      sha256: String(index + 5).repeat(64)
    })),
    contrast: Array.from({ length: 11 }, (_, index) => ({
      id: `pair-${index}`,
      minimumRatio: 4.5,
      ratio: 7
    })),
    summary: {
      headingCount: 9,
      imageCount: 1,
      buttonCount: 7,
      landmarkSectionCount: 5
    },
    remainingRequirements: [
      "Automated browser accessibility scan on the exact public release.",
      "Keyboard-only, 200% zoom, mobile reflow, and reduced-motion private review on the exact public release.",
      "Screen-reader review on the exact public release."
    ],
    checks: { fixtureAccessibilityPass: true },
    claimBoundary: "Fixture static accessibility only."
  };
}

function securityReceipt() {
  return {
    schemaVersion: "tideproof.release-security-verification.v1",
    status: "CURRENT_SOURCE_SECURITY_PASS",
    finalReleaseReady: false,
    reviewedOn: "2026-07-31",
    manifestPath: "RELEASE_SECURITY_MANIFEST.json",
    manifestSha256: "9".repeat(64),
    surfaceCount: 18,
    publicPathCount: 10,
    securityHeaderCount: 9,
    negativeProbeCount: 6,
    publicRouteCount: 10,
    iamRoleCount: 7,
    lambdaPermissionCount: 3,
    boundedFunctionCount: 5,
    logGroupCount: 11,
    finalReleaseRequirements: [
      "Exact-release live security receipts.",
      "Separate private human security review."
    ],
    checks: { fixtureSecurityPass: true },
    claimBoundary: "Fixture current source security only."
  };
}

function submissionReceipt() {
  return {
    schemaVersion: "tideproof.release-submission-verification.v1",
    status: "DRAFT_SAFELY_BLOCKED",
    finalReleaseReady: false,
    reviewedOn: "2026-07-31",
    manifestPath: "RELEASE_SUBMISSION_MANIFEST.json",
    manifestSha256: "6".repeat(64),
    surfaceCount: 7,
    checklistItemCount: 14,
    uncheckedChecklistItemCount: 14,
    stopTokenOccurrenceCount: 13,
    uniqueStopTokenCount: 12,
    officialCoordinateCount: 11,
    finalReleaseRequirements: [
      "Accepted live receipts.",
      "Exact-release private review.",
      "Authorized-entrant confirmation.",
      "Timestamped final submission receipt."
    ],
    checks: { fixtureSubmissionBlocked: true },
    claimBoundary: "Fixture fail-closed submission draft only."
  };
}

function treeOutput() {
  return [
    `100644 blob ${"c".repeat(40)}\tREADME.md`,
    `100755 blob ${"d".repeat(40)}\tscripts/check`
  ].join("\0") + "\0";
}

function repositoryRunner({ branch = "main", calls = [] } = {}) {
  return (command, args) => {
    const call = [command, ...args];
    calls.push(call);
    const shape = `${command} ${args.join(" ")}`;
    const outputs = new Map([
      ["git remote get-url origin", `${__test.OFFICIAL_REMOTE}\n`],
      ["git symbolic-ref --short HEAD", `${branch}\n`],
      ["git status --porcelain=v1 --untracked-files=all", ""],
      ["git rev-parse HEAD", `${SOURCE_COMMIT}\n`],
      ["git rev-parse refs/remotes/origin/main", `${SOURCE_COMMIT}\n`],
      ["git rev-parse HEAD^{tree}", `${TREE_DIGEST}\n`],
      ["git rev-parse --is-shallow-repository", "false\n"],
      ["git replace -l", ""],
      ["git rev-parse --git-path info/grafts", ".git/info/grafts\n"],
      [
        "git rev-parse --git-path objects/info/alternates",
        ".git/objects/info/alternates\n"
      ],
      ["git rev-list --max-parents=0 HEAD", `${__test.CLEAN_ROOM_ROOT}\n`],
      ["git rev-list --count HEAD", "41\n"],
      ["git rev-list --count --merges HEAD", "9\n"],
      [
        `git show -s --format=%aI%x09%cI ${__test.CLEAN_ROOM_ROOT}`,
        "2026-07-29T07:21:03-04:00\t2026-07-29T07:21:03-04:00\n"
      ],
      [
        "git show -s --format=%aI%x09%cI HEAD",
        "2026-07-31T10:00:00-04:00\t2026-07-31T10:00:00-04:00\n"
      ],
      ["git ls-tree -r -z --full-tree HEAD", treeOutput()],
      ["git fsck --strict --no-dangling HEAD", ""]
    ]);
    if (command === "git" && args.includes("fetch")) {
      return { status: 0, stdout: "", stderr: "" };
    }
    if (!outputs.has(shape)) {
      return { status: 1, stdout: "", stderr: `unexpected: ${shape}` };
    }
    return { status: 0, stdout: outputs.get(shape), stderr: "" };
  };
}

test("installed dependency tree matches required lock records", () => {
  const fixture = dependencyFixture();
  try {
    assert.deepEqual(
      validateInstalledTree(fixture),
      {
        status: "PASS",
        lockedPackageCount: 2,
        installedPackageCount: 1,
        installedRuntimeCount: 1,
        installedDevelopmentOnlyCount: 0,
        installedOptionalCount: 0,
        omittedOptionalCount: 1,
        extraPackageCount: 0,
        mismatchedPackageCount: 0
      }
    );
  } finally {
    fixture.cleanup();
  }
});

test("installed dependency tree rejects an undeclared package", () => {
  const fixture = dependencyFixture();
  try {
    const extraRoot = writePackage(
      fixture.projectRoot,
      "node_modules/extra",
      "extra",
      "1.0.0"
    );
    fixture.query.push({
      name: "extra",
      version: "1.0.0",
      location: "node_modules/extra",
      path: extraRoot,
      realpath: extraRoot,
      resolved: "https://registry.npmjs.org/extra/-/extra-1.0.0.tgz",
      inBundle: false,
      overridden: false
    });
    assert.throws(
      () => validateInstalledTree(fixture),
      /RELEASE_PROVENANCE_NPM_PACKAGE/
    );
  } finally {
    fixture.cleanup();
  }
});

test("installed dependency tree rejects changed installed identity", () => {
  const fixture = dependencyFixture();
  try {
    fs.writeFileSync(
      path.join(fixture.projectRoot, "node_modules/required/package.json"),
      `${JSON.stringify({ name: "required", version: "2.0.1" })}\n`
    );
    assert.throws(
      () => validateInstalledTree(fixture),
      /RELEASE_PROVENANCE_NPM_MANIFEST/
    );
  } finally {
    fixture.cleanup();
  }
});

test("tracked release tree accepts only regular blobs", () => {
  assert.deepEqual(validateTrackedTree(treeOutput()), {
    fileCount: 2,
    regularFileCount: 2,
    executableFileCount: 1,
    symlinkCount: 0,
    gitlinkCount: 0
  });
  assert.throws(
    () =>
      validateTrackedTree(
        `120000 blob ${"e".repeat(40)}\tlinked\0`
      ),
    /RELEASE_PROVENANCE_TREE_RECORD/
  );
  assert.throws(
    () =>
      validateTrackedTree(
        `160000 commit ${"f".repeat(40)}\tvendor\0`
      ),
    /RELEASE_PROVENANCE_TREE_RECORD/
  );
});

test("repository history binds the official full clean-room ancestry", () => {
  const calls = [];
  const receipt = verifyRepositoryHistory({
    run: repositoryRunner({ calls })
  });
  assert.equal(receipt.checkout.commit, SOURCE_COMMIT);
  assert.equal(receipt.checkout.tree, TREE_DIGEST);
  assert.equal(receipt.history.rootCommit, __test.CLEAN_ROOM_ROOT);
  assert.equal(receipt.history.commitCount, 41);
  assert.equal(receipt.history.mergeCommitCount, 9);
  assert.equal(receipt.history.legacyGraftFilePresent, false);
  assert.equal(receipt.history.alternateObjectDatabaseCount, 0);
  assert.equal(receipt.trackedTree.symlinkCount, 0);
  assert.equal(calls.some((call) => call.includes("fsck")), true);
  assert.equal(calls.filter((call) => call.includes("fetch")).length, 1);
});

test("repository history rejects a feature branch", () => {
  assert.throws(
    () =>
      verifyRepositoryHistory({
        run: repositoryRunner({ branch: "agent/work" })
      }),
    /RELEASE_PROVENANCE_CHECKOUT/
  );
});

test("repository history rejects legacy graft metadata", () => {
  const projectRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "tideproof-release-graft-")
  );
  try {
    fs.mkdirSync(path.join(projectRoot, ".git/info"), { recursive: true });
    fs.writeFileSync(path.join(projectRoot, ".git/info/grafts"), "graft\n");
    assert.throws(
      () =>
        verifyRepositoryHistory({
          projectRoot,
          run: repositoryRunner()
        }),
      /RELEASE_PROVENANCE_GIT_GRAFTS/
    );
  } finally {
    fs.rmSync(projectRoot, { recursive: true, force: true });
  }
});

test("complete provenance receipt binds source, install, inventory, and notices", async () => {
  const fixture = dependencyFixture();
  const calls = [];
  const runner = repositoryRunner({ calls });
  const run = (command, args) => {
    if (`${command} ${args.join(" ")}` === "npm query * --json") {
      return {
        status: 0,
        stdout: JSON.stringify(fixture.query),
        stderr: ""
      };
    }
    return runner(command, args);
  };
  const lockBytes = fs.readFileSync(
    path.join(fixture.projectRoot, "package-lock.json")
  );
  const packageLockSha256 = sha256(lockBytes);
  try {
    const receipt = await runReleaseProvenance({
      projectRoot: fixture.projectRoot,
      run,
      verifyInventory: () => ({
        status: "PASS",
        sourceLockSha256: packageLockSha256,
        inventorySha256: "1".repeat(64),
        packageCount: 2
      }),
      verifyNotices: async () => ({
        status: "PASS",
        noticePath: "THIRD_PARTY_NOTICES.txt",
        noticeSha256: "2".repeat(64),
        noticeBytes: 100,
        packageLockSha256,
        packageCount: 1,
        licenseTextCount: 1,
        fallbackCount: 0,
        licenses: { MIT: 1 },
        artifactPackages: { demo: ["required"] }
      }),
      verifyAccessibilityReceipt: () => accessibilityReceipt(),
      verifyClaims: () => claimsReceipt(),
      verifyPrivacy: () => privacyReceipt(),
      verifyRights: () => rightsReceipt(),
      verifySecurity: () => securityReceipt(),
      verifySubmission: () => submissionReceipt()
    });
    assert.equal(receipt.schemaVersion, "tideproof.release-provenance.v6");
    assert.equal(receipt.status, "PASS");
    assert.equal(receipt.source.commit, SOURCE_COMMIT);
    assert.match(
      receipt.dependencies.installedTree.packageLockSha256,
      PACKAGE_LOCK_SHA
    );
    assert.equal(receipt.checks.installedTreeMatchesLock, true);
    assert.equal(receipt.checks.currentClaimSurfacesVerified, true);
    assert.equal(receipt.checks.releasePrivacyVerified, true);
    assert.equal(receipt.checks.currentSurfaceRightsVerified, true);
    assert.equal(receipt.checks.staticAccessibilityVerified, true);
    assert.equal(receipt.checks.currentSourceSecurityVerified, true);
    assert.equal(receipt.checks.submissionDraftFailClosed, true);
    assert.equal(receipt.rights.finalReleaseReady, false);
    assert.equal(receipt.privacy.finalReleaseReady, false);
    assert.equal(receipt.accessibility.finalReleaseReady, false);
    assert.equal(receipt.claims.finalReleaseReady, false);
    assert.equal(receipt.security.finalReleaseReady, false);
    assert.equal(receipt.submission.finalReleaseReady, false);
    assert.equal(calls.filter((call) => call.includes("fetch")).length, 2);
  } finally {
    fixture.cleanup();
  }
});

test("provenance child environment removes credentials and Git overrides", () => {
  const isolated = __test.childEnvironment({
    PATH: "/usr/bin",
    SAFE_VALUE: "retained",
    AWS_SESSION_TOKEN: "secret",
    DATABASE_URL: "postgresql://private",
    GIT_OBJECT_DIRECTORY: "/tmp/objects",
    GITHUB_TOKEN: "secret",
    NODE_OPTIONS: "--require=/tmp/inject.js",
    npm_config_userconfig: "/tmp/npmrc"
  });
  assert.equal(isolated.PATH, "/usr/bin");
  assert.equal(isolated.SAFE_VALUE, "retained");
  assert.equal(isolated.AWS_SESSION_TOKEN, undefined);
  assert.equal(isolated.DATABASE_URL, undefined);
  assert.equal(isolated.GIT_OBJECT_DIRECTORY, undefined);
  assert.equal(isolated.GITHUB_TOKEN, undefined);
  assert.equal(isolated.NODE_OPTIONS, undefined);
  assert.equal(isolated.GIT_CONFIG_GLOBAL, "/dev/null");
  assert.equal(isolated.npm_config_userconfig, "/dev/null");
});
