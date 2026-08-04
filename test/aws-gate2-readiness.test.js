import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { templateReceipt } from "../src/cloud/aws-gate2-template.js";
import { deterministicZip } from "../scripts/lib/deterministic-zip.js";
import {
  __test,
  parseArguments,
  runAwsReadiness,
  validateAuditReport,
  validateBuildReceipt,
  validatePreflightReceipt,
  validateReleaseProvenance
} from "../scripts/gate2-aws-readiness.js";
import {
  RELEASE_CLAIMS_STOP_TOKEN_COUNT,
  RELEASE_CLAIMS_SURFACE_COUNT,
  RELEASE_CLAIMS_UNCHECKED_GATE_COUNT
} from "../scripts/verify-release-claims.js";
import {
  RELEASE_COST_SURFACE_COUNT,
  __test as costVerifierContract
} from "../scripts/verify-release-cost.js";
import {
  RELEASE_SECURITY_SURFACE_COUNT,
  __test as securityVerifierContract
} from "../scripts/verify-release-security.js";

const SOURCE_COMMIT = "a".repeat(40);
const TREE_DIGEST = "b".repeat(40);

function sha256(value, encoding = "hex") {
  return crypto.createHash("sha256").update(value).digest(encoding);
}

function writeFile(root, relativePath, value) {
  const filePath = path.join(root, relativePath);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, value);
  return filePath;
}

function fixture() {
  const projectRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "tideproof-aws-readiness-")
  );
  const packageLock = Buffer.from(
    '{"lockfileVersion":3}\n',
    "utf8"
  );
  const packageJson = Buffer.from(
    '{"name":"fixture","private":true}\n',
    "utf8"
  );
  const bootstrapTemplateValue = {};
  const gate2TemplateValue = { Resources: {} };
  const bootstrapTemplateReceipt = templateReceipt(bootstrapTemplateValue);
  const gate2TemplateReceipt = templateReceipt(gate2TemplateValue);
  const bootstrapTemplate = Buffer.from(
    `${JSON.stringify(bootstrapTemplateValue, null, 2)}\n`,
    "utf8"
  );
  const gate2Template = Buffer.from(
    `${JSON.stringify(gate2TemplateValue, null, 2)}\n`,
    "utf8"
  );
  const thirdPartyNotices = Buffer.from(
    "Fixture bundled third-party notices.\n",
    "utf8"
  );
  writeFile(projectRoot, "package.json", packageJson);
  writeFile(projectRoot, "package-lock.json", packageLock);
  writeFile(
    projectRoot,
    "THIRD_PARTY_NOTICES.txt",
    thirdPartyNotices
  );
  writeFile(
    projectRoot,
    "infra/aws/bootstrap-template.json",
    bootstrapTemplate
  );
  writeFile(
    projectRoot,
    "infra/aws/gate2-template.json",
    gate2Template
  );
  const buildControlInputs = [
    "infra/aws/lambda/agent.cjs",
    "scripts/build-gate2-exact.js",
    "scripts/build-gate2-template.js",
    "scripts/lib/aws-provider-bundle-entry.js",
    "scripts/lib/aws-provider-runtime.js",
    "scripts/lib/aws-provider-runtime-loader.js",
    "scripts/lib/bundled-third-party-notices.js",
    "scripts/lib/dependency-snapshot.js",
    "scripts/lib/deterministic-zip.js",
    "scripts/lib/exact-build-reproduction.js",
    "scripts/lib/exact-git-source.js",
    "scripts/lib/raw-text-plugin.js",
    "scripts/verify-bundled-third-party-notices.js",
    "src/cloud/aws-gate2-template.js",
    "src/cloud/public-demo.js"
  ].map((controlPath, index) => {
    const bytes = Buffer.from(`fixture build control ${index}\n`, "utf8");
    writeFile(projectRoot, controlPath, bytes);
    return {
      gitBlobId: __test.gitBlobId(bytes),
      path: controlPath,
      sha256: sha256(bytes)
    };
  });

  const artifacts = [];
  for (const name of __test.ARTIFACT_NAMES) {
    const extension = name === "demo" ? "js" : "cjs";
    const sourcePath = `infra/aws/lambda/${name}.${extension}`;
    const source =
      name === "agent"
        ? fs.readFileSync(path.join(projectRoot, sourcePath))
        : Buffer.from(`exports.handler = async () => "${name}";\n`, "utf8");
    if (name !== "agent") {
      writeFile(projectRoot, sourcePath, source);
    }
    const archive = deterministicZip([
      {
        fileName: "THIRD_PARTY_NOTICES.txt",
        content: thirdPartyNotices
      },
      { fileName: "index.js", content: source }
    ]);
    const artifactDigest = sha256(archive);
    const artifactFile = `${name}-${artifactDigest}.zip`;
    const artifactPath = `dist/aws/${artifactFile}`;
    writeFile(projectRoot, artifactPath, archive);
    artifacts.push({
      name,
      sourcePath,
      sourceDigest: sha256(source),
      artifactPath,
      artifactFile,
      artifactDigest,
      artifactCodeSha256: sha256(archive, "base64"),
      artifactBytes: archive.length,
      bundledPackages: ["@fixture/runtime"],
      exactGitInputs: [
        {
          gitBlobId: __test.gitBlobId(source),
          path: sourcePath,
          sha256: sha256(source)
        }
      ],
      suggestedS3Key:
        `gate2/${SOURCE_COMMIT}/${artifactFile}`
    });
  }

  const providerBytes = Buffer.from(
    "export async function createAwsProviderClients(){return {};}\n",
    "utf8"
  );
  const providerDigest = sha256(providerBytes);
  const providerPath = `dist/aws/evidence-provider-${providerDigest}.mjs`;
  writeFile(projectRoot, providerPath, providerBytes);
  const providerInputPaths = [
    "scripts/lib/aws-provider-bundle-entry.js",
    "scripts/lib/aws-provider-runtime.js"
  ];
  const evidenceProviderRuntime = {
    bundledPackages: ["@fixture/provider"],
    bytes: providerBytes.length,
    exactGitInputs: providerInputPaths.map((inputPath) => {
      const bytes = fs.readFileSync(path.join(projectRoot, inputPath));
      return {
        gitBlobId: __test.gitBlobId(bytes),
        path: inputPath,
        sha256: sha256(bytes)
      };
    }),
    externalImports: ["node:module"],
    path: providerPath,
    sha256: providerDigest
  };

  const buildReceipt = {
    schemaVersion: "tideproof.gate2-build.v6",
    mode: "CLEAN_ARTIFACT_BUILD",
    projectSourceMode: "ISOLATED_EXACT_GIT_CHECKOUT_AND_BLOBS",
    sourceCommit: SOURCE_COMMIT,
    treeDigest: TREE_DIGEST,
    workingTreeClean: true,
    workingTreeCleanBeforeGeneration: true,
    archiveFormat: "ZIP_STORED_TWO_FILE_V2",
    buildControlInputs,
    dependencySnapshot: {
      schemaVersion: "tideproof.dependency-snapshot.v1",
      installMode: "NPM_CI_IGNORE_SCRIPTS_CLEAN_CACHE",
      fileCount: 321,
      totalBytes: 123456,
      symlinkCount: 0,
      packageJsonDigest: sha256(packageJson),
      packageLockDigest: sha256(packageLock),
      treeDigest: "9".repeat(64)
    },
    evidenceProviderRuntime,
    packageJsonDigest: sha256(packageJson),
    packageLockDigest: sha256(packageLock),
    toolchain: {
      schemaVersion: "tideproof.build-toolchain.v2",
      architecture: "arm64",
      gitExecutableSha256: "5".repeat(64),
      gitVersion: "2.50.1 (Apple Git-155)",
      nodeExecutableSha256: "7".repeat(64),
      nodeVersion: "v22.23.1",
      npmCliSha256: "8".repeat(64),
      npmPackageBytes: 123456,
      npmPackageFileCount: 321,
      npmPackageTreeDigest: "6".repeat(64),
      npmVersion: "11.6.2",
      platform: "darwin"
    },
    thirdPartyNotices: {
      schema: "tideproof.bundled-third-party-notices.v1",
      status: "PASS",
      noticePath: "THIRD_PARTY_NOTICES.txt",
      noticeSha256: sha256(thirdPartyNotices),
      noticeBytes: thirdPartyNotices.length,
      packageLockSha256: sha256(packageLock),
      packageNames: ["@fixture/provider", "@fixture/runtime"],
      packageCount: 2,
      licenseTextCount: 2,
      fallbackCount: 0,
      licenses: { MIT: 2 }
    },
    bootstrapTemplate: {
      path: "infra/aws/bootstrap-template.json",
      templateDigest: sha256(bootstrapTemplate),
      canonicalDigest: bootstrapTemplateReceipt.canonicalDigest,
      bytes: bootstrapTemplate.length
    },
    gate2Template: {
      path: "infra/aws/gate2-template.json",
      templateDigest: sha256(gate2Template),
      canonicalDigest: gate2TemplateReceipt.canonicalDigest,
      bytes: gate2Template.length
    },
    artifacts
  };

  return {
    projectRoot,
    buildReceipt,
    cleanup() {
      fs.rmSync(projectRoot, { recursive: true, force: true });
    }
  };
}

function cleanAuditReport() {
  return {
    metadata: {
      vulnerabilities: {
        info: 0,
        low: 0,
        moderate: 0,
        high: 0,
        critical: 0,
        total: 0
      }
    }
  };
}

function releaseRightsReceipt() {
  return {
    schemaVersion: "tideproof.release-rights-verification.v1",
    status: "CURRENT_SURFACES_PASS",
    finalReleaseReady: false,
    reviewedOn: "2026-07-31",
    manifestPath: "docs/media/RIGHTS_MANIFEST.json",
    manifestSha256: "5".repeat(64),
    ledgerSha256: "6".repeat(64),
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

function accessibilityReceipt() {
  const pairs = [
    "amber-on-amber-surface",
    "blue-on-page",
    "blue-on-surface",
    "focus-on-page",
    "green-on-green-surface",
    "ink-on-page",
    "ink-on-surface",
    "line-strong-on-surface",
    "muted-on-page",
    "muted-on-surface",
    "red-on-red-surface"
  ];
  return {
    schemaVersion: "tideproof.accessibility-static.v1",
    status: "STATIC_SOURCE_PASS",
    finalReleaseReady: false,
    standardTarget: "WCAG_2_2_AA",
    rightsManifestSha256: "5".repeat(64),
    reviewedFiles: [
      ["architecture-svg", "docs/media/architecture.svg"],
      ["browser-app", "web/app.js"],
      ["browser-document", "web/index.html"],
      ["browser-styles", "web/styles.css"]
    ].map(([id, filePath], index) => ({
      id,
      path: filePath,
      sha256: String(index + 5).repeat(64)
    })),
    contrast: pairs.map((id) => ({
      id,
      foregroundToken: "fixture-foreground",
      backgroundToken: "fixture-background",
      foreground: "#ffffff",
      background: "#000000",
      minimumRatio: id === "focus-on-page" ? 3 : 4.5,
      ratio: 21
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
    checks: {
      exactRightsBoundSources: true,
      documentLanguageAndMetadata: true,
      landmarksAndHeadingOrder: true,
      skipNavigation: true,
      uniqueIdsAndAriaReferences: true,
      namedImagesAndControls: true,
      controlsFailClosedDuringLoad: true,
      keyboardPresenterPath: true,
      liveStatusAnnouncements: true,
      hiddenPageAutoplayPause: true,
      focusVisibility: true,
      reducedMotionSourceSupport: true,
      responsiveReflowGuards: true,
      minimumControlHeight: true,
      contrastPairsPass: true,
      unsafeDynamicHtmlAbsent: true,
      textualStatusLabelsPresent: true,
      architectureAlternativePresent: true
    },
    claimBoundary: "Fixture static accessibility only."
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
    manifestSha256: "4".repeat(64),
    commitCount: 50,
    commitIdentityCount: 3,
    trackedFileCount: 120,
    reachableBlobCount: 300,
    scannedBytes: 1_000_000,
    findingCount: 10,
    allowanceCount: 4,
    checks: {
      canonicalManifest: true,
      cleanBeforeAndAfter: true,
      fullReachableHistory: true,
      trackedPathPolicy: true,
      everyReachableBlobScanned: true,
      highConfidenceSignaturesReviewed: true,
      commitIdentitiesReviewed: true
    },
    finalReleaseRequirements: [
      "Rerun on the exact final official-main commit and bind the PASS receipt to hosted CI and deployed artifact hashes.",
      "Complete a private human review for secrets, personal data, internal URLs, metadata, screenshots, video, and submission fields."
    ],
    claimBoundary: "Fixture bounded privacy review only."
  };
}

function releaseClaimsReceipt() {
  return {
    schemaVersion: "tideproof.release-claims-verification.v1",
    status: "CURRENT_PUBLIC_CLAIMS_PASS",
    finalReleaseReady: false,
    reviewedOn: "2026-07-31",
    manifestPath: "RELEASE_CLAIMS_MANIFEST.json",
    manifestSha256: "7".repeat(64),
    proofManifestSha256: "8".repeat(64),
    claimCount: 12,
    claimStates: { VERIFIED: 5, PARTIAL: 7, PENDING: 0 },
    surfaceCount: RELEASE_CLAIMS_SURFACE_COUNT,
    stopTokenCount: RELEASE_CLAIMS_STOP_TOKEN_COUNT,
    uncheckedGateCount: RELEASE_CLAIMS_UNCHECKED_GATE_COUNT,
    externalUrls: [
      "http://127.0.0.1:4173",
      "https://cockroachdb-ai.devpost.com/",
      "https://cockroachdb-ai.devpost.com/resources",
      "https://cockroachdb-ai.devpost.com/rules",
      "https://github.com/Flash-Bri/prooftoact",
      "https://github.com/Flash-Bri/prooftoact.git"
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

function releaseCostReceipt() {
  return {
    schemaVersion: "tideproof.release-cost-verification.v1",
    status: "CURRENT_COST_GUARDS_PASS",
    finalReleaseReady: false,
    reviewedOn: "2026-07-31",
    manifestPath: "RELEASE_COST_MANIFEST.json",
    manifestSha256: "8".repeat(64),
    surfaceCount: RELEASE_COST_SURFACE_COUNT,
    budgetAlertCount: 4,
    forbiddenResourceTypeCount: 5,
    unapprovedPurchaseClassCount: 5,
    boundedFunctionCount: 10,
    logGroupCount: 11,
    finalReleaseRequirements: [
      ...costVerifierContract.EXPECTED_FINAL_RELEASE_REQUIREMENTS
    ],
    checks: {
      canonicalManifest: true,
      exactSurfaceHashes: true,
      budgetAndAlertsBounded: true,
      recordedSpendArithmeticExact: true,
      liveSpendClaimAbsent: true,
      deploymentStopPreserved: true,
      preflightCostCeilingsFailClosed: true,
      fixedChargeResourcesAbsent: true,
      runtimeAndLogBoundsExact: true,
      unapprovedPurchasesRemainBlocked: true
    },
    claimBoundary: "Fixture current-source cost guards only."
  };
}

function releaseGovernanceReceipt() {
  return {
    schemaVersion: "tideproof.release-governance-verification.v1",
    status: "CURRENT_REPOSITORY_GOVERNANCE_PASS",
    finalReleaseReady: false,
    reviewedOn: "2026-08-01",
    manifestPath: "RELEASE_GOVERNANCE_MANIFEST.json",
    manifestSha256: "5".repeat(64),
    snapshotPath:
      "evidence/github-release-governance-rename-2026-08-03.json",
    snapshotSha256: "6".repeat(64),
    observedAt: "2026-08-01T01:45:38Z",
    sourceCommit: "7".repeat(40),
    sourceTree: "8".repeat(40),
    surfaceCount: 8,
    requiredCheckCount: 1,
    requiredApprovingReviewCount: 0,
    finalReleaseRequirements: [
      "Requery final settings.",
      "Verify final hosted CI.",
      "Complete signed-out review."
    ],
    checks: {
      canonicalManifest: true,
      canonicalSnapshot: true,
      exactSurfaceHashes: true,
      publicRepositoryCoordinatesExact: true,
      branchProtectionSnapshotExact: true,
      securitySnapshotExact: true,
      requiredCiSnapshotExact: true,
      localWorkflowIdentityExact: true,
      publicBoundariesExplicit: true,
      nonfinalBoundaryPreserved: true
    },
    claimBoundary: "Fixture historical repository governance only."
  };
}

function releaseSecurityReceipt() {
  return {
    schemaVersion: "tideproof.release-security-verification.v1",
    status: "CURRENT_SOURCE_SECURITY_PASS",
    finalReleaseReady: false,
    reviewedOn: "2026-07-31",
    manifestPath: "RELEASE_SECURITY_MANIFEST.json",
    manifestSha256: "9".repeat(64),
    surfaceCount: RELEASE_SECURITY_SURFACE_COUNT,
    publicPathCount: 10,
    securityHeaderCount: 9,
    negativeProbeCount: 6,
    publicRouteCount: 10,
    iamRoleCount: 9,
    lambdaPermissionCount: 3,
    boundedFunctionCount: 5,
    logGroupCount: 11,
    finalReleaseRequirements: [
      ...securityVerifierContract.EXPECTED_FINAL_RELEASE_REQUIREMENTS
    ],
    checks: {
      canonicalManifest: true,
      exactSurfaceHashes: true,
      sourceSecurityMarkersPresent: true,
      generatedTemplateMatchesSource: true,
      exactPublicRouteSet: true,
      advisoryRouteIamAuthenticated: true,
      publicCorsAndLambdaUrlsAbsent: true,
      throttlesAndConcurrencyBounded: true,
      numericLambdaInvocationTargetsBounded: true,
      leastPrivilegeRoleActionsBounded: true,
      criticalRoleDenialsPresent: true,
      evidenceOperatorTrustBounded: true,
      deploymentAttestationContractBounded: true,
      exactGitArtifactInputsBounded: true,
      apiGatewayInvokePermissionsBounded: true,
      asymmetricSigningKeyBounded: true,
      logsBoundedAndPrivacyMinimized: true,
      publicHeadersAndNegativeProbesBounded: true
    },
    claimBoundary: "Fixture current source security review only."
  };
}

function releaseSubmissionReceipt() {
  return {
    schemaVersion: "tideproof.release-submission-verification.v1",
    status: "DRAFT_SAFELY_BLOCKED",
    finalReleaseReady: false,
    reviewedOn: "2026-07-31",
    manifestPath: "RELEASE_SUBMISSION_MANIFEST.json",
    manifestSha256: "6".repeat(64),
    surfaceCount: 10,
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
    checks: {
      canonicalManifest: true,
      exactSurfaceHashes: true,
      canonicalDraftStatus: true,
      submissionCoordinatesExact: true,
      officialScheduleInternallyConsistent: true,
      allHardPublishGatesUnchecked: true,
      exactStopTokenVocabulary: true,
      liveAndOwnerFieldsUnresolved: true,
      contestMatrixRemainsBlocked: true,
      releasePlanRemainsFailClosed: true,
      rightsAndClaimsRemainNonfinal: true,
      releaseClaimsPacketBindingExact: true
    },
    claimBoundary: "Fixture fail-closed submission draft only."
  };
}

function releaseProvenanceReceipt() {
  return {
    schemaVersion: "tideproof.release-provenance.v8",
    status: "PASS",
    source: {
      commit: SOURCE_COMMIT,
      tree: TREE_DIGEST,
      branch: "main",
      originMain: SOURCE_COMMIT,
      officialRemote: __test.OFFICIAL_REMOTE,
      cleanRoomRoot: __test.CLEAN_ROOM_ROOT
    },
    history: {
      rootCommit: __test.CLEAN_ROOM_ROOT,
      commitCount: 41,
      mergeCommitCount: 9,
      rootAuthorTime: "2026-07-29T07:21:03-04:00",
      rootCommitterTime: "2026-07-29T07:21:03-04:00",
      headAuthorTime: "2026-07-31T10:00:00-04:00",
      headCommitterTime: "2026-07-31T10:00:00-04:00",
      shallow: false,
      replaceRefCount: 0,
      replacementObjectsDisabled: true,
      filesystemMonitorDisabled: true,
      legacyGraftFilePresent: false,
      alternateObjectDatabaseCount: 0,
      objectIntegrity: true
    },
    trackedTree: {
      fileCount: 100,
      regularFileCount: 100,
      executableFileCount: 0,
      symlinkCount: 0,
      gitlinkCount: 0,
      indexEntryCount: 100,
      skipWorktreeEntryCount: 0,
      assumeUnchangedEntryCount: 0
    },
    claims: releaseClaimsReceipt(),
    cost: releaseCostReceipt(),
    governance: releaseGovernanceReceipt(),
    privacy: privacyReceipt(),
    rights: releaseRightsReceipt(),
    accessibility: accessibilityReceipt(),
    security: releaseSecurityReceipt(),
    submission: releaseSubmissionReceipt(),
    dependencies: {
      installedTree: {
        status: "PASS",
        lockedPackageCount: 72,
        installedPackageCount: 47,
        installedRuntimeCount: 44,
        installedDevelopmentOnlyCount: 3,
        installedOptionalCount: 2,
        omittedOptionalCount: 25,
        extraPackageCount: 0,
        mismatchedPackageCount: 0,
        packageLockSha256: "1".repeat(64)
      },
      inventory: {
        schema: "tideproof.dependency-inventory-verification.v1",
        status: "PASS",
        sourceLockSha256: "1".repeat(64),
        inventorySha256: "3".repeat(64),
        packageCount: 72,
        runtimeCount: 44,
        developmentOnlyCount: 28,
        optionalCount: 27,
        installScriptCount: 1,
        licenses: { MIT: 71, "MPL-2.0": 1 }
      },
      bundledThirdPartyNotices: {
        status: "PASS",
        noticePath: "THIRD_PARTY_NOTICES.txt",
        noticeSha256: "2".repeat(64),
        noticeBytes: 100,
        packageLockSha256: "1".repeat(64),
        packageCount: 42,
        licenseTextCount: 17,
        fallbackCount: 5,
        licenses: { MIT: 42 },
        artifactPackages: Object.fromEntries(
          [...__test.ARTIFACT_NAMES, "evidenceProvider"].map((name) => [
            name,
            []
          ])
        )
      }
    },
    checks: {
      officialCleanCheckout: true,
      fullSingleRootHistory: true,
      objectIntegrity: true,
      replaceRefsAbsent: true,
      legacyGraftsAbsent: true,
      alternateObjectDatabasesAbsent: true,
      trackedSymlinksAbsent: true,
      submodulesAbsent: true,
      installedTreeMatchesLock: true,
      dependencyInventoryMatchesLock: true,
      bundledThirdPartyNoticesMatchInputs: true,
      currentClaimSurfacesVerified: true,
      currentCostGuardsVerified: true,
      repositoryGovernanceSnapshotVerified: true,
      releasePrivacyVerified: true,
      currentSurfaceRightsVerified: true,
      staticAccessibilityVerified: true,
      currentSourceSecurityVerified: true,
      submissionDraftFailClosed: true,
      cleanBeforeAndAfter: true
    },
    claimBoundary: "Fixture provenance only."
  };
}

function preflightReceipt() {
  return {
    schemaVersion: "tideproof.gate2.aws-preflight.v5",
    status: "PASS",
    observedAt: "2026-07-31T05:30:00.000Z",
    sourceCommit: SOURCE_COMMIT,
    treeDigest: TREE_DIGEST,
    region: "us-east-1",
    controls: {
      authenticatedAwsCaller: true,
      callerBinding: {
        bindingDigest: "7".repeat(64),
        callerIdentityDigest: "8".repeat(64),
        contextDigest: "6".repeat(64),
        expectedIdentityDigest: "8".repeat(64),
        expectedPrincipalDigest: "9".repeat(64),
        principalIdDigest: "5".repeat(64),
        principalType: "iam-user"
      },
      bootstrapStack: {
        name: "tideproof-gate2-artifacts",
        status: "UPDATE_COMPLETE"
      },
      budget: {
        name: "tideproof-gate2-artifacts-account-safety",
        scope: "ACCOUNT_WIDE",
        type: "COST",
        timeUnit: "MONTHLY",
        costBasis: "UnblendedCost",
        defaultCostTypes: true,
        fixedLimit: true,
        limitUsd: 15,
        coverageStart: "2026-07-01T00:00:00.000Z",
        coverageEnd: "2087-06-15T00:00:00.000Z",
        budgetReportedActualUsd: "0.250000",
        conservativeObservedActualUsd: "0.250000",
        notifications: [
          ["ACTUAL", 1],
          ["ACTUAL", 5],
          ["ACTUAL", 10],
          ["FORECASTED", 15]
        ].map(([metric, thresholdUsd]) => ({
          metric,
          comparison: "GREATER_THAN",
          thresholdUsd,
          thresholdType: "ABSOLUTE_VALUE",
          emailRecipientCount: 1
        }))
      },
      currentCost: {
        scope: "ACCOUNT_WIDE_PROJECT_WINDOW_TO_DATE",
        periodStart: "2026-07-01",
        periodEndExclusive: "2026-08-01",
        amountUsd: "0.200000",
        estimated: true
      },
      projectExposure: {
        scope: "TIDEPROOF_TOTAL_APPROVED_EXPOSURE",
        ceilingUsd: "25.000000",
        recordedNonAwsSpendUsd: "11.860000",
        effectiveAwsSpendCeilingUsd: "13.140000",
        conservativeObservedTotalExposureUsd: "12.110000",
        remainingExposureUsd: "12.890000",
        awsCostWindowStart: "2026-07-01",
        recordedSpendBasis:
          "OWNER_REPORTED_TIDEPROOF_NET_REGISTRATION",
        registrarReceiptVerified: false,
        autoRenewReportedEnabled: false
      },
      mainGateTwoStack: {
        name: "prooftoact-gate2",
        state: "ABSENT",
        legacyName: "tideproof-gate2",
        legacyState: "ABSENT"
      },
      bedrock: {
        modelId: "amazon.nova-micro-v1:0",
        catalogStatus: "ACTIVE",
        textInput: true,
        textOutput: true,
        onDemandListed: true
      },
      artifactBucket: {
        versioningEnabled: true,
        aes256AtRest: true,
        publicAccessBlocked: true,
        bucketOwnerEnforced: true,
        tlsOnlyPolicy: true
      }
    },
    privacy:
      "AWS account, caller ARN, bucket name, and subscriber addresses were validated but omitted.",
    claimBoundary:
      "Read-only preflight fixture; no AWS mutation or live behavior claim."
  };
}

function successfulRunner(buildReceipt, calls) {
  return (command, args, options = {}) => {
    const call = [command, ...args];
    call.options = options;
    calls.push(call);
    const shape = `${command} ${args.join(" ")}`;
    let stdout = "";
    if (shape === "git remote get-url origin") {
      stdout = `${__test.OFFICIAL_REMOTE}\n`;
    } else if (shape === "git symbolic-ref --short HEAD") {
      stdout = "main\n";
    } else if (shape === "git rev-parse HEAD") {
      stdout = `${SOURCE_COMMIT}\n`;
    } else if (
      shape === "git rev-parse refs/remotes/origin/main"
    ) {
      stdout = `${SOURCE_COMMIT}\n`;
    } else if (shape === "git rev-parse HEAD^{tree}") {
      stdout = `${TREE_DIGEST}\n`;
    } else if (
      shape === "npm run --silent release:provenance"
    ) {
      stdout = JSON.stringify(releaseProvenanceReceipt());
    } else if (
      shape === "npm audit --json --audit-level=low"
    ) {
      stdout = JSON.stringify(cleanAuditReport());
    } else if (
      shape === "npm run --silent build:gate2"
    ) {
      stdout = JSON.stringify(buildReceipt);
    } else if (
      shape === "npm run --silent gate2:aws-preflight"
    ) {
      stdout = JSON.stringify(preflightReceipt());
    }
    return { status: 0, stdout, stderr: "" };
  };
}

test("AWS readiness validates every exact-head artifact byte", () => {
  const current = fixture();
  try {
    const accepted = validateBuildReceipt(
      current.buildReceipt,
      {
        projectRoot: current.projectRoot,
        sourceCommit: SOURCE_COMMIT,
        treeDigest: TREE_DIGEST
      }
    );
    assert.equal(accepted.mode, "CLEAN_ARTIFACT_BUILD");
    assert.deepEqual(
      Object.keys(accepted.artifacts).sort(),
      [...__test.ARTIFACT_NAMES].sort()
    );
    assert.equal(
      accepted.artifacts.demo.artifactDigest,
      current.buildReceipt.artifacts.find(
        (artifact) => artifact.name === "demo"
      ).artifactDigest
    );
  } finally {
    current.cleanup();
  }
});

test("AWS readiness rejects substituted exact-Git input identity", () => {
  const current = fixture();
  try {
    current.buildReceipt.artifacts[0].exactGitInputs[0].gitBlobId =
      "0".repeat(40);
    assert.throws(
      () =>
        validateBuildReceipt(current.buildReceipt, {
          projectRoot: current.projectRoot,
          sourceCommit: SOURCE_COMMIT,
          treeDigest: TREE_DIGEST
        }),
      /AWS_READINESS_EXACT_GIT_INPUT_DIGEST/
    );
  } finally {
    current.cleanup();
  }
});

test("AWS readiness rejects a fabricated dependency or toolchain snapshot", () => {
  const current = fixture();
  try {
    current.buildReceipt.dependencySnapshot.treeDigest = "0";
    assert.throws(
      () =>
        validateBuildReceipt(current.buildReceipt, {
          projectRoot: current.projectRoot,
          sourceCommit: SOURCE_COMMIT,
          treeDigest: TREE_DIGEST
        }),
      /DEPENDENCY_SNAPSHOT_RECEIPT/
    );
    current.buildReceipt.dependencySnapshot.treeDigest = "9".repeat(64);
    current.buildReceipt.toolchain.npmCliSha256 = "0";
    assert.throws(
      () =>
        validateBuildReceipt(current.buildReceipt, {
          projectRoot: current.projectRoot,
          sourceCommit: SOURCE_COMMIT,
          treeDigest: TREE_DIGEST
        }),
      /DEPENDENCY_SNAPSHOT_TOOLCHAIN/
    );
  } finally {
    current.cleanup();
  }
});

test("AWS readiness rejects an artifact changed after the build", () => {
  const current = fixture();
  try {
    const artifact =
      current.buildReceipt.artifacts[0];
    fs.appendFileSync(
      path.join(current.projectRoot, artifact.artifactPath),
      "tamper"
    );
    assert.throws(
      () =>
        validateBuildReceipt(current.buildReceipt, {
          projectRoot: current.projectRoot,
          sourceCommit: SOURCE_COMMIT,
          treeDigest: TREE_DIGEST
        }),
      /AWS_READINESS_ARTIFACT_DIGEST/
    );
  } finally {
    current.cleanup();
  }
});

test("AWS readiness rejects changed third-party notice bytes", () => {
  const current = fixture();
  try {
    fs.appendFileSync(
      path.join(current.projectRoot, "THIRD_PARTY_NOTICES.txt"),
      "tamper\n"
    );
    assert.throws(
      () =>
        validateBuildReceipt(current.buildReceipt, {
          projectRoot: current.projectRoot,
          sourceCommit: SOURCE_COMMIT,
          treeDigest: TREE_DIGEST
        }),
      /AWS_READINESS_THIRD_PARTY_NOTICE_DIGEST/
    );
  } finally {
    current.cleanup();
  }
});

test("AWS readiness rejects a hash-valid ZIP without bundled notices", () => {
  const current = fixture();
  try {
    const artifact = current.buildReceipt.artifacts[0];
    const source = fs.readFileSync(
      path.join(current.projectRoot, artifact.sourcePath)
    );
    const archive = deterministicZip([
      { fileName: "index.js", content: source }
    ]);
    const artifactDigest = sha256(archive);
    const artifactFile = `${artifact.name}-${artifactDigest}.zip`;
    artifact.artifactDigest = artifactDigest;
    artifact.artifactFile = artifactFile;
    artifact.artifactPath = `dist/aws/${artifactFile}`;
    artifact.artifactCodeSha256 = sha256(archive, "base64");
    artifact.artifactBytes = archive.length;
    artifact.suggestedS3Key =
      `gate2/${SOURCE_COMMIT}/${artifactFile}`;
    writeFile(current.projectRoot, artifact.artifactPath, archive);

    assert.throws(
      () =>
        validateBuildReceipt(current.buildReceipt, {
          projectRoot: current.projectRoot,
          sourceCommit: SOURCE_COMMIT,
          treeDigest: TREE_DIGEST
        }),
      /AWS_READINESS_ZIP_END/
    );
  } finally {
    current.cleanup();
  }
});

test("AWS readiness requires a zero-vulnerability audit", () => {
  assert.deepEqual(validateAuditReport(cleanAuditReport()), {
    status: "PASS",
    knownVulnerabilities: 0
  });
  const vulnerable = cleanAuditReport();
  vulnerable.metadata.vulnerabilities.high = 1;
  vulnerable.metadata.vulnerabilities.total = 1;
  assert.throws(
    () => validateAuditReport(vulnerable),
    /AWS_READINESS_AUDIT/
  );
});

test("AWS readiness binds the preflight to the exact checkout", () => {
  const receipt = preflightReceipt();
  assert.equal(
    validatePreflightReceipt(receipt, {
      sourceCommit: SOURCE_COMMIT,
      treeDigest: TREE_DIGEST
    }),
    receipt
  );
  assert.throws(
    () =>
      validatePreflightReceipt(receipt, {
        sourceCommit: "e".repeat(40),
        treeDigest: TREE_DIGEST
      }),
    /AWS_READINESS_PREFLIGHT/
  );
});

test("AWS readiness binds release provenance to the exact checkout", () => {
  const receipt = releaseProvenanceReceipt();
  assert.equal(
    validateReleaseProvenance(receipt, {
      sourceCommit: SOURCE_COMMIT,
      treeDigest: TREE_DIGEST
    }),
    receipt
  );
  assert.throws(
    () =>
      validateReleaseProvenance(receipt, {
        sourceCommit: "e".repeat(40),
        treeDigest: TREE_DIGEST
      }),
    /AWS_READINESS_RELEASE_PROVENANCE/
  );
  const overstated = releaseProvenanceReceipt();
  overstated.rights.finalReleaseReady = true;
  assert.throws(
    () =>
      validateReleaseProvenance(overstated, {
        sourceCommit: SOURCE_COMMIT,
        treeDigest: TREE_DIGEST
      }),
    /AWS_READINESS_RELEASE_PROVENANCE/
  );
  const prematureClaims = releaseProvenanceReceipt();
  prematureClaims.claims.finalReleaseReady = true;
  assert.throws(
    () =>
      validateReleaseProvenance(prematureClaims, {
        sourceCommit: SOURCE_COMMIT,
        treeDigest: TREE_DIGEST
      }),
    /AWS_READINESS_RELEASE_PROVENANCE/
  );
  const prematureCost = releaseProvenanceReceipt();
  prematureCost.cost.finalReleaseReady = true;
  assert.throws(
    () =>
      validateReleaseProvenance(prematureCost, {
        sourceCommit: SOURCE_COMMIT,
        treeDigest: TREE_DIGEST
      }),
    /AWS_READINESS_RELEASE_PROVENANCE/
  );
  const inaccessible = releaseProvenanceReceipt();
  inaccessible.accessibility.contrast[0].ratio = 1;
  assert.throws(
    () =>
      validateReleaseProvenance(inaccessible, {
        sourceCommit: SOURCE_COMMIT,
        treeDigest: TREE_DIGEST
      }),
    /AWS_READINESS_RELEASE_PROVENANCE/
  );
  const insecure = releaseProvenanceReceipt();
  insecure.security.checks.criticalRoleDenialsPresent = false;
  assert.throws(
    () =>
      validateReleaseProvenance(insecure, {
        sourceCommit: SOURCE_COMMIT,
        treeDigest: TREE_DIGEST
      }),
    /AWS_READINESS_RELEASE_PROVENANCE/
  );
  for (const offset of [-1, 1]) {
    for (const field of [
      "surfaceCount",
      "stopTokenCount",
      "uncheckedGateCount"
    ]) {
      const staleClaimsContract = releaseProvenanceReceipt();
      staleClaimsContract.claims[field] += offset;
      assert.throws(
        () =>
          validateReleaseProvenance(staleClaimsContract, {
            sourceCommit: SOURCE_COMMIT,
            treeDigest: TREE_DIGEST
          }),
        /AWS_READINESS_RELEASE_PROVENANCE/
      );
    }
    const staleCostContract = releaseProvenanceReceipt();
    staleCostContract.cost.surfaceCount =
      RELEASE_COST_SURFACE_COUNT + offset;
    assert.throws(
      () =>
        validateReleaseProvenance(staleCostContract, {
          sourceCommit: SOURCE_COMMIT,
          treeDigest: TREE_DIGEST
        }),
      /AWS_READINESS_RELEASE_PROVENANCE/
    );
    const staleSecurityContract = releaseProvenanceReceipt();
    staleSecurityContract.security.surfaceCount =
      RELEASE_SECURITY_SURFACE_COUNT + offset;
    assert.throws(
      () =>
        validateReleaseProvenance(staleSecurityContract, {
          sourceCommit: SOURCE_COMMIT,
          treeDigest: TREE_DIGEST
        }),
      /AWS_READINESS_RELEASE_PROVENANCE/
    );
  }
  const hiddenIndexEntry = releaseProvenanceReceipt();
  hiddenIndexEntry.trackedTree.skipWorktreeEntryCount = 1;
  assert.throws(
    () =>
      validateReleaseProvenance(hiddenIndexEntry, {
        sourceCommit: SOURCE_COMMIT,
        treeDigest: TREE_DIGEST
      }),
    /AWS_READINESS_RELEASE_PROVENANCE/
  );
  const replacementObjectsEnabled = releaseProvenanceReceipt();
  replacementObjectsEnabled.history.replacementObjectsDisabled = false;
  assert.throws(
    () =>
      validateReleaseProvenance(replacementObjectsEnabled, {
        sourceCommit: SOURCE_COMMIT,
        treeDigest: TREE_DIGEST
      }),
    /AWS_READINESS_RELEASE_PROVENANCE/
  );
  const submissionReady = releaseProvenanceReceipt();
  submissionReady.submission.finalReleaseReady = true;
  assert.throws(
    () =>
      validateReleaseProvenance(submissionReady, {
        sourceCommit: SOURCE_COMMIT,
        treeDigest: TREE_DIGEST
      }),
    /AWS_READINESS_RELEASE_PROVENANCE/
  );
  const unsupportedInventoryLicense = releaseProvenanceReceipt();
  unsupportedInventoryLicense.dependencies.inventory.licenses = {
    MIT: 71,
    "GPL-3.0": 1
  };
  assert.throws(
    () =>
      validateReleaseProvenance(unsupportedInventoryLicense, {
        sourceCommit: SOURCE_COMMIT,
        treeDigest: TREE_DIGEST
      }),
    /AWS_READINESS_RELEASE_PROVENANCE/
  );
});

test("AWS readiness full mode performs only reviewed command families", async () => {
  const current = fixture();
  const calls = [];
  try {
    const receipt = await runAwsReadiness({
      projectRoot: current.projectRoot,
      run: successfulRunner(current.buildReceipt, calls)
    });
    assert.equal(receipt.status, "PASS");
    assert.equal(receipt.checks.awsPreflight, "PASS");
    assert.equal(receipt.checks.releaseProvenance, true);
    assert.equal(receipt.checks.staticAccessibility, true);
    assert.equal(receipt.source.commit, SOURCE_COMMIT);
    assert.equal(
      calls.some(
        (call) =>
          call[0] === "npm" &&
          call.includes("gate2:aws-preflight")
      ),
      true
    );
    const preflightCall = calls.find(
      (call) =>
        call[0] === "npm" &&
        call.includes("gate2:aws-preflight")
    );
    assert.deepEqual(preflightCall.options, {
      awsAuthenticated: true
    });
    assert.equal(
      calls
        .filter((call) => call !== preflightCall)
        .every(
          (call) =>
            call.options.awsAuthenticated !== true
        ),
      true
    );
    assert.equal(
      calls.some(
        (call) =>
          call[0] === "npm" &&
          call[1] === "ci" &&
          call.includes("--ignore-scripts")
      ),
      true
    );
    assert.equal(
      calls.every(
        (call) =>
          call[0] === "git" || call[0] === "npm"
      ),
      true
    );
    const fetches = calls.filter((call) =>
      call.includes("fetch")
    );
    assert.equal(fetches.length, 2);
    assert.equal(
      fetches.every((call) =>
        call.includes(
          "http.https://github.com/.extraheader="
        )
      ),
      true
    );
  } finally {
    current.cleanup();
  }
});

test("AWS readiness local mode is explicit non-AWS evidence", async () => {
  const current = fixture();
  const calls = [];
  try {
    const receipt = await runAwsReadiness({
      projectRoot: current.projectRoot,
      localOnly: true,
      now: () => new Date("2026-07-31T05:45:00.000Z"),
      run: successfulRunner(current.buildReceipt, calls)
    });
    assert.equal(receipt.status, "LOCAL_ONLY_PASS");
    assert.equal(receipt.awsPreflight, null);
    assert.equal(receipt.checks.awsPreflight, "NOT_RUN");
    assert.equal(receipt.checks.staticAccessibility, true);
    assert.equal(
      calls.some((call) => call.includes("gate2:aws-preflight")),
      false
    );
  } finally {
    current.cleanup();
  }
});

test("AWS readiness accepts only full or explicit local mode", () => {
  assert.deepEqual(parseArguments([]), { localOnly: false });
  assert.deepEqual(parseArguments(["--local-only"]), {
    localOnly: true
  });
  assert.throws(
    () => parseArguments(["--execute"]),
    /AWS_READINESS_ARGUMENT/
  );
});

test("AWS readiness accepts only public official remote forms", () => {
  assert.equal(
    __test.isOfficialRemote(
      "https://github.com/Flash-Bri/prooftoact.git"
    ),
    true
  );
  assert.equal(
    __test.isOfficialRemote(
      "https://github.com/Flash-Bri/prooftoact"
    ),
    true
  );
  assert.equal(
    __test.isOfficialRemote(
      "git@github.com:Flash-Bri/prooftoact.git"
    ),
    false
  );
  assert.equal(
    __test.isOfficialRemote(
      "https://github.com/other/tideproof.git"
    ),
    false
  );
});

test("AWS readiness isolates credentials outside the AWS preflight", () => {
  const source = {
    PATH: "/usr/bin",
    AWS_ACCESS_KEY_ID: "temporary-access",
    AWS_SESSION_TOKEN: "temporary-session",
    aws_access_key_id: "lowercase-secret",
    AWS_ENDPOINT_URL: "http://127.0.0.1:9000",
    AWS_ENDPOINT_URL_STS: "http://127.0.0.1:9001",
    AWS_CONFIG_FILE: "/tmp/aws-config",
    AWS_PROFILE: "unreviewed",
    AWS_EVIDENCE_EXPECTED_ACCOUNT_ID: "111111111111",
    AWS_EVIDENCE_EXPECTED_PREFLIGHT_PRINCIPAL_ARN:
      "arn:aws:iam::111111111111:user/tideproof-deployer",
    AWS_EVIDENCE_EXPECTED_PREFLIGHT_CALLER_ARN:
      "arn:aws:iam::111111111111:user/tideproof-deployer",
    AWS_EVIDENCE_EXPECTED_PREFLIGHT_CALLER_USER_ID: "AIDATIDEPROOF",
    DATABASE_URL: "postgresql://private",
    GIT_OBJECT_DIRECTORY: "/tmp/objects",
    NODE_OPTIONS: "--require=/tmp/inject.js",
    NODE_DEBUG: "child_process",
    NODE_TLS_REJECT_UNAUTHORIZED: "0",
    NODE_EXTRA_CA_CERTS: "/tmp/untrusted-ca.pem",
    NODE_V8_COVERAGE: "/tmp/coverage",
    LD_AUDIT: "/tmp/injected-audit.so",
    LD_DEBUG: "all",
    LD_LIBRARY_PATH: "/tmp/injected-libraries",
    DYLD_INSERT_LIBRARIES: "/tmp/injected.dylib",
    npm_config_userconfig: "/tmp/npmrc",
    TMPDIR: "/tmp/untrusted-runtime",
    OPENAI_API_KEY: "private-model-key",
    SAFE_VALUE: "retained"
  };
  const isolated = __test.childEnvironment(source);
  assert.equal(isolated.PATH, "/usr/bin:/bin");
  assert.equal(isolated.TMPDIR, fs.realpathSync("/tmp"));
  assert.notEqual(isolated.TMPDIR, source.TMPDIR);
  assert.equal(isolated.SAFE_VALUE, undefined);
  assert.equal(isolated.AWS_ACCESS_KEY_ID, undefined);
  assert.equal(isolated.AWS_SESSION_TOKEN, undefined);
  assert.equal(isolated.DATABASE_URL, undefined);
  assert.equal(isolated.GIT_OBJECT_DIRECTORY, undefined);
  assert.equal(isolated.NODE_OPTIONS, undefined);
  assert.equal(isolated.OPENAI_API_KEY, undefined);
  assert.equal(
    isolated.AWS_SHARED_CREDENTIALS_FILE,
    "/dev/null"
  );
  assert.equal(isolated.AWS_ENDPOINT_URL, undefined);
  assert.equal(isolated.AWS_ENDPOINT_URL_STS, undefined);
  assert.equal(isolated.AWS_EVIDENCE_EXPECTED_ACCOUNT_ID, undefined);
  assert.equal(isolated.aws_access_key_id, undefined);
  assert.equal(isolated.NODE_DEBUG, undefined);
  assert.equal(isolated.LD_AUDIT, undefined);
  assert.equal(isolated.LD_DEBUG, undefined);
  assert.equal(isolated.LD_LIBRARY_PATH, undefined);
  assert.equal(isolated.DYLD_INSERT_LIBRARIES, undefined);
  assert.equal(isolated.GIT_TERMINAL_PROMPT, "0");
  assert.equal(
    isolated.npm_config_userconfig,
    "/etc/tideproof-npm-userconfig"
  );
  assert.equal(
    isolated.npm_config_globalconfig,
    "/etc/tideproof-npm-globalconfig"
  );
  assert.equal(isolated.npm_config_ignore_scripts, "true");
  assert.equal(isolated.npm_config_script_shell, "/bin/sh");

  assert.throws(
    () =>
      __test.childEnvironment(source, {
        awsAuthenticated: true
      }),
    /AWS_EVIDENCE_ENDPOINT_OVERRIDE/
  );
  const authenticated = __test.childEnvironment(
    Object.fromEntries(
      Object.entries(source).filter(
        ([name]) => !name.startsWith("AWS_ENDPOINT_URL")
      )
    ),
    { awsAuthenticated: true }
  );
  assert.equal(
    authenticated.AWS_ACCESS_KEY_ID,
    "temporary-access"
  );
  assert.equal(
    authenticated.AWS_SESSION_TOKEN,
    "temporary-session"
  );
  assert.equal(authenticated.AWS_ENDPOINT_URL, undefined);
  assert.equal(authenticated.AWS_ENDPOINT_URL_STS, undefined);
  assert.equal(authenticated.aws_access_key_id, undefined);
  assert.equal(authenticated.AWS_PROFILE, undefined);
  assert.equal(authenticated.NODE_DEBUG, undefined);
  assert.equal(authenticated.NODE_TLS_REJECT_UNAUTHORIZED, undefined);
  assert.equal(authenticated.NODE_EXTRA_CA_CERTS, undefined);
  assert.equal(authenticated.NODE_V8_COVERAGE, undefined);
  assert.equal(authenticated.LD_AUDIT, undefined);
  assert.equal(authenticated.LD_LIBRARY_PATH, undefined);
  assert.equal(authenticated.SAFE_VALUE, undefined);
  assert.equal(
    authenticated.AWS_EVIDENCE_EXPECTED_ACCOUNT_ID,
    "111111111111"
  );
  assert.equal(authenticated.AWS_CONFIG_FILE, "/dev/null");
  assert.equal(
    authenticated.AWS_SHARED_CREDENTIALS_FILE,
    "/dev/null"
  );
  assert.equal(
    authenticated.AWS_IGNORE_CONFIGURED_ENDPOINT_URLS,
    "true"
  );
  assert.equal(authenticated.DATABASE_URL, undefined);
  assert.equal(authenticated.OPENAI_API_KEY, undefined);
  assert.equal(authenticated.AWS_CONFIG_FILE, "/dev/null");
});

test("AWS readiness ignores PATH-selected Git and npm wrappers", () => {
  const projectRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "tideproof-readiness-tools-")
  );
  try {
    for (const name of ["git", "npm"]) {
      fs.writeFileSync(
        path.join(projectRoot, name),
        `#!/bin/sh\necho PATH_WRAPPER_${name.toUpperCase()}\n`,
        { mode: 0o755 }
      );
    }
    const runner = __test.defaultRunner(projectRoot, {
      ...process.env,
      npm_execpath:
        process.env.npm_execpath ??
        fs.realpathSync(path.join(path.dirname(process.execPath), "npm")),
      npm_node_execpath: process.execPath,
      PATH: projectRoot
    });
    const gitResult = runner("git", ["--version"]);
    const npmResult = runner("npm", ["--version"]);
    assert.equal(gitResult.status, 0);
    assert.equal(npmResult.status, 0);
    assert.match(gitResult.stdout, /^git version /);
    assert.match(npmResult.stdout, /^[0-9]+\.[0-9]+\.[0-9]+\n$/);
    assert.doesNotMatch(gitResult.stdout, /PATH_WRAPPER/);
    assert.doesNotMatch(npmResult.stdout, /PATH_WRAPPER/);
    assert.throws(
      () => runner("node", ["--version"]),
      /AWS_READINESS_COMMAND/
    );
  } finally {
    fs.rmSync(projectRoot, { force: true, recursive: true });
  }
});
