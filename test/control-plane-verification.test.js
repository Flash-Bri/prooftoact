import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  CONTROL_PLANE_VERIFICATION_CONSTANTS,
  buildReleaseControlMetadata,
  buildCandidate,
  canonicalJson,
  renderDependencyInventory,
  renderDependencyInventoryJson,
  renderProviderDependencyInventoryJson,
  renderProviderThirdPartyNotices,
  renderThirdPartyNotices,
  validateGovernanceEvidence,
  validateProvenanceEvidence,
  verifyReleaseControlMetadata,
  verifyReleaseProviderMetadata,
  verifyCandidate
} from "../control-plane-verification/control-plane-verification.js";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const HEX = "a".repeat(64);

function governanceEvidence() {
  return {
    schemaVersion:
      CONTROL_PLANE_VERIFICATION_CONSTANTS.GOVERNANCE_EVIDENCE_SCHEMA,
    status: "ACCEPTED",
    repository: "Flash-Bri/prooftoact",
    repositoryId: "1317716765",
    accountIdSha256: HEX,
    observedAt: "2026-08-17T22:00:00.000Z",
    branchProtection: {
      administratorsEnforced: true,
      deletionAllowed: false,
      forcePushAllowed: false,
      requiredCheck: "verify",
      status: "ACCEPTED",
      strict: true
    },
    environments: CONTROL_PLANE_VERIFICATION_CONSTANTS.GOVERNANCE_LANES.map((item) => ({
      adminsCanBypass: false,
      deploymentBranch: "main",
      environment: item.environment,
      jobNames: item.jobNames,
      preventSelfReview: true,
      requiredReviewerCount: 1,
      roleArnSha256: HEX,
      trustPolicySha256: "b".repeat(64),
      workflowRef:
        `Flash-Bri/prooftoact/.github/workflows/${item.file}@refs/heads/main`
    }))
  };
}

function provenanceEvidence(dependencies, providerDependencies) {
  return {
    schemaVersion:
      CONTROL_PLANE_VERIFICATION_CONSTANTS.PROVENANCE_EVIDENCE_SCHEMA,
    status: "ACCEPTED",
    origin: "https://github.com/Flash-Bri/prooftoact.git",
    controlPlane: {
      commit: "1".repeat(40),
      tree: "2".repeat(40)
    },
    frozenApplication: {
      commit: "963937a9873f0199b91897fe88da1b91bc84b5e3",
      tree: "a330e0d57328e63a568be73c523b2cae6338f26c"
    },
    git: {
      grafts: false,
      replacements: false,
      shallow: false,
      standalone: true
    },
    clean: true,
    install: {
      releaseControl: {
        arguments: ["ci", "--ignore-scripts"],
        packageLockSha256: dependencies.packageLockSha256
      },
      releaseProvider: {
        arguments: ["ci", "--ignore-scripts"],
        packageLockSha256: providerDependencies.packageLockSha256
      }
    },
    node: {
      executableSha256: "3".repeat(64),
      version: "v22.23.1"
    },
    npm: {
      version: "10.9.8"
    },
    build: {
      releaseControl: {
        packageJsonSha256: dependencies.packageSha256,
        packageLockSha256: dependencies.packageLockSha256,
        receiptSha256: "4".repeat(64),
        reproducible: true,
        runtimeSha256: "5".repeat(64)
      },
      releaseProvider: {
        externalImports: ["node:buffer", "node:crypto"],
        packageJsonSha256: providerDependencies.packageSha256,
        packageLockSha256: providerDependencies.packageLockSha256,
        receiptSha256: "6".repeat(64),
        reproducible: true,
        runtimeCount: 3,
        runtimeSetSha256: providerDependencies.runtimeSetSha256,
        sourceInventorySha256: "7".repeat(64)
      }
    },
    tests: {
      failed: 0,
      passed: 100,
      skipped: 0
    },
    auditFindingCount: 0
  };
}

test("candidate deterministically binds the complete control-plane surface", () => {
  const candidate = buildCandidate({ rootDir: ROOT });
  const result = verifyCandidate(candidate, { rootDir: ROOT });
  assert.equal(result.bodySha256, candidate.bodySha256);
  assert.equal(result.providerExecutionAuthorized, false);
  assert.equal(candidate.body.claimBoundary.sourceConfigurationOnly, true);
  assert.equal(candidate.body.claimBoundary.providerFactsInferredFromSource, false);
  assert.equal(candidate.body.dependencies.packageCount > 0, true);
  assert.equal(candidate.body.dependencies.ready, true);
  assert.equal(candidate.body.providerDependencies.packageCount > 0, true);
  assert.equal(candidate.body.providerDependencies.ready, true);
  assert.equal(candidate.body.notices.ready, true);
  assert.equal(candidate.body.providerNotices.ready, true);
  assert.equal(candidate.body.security.ready, true);
  assert.equal(candidate.body.cost.controlPlaneCumulativeCapUsd, 20);
  assert.equal(candidate.body.cost.historicalApplicationCostPolicy,
    "UNCHANGED_SEPARATE_FROZEN_APPLICATION_CONTROL");
  assert.equal(candidate.body.governance.sourceMappings.length, 7);
  assert.equal(candidate.body.governance.providerEvidence.status, "NOT_PROVIDED");
  assert.equal(candidate.body.provenance.providerEvidence.status, "NOT_PROVIDED");
  assert.equal(candidate.body.readiness.providerExecutionAuthorized, false);

  const inventoryPaths = candidate.body.inventory.files.map((item) => item.path);
  for (const workflow of CONTROL_PLANE_VERIFICATION_CONSTANTS.WORKFLOWS) {
    assert.equal(inventoryPaths.includes(`.github/workflows/${workflow.file}`), true);
  }
  for (const exactPath of [
    "config/prooftoact-release-operator-public.pub",
    "infra/aws/release-deployment-roles-template.json",
    "release-control/package.json",
    "release-control/package-lock.json",
    "release-control/DEPENDENCY_INVENTORY.json",
    "release-control/THIRD_PARTY_NOTICES.txt",
    "release-control/build-release-control-runtime.js",
    "release-provider/package.json",
    "release-provider/package-lock.json",
    "release-provider/DEPENDENCY_INVENTORY.json",
    "release-provider/THIRD_PARTY_NOTICES.txt",
    "release-provider/build-release-provider-runtimes.js",
    "release-provider/generate-release-provider-metadata.js",
    "scripts/bootstrap-fresh-primary.js",
    "scripts/normalize-release-control-checkouts.js",
    "scripts/prepare-release-control-bootstrap.js",
    "scripts/prepare-release-deployment.js",
    "scripts/release-provider-controller.js",
    "scripts/release-provider-one-shot-broker.js",
    "scripts/run-release-prepare-common.js",
    "scripts/run-release-prepare-diagnostic.js",
    "scripts/run-release-prepare-phase.js",
    "scripts/run-release-prepare-preflight.js",
    "scripts/sign-release-provider-approval.js",
    "test/control-plane-verification.test.js",
    "test/release-control-bootstrap-plan.test.js",
    "test/release-provider-runtime-loader.test.js",
    "test/release-provider-runtime.test.js",
    "test/release-prepare-runner.test.js"
  ]) assert.equal(inventoryPaths.includes(exactPath), true, exactPath);

  for (const name of fs.readdirSync(path.join(ROOT, "release-control/src"))
    .filter((item) => /^release-control-.*\.js$/u.test(item))) {
    assert.equal(inventoryPaths.includes(`release-control/src/${name}`), true, name);
  }
  for (const name of fs.readdirSync(path.join(ROOT, "release-provider/src"))
    .filter((item) => /^release-provider-.*\.js$/u.test(item))) {
    assert.equal(inventoryPaths.includes(`release-provider/src/${name}`), true,
      name);
  }
  assert.equal(candidate.body.proof.inventorySha256,
    candidate.body.inventory.inventorySha256);
  assert.match(candidate.body.proof.controlPlaneSurfaceSha256,
    /^[0-9a-f]{64}$/u);
  assert.match(candidate.body.proof.governanceSourceSha256,
    /^[0-9a-f]{64}$/u);
  assert.match(candidate.body.proof.securityContractSha256,
    /^[0-9a-f]{64}$/u);
  assert.equal(candidate.body.metadataArtifacts.ready, true);
  assert.equal(candidate.body.metadataArtifacts.artifacts.every((item) =>
    item.status === "VERIFIED"), true);
  assert.equal(candidate.body.providerMetadataArtifacts.ready, true);
  assert.equal(candidate.body.providerMetadataArtifacts.artifacts.every((item) =>
    item.status === "VERIFIED"), true);
  assert.equal(candidate.body.inventory.files.every((item) =>
    typeof item.gitTracked === "boolean" &&
    typeof item.gitMatchesHead === "boolean"), true);
  for (const item of candidate.body.inventory.untrackedPaths) {
    assert.equal(candidate.body.findings.includes(`UNTRACKED:${item}`), true,
      item);
  }
  for (const item of candidate.body.inventory.dirtyPaths) {
    assert.equal(candidate.body.findings.includes(`DIRTY:${item}`), true,
      item);
  }
  assert.equal(candidate.body.governance.sourceMappings.every((item) =>
    item.workflowSourceBound), true);
  assert.equal(candidate.body.readiness.localSourceReady,
    candidate.body.findings.length === 0);
});

test("candidate envelope and current source mismatch fail closed", () => {
  const candidate = buildCandidate({ rootDir: ROOT });
  const tampered = structuredClone(candidate);
  tampered.body.claimBoundary.providerActionsPerformed = true;
  assert.throws(() => verifyCandidate(tampered, { rootDir: ROOT }),
    /CONTROL_PLANE_CANDIDATE_ENVELOPE_REJECTED/u);
  const wrongDigest = structuredClone(candidate);
  wrongDigest.bodySha256 = "0".repeat(64);
  assert.throws(() => verifyCandidate(wrongDigest, { rootDir: ROOT }),
    /CONTROL_PLANE_CANDIDATE_ENVELOPE_REJECTED/u);
});

test("governance evidence requires all seven protected environments and no bypass", () => {
  const evidence = governanceEvidence();
  assert.equal(validateGovernanceEvidence(evidence), evidence);
  const missing = structuredClone(evidence);
  missing.environments.pop();
  assert.throws(() => validateGovernanceEvidence(missing),
    /CONTROL_PLANE_GOVERNANCE_EVIDENCE_REJECTED/u);
  const bypass = structuredClone(evidence);
  bypass.environments[0].adminsCanBypass = true;
  assert.throws(() => validateGovernanceEvidence(bypass),
    /CONTROL_PLANE_GOVERNANCE_ENVIRONMENT_EVIDENCE_REJECTED/u);
  const broadRef = structuredClone(evidence);
  broadRef.environments[0].workflowRef = "Flash-Bri/prooftoact/.github/workflows/x.yml@main";
  assert.throws(() => validateGovernanceEvidence(broadRef),
    /CONTROL_PLANE_GOVERNANCE_ENVIRONMENT_EVIDENCE_REJECTED/u);
  const omittedCoordinatorJob = structuredClone(evidence);
  const coordinator = omittedCoordinatorJob.environments.find((item) =>
    item.environment === "aws-release-coordination");
  coordinator.jobNames.pop();
  assert.throws(() => validateGovernanceEvidence(omittedCoordinatorJob),
    /CONTROL_PLANE_GOVERNANCE_ENVIRONMENT_EVIDENCE_REJECTED/u);
});

test("provenance evidence binds standalone Git, nested lock, build, test, and audit", () => {
  const candidate = buildCandidate({ rootDir: ROOT });
  const evidence = provenanceEvidence(candidate.body.dependencies,
    candidate.body.providerDependencies);
  assert.equal(validateProvenanceEvidence(evidence,
    candidate.body.dependencies, candidate.body.providerDependencies), evidence);
  const wrongLock = structuredClone(evidence);
  wrongLock.install.releaseControl.packageLockSha256 = "f".repeat(64);
  assert.throws(() => validateProvenanceEvidence(wrongLock,
    candidate.body.dependencies, candidate.body.providerDependencies),
  /CONTROL_PLANE_PROVENANCE_EVIDENCE_REJECTED/u);
  const sameAsFrozen = structuredClone(evidence);
  sameAsFrozen.controlPlane.commit =
    sameAsFrozen.frozenApplication.commit;
  assert.throws(() => validateProvenanceEvidence(sameAsFrozen,
    candidate.body.dependencies, candidate.body.providerDependencies),
  /CONTROL_PLANE_PROVENANCE_EVIDENCE_REJECTED/u);
  const external = structuredClone(evidence);
  external.build.releaseProvider.externalImports.push("@aws-sdk/client-s3");
  assert.throws(() => validateProvenanceEvidence(external,
    candidate.body.dependencies, candidate.body.providerDependencies),
  /CONTROL_PLANE_PROVENANCE_EVIDENCE_REJECTED/u);
  const wrongProviderLock = structuredClone(evidence);
  wrongProviderLock.install.releaseProvider.packageLockSha256 = "e".repeat(64);
  assert.throws(() => validateProvenanceEvidence(wrongProviderLock,
    candidate.body.dependencies, candidate.body.providerDependencies),
  /CONTROL_PLANE_PROVENANCE_EVIDENCE_REJECTED/u);
});

test("accepted evidence is digest-bound but never authorizes provider execution", () => {
  const source = buildCandidate({ rootDir: ROOT });
  const governance = governanceEvidence();
  const provenance = provenanceEvidence(source.body.dependencies,
    source.body.providerDependencies);
  const candidate = buildCandidate({
    governanceEvidence: governance,
    provenanceEvidence: provenance,
    rootDir: ROOT
  });
  const result = verifyCandidate(candidate, {
    governanceEvidence: governance,
    provenanceEvidence: provenance,
    rootDir: ROOT
  });
  assert.equal(result.providerEvidenceReady, true);
  assert.equal(result.providerExecutionAuthorized, false);
  assert.equal(candidate.body.governance.providerEvidence.status, "ACCEPTED");
  assert.equal(candidate.body.provenance.providerEvidence.status, "ACCEPTED");
  const substituted = structuredClone(governance);
  substituted.observedAt = "2026-08-17T22:01:00.000Z";
  assert.throws(() => verifyCandidate(candidate, {
    governanceEvidence: substituted,
    provenanceEvidence: provenance,
    rootDir: ROOT
  }), /CONTROL_PLANE_CANDIDATE_SOURCE_MISMATCH/u);
});

test("dependency inventory and notice rendering are deterministic", () => {
  const candidate = buildCandidate({ rootDir: ROOT });
  const firstInventory = renderDependencyInventory(candidate.body.dependencies);
  const secondInventory = renderDependencyInventory(candidate.body.dependencies);
  assert.equal(firstInventory, secondInventory);
  assert.match(firstInventory,
    /separate release-control lock/u);
  const records = [{
    integrity: "sha512-example",
    license: "MIT",
    licenseSource: "release-control/node_modules/example/LICENSE",
    licenseTextSha256: HEX,
    name: "example",
    registry: "https://registry.npmjs.org/example/-/example-1.0.0.tgz",
    version: "1.0.0"
  }];
  const texts = new Map([[HEX, "Example license\n"]]);
  const firstNotice = renderThirdPartyNotices({ noticeRecords: records,
    textByDigest: texts });
  const secondNotice = renderThirdPartyNotices({ noticeRecords: records,
    textByDigest: texts });
  assert.equal(firstNotice, secondNotice);
  assert.match(firstNotice, /Example license/u);
});

test("build-bound dependency inventory and notices reproduce byte-for-byte", () => {
  const metadata = buildReleaseControlMetadata({ rootDir: ROOT });
  const verified = verifyReleaseControlMetadata({ rootDir: ROOT });
  assert.equal(verified.ready, true);
  assert.equal(verified.findings.length, 0);
  assert.equal(fs.readFileSync(path.join(ROOT,
    "release-control/DEPENDENCY_INVENTORY.json"), "utf8"),
  metadata.dependencyInventory);
  assert.equal(fs.readFileSync(path.join(ROOT,
    "release-control/THIRD_PARTY_NOTICES.txt"), "utf8"),
  metadata.thirdPartyNotices);
  const candidate = buildCandidate({ rootDir: ROOT });
  assert.equal(renderDependencyInventoryJson(candidate.body.dependencies),
    metadata.dependencyInventory);
  const provider = verifyReleaseProviderMetadata({ rootDir: ROOT });
  assert.equal(provider.ready, true);
  assert.equal(provider.findings.length, 0);
  assert.equal(fs.readFileSync(path.join(ROOT,
    "release-provider/DEPENDENCY_INVENTORY.json"), "utf8"),
  renderProviderDependencyInventoryJson(provider.dependencies));
  assert.equal(provider.artifacts.every((item) => item.status === "VERIFIED"),
    true);
  const texts = new Map();
  for (const record of provider.notices.noticeRecords) {
    const bytes = fs.readFileSync(path.join(ROOT, "release-provider",
      record.licenseSource));
    texts.set(record.licenseTextSha256,
      `${bytes.toString("utf8").replaceAll("\r\n", "\n").trim()}\n`);
  }
  assert.equal(fs.readFileSync(path.join(ROOT,
    "release-provider/THIRD_PARTY_NOTICES.txt"), "utf8"),
  renderProviderThirdPartyNotices({
    noticeRecords: provider.notices.noticeRecords,
    textByDigest: texts
  }));
});

test("schemas are source-owned and candidate stays a non-authorizing HOLD without live evidence", () => {
  for (const schema of [
    "control-plane-candidate.schema.json",
    "control-plane-governance-evidence.schema.json",
    "control-plane-provenance-evidence.schema.json"
  ]) {
    const parsed = JSON.parse(fs.readFileSync(path.join(ROOT,
      "control-plane-verification/schemas", schema), "utf8"));
    assert.equal(parsed.$schema,
      "https://json-schema.org/draft/2020-12/schema");
  }
  const candidateSchema = JSON.parse(fs.readFileSync(path.join(ROOT,
    "control-plane-verification/schemas/control-plane-candidate.schema.json"),
  "utf8"));
  for (const section of ["providerDependencies", "providerMetadataArtifacts",
    "providerNotices"]) {
    assert.equal(candidateSchema.properties.body.required.includes(section),
      true, section);
  }
  const candidate = buildCandidate({ rootDir: ROOT });
  assert.equal(candidate.body.readiness.providerEvidenceReady, false);
  assert.equal(candidate.body.readiness.providerExecutionAuthorized, false);
  assert.equal(candidate.body.readiness.finalDisposition, "HOLD");
  assert.equal(canonicalJson(candidate).includes("providerExecutionAuthorized\":false"),
    true);
});
