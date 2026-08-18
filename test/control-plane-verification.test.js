import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
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
import {
  CONTROL_PLANE_PROVENANCE_CONSTANTS,
  __test as provenanceTest,
  canonicalProvenanceJson,
  provenanceSha256,
  validateControlPlaneProvenanceEvidence
} from "../control-plane-verification/control-plane-provenance.js";
import {
  expectedOfficialNodeRuntime
} from "../src/cloud/official-node-runtime-contract.js";

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
  const officialNode = expectedOfficialNodeRuntime(process.platform,
    process.arch);
  const file = (pathName, marker) => ({
    bytes: 100,
    gitBlobId: marker.repeat(40),
    path: pathName,
    sha256: marker.repeat(64)
  });
  const execution = (command, semantic, kind) => {
    const stdout = kind === "test"
      ? Buffer.from("TAP version 13\n# tests 10\n# suites 1\n# pass 10\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n", "utf8")
      : kind === "audit"
        ? Buffer.from(`${JSON.stringify({ metadata: { vulnerabilities:
          semantic.vulnerabilities } })}\n`, "utf8")
        : Buffer.from("installed\n", "utf8");
    const stderr = Buffer.alloc(0);
    return {
      argumentsSha256: "a".repeat(64),
      command,
      outputBytes: stdout.length,
      outputSha256: provenanceSha256(Buffer.concat([stdout,
        Buffer.from("\n---STDERR---\n", "utf8"), stderr])),
      semantic,
      stderrBase64: stderr.toString("base64"),
      stdoutBase64: stdout.toString("base64")
    };
  };
  const receipt = (marker) => {
    const body = { zeta: marker, alpha: "multi-key-order-binding" };
    return {
      ...body,
      provenanceSha256: provenanceSha256(Buffer.from(
        `${JSON.stringify(body)}\n`, "utf8"))
    };
  };
  const controlReceipt = receipt("control");
  const providerReceipt = receipt("provider");
  const body = {
    schemaVersion: CONTROL_PLANE_PROVENANCE_CONSTANTS.SCHEMA,
    claimBoundary: {
      applicationDeploymentObserved: false,
      hostedCiParityObserved: false,
      privilegedRootStageObserved: false,
      providerActionsPerformed: false,
      providerExecutionAuthorized: false,
      providerFactsAsserted: false,
      sourceAndLocalExecutionEvidenceOnly: true
    },
    decision: {
      cleanStandaloneProvenanceObserved: true,
      nextGate: "SEPARATE_GOVERNED_PROVIDER_AUTHORIZATION",
      providerExecutionAuthorized: false,
      status: "LOCAL_PROVENANCE_VERIFIED"
    },
    git: {
      controlPlane: {
        clean: true,
        commit: "1".repeat(40),
        grafts: false,
        origin: "https://github.com/Flash-Bri/prooftoact.git",
        replacements: false,
        role: "CONTROL_PLANE",
        rootDevice: 1,
        rootInode: 10,
        rootMode: 0o755,
        rootOwnerUid: process.getuid(),
        shallow: false,
        standalone: true,
        tree: "2".repeat(40)
      },
      frozenApplication: {
        clean: true,
        commit: CONTROL_PLANE_PROVENANCE_CONSTANTS.FROZEN_APPLICATION.commit,
        grafts: false,
        origin: "https://github.com/Flash-Bri/prooftoact.git",
        replacements: false,
        role: "FROZEN_APPLICATION",
        rootDevice: 1,
        rootInode: 11,
        rootMode: 0o755,
        rootOwnerUid: process.getuid(),
        shallow: false,
        standalone: true,
        tree: CONTROL_PLANE_PROVENANCE_CONSTANTS.FROZEN_APPLICATION.tree
      }
    },
    packages: {
      application: [file("package.json", "3"),
        file("package-lock.json", "4")],
      controlPlane: [file("package.json", "3"),
        file("package-lock.json", "4"),
        file("release-control/package.json", "5"),
        file("release-control/package-lock.json", "6"),
        file("release-provider/package.json", "7"),
        file("release-provider/package-lock.json", "8")]
    },
    executions: {
      installations: ["control-plane-root", "release-control",
        "release-provider", "frozen-application"].map((name) =>
        execution(name, {
          arguments: ["ci", "--ignore-scripts", "--no-audit", "--no-fund"],
          status: "PASS"
        }, "install")),
      tests: ["control-plane-root", "release-control", "release-provider",
        "frozen-application"].map((name) =>
        execution(name, {
          cancelled: 0,
          failed: 0,
          packageScriptSha256: "9".repeat(64),
          passed: 10,
          script: "test",
          skipped: 0,
          tests: 10,
          todo: 0
        }, "test")),
      audits: ["control-plane-root", "release-control", "release-provider",
        "frozen-application"].map((name) =>
        execution(name, {
          auditFindingCount: 0,
          vulnerabilities: {
            critical: 0, high: 0, info: 0, low: 0, moderate: 0, total: 0
          }
        }, "audit")),
      build: {
        reproducible: true,
        releaseControl: {
          externalImports: ["node:crypto"],
          packageJsonSha256: dependencies.packageSha256,
          packageLockSha256: dependencies.packageLockSha256,
          provenanceSha256: controlReceipt.provenanceSha256,
          rawOutputSha256: provenanceSha256(Buffer.from(
            `${JSON.stringify(controlReceipt)}\n`, "utf8")),
          receiptBase64: Buffer.from(`${JSON.stringify(controlReceipt)}\n`,
            "utf8").toString("base64"),
          runtimeSha256: "c".repeat(64),
          sourceInventorySha256: "d".repeat(64)
        },
        releaseProvider: {
          externalImports: ["node:crypto"],
          packageJsonSha256: providerDependencies.packageSha256,
          packageLockSha256: providerDependencies.packageLockSha256,
          provenanceSha256: providerReceipt.provenanceSha256,
          rawOutputSha256: provenanceSha256(Buffer.from(
            `${JSON.stringify(providerReceipt)}\n`, "utf8")),
          receiptBase64: Buffer.from(`${JSON.stringify(providerReceipt)}\n`,
            "utf8").toString("base64"),
          runtimeCount: 3,
          runtimeSetSha256: providerDependencies.runtimeSetSha256,
          sourceInventorySha256: "a".repeat(64)
        }
      },
      toolchain: {
        nodeArch: officialNode.architecture,
        nodeDistribution: officialNode.distribution,
        nodeExecutableSha256: officialNode.sha256,
        nodePlatform: officialNode.platform,
        nodeVersion: officialNode.version,
        npmCliSha256:
          CONTROL_PLANE_PROVENANCE_CONSTANTS.NPM_PACKAGE_IDENTITY.cliSha256,
        npmPackageFileCount:
          CONTROL_PLANE_PROVENANCE_CONSTANTS.NPM_PACKAGE_IDENTITY.fileCount,
        npmPackageJsonSha256:
          CONTROL_PLANE_PROVENANCE_CONSTANTS.NPM_PACKAGE_IDENTITY
            .packageJsonSha256,
        npmPackageTreeSha256:
          CONTROL_PLANE_PROVENANCE_CONSTANTS.NPM_PACKAGE_IDENTITY.treeSha256,
        npmVersion: "10.9.8"
      }
    }
  };
  return {
    body,
    bodySha256: provenanceSha256(Buffer.from(canonicalProvenanceJson(body))),
    schemaVersion: CONTROL_PLANE_PROVENANCE_CONSTANTS.SCHEMA
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
    ".github/workflows/prooftoact-hosted-dual-root-verification.yml",
    "config/prooftoact-release-operator-public.pub",
    "control-plane-verification/generate-hosted-dual-root-verification.js",
    "control-plane-verification/hosted-dual-root-verification.js",
    "control-plane-verification/verify-hosted-dual-root-verification.js",
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
    "scripts/release-provider-bootstrap-readback.js",
    "scripts/release-provider-bootstrap-readback-collector.sh",
    "scripts/release-provider-controller.js",
    "scripts/release-provider-one-shot-broker.js",
    "scripts/run-release-prepare-common.js",
    "scripts/run-release-prepare-diagnostic.js",
    "scripts/run-release-prepare-phase.js",
    "scripts/run-release-prepare-preflight.js",
    "scripts/sign-release-provider-approval.js",
    "test/control-plane-verification.test.js",
    "test/hosted-dual-root-verification.test.js",
    "test/release-control-bootstrap-plan.test.js",
    "test/release-control-bootstrap-readback.test.js",
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
  assert.equal(candidate.body.security.checks.find(({ id }) =>
    id === "HOSTED_DUAL_ROOT_NO_OIDC_COMPLETE_EVIDENCE")?.passed, true);
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
  assert.equal(validateControlPlaneProvenanceEvidence(evidence), evidence);
  const canonicalRoundTrip = JSON.parse(canonicalProvenanceJson(evidence));
  assert.equal(validateControlPlaneProvenanceEvidence(canonicalRoundTrip),
    canonicalRoundTrip);
  assert.throws(() => validateProvenanceEvidence(evidence,
    candidate.body.dependencies, candidate.body.providerDependencies),
  /CONTROL_PLANE_PROVENANCE_INDEPENDENT_REPRODUCTION_REQUIRED/u);
  const wrongLock = structuredClone(evidence);
  wrongLock.body.executions.build.releaseControl.packageLockSha256 =
    "f".repeat(64);
  wrongLock.bodySha256 = provenanceSha256(Buffer.from(
    canonicalProvenanceJson(wrongLock.body)));
  assert.throws(() => validateProvenanceEvidence(wrongLock,
    candidate.body.dependencies, candidate.body.providerDependencies),
  /CONTROL_PLANE_PROVENANCE_DEPENDENCY_BINDING_REJECTED/u);
  const sameAsFrozen = structuredClone(evidence);
  sameAsFrozen.body.git.controlPlane.commit =
    sameAsFrozen.body.git.frozenApplication.commit;
  sameAsFrozen.bodySha256 = provenanceSha256(Buffer.from(
    canonicalProvenanceJson(sameAsFrozen.body)));
  assert.throws(() => validateControlPlaneProvenanceEvidence(sameAsFrozen),
    /CONTROL_PLANE_PROVENANCE_PACKAGE_EVIDENCE_REJECTED/u);
  const outputSubstitution = structuredClone(evidence);
  outputSubstitution.body.executions.tests[0].stdoutBase64 =
    Buffer.from("forged\n", "utf8").toString("base64");
  outputSubstitution.bodySha256 = provenanceSha256(Buffer.from(
    canonicalProvenanceJson(outputSubstitution.body)));
  assert.throws(() => validateControlPlaneProvenanceEvidence(outputSubstitution),
    /CONTROL_PLANE_PROVENANCE_TEST_OUTPUT_REJECTED/u);
  const receiptSubstitution = structuredClone(evidence);
  receiptSubstitution.body.executions.build.releaseControl.receiptBase64 =
    Buffer.from('{"forged":true}\n', "utf8").toString("base64");
  receiptSubstitution.bodySha256 = provenanceSha256(Buffer.from(
    canonicalProvenanceJson(receiptSubstitution.body)));
  assert.throws(() => validateControlPlaneProvenanceEvidence(receiptSubstitution),
    /CONTROL_PLANE_PROVENANCE_BUILD_RECEIPT_REJECTED/u);
});

test("provenance JSON cannot self-assert readiness or provider authority", () => {
  const source = buildCandidate({ rootDir: ROOT });
  const governance = governanceEvidence();
  const provenance = provenanceEvidence(source.body.dependencies,
    source.body.providerDependencies);
  assert.equal(provenance.body.decision.providerExecutionAuthorized, false);
  assert.equal(provenance.body.claimBoundary.providerFactsAsserted, false);
  assert.throws(() => buildCandidate({
    governanceEvidence: governance,
    provenanceEvidence: provenance,
    rootDir: ROOT
  }), /CONTROL_PLANE_PROVENANCE_INDEPENDENT_REPRODUCTION_REQUIRED/u);
});

test("provenance boundary rejects nested roots, failing outputs, duplicate flags, and broad evidence modes", (t) => {
  assert.equal(provenanceTest.rootsAreSeparate("/tmp/control", "/tmp/app"),
    true);
  assert.equal(provenanceTest.rootsAreSeparate("/tmp/control", "/tmp/control"),
    false);
  assert.equal(provenanceTest.rootsAreSeparate("/tmp/control", "/tmp/control/app"),
    false);
  assert.throws(() => provenanceTest.parseTap(Buffer.from(
    "# tests 1\n# pass 0\n# fail 1\n# cancelled 0\n# skipped 0\n# todo 0\n", "utf8"), "TEST_TAP_REJECTED"), /TEST_TAP_REJECTED/u);
  assert.throws(() => provenanceTest.parseAudit(Buffer.from(JSON.stringify({
    metadata: { vulnerabilities: {
      critical: 0, high: 1, info: 0, low: 0, moderate: 0, total: 1
    } }
  }), "utf8"), "TEST_AUDIT_REJECTED"), /TEST_AUDIT_REJECTED/u);

  const duplicate = spawnSync(process.execPath, [
    path.join(ROOT,
      "control-plane-verification/generate-control-plane-provenance-evidence.js"),
    "--control-root", "/tmp/one", "--control-root", "/tmp/two"
  ], { encoding: "utf8" });
  assert.notEqual(duplicate.status, 0);
  assert.match(duplicate.stderr,
    /CONTROL_PLANE_PROVENANCE_ARGUMENT_REJECTED/u);

  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(),
    "prooftoact-provenance-mode-test-"));
  t.after(() => fs.rmSync(temporaryRoot, { force: true, recursive: true }));
  const controlRoot = path.join(temporaryRoot, "control");
  const applicationRoot = path.join(temporaryRoot, "application");
  const environmentRoot = path.join(temporaryRoot, "environment");
  fs.mkdirSync(controlRoot, { mode: 0o700 });
  fs.mkdirSync(applicationRoot, { mode: 0o700 });
  fs.mkdirSync(environmentRoot, { mode: 0o700 });
  const commandEnvironment = provenanceTest.commandEnvironment(environmentRoot);
  assert.equal(commandEnvironment.HOME, environmentRoot);
  assert.equal(commandEnvironment.TMPDIR, environmentRoot);
  assert.equal(commandEnvironment.TMP, environmentRoot);
  assert.equal(commandEnvironment.TEMP, environmentRoot);
  assert.notEqual(commandEnvironment.npm_config_globalconfig,
    commandEnvironment.npm_config_userconfig);
  for (const filePath of [commandEnvironment.npm_config_globalconfig,
    commandEnvironment.npm_config_userconfig]) {
    assert.equal(fs.readFileSync(filePath).length, 0);
    assert.equal(fs.lstatSync(filePath).mode & 0o777, 0o600);
  }
  const evidencePath = path.join(temporaryRoot, "evidence.json");
  fs.writeFileSync(evidencePath, "{}\n", { mode: 0o644 });
  fs.chmodSync(evidencePath, 0o644);
  const broadMode = spawnSync(process.execPath, [
    path.join(ROOT,
      "control-plane-verification/verify-control-plane-provenance-evidence.js"),
    "--control-root", controlRoot, "--application-root", applicationRoot,
    "--npm-cli", process.execPath, "--evidence", evidencePath
  ], { encoding: "utf8" });
  assert.notEqual(broadMode.status, 0);
  assert.match(broadMode.stderr,
    /CONTROL_PLANE_PROVENANCE_EVIDENCE_FILE_REJECTED/u);
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
