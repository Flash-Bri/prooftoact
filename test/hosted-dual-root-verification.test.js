import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  HOSTED_DUAL_ROOT_CONSTANTS,
  __test,
  parseRequiredTap,
  validateHostedWorkflowContext
} from "../control-plane-verification/hosted-dual-root-verification.js";
import { PARAMETER_KEYS } from
  "../release-provider/src/release-provider-common.js";
import { verifyReleaseSecurity } from
  "../scripts/verify-release-security.js";
import { verifyIntegratedLiveDrillProcessBoundaries } from
  "../scripts/verify-integrated-live-drill-process-boundaries.js";
import { verifyIntegratedLiveDrillSystemdBoundary } from
  "../scripts/verify-integrated-live-drill-systemd-boundary.js";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const COMMIT = "1".repeat(40);

function context() {
  return {
    CI: "true",
    EXPECTED_OFFICIAL_MAIN_COMMIT: COMMIT,
    GITHUB_ACTIONS: "true",
    GITHUB_EVENT_NAME: "workflow_dispatch",
    GITHUB_JOB: "verify-dual-root",
    GITHUB_REF: "refs/heads/main",
    GITHUB_REF_NAME: "main",
    GITHUB_REF_TYPE: "branch",
    GITHUB_REPOSITORY: "Flash-Bri/prooftoact",
    GITHUB_REPOSITORY_ID: "1317716765",
    GITHUB_REPOSITORY_OWNER_ID: "252500266",
    GITHUB_RUN_ATTEMPT: "1",
    GITHUB_RUN_ID: "1234567890",
    GITHUB_SHA: COMMIT,
    GITHUB_WORKFLOW: "ProofToAct Hosted Dual Root Verification",
    GITHUB_WORKFLOW_REF:
      "Flash-Bri/prooftoact/.github/workflows/" +
      "prooftoact-hosted-dual-root-verification.yml@refs/heads/main",
    GITHUB_WORKFLOW_SHA: COMMIT,
    RUNNER_ENVIRONMENT: "github-hosted",
    RUNNER_OS: "Linux"
  };
}

function tap(overrides = {}) {
  const value = {
    tests: 12,
    pass: 12,
    fail: 0,
    cancelled: 0,
    skipped: 0,
    todo: 0,
    ...overrides
  };
  return Buffer.from([
    "TAP version 13",
    `# tests ${value.tests}`,
    "# suites 1",
    `# pass ${value.pass}`,
    `# fail ${value.fail}`,
    `# cancelled ${value.cancelled}`,
    `# skipped ${value.skipped}`,
    `# todo ${value.todo}`,
    ""
  ].join("\n"), "utf8");
}

test("hosted context is main-only, first-attempt, no-OIDC, and credential-free",
  () => {
    const accepted = validateHostedWorkflowContext(context(), "linux");
    assert.equal(accepted.commit, COMMIT);
    assert.equal(accepted.runAttempt, 1);
    for (const mutation of [
      { GITHUB_REF: "refs/heads/release" },
      { GITHUB_RUN_ATTEMPT: "2" },
      { GITHUB_WORKFLOW_SHA: "2".repeat(40) },
      { ACTIONS_ID_TOKEN_REQUEST_TOKEN: "present" },
      { AWS_ACCESS_KEY_ID: `ASIA${"A".repeat(16)}` },
      { AWS_PROFILE: "default" },
      { AWS_CONTAINER_CREDENTIALS_RELATIVE_URI: "/v2/credentials" },
      { COCKROACH_DATABASE_URL: "present" },
      { CRDB_URL: "present" },
      { PGPASSWORD: "present" },
      { GITHUB_TOKEN: "present" },
      { NODE_AUTH_TOKEN: "present" },
      { OPENAI_API_KEY: "present" },
      { PROOFTOACT_RELEASE_APPROVAL_TOKEN: "present" }
    ]) {
      assert.throws(() => validateHostedWorkflowContext({
        ...context(), ...mutation
      }, "linux"), /HOSTED_DUAL_ROOT_CONTEXT_REJECTED/u);
    }
    assert.throws(() => validateHostedWorkflowContext(context(), "darwin"),
      /HOSTED_DUAL_ROOT_CONTEXT_REJECTED/u);
  });

test("required TAP rejects every skip, todo, cancellation, and partial pass",
  () => {
    assert.deepEqual(parseRequiredTap(tap()), {
      cancelled: 0,
      failed: 0,
      passed: 12,
      skipped: 0,
      tests: 12,
      todo: 0
    });
    for (const mutation of [
      { skipped: 1, pass: 11 },
      { todo: 1, pass: 11 },
      { cancelled: 1, pass: 11 },
      { fail: 1, pass: 11 },
      { tests: 12, pass: 11 }
    ]) assert.throws(() => parseRequiredTap(tap(mutation)),
      /HOSTED_DUAL_ROOT_TAP_REJECTED/u);
  });

test("artifact contract includes every required log and no manifest recursion",
  () => {
    const paths = HOSTED_DUAL_ROOT_CONSTANTS.REQUIRED_ARTIFACT_PATHS;
    assert.equal(paths.includes("manifest.json"), false);
    assert.equal(new Set(paths).size, paths.length);
    assert.equal(paths.join("\n"), [...paths].sort().join("\n"));
    for (const required of [
      "builds/application-build-1.log",
      "builds/application-build-2.log",
      "builds/executable-manifest-1.json",
      "builds/executable-manifest-2.json",
      "control-plane-provenance.json",
      "logs/privileged-root-stage.tap",
      "logs/process-boundaries.log",
      "logs/safety.tap",
      "logs/source-security-tests.tap",
      "logs/source-security-verifier.json"
    ]) assert.equal(paths.includes(required), true, required);
    assert.equal(__test.requireExactArtifactPaths([...paths]), true);
    assert.throws(() => __test.requireExactArtifactPaths(paths.slice(1)),
      /HOSTED_DUAL_ROOT_ARTIFACT_SET_REJECTED/u);
    assert.throws(() => __test.requireExactArtifactPaths([...paths,
      "logs/unexpected.log"]),
    /HOSTED_DUAL_ROOT_ARTIFACT_SET_REJECTED/u);
  });

test("safety inventory explicitly spans replay, concurrency, spend, and teardown",
  () => {
    const files = HOSTED_DUAL_ROOT_CONSTANTS.SAFETY_TEST_FILES;
    for (const required of [
      "test/integrated-live-drill-provider-execution-fence.test.js",
      "test/integrated-live-drill-provider-reconciliation.test.js",
      "test/integrated-live-drill-stress.test.js",
      "test/provider-dispatch-activation-terminalization.test.js",
      "test/release-cost.test.js",
      "test/release-deployment-plan.test.js",
      "test/release-provider-one-shot-broker.test.js"
    ]) assert.equal(files.includes(required), true, required);
    for (const relativePath of [
      ...files,
      ...HOSTED_DUAL_ROOT_CONSTANTS.SOURCE_SECURITY_TEST_FILES
    ]) assert.equal(fs.lstatSync(path.join(ROOT, relativePath)).isFile(), true);
  });

test("parameter evidence hashes all 45 schemas and labels live values absent",
  () => {
    const exactPrivateKeys = [
      "AgentArtifactVersion",
      "ArtifactBucket",
      "AuthorityArtifactVersion",
      "AuthorityDatabaseHost",
      "AuthorityDatabasePort",
      "AuthorityDatabaseSecretArn",
      "AuthorityDatabaseSecretVersionId",
      "AuthorityIncidentId",
      "AuthorityResourceId",
      "AuthorityTenantId",
      "BedrockModelId",
      "BoundaryArtifactVersion",
      "ConfigDigest",
      "DemoArtifactVersion",
      "EvidenceOperatorPrincipalArn",
      "ProbeArtifactVersion",
      "SignerArtifactVersion"
    ];
    assert.equal(PARAMETER_KEYS.length, 45);
    assert.deepEqual(HOSTED_DUAL_ROOT_CONSTANTS.PRIVATE_PARAMETER_KEYS,
      exactPrivateKeys);
    assert.equal(exactPrivateKeys.length, 17);
    assert.equal(PARAMETER_KEYS.length - exactPrivateKeys.length, 28);
    const temporary = fs.mkdtempSync(path.join(os.tmpdir(),
      "prooftoact-hosted-parameters-"));
    try {
      const template = JSON.parse(fs.readFileSync(path.join(ROOT,
        "infra/aws/gate2-template.json"), "utf8"));
      fs.mkdirSync(path.join(temporary, "infra", "aws"), { recursive: true });
      fs.writeFileSync(path.join(temporary, "infra/aws/gate2-template.json"),
        `${JSON.stringify(template)}\n`);
      const receipt = {
        artifacts: ["agent", "authority", "boundary", "demo", "probe",
          "signer"].map((name, index) => ({
          artifactCodeSha256: Buffer.alloc(32, index + 1).toString("base64"),
          artifactDigest: String(index + 1).repeat(64),
          artifactPath: `dist/aws/${name}-${String(index + 1).repeat(64)}.zip`,
          name,
          sourceDigest: String(index + 2).repeat(64),
          suggestedS3Key: `gate2/${COMMIT}/${name}.zip`
        })),
        gate2Template: { path: "infra/aws/gate2-template.json" },
        packageLockDigest: "a".repeat(64),
        sourceCommit: HOSTED_DUAL_ROOT_CONSTANTS.FROZEN_APPLICATION.commit,
        treeDigest: HOSTED_DUAL_ROOT_CONSTANTS.FROZEN_APPLICATION.tree
      };
      const first = __test.templateParameterContract(temporary, receipt);
      assert.equal(first.keyCount, PARAMETER_KEYS.length);
      assert.equal(first.liveParameterValuesObserved, false);
      assert.deepEqual(Object.keys(first.parameterDispositions).sort(),
        [...PARAMETER_KEYS].sort());
      assert.equal(first.observedValueCount + first.notObservedValueCount,
        PARAMETER_KEYS.length);
      assert.equal(first.notObservedValueCount,
        HOSTED_DUAL_ROOT_CONSTANTS.PRIVATE_PARAMETER_KEYS.length);
      for (const name of PARAMETER_KEYS) {
        const disposition = first.parameterDispositions[name];
        assert.deepEqual(Object.keys(disposition).sort(), [
          "evidence", "status", "valueObserved", "valueSha256"
        ]);
        if (HOSTED_DUAL_ROOT_CONSTANTS.PRIVATE_PARAMETER_KEYS.includes(name)) {
          assert.equal(disposition.status,
            "NOT_OBSERVED_NO_PROVIDER_CONFIGURATION");
          assert.equal(disposition.valueObserved, false);
          assert.equal(disposition.valueSha256, null);
        } else {
          assert.equal(disposition.status, "OBSERVED_BUILD_DERIVED_VALUE");
          assert.equal(disposition.valueObserved, true);
          assert.match(disposition.valueSha256, /^[0-9a-f]{64}$/u);
        }
      }
      assert.equal(first.status,
        "SOURCE_CONTRACT_ONLY_NO_PROVIDER_CONFIGURATION");
      const changed = structuredClone(receipt);
      changed.artifacts[0].artifactDigest = "f".repeat(64);
      const second = __test.templateParameterContract(temporary, changed);
      assert.notEqual(first.buildDerivedParameterInputsSha256,
        second.buildDerivedParameterInputsSha256);
      assert.notEqual(first.parameterDispositionSha256,
        second.parameterDispositionSha256);
      assert.equal(first.parameterSchemaSha256,
        second.parameterSchemaSha256);
    } finally {
      fs.rmSync(temporary, { force: true, recursive: true });
    }
  });

test("publication scanner rejects reusable credentials and private keys", () => {
  assert.equal(__test.assertNonsecretBytes(Buffer.from("safe log\n"),
    "TEST_CODE").toString("utf8"), "safe log\n");
  for (const value of [
    `AKIA${"A".repeat(16)}`,
    "-----BEGIN PRIVATE KEY-----",
    `ghp_${"a".repeat(24)}`,
    `sk-${"a".repeat(24)}`,
    "postgresql://user:password@cluster.invalid/db"
  ]) assert.throws(() => __test.assertNonsecretBytes(Buffer.from(value),
    "TEST_CODE"), /TEST_CODE/u);
});

test("retained command bindings reject argument, executable, and source drift",
  () => {
    const temporary = fs.mkdtempSync(path.join(os.tmpdir(),
      "prooftoact-hosted-command-binding-"));
    try {
      fs.writeFileSync(path.join(temporary, "source.js"), "export {};\n",
        { mode: 0o600 });
      const expected = {
        args: ["--test", "source.js"],
        executable: process.execPath,
        sourcePaths: ["source.js"],
        sourceRole: "test-root",
        sourceRoot: temporary
      };
      const binding = __test.createCommandBinding(expected);
      assert.deepEqual(__test.verifyCommandBinding(binding, expected), binding);
      const argumentTamper = structuredClone(binding);
      argumentTamper.arguments[0] = "--tampered";
      assert.throws(() => __test.verifyCommandBinding(argumentTamper, expected),
        /HOSTED_DUAL_ROOT_COMMAND_BINDING_REJECTED/u);
      const sourceTamper = structuredClone(binding);
      sourceTamper.sourceFiles[0].sha256 = "0".repeat(64);
      assert.throws(() => __test.verifyCommandBinding(sourceTamper, expected),
        /HOSTED_DUAL_ROOT_COMMAND_BINDING_REJECTED/u);
      const executableTamper = structuredClone(binding);
      executableTamper.executableSha256 = "0".repeat(64);
      assert.throws(() => __test.verifyCommandBinding(executableTamper,
        expected), /HOSTED_DUAL_ROOT_COMMAND_BINDING_REJECTED/u);
    } finally {
      fs.rmSync(temporary, { force: true, recursive: true });
    }
  });

test("process and source-security receipts require exact pass dispositions",
  () => {
    const processBytes = Buffer.from([
      JSON.stringify({ schemaVersion:
        "tideproof.highwater-drill-process-boundary-verification.v5",
      status: "PASS" }),
      JSON.stringify({ schemaVersion:
        "tideproof.integrated-live-drill-systemd-boundary.v1",
      status: "PASS" }),
      ""
    ].join("\n"));
    assert.equal(__test.parseProcessBoundaryReceipts(processBytes).length, 2);
    assert.throws(() => __test.parseProcessBoundaryReceipts(Buffer.from(
      `${JSON.stringify({ status: "PASS" })}\n`)),
    /HOSTED_DUAL_ROOT_PROCESS_BOUNDARY_REJECTED/u);
    const securityReceipt = verifyReleaseSecurity({ rootDir: ROOT });
    const securityBytes = Buffer.from(
      `${JSON.stringify(securityReceipt, null, 2)}\n`, "utf8");
    assert.equal(__test.parseSecurityReceipt(securityBytes).status,
      "CURRENT_SOURCE_SECURITY_PASS");
    const changed = structuredClone(securityReceipt);
    changed.checks.canonicalManifest = false;
    assert.throws(() => __test.parseSecurityReceipt(Buffer.from(
      `${JSON.stringify(changed, null, 2)}\n`, "utf8")),
    /HOSTED_DUAL_ROOT_SECURITY_RECEIPT_REJECTED/u);
    const securitySources = __test.securityVerifierSourceFiles(ROOT);
    assert.equal(securitySources.includes("RELEASE_SECURITY_MANIFEST.json"),
      true);
    assert.equal(securitySources.length > 200 && securitySources.every(
      (relativePath) => fs.statSync(path.join(ROOT, relativePath)).isFile()),
    true);
    const processSources = __test.processBoundarySourceFiles([
      verifyIntegratedLiveDrillProcessBoundaries(),
      verifyIntegratedLiveDrillSystemdBoundary()
    ]);
    assert.equal(processSources.includes(
      "src/cloud/integrated-live-drill-provider-worker.js"), true);
    assert.equal(processSources.includes(
      "infra/systemd/prooftoact-integrated-live-drill@.service"), true);
    assert.equal(processSources.every((relativePath) =>
      fs.statSync(path.join(ROOT, relativePath)).isFile()), true);
  });

test("hosted workflow is no-OIDC, exact-root, retained, and action-pinned",
  () => {
    const source = fs.readFileSync(path.join(ROOT, ".github/workflows/",
      HOSTED_DUAL_ROOT_CONSTANTS.WORKFLOW_FILE), "utf8");
    assert.equal(/^\s*id-token:/mu.test(source), false);
    assert.equal(/^\s*environment:/mu.test(source), false);
    assert.equal(/\$\{\{\s*secrets\./u.test(source), false);
    assert.equal(/^\s+if:\s*\$\{\{\s*github\.ref\s*==/mu.test(source),
      false);
    assert.equal(source.includes(
      "run: test \"$EXACT_DISPATCH_REF\" = \"refs/heads/main\""), true);
    assert.equal(source.includes(
      HOSTED_DUAL_ROOT_CONSTANTS.FROZEN_APPLICATION.commit), true);
    assert.equal(source.includes("retention-days: 90"), true);
    assert.equal(source.includes("if-no-files-found: error"), true);
    assert.equal(source.includes(
      '--control-root "$GITHUB_WORKSPACE/control-plane"'), true);
    assert.equal(source.includes(
      '--application-root "$GITHUB_WORKSPACE/frozen-application"'), true);
    assert.equal((source.match(/--npm-cli "\$npm_cli"/gu) ?? []).length, 4);
    assert.equal(source.includes("if: ${{ success() }}"), true);
    assert.equal(source.includes("if: ${{ always() }}"), false);
    const generate = source.indexOf(
      "generate-hosted-dual-root-verification.js");
    const verify = source.indexOf(
      "verify-hosted-dual-root-verification.js");
    const tamper = source.indexOf(
      "test-hosted-dual-root-verification-tamper.js");
    assert.equal(generate >= 0 && verify > generate && tamper > verify, true);
    const pins = [...source.matchAll(/^\s*uses:\s*[^@\s]+@([^\s#]+)/gmu)]
      .map((match) => match[1]);
    assert.equal(pins.length, 4);
    assert.equal(pins.every((pin) => /^[0-9a-f]{40}$/u.test(pin)), true);
  });
