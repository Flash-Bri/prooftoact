import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { __test } from "../scripts/launch-one-time-bootstrap-ceremony.js";
import { buildOneTimeBootstrapCostReconciliationReceipt } from
  "../scripts/prepare-one-time-bootstrap-authority.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const LAUNCHER = fs.readFileSync(path.join(
  ROOT, "scripts/launch-one-time-bootstrap-ceremony.js"
), "utf8");
const RUNNER = fs.readFileSync(path.join(
  ROOT, "scripts/run-one-time-bootstrap-ceremony.js"
), "utf8");

function temporaryDirectory(t) {
  const directory = fs.mkdtempSync(path.join(
    fs.realpathSync(os.tmpdir()), "prooftoact-b0-launch-test-"
  ));
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  return directory;
}

test("B0 launcher statically imports built-ins only and runner is launcher-only", () => {
  const specifiers = [...LAUNCHER.matchAll(
    /^import(?:[\s\S]*?\sfrom\s+|\s+)["']([^"']+)["'];$/gmu
  )].map((match) => match[1]).sort();
  assert.deepEqual(specifiers, [
    "node:child_process", "node:crypto", "node:fs", "node:os", "node:path",
    "node:url"
  ]);
  assert.doesNotMatch(LAUNCHER, /@aws-sdk|@smithy|credential-provider/u);
  assert.match(RUNNER, /ONE_TIME_BOOTSTRAP_LAUNCHER_REQUIRED/u);
  assert.doesNotMatch(RUNNER,
    /if \(startedDirectly\) \{\s*main\(/u);
});

test("launcher argument and import graph gates reject duplicates and computed imports", () => {
  const args = __test.ARGUMENT_NAMES.flatMap((name, index) => [
    name,
    name === "--mode" ? "NEW" : `/private/value-${index}`
  ]);
  assert.equal(__test.parseArguments(args)["--mode"], "NEW");
  const duplicate = [...args];
  duplicate[2] = duplicate[0];
  assert.throws(() => __test.parseArguments(duplicate),
    /ONE_TIME_BOOTSTRAP_LAUNCH_ARGUMENTS_REJECTED/u);
  assert.throws(() => __test.parseImportSpecifiers(
    "const target = './unsafe.js'; import(target);",
    "scripts/not-reviewed.js"
  ), /ONE_TIME_BOOTSTRAP_LAUNCH_IMPORT_GRAPH_REJECTED/u);
});

test("complete B0 graph includes runner, planner, root assume, and all computed A1 modules", () => {
  const source = fs.readFileSync(path.join(ROOT,
    "scripts/run-one-time-bootstrap-ceremony.js"), "utf8");
  const imports = __test.parseImportSpecifiers(source,
    "scripts/run-one-time-bootstrap-ceremony.js");
  assert.equal(imports.includes("./prepare-one-time-bootstrap-authority.js"),
    true);
  assert.equal(imports.includes("@aws-sdk/client-cloudformation"), true);
  assert.deepEqual(__test.COMPUTED_IMPORT_PATHS, [
    "scripts/bootstrap-fresh-primary.js",
    "scripts/fresh-primary-bootstrap-role-readback.js",
    "scripts/fresh-primary-credential-custody-readback.js",
    "scripts/fresh-primary-credential-sealer.js",
    "scripts/prepare-fresh-primary-bootstrap-role.js",
    "scripts/prepare-fresh-primary-credential-custody.js"
  ]);
});

test("dependency runtime tree rejects non-bin symlinks and changes on byte tamper", (t) => {
  const root = temporaryDirectory(t);
  fs.writeFileSync(path.join(root, "a.js"), "one\n");
  const first = __test.runtimeTree(root, { skipRootBin: true });
  fs.writeFileSync(path.join(root, "a.js"), "two\n");
  const second = __test.runtimeTree(root, { skipRootBin: true });
  assert.notEqual(first.treeDigest, second.treeDigest);
  fs.symlinkSync("a.js", path.join(root, "alias.js"));
  assert.throws(() => __test.runtimeTree(root, { skipRootBin: true }),
    /ONE_TIME_BOOTSTRAP_LAUNCH_RUNTIME_TREE_REJECTED/u);
});

test("sealed snapshot preserves the bound real node_modules content digest before mode hardening", () => {
  const runnerPath = "scripts/run-one-time-bootstrap-ceremony.js";
  const bytes = fs.readFileSync(path.join(ROOT, runnerPath));
  const dependencies = __test.runtimeTree(path.join(ROOT, "node_modules"), {
    skipRootBin: true
  });
  const snapshot = __test.createSealedSnapshot({
    records: [{ path: runnerPath, sha256: __test.sha256(bytes) }]
  }, { dependencies });
  try {
    assert.equal(fs.existsSync(path.join(snapshot, runnerPath)), true);
    assert.equal(fs.statSync(path.join(snapshot, runnerPath)).mode & 0o777,
      0o400);
    assert.equal(fs.statSync(path.join(snapshot, "node_modules")).mode & 0o777,
      0o500);
  } finally {
    __test.removeSnapshot(snapshot);
  }
});

test("authorization must bind the exact runtime snapshot and both five-dollar ceilings", () => {
  const runtime = { exact: "runtime", homeDirectory: process.env.HOME };
  const costReconciliation =
    buildOneTimeBootstrapCostReconciliationReceipt({
      accountId: "123456789012",
      operationId: "123e4567-e89b-42d3-a456-426614174000",
      pricingObservedAt: "2026-08-19T07:00:00.000Z",
      pricingSourceSha256: {
        awsSecretsManager: "1".repeat(64),
        cockroachBasic: "2".repeat(64)
      },
      sourceCommit: "a".repeat(40),
      targetTemplateSha256: {
        freshPrimaryBootstrapRole: "3".repeat(64),
        freshPrimaryCredentialCustody: "4".repeat(64),
        privateRecoveryQueryBootstrap: "5".repeat(64)
      },
      treeDigest: "b".repeat(40)
    });
  const receipt = {
    schemaVersion: "prooftoact.one-time-bootstrap-authorization.v1",
    status: "AUTHORIZED_EXACT_ROOT_B0_CEREMONY_AND_COST_CEILING",
    accountId: "123456789012",
    approvedAt: "2026-08-19T07:00:00.000Z",
    cleanupOnlyAuthorizationApproved: true,
    cleanupOnlyAuthorization: {
      schemaVersion: "prooftoact.one-time-bootstrap-cleanup-authorization.v2",
      beginsAt: "2026-08-19T08:00:00.000Z",
      expiresAt: "2026-08-20T08:00:00.000Z",
      acceptedCompletionOrAbandonedPartialDispositionRequired: true,
      acceptedCompletionReceiptRequiredForCompletedExecution: true,
      abandonedPartialDispositionRequiredForIncompleteExecution: true
    },
    expiresAt: "2026-08-19T08:00:00.000Z",
    operationId: "123e4567-e89b-42d3-a456-426614174000",
    sourceCommit: "a".repeat(40),
    treeDigest: "b".repeat(40),
    runtimeExecutionBindingSha256: __test.digest(runtime),
    costCeiling: {
      currency: "USD",
      maximumMonthlyUsdCents: 350,
      maximumOneTimeUsdCents: 500,
      reconciliationReceipt: costReconciliation,
      reconciliationReceiptSha256: costReconciliation.receiptSha256
    }
  };
  const plan = {
    schemaVersion: "prooftoact.one-time-bootstrap-authority-plan.v1",
    account: { accountId: receipt.accountId },
    authorization: {
      cleanupOnlyAuthorization: receipt.cleanupOnlyAuthorization,
      userAuthorizationReceiptSha256: ""
    },
    costCeiling: receipt.costCeiling,
    notAfter: receipt.expiresAt,
    operation: { operationId: receipt.operationId },
    source: {
      commit: receipt.sourceCommit,
      runtimeExecutionBinding: runtime,
      tree: receipt.treeDigest
    }
  };
  const authorizationBytes = Buffer.from(
    `${__test.canonicalJson(receipt)}\n`, "utf8"
  );
  plan.authorization.userAuthorizationReceiptSha256 =
    __test.sha256(authorizationBytes);
  plan.planBodySha256 = __test.digest(plan);
  const planBytes = Buffer.from(`${__test.canonicalJson(plan)}\n`, "utf8");
  const originalNow = Date.now;
  Date.now = () => Date.parse("2026-08-19T07:30:00.000Z");
  try {
    assert.equal(__test.verifyPlanAndAuthorization(
      planBytes, authorizationBytes
    ).plan.planBodySha256, plan.planBodySha256);
    Date.now = () => Date.parse("2026-08-19T08:30:00.000Z");
    assert.throws(() => __test.verifyPlanAndAuthorization(
      planBytes, authorizationBytes, "NEW"
    ), /ONE_TIME_BOOTSTRAP_LAUNCH_AUTHORIZATION_REJECTED/u);
    assert.equal(__test.verifyPlanAndAuthorization(
      planBytes, authorizationBytes, "RECONCILE_ONLY"
    ).plan.planBodySha256, plan.planBodySha256);
    Date.now = () => Date.parse("2026-08-20T07:59:59.999Z");
    assert.equal(__test.verifyPlanAndAuthorization(
      planBytes, authorizationBytes, "RECONCILE_ONLY"
    ).plan.planBodySha256, plan.planBodySha256);
    Date.now = () => Date.parse("2026-08-20T08:00:00.000Z");
    assert.throws(() => __test.verifyPlanAndAuthorization(
      planBytes, authorizationBytes, "RECONCILE_ONLY"
    ), /ONE_TIME_BOOTSTRAP_LAUNCH_AUTHORIZATION_REJECTED/u);
    Date.now = () => Date.parse("2026-08-19T07:30:00.000Z");
    const changed = structuredClone(receipt);
    changed.runtimeExecutionBindingSha256 = "f".repeat(64);
    const changedBytes = Buffer.from(
      `${__test.canonicalJson(changed)}\n`, "utf8"
    );
    plan.authorization.userAuthorizationReceiptSha256 =
      __test.sha256(changedBytes);
    const changedBody = { ...plan };
    delete changedBody.planBodySha256;
    plan.planBodySha256 = __test.digest(changedBody);
    assert.throws(() => __test.verifyPlanAndAuthorization(
      Buffer.from(`${__test.canonicalJson(plan)}\n`, "utf8"), changedBytes
    ), /ONE_TIME_BOOTSTRAP_LAUNCH_AUTHORIZATION_REJECTED/u);
  } finally {
    Date.now = originalNow;
  }
});

test("rendered launcher source rejects ambient preloads, endpoint overrides, and proxy state", () => {
  for (const forbidden of [
    "NODE_OPTIONS", "NODE_PATH", "AWS_ENDPOINT_URL", "AWS_CA_BUNDLE",
    "HTTP_PROXY", "HTTPS_PROXY", "SSL_CERT_FILE", "SSL_CERT_DIR"
  ]) assert.equal(__test.ALLOWED_ENVIRONMENT.has(forbidden), false, forbidden);
  assert.match(LAUNCHER, /process\.execArgv\.length === 0/u);
  assert.match(LAUNCHER, /process\.env\.PATH === "\/usr\/bin:\/bin"/u);
});
