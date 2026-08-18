import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { buildReleaseProviderRuntimes } from
  "../release-provider/build-release-provider-runtimes.js";
import { buildReleaseProviderMetadata } from
  "../release-provider/generate-release-provider-metadata.js";
import { loadReleaseProviderRuntime } from
  "../release-provider/src/release-provider-runtime-loader.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PROVIDER_ROOT = path.join(ROOT, "release-provider");
const COMMIT = "1".repeat(40);
const TREE = "2".repeat(40);
const CREDENTIALS = Object.freeze({
  accessKeyId: `ASIA${"A".repeat(16)}`,
  secretAccessKey: "b".repeat(40),
  sessionToken: "temporary-session-token"
});

function digest(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath))
    .digest("hex");
}

async function built() {
  const outputRoot = fs.mkdtempSync(path.join(os.tmpdir(),
    "prooftoact-release-provider-"));
  const receipt = await buildReleaseProviderRuntimes({
    controlPlaneCommit: COMMIT,
    controlPlaneTree: TREE,
    outputRoot,
    projectRoot: PROVIDER_ROOT
  });
  return { outputRoot, receipt };
}

function loaderInput(outputRoot, receipt, capability) {
  return {
    capability,
    expectedControlPlaneCommit: COMMIT,
    expectedControlPlaneTree: TREE,
    expectedPackageJsonSha256: digest(path.join(PROVIDER_ROOT, "package.json")),
    expectedPackageLockSha256: digest(path.join(PROVIDER_ROOT,
      "package-lock.json")),
    outputRoot,
    receipt
  };
}

test("builds six deterministic capability-specific content-addressed runtimes", async () => {
  const first = await built();
  const second = await built();
  assert.equal(first.receipt.runtimeSetSha256,
    second.receipt.runtimeSetSha256);
  assert.equal(first.receipt.provenanceSha256,
    second.receipt.provenanceSha256);
  assert.deepEqual(first.receipt.runtimes.map(({ capability }) => capability), [
    "PERMIT_READER", "EXECUTE_PERMIT_READER", "EXECUTE_DISPATCHER",
    "EXECUTE_READBACK", "PREPARE_DISPATCHER", "PREPARE_READBACK"
  ]);
  for (const runtime of first.receipt.runtimes) {
    assert.equal(runtime.path.endsWith(`${runtime.sha256}.mjs`), true);
    assert.equal(runtime.externalImports.every((name) =>
      name.startsWith("node:")), true);
    assert.equal(runtime.bundledPackages.some((name) =>
      name.startsWith("@aws-sdk/credential-provider-")), false);
    const bytes = fs.readFileSync(path.join(first.outputRoot, runtime.path));
    assert.equal(crypto.createHash("sha256").update(bytes).digest("hex"),
      runtime.sha256);
    assert.equal(fs.statSync(path.join(first.outputRoot, runtime.path)).mode &
      0o777, 0o600);
  }
});

test("loader verifies provenance, exact bytes, modes, and capability exports", async () => {
  const { outputRoot, receipt } = await built();
  const permit = await loadReleaseProviderRuntime(loaderInput(
    outputRoot, receipt, "PERMIT_READER"));
  const executePermit = await loadReleaseProviderRuntime(loaderInput(
    outputRoot, receipt, "EXECUTE_PERMIT_READER"));
  const executeDispatch = await loadReleaseProviderRuntime(loaderInput(
    outputRoot, receipt, "EXECUTE_DISPATCHER"));
  const executeReadback = await loadReleaseProviderRuntime(loaderInput(
    outputRoot, receipt, "EXECUTE_READBACK"));
  const dispatch = await loadReleaseProviderRuntime(loaderInput(
    outputRoot, receipt, "PREPARE_DISPATCHER"));
  const readback = await loadReleaseProviderRuntime(loaderInput(
    outputRoot, receipt, "PREPARE_READBACK"));
  assert.deepEqual(Object.keys(permit.exports), [
    "createAwsPreparePermitTransport", "createPreparePermitReader"
  ]);
  assert.deepEqual(Object.keys(executePermit.exports), [
    "createAwsExecutePermitTransport", "createExecutePermitReader"
  ]);
  assert.deepEqual(Object.keys(executeDispatch.exports), [
    "createAwsExecuteDispatcherTransport", "createExecuteDispatcher"
  ]);
  assert.deepEqual(Object.keys(executeReadback.exports), [
    "createAwsExecuteReadbackTransport", "createExecuteReadback"
  ]);
  assert.deepEqual(Object.keys(dispatch.exports), [
    "createAwsPrepareDispatcherTransport", "createPrepareDispatcher"
  ]);
  assert.deepEqual(Object.keys(readback.exports), [
    "createAwsPrepareReadbackTransport", "createPrepareReadback"
  ]);
  assert.equal(permit.runtimeSetSha256, dispatch.runtimeSetSha256);
  assert.equal(executePermit.runtimeSetSha256, dispatch.runtimeSetSha256);
  assert.equal(executeDispatch.runtimeSetSha256, dispatch.runtimeSetSha256);
  assert.equal(executeReadback.runtimeSetSha256, dispatch.runtimeSetSha256);
  assert.equal(dispatch.runtimeSetSha256, readback.runtimeSetSha256);

  const permitTransport = await permit.exports.createAwsPreparePermitTransport({
    credentials: CREDENTIALS,
    tableArn:
      "arn:aws:dynamodb:us-east-1:111111111111:table/" +
      "prooftoact-release-controller"
  });
  const executePermitTransport = await executePermit.exports
    .createAwsExecutePermitTransport({
      credentials: CREDENTIALS,
      tableArn:
        "arn:aws:dynamodb:us-east-1:111111111111:table/" +
        "prooftoact-release-controller"
    });
  const dispatchTransport =
    await dispatch.exports.createAwsPrepareDispatcherTransport({
      credentials: CREDENTIALS
    });
  const executeDispatchTransport =
    await executeDispatch.exports.createAwsExecuteDispatcherTransport({
      credentials: CREDENTIALS
    });
  const executeReadbackTransport =
    await executeReadback.exports.createAwsExecuteReadbackTransport({
      credentials: CREDENTIALS
    });
  const readbackTransport =
    await readback.exports.createAwsPrepareReadbackTransport({
      credentials: CREDENTIALS
    });
  assert.deepEqual(Object.keys(permitTransport), [
    "describeTable", "getCallerIdentity", "getIntentItem", "listTags"
  ]);
  assert.deepEqual(Object.keys(executePermitTransport), [
    "describeTable", "getCallerIdentity", "getIntentItem", "listTags"
  ]);
  assert.deepEqual(Object.keys(dispatchTransport), [
    "createChangeSet", "getObject", "headObject", "putObject"
  ]);
  assert.deepEqual(Object.keys(executeDispatchTransport), [
    "describeChangeSet", "describeStacks", "executeChangeSet",
    "updateTerminationProtection"
  ]);
  assert.deepEqual(Object.keys(executeReadbackTransport), [
    "describeChangeSet", "describeStackEvents", "describeStacks"
  ]);
  assert.deepEqual(Object.keys(readbackTransport), [
    "describeChangeSet", "describeStackEvents", "describeStackResources",
    "describeStacks", "getTemplate", "getObject", "headObject"
  ]);
});

test("built runtimes contain no forbidden cross-capability SDK command", async () => {
  const { outputRoot, receipt } = await built();
  const forbidden = {
    PERMIT_READER: [
      "CreateChangeSetCommand", "DeleteStackCommand", "ExecuteChangeSetCommand",
      "InvokeFunctionCommand", "PutObjectCommand", "TransactWriteItemsCommand",
      "UpdateItemCommand"
    ],
    EXECUTE_PERMIT_READER: [
      "CreateChangeSetCommand", "DeleteStackCommand", "ExecuteChangeSetCommand",
      "InvokeFunctionCommand", "PutObjectCommand", "TransactWriteItemsCommand",
      "UpdateItemCommand", "UpdateTerminationProtectionCommand"
    ],
    EXECUTE_DISPATCHER: [
      "AssumeRoleCommand", "CreateChangeSetCommand", "DeleteStackCommand",
      "DescribeStackEventsCommand", "GetObjectCommand", "InvokeFunctionCommand",
      "PutItemCommand", "PutObjectCommand", "TransactWriteItemsCommand",
      "UpdateItemCommand"
    ],
    EXECUTE_READBACK: [
      "AssumeRoleCommand", "CreateChangeSetCommand", "DeleteStackCommand",
      "ExecuteChangeSetCommand", "GetObjectCommand", "InvokeFunctionCommand",
      "PutItemCommand", "PutObjectCommand", "TransactWriteItemsCommand",
      "UpdateItemCommand", "UpdateTerminationProtectionCommand"
    ],
    PREPARE_DISPATCHER: [
      "AssumeRoleCommand", "DeleteStackCommand", "ExecuteChangeSetCommand",
      "InvokeFunctionCommand", "PutItemCommand", "TransactWriteItemsCommand",
      "UpdateItemCommand"
    ],
    PREPARE_READBACK: [
      "AssumeRoleCommand", "CreateChangeSetCommand", "DeleteStackCommand",
      "ExecuteChangeSetCommand", "InvokeFunctionCommand",
      "ListStackResourcesCommand", "PutObjectCommand",
      "TransactWriteItemsCommand", "UpdateItemCommand"
    ]
  };
  for (const runtime of receipt.runtimes) {
    const text = fs.readFileSync(path.join(outputRoot, runtime.path), "utf8");
    if (["PERMIT_READER", "EXECUTE_PERMIT_READER"]
      .includes(runtime.capability)) {
      assert.match(text, /readStrong/u,
        "sealed permit reader must expose broker-compatible readStrong");
    }
    if (runtime.capability === "PREPARE_DISPATCHER") {
      assert.match(text, /authorityNotAfter/u);
      assert.match(text, /Date\.now/u);
      assert.equal(text.includes("createPrepareDispatcherForTest"), false,
        "sealed dispatcher must not expose the test clock seam");
    }
    if (runtime.capability === "PREPARE_READBACK") {
      assert.match(text, /DescribeStackResourcesCommand/u);
      assert.match(text, /GetTemplateCommand/u);
      assert.match(text, /Date\.now/u);
      assert.equal(text.includes("createPrepareReadbackForTest"), false,
        "sealed readback must not expose the test clock seam");
    }
    if (runtime.capability === "EXECUTE_DISPATCHER") {
      assert.match(text, /ExecuteChangeSetCommand/u);
      assert.match(text, /UpdateTerminationProtectionCommand/u);
      assert.match(text, /Date\.now/u);
      assert.equal(text.includes("createExecuteDispatcherForTest"), false,
        "sealed execute dispatcher must not expose the test clock seam");
    }
    if (runtime.capability === "EXECUTE_READBACK") {
      assert.match(text, /DescribeStackEventsCommand/u);
      assert.match(text, /Date\.now/u);
      assert.equal(text.includes("createExecuteReadbackForTest"), false,
        "sealed execute readback must not expose the test clock seam");
    }
    for (const name of forbidden[runtime.capability]) {
      assert.equal(text.includes(name), false,
        `${runtime.capability} leaked ${name}`);
    }
  }
});

test("loader rejects receipt drift, byte tampering, and unsafe mode", async () => {
  const { outputRoot, receipt } = await built();
  const drift = structuredClone(receipt);
  drift.packageLockSha256 = "0".repeat(64);
  await assert.rejects(loadReleaseProviderRuntime(loaderInput(
    outputRoot, drift, "PERMIT_READER")),
  /RELEASE_PROVIDER_BUILD_RECEIPT_REJECTED/u);

  const runtime = receipt.runtimes[0];
  const filePath = path.join(outputRoot, runtime.path);
  fs.chmodSync(filePath, 0o644);
  await assert.rejects(loadReleaseProviderRuntime(loaderInput(
    outputRoot, receipt, "PERMIT_READER")),
  /RELEASE_PROVIDER_RUNTIME_FILE_REJECTED/u);
  fs.chmodSync(filePath, 0o600);
  fs.appendFileSync(filePath, "\n");
  await assert.rejects(loadReleaseProviderRuntime(loaderInput(
    outputRoot, receipt, "PERMIT_READER")),
  /RELEASE_PROVIDER_RUNTIME_FILE_REJECTED|RELEASE_PROVIDER_RUNTIME_DIGEST_REJECTED/u);
});

test("package and lock pin the independent provider toolchain exactly", () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(PROVIDER_ROOT,
    "package.json"), "utf8"));
  const lock = JSON.parse(fs.readFileSync(path.join(PROVIDER_ROOT,
    "package-lock.json"), "utf8"));
  assert.deepEqual(manifest.dependencies, {
    "@aws-sdk/client-cloudformation": "3.1098.0",
    "@aws-sdk/client-dynamodb": "3.1098.0",
    "@aws-sdk/client-s3": "3.1098.0",
    "@aws-sdk/client-sts": "3.1098.0",
    "@smithy/node-http-handler": "4.9.13"
  });
  assert.equal(manifest.devDependencies.esbuild, "0.28.1");
  assert.deepEqual(lock.packages[""].dependencies, manifest.dependencies);
  assert.deepEqual(lock.packages[""].devDependencies, manifest.devDependencies);
});

test("provider dependency inventory and notices reproduce byte for byte", async () => {
  const metadata = await buildReleaseProviderMetadata({
    projectRoot: PROVIDER_ROOT
  });
  assert.equal(fs.readFileSync(path.join(PROVIDER_ROOT,
    "DEPENDENCY_INVENTORY.json"), "utf8"), metadata.dependencyInventory);
  assert.equal(fs.readFileSync(path.join(PROVIDER_ROOT,
    "THIRD_PARTY_NOTICES.txt"), "utf8"), metadata.thirdPartyNotices);
  assert.equal(metadata.packageCount, 61);
  assert.equal(metadata.licenseTextCount > 0, true);
  const inventory = JSON.parse(metadata.dependencyInventory);
  assert.equal(inventory.runtimeSetSha256, metadata.runtimeSetSha256);
  assert.equal(inventory.status,
    "GENERATED_FROM_HERMETIC_LOCK_AND_BUNDLE_METAFILES");
  assert.equal(inventory.packages.filter(({ bundledCapabilities }) =>
    bundledCapabilities.length > 0).length > 0, true);
  assert.equal(inventory.packages.filter(({ name }) =>
    name.startsWith("@aws-sdk/credential-provider-")).every(
    ({ bundledCapabilities }) => bundledCapabilities.length === 0), true);
});
