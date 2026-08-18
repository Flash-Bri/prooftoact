import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { buildReleaseControlRuntime } from
  "../release-control/build-release-control-runtime.js";
import { loadReleaseControlRuntime } from
  "../release-control/src/release-control-runtime-loader.js";
import { attestReleaseControlTable as directTableAttestor } from
  "../scripts/lib/release-control-table-identity.js";

const CONTROL_PLANE_COMMIT = "a".repeat(40);
const CONTROL_PLANE_TREE = "b".repeat(40);

const CREDENTIALS = Object.freeze({
  accessKeyId: "ASIAEXPLICITFIXTURE1",
  secretAccessKey: "s".repeat(40),
  sessionToken: "t".repeat(32)
});

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function loadInput(projectRoot, receipt, overrides = {}) {
  return {
    expectedControlPlaneCommit: CONTROL_PLANE_COMMIT,
    expectedControlPlaneTree: CONTROL_PLANE_TREE,
    expectedPackageJsonSha256: receipt.packageJsonSha256,
    expectedPackageLockSha256: receipt.packageLockSha256,
    projectRoot,
    receipt,
    ...overrides
  };
}

function tableEvidence() {
  const accountId = "111111111111";
  return {
    describeResponse: {
      Table: {
        AttributeDefinitions: [{ AttributeName: "pk", AttributeType: "S" }],
        BillingModeSummary: { BillingMode: "PAY_PER_REQUEST" },
        DeletionProtectionEnabled: true,
        ItemCount: 0,
        KeySchema: [{ AttributeName: "pk", KeyType: "HASH" }],
        SSEDescription: {
          KMSMasterKeyArn:
            `arn:aws:kms:us-east-1:${accountId}:key/` +
            "223e4567-e89b-42d3-a456-426614174001",
          SSEType: "KMS",
          Status: "ENABLED"
        },
        TableArn:
          `arn:aws:dynamodb:us-east-1:${accountId}:table/` +
          "prooftoact-release-controller",
        TableId: "123e4567-e89b-42d3-a456-426614174000",
        TableName: "prooftoact-release-controller",
        TableSizeBytes: 0,
        TableStatus: "ACTIVE"
      }
    },
    expectedAccountId: accountId,
    listTagsResponse: {
      Tags: [
        { Key: "Project", Value: "ProofToAct" },
        { Key: "Purpose", Value: "RetainedReleaseControl" },
        { Key: "Retention", Value: "IntentionalOutsideApplicationTeardown" }
      ]
    },
    region: "us-east-1"
  };
}

test("content-addressed release-control provider bundle builds and loads exact bytes", async () => {
  const outputRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "prooftoact-release-control-runtime-")
  );
  try {
    const receipt = await buildReleaseControlRuntime({
      controlPlaneCommit: CONTROL_PLANE_COMMIT,
      controlPlaneTree: CONTROL_PLANE_TREE,
      outputRoot,
      projectRoot: path.resolve(import.meta.dirname, "../release-control")
    });
    assert.match(receipt.path,
      /^dist\/aws\/release-control-provider-[0-9a-f]{64}\.mjs$/u);
    assert.equal(receipt.bundledPackages.includes("@aws-sdk/client-dynamodb"), true);
    assert.equal(receipt.bundledPackages.some((name) =>
      name.includes("credential-provider") || name.includes("token-providers")),
    false);
    assert.equal(receipt.packageJsonSha256, sha256File(path.resolve(
      import.meta.dirname,
      "../release-control/package.json"
    )));
    assert.equal(receipt.packageLockSha256, sha256File(path.resolve(
      import.meta.dirname,
      "../release-control/package-lock.json"
    )));
    assert.equal(receipt.externalImports.every((name) => name.startsWith("node:")), true);
    assert.equal(receipt.controlPlaneCommit, CONTROL_PLANE_COMMIT);
    assert.equal(receipt.controlPlaneTree, CONTROL_PLANE_TREE);
    assert.equal(receipt.packageInventory.map(({ name }) => name).join("\n"),
      receipt.bundledPackages.join("\n"));
    assert.equal(receipt.sourceInventory.some(({ path: sourcePath }) =>
      sourcePath === "scripts/lib/release-control-table-identity.js"), true);
    assert.deepEqual(
      receipt.optionalArtifacts.map(({ path: artifactPath, sha256, status }) => ({
        path: artifactPath,
        sha256,
        status
      })),
      [
        {
          path: "release-control/DEPENDENCY_INVENTORY.json",
          sha256: "86aaf3acdc45bc53794986179f6e683c78b9bc55045f06f575edfd24765ca9f6",
          status: "PRESENT"
        },
        {
          path: "release-control/THIRD_PARTY_NOTICES.txt",
          sha256: "2fcc2b85628294fc4d8580b86e53988abd08cf74cca8404800362d260be767ad",
          status: "PRESENT"
        }
      ]
    );
    assert.equal(receipt.nodeExecutableSha256,
      sha256File(fs.realpathSync(process.execPath)));
    assert.match(receipt.builderSha256, /^[0-9a-f]{64}$/u);
    assert.match(receipt.esbuildBinarySha256, /^[0-9a-f]{64}$/u);
    const loaded = await loadReleaseControlRuntime(loadInput(outputRoot, receipt));
    assert.equal(loaded.runtimeSha256, receipt.sha256);
    assert.equal(typeof loaded.createReleaseControlDynamoDbStore, "function");
    assert.deepEqual(
      loaded.attestReleaseControlTable(tableEvidence()),
      directTableAttestor(tableEvidence())
    );
    const runtime = await loaded.createReleaseControlAwsRuntime({
      credentials: CREDENTIALS,
      region: "us-east-1",
      tableArn:
        "arn:aws:dynamodb:us-east-1:111111111111:table/prooftoact-release-controller"
    });
    assert.equal(typeof runtime.transactReleaseControlItems, "function");
    assert.equal(typeof runtime.getReleaseControlCallerIdentity, "function");
    const filePath = path.join(outputRoot, receipt.path);
    fs.appendFileSync(filePath, "\n");
    await assert.rejects(
      loadReleaseControlRuntime(loadInput(outputRoot, receipt)),
      /RUNTIME_FILE_REJECTED|RUNTIME_DIGEST_REJECTED/u
    );
  } finally {
    fs.rmSync(outputRoot, { recursive: true, force: true });
  }
});

test("runtime loader rejects provenance and expected-control-plane substitution", async () => {
  const outputRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "prooftoact-release-control-provenance-")
  );
  try {
    const receipt = await buildReleaseControlRuntime({
      controlPlaneCommit: CONTROL_PLANE_COMMIT,
      controlPlaneTree: CONTROL_PLANE_TREE,
      outputRoot,
      projectRoot: path.resolve(import.meta.dirname, "../release-control")
    });
    await assert.rejects(
      loadReleaseControlRuntime(loadInput(outputRoot, receipt, {
        expectedControlPlaneCommit: "c".repeat(40)
      })),
      /RUNTIME_RECEIPT_REJECTED/u
    );
    const changed = structuredClone(receipt);
    changed.sourceInventory[0].sha256 = "d".repeat(64);
    await assert.rejects(
      loadReleaseControlRuntime(loadInput(outputRoot, changed)),
      /RUNTIME_PROVENANCE_REJECTED/u
    );
  } finally {
    fs.rmSync(outputRoot, { recursive: true, force: true });
  }
});

test("runtime loader rejects path, digest, and receipt-shape substitution", async () => {
  await assert.rejects(
    loadReleaseControlRuntime({
      projectRoot: os.tmpdir(),
      receipt: {
        bundledPackages: [],
        bytes: 1,
        externalImports: ["node:fs"],
        packageJsonSha256: "1".repeat(64),
        packageLockSha256: "2".repeat(64),
        path: "../../escape.mjs",
        sha256: "0".repeat(64)
      }
    }),
    /RUNTIME_RECEIPT_REJECTED/u
  );
});
