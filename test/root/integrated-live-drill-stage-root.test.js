import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { canonicalJson } from "../../src/cloud/canonical-json.js";
import {
  installIntegratedLiveDrillStage
} from "../../scripts/install-integrated-live-drill-stage.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const COMPONENTS = Object.freeze([
  "authority-race", "dispatch-broker", "provider-operation", "dvi", "finalizer", "orchestrator", "reconciler",
  "supervisor", "worker"
]);
const STAGE_CONTROLS = Object.freeze([
  "infra/systemd/prooftoact-integrated-live-drill-stage-verify@.service",
  "infra/systemd/prooftoact-integrated-live-drill@.service",
  "infra/systemd/prooftoact-integrated-live-drill-resume@.service",
  "infra/systemd/prooftoact-integrated-live-drill-dispatch-broker@.service",
  "infra/systemd/prooftoact-integrated-live-drill-executor@.service",
  "infra/systemd/prooftoact-integrated-live-drill-provider-operation@.service",
  "infra/systemd/prooftoact-integrated-live-drill-provider-operation@.socket",
  "infra/systemd/prooftoact-integrated-live-drill-reconcile@.service",
  "scripts/install-integrated-live-drill-stage.js",
  "scripts/verify-integrated-live-drill-stage.js",
  "scripts/verify-integrated-live-drill-systemd-boundary.js"
]);
const SOURCE_COMMIT = "1".repeat(40);
const TREE_DIGEST = "2".repeat(40);
const PACKAGE_LOCK_DIGEST = "3".repeat(64);
const STAGE_INSTANCE = "11111111-1111-4111-8111-111111111111";
const OFFICIAL_LINUX_X64_NODE_SHA256 =
  "93956de2e59480474a7b46571da1651180b1a050cdf32641ebec4ce6e478e068";

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function writeExact(filePath, bytes, mode = 0o444) {
  fs.mkdirSync(path.dirname(filePath), { mode: 0o755, recursive: true });
  fs.writeFileSync(filePath, bytes, { flag: "wx", mode });
  fs.chownSync(filePath, 0, 0);
  fs.chmodSync(filePath, mode);
}

function fixture(fixtureRoot) {
  const buildRoot = path.join(fixtureRoot, "build");
  const runtimeRoot = path.join(buildRoot, "dist/runtime");
  const stageParent = path.join(fixtureRoot, "stage");
  const receiptRoot = path.join(fixtureRoot, "receipts");
  const verifierParent = path.join(fixtureRoot, "verifiers");
  const unitRoot = path.join(fixtureRoot, "systemd");
  const acceptedBuildParent = path.join(fixtureRoot, "accepted-build");
  for (const directory of [
    acceptedBuildParent, buildRoot, runtimeRoot, stageParent, receiptRoot,
    unitRoot, verifierParent
  ]) {
    fs.mkdirSync(directory, { mode: 0o755, recursive: true });
    fs.chownSync(directory, 0, 0);
    fs.chmodSync(directory, 0o755);
  }
  const nodeBytes = fs.readFileSync(process.execPath);
  assert.equal(process.platform, "linux");
  assert.equal(process.arch, "x64");
  assert.equal(process.version, "v22.23.1");
  assert.equal(sha256(nodeBytes), OFFICIAL_LINUX_X64_NODE_SHA256);
  const nodeFile = `node-${OFFICIAL_LINUX_X64_NODE_SHA256}`;
  writeExact(path.join(runtimeRoot, nodeFile), nodeBytes, 0o555);

  const launcherBytes = fs.readFileSync(
    path.join(ROOT, "scripts/lib/verified-node-bundle-launcher.pl")
  );
  const launcherSha256 = sha256(launcherBytes);
  writeExact(
    path.join(runtimeRoot, "verified-node-bundle-launcher.pl"),
    launcherBytes,
    0o555
  );

  const componentRecords = {};
  const manifestComponents = {};
  for (const [index, name] of COMPONENTS.entries()) {
    const bytes = Buffer.from(
      `export const component = ${JSON.stringify(name)};\n`,
      "utf8"
    );
    const digest = sha256(bytes);
    const file = `${name}-${digest}.mjs`;
    writeExact(path.join(runtimeRoot, file), bytes, 0o555);
    componentRecords[name] = Object.freeze({
      path: `dist/runtime/${file}`,
      sha256: digest
    });
    manifestComponents[name] = Object.freeze({
      bundledPackages: [4, 7].includes(index) ? ["pg"] : [],
      bytes: bytes.length,
      externalImports: ["node:fs"],
      file,
      sha256: digest
    });
  }
  const toolchain = Object.freeze({
    architecture: "x64",
    nodeVersion: "v22.23.1",
    npmVersion: "10.9.8",
    platform: "linux",
    schemaVersion: "tideproof.build-toolchain.v1"
  });
  const manifest = Object.freeze({
    schemaVersion: "tideproof.integrated-live-drill-runtime-manifest.v1",
    sourceCommit: SOURCE_COMMIT,
    treeDigest: TREE_DIGEST,
    packageLockDigest: PACKAGE_LOCK_DIGEST,
    toolchainSha256: sha256(Buffer.from(canonicalJson(toolchain))),
    launcher: Object.freeze({
      file: "verified-node-bundle-launcher.pl",
      sha256: launcherSha256
    }),
    node: Object.freeze({
      architecture: "x64",
      distribution: "nodejs.org-release-v22.23.1",
      file: nodeFile,
      platform: "linux",
      sha256: OFFICIAL_LINUX_X64_NODE_SHA256,
      version: "v22.23.1"
    }),
    components: Object.freeze(manifestComponents)
  });
  const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`);
  const manifestSha256 = sha256(manifestBytes);
  const manifestPath =
    `dist/runtime/runtime-manifest-${manifestSha256}.json`;
  writeExact(path.join(buildRoot, manifestPath), manifestBytes, 0o444);

  const buildReceipt = Object.freeze({
    mode: "CLEAN_ARTIFACT_BUILD",
    projectSourceMode: "ISOLATED_EXACT_GIT_CHECKOUT_AND_BLOBS",
    sourceCommit: SOURCE_COMMIT,
    treeDigest: TREE_DIGEST,
    packageLockDigest: PACKAGE_LOCK_DIGEST,
    workingTreeClean: true,
    workingTreeCleanBeforeGeneration: true,
    buildControlInputs: STAGE_CONTROLS.map((controlPath, index) => ({
      gitBlobId: index.toString(16).padStart(40, "0"),
      path: controlPath,
      sha256: sha256(fs.readFileSync(path.join(ROOT, controlPath)))
    })),
    toolchain,
    liveDrillRuntime: Object.freeze({
      manifestPath,
      manifestSha256,
      launcher: Object.freeze({
        path: "dist/runtime/verified-node-bundle-launcher.pl",
        sha256: launcherSha256
      }),
      node: Object.freeze({
        architecture: "x64",
        distribution: "nodejs.org-release-v22.23.1",
        path: `dist/runtime/${nodeFile}`,
        platform: "linux",
        sha256: OFFICIAL_LINUX_X64_NODE_SHA256,
        version: "v22.23.1"
      }),
      components: Object.freeze(componentRecords)
    })
  });
  const buildReceiptPath = path.join(buildRoot, "gate2-build-receipt.json");
  writeExact(
    path.join(buildRoot, "scripts/verify-integrated-live-drill-stage.js"),
    fs.readFileSync(path.join(
      ROOT,
      "scripts/verify-integrated-live-drill-stage.js"
    )),
    0o444
  );
  for (const controlPath of STAGE_CONTROLS.filter((candidate) =>
    candidate.startsWith("infra/systemd/")
  )) {
    writeExact(
      path.join(buildRoot, controlPath),
      fs.readFileSync(path.join(ROOT, controlPath)),
      0o444
    );
  }
  writeExact(
    buildReceiptPath,
    Buffer.from(`${canonicalJson(buildReceipt)}\n`),
    0o444
  );
  return Object.freeze({
    buildRoot: path.join(acceptedBuildParent, STAGE_INSTANCE),
    buildSourceRoot: buildRoot,
    buildReceiptPath,
    buildReceiptSha256: sha256(fs.readFileSync(buildReceiptPath)),
    manifestSha256,
    receiptRoot,
    stageRoot: path.join(stageParent, STAGE_INSTANCE),
    unitRoot,
    verifierRoot: path.join(verifierParent, STAGE_INSTANCE)
  });
}

function verifyAsUnprivileged(
  buildRoot,
  expectedBuildReceiptSha256Path,
  stageReceiptPath,
  unitRoot,
  verifierRoot,
  stageRoot
) {
  return spawnSync(
    "/usr/bin/setpriv",
    [
      "--reuid=65534",
      "--regid=65534",
      "--clear-groups",
      path.join(verifierRoot, "node"),
      path.join(verifierRoot, "verify-integrated-live-drill-stage.js"),
      "--build-root",
      buildRoot,
      "--build-receipt",
      path.join(buildRoot, "gate2-build-receipt.json"),
      "--expected-build-receipt-sha256-path",
      expectedBuildReceiptSha256Path,
      "--expected-stage-root",
      stageRoot,
      "--stage-receipt",
      stageReceiptPath,
      "--unit-root",
      unitRoot,
      "--verifier-root",
      verifierRoot
    ],
    { encoding: "utf8", env: { LANG: "C.UTF-8", PATH: "/usr/bin:/bin" } }
  );
}

test("root installer publishes one exact stage and independent non-root verification rejects drift", {
  skip: process.geteuid?.() !== 0 || !fs.existsSync("/usr/bin/setpriv")
}, () => {
  const fixtureRoot = `/opt/prooftoact-stage-regression-${process.pid}`;
  assert.equal(fs.existsSync(fixtureRoot), false);
  fs.mkdirSync(fixtureRoot, { mode: 0o755 });
  fs.chownSync(fixtureRoot, 0, 0);
  fs.chmodSync(fixtureRoot, 0o755);
  try {
    const current = fixture(fixtureRoot);
    const stageReceiptPath = path.join(current.receiptRoot, "stage-1.json");
    const acceptedBuildReceiptSha256Path = path.join(
      current.receiptRoot,
      "accepted-build-receipt-sha256"
    );
    const receipt = installIntegratedLiveDrillStage({
      buildRoot: current.buildRoot,
      buildSourceRoot: current.buildSourceRoot,
      expectedBuildReceiptSha256: current.buildReceiptSha256,
      outputReceiptPath: stageReceiptPath,
      stageRoot: current.stageRoot,
      unitRoot: current.unitRoot,
      verifierRoot: current.verifierRoot
    }, {
      systemdReloader: () => true
    });
    assert.equal(receipt.files.length, 12);
    assert.equal(receipt.manifestSha256, current.manifestSha256);
    assert.equal(receipt.stageInstance, STAGE_INSTANCE);
    assert.equal(receipt.stageRoot, current.stageRoot);
    assert.equal(receipt.verifierRoot, current.verifierRoot);
    assert.equal(receipt.unitRoot, current.unitRoot);
    assert.equal(receipt.unitFiles.length, 8);
    assert.deepEqual(receipt.verifierFiles.map(({ name }) => name), [
      "node",
      "verify-integrated-live-drill-stage.js"
    ]);
    assert.deepEqual(
      receipt.stageControls.map(({ path: controlPath }) => controlPath),
      STAGE_CONTROLS
    );
    assert.equal(fs.statSync(receipt.stageRoot).mode & 0o7777, 0o555);
    assert.equal(fs.statSync(stageReceiptPath).mode & 0o7777, 0o444);
    const accepted = verifyAsUnprivileged(
      current.buildRoot,
      acceptedBuildReceiptSha256Path,
      stageReceiptPath,
      current.unitRoot,
      current.verifierRoot,
      current.stageRoot
    );
    assert.equal(accepted.status, 0, accepted.stderr);
    assert.equal(JSON.parse(accepted.stdout).status, "PASS");

    const reusedReceiptPath = path.join(current.receiptRoot, "stage-2.json");
    const reused = installIntegratedLiveDrillStage({
      buildRoot: current.buildRoot,
      buildSourceRoot: current.buildSourceRoot,
      expectedBuildReceiptSha256: current.buildReceiptSha256,
      outputReceiptPath: reusedReceiptPath,
      stageRoot: current.stageRoot,
      unitRoot: current.unitRoot,
      verifierRoot: current.verifierRoot
    }, {
      systemdReloader: () => true
    });
    assert.equal(reused.receiptSha256, receipt.receiptSha256);

    const executable = path.join(
      receipt.stageRoot,
      receipt.files.find(({ mode }) => mode === 0o555).name
    );
    fs.chmodSync(executable, 0o755);
    const wrongMode = verifyAsUnprivileged(
      current.buildRoot,
      acceptedBuildReceiptSha256Path,
      stageReceiptPath,
      current.unitRoot,
      current.verifierRoot,
      current.stageRoot
    );
    assert.notEqual(wrongMode.status, 0);
    fs.chmodSync(executable, 0o555);

    fs.chmodSync(receipt.stageRoot, 0o755);
    fs.writeFileSync(path.join(receipt.stageRoot, "extra"), "extra", {
      flag: "wx",
      mode: 0o444
    });
    fs.chmodSync(receipt.stageRoot, 0o555);
    const extra = verifyAsUnprivileged(
      current.buildRoot,
      acceptedBuildReceiptSha256Path,
      stageReceiptPath,
      current.unitRoot,
      current.verifierRoot,
      current.stageRoot
    );
    assert.notEqual(extra.status, 0);
    fs.chmodSync(receipt.stageRoot, 0o755);
    fs.unlinkSync(path.join(receipt.stageRoot, "extra"));
    fs.chmodSync(receipt.stageRoot, 0o555);

    fs.chmodSync(receipt.stageRoot, 0o755);
    const replaced = `${executable}.replaced`;
    fs.renameSync(executable, replaced);
    fs.symlinkSync(path.basename(replaced), executable);
    fs.chmodSync(receipt.stageRoot, 0o555);
    const symlink = verifyAsUnprivileged(
      current.buildRoot,
      acceptedBuildReceiptSha256Path,
      stageReceiptPath,
      current.unitRoot,
      current.verifierRoot,
      current.stageRoot
    );
    assert.notEqual(symlink.status, 0);
    fs.chmodSync(receipt.stageRoot, 0o755);
    fs.unlinkSync(executable);
    fs.renameSync(replaced, executable);
    fs.chmodSync(receipt.stageRoot, 0o555);

    fs.chmodSync(receipt.stageRoot, 0o755);
    const hardlink = path.join(receipt.stageRoot, "hardlink");
    fs.linkSync(executable, hardlink);
    fs.chmodSync(receipt.stageRoot, 0o555);
    const linked = verifyAsUnprivileged(
      current.buildRoot,
      acceptedBuildReceiptSha256Path,
      stageReceiptPath,
      current.unitRoot,
      current.verifierRoot,
      current.stageRoot
    );
    assert.notEqual(linked.status, 0);
    fs.chmodSync(receipt.stageRoot, 0o755);
    fs.unlinkSync(hardlink);
    fs.chmodSync(receipt.stageRoot, 0o555);

    fs.chmodSync(executable, 0o755);
    assert.throws(
      () => installIntegratedLiveDrillStage({
        buildRoot: current.buildRoot,
        buildSourceRoot: current.buildSourceRoot,
        expectedBuildReceiptSha256: current.buildReceiptSha256,
        outputReceiptPath: path.join(current.receiptRoot, "conflict.json"),
        stageRoot: current.stageRoot,
        unitRoot: current.unitRoot,
        verifierRoot: current.verifierRoot
      }, {
        systemdReloader: () => true
      }),
      /INTEGRATED_LIVE_DRILL_STAGE_INSTALL_REJECTED/u
    );
  } finally {
    fs.chmodSync(fixtureRoot, 0o700);
    fs.rmSync(fixtureRoot, { force: true, recursive: true });
  }
});
