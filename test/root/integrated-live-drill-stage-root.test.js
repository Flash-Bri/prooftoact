import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { canonicalJson } from "../../src/cloud/canonical-json.js";
import {
  __test as installerTest,
  installIntegratedLiveDrillStage
} from "../../scripts/install-integrated-live-drill-stage.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const COMPONENTS = Object.freeze([
  "authority-race", "dispatch-broker", "provider-activation", "provider-exchange",
  "provider-operation", "provider-terminalizer", "dvi", "finalizer", "orchestrator", "reconciler",
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
  "infra/systemd/prooftoact-integrated-live-drill-provider-activation@.service",
  "infra/systemd/prooftoact-integrated-live-drill-provider-activation@.socket",
  "infra/systemd/prooftoact-integrated-live-drill-provider-callback@.socket",
  "infra/systemd/prooftoact-integrated-live-drill-provider-exchange@.service",
  "infra/systemd/prooftoact-integrated-live-drill-provider-terminalizer@.service",
  "infra/systemd/prooftoact-integrated-live-drill-provider-terminalizer@.timer",
  "infra/systemd/prooftoact-integrated-live-drill-reconcile@.service",
  "infra/sysusers.d/prooftoact.conf",
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
const ROOT_STAGE_TEST_PARENT = "/var/lib/prooftoact-root-stage-tests";

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function writeExact(filePath, bytes, mode = 0o444) {
  fs.mkdirSync(path.dirname(filePath), { mode: 0o755, recursive: true });
  fs.writeFileSync(filePath, bytes, { flag: "wx", mode });
  fs.chownSync(filePath, 0, 0);
  fs.chmodSync(filePath, mode);
}

function createRootFixture(name) {
  fs.mkdirSync(ROOT_STAGE_TEST_PARENT, { mode: 0o755, recursive: true });
  fs.chownSync(ROOT_STAGE_TEST_PARENT, 0, 0);
  fs.chmodSync(ROOT_STAGE_TEST_PARENT, 0o755);
  const fixtureRoot = path.join(
    ROOT_STAGE_TEST_PARENT,
    `${name}-${process.pid}`
  );
  assert.equal(fs.existsSync(fixtureRoot), false);
  fs.mkdirSync(fixtureRoot, { mode: 0o755 });
  fs.chownSync(fixtureRoot, 0, 0);
  fs.chmodSync(fixtureRoot, 0o755);
  return fixtureRoot;
}

function removeRootFixture(fixtureRoot) {
  fs.chmodSync(fixtureRoot, 0o700);
  fs.rmSync(fixtureRoot, { force: true, recursive: true });
}

function injectedFileSystem(method, {
  beforeCall = null,
  beforeFailure = null,
  code = "EIO",
  occurrence = 1,
  persistent = false,
  shortWriteBytes = null,
  shortWriteOccurrence = null
} = {}) {
  let calls = 0;
  return new Proxy(fs, {
    get(target, property) {
      const original = Reflect.get(target, property);
      if (property !== method || typeof original !== "function") {
        return original;
      }
      return (...args) => {
        calls += 1;
        beforeCall?.({ args, calls });
        if (
          calls === shortWriteOccurrence &&
          Number.isSafeInteger(shortWriteBytes)
        ) {
          const [descriptor, bytes, offset, length, position] = args;
          return fs.writeSync(
            descriptor,
            bytes,
            offset,
            Math.min(shortWriteBytes, length),
            position
          );
        }
        if (calls === occurrence || (persistent && calls >= occurrence)) {
          beforeFailure?.({ args, calls });
          const error = new Error(`injected ${String(method)} failure`);
          error.code = code;
          throw error;
        }
        return Reflect.apply(original, target, args);
      };
    }
  });
}

function fixture(fixtureRoot) {
  const buildRoot = path.join(fixtureRoot, "build");
  const runtimeRoot = path.join(buildRoot, "dist/runtime");
  const stageParent = path.join(fixtureRoot, "stage");
  const receiptRoot = path.join(fixtureRoot, "receipts");
  const verifierParent = path.join(fixtureRoot, "verifiers");
  const unitRoot = path.join(fixtureRoot, "systemd");
  const sysusersRoot = path.join(fixtureRoot, "sysusers.d");
  const stateParent = path.join(fixtureRoot, "var/lib");
  const stateRoot = path.join(stateParent, "prooftoact");
  const acceptedBuildParent = path.join(fixtureRoot, "accepted-build");
  for (const directory of [
    acceptedBuildParent, buildRoot, runtimeRoot, stageParent, receiptRoot,
    stateParent, sysusersRoot, unitRoot, verifierParent
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
      `import fs from "node:fs";\n` +
        `export const component = ${JSON.stringify(name)};\n` +
        `const executableStat = fs.statSync("/proc/self/exe", {bigint: true});\n` +
        `process.stdout.write(JSON.stringify({component, argv0: process.argv0, ` +
        `execPath: process.execPath, executableLink: fs.readlinkSync("/proc/self/exe"), ` +
        `executableDev: String(executableStat.dev), ` +
        `executableIno: String(executableStat.ino)}) + "\\n");\n`,
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
    candidate.startsWith("infra/")
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
    stateRoot,
    sysusersRoot,
    unitRoot,
    verifierRoot: path.join(verifierParent, STAGE_INSTANCE)
  });
}

function verifyAsUnprivileged(
  buildRoot,
  expectedBuildReceiptSha256Path,
  stageReceiptPath,
  stateRoot,
  sysusersRoot,
  unitRoot,
  verifierRoot,
  stageRoot,
  { gid, uid }
) {
  return spawnSync(
    "/usr/bin/setpriv",
    [
      `--reuid=${uid}`,
      `--regid=${gid}`,
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
      "--state-root",
      stateRoot,
      "--sysusers-root",
      sysusersRoot,
      "--unit-root",
      unitRoot,
      "--verifier-root",
      verifierRoot
    ],
    { encoding: "utf8", env: { LANG: "C.UTF-8", PATH: "/usr/bin:/bin" } }
  );
}

function launchComponentAsUnprivileged(stageRoot, manifestSha256, component, {
  environment = {}
} = {}) {
  return spawnSync(
    "/usr/bin/setpriv",
    [
      "--reuid=65534",
      "--regid=65534",
      "--clear-groups",
      "/usr/bin/perl",
      path.join(stageRoot, "verified-node-bundle-launcher.pl"),
      component
    ],
    {
      cwd: stageRoot,
      encoding: "utf8",
      env: {
        LANG: "C.UTF-8",
        LC_ALL: "C.UTF-8",
        PATH: "/usr/bin:/bin",
        TIDEPROOF_INTEGRATED_LIVE_DRILL_RUNTIME_MANIFEST_SHA256:
          manifestSha256,
        TIDEPROOF_INTEGRATED_LIVE_DRILL_RUNTIME_STAGE_ROOT: stageRoot,
        ...environment
      }
    }
  );
}

test("fresh persistent state creates private roots before guard validation", {
  skip: process.geteuid?.() !== 0
}, () => {
  const fixtureRoot = createRootFixture("prooftoact-state-regression");
  const stateRoot = path.join(fixtureRoot, "state");
  try {
    const accounts = [
      "prooftoact",
      "prooftoact-broker",
      "prooftoact-operation",
      "prooftoact-activate",
      "prooftoact-provider"
    ].map((name) => Object.freeze({ gid: 0, name, uid: 0 }));
    const records = installerTest.preparePersistentState({
      accounts,
      code: "INTEGRATED_LIVE_DRILL_STAGE_INSTALL_REJECTED",
      instance: STAGE_INSTANCE,
      stateRoot
    });
    const guards = records.filter(({ role }) => role === "PRIVATE_GUARD");
    assert.equal(guards.length, 2);
    assert.deepEqual(guards.map(({ entries }) => entries), [["root"], ["root"]]);
    for (const name of ["evidence", "authorization"]) {
      assert.equal(
        fs.lstatSync(path.join(stateRoot, name, STAGE_INSTANCE, "root"))
          .isDirectory(),
        true
      );
    }
  } finally {
    removeRootFixture(fixtureRoot);
  }
});

test("root installer rejects a world-writable fixture ancestor", {
  skip: process.geteuid?.() !== 0
}, () => {
  const fixtureRoot = createRootFixture(
    "prooftoact-mutable-ancestor-regression"
  );
  const mutableParent = path.join(fixtureRoot, "mutable");
  fs.mkdirSync(mutableParent, { mode: 0o755 });
  fs.chownSync(mutableParent, 0, 0);
  fs.chmodSync(mutableParent, 0o777);
  try {
    assert.throws(
      () => installerTest.preparePersistentState({
        accounts: [],
        code: "INTEGRATED_LIVE_DRILL_STAGE_INSTALL_REJECTED",
        instance: STAGE_INSTANCE,
        stateRoot: path.join(mutableParent, "state")
      }),
      /INTEGRATED_LIVE_DRILL_STAGE_INSTALL_REJECTED/u
    );
  } finally {
    fs.chmodSync(mutableParent, 0o700);
    removeRootFixture(fixtureRoot);
  }
});

test("root exact-file publication is failure-convergent across publication boundaries", {
  skip: process.geteuid?.() !== 0
}, () => {
  const fixtureRoot = createRootFixture("prooftoact-publication-regression");
  const bytes = Buffer.from('{"schemaVersion":"publication-regression.v1"}\n');
  const code = "INTEGRATED_LIVE_DRILL_STAGE_INSTALL_REJECTED";
  const publish = (filePath, fileSystem = fs) =>
    installerTest.publishOrVerifyExactRootFile({
      bytes,
      code,
      filePath,
      fileSystem,
      mode: 0o444
    });
  try {
    const failures = [
      ["openSync", { code: "EACCES" }],
      ["writeSync", {
        code: "ENOSPC",
        occurrence: 2,
        shortWriteBytes: 15,
        shortWriteOccurrence: 1
      }],
      ["fchownSync", { code: "EPERM" }],
      ["fchmodSync", { code: "EPERM" }],
      ["fsyncSync", { code: "EIO" }],
      ["readSync", { code: "EIO" }],
      ["linkSync", { code: "EXDEV" }]
    ];
    for (const [index, [method, options]] of failures.entries()) {
      const filePath = path.join(fixtureRoot, `prepublication-${index}.json`);
      assert.throws(
        () => publish(filePath, injectedFileSystem(method, options)),
        /INTEGRATED_LIVE_DRILL_STAGE_INSTALL_REJECTED/u,
        method
      );
      assert.equal(fs.existsSync(filePath), false, method);
      assert.equal(
        fs.readdirSync(fixtureRoot).some((name) =>
          name.startsWith(`.${path.basename(filePath)}.publish-`)
        ),
        false,
        `${method}: temporary cleanup`
      );
      assert.equal(publish(filePath).sha256, sha256(bytes));
    }

    const directoryFsyncPath = path.join(fixtureRoot, "directory-fsync.json");
    assert.equal(
      publish(
        directoryFsyncPath,
        injectedFileSystem("fsyncSync", { code: "EIO", occurrence: 2 })
      ).sha256,
      sha256(bytes)
    );
    assert.equal(publish(directoryFsyncPath).sha256, sha256(bytes));

    const ambiguousPath = path.join(fixtureRoot, "ambiguous-fsync.json");
    assert.throws(
      () => publish(
        ambiguousPath,
        injectedFileSystem("fsyncSync", {
          code: "EIO",
          occurrence: 2,
          persistent: true
        })
      ),
      /INTEGRATED_LIVE_DRILL_STAGE_INSTALL_REJECTED/u
    );
    assert.equal(fs.readFileSync(ambiguousPath).equals(bytes), true);
    assert.equal(publish(ambiguousPath).sha256, sha256(bytes));

    const prelinkCrashPath = path.join(fixtureRoot, "prelink-crash.json");
    const prelinkTemporary = path.join(
      fixtureRoot,
      `.${path.basename(prelinkCrashPath)}.publish-${"a".repeat(32)}`
    );
    fs.writeFileSync(prelinkTemporary, bytes.subarray(0, 15), {
      flag: "wx",
      mode: 0o600
    });
    fs.chownSync(prelinkTemporary, 0, 0);
    assert.equal(publish(prelinkCrashPath).sha256, sha256(bytes));
    assert.equal(fs.existsSync(prelinkTemporary), true);
    assert.equal(fs.readFileSync(prelinkTemporary).length, 15);
    fs.unlinkSync(prelinkTemporary);

    const postlinkCrashPath = path.join(fixtureRoot, "postlink-crash.json");
    const postlinkTemporary = path.join(
      fixtureRoot,
      `.${path.basename(postlinkCrashPath)}.publish-${"b".repeat(32)}`
    );
    fs.writeFileSync(postlinkTemporary, bytes, { flag: "wx", mode: 0o444 });
    fs.chownSync(postlinkTemporary, 0, 0);
    fs.chmodSync(postlinkTemporary, 0o444);
    fs.linkSync(postlinkTemporary, postlinkCrashPath);
    assert.equal(publish(postlinkCrashPath).sha256, sha256(bytes));
    assert.equal(fs.existsSync(postlinkTemporary), false);
    assert.equal(fs.statSync(postlinkCrashPath).nlink, 1);

    const concurrentCleanupPath = path.join(
      fixtureRoot,
      "concurrent-cleanup.json"
    );
    const concurrentCleanupTemporary = path.join(
      fixtureRoot,
      `.${path.basename(concurrentCleanupPath)}.publish-${"d".repeat(32)}`
    );
    fs.writeFileSync(concurrentCleanupTemporary, bytes, {
      flag: "wx",
      mode: 0o444
    });
    fs.chownSync(concurrentCleanupTemporary, 0, 0);
    fs.chmodSync(concurrentCleanupTemporary, 0o444);
    fs.linkSync(concurrentCleanupTemporary, concurrentCleanupPath);
    assert.equal(publish(
      concurrentCleanupPath,
      injectedFileSystem("unlinkSync", {
        code: "ENOENT",
        beforeFailure({ args }) {
          fs.unlinkSync(args[0]);
        }
      })
    ).sha256, sha256(bytes));
    assert.equal(fs.existsSync(concurrentCleanupTemporary), false);
    assert.equal(fs.statSync(concurrentCleanupPath).nlink, 1);

    const cleanupIoErrorPath = path.join(
      fixtureRoot,
      "cleanup-io-error.json"
    );
    const cleanupIoErrorTemporary = path.join(
      fixtureRoot,
      `.${path.basename(cleanupIoErrorPath)}.publish-${"e".repeat(32)}`
    );
    fs.writeFileSync(cleanupIoErrorTemporary, bytes, {
      flag: "wx",
      mode: 0o444
    });
    fs.chownSync(cleanupIoErrorTemporary, 0, 0);
    fs.chmodSync(cleanupIoErrorTemporary, 0o444);
    fs.linkSync(cleanupIoErrorTemporary, cleanupIoErrorPath);
    assert.throws(
      () => publish(
        cleanupIoErrorPath,
        injectedFileSystem("unlinkSync", { code: "EIO" })
      ),
      /INTEGRATED_LIVE_DRILL_STAGE_INSTALL_REJECTED/u
    );
    assert.equal(fs.existsSync(cleanupIoErrorTemporary), true);
    assert.equal(publish(cleanupIoErrorPath).sha256, sha256(bytes));
    assert.equal(fs.existsSync(cleanupIoErrorTemporary), false);
    assert.equal(fs.statSync(cleanupIoErrorPath).nlink, 1);

    const concurrentPath = path.join(fixtureRoot, "concurrent.json");
    const concurrentTemporary = path.join(
      fixtureRoot,
      `.${path.basename(concurrentPath)}.publish-${"c".repeat(32)}`
    );
    const concurrentDescriptor = fs.openSync(
      concurrentTemporary,
      fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_EXCL,
      0o600
    );
    try {
      fs.writeFileSync(concurrentDescriptor, bytes.subarray(0, 15));
      fs.fchownSync(concurrentDescriptor, 0, 0);
      assert.equal(publish(concurrentPath).sha256, sha256(bytes));
      assert.equal(fs.existsSync(concurrentTemporary), true);
      assert.equal(fs.fstatSync(concurrentDescriptor).nlink, 1);
    } finally {
      fs.closeSync(concurrentDescriptor);
      fs.unlinkSync(concurrentTemporary);
    }

    const peerBytes = Buffer.from("peer-owned-temporary\n");
    const collisionPath = path.join(fixtureRoot, "temporary-collision.json");
    let collisionTemporary;
    let collisionIdentity;
    assert.throws(() => publish(collisionPath,
      injectedFileSystem("openSync", {
        occurrence: Number.MAX_SAFE_INTEGER,
        beforeCall({ args, calls }) {
          if (calls !== 1) return;
          [collisionTemporary] = args;
          const descriptor = fs.openSync(
            collisionTemporary,
            fs.constants.O_WRONLY | fs.constants.O_CREAT |
              fs.constants.O_EXCL | fs.constants.O_NOFOLLOW,
            0o600
          );
          try {
            fs.writeFileSync(descriptor, peerBytes);
            fs.fchownSync(descriptor, 0, 0);
            fs.fchmodSync(descriptor, 0o600);
            fs.fsyncSync(descriptor);
            collisionIdentity = fs.fstatSync(descriptor);
          } finally { fs.closeSync(descriptor); }
        }
      })), /INTEGRATED_LIVE_DRILL_STAGE_INSTALL_REJECTED/u);
    assert.equal(fs.existsSync(collisionPath), false);
    const collisionAfter = fs.lstatSync(collisionTemporary);
    assert.equal(collisionAfter.dev, collisionIdentity.dev);
    assert.equal(collisionAfter.ino, collisionIdentity.ino);
    assert.equal(collisionAfter.nlink, 1);
    assert.equal(collisionAfter.uid, 0);
    assert.equal(collisionAfter.gid, 0);
    assert.equal(collisionAfter.mode & 0o777, 0o600);
    assert.equal(fs.readFileSync(collisionTemporary).equals(peerBytes), true);
    fs.unlinkSync(collisionTemporary);
    assert.equal(publish(collisionPath).sha256, sha256(bytes));

    const substitutionPath = path.join(
      fixtureRoot,
      "temporary-substitution.json"
    );
    let substitutionTemporary;
    let replacementIdentity;
    assert.throws(() => publish(substitutionPath,
      injectedFileSystem("writeSync", {
        code: "EIO",
        beforeFailure() {
          const prefix = `.${path.basename(substitutionPath)}.publish-`;
          const names = fs.readdirSync(fixtureRoot)
            .filter((name) => name.startsWith(prefix));
          assert.equal(names.length, 1);
          substitutionTemporary = path.join(fixtureRoot, names[0]);
          fs.unlinkSync(substitutionTemporary);
          const descriptor = fs.openSync(
            substitutionTemporary,
            fs.constants.O_WRONLY | fs.constants.O_CREAT |
              fs.constants.O_EXCL | fs.constants.O_NOFOLLOW,
            0o600
          );
          try {
            fs.writeFileSync(descriptor, peerBytes);
            fs.fchownSync(descriptor, 0, 0);
            fs.fchmodSync(descriptor, 0o600);
            fs.fsyncSync(descriptor);
            replacementIdentity = fs.fstatSync(descriptor);
          } finally { fs.closeSync(descriptor); }
        }
      })), /INTEGRATED_LIVE_DRILL_STAGE_INSTALL_REJECTED/u);
    assert.equal(fs.existsSync(substitutionPath), false);
    const replacementAfter = fs.lstatSync(substitutionTemporary);
    assert.equal(replacementAfter.dev, replacementIdentity.dev);
    assert.equal(replacementAfter.ino, replacementIdentity.ino);
    assert.equal(replacementAfter.nlink, 1);
    assert.equal(replacementAfter.uid, 0);
    assert.equal(replacementAfter.gid, 0);
    assert.equal(replacementAfter.mode & 0o777, 0o600);
    assert.equal(
      fs.readFileSync(substitutionTemporary).equals(peerBytes),
      true
    );
    fs.unlinkSync(substitutionTemporary);
    assert.equal(publish(substitutionPath).sha256, sha256(bytes));

    const conflictPath = path.join(fixtureRoot, "conflict.json");
    writeExact(conflictPath, Buffer.from("different\n"));
    assert.throws(
      () => publish(conflictPath),
      /INTEGRATED_LIVE_DRILL_STAGE_INSTALL_REJECTED/u
    );
  } finally {
    removeRootFixture(fixtureRoot);
  }
});

test("root installer publishes one exact stage and independent non-root verification rejects drift", {
  skip: process.geteuid?.() !== 0 || process.arch !== "x64" ||
    !fs.existsSync("/usr/bin/setpriv")
}, () => {
  const fixtureRoot = createRootFixture("prooftoact-stage-regression");
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
      stateRoot: current.stateRoot,
      sysusersRoot: current.sysusersRoot,
      unitRoot: current.unitRoot,
      verifierRoot: current.verifierRoot
    }, {
      systemdReloader: () => true
    });
    assert.equal(receipt.files.length, 15);
    assert.equal(receipt.manifestSha256, current.manifestSha256);
    assert.equal(receipt.stageInstance, STAGE_INSTANCE);
    assert.equal(receipt.stageRoot, current.stageRoot);
    assert.equal(
      receipt.schemaVersion,
      "tideproof.integrated-live-drill-root-stage.v5"
    );
    assert.equal(receipt.accountRecords.length, 7);
    assert.equal(new Set(receipt.accountRecords.map(({ uid }) => uid)).size, 7);
    assert.equal(receipt.systemdSysusersExecuted, true);
    assert.equal(receipt.stateRoot, current.stateRoot);
    assert.equal(receipt.verifierRoot, current.verifierRoot);
    assert.equal(receipt.unitRoot, current.unitRoot);
    assert.equal(receipt.unitFiles.length, 14);
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
      current.stateRoot,
      current.sysusersRoot,
      current.unitRoot,
      current.verifierRoot,
      current.stageRoot,
      receipt.accountRecords[0]
    );
    assert.equal(accepted.status, 0, accepted.stderr);
    assert.equal(JSON.parse(accepted.stdout).status, "PASS");

    for (const component of COMPONENTS) {
      const launched = launchComponentAsUnprivileged(
        current.stageRoot,
        current.manifestSha256,
        component
      );
      assert.equal(launched.status, 0, `${component}: ${launched.stderr}`);
      const entry = JSON.parse(launched.stdout);
      const expectedNode = path.join(
        current.stageRoot,
        `node-${OFFICIAL_LINUX_X64_NODE_SHA256}`
      );
      const expectedNodeStat = fs.statSync(expectedNode, { bigint: true });
      assert.equal(entry.component, component);
      assert.match(entry.argv0, /^\/proc\/self\/fd\/\d+$/u);
      assert.equal(entry.execPath, expectedNode);
      assert.equal(entry.executableLink, expectedNode);
      assert.equal(entry.executableDev, String(expectedNodeStat.dev));
      assert.equal(entry.executableIno, String(expectedNodeStat.ino));
      assert.equal(
        sha256(fs.readFileSync(expectedNode)),
        OFFICIAL_LINUX_X64_NODE_SHA256
      );
    }
    const injected = launchComponentAsUnprivileged(
      current.stageRoot,
      current.manifestSha256,
      "worker",
      { environment: { OPENSSL_CONF: "/tmp/attacker-openssl.cnf" } }
    );
    assert.equal(injected.status, 126);
    assert.equal(
      injected.stderr.trim(),
      "INTEGRATED_LIVE_DRILL_RUNTIME_ENVIRONMENT_REJECTED"
    );

    const reusedReceiptPath = path.join(current.receiptRoot, "stage-2.json");
    const reused = installIntegratedLiveDrillStage({
      buildRoot: current.buildRoot,
      buildSourceRoot: current.buildSourceRoot,
      expectedBuildReceiptSha256: current.buildReceiptSha256,
      outputReceiptPath: reusedReceiptPath,
      stageRoot: current.stageRoot,
      stateRoot: current.stateRoot,
      sysusersRoot: current.sysusersRoot,
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
      current.stateRoot,
      current.sysusersRoot,
      current.unitRoot,
      current.verifierRoot,
      current.stageRoot,
      receipt.accountRecords[0]
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
      current.stateRoot,
      current.sysusersRoot,
      current.unitRoot,
      current.verifierRoot,
      current.stageRoot,
      receipt.accountRecords[0]
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
      current.stateRoot,
      current.sysusersRoot,
      current.unitRoot,
      current.verifierRoot,
      current.stageRoot,
      receipt.accountRecords[0]
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
      current.stateRoot,
      current.sysusersRoot,
      current.unitRoot,
      current.verifierRoot,
      current.stageRoot,
      receipt.accountRecords[0]
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
        stateRoot: current.stateRoot,
        sysusersRoot: current.sysusersRoot,
        unitRoot: current.unitRoot,
        verifierRoot: current.verifierRoot
      }, {
        systemdReloader: () => true
      }),
      /INTEGRATED_LIVE_DRILL_STAGE_INSTALL_REJECTED/u
    );
  } finally {
    removeRootFixture(fixtureRoot);
  }
});
