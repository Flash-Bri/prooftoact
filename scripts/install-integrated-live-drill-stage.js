import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { canonicalJson } from "../src/cloud/canonical-json.js";
import {
  validateIntegratedLiveDrillRuntimeManifest
} from "../src/cloud/integrated-live-drill-runtime.js";

export const ROOT_STAGE_RECEIPT_SCHEMA =
  "tideproof.integrated-live-drill-root-stage.v4";

const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const SAFE_NAME = /^[a-z0-9][a-z0-9.-]{0,159}$/u;
const MAX_RECEIPT_BYTES = 16 * 1024 * 1024;
const RUN_INSTANCE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[4-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const RUNTIME_COMPONENTS = Object.freeze([
  "authority-race",
  "dispatch-broker",
  "provider-operation",
  "dvi",
  "finalizer",
  "orchestrator",
  "reconciler",
  "supervisor",
  "worker"
]);
const STAGE_CONTROL_PATHS = Object.freeze([
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
const SYSTEMD_UNIT_PATHS = Object.freeze(STAGE_CONTROL_PATHS.filter(
  (controlPath) => controlPath.startsWith("infra/systemd/")
));

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function exactKeys(value, keys) {
  return value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join("\n") === [...keys].sort().join("\n");
}

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function readJsonFile(filePath, code, readFile = readNoFollowFile) {
  const opened = readFile(filePath, code);
  requireCondition(opened.bytes.length <= MAX_RECEIPT_BYTES, code);
  try {
    return Object.freeze({
      bytes: opened.bytes,
      value: JSON.parse(opened.bytes.toString("utf8"))
    });
  } catch (cause) {
    reject(code, cause);
  }
}

function readNoFollowFile(filePath, code) {
  let descriptor;
  try {
    descriptor = fs.openSync(
      filePath,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW
    );
    const before = fs.fstatSync(descriptor);
    requireCondition(
      before.isFile() && before.nlink === 1 && before.size > 0,
      code
    );
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor);
    requireCondition(
      before.dev === after.dev &&
        before.ino === after.ino &&
        before.mode === after.mode &&
        before.uid === after.uid &&
        before.gid === after.gid &&
        before.nlink === after.nlink &&
        before.size === after.size &&
        bytes.length === before.size,
      code
    );
    return Object.freeze({ bytes, stat: before });
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  } finally {
    if (Number.isSafeInteger(descriptor)) fs.closeSync(descriptor);
  }
}

function readBeneathFile(rootPath, relativePath, code) {
  requireCondition(
    process.platform === "linux" && fs.existsSync("/proc/self/fd") &&
      typeof rootPath === "string" && path.isAbsolute(rootPath) &&
      path.resolve(rootPath) === rootPath &&
      typeof relativePath === "string" && relativePath.length > 0 &&
      relativePath === path.posix.normalize(relativePath) &&
      !path.posix.isAbsolute(relativePath) &&
      !relativePath.split("/").some((part) =>
        part === "" || part === "." || part === ".."
      ),
    code
  );
  const descriptors = [];
  let fileDescriptor;
  try {
    let directoryDescriptor = fs.openSync(
      rootPath,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW |
        fs.constants.O_DIRECTORY
    );
    descriptors.push(directoryDescriptor);
    requireCondition(fs.fstatSync(directoryDescriptor).isDirectory(), code);
    const parts = relativePath.split("/");
    for (const part of parts.slice(0, -1)) {
      directoryDescriptor = fs.openSync(
        `/proc/self/fd/${directoryDescriptor}/${part}`,
        fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW |
          fs.constants.O_DIRECTORY
      );
      descriptors.push(directoryDescriptor);
      requireCondition(fs.fstatSync(directoryDescriptor).isDirectory(), code);
    }
    fileDescriptor = fs.openSync(
      `/proc/self/fd/${directoryDescriptor}/${parts.at(-1)}`,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW
    );
    const before = fs.fstatSync(fileDescriptor);
    requireCondition(
      before.isFile() && before.nlink === 1 && before.size > 0,
      code
    );
    const bytes = fs.readFileSync(fileDescriptor);
    const after = fs.fstatSync(fileDescriptor);
    requireCondition(
      before.dev === after.dev && before.ino === after.ino &&
        before.mode === after.mode && before.uid === after.uid &&
        before.gid === after.gid && before.nlink === after.nlink &&
        before.size === after.size && bytes.length === before.size,
      code
    );
    return Object.freeze({ bytes, stat: before });
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  } finally {
    if (Number.isSafeInteger(fileDescriptor)) fs.closeSync(fileDescriptor);
    for (const descriptor of descriptors.reverse()) fs.closeSync(descriptor);
  }
}

function syncDirectory(directory, code) {
  let descriptor;
  try {
    descriptor = fs.openSync(
      directory,
      fs.constants.O_RDONLY |
        fs.constants.O_NOFOLLOW |
        (fs.constants.O_DIRECTORY ?? 0)
    );
    requireCondition(fs.fstatSync(descriptor).isDirectory(), code);
    fs.fsyncSync(descriptor);
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  } finally {
    if (Number.isSafeInteger(descriptor)) fs.closeSync(descriptor);
  }
}

function runtimeInventory(buildReceipt) {
  const code = "INTEGRATED_LIVE_DRILL_STAGE_BUILD_RECEIPT_REJECTED";
  const runtime = buildReceipt?.liveDrillRuntime;
  requireCondition(
    buildReceipt?.mode === "CLEAN_ARTIFACT_BUILD" &&
      buildReceipt?.projectSourceMode ===
        "ISOLATED_EXACT_GIT_CHECKOUT_AND_BLOBS" &&
      HEX_40.test(buildReceipt?.sourceCommit ?? "") &&
      HEX_40.test(buildReceipt?.treeDigest ?? "") &&
      HEX_64.test(buildReceipt?.packageLockDigest ?? "") &&
      buildReceipt?.workingTreeClean === true &&
      buildReceipt?.workingTreeCleanBeforeGeneration === true &&
      HEX_64.test(runtime?.manifestSha256 ?? "") &&
      runtime?.manifestPath ===
        `dist/runtime/runtime-manifest-${runtime.manifestSha256}.json` &&
      runtime?.launcher?.path ===
        "dist/runtime/verified-node-bundle-launcher.pl" &&
      HEX_64.test(runtime?.launcher?.sha256 ?? "") &&
      typeof runtime?.node?.path === "string" &&
      runtime.node.path === `dist/runtime/node-${runtime.node.sha256}` &&
      HEX_64.test(runtime.node.sha256 ?? "") &&
      runtime?.components &&
      typeof runtime.components === "object" &&
      !Array.isArray(runtime.components) &&
      exactKeys(runtime.components, RUNTIME_COMPONENTS),
    code
  );
  const records = [
    {
      mode: 0o444,
      name: path.posix.basename(runtime.manifestPath),
      path: runtime.manifestPath,
      sha256: runtime.manifestSha256
    },
    {
      mode: 0o555,
      name: path.posix.basename(runtime.launcher.path),
      path: runtime.launcher.path,
      sha256: runtime.launcher.sha256
    },
    {
      mode: 0o555,
      name: path.posix.basename(runtime.node.path),
      path: runtime.node.path,
      sha256: runtime.node.sha256
    },
    ...RUNTIME_COMPONENTS.map((component) => ({
      component,
      mode: 0o555,
      name: path.posix.basename(runtime.components[component]?.path ?? ""),
      path: runtime.components[component]?.path,
      sha256: runtime.components[component]?.sha256
    }))
  ];
  requireCondition(
    records.length === 12 &&
      new Set(records.map(({ name }) => name)).size === records.length &&
      records.every(({ name, path: relativePath, sha256: digest }) =>
        SAFE_NAME.test(name ?? "") &&
        typeof relativePath === "string" &&
        relativePath === `dist/runtime/${name}` &&
        HEX_64.test(digest ?? "")
      ),
    code
  );
  return Object.freeze(records.map((record) => Object.freeze(record)));
}

function assertManifestMatchesBuildReceipt(manifest, buildReceipt, code) {
  const accepted = validateIntegratedLiveDrillRuntimeManifest(manifest);
  const runtime = buildReceipt.liveDrillRuntime;
  requireCondition(
    accepted.sourceCommit === buildReceipt.sourceCommit &&
      accepted.treeDigest === buildReceipt.treeDigest &&
      accepted.packageLockDigest === buildReceipt.packageLockDigest &&
      accepted.toolchainSha256 ===
        sha256(Buffer.from(canonicalJson(buildReceipt.toolchain))) &&
      accepted.launcher.sha256 === runtime.launcher.sha256 &&
      accepted.node.sha256 === runtime.node.sha256 &&
      accepted.node.platform === runtime.node.platform &&
      accepted.node.architecture === runtime.node.architecture &&
      accepted.node.distribution === runtime.node.distribution &&
      accepted.node.version === runtime.node.version &&
      RUNTIME_COMPONENTS.every((component) =>
        accepted.components[component].sha256 ===
          runtime.components[component].sha256 &&
        runtime.components[component].path ===
          `dist/runtime/${accepted.components[component].file}`
      ),
    code
  );
  return accepted;
}

function stageControlRecords(buildReceipt, code) {
  const byPath = new Map((buildReceipt?.buildControlInputs ?? []).map(
    (record) => [record?.path, record]
  ));
  requireCondition(
    STAGE_CONTROL_PATHS.every((controlPath) => {
      const record = byPath.get(controlPath);
      return record?.path === controlPath &&
        /^[0-9a-f]{40}$/u.test(record?.gitBlobId ?? "") &&
        HEX_64.test(record?.sha256 ?? "");
    }),
    code
  );
  return Object.freeze(STAGE_CONTROL_PATHS.map((controlPath) => {
    const record = byPath.get(controlPath);
    return Object.freeze({
      gitBlobId: record.gitBlobId,
      path: record.path,
      sha256: record.sha256
    });
  }));
}

function assertRootOwnedImmutableDirectoryChain(directory, code) {
  for (let current = directory;; current = path.dirname(current)) {
    const stat = fs.lstatSync(current);
    requireCondition(
      stat.isDirectory() && !stat.isSymbolicLink() && stat.uid === 0 &&
        (stat.mode & 0o022) === 0 && fs.realpathSync(current) === current,
      code
    );
    if (path.dirname(current) === current) break;
  }
}

function ancestorRecords(stageRoot, code) {
  const records = [];
  for (let current = stageRoot;; current = path.dirname(current)) {
    const stat = fs.lstatSync(current);
    requireCondition(
      stat.isDirectory() &&
        !stat.isSymbolicLink() &&
        stat.uid === 0 &&
        (stat.mode & 0o022) === 0 &&
        fs.realpathSync(current) === current,
      code
    );
    records.push(Object.freeze({
      dev: String(stat.dev),
      gid: stat.gid,
      ino: String(stat.ino),
      mode: stat.mode & 0o7777,
      path: current,
      uid: stat.uid
    }));
    if (path.dirname(current) === current) break;
  }
  return Object.freeze(records);
}

function fileRecord(stageRoot, expected, code) {
  const filePath = path.join(stageRoot, expected.name);
  const opened = readNoFollowFile(filePath, code);
  requireCondition(
    sha256(opened.bytes) === expected.sha256 &&
      opened.stat.uid === 0 &&
      opened.stat.gid === 0 &&
      opened.stat.nlink === 1 &&
      (opened.stat.mode & 0o7777) === expected.mode,
    code
  );
  return Object.freeze({
    bytes: opened.bytes.length,
    dev: String(opened.stat.dev),
    gid: opened.stat.gid,
    ino: String(opened.stat.ino),
    mode: opened.stat.mode & 0o7777,
    name: expected.name,
    nlink: opened.stat.nlink,
    sha256: expected.sha256,
    uid: opened.stat.uid
  });
}

function observedFileRecord(filePath, expected, code) {
  const opened = readNoFollowFile(filePath, code);
  requireCondition(
    sha256(opened.bytes) === expected.sha256 && opened.stat.uid === 0 &&
      opened.stat.gid === 0 && opened.stat.nlink === 1 &&
      (opened.stat.mode & 0o7777) === expected.mode,
    code
  );
  return Object.freeze({
    bytes: opened.bytes.length,
    dev: String(opened.stat.dev),
    gid: opened.stat.gid,
    ino: String(opened.stat.ino),
    mode: opened.stat.mode & 0o7777,
    name: expected.name,
    nlink: opened.stat.nlink,
    sha256: expected.sha256,
    uid: opened.stat.uid
  });
}

function publishExactFiles({
  code,
  files,
  root,
  readSource = readNoFollowFile
}) {
  const created = [];
  try {
    for (const expected of files) {
      const destination = path.join(root, expected.name);
      if (fs.existsSync(destination)) {
        observedFileRecord(destination, expected, code);
        continue;
      }
      const temporary = path.join(
        root,
        `.${expected.name}.install-${crypto.randomBytes(16).toString("hex")}`
      );
      try {
        copyRuntimeFile({
          code,
          destination: temporary,
          expected,
          readSource,
          source: expected.source
        });
        observedFileRecord(temporary, expected, code);
        fs.linkSync(temporary, destination);
        created.push(destination);
        fs.unlinkSync(temporary);
        observedFileRecord(destination, expected, code);
        syncDirectory(root, code);
      } catch (cause) {
        try {
          if (fs.existsSync(temporary)) fs.unlinkSync(temporary);
        } catch {
          // Preserve the first failure.
        }
        throw cause;
      }
    }
  } catch (cause) {
    for (const destination of created.reverse()) {
      try {
        fs.unlinkSync(destination);
      } catch {
        // A partial unit set is never receipted. Preserve the first failure.
      }
    }
    try {
      syncDirectory(root, code);
    } catch {
      // Preserve the first failure.
    }
    if (cause?.message === code) throw cause;
    reject(code, cause);
  }
  return Object.freeze(files.map((expected) => observedFileRecord(
    path.join(root, expected.name),
    expected,
    code
  )));
}

function publishExactDirectory({
  code,
  files,
  finalRoot,
  parentRoot,
  readSource = readNoFollowFile
}) {
  const parentStat = fs.lstatSync(parentRoot);
  if (!fs.existsSync(finalRoot)) {
    const temporaryRoot = fs.mkdtempSync(
      path.join(parentRoot, `.${path.basename(finalRoot)}.install-`)
    );
    try {
      requireCondition(fs.lstatSync(temporaryRoot).dev === parentStat.dev, code);
      fs.chownSync(temporaryRoot, 0, 0);
      fs.chmodSync(temporaryRoot, 0o700);
      for (const expected of files) {
        copyRuntimeFile({
          code,
          destination: path.join(temporaryRoot, expected.name),
          expected,
          readSource,
          source: expected.source
        });
      }
      requireCondition(
        fs.readdirSync(temporaryRoot).sort().join("\n") ===
          files.map(({ name }) => name).sort().join("\n"),
        code
      );
      for (const expected of files) {
        observedFileRecord(path.join(temporaryRoot, expected.name), expected, code);
      }
      fs.chmodSync(temporaryRoot, 0o555);
      syncDirectory(temporaryRoot, code);
      syncDirectory(parentRoot, code);
      requireCondition(!fs.existsSync(finalRoot), code);
      fs.renameSync(temporaryRoot, finalRoot);
      syncDirectory(parentRoot, code);
    } catch (cause) {
      try {
        if (fs.existsSync(temporaryRoot)) {
          fs.chmodSync(temporaryRoot, 0o700);
          fs.rmSync(temporaryRoot, { force: true, recursive: true });
        }
      } catch {
        // Preserve the first failure; no incomplete pathname is authoritative.
      }
      if (cause?.message === code) throw cause;
      reject(code, cause);
    }
  }
  requireCondition(
    fs.readdirSync(finalRoot).sort().join("\n") ===
      files.map(({ name }) => name).sort().join("\n"),
    code
  );
  return Object.freeze(files.map((expected) => observedFileRecord(
    path.join(finalRoot, expected.name),
    expected,
    code
  )));
}

function copyRuntimeFile({
  source,
  destination,
  expected,
  code,
  readSource = readNoFollowFile
}) {
  const opened = readSource(source, code);
  requireCondition(sha256(opened.bytes) === expected.sha256, code);
  let descriptor;
  try {
    descriptor = fs.openSync(
      destination,
      fs.constants.O_WRONLY |
        fs.constants.O_CREAT |
        fs.constants.O_EXCL |
        fs.constants.O_NOFOLLOW,
      0o600
    );
    const created = fs.fstatSync(descriptor);
    requireCondition(
      created.isFile() && created.nlink === 1 && created.size === 0,
      code
    );
    fs.writeFileSync(descriptor, opened.bytes);
    fs.fchownSync(descriptor, 0, 0);
    fs.fchmodSync(descriptor, expected.mode);
    fs.fsyncSync(descriptor);
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  } finally {
    if (Number.isSafeInteger(descriptor)) fs.closeSync(descriptor);
  }
}

function publishAcceptedBuildReceipt({
  buildRoot,
  bytes,
  code,
  parentRoot,
  sha256: expectedSha256
}) {
  requireCondition(!fs.existsSync(buildRoot), code);
  const temporaryRoot = fs.mkdtempSync(
    path.join(parentRoot, `.${path.basename(buildRoot)}.install-`)
  );
  try {
    fs.chownSync(temporaryRoot, 0, 0);
    fs.chmodSync(temporaryRoot, 0o700);
    const expected = Object.freeze({
      mode: 0o444,
      name: "gate2-build-receipt.json",
      sha256: expectedSha256
    });
    let descriptor;
    try {
      descriptor = fs.openSync(
        path.join(temporaryRoot, expected.name),
        fs.constants.O_WRONLY | fs.constants.O_CREAT |
          fs.constants.O_EXCL | fs.constants.O_NOFOLLOW,
        0o600
      );
      fs.writeFileSync(descriptor, bytes);
      fs.fchownSync(descriptor, 0, 0);
      fs.fchmodSync(descriptor, expected.mode);
      fs.fsyncSync(descriptor);
    } finally {
      if (Number.isSafeInteger(descriptor)) fs.closeSync(descriptor);
    }
    observedFileRecord(
      path.join(temporaryRoot, expected.name),
      expected,
      code
    );
    fs.chmodSync(temporaryRoot, 0o555);
    syncDirectory(temporaryRoot, code);
    fs.renameSync(temporaryRoot, buildRoot);
    syncDirectory(parentRoot, code);
    return Object.freeze([observedFileRecord(
      path.join(buildRoot, expected.name),
      expected,
      code
    )]);
  } catch (cause) {
    try {
      if (fs.existsSync(temporaryRoot)) {
        fs.chmodSync(temporaryRoot, 0o700);
        fs.rmSync(temporaryRoot, { force: true, recursive: true });
      }
    } catch {
      // Preserve the first failure.
    }
    if (cause?.message === code) throw cause;
    reject(code, cause);
  }
}

function writeOrVerifyExactRootFile({ bytes, code, filePath, mode }) {
  const expected = Object.freeze({
    mode,
    name: path.basename(filePath),
    sha256: sha256(bytes)
  });
  if (!fs.existsSync(filePath)) {
    let descriptor;
    try {
      descriptor = fs.openSync(
        filePath,
        fs.constants.O_WRONLY | fs.constants.O_CREAT |
          fs.constants.O_EXCL | fs.constants.O_NOFOLLOW,
        0o600
      );
      fs.writeFileSync(descriptor, bytes);
      fs.fchownSync(descriptor, 0, 0);
      fs.fchmodSync(descriptor, mode);
      fs.fsyncSync(descriptor);
    } catch (cause) {
      if (cause?.message === code) throw cause;
      reject(code, cause);
    } finally {
      if (Number.isSafeInteger(descriptor)) fs.closeSync(descriptor);
    }
    syncDirectory(path.dirname(filePath), code);
  }
  return observedFileRecord(filePath, expected, code);
}

function reloadSystemdManager(code) {
  const executable = "/usr/bin/systemctl";
  const stat = fs.lstatSync(executable);
  requireCondition(
    stat.isFile() && !stat.isSymbolicLink() && stat.uid === 0 &&
      (stat.mode & 0o022) === 0,
    code
  );
  const result = spawnSync(executable, ["daemon-reload"], {
    encoding: "utf8",
    env: { LANG: "C.UTF-8", LC_ALL: "C.UTF-8", PATH: "/usr/bin:/bin" },
    stdio: ["ignore", "ignore", "ignore"]
  });
  requireCondition(!result.error && result.status === 0, code);
  return true;
}

export function installIntegratedLiveDrillStage({
  buildRoot,
  buildSourceRoot,
  expectedBuildReceiptSha256,
  outputReceiptPath,
  stageRoot,
  unitRoot,
  verifierRoot
}, { systemdReloader = reloadSystemdManager } = {}) {
  const code = "INTEGRATED_LIVE_DRILL_STAGE_INSTALL_REJECTED";
  const stageParent = typeof stageRoot === "string"
    ? path.dirname(stageRoot)
    : null;
  requireCondition(
    typeof process.geteuid === "function" && process.geteuid() === 0 &&
      [buildRoot, buildSourceRoot, outputReceiptPath, stageRoot, unitRoot,
        verifierRoot]
        .every(
        (candidate) =>
          typeof candidate === "string" &&
          path.isAbsolute(candidate) &&
          path.resolve(candidate) === candidate
      ) &&
      HEX_64.test(expectedBuildReceiptSha256 ?? "") &&
      typeof stageParent === "string" &&
      RUN_INSTANCE.test(path.basename(stageRoot)) &&
      path.basename(verifierRoot) === path.basename(stageRoot) &&
      path.dirname(outputReceiptPath) !== stageParent &&
      path.dirname(outputReceiptPath) !== stageRoot &&
      path.dirname(outputReceiptPath) !== verifierRoot &&
      stageRoot !== verifierRoot && unitRoot !== stageRoot &&
      unitRoot !== verifierRoot && typeof systemdReloader === "function",
    code
  );
  const readBuildSource = (relativePath, failureCode) => readBeneathFile(
    buildSourceRoot,
    relativePath,
    failureCode
  );
  const build = readJsonFile(
    "gate2-build-receipt.json",
    code,
    readBuildSource
  );
  requireCondition(sha256(build.bytes) === expectedBuildReceiptSha256, code);
  const buildReceipt = build.value;
  const inventory = runtimeInventory(buildReceipt);
  const stageControls = stageControlRecords(buildReceipt, code);
  const manifestRecord = inventory[0];
  const manifestSource = manifestRecord.path;
  const manifest = JSON.parse(
    readBuildSource(manifestSource, code).bytes.toString("utf8")
  );
  requireCondition(
    assertManifestMatchesBuildReceipt(manifest, buildReceipt, code),
    code
  );
  assertRootOwnedImmutableDirectoryChain(stageParent, code);
  const verifierParent = path.dirname(verifierRoot);
  assertRootOwnedImmutableDirectoryChain(verifierParent, code);
  assertRootOwnedImmutableDirectoryChain(unitRoot, code);
  const buildParent = path.dirname(buildRoot);
  assertRootOwnedImmutableDirectoryChain(buildParent, code);
  if (fs.existsSync(buildRoot)) {
    assertRootOwnedImmutableDirectoryChain(buildRoot, code);
  }
  assertRootOwnedImmutableDirectoryChain(path.dirname(outputReceiptPath), code);
  const finalRoot = stageRoot;
  const runtimeFiles = inventory.map((expected) => {
    return Object.freeze({ ...expected, source: expected.path });
  });
  const buildFiles = fs.existsSync(buildRoot)
    ? (() => {
      requireCondition(
        fs.readdirSync(buildRoot).join("\n") ===
          "gate2-build-receipt.json",
        code
      );
      return Object.freeze([observedFileRecord(
        path.join(buildRoot, "gate2-build-receipt.json"),
        {
          mode: 0o444,
          name: "gate2-build-receipt.json",
          sha256: expectedBuildReceiptSha256
        },
        code
      )]);
    })()
    : publishAcceptedBuildReceipt({
      buildRoot,
      bytes: build.bytes,
      code,
      parentRoot: buildParent,
      sha256: expectedBuildReceiptSha256
    });
  const files = publishExactDirectory({
    code,
    files: runtimeFiles,
    finalRoot,
    parentRoot: stageParent,
    readSource: readBuildSource
  });
  const verifierControl = stageControls.find(({ path: controlPath }) =>
    controlPath === "scripts/verify-integrated-live-drill-stage.js"
  );
  const verifierFiles = publishExactDirectory({
    code,
    files: [
      Object.freeze({
        mode: 0o555,
        name: "node",
        sha256: buildReceipt.liveDrillRuntime.node.sha256,
        source: buildReceipt.liveDrillRuntime.node.path
      }),
      Object.freeze({
        mode: 0o444,
        name: "verify-integrated-live-drill-stage.js",
        sha256: verifierControl.sha256,
        source: "scripts/verify-integrated-live-drill-stage.js"
      })
    ],
    finalRoot: verifierRoot,
    parentRoot: verifierParent,
    readSource: readBuildSource
  });
  const stageControlsByPath = new Map(stageControls.map((record) => [
    record.path,
    record
  ]));
  const unitFiles = publishExactFiles({
    code,
    files: SYSTEMD_UNIT_PATHS.map((controlPath) => {
      const control = stageControlsByPath.get(controlPath);
      return Object.freeze({
        mode: 0o444,
        name: path.posix.basename(controlPath),
        sha256: control.sha256,
        source: controlPath
      });
    }),
    root: unitRoot,
    readSource: readBuildSource
  });
  const unitNames = new Set(unitFiles.map(({ name }) => name));
  requireCondition(
    fs.readdirSync(unitRoot).filter((name) => name.startsWith(
      "prooftoact-integrated-live-drill"
    )).every((name) => unitNames.has(name)),
    code
  );
  const acceptedBuildReceiptSha256Path = path.join(
    path.dirname(outputReceiptPath),
    "accepted-build-receipt-sha256"
  );
  const acceptedBuildReceiptSha256File = writeOrVerifyExactRootFile({
    bytes: Buffer.from(`${expectedBuildReceiptSha256}\n`, "utf8"),
    code,
    filePath: acceptedBuildReceiptSha256Path,
    mode: 0o444
  });
  requireCondition(systemdReloader(code) === true, code);
  const body = Object.freeze({
    schemaVersion: ROOT_STAGE_RECEIPT_SCHEMA,
    acceptedBuildReceiptSha256File,
    acceptedBuildReceiptSha256Path,
    buildAncestors: ancestorRecords(buildRoot, code),
    buildFiles,
    buildRoot,
    buildReceiptSha256: sha256(build.bytes),
    files,
    manifestSha256: manifestRecord.sha256,
    packageLockDigest: buildReceipt.packageLockDigest,
    sourceCommit: buildReceipt.sourceCommit,
    stageControls,
    stageInstance: path.basename(finalRoot),
    stageAncestors: ancestorRecords(finalRoot, code),
    stageRoot: finalRoot,
    unitAncestors: ancestorRecords(unitRoot, code),
    unitFiles,
    unitRoot,
    systemdDaemonReloaded: true,
    verifierAncestors: ancestorRecords(verifierRoot, code),
    verifierFiles,
    verifierRoot,
    toolchainSha256: sha256(Buffer.from(canonicalJson(buildReceipt.toolchain))),
    treeDigest: buildReceipt.treeDigest
  });
  const receipt = Object.freeze({
    ...body,
    receiptSha256: sha256(Buffer.from(canonicalJson(body)))
  });
  requireCondition(
    !fs.existsSync(outputReceiptPath) &&
      path.dirname(outputReceiptPath) !== finalRoot,
    code
  );
  let receiptDescriptor;
  try {
    receiptDescriptor = fs.openSync(
      outputReceiptPath,
      fs.constants.O_WRONLY |
        fs.constants.O_CREAT |
      fs.constants.O_EXCL |
      fs.constants.O_NOFOLLOW,
      0o444
    );
    fs.writeFileSync(
      receiptDescriptor,
      Buffer.from(`${canonicalJson(receipt)}\n`, "utf8")
    );
    fs.fchownSync(receiptDescriptor, 0, 0);
    fs.fchmodSync(receiptDescriptor, 0o444);
    fs.fsyncSync(receiptDescriptor);
  } catch (cause) {
    reject(code, cause);
  } finally {
    if (Number.isSafeInteger(receiptDescriptor)) {
      fs.closeSync(receiptDescriptor);
    }
  }
  syncDirectory(path.dirname(outputReceiptPath), code);
  return receipt;
}

function parseArguments(argv) {
  requireCondition(argv.length === 14, "INTEGRATED_LIVE_DRILL_STAGE_ARGUMENTS");
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    requireCondition(
      [
        "--build-root", "--build-source-root",
        "--expected-build-receipt-sha256",
        "--output-receipt", "--stage-root", "--unit-root", "--verifier-root"
      ].includes(name) &&
        !Object.hasOwn(values, name),
      "INTEGRATED_LIVE_DRILL_STAGE_ARGUMENTS"
    );
    values[name] = name === "--expected-build-receipt-sha256"
      ? argv[index + 1]
      : path.resolve(argv[index + 1]);
  }
  return Object.freeze({
    buildRoot: values["--build-root"],
    buildSourceRoot: values["--build-source-root"],
    expectedBuildReceiptSha256:
      values["--expected-build-receipt-sha256"],
    outputReceiptPath: values["--output-receipt"],
    stageRoot: values["--stage-root"],
    unitRoot: values["--unit-root"],
    verifierRoot: values["--verifier-root"]
  });
}

const startedDirectly =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (startedDirectly) {
  try {
    process.stdout.write(
      `${canonicalJson(installIntegratedLiveDrillStage(
        parseArguments(process.argv.slice(2))
      ))}\n`
    );
  } catch (error) {
    const code = /^INTEGRATED_LIVE_DRILL_STAGE_[A-Z0-9_]{1,100}$/u.test(
      String(error?.message ?? "")
    ) ? error.message : "INTEGRATED_LIVE_DRILL_STAGE_UNKNOWN";
    process.stderr.write(`${code}\n`);
    process.exitCode = 1;
  }
}

export const __test = Object.freeze({ runtimeInventory, stageControlRecords });
