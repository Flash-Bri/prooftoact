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
  "tideproof.integrated-live-drill-root-stage.v5";

const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const SAFE_NAME = /^[a-z0-9][a-z0-9.-]{0,159}$/u;
const MAX_RECEIPT_BYTES = 16 * 1024 * 1024;
const RUN_INSTANCE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[4-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SYSUSERS_CONTROL_PATH = "infra/sysusers.d/prooftoact.conf";
const SYSTEMD_SYSUSERS = "/usr/bin/systemd-sysusers";
const GETENT = "/usr/bin/getent";
const ID = "/usr/bin/id";
const PASSWD = "/usr/bin/passwd";
const SERVICE_ACCOUNTS = Object.freeze([
  Object.freeze({ name: "prooftoact", description: "ProofToAct runtime" }),
  Object.freeze({ name: "prooftoact-broker", description: "ProofToAct dispatch broker" }),
  Object.freeze({ name: "prooftoact-operation", description: "ProofToAct provider operation broker" }),
  Object.freeze({ name: "prooftoact-activate", description: "ProofToAct provider activation gate" }),
  Object.freeze({ name: "prooftoact-provider", description: "ProofToAct provider exchange" }),
  Object.freeze({ name: "prooftoact-terminalize", description: "ProofToAct provider terminalizer" }),
  Object.freeze({ name: "prooftoact-reconcile", description: "ProofToAct resolver" })
]);
const EXACT_SYSUSERS_CONFIG = `${SERVICE_ACCOUNTS.map(({ name, description }) =>
  `u ${name} - ${JSON.stringify(description)} / /usr/sbin/nologin`
).join("\n")}\n`;
const RUNTIME_COMPONENTS = Object.freeze([
  "authority-race",
  "dispatch-broker",
  "provider-activation",
  "provider-exchange",
  "provider-operation",
  "provider-terminalizer",
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
  "infra/systemd/prooftoact-integrated-live-drill-provider-activation@.service",
  "infra/systemd/prooftoact-integrated-live-drill-provider-activation@.socket",
  "infra/systemd/prooftoact-integrated-live-drill-provider-callback@.socket",
  "infra/systemd/prooftoact-integrated-live-drill-provider-exchange@.service",
  "infra/systemd/prooftoact-integrated-live-drill-provider-terminalizer@.service",
  "infra/systemd/prooftoact-integrated-live-drill-provider-terminalizer@.timer",
  "infra/systemd/prooftoact-integrated-live-drill-reconcile@.service",
  SYSUSERS_CONTROL_PATH,
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

function syncDirectory(directory, code, fileSystem = fs) {
  let descriptor;
  try {
    descriptor = fileSystem.openSync(
      directory,
      fileSystem.constants.O_RDONLY |
        fileSystem.constants.O_NOFOLLOW |
        (fileSystem.constants.O_DIRECTORY ?? 0)
    );
    requireCondition(fileSystem.fstatSync(descriptor).isDirectory(), code);
    fileSystem.fsyncSync(descriptor);
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  } finally {
    if (Number.isSafeInteger(descriptor)) fileSystem.closeSync(descriptor);
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
    records.length === 15 &&
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

function publicationTemporaryPrefix(filePath) {
  return `.${path.basename(filePath)}.publish-`;
}

function unlinkPublishedTemporaryIfPresent(temporary, fileSystem = fs) {
  try {
    fileSystem.unlinkSync(temporary);
  } catch (cause) {
    if (cause?.code !== "ENOENT") throw cause;
  }
}

function removePublishedTemporaryLinks(filePath, fileSystem = fs) {
  const parent = path.dirname(filePath);
  const finalStat = fileSystem.existsSync(filePath)
    ? fileSystem.lstatSync(filePath)
    : null;
  if (!finalStat?.isFile() || finalStat.isSymbolicLink()) return;
  const prefix = publicationTemporaryPrefix(filePath);
  for (const name of fileSystem.readdirSync(parent)) {
    if (!name.startsWith(prefix) ||
      !/^[0-9a-f]{32}$/u.test(name.slice(prefix.length))) continue;
    const temporary = path.join(parent, name);
    let temporaryStat;
    try {
      temporaryStat = fileSystem.lstatSync(temporary);
    } catch (cause) {
      if (cause?.code === "ENOENT") continue;
      throw cause;
    }
    const isPublishedLink = temporaryStat.dev === finalStat.dev &&
      temporaryStat.ino === finalStat.ino;
    if (temporaryStat.isFile() && !temporaryStat.isSymbolicLink() &&
      temporaryStat.uid === 0 && temporaryStat.gid === 0 &&
      temporaryStat.nlink === 2 && isPublishedLink) {
      unlinkPublishedTemporaryIfPresent(temporary, fileSystem);
    }
  }
}

function writeAllToDescriptor(descriptor, bytes, code, fileSystem = fs) {
  let offset = 0;
  while (offset < bytes.length) {
    const written = fileSystem.writeSync(
      descriptor,
      bytes,
      offset,
      bytes.length - offset,
      offset
    );
    requireCondition(Number.isSafeInteger(written) && written > 0, code);
    offset += written;
  }
}

function readDescriptorBytes(descriptor, length, code, fileSystem = fs) {
  const bytes = Buffer.alloc(length);
  let offset = 0;
  while (offset < length) {
    const count = fileSystem.readSync(
      descriptor,
      bytes,
      offset,
      length - offset,
      offset
    );
    requireCondition(Number.isSafeInteger(count) && count > 0, code);
    offset += count;
  }
  return bytes;
}

function publishOrVerifyExactRootFile({
  bytes,
  code,
  filePath,
  fileSystem = fs,
  mode
}) {
  const expected = Object.freeze({
    mode,
    name: path.basename(filePath),
    sha256: sha256(bytes)
  });
  const parent = path.dirname(filePath);
  if (fileSystem.existsSync(filePath)) {
    try {
      removePublishedTemporaryLinks(filePath, fileSystem);
      const observed = observedFileRecord(filePath, expected, code);
      syncDirectory(parent, code, fileSystem);
      return observed;
    } catch (cause) {
      if (cause?.message === code) throw cause;
      reject(code, cause);
    }
  }
  const temporary = path.join(
    parent,
    `${publicationTemporaryPrefix(filePath)}` +
      crypto.randomBytes(16).toString("hex")
  );
  let descriptor;
  let openedIdentity;
  let published = false;
  let observed;
  let publicationComplete = false;
  let primaryCause;
  try {
    descriptor = fileSystem.openSync(
      temporary,
      fileSystem.constants.O_RDWR | fileSystem.constants.O_CREAT |
        fileSystem.constants.O_EXCL | fileSystem.constants.O_NOFOLLOW,
      0o600
    );
    const created = fileSystem.fstatSync(descriptor);
    openedIdentity = Object.freeze({ dev: created.dev, ino: created.ino });
    requireCondition(
      created.isFile() && created.nlink === 1 && created.size === 0,
      code
    );
    writeAllToDescriptor(descriptor, bytes, code, fileSystem);
    fileSystem.fchownSync(descriptor, 0, 0);
    fileSystem.fchmodSync(descriptor, mode);
    fileSystem.fsyncSync(descriptor);
    const settled = fileSystem.fstatSync(descriptor);
    requireCondition(
      settled.isFile() && settled.nlink === 1 && settled.uid === 0 &&
        settled.gid === 0 && (settled.mode & 0o7777) === mode &&
        settled.size === bytes.length &&
        readDescriptorBytes(descriptor, bytes.length, code, fileSystem)
          .equals(bytes),
      code
    );
    const namedTemporary = fileSystem.lstatSync(temporary);
    requireCondition(
      namedTemporary.isFile() && !namedTemporary.isSymbolicLink() &&
        namedTemporary.dev === settled.dev && namedTemporary.ino === settled.ino &&
        namedTemporary.nlink === 1 && namedTemporary.uid === settled.uid &&
        namedTemporary.gid === settled.gid &&
        namedTemporary.mode === settled.mode &&
        namedTemporary.size === settled.size,
      code
    );
    fileSystem.linkSync(temporary, filePath);
    published = true;
    const namedFinal = fileSystem.lstatSync(filePath);
    const linkedTemporary = fileSystem.lstatSync(temporary);
    requireCondition(
      namedFinal.isFile() && !namedFinal.isSymbolicLink() &&
        namedFinal.dev === settled.dev && namedFinal.ino === settled.ino &&
        linkedTemporary.dev === settled.dev &&
        linkedTemporary.ino === settled.ino &&
        namedFinal.nlink === 2 && linkedTemporary.nlink === 2,
      code
    );
    unlinkPublishedTemporaryIfPresent(temporary, fileSystem);
    observed = observedFileRecord(filePath, expected, code);
    syncDirectory(parent, code, fileSystem);
    publicationComplete = true;
  } catch (cause) {
    primaryCause = cause;
  } finally {
    if (Number.isSafeInteger(descriptor)) {
      try {
        fileSystem.closeSync(descriptor);
      } catch (cause) {
        primaryCause ??= cause;
      }
    }
    try {
      if (openedIdentity !== undefined && fileSystem.existsSync(temporary)) {
        const namedTemporary = fileSystem.lstatSync(temporary);
        const namedFinal = fileSystem.existsSync(filePath)
          ? fileSystem.lstatSync(filePath)
          : null;
        if (
          namedTemporary.isFile() && !namedTemporary.isSymbolicLink() &&
          namedTemporary.dev === openedIdentity.dev &&
          namedTemporary.ino === openedIdentity.ino &&
          namedTemporary.uid === 0 && namedTemporary.gid === 0 &&
          (namedTemporary.nlink === 1 ||
            namedTemporary.nlink === 2 &&
              namedFinal?.dev === namedTemporary.dev &&
              namedFinal?.ino === namedTemporary.ino)
        ) unlinkPublishedTemporaryIfPresent(temporary, fileSystem);
      }
    } catch (cause) {
      primaryCause ??= cause;
    }
  }
  if (publicationComplete && primaryCause === undefined) return observed;
  if (published || fileSystem.existsSync(filePath)) {
    try {
      removePublishedTemporaryLinks(filePath, fileSystem);
      const observed = observedFileRecord(filePath, expected, code);
      syncDirectory(parent, code, fileSystem);
      return observed;
    } catch (cause) {
      primaryCause ??= cause;
    }
  }
  if (primaryCause?.message === code) throw primaryCause;
  reject(code, primaryCause);
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

function assertTrustedExecutable(executable, code) {
  const stat = fs.lstatSync(executable);
  requireCondition(
    stat.isFile() && !stat.isSymbolicLink() && stat.uid === 0 &&
      stat.gid === 0 && (stat.mode & 0o022) === 0,
    code
  );
}

function runBounded(executable, argumentsList, code) {
  assertTrustedExecutable(executable, code);
  const result = spawnSync(executable, argumentsList, {
    encoding: "utf8",
    env: { LANG: "C.UTF-8", LC_ALL: "C.UTF-8", PATH: "/usr/bin:/bin" },
    maxBuffer: 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"]
  });
  requireCondition(
    !result.error && result.signal === null && result.status === 0 &&
      typeof result.stdout === "string" && typeof result.stderr === "string",
    code
  );
  return result.stdout;
}

function parsePasswdLine(line, code) {
  const fields = line.trimEnd().split(":");
  requireCondition(fields.length === 7, code);
  const [name, , uidText, gidText, description, home, shell] = fields;
  const uid = Number(uidText);
  const gid = Number(gidText);
  requireCondition(
    Number.isSafeInteger(uid) && uid >= 0 && Number.isSafeInteger(gid) && gid >= 0,
    code
  );
  return Object.freeze({ description, gid, home, name, shell, uid });
}

function parseGroupLine(line, code) {
  const fields = line.trimEnd().split(":");
  requireCondition(fields.length === 4, code);
  const [name, , gidText, membersText] = fields;
  const gid = Number(gidText);
  requireCondition(Number.isSafeInteger(gid) && gid >= 0, code);
  return Object.freeze({
    gid,
    members: membersText === "" ? [] : membersText.split(","),
    name
  });
}

function enumerateAccountDatabase(code) {
  const passwdLines = runBounded(GETENT, ["passwd"], code)
    .split("\n").filter(Boolean).map((line) => parsePasswdLine(line, code));
  const groupLines = runBounded(GETENT, ["group"], code)
    .split("\n").filter(Boolean).map((line) => parseGroupLine(line, code));
  const byName = new Map(passwdLines.map((record) => [record.name, record]));
  const groupsByName = new Map(groupLines.map((record) => [record.name, record]));
  const records = [];
  for (const expected of SERVICE_ACCOUNTS) {
    const account = byName.get(expected.name);
    const group = groupsByName.get(expected.name);
    if (account === undefined && group === undefined) continue;
    requireCondition(account !== undefined && group !== undefined, code);
    const supplementaryGids = runBounded(ID, ["-G", expected.name], code)
      .trim().split(/\s+/u).filter(Boolean).map(Number);
    const passwordStatus = runBounded(PASSWD, ["-S", expected.name], code)
      .trim().split(/\s+/u);
    requireCondition(
      account.description === expected.description && account.home === "/" &&
        account.shell === "/usr/sbin/nologin" && account.gid === group.gid &&
        group.members.length === 0 && supplementaryGids.length === 1 &&
        supplementaryGids[0] === group.gid &&
        passwordStatus[0] === expected.name &&
        ["L", "LK"].includes(passwordStatus[1]) &&
        passwdLines.filter(({ uid }) => uid === account.uid).length === 1 &&
        groupLines.filter(({ gid }) => gid === group.gid).length === 1,
      code
    );
    records.push(Object.freeze({
      description: account.description,
      gid: group.gid,
      group: group.name,
      home: account.home,
      name: account.name,
      passwordLocked: true,
      shell: account.shell,
      supplementaryGids: Object.freeze([]),
      uid: account.uid
    }));
  }
  requireCondition(
    new Set(records.map(({ uid }) => uid)).size === records.length &&
      new Set(records.map(({ gid }) => gid)).size === records.length,
    code
  );
  return Object.freeze(records);
}

function runSystemdSysusers(configPath, code) {
  runBounded(SYSTEMD_SYSUSERS, [configPath], code);
  return true;
}

function validateAccountRecords(value, code, { complete }) {
  requireCondition(Array.isArray(value), code);
  const expectedNames = complete
    ? SERVICE_ACCOUNTS.map(({ name }) => name)
    : value.map(({ name }) => name);
  requireCondition(
    value.length <= SERVICE_ACCOUNTS.length &&
      (!complete || value.length === SERVICE_ACCOUNTS.length) &&
      value.map(({ name }) => name).join("\n") === expectedNames.join("\n") &&
      value.every((record, index) => {
        const expected = SERVICE_ACCOUNTS[index];
        return exactKeys(record, [
          "description", "gid", "group", "home", "name",
          "passwordLocked", "shell", "supplementaryGids", "uid"
        ]) && record.name === expected?.name &&
          record.description === expected.description &&
          record.group === expected.name && record.home === "/" &&
          record.shell === "/usr/sbin/nologin" &&
          record.passwordLocked === true &&
          Array.isArray(record.supplementaryGids) &&
          record.supplementaryGids.length === 0 &&
          Number.isSafeInteger(record.uid) && record.uid > 0 &&
          Number.isSafeInteger(record.gid) && record.gid > 0;
      }) &&
      new Set(value.map(({ uid }) => uid)).size === value.length &&
      new Set(value.map(({ gid }) => gid)).size === value.length,
    code
  );
  return Object.freeze(value.map((record) => Object.freeze({ ...record })));
}

function statePlan(stateRoot, instance, accounts) {
  const ids = Object.fromEntries(accounts.map((record) => [record.name, record]));
  const root = { uid: 0, gid: 0 };
  const runtime = ids.prooftoact;
  const broker = ids["prooftoact-broker"];
  const operation = ids["prooftoact-operation"];
  const activate = ids["prooftoact-activate"];
  const provider = ids["prooftoact-provider"];
  return Object.freeze([
    { path: stateRoot, mode: 0o755, role: "STATE_ROOT", ...root },
    ...["evidence", "authorization", "dispatch-broker", "executions",
      "reconciliation-inputs", "provider-activations",
      "provider-operations", "provider-exchanges"].map((name) => ({
      path: path.join(stateRoot, name), mode: 0o755, role: "CATEGORY", ...root
    })),
    ...["evidence", "authorization"].flatMap((name) => [
      { path: path.join(stateRoot, name, instance), mode: 0o700,
        role: "PRIVATE_GUARD", ...runtime },
      { path: path.join(stateRoot, name, instance, "root"), mode: 0o700,
        role: "PRIVATE_ROOT", ...runtime }
    ]),
    ...["dispatch-broker", "executions", "reconciliation-inputs"].map((name) => ({
      path: path.join(stateRoot, name, instance), mode: 0o700,
      role: "BROKER_ROOT", ...broker
    })),
    { path: path.join(stateRoot, "provider-activations", instance), mode: 0o700,
      role: "ACTIVATION_ROOT", ...activate },
    { path: path.join(stateRoot, "provider-operations", instance), mode: 0o700,
      role: "PROVIDER_OPERATION_ROOT", ...operation },
    { path: path.join(stateRoot, "provider-exchanges", instance), mode: 0o700,
      role: "PROVIDER_EXCHANGE_ROOT", ...provider }
  ]);
}

function preparePersistentState({ accounts, code, instance, stateRoot }) {
  const parent = path.dirname(stateRoot);
  assertRootOwnedImmutableDirectoryChain(parent, code);
  const plan = statePlan(stateRoot, instance, accounts);
  const preparedIdentities = new Map();
  const records = [];
  for (const expected of plan) {
    let prepared;
    try {
      prepared = fs.lstatSync(expected.path);
    } catch (cause) {
      requireCondition(cause?.code === "ENOENT", code);
      fs.mkdirSync(expected.path, { mode: 0o700 });
      fs.chownSync(expected.path, expected.uid, expected.gid);
      fs.chmodSync(expected.path, expected.mode);
      syncDirectory(path.dirname(expected.path), code);
      prepared = fs.lstatSync(expected.path);
    }
    requireCondition(
      prepared.isDirectory() && !prepared.isSymbolicLink() &&
        prepared.uid === expected.uid && prepared.gid === expected.gid &&
        (prepared.mode & 0o7777) === expected.mode,
      code
    );
    if (expected.role === "PRIVATE_GUARD") {
      const entries = fs.readdirSync(expected.path).sort();
      requireCondition(
        entries.length === 0 || entries.join("\n") === "root",
        code
      );
    }
    preparedIdentities.set(expected.path, Object.freeze({
      dev: prepared.dev,
      ino: prepared.ino
    }));
  }
  for (const expected of plan) {
    const prepared = preparedIdentities.get(expected.path);
    const before = fs.lstatSync(expected.path);
    requireCondition(
      before.isDirectory() && !before.isSymbolicLink() &&
        before.uid === expected.uid && before.gid === expected.gid &&
        (before.mode & 0o7777) === expected.mode &&
        before.dev === prepared?.dev && before.ino === prepared?.ino,
      code
    );
    const entries = expected.role === "PRIVATE_GUARD"
      ? fs.readdirSync(expected.path).sort()
      : null;
    if (entries !== null) requireCondition(entries.join("\n") === "root", code);
    const after = fs.lstatSync(expected.path);
    requireCondition(before.dev === after.dev && before.ino === after.ino, code);
    records.push(Object.freeze({
      dev: String(before.dev), entries, gid: before.gid,
      ino: String(before.ino), mode: before.mode & 0o7777,
      path: expected.path, role: expected.role, uid: before.uid
    }));
  }
  return Object.freeze(records.slice(1));
}

export function installIntegratedLiveDrillStage({
  buildRoot,
  buildSourceRoot,
  expectedBuildReceiptSha256,
  outputReceiptPath,
  stageRoot,
  stateRoot,
  sysusersRoot,
  unitRoot,
  verifierRoot
}, {
  accountCensus = enumerateAccountDatabase,
  publicationFileSystem = fs,
  statePreparer = preparePersistentState,
  sysusersRunner = runSystemdSysusers,
  systemdReloader = reloadSystemdManager
} = {}) {
  const code = "INTEGRATED_LIVE_DRILL_STAGE_INSTALL_REJECTED";
  const stageParent = typeof stageRoot === "string"
    ? path.dirname(stageRoot)
    : null;
  requireCondition(
    typeof process.geteuid === "function" && process.geteuid() === 0 &&
      [buildRoot, buildSourceRoot, outputReceiptPath, stageRoot, stateRoot,
        sysusersRoot, unitRoot, verifierRoot]
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
      unitRoot !== verifierRoot && stateRoot !== stageRoot &&
      path.basename(stateRoot) === "prooftoact" &&
      typeof accountCensus === "function" &&
      typeof statePreparer === "function" &&
      typeof sysusersRunner === "function" &&
      typeof systemdReloader === "function" &&
      publicationFileSystem &&
      typeof publicationFileSystem.openSync === "function",
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
  const sysusersControl = stageControls.find(({ path: controlPath }) =>
    controlPath === SYSUSERS_CONTROL_PATH
  );
  const sysusersSource = readBuildSource(SYSUSERS_CONTROL_PATH, code);
  requireCondition(
    sysusersSource.bytes.toString("utf8") === EXACT_SYSUSERS_CONFIG &&
      sha256(sysusersSource.bytes) === sysusersControl?.sha256,
    code
  );
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
  assertRootOwnedImmutableDirectoryChain(sysusersRoot, code);
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
  const preflightAccounts = validateAccountRecords(accountCensus(code), code, {
    complete: accountCensus === enumerateAccountDatabase
      ? accountCensus(code).length !== 0
      : accountCensus(code).length !== 0
  });
  requireCondition(
    preflightAccounts.length === 0 ||
      preflightAccounts.length === SERVICE_ACCOUNTS.length,
    code
  );
  const configPath = path.join(sysusersRoot, "prooftoact.conf");
  const shadowRoots = ["/run/sysusers.d", "/usr/lib/sysusers.d"]
    .filter((candidate) => candidate !== sysusersRoot);
  requireCondition(
    shadowRoots.every((root) =>
      !fs.existsSync(path.join(root, "prooftoact.conf"))
    ),
    code
  );
  const accountConfigFile = publishOrVerifyExactRootFile({
    bytes: sysusersSource.bytes,
    code,
    filePath: configPath,
    fileSystem: publicationFileSystem,
    mode: 0o444
  });
  requireCondition(sysusersRunner(configPath, code) === true, code);
  const accountRecords = accountCensus(code);
  requireCondition(accountRecords.length === SERVICE_ACCOUNTS.length, code);
  const stateDirectories = statePreparer({
    accounts: accountRecords,
    code,
    instance: path.basename(finalRoot),
    stateRoot
  });
  const acceptedBuildReceiptSha256Path = path.join(
    path.dirname(outputReceiptPath),
    "accepted-build-receipt-sha256"
  );
  const acceptedBuildReceiptSha256File = publishOrVerifyExactRootFile({
    bytes: Buffer.from(`${expectedBuildReceiptSha256}\n`, "utf8"),
    code,
    filePath: acceptedBuildReceiptSha256Path,
    fileSystem: publicationFileSystem,
    mode: 0o444
  });
  requireCondition(systemdReloader(code) === true, code);
  requireCondition(
    canonicalJson(accountCensus(code)) === canonicalJson(accountRecords),
    code
  );
  const body = Object.freeze({
    schemaVersion: ROOT_STAGE_RECEIPT_SCHEMA,
    accountConfigFile,
    accountConfigPath: configPath,
    accountRecords,
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
    stateAncestors: ancestorRecords(stateRoot, code),
    stateDirectories,
    stateRoot,
    stageControls,
    stageInstance: path.basename(finalRoot),
    stageAncestors: ancestorRecords(finalRoot, code),
    stageRoot: finalRoot,
    unitAncestors: ancestorRecords(unitRoot, code),
    unitFiles,
    unitRoot,
    systemdDaemonReloaded: true,
    systemdSysusersExecuted: true,
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
  requireCondition(path.dirname(outputReceiptPath) !== finalRoot, code);
  publishOrVerifyExactRootFile({
    bytes: Buffer.from(`${canonicalJson(receipt)}\n`, "utf8"),
    code,
    filePath: outputReceiptPath,
    fileSystem: publicationFileSystem,
    mode: 0o444
  });
  return receipt;
}

function parseArguments(argv) {
  requireCondition(argv.length === 18, "INTEGRATED_LIVE_DRILL_STAGE_ARGUMENTS");
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    requireCondition(
      [
        "--build-root", "--build-source-root",
        "--expected-build-receipt-sha256",
        "--output-receipt", "--stage-root", "--state-root",
        "--sysusers-root", "--unit-root", "--verifier-root"
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
    stateRoot: values["--state-root"],
    sysusersRoot: values["--sysusers-root"],
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

export const __test = Object.freeze({
  enumerateAccountDatabase,
  preparePersistentState,
  publishOrVerifyExactRootFile,
  runtimeInventory,
  stageControlRecords
});
