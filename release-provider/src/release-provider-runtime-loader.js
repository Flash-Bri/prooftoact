import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const CAPABILITIES = Object.freeze({
  PERMIT_READER: Object.freeze([
    "createAwsPreparePermitTransport", "createPreparePermitReader"
  ]),
  PREPARE_DISPATCHER: Object.freeze([
    "createAwsPrepareDispatcherTransport", "createPrepareDispatcher"
  ]),
  PREPARE_READBACK: Object.freeze([
    "createAwsPrepareReadbackTransport", "createPrepareReadback"
  ])
});

function requireCondition(condition, code) {
  if (!condition) throw new Error(code);
}

function plainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value, expected) {
  return plainObject(value) && Object.keys(value).sort().join("\n") ===
    [...expected].sort().join("\n");
}

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function jsonDigest(value) {
  return sha256(Buffer.from(`${JSON.stringify(value)}\n`, "utf8"));
}

function validatePackageInventory(value) {
  requireCondition(Array.isArray(value) && value.length > 0 &&
    value.every((entry) => exactKeys(entry, [
      "name", "packageJsonSha256", "version"
    ]) && /^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/u.test(entry.name ?? "") &&
      typeof entry.version === "string" && entry.version.length > 0 &&
      entry.version.length <= 64 && HEX_64.test(entry.packageJsonSha256 ?? "")) &&
    value.map(({ name }) => name).join("\n") ===
      [...value].map(({ name }) => name).sort().join("\n") &&
    new Set(value.map(({ name }) => name)).size === value.length,
  "RELEASE_PROVIDER_RUNTIME_PACKAGE_INVENTORY_REJECTED");
  return value;
}

function validateRuntime(value) {
  const exports = CAPABILITIES[value?.capability];
  requireCondition(exports && exactKeys(value, [
    "bundledPackages", "bytes", "capability", "exports", "externalImports",
    "packageInventory", "packageInventorySha256", "path", "sha256"
  ]) && Array.isArray(value.exports) &&
    value.exports.join("\n") === exports.join("\n") &&
    Array.isArray(value.bundledPackages) && value.bundledPackages.length > 0 &&
    value.bundledPackages.join("\n") ===
      [...value.bundledPackages].sort().join("\n") &&
    Array.isArray(value.externalImports) && value.externalImports.length > 0 &&
    value.externalImports.every((name) =>
      /^node:[a-z0-9_./-]+$/u.test(name)) &&
    Number.isSafeInteger(value.bytes) && value.bytes > 0 &&
    value.bytes <= 10 * 1024 * 1024 && HEX_64.test(value.sha256 ?? "") &&
    value.path === `dist/aws/release-provider-${value.capability
      .toLowerCase().replaceAll("_", "-")}-${value.sha256}.mjs`,
  "RELEASE_PROVIDER_RUNTIME_RECEIPT_REJECTED");
  const inventory = validatePackageInventory(value.packageInventory);
  requireCondition(value.packageInventorySha256 === jsonDigest(inventory) &&
    value.bundledPackages.join("\n") ===
      inventory.map(({ name }) => name).join("\n"),
  "RELEASE_PROVIDER_RUNTIME_PACKAGE_BINDING_REJECTED");
  return value;
}

function validateSourceInventory(value) {
  requireCondition(Array.isArray(value) && value.length >= 9 &&
    value.every((entry) => exactKeys(entry, ["bytes", "path", "sha256"]) &&
      Number.isSafeInteger(entry.bytes) && entry.bytes > 0 &&
      entry.bytes <= 5 * 1024 * 1024 &&
      /^(?:release-provider|scripts|src)\/[a-z0-9_./-]+\.js$/u
        .test(entry.path ?? "") && !entry.path.includes("../") &&
      HEX_64.test(entry.sha256 ?? "")) &&
    value.map(({ path: itemPath }) => itemPath).join("\n") ===
      [...value].map(({ path: itemPath }) => itemPath).sort().join("\n") &&
    new Set(value.map(({ path: itemPath }) => itemPath)).size === value.length,
  "RELEASE_PROVIDER_RUNTIME_SOURCE_INVENTORY_REJECTED");
  return value;
}

export async function loadReleaseProviderRuntime({
  capability,
  expectedControlPlaneCommit,
  expectedControlPlaneTree,
  expectedPackageJsonSha256,
  expectedPackageLockSha256,
  outputRoot,
  receipt
}) {
  requireCondition(Object.hasOwn(CAPABILITIES, capability) &&
    exactKeys(receipt, [
      "builderSha256", "controlPlaneCommit", "controlPlaneTree",
      "esbuildBinarySha256", "esbuildLauncherSha256",
      "esbuildPackageJsonSha256", "esbuildVersion", "nodeArch",
      "nodeExecutableSha256", "nodePlatform", "nodeVersion",
      "packageJsonSha256", "packageLockSha256", "provenanceSha256",
      "runtimes", "runtimeSetSha256", "schemaVersion", "sourceInventory",
      "sourceInventorySha256"
    ]) && receipt.schemaVersion ===
      "prooftoact.release-provider-runtime-build.v1" &&
    HEX_40.test(receipt.controlPlaneCommit ?? "") &&
    HEX_40.test(receipt.controlPlaneTree ?? "") &&
    receipt.controlPlaneCommit === expectedControlPlaneCommit &&
    receipt.controlPlaneTree === expectedControlPlaneTree &&
    receipt.packageJsonSha256 === expectedPackageJsonSha256 &&
    receipt.packageLockSha256 === expectedPackageLockSha256 &&
    receipt.esbuildVersion === "0.28.1" &&
    receipt.nodeVersion === process.version &&
    receipt.nodePlatform === process.platform &&
    receipt.nodeArch === process.arch && [
      receipt.builderSha256, receipt.esbuildBinarySha256,
      receipt.esbuildLauncherSha256, receipt.esbuildPackageJsonSha256,
      receipt.nodeExecutableSha256, receipt.packageJsonSha256,
      receipt.packageLockSha256, receipt.provenanceSha256,
      receipt.runtimeSetSha256, receipt.sourceInventorySha256
    ].every((digest) => HEX_64.test(digest ?? "")),
  "RELEASE_PROVIDER_BUILD_RECEIPT_REJECTED");
  const sources = validateSourceInventory(receipt.sourceInventory);
  requireCondition(receipt.sourceInventorySha256 === jsonDigest(sources) &&
    receipt.nodeExecutableSha256 ===
      sha256(fs.readFileSync(fs.realpathSync(process.execPath))),
  "RELEASE_PROVIDER_BUILD_PROVENANCE_REJECTED");
  requireCondition(Array.isArray(receipt.runtimes) &&
    receipt.runtimes.length === 3 && receipt.runtimes.map(({ capability: name }) =>
      name).join("\n") === Object.keys(CAPABILITIES).join("\n"),
  "RELEASE_PROVIDER_RUNTIME_SET_REJECTED");
  for (const runtime of receipt.runtimes) validateRuntime(runtime);
  requireCondition(receipt.runtimeSetSha256 === jsonDigest(receipt.runtimes.map(
    ({ capability: name, path: runtimePath, sha256: digest }) => ({
      capability: name, path: runtimePath, sha256: digest
    }))), "RELEASE_PROVIDER_RUNTIME_SET_REJECTED");
  const unsigned = { ...receipt };
  delete unsigned.provenanceSha256;
  requireCondition(receipt.provenanceSha256 === jsonDigest(unsigned),
    "RELEASE_PROVIDER_BUILD_PROVENANCE_REJECTED");
  const runtime = receipt.runtimes.find((entry) =>
    entry.capability === capability);
  const root = fs.realpathSync(outputRoot);
  const filePath = path.resolve(root, runtime.path);
  requireCondition(path.relative(root, filePath) ===
    runtime.path.split("/").join(path.sep) && fs.realpathSync(filePath) ===
    filePath, "RELEASE_PROVIDER_RUNTIME_PATH_REJECTED");
  const descriptor = fs.openSync(filePath,
    fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  let bytes;
  try {
    const stat = fs.fstatSync(descriptor);
    const uid = typeof process.getuid === "function" ? process.getuid() : null;
    requireCondition(stat.isFile() && stat.nlink === 1 &&
      stat.size === runtime.bytes && (stat.mode & 0o777) === 0o600 &&
      (uid === null || stat.uid === uid),
    "RELEASE_PROVIDER_RUNTIME_FILE_REJECTED");
    bytes = fs.readFileSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  requireCondition(bytes.length === runtime.bytes &&
    sha256(bytes) === runtime.sha256,
  "RELEASE_PROVIDER_RUNTIME_DIGEST_REJECTED");
  const module = await import(
    `data:text/javascript;base64,${bytes.toString("base64")}`);
  requireCondition(Object.keys(module).join("\n") ===
    CAPABILITIES[capability].join("\n") &&
    CAPABILITIES[capability].every((name) =>
      typeof module[name] === "function"),
  "RELEASE_PROVIDER_RUNTIME_EXPORT_REJECTED");
  return Object.freeze({
    capability,
    controlPlaneCommit: receipt.controlPlaneCommit,
    controlPlaneTree: receipt.controlPlaneTree,
    exports: module,
    packageJsonSha256: receipt.packageJsonSha256,
    packageLockSha256: receipt.packageLockSha256,
    provenanceSha256: receipt.provenanceSha256,
    runtimeSetSha256: receipt.runtimeSetSha256,
    runtimeSha256: runtime.sha256
  });
}

export const __test = Object.freeze({
  CAPABILITIES, exactKeys, jsonDigest, sha256, validatePackageInventory,
  validateRuntime, validateSourceInventory
});
