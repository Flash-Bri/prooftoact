import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

// Loads only exact owner-only runtime bytes named by their SHA-256 digest.

const HEX_64 = /^[0-9a-f]{64}$/u;
const HEX_40 = /^[0-9a-f]{40}$/u;
const RUNTIME_PATH =
  /^dist\/aws\/release-control-provider-[0-9a-f]{64}\.mjs$/u;

function requireCondition(condition, code) {
  if (!condition) throw new Error(code);
}

function exactKeys(value, expected) {
  return value && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).sort().join("\n") === [...expected].sort().join("\n");
}

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function jsonDigest(value) {
  return sha256(Buffer.from(`${JSON.stringify(value)}\n`, "utf8"));
}

function sortedUniqueStrings(value, pattern) {
  return Array.isArray(value) && value.length > 0 &&
    value.every((entry) => typeof entry === "string" && pattern.test(entry)) &&
    [...new Set(value)].sort().join("\n") === value.join("\n");
}

function validatePackageInventory(value) {
  requireCondition(Array.isArray(value) && value.length > 0 &&
    value.every((entry) => exactKeys(entry, [
      "name", "packageJsonSha256", "version"
    ]) && /^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/u.test(entry.name) &&
      typeof entry.version === "string" && entry.version.length > 0 &&
      entry.version.length <= 64 && HEX_64.test(entry.packageJsonSha256)) &&
    value.map(({ name }) => name).sort().join("\n") ===
      value.map(({ name }) => name).join("\n") &&
    new Set(value.map(({ name }) => name)).size === value.length,
  "RELEASE_CONTROL_RUNTIME_PACKAGE_INVENTORY_REJECTED");
  return value;
}

function validateSourceInventory(value) {
  requireCondition(Array.isArray(value) && value.length >= 6 &&
    value.every((entry) => exactKeys(entry, ["bytes", "path", "sha256"]) &&
      Number.isSafeInteger(entry.bytes) && entry.bytes > 0 &&
      entry.bytes <= 5 * 1024 * 1024 &&
      /^(?:release-control|scripts|src)\/[a-z0-9_./-]+\.js$/u.test(entry.path) &&
      !entry.path.includes("../") && HEX_64.test(entry.sha256)) &&
    value.map(({ path: entryPath }) => entryPath).sort().join("\n") ===
      value.map(({ path: entryPath }) => entryPath).join("\n") &&
    new Set(value.map(({ path: entryPath }) => entryPath)).size === value.length,
  "RELEASE_CONTROL_RUNTIME_SOURCE_INVENTORY_REJECTED");
  return value;
}

function validateOptionalArtifacts(value) {
  requireCondition(Array.isArray(value) && value.length === 2 &&
    value.map(({ path: entryPath }) => entryPath).join("\n") === [
      "release-control/DEPENDENCY_INVENTORY.json",
      "release-control/THIRD_PARTY_NOTICES.txt"
    ].join("\n") && value.every((entry) => exactKeys(entry, [
      "bytes", "path", "sha256", "status"
    ]) && (entry.status === "ABSENT"
      ? entry.bytes === 0 && entry.sha256 === null
      : entry.status === "PRESENT" && Number.isSafeInteger(entry.bytes) &&
        entry.bytes > 0 && entry.bytes <= 5 * 1024 * 1024 &&
        HEX_64.test(entry.sha256 ?? ""))),
  "RELEASE_CONTROL_RUNTIME_OPTIONAL_ARTIFACT_REJECTED");
  return value;
}

export async function loadReleaseControlRuntime({
  expectedControlPlaneCommit,
  expectedControlPlaneTree,
  expectedPackageJsonSha256,
  expectedPackageLockSha256,
  projectRoot,
  receipt
}) {
  requireCondition(exactKeys(receipt, [
    "builderSha256", "bundledPackages", "bytes", "controlPlaneCommit",
    "controlPlaneIdentitySha256", "controlPlaneTree", "esbuildBinarySha256",
    "esbuildLauncherSha256", "esbuildPackageJsonSha256", "esbuildVersion",
    "externalImports", "nodeArch", "nodeExecutableSha256", "nodePlatform",
    "nodeVersion", "optionalArtifacts", "packageInventory",
    "packageInventorySha256", "packageJsonSha256", "packageLockSha256",
    "path", "provenanceSha256", "sha256", "sourceInventory",
    "sourceInventorySha256"
  ]) && HEX_40.test(receipt.controlPlaneCommit ?? "") &&
    HEX_40.test(receipt.controlPlaneTree ?? "") &&
    receipt.controlPlaneCommit === expectedControlPlaneCommit &&
    receipt.controlPlaneTree === expectedControlPlaneTree &&
    receipt.packageJsonSha256 === expectedPackageJsonSha256 &&
    receipt.packageLockSha256 === expectedPackageLockSha256 &&
    sortedUniqueStrings(receipt.bundledPackages,
      /^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/u) &&
    sortedUniqueStrings(receipt.externalImports, /^node:[a-z0-9_./-]+$/u) &&
    RUNTIME_PATH.test(receipt.path) &&
    [receipt.builderSha256, receipt.controlPlaneIdentitySha256,
      receipt.esbuildBinarySha256, receipt.esbuildLauncherSha256,
      receipt.esbuildPackageJsonSha256, receipt.nodeExecutableSha256,
      receipt.packageInventorySha256, receipt.packageJsonSha256,
      receipt.packageLockSha256, receipt.provenanceSha256, receipt.sha256,
      receipt.sourceInventorySha256].every((value) => HEX_64.test(value ?? "")) &&
    receipt.esbuildVersion === "0.28.1" &&
    receipt.nodeVersion === process.version &&
    receipt.nodePlatform === process.platform && receipt.nodeArch === process.arch &&
    HEX_64.test(receipt.packageJsonSha256 ?? "") &&
    HEX_64.test(receipt.packageLockSha256 ?? "") &&
    HEX_64.test(receipt.sha256 ?? "") &&
    receipt.path === `dist/aws/release-control-provider-${receipt.sha256}.mjs` &&
    Number.isSafeInteger(receipt.bytes) && receipt.bytes > 0 &&
    receipt.bytes <= 5 * 1024 * 1024,
  "RELEASE_CONTROL_RUNTIME_RECEIPT_REJECTED");
  const packageInventory = validatePackageInventory(receipt.packageInventory);
  const sourceInventory = validateSourceInventory(receipt.sourceInventory);
  validateOptionalArtifacts(receipt.optionalArtifacts);
  const unsignedReceipt = { ...receipt };
  delete unsignedReceipt.provenanceSha256;
  requireCondition(receipt.bundledPackages.join("\n") ===
    packageInventory.map(({ name }) => name).join("\n") &&
    receipt.packageInventorySha256 === jsonDigest(packageInventory) &&
    receipt.sourceInventorySha256 === jsonDigest(sourceInventory) &&
    receipt.controlPlaneIdentitySha256 === jsonDigest({
      builderSha256: receipt.builderSha256,
      commit: receipt.controlPlaneCommit,
      packageInventorySha256: receipt.packageInventorySha256,
      packageJsonSha256: receipt.packageJsonSha256,
      packageLockSha256: receipt.packageLockSha256,
      sourceInventorySha256: receipt.sourceInventorySha256,
      tree: receipt.controlPlaneTree
    }) && receipt.nodeExecutableSha256 ===
      sha256(fs.readFileSync(fs.realpathSync(process.execPath))) &&
    receipt.provenanceSha256 === jsonDigest(unsignedReceipt),
  "RELEASE_CONTROL_RUNTIME_PROVENANCE_REJECTED");
  const root = fs.realpathSync(projectRoot);
  const filePath = path.resolve(root, receipt.path);
  const relative = path.relative(root, filePath);
  requireCondition(relative === receipt.path.split("/").join(path.sep) &&
    !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative),
  "RELEASE_CONTROL_RUNTIME_PATH_REJECTED");
  requireCondition(fs.realpathSync(filePath) === filePath,
    "RELEASE_CONTROL_RUNTIME_REALPATH_REJECTED");
  const descriptor = fs.openSync(
    filePath,
    fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW
  );
  let bytes;
  try {
    const stat = fs.fstatSync(descriptor);
    const expectedUid = typeof process.getuid === "function"
      ? process.getuid() : null;
    requireCondition(stat.isFile() && stat.nlink === 1 &&
      stat.size === receipt.bytes && (stat.mode & 0o777) === 0o600 &&
      (expectedUid === null || stat.uid === expectedUid),
    "RELEASE_CONTROL_RUNTIME_FILE_REJECTED");
    bytes = fs.readFileSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  requireCondition(bytes.length === receipt.bytes &&
    sha256(bytes) === receipt.sha256,
  "RELEASE_CONTROL_RUNTIME_DIGEST_REJECTED");
  const module = await import(
    `data:text/javascript;base64,${bytes.toString("base64")}`
  );
  requireCondition(Object.keys(module).join("\n") === [
    "attestReleaseControlTable",
    "createReleaseControlAwsRuntime",
    "createReleaseControlDynamoDbStore"
  ].join("\n") && typeof module.createReleaseControlAwsRuntime === "function" &&
    typeof module.createReleaseControlDynamoDbStore === "function" &&
    typeof module.attestReleaseControlTable === "function",
  "RELEASE_CONTROL_RUNTIME_EXPORT_REJECTED");
  return Object.freeze({
    attestReleaseControlTable: module.attestReleaseControlTable,
    controlPlaneIdentitySha256: receipt.controlPlaneIdentitySha256,
    createReleaseControlAwsRuntime: module.createReleaseControlAwsRuntime,
    createReleaseControlDynamoDbStore: module.createReleaseControlDynamoDbStore,
    packageJsonSha256: receipt.packageJsonSha256,
    packageLockSha256: receipt.packageLockSha256,
    provenanceSha256: receipt.provenanceSha256,
    runtimeSha256: receipt.sha256
  });
}

export const __test = Object.freeze({
  RUNTIME_PATH,
  exactKeys,
  jsonDigest,
  sha256,
  sortedUniqueStrings,
  validateOptionalArtifacts,
  validatePackageInventory,
  validateSourceInventory
});
