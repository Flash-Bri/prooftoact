#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { buildReleaseProviderRuntimes } from
  "./build-release-provider-runtimes.js";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const ALLOWED_LICENSES = Object.freeze(["0BSD", "Apache-2.0", "MIT"]);
const DUMMY_COMMIT = "1".repeat(40);
const DUMMY_TREE = "2".repeat(40);
const LICENSE_NAMES = Object.freeze([
  "LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE", "LICENCE.md",
  "NOTICE", "NOTICE.txt"
]);

function invariant(condition, code) {
  if (!condition) throw new Error(code);
}

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function jsonDigest(value) {
  return sha256(Buffer.from(`${JSON.stringify(value)}\n`, "utf8"));
}

function exactFile(root, relative, maximumBytes = 1024 * 1024) {
  const filePath = path.resolve(root, relative);
  invariant(path.relative(root, filePath) === relative.split("/").join(path.sep),
    "RELEASE_PROVIDER_METADATA_PATH_REJECTED");
  invariant(fs.realpathSync(filePath) === filePath,
    "RELEASE_PROVIDER_METADATA_REALPATH_REJECTED");
  const stat = fs.lstatSync(filePath);
  invariant(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1 &&
    stat.size > 0 && stat.size <= maximumBytes,
  "RELEASE_PROVIDER_METADATA_FILE_REJECTED");
  return Object.freeze({ bytes: fs.readFileSync(filePath), relative });
}

function packageName(lockPath) {
  const marker = "node_modules/";
  const index = lockPath.lastIndexOf(marker);
  invariant(index >= 0, "RELEASE_PROVIDER_LOCK_PATH_REJECTED");
  const suffix = lockPath.slice(index + marker.length);
  const parts = suffix.split("/");
  const name = parts[0].startsWith("@")
    ? `${parts[0]}/${parts[1] ?? ""}` : parts[0];
  invariant(/^(@[a-z0-9._-]+\/)?[a-z0-9._-]+$/u.test(name),
    "RELEASE_PROVIDER_PACKAGE_NAME_REJECTED");
  return name;
}

function normalizedLicense(bytes) {
  return Buffer.from(`${bytes.toString("utf8").replaceAll("\r\n", "\n")
    .trim()}\n`, "utf8");
}

function licenseCandidates(name, lockPath) {
  const direct = LICENSE_NAMES.map((fileName) => `${lockPath}/${fileName}`);
  const family = name.startsWith("@aws-sdk/")
    ? ["node_modules/@aws-sdk/client-cloudformation/LICENSE"]
    : name.startsWith("@smithy/")
      ? ["node_modules/@smithy/node-http-handler/LICENSE"]
      : name.startsWith("@esbuild/")
        ? ["node_modules/esbuild/LICENSE.md"] : [];
  return [...direct, ...family];
}

function directDependencies(manifest, lock, field) {
  return Object.keys(manifest[field] ?? {}).sort().map((name) => {
    const declared = manifest[field][name];
    const locked = lock.packages?.[`node_modules/${name}`]?.version ?? null;
    invariant(/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/u.test(declared) &&
      declared === locked, "RELEASE_PROVIDER_DIRECT_LOCK_REJECTED");
    return Object.freeze({ declared, locked, name });
  });
}

function packageRecords({ lock, runtimes }) {
  const capabilities = new Map();
  for (const runtime of runtimes) {
    for (const name of runtime.bundledPackages) {
      const current = capabilities.get(name) ?? [];
      current.push(runtime.capability);
      capabilities.set(name, current);
    }
  }
  const records = Object.keys(lock.packages ?? {}).filter(Boolean).sort()
    .map((lockPath) => {
      const value = lock.packages[lockPath];
      const name = packageName(lockPath);
      invariant(/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/u.test(
        value.version ?? "") && ALLOWED_LICENSES.includes(value.license) &&
        value.deprecated === undefined &&
        /^https:\/\/registry\.npmjs\.org\//u.test(value.resolved ?? "") &&
        /^sha512-[A-Za-z0-9+/]+=*$/u.test(value.integrity ?? ""),
      "RELEASE_PROVIDER_LOCK_RECORD_REJECTED");
      return Object.freeze({
        bundledCapabilities: Object.freeze(
          [...new Set(capabilities.get(name) ?? [])].sort()),
        developmentOnly: value.dev === true,
        hasInstallScript: value.hasInstallScript === true,
        integrity: value.integrity,
        license: value.license,
        lockPath,
        name,
        optional: value.optional === true,
        registry: value.resolved,
        version: value.version
      });
    });
  const lockedNames = new Set(records.map(({ name }) => name));
  invariant([...capabilities.keys()].every((name) => lockedNames.has(name)),
    "RELEASE_PROVIDER_BUNDLE_PACKAGE_NOT_LOCKED");
  invariant([...capabilities.keys()].every((name) =>
    !name.startsWith("@aws-sdk/credential-provider-") &&
    name !== "@aws-sdk/token-providers" &&
    name !== "@smithy/credential-provider-imds"),
  "RELEASE_PROVIDER_BUNDLE_CREDENTIAL_CHAIN_REJECTED");
  return Object.freeze(records);
}

function collectLicenseRecords(root, records) {
  const texts = new Map();
  const packages = records.map((record) => {
    const relative = licenseCandidates(record.name, record.lockPath)
      .find((candidate) => fs.existsSync(path.join(root, candidate)));
    invariant(relative !== undefined,
      "RELEASE_PROVIDER_LICENSE_TEXT_MISSING");
    const normalized = normalizedLicense(exactFile(root, relative,
      512 * 1024).bytes);
    const digest = sha256(normalized);
    texts.set(digest, normalized.toString("utf8"));
    return Object.freeze({
      ...record,
      licenseSource: relative,
      licenseSourceKind: relative.startsWith(`${record.lockPath}/`)
        ? "package-file" : "reviewed-family-fallback",
      licenseTextSha256: digest
    });
  });
  return Object.freeze({ packages: Object.freeze(packages), texts });
}

function renderNotices({ packages, texts }) {
  const lines = [
    "PROOFTOACT RELEASE-PROVIDER THIRD-PARTY NOTICES",
    "",
    "Generated only for the separately locked release-provider toolchain. " +
      "This notice does not modify the frozen application notice set.",
    "",
    "PACKAGE RECORDS",
    ""
  ];
  for (const item of packages) {
    lines.push(`${item.name}@${item.version}`,
      `  License: ${item.license}`,
      `  Registry: ${item.registry}`,
      `  Integrity: ${item.integrity}`,
      `  Bundled capabilities: ${item.bundledCapabilities.join(",") || "NONE"}`,
      `  Text: ${item.licenseTextSha256}`,
      `  Source: ${item.licenseSource}`, "");
  }
  lines.push("LICENSE TEXTS", "");
  for (const digest of [...texts.keys()].sort()) {
    lines.push(`----- ${digest} -----`, texts.get(digest).trimEnd(), "");
  }
  return `${lines.join("\n").trimEnd()}\n`;
}

export async function buildReleaseProviderMetadata({ projectRoot = ROOT } = {}) {
  const root = fs.realpathSync(projectRoot);
  const packageBytes = exactFile(root, "package.json").bytes;
  const lockBytes = exactFile(root, "package-lock.json", 4 * 1024 * 1024).bytes;
  const generatorBytes = exactFile(root,
    "generate-release-provider-metadata.js").bytes;
  const manifest = JSON.parse(packageBytes.toString("utf8"));
  const lock = JSON.parse(lockBytes.toString("utf8"));
  invariant(manifest.name === "@prooftoact/release-provider-runtime" &&
    manifest.private === true && manifest.type === "module" &&
    lock.lockfileVersion === 3 && lock.packages?.[""],
  "RELEASE_PROVIDER_METADATA_PACKAGE_REJECTED");

  const outputRoot = fs.mkdtempSync(path.join(os.tmpdir(),
    "prooftoact-release-provider-metadata-"));
  let runtimeReceipt;
  try {
    runtimeReceipt = await buildReleaseProviderRuntimes({
      controlPlaneCommit: DUMMY_COMMIT,
      controlPlaneTree: DUMMY_TREE,
      outputRoot,
      projectRoot: root
    });
  } finally {
    fs.rmSync(outputRoot, { recursive: true, force: true });
  }
  const records = packageRecords({ lock, runtimes: runtimeReceipt.runtimes });
  const licenses = collectLicenseRecords(root, records);
  const inventory = {
    schemaVersion: "prooftoact.release-provider-dependency-inventory.v1",
    status: "GENERATED_FROM_HERMETIC_LOCK_AND_BUNDLE_METAFILES",
    generatorSha256: sha256(generatorBytes),
    packageJsonSha256: sha256(packageBytes),
    packageLockSha256: sha256(lockBytes),
    lockfileVersion: lock.lockfileVersion,
    directRuntimeDependencies:
      directDependencies(manifest, lock, "dependencies"),
    directDevelopmentDependencies:
      directDependencies(manifest, lock, "devDependencies"),
    runtimeSetSha256: runtimeReceipt.runtimeSetSha256,
    packageCount: records.length,
    packageInventorySha256: jsonDigest(records),
    packages: records
  };
  const dependencyInventory = `${JSON.stringify(inventory)}\n`;
  const thirdPartyNotices = renderNotices(licenses);
  return Object.freeze({
    dependencyInventory,
    dependencyInventoryBytes: Buffer.byteLength(dependencyInventory),
    dependencyInventorySha256:
      sha256(Buffer.from(dependencyInventory, "utf8")),
    licenseTextCount: licenses.texts.size,
    packageCount: records.length,
    runtimeSetSha256: runtimeReceipt.runtimeSetSha256,
    thirdPartyNotices,
    thirdPartyNoticesBytes: Buffer.byteLength(thirdPartyNotices),
    thirdPartyNoticesSha256:
      sha256(Buffer.from(thirdPartyNotices, "utf8"))
  });
}

async function main(args = process.argv.slice(2)) {
  invariant(args.length === 4 && args[0] === "--inventory-output" &&
    args[2] === "--notices-output" && path.isAbsolute(args[1]) &&
    path.isAbsolute(args[3]), "RELEASE_PROVIDER_METADATA_USAGE");
  const metadata = await buildReleaseProviderMetadata();
  for (const [filePath, content] of [
    [args[1], metadata.dependencyInventory],
    [args[3], metadata.thirdPartyNotices]
  ]) {
    fs.writeFileSync(filePath, content, { encoding: "utf8", flag: "wx",
      mode: 0o600 });
  }
  process.stdout.write(`${JSON.stringify({
    dependencyInventoryBytes: metadata.dependencyInventoryBytes,
    dependencyInventorySha256: metadata.dependencyInventorySha256,
    licenseTextCount: metadata.licenseTextCount,
    packageCount: metadata.packageCount,
    providerExecutionAuthorized: false,
    runtimeSetSha256: metadata.runtimeSetSha256,
    thirdPartyNoticesBytes: metadata.thirdPartyNoticesBytes,
    thirdPartyNoticesSha256: metadata.thirdPartyNoticesSha256
  })}\n`);
}

if (process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}

export const __test = Object.freeze({
  ALLOWED_LICENSES, collectLicenseRecords, directDependencies, exactFile,
  jsonDigest, licenseCandidates, normalizedLicense, packageName,
  packageRecords, renderNotices, sha256
});
