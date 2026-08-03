import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { assertNoAwsEndpointOverrides } from "../src/cloud/aws-evidence-identity.js";
import { templateReceipt } from "../src/cloud/aws-gate2-template.js";
import { exactNpmCli } from "./build-gate2-exact.js";
import {
  validateBuildToolchain,
  validateDependencySnapshot
} from "./lib/dependency-snapshot.js";
import {
  assertSafeProjectPath,
  gitEnvironment,
  gitInvariantArguments,
  trustedGitExecutable,
  trustedTemporaryRoot
} from "./lib/exact-git-source.js";
import { validateReleaseCostReceipt } from "./verify-release-cost.js";
import { validateReleaseSecurityReceipt } from "./verify-release-security.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");
const OFFICIAL_REMOTE =
  "https://github.com/Flash-Bri/tideproof.git";
const EXPECTED_BRANCH = "main";
const EXPECTED_REGION = "us-east-1";
const CLEAN_ROOM_ROOT = "e198f4146d3d769ebdaf62927d3bbe92025e8340";
const ARTIFACT_NAMES = Object.freeze([
  "agent",
  "authority",
  "boundary",
  "demo",
  "probe",
  "signer"
]);
const BUNDLED_COMPONENT_NAMES = Object.freeze([
  ...ARTIFACT_NAMES,
  "evidenceProvider"
]);
const HEX_40 = /^[0-9a-f]{40}$/;
const HEX_64 = /^[0-9a-f]{64}$/;
const FIXED_ZIP_DATE = ((2026 - 1980) << 9) | (7 << 5) | 30;
const CRC32_TABLE = Array.from({ length: 256 }, (_, value) => {
  let crc = value;
  for (let bit = 0; bit < 8; bit += 1) {
    crc = (crc & 1) === 1
      ? 0xedb88320 ^ (crc >>> 1)
      : crc >>> 1;
  }
  return crc >>> 0;
});
const SAFE_CHILD_ENVIRONMENT_NAMES = new Set([
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "NO_COLOR"
]);
const AUTHENTICATED_AWS_ENVIRONMENT_NAMES = new Set([
  "AWS_ACCESS_KEY_ID",
  "AWS_DEFAULT_REGION",
  "AWS_EVIDENCE_EXPECTED_ACCOUNT_ID",
  "AWS_EVIDENCE_EXPECTED_PREFLIGHT_CALLER_ARN",
  "AWS_EVIDENCE_EXPECTED_PREFLIGHT_CALLER_USER_ID",
  "AWS_EVIDENCE_EXPECTED_PREFLIGHT_PRINCIPAL_ARN",
  "AWS_REGION",
  "AWS_SECRET_ACCESS_KEY",
  "AWS_SESSION_TOKEN"
]);

function requireCondition(condition, code) {
  if (!condition) {
    throw new Error(code);
  }
}

function exactKeys(value, keys) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join("\n") ===
      [...keys].sort().join("\n")
  );
}

function sha256(value, encoding = "hex") {
  return crypto.createHash("sha256").update(value).digest(encoding);
}

function gitBlobId(value) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value);
  return crypto
    .createHash("sha1")
    .update(Buffer.from(`blob ${bytes.length}\0`, "utf8"))
    .update(bytes)
    .digest("hex");
}

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc = CRC32_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function sha256File(filePath, encoding = "hex") {
  return sha256(fs.readFileSync(filePath), encoding);
}

function resolvedFile(projectRoot, relativePath, code) {
  requireCondition(
    typeof relativePath === "string" &&
      relativePath.length > 0 &&
      !path.isAbsolute(relativePath),
    code
  );
  const resolved = path.resolve(projectRoot, relativePath);
  const relative = path.relative(projectRoot, resolved);
  requireCondition(
    relative.length > 0 &&
      !relative.startsWith(`..${path.sep}`) &&
      relative !== ".." &&
      !path.isAbsolute(relative),
    code
  );
  assertSafeProjectPath({
    rootDir: projectRoot,
    filePath: resolved,
    code
  });
  const stat = fs.lstatSync(resolved);
  requireCondition(stat.isFile() && !stat.isSymbolicLink(), code);
  return { resolved, stat };
}

function validateStoredTwoFileZip(buffer) {
  requireCondition(
    Buffer.isBuffer(buffer) && buffer.length >= 82,
    "AWS_READINESS_ZIP"
  );
  const endOffset = buffer.length - 22;
  requireCondition(
    buffer.readUInt32LE(endOffset) === 0x06054b50 &&
      buffer.readUInt16LE(endOffset + 4) === 0 &&
      buffer.readUInt16LE(endOffset + 6) === 0 &&
      buffer.readUInt16LE(endOffset + 8) === 2 &&
      buffer.readUInt16LE(endOffset + 10) === 2 &&
      buffer.readUInt16LE(endOffset + 20) === 0,
    "AWS_READINESS_ZIP_END"
  );
  const centralBytes = buffer.readUInt32LE(endOffset + 12);
  const centralOffset = buffer.readUInt32LE(endOffset + 16);
  requireCondition(
    centralOffset > 0 &&
      centralBytes > 0 &&
      centralOffset + centralBytes === endOffset,
    "AWS_READINESS_ZIP_DIRECTORY"
  );

  const localEntries = [];
  let offset = 0;
  while (offset < centralOffset) {
    requireCondition(
      offset + 30 <= centralOffset &&
        buffer.readUInt32LE(offset) === 0x04034b50,
      "AWS_READINESS_ZIP_LOCAL_HEADER"
    );
    const flags = buffer.readUInt16LE(offset + 6);
    const method = buffer.readUInt16LE(offset + 8);
    const time = buffer.readUInt16LE(offset + 10);
    const date = buffer.readUInt16LE(offset + 12);
    const checksum = buffer.readUInt32LE(offset + 14);
    const compressedBytes = buffer.readUInt32LE(offset + 18);
    const uncompressedBytes = buffer.readUInt32LE(offset + 22);
    const nameBytes = buffer.readUInt16LE(offset + 26);
    const extraBytes = buffer.readUInt16LE(offset + 28);
    const nameStart = offset + 30;
    const nameEnd = nameStart + nameBytes;
    const contentStart = nameEnd + extraBytes;
    const contentEnd = contentStart + compressedBytes;
    const content = buffer.subarray(contentStart, contentEnd);
    requireCondition(
      buffer.readUInt16LE(offset + 4) === 20 &&
        flags === 0 &&
        method === 0 &&
        time === 0 &&
        date === FIXED_ZIP_DATE &&
        compressedBytes > 0 &&
        compressedBytes === uncompressedBytes &&
        nameBytes > 0 &&
        extraBytes === 0 &&
        contentEnd <= centralOffset &&
        crc32(content) === checksum,
      "AWS_READINESS_ZIP_LOCAL_ENTRY"
    );
    const name = buffer.subarray(nameStart, nameEnd).toString("utf8");
    requireCondition(
      /^[A-Za-z0-9._-]+$/.test(name) &&
        Buffer.byteLength(name, "utf8") === nameBytes,
      "AWS_READINESS_ZIP_LOCAL_NAME"
    );
    localEntries.push({
      name,
      checksum,
      compressedBytes,
      localOffset: offset,
      content
    });
    offset = contentEnd;
  }
  requireCondition(
    offset === centralOffset && localEntries.length === 2,
    "AWS_READINESS_ZIP_LOCAL_SET"
  );

  const centralEntries = [];
  offset = centralOffset;
  while (offset < endOffset) {
    requireCondition(
      offset + 46 <= endOffset &&
        buffer.readUInt32LE(offset) === 0x02014b50,
      "AWS_READINESS_ZIP_CENTRAL_HEADER"
    );
    const flags = buffer.readUInt16LE(offset + 8);
    const method = buffer.readUInt16LE(offset + 10);
    const time = buffer.readUInt16LE(offset + 12);
    const date = buffer.readUInt16LE(offset + 14);
    const checksum = buffer.readUInt32LE(offset + 16);
    const compressedBytes = buffer.readUInt32LE(offset + 20);
    const uncompressedBytes = buffer.readUInt32LE(offset + 24);
    const nameBytes = buffer.readUInt16LE(offset + 28);
    const extraBytes = buffer.readUInt16LE(offset + 30);
    const commentBytes = buffer.readUInt16LE(offset + 32);
    const disk = buffer.readUInt16LE(offset + 34);
    const internalAttributes = buffer.readUInt16LE(offset + 36);
    const externalAttributes = buffer.readUInt32LE(offset + 38);
    const localOffset = buffer.readUInt32LE(offset + 42);
    const nameStart = offset + 46;
    const nameEnd = nameStart + nameBytes;
    const nextOffset = nameEnd + extraBytes + commentBytes;
    requireCondition(
      buffer.readUInt16LE(offset + 4) === ((3 << 8) | 20) &&
        buffer.readUInt16LE(offset + 6) === 20 &&
        flags === 0 &&
        method === 0 &&
        time === 0 &&
        date === FIXED_ZIP_DATE &&
        compressedBytes > 0 &&
        compressedBytes === uncompressedBytes &&
        extraBytes === 0 &&
        commentBytes === 0 &&
        disk === 0 &&
        internalAttributes === 0 &&
        externalAttributes === ((0o100644 * 65_536) >>> 0) &&
        nextOffset <= endOffset,
      "AWS_READINESS_ZIP_CENTRAL_ENTRY"
    );
    centralEntries.push({
      name: buffer.subarray(nameStart, nameEnd).toString("utf8"),
      checksum,
      compressedBytes,
      localOffset
    });
    offset = nextOffset;
  }
  requireCondition(
    offset === endOffset && centralEntries.length === 2,
    "AWS_READINESS_ZIP_CENTRAL_SET"
  );
  for (let index = 0; index < localEntries.length; index += 1) {
    const local = localEntries[index];
    const central = centralEntries[index];
    requireCondition(
      central.name === local.name &&
        central.checksum === local.checksum &&
        central.compressedBytes === local.compressedBytes &&
        central.localOffset === local.localOffset,
      "AWS_READINESS_ZIP_ENTRY_MISMATCH"
    );
  }
  const expectedNames = ["THIRD_PARTY_NOTICES.txt", "index.js"];
  requireCondition(
    localEntries.map(({ name }) => name).join("\n") === expectedNames.join("\n"),
    "AWS_READINESS_ZIP_ENTRY_SET"
  );
  return Object.fromEntries(
    localEntries.map(({ name, content }) => [name, content])
  );
}

function validateTemplateReceipt(
  projectRoot,
  receipt,
  expectedPath,
  code
) {
  requireCondition(
    exactKeys(receipt, [
      "bytes",
      "canonicalDigest",
      "path",
      "templateDigest"
    ]) &&
      receipt.path === expectedPath &&
      HEX_64.test(receipt.templateDigest) &&
      HEX_64.test(receipt.canonicalDigest) &&
      Number.isSafeInteger(receipt.bytes) &&
      receipt.bytes > 0,
    code
  );
  const file = resolvedFile(projectRoot, expectedPath, code);
  const templateBytes = fs.readFileSync(file.resolved);
  let computed;
  try {
    computed = templateReceipt(JSON.parse(templateBytes.toString("utf8")));
  } catch {
    throw new Error(code);
  }
  requireCondition(
    file.stat.size === receipt.bytes &&
      sha256File(file.resolved) === receipt.templateDigest &&
      computed.bytes === receipt.bytes &&
      computed.templateDigest === receipt.templateDigest &&
      computed.canonicalDigest === receipt.canonicalDigest,
    code
  );
  return {
    path: expectedPath,
    templateDigest: receipt.templateDigest,
    canonicalDigest: receipt.canonicalDigest,
    bytes: receipt.bytes
  };
}

function validateThirdPartyNotices(
  projectRoot,
  receipt,
  packageLockDigest
) {
  requireCondition(
    exactKeys(receipt, [
      "fallbackCount",
      "licenseTextCount",
      "licenses",
      "noticeBytes",
      "noticePath",
      "noticeSha256",
      "packageCount",
      "packageLockSha256",
      "packageNames",
      "schema",
      "status"
    ]) &&
      receipt.schema === "tideproof.bundled-third-party-notices.v1" &&
      receipt.status === "PASS" &&
      receipt.noticePath === "THIRD_PARTY_NOTICES.txt" &&
      HEX_64.test(receipt.noticeSha256) &&
      receipt.packageLockSha256 === packageLockDigest &&
      Array.isArray(receipt.packageNames) &&
      receipt.packageNames.length === receipt.packageCount &&
      new Set(receipt.packageNames).size === receipt.packageNames.length &&
      receipt.packageNames.every(
        (packageName) =>
          typeof packageName === "string" &&
          /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/i.test(
            packageName
          )
      ) &&
      JSON.stringify(receipt.packageNames) ===
        JSON.stringify([...receipt.packageNames].sort()) &&
      Number.isSafeInteger(receipt.noticeBytes) &&
      receipt.noticeBytes > 0 &&
      Number.isSafeInteger(receipt.packageCount) &&
      receipt.packageCount > 0 &&
      Number.isSafeInteger(receipt.licenseTextCount) &&
      receipt.licenseTextCount > 0 &&
      Number.isSafeInteger(receipt.fallbackCount) &&
      receipt.fallbackCount >= 0 &&
      receipt.fallbackCount <= receipt.packageCount &&
      receipt.licenses &&
      typeof receipt.licenses === "object" &&
      !Array.isArray(receipt.licenses),
    "AWS_READINESS_THIRD_PARTY_NOTICES"
  );
  const licenseEntries = Object.entries(receipt.licenses);
  requireCondition(
    licenseEntries.length > 0 &&
      licenseEntries.every(
        ([license, count]) =>
          ["0BSD", "Apache-2.0", "ISC", "MIT"].includes(license) &&
          Number.isSafeInteger(count) &&
          count > 0
      ) &&
      licenseEntries.reduce((sum, [, count]) => sum + count, 0) ===
        receipt.packageCount,
    "AWS_READINESS_THIRD_PARTY_LICENSES"
  );
  const notice = resolvedFile(
    projectRoot,
    receipt.noticePath,
    "AWS_READINESS_THIRD_PARTY_NOTICE_FILE"
  );
  const bytes = fs.readFileSync(notice.resolved);
  requireCondition(
    notice.stat.size === receipt.noticeBytes &&
      sha256(bytes) === receipt.noticeSha256,
    "AWS_READINESS_THIRD_PARTY_NOTICE_DIGEST"
  );
  return {
    accepted: {
      ...receipt,
      licenses: Object.fromEntries(licenseEntries)
    },
    bytes
  };
}

export function validateBuildReceipt(
  receipt,
  {
    projectRoot = root,
    sourceCommit,
    treeDigest
  }
) {
  requireCondition(
    exactKeys(receipt, [
      "archiveFormat",
      "artifacts",
      "bootstrapTemplate",
      "buildControlInputs",
      "dependencySnapshot",
      "evidenceProviderRuntime",
      "gate2Template",
      "mode",
      "packageJsonDigest",
      "packageLockDigest",
      "projectSourceMode",
      "schemaVersion",
      "sourceCommit",
      "thirdPartyNotices",
      "toolchain",
      "treeDigest",
      "workingTreeClean",
      "workingTreeCleanBeforeGeneration"
    ]) &&
      receipt.schemaVersion === "tideproof.gate2-build.v6" &&
      receipt.mode === "CLEAN_ARTIFACT_BUILD" &&
      receipt.projectSourceMode ===
        "ISOLATED_EXACT_GIT_CHECKOUT_AND_BLOBS" &&
      receipt.sourceCommit === sourceCommit &&
      receipt.treeDigest === treeDigest &&
      receipt.workingTreeClean === true &&
      receipt.workingTreeCleanBeforeGeneration === true &&
      receipt.archiveFormat === "ZIP_STORED_TWO_FILE_V2" &&
      HEX_64.test(receipt.packageJsonDigest) &&
      HEX_64.test(receipt.packageLockDigest),
    "AWS_READINESS_BUILD_RECEIPT"
  );
  const expectedBuildControlPaths = [
    "infra/aws/lambda/agent.cjs",
    "scripts/build-gate2-exact.js",
    "scripts/build-gate2-template.js",
    "scripts/lib/aws-provider-bundle-entry.js",
    "scripts/lib/aws-provider-runtime.js",
    "scripts/lib/aws-provider-runtime-loader.js",
    "scripts/lib/bundled-third-party-notices.js",
    "scripts/lib/dependency-snapshot.js",
    "scripts/lib/deterministic-zip.js",
    "scripts/lib/exact-build-reproduction.js",
    "scripts/lib/exact-git-source.js",
    "scripts/lib/raw-text-plugin.js",
    "scripts/verify-bundled-third-party-notices.js",
    "src/cloud/aws-gate2-template.js",
    "src/cloud/public-demo.js"
  ];
  const buildControlInputs = Array.isArray(receipt.buildControlInputs)
    ? receipt.buildControlInputs
    : [];
  requireCondition(
    JSON.stringify(buildControlInputs.map((input) => input?.path)) ===
      JSON.stringify(expectedBuildControlPaths),
    "AWS_READINESS_BUILD_CONTROL_SET"
  );
  const acceptedBuildControlInputs = [];
  for (const input of buildControlInputs) {
    requireCondition(
      exactKeys(input, ["gitBlobId", "path", "sha256"]) &&
        /^[0-9a-f]{40}$/.test(input.gitBlobId) &&
        HEX_64.test(input.sha256),
      "AWS_READINESS_BUILD_CONTROL_INPUT"
    );
    const inputFile = resolvedFile(
      projectRoot,
      input.path,
      "AWS_READINESS_BUILD_CONTROL_FILE"
    );
    const inputBytes = fs.readFileSync(inputFile.resolved);
    requireCondition(
      sha256(inputBytes) === input.sha256 &&
        gitBlobId(inputBytes) === input.gitBlobId,
      "AWS_READINESS_BUILD_CONTROL_DIGEST"
    );
    acceptedBuildControlInputs.push({ ...input });
  }
  const packageLock = resolvedFile(
    projectRoot,
    "package-lock.json",
    "AWS_READINESS_PACKAGE_LOCK"
  );
  const packageJson = resolvedFile(
    projectRoot,
    "package.json",
    "AWS_READINESS_PACKAGE_JSON"
  );
  const thirdPartyNotices = validateThirdPartyNotices(
    projectRoot,
    receipt.thirdPartyNotices,
    receipt.packageLockDigest
  );
  requireCondition(
    sha256File(packageJson.resolved) === receipt.packageJsonDigest &&
      sha256File(packageLock.resolved) === receipt.packageLockDigest,
    "AWS_READINESS_PACKAGE_LOCK"
  );
  const dependencySnapshot = validateDependencySnapshot(
    receipt.dependencySnapshot,
    {
      packageJsonDigest: receipt.packageJsonDigest,
      packageLockDigest: receipt.packageLockDigest
    }
  );
  const toolchain = validateBuildToolchain(receipt.toolchain);

  const artifacts = Array.isArray(receipt.artifacts)
    ? receipt.artifacts
    : [];
  requireCondition(
    artifacts.length === ARTIFACT_NAMES.length &&
      artifacts
        .map((artifact) => artifact?.name)
        .sort()
        .join("\n") === [...ARTIFACT_NAMES].sort().join("\n"),
    "AWS_READINESS_ARTIFACT_SET"
  );

  const acceptedArtifacts = {};
  const bundledPackageUnion = new Set();
  for (const name of ARTIFACT_NAMES) {
    const artifact = artifacts.find(
      (candidate) => candidate?.name === name
    );
    const expectedSourcePath =
      `infra/aws/lambda/${name}.${name === "demo" ? "js" : "cjs"}`;
    const exactGitInputs = Array.isArray(artifact?.exactGitInputs)
      ? artifact.exactGitInputs
      : [];
    requireCondition(
      exactKeys(artifact, [
        "artifactBytes",
        "artifactCodeSha256",
        "artifactDigest",
        "artifactFile",
        "artifactPath",
        "bundledPackages",
        "exactGitInputs",
        "name",
        "sourceDigest",
        "sourcePath",
        "suggestedS3Key"
      ]) &&
        artifact.sourcePath === expectedSourcePath &&
        HEX_64.test(artifact.sourceDigest) &&
        HEX_64.test(artifact.artifactDigest) &&
        typeof artifact.artifactCodeSha256 === "string" &&
        Number.isSafeInteger(artifact.artifactBytes) &&
        artifact.artifactBytes > 0 &&
        exactGitInputs.length > 0 &&
        exactGitInputs.length <= 512 &&
        JSON.stringify(exactGitInputs.map((input) => input?.path)) ===
          JSON.stringify(
            exactGitInputs.map((input) => input?.path).sort()
          ) &&
        new Set(exactGitInputs.map((input) => input?.path)).size ===
          exactGitInputs.length &&
        Array.isArray(artifact.bundledPackages) &&
        new Set(artifact.bundledPackages).size ===
          artifact.bundledPackages.length &&
        artifact.bundledPackages.every(
          (packageName) =>
            typeof packageName === "string" &&
            /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/i.test(
              packageName
            )
        ) &&
        JSON.stringify(artifact.bundledPackages) ===
          JSON.stringify([...artifact.bundledPackages].sort()),
      "AWS_READINESS_ARTIFACT_RECEIPT"
    );
    const acceptedGitInputs = [];
    for (const input of exactGitInputs) {
      requireCondition(
        exactKeys(input, ["gitBlobId", "path", "sha256"]) &&
          /^[0-9a-f]{40}$/.test(input.gitBlobId) &&
          HEX_64.test(input.sha256) &&
          typeof input.path === "string" &&
          !input.path.split("/").includes("node_modules"),
        "AWS_READINESS_EXACT_GIT_INPUT"
      );
      const inputFile = resolvedFile(
        projectRoot,
        input.path,
        "AWS_READINESS_EXACT_GIT_INPUT_FILE"
      );
      const inputBytes = fs.readFileSync(inputFile.resolved);
      requireCondition(
        sha256(inputBytes) === input.sha256 &&
          gitBlobId(inputBytes) === input.gitBlobId,
        "AWS_READINESS_EXACT_GIT_INPUT_DIGEST"
      );
      acceptedGitInputs.push({ ...input });
    }
    const sourceInput = exactGitInputs.find(
      (input) => input.path === expectedSourcePath
    );
    requireCondition(
      sourceInput?.sha256 === artifact.sourceDigest,
      "AWS_READINESS_EXACT_GIT_SOURCE"
    );
    artifact.bundledPackages.forEach((packageName) =>
      bundledPackageUnion.add(packageName)
    );
    const expectedArtifactFile =
      `${name}-${artifact.artifactDigest}.zip`;
    const expectedArtifactPath =
      `dist/aws/${expectedArtifactFile}`;
    requireCondition(
      artifact.artifactFile === expectedArtifactFile &&
        artifact.artifactPath === expectedArtifactPath &&
        artifact.suggestedS3Key ===
          `gate2/${sourceCommit}/${expectedArtifactFile}`,
      "AWS_READINESS_ARTIFACT_PATH"
    );

    const source = resolvedFile(
      projectRoot,
      expectedSourcePath,
      "AWS_READINESS_ARTIFACT_SOURCE"
    );
    const archive = resolvedFile(
      projectRoot,
      expectedArtifactPath,
      "AWS_READINESS_ARTIFACT_FILE"
    );
    const archiveBuffer = fs.readFileSync(archive.resolved);
    requireCondition(
      sha256File(source.resolved) === artifact.sourceDigest &&
        archive.stat.size === artifact.artifactBytes &&
        sha256(archiveBuffer) === artifact.artifactDigest &&
        sha256(archiveBuffer, "base64") ===
          artifact.artifactCodeSha256,
      "AWS_READINESS_ARTIFACT_DIGEST"
    );
    const archiveEntries = validateStoredTwoFileZip(archiveBuffer);
    requireCondition(
      archiveEntries["THIRD_PARTY_NOTICES.txt"].equals(
        thirdPartyNotices.bytes
      ) && archiveEntries["index.js"].length > 0,
      "AWS_READINESS_ARTIFACT_NOTICE"
    );
    acceptedArtifacts[name] = {
      sourceDigest: artifact.sourceDigest,
      artifactDigest: artifact.artifactDigest,
      artifactCodeSha256: artifact.artifactCodeSha256,
      artifactBytes: artifact.artifactBytes,
      artifactPath: expectedArtifactPath,
      bundledPackages: artifact.bundledPackages,
      exactGitInputs: acceptedGitInputs,
      suggestedS3Key: artifact.suggestedS3Key
    };
  }
  const providerRuntime = receipt.evidenceProviderRuntime;
  const providerInputs = Array.isArray(providerRuntime?.exactGitInputs)
    ? providerRuntime.exactGitInputs
    : [];
  requireCondition(
    exactKeys(providerRuntime, [
      "bundledPackages",
      "bytes",
      "exactGitInputs",
      "externalImports",
      "path",
      "sha256"
    ]) &&
      HEX_64.test(providerRuntime.sha256) &&
      providerRuntime.path ===
        `dist/aws/evidence-provider-${providerRuntime.sha256}.mjs` &&
      Number.isSafeInteger(providerRuntime.bytes) &&
      providerRuntime.bytes > 0 &&
      providerRuntime.bytes <= 5 * 1024 * 1024 &&
      Array.isArray(providerRuntime.bundledPackages) &&
      providerRuntime.bundledPackages.length > 0 &&
      JSON.stringify(providerRuntime.bundledPackages) ===
        JSON.stringify([...providerRuntime.bundledPackages].sort()) &&
      new Set(providerRuntime.bundledPackages).size ===
        providerRuntime.bundledPackages.length &&
      providerRuntime.bundledPackages.every(
        (packageName) =>
          typeof packageName === "string" &&
          /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/i.test(
            packageName
          )
      ) &&
      providerInputs.length >= 2 &&
      providerInputs.length <= 64 &&
      JSON.stringify(providerInputs.map((input) => input?.path)) ===
        JSON.stringify(providerInputs.map((input) => input?.path).sort()) &&
      new Set(providerInputs.map((input) => input?.path)).size ===
        providerInputs.length &&
      Array.isArray(providerRuntime.externalImports) &&
      providerRuntime.externalImports.length > 0 &&
      JSON.stringify(providerRuntime.externalImports) ===
        JSON.stringify([...providerRuntime.externalImports].sort()) &&
      new Set(providerRuntime.externalImports).size ===
        providerRuntime.externalImports.length &&
      providerRuntime.externalImports.every((candidate) =>
        /^node:[a-z0-9_./-]+$/.test(candidate)
      ),
    "AWS_READINESS_PROVIDER_RUNTIME_RECEIPT"
  );
  const acceptedProviderInputs = [];
  for (const input of providerInputs) {
    requireCondition(
      exactKeys(input, ["gitBlobId", "path", "sha256"]) &&
        /^[0-9a-f]{40}$/.test(input.gitBlobId) &&
        HEX_64.test(input.sha256) &&
        typeof input.path === "string" &&
        !input.path.split("/").includes("node_modules"),
      "AWS_READINESS_PROVIDER_RUNTIME_INPUT"
    );
    const inputFile = resolvedFile(
      projectRoot,
      input.path,
      "AWS_READINESS_PROVIDER_RUNTIME_INPUT_FILE"
    );
    const inputBytes = fs.readFileSync(inputFile.resolved);
    requireCondition(
      sha256(inputBytes) === input.sha256 &&
        gitBlobId(inputBytes) === input.gitBlobId,
      "AWS_READINESS_PROVIDER_RUNTIME_INPUT_DIGEST"
    );
    acceptedProviderInputs.push({ ...input });
  }
  requireCondition(
    providerInputs.some(
      (input) => input.path === "scripts/lib/aws-provider-bundle-entry.js"
    ) &&
      providerInputs.some(
        (input) => input.path === "scripts/lib/aws-provider-runtime.js"
      ),
    "AWS_READINESS_PROVIDER_RUNTIME_SOURCE"
  );
  const providerFile = resolvedFile(
    projectRoot,
    providerRuntime.path,
    "AWS_READINESS_PROVIDER_RUNTIME_FILE"
  );
  requireCondition(
    providerFile.stat.size === providerRuntime.bytes &&
      sha256File(providerFile.resolved) === providerRuntime.sha256,
    "AWS_READINESS_PROVIDER_RUNTIME_DIGEST"
  );
  providerRuntime.bundledPackages.forEach((packageName) =>
    bundledPackageUnion.add(packageName)
  );
  requireCondition(
    JSON.stringify([...bundledPackageUnion].sort()) ===
      JSON.stringify(thirdPartyNotices.accepted.packageNames),
    "AWS_READINESS_BUNDLED_PACKAGE_UNION"
  );

  return {
    schemaVersion: receipt.schemaVersion,
    mode: receipt.mode,
    projectSourceMode: receipt.projectSourceMode,
    buildControlInputs: acceptedBuildControlInputs,
    dependencySnapshot,
    packageJsonDigest: receipt.packageJsonDigest,
    packageLockDigest: receipt.packageLockDigest,
    toolchain,
    thirdPartyNotices: thirdPartyNotices.accepted,
    evidenceProviderRuntime: {
      bundledPackages: providerRuntime.bundledPackages,
      bytes: providerRuntime.bytes,
      exactGitInputs: acceptedProviderInputs,
      externalImports: providerRuntime.externalImports,
      path: providerRuntime.path,
      sha256: providerRuntime.sha256
    },
    bootstrapTemplate: validateTemplateReceipt(
      projectRoot,
      receipt.bootstrapTemplate,
      "infra/aws/bootstrap-template.json",
      "AWS_READINESS_BOOTSTRAP_TEMPLATE"
    ),
    gate2Template: validateTemplateReceipt(
      projectRoot,
      receipt.gate2Template,
      "infra/aws/gate2-template.json",
      "AWS_READINESS_GATE2_TEMPLATE"
    ),
    artifacts: acceptedArtifacts
  };
}

export function validateAuditReport(report) {
  const vulnerabilities = report?.metadata?.vulnerabilities;
  const expectedKeys = [
    "critical",
    "high",
    "info",
    "low",
    "moderate",
    "total"
  ];
  requireCondition(
    vulnerabilities &&
      typeof vulnerabilities === "object" &&
      !Array.isArray(vulnerabilities) &&
      expectedKeys.every(
        (key) =>
          Number.isSafeInteger(vulnerabilities[key]) &&
          vulnerabilities[key] === 0
      ),
    "AWS_READINESS_AUDIT"
  );
  return {
    status: "PASS",
    knownVulnerabilities: 0
  };
}

export function validateReleaseProvenance(
  receipt,
  { sourceCommit, treeDigest }
) {
  const source = receipt?.source;
  const history = receipt?.history;
  const trackedTree = receipt?.trackedTree;
  const claims = receipt?.claims;
  const claimStates = claims?.claimStates;
  const claimsChecks = claims?.checks;
  const cost = receipt?.cost;
  const governance = receipt?.governance;
  const governanceChecks = governance?.checks;
  const privacy = receipt?.privacy;
  const privacyChecks = privacy?.checks;
  const rights = receipt?.rights;
  const rightsChecks = rights?.checks;
  const accessibility = receipt?.accessibility;
  const accessibilityChecks = accessibility?.checks;
  const accessibilitySummary = accessibility?.summary;
  const security = receipt?.security;
  const securityChecks = security?.checks;
  const submission = receipt?.submission;
  const submissionChecks = submission?.checks;
  const dependencies = receipt?.dependencies;
  const installedTree = dependencies?.installedTree;
  const inventory = dependencies?.inventory;
  const notices = dependencies?.bundledThirdPartyNotices;
  const checks = receipt?.checks;
  let costContractValid = false;
  try {
    validateReleaseCostReceipt(cost);
    costContractValid = true;
  } catch {
    costContractValid = false;
  }
  let securityContractValid = false;
  try {
    validateReleaseSecurityReceipt(security);
    securityContractValid = true;
  } catch {
    securityContractValid = false;
  }
  requireCondition(
    exactKeys(receipt, [
      "accessibility",
      "claims",
      "checks",
      "claimBoundary",
      "cost",
      "dependencies",
      "governance",
      "history",
      "privacy",
      "rights",
      "schemaVersion",
      "security",
      "source",
      "status",
      "submission",
      "trackedTree"
    ]) &&
      exactKeys(source, [
        "branch",
        "cleanRoomRoot",
        "commit",
        "officialRemote",
        "originMain",
        "tree"
      ]) &&
      exactKeys(history, [
        "alternateObjectDatabaseCount",
        "commitCount",
        "filesystemMonitorDisabled",
        "headAuthorTime",
        "headCommitterTime",
        "legacyGraftFilePresent",
        "mergeCommitCount",
        "objectIntegrity",
        "replaceRefCount",
        "replacementObjectsDisabled",
        "rootAuthorTime",
        "rootCommit",
        "rootCommitterTime",
        "shallow"
      ]) &&
      exactKeys(trackedTree, [
        "assumeUnchangedEntryCount",
        "executableFileCount",
        "fileCount",
        "gitlinkCount",
        "indexEntryCount",
        "regularFileCount",
        "skipWorktreeEntryCount",
        "symlinkCount"
      ]) &&
      exactKeys(claims, [
        "checks",
        "claimBoundary",
        "claimCount",
        "claimStates",
        "externalUrls",
        "finalReleaseReady",
        "finalReleaseRequirements",
        "manifestPath",
        "manifestSha256",
        "proofManifestSha256",
        "reviewedOn",
        "schemaVersion",
        "status",
        "stopTokenCount",
        "surfaceCount",
        "uncheckedGateCount"
      ]) &&
      exactKeys(claimStates, ["PARTIAL", "PENDING", "VERIFIED"]) &&
      exactKeys(claimsChecks, [
        "canonicalManifest",
        "claimsLedgerMatchesProofManifest",
        "currentDraftStateExplicit",
        "exactSurfaceHashes",
        "localAndHostedAwsBoundariesExplicit",
        "publicLinksConstrained",
        "submissionStopTokensPreserved",
        "syntheticScopeExplicit"
      ]) &&
      costContractValid &&
      exactKeys(governance, [
        "checks",
        "claimBoundary",
        "finalReleaseReady",
        "finalReleaseRequirements",
        "manifestPath",
        "manifestSha256",
        "observedAt",
        "requiredApprovingReviewCount",
        "requiredCheckCount",
        "reviewedOn",
        "schemaVersion",
        "snapshotPath",
        "snapshotSha256",
        "sourceCommit",
        "sourceTree",
        "status",
        "surfaceCount"
      ]) &&
      exactKeys(governanceChecks, [
        "branchProtectionSnapshotExact",
        "canonicalManifest",
        "canonicalSnapshot",
        "exactSurfaceHashes",
        "localWorkflowIdentityExact",
        "nonfinalBoundaryPreserved",
        "publicBoundariesExplicit",
        "publicRepositoryCoordinatesExact",
        "requiredCiSnapshotExact",
        "securitySnapshotExact"
      ]) &&
      exactKeys(privacy, [
        "allowanceCount",
        "checks",
        "claimBoundary",
        "commitCount",
        "commitIdentityCount",
        "finalReleaseReady",
        "finalReleaseRequirements",
        "findingCount",
        "manifestPath",
        "manifestSha256",
        "reachableBlobCount",
        "reviewedOn",
        "scannedBytes",
        "schemaVersion",
        "sourceCommit",
        "status",
        "trackedFileCount",
        "treeDigest"
      ]) &&
      exactKeys(privacyChecks, [
        "canonicalManifest",
        "cleanBeforeAndAfter",
        "commitIdentitiesReviewed",
        "everyReachableBlobScanned",
        "fullReachableHistory",
        "highConfidenceSignaturesReviewed",
        "trackedPathPolicy"
      ]) &&
      exactKeys(rights, [
        "checks",
        "claimBoundary",
        "currentClearedFileCount",
        "distributedFileCount",
        "finalReleaseReady",
        "finalReleaseRequirements",
        "interimOnlyFileCount",
        "ledgerSha256",
        "manifestPath",
        "manifestSha256",
        "prohibitedSourceDigestCount",
        "repositoryMediaFileCount",
        "reviewedOn",
        "schemaVersion",
        "status",
        "trackedFileCount"
      ]) &&
      exactKeys(rightsChecks, [
        "awsDistributionBindingsExact",
        "blockedPlannedPathsAbsent",
        "canonicalManifest",
        "completeRepositoryMediaInventory",
        "exactFileHashes",
        "ledgerBindings",
        "localServerBindingsExact",
        "prohibitedReferenceBytesAbsent",
        "publicDemoCspRejectsDataImages",
        "redistributedFontsAbsent",
        "remoteEmbeddedMediaAbsent"
      ]) &&
      exactKeys(accessibility, [
        "checks",
        "claimBoundary",
        "contrast",
        "finalReleaseReady",
        "remainingRequirements",
        "reviewedFiles",
        "rightsManifestSha256",
        "schemaVersion",
        "standardTarget",
        "status",
        "summary"
      ]) &&
      exactKeys(accessibilitySummary, [
        "buttonCount",
        "headingCount",
        "imageCount",
        "landmarkSectionCount"
      ]) &&
      exactKeys(accessibilityChecks, [
        "architectureAlternativePresent",
        "contrastPairsPass",
        "controlsFailClosedDuringLoad",
        "documentLanguageAndMetadata",
        "exactRightsBoundSources",
        "focusVisibility",
        "hiddenPageAutoplayPause",
        "keyboardPresenterPath",
        "landmarksAndHeadingOrder",
        "liveStatusAnnouncements",
        "minimumControlHeight",
        "namedImagesAndControls",
        "reducedMotionSourceSupport",
        "responsiveReflowGuards",
        "skipNavigation",
        "textualStatusLabelsPresent",
        "uniqueIdsAndAriaReferences",
        "unsafeDynamicHtmlAbsent"
      ]) &&
      securityContractValid &&
      exactKeys(submission, [
        "checklistItemCount",
        "checks",
        "claimBoundary",
        "finalReleaseReady",
        "finalReleaseRequirements",
        "manifestPath",
        "manifestSha256",
        "officialCoordinateCount",
        "reviewedOn",
        "schemaVersion",
        "status",
        "stopTokenOccurrenceCount",
        "surfaceCount",
        "uncheckedChecklistItemCount",
        "uniqueStopTokenCount"
      ]) &&
      exactKeys(submissionChecks, [
        "allHardPublishGatesUnchecked",
        "canonicalDraftStatus",
        "canonicalManifest",
        "contestMatrixRemainsBlocked",
        "exactStopTokenVocabulary",
        "exactSurfaceHashes",
        "liveAndOwnerFieldsUnresolved",
        "officialScheduleInternallyConsistent",
        "releaseClaimsPacketBindingExact",
        "releasePlanRemainsFailClosed",
        "rightsAndClaimsRemainNonfinal",
        "submissionCoordinatesExact"
      ]) &&
      exactKeys(dependencies, [
        "bundledThirdPartyNotices",
        "installedTree",
        "inventory"
      ]) &&
      exactKeys(installedTree, [
        "extraPackageCount",
        "installedDevelopmentOnlyCount",
        "installedOptionalCount",
        "installedPackageCount",
        "installedRuntimeCount",
        "lockedPackageCount",
        "mismatchedPackageCount",
        "omittedOptionalCount",
        "packageLockSha256",
        "status"
      ]) &&
      exactKeys(inventory, [
        "developmentOnlyCount",
        "installScriptCount",
        "inventorySha256",
        "licenses",
        "optionalCount",
        "packageCount",
        "runtimeCount",
        "schema",
        "sourceLockSha256",
        "status"
      ]) &&
      exactKeys(notices, [
        "artifactPackages",
        "fallbackCount",
        "licenseTextCount",
        "licenses",
        "noticeBytes",
        "noticePath",
        "noticeSha256",
        "packageCount",
        "packageLockSha256",
        "status"
      ]) &&
      exactKeys(checks, [
        "alternateObjectDatabasesAbsent",
        "bundledThirdPartyNoticesMatchInputs",
        "cleanBeforeAndAfter",
        "currentClaimSurfacesVerified",
        "currentCostGuardsVerified",
        "currentSourceSecurityVerified",
        "currentSurfaceRightsVerified",
        "dependencyInventoryMatchesLock",
        "fullSingleRootHistory",
        "installedTreeMatchesLock",
        "legacyGraftsAbsent",
        "objectIntegrity",
        "officialCleanCheckout",
        "replaceRefsAbsent",
        "releasePrivacyVerified",
        "repositoryGovernanceSnapshotVerified",
        "staticAccessibilityVerified",
        "submodulesAbsent",
        "submissionDraftFailClosed",
        "trackedSymlinksAbsent"
      ]) &&
      receipt.schemaVersion === "tideproof.release-provenance.v8" &&
      receipt.status === "PASS" &&
      typeof receipt.claimBoundary === "string" &&
      receipt.claimBoundary.length > 0 &&
      source.commit === sourceCommit &&
      source.tree === treeDigest &&
      source.originMain === sourceCommit &&
      source.branch === EXPECTED_BRANCH &&
      isOfficialRemote(source.officialRemote) &&
      source.cleanRoomRoot === CLEAN_ROOM_ROOT &&
      history.rootCommit === CLEAN_ROOM_ROOT &&
      Number.isSafeInteger(history.commitCount) &&
      history.commitCount > 0 &&
      Number.isSafeInteger(history.mergeCommitCount) &&
      history.mergeCommitCount >= 0 &&
      history.mergeCommitCount < history.commitCount &&
      history.shallow === false &&
      history.replaceRefCount === 0 &&
      history.replacementObjectsDisabled === true &&
      history.filesystemMonitorDisabled === true &&
      history.legacyGraftFilePresent === false &&
      history.alternateObjectDatabaseCount === 0 &&
      history.objectIntegrity === true &&
      [
        history.rootAuthorTime,
        history.rootCommitterTime,
        history.headAuthorTime,
        history.headCommitterTime
      ].every((value) => Number.isFinite(Date.parse(value))) &&
      Number.isSafeInteger(trackedTree.fileCount) &&
      trackedTree.fileCount > 0 &&
      trackedTree.regularFileCount === trackedTree.fileCount &&
      Number.isSafeInteger(trackedTree.executableFileCount) &&
      trackedTree.executableFileCount >= 0 &&
      trackedTree.executableFileCount <= trackedTree.fileCount &&
      trackedTree.symlinkCount === 0 &&
      trackedTree.gitlinkCount === 0 &&
      trackedTree.indexEntryCount === trackedTree.fileCount &&
      trackedTree.skipWorktreeEntryCount === 0 &&
      trackedTree.assumeUnchangedEntryCount === 0 &&
      claims.schemaVersion ===
        "tideproof.release-claims-verification.v1" &&
      claims.status === "CURRENT_PUBLIC_CLAIMS_PASS" &&
      claims.finalReleaseReady === false &&
      /^\d{4}-\d{2}-\d{2}$/.test(claims.reviewedOn) &&
      claims.manifestPath === "RELEASE_CLAIMS_MANIFEST.json" &&
      HEX_64.test(claims.manifestSha256) &&
      HEX_64.test(claims.proofManifestSha256) &&
      claims.claimCount === 12 &&
      claimStates.VERIFIED === 5 &&
      claimStates.PARTIAL === 7 &&
      claimStates.PENDING === 0 &&
      claims.surfaceCount === 13 &&
      claims.stopTokenCount === 13 &&
      claims.uncheckedGateCount === 14 &&
      Array.isArray(claims.externalUrls) &&
      claims.externalUrls.length === 6 &&
      claims.externalUrls.every(
        (url) => typeof url === "string" && /^https?:\/\//.test(url)
      ) &&
      JSON.stringify(claims.externalUrls) ===
        JSON.stringify([...claims.externalUrls].sort()) &&
      Array.isArray(claims.finalReleaseRequirements) &&
      claims.finalReleaseRequirements.length === 2 &&
      Object.values(claimsChecks).every((value) => value === true) &&
      typeof claims.claimBoundary === "string" &&
      claims.claimBoundary.length > 0 &&
      governance.schemaVersion ===
        "tideproof.release-governance-verification.v1" &&
      governance.status === "CURRENT_REPOSITORY_GOVERNANCE_PASS" &&
      governance.finalReleaseReady === false &&
      /^\d{4}-\d{2}-\d{2}$/.test(governance.reviewedOn) &&
      governance.manifestPath === "RELEASE_GOVERNANCE_MANIFEST.json" &&
      HEX_64.test(governance.manifestSha256) &&
      governance.snapshotPath ===
        "evidence/github-release-governance-2026-08-01.json" &&
      HEX_64.test(governance.snapshotSha256) &&
      Number.isFinite(Date.parse(governance.observedAt)) &&
      HEX_40.test(governance.sourceCommit) &&
      HEX_40.test(governance.sourceTree) &&
      governance.surfaceCount === 5 &&
      governance.requiredCheckCount === 1 &&
      governance.requiredApprovingReviewCount === 0 &&
      Array.isArray(governance.finalReleaseRequirements) &&
      governance.finalReleaseRequirements.length === 3 &&
      Object.values(governanceChecks).every((value) => value === true) &&
      typeof governance.claimBoundary === "string" &&
      governance.claimBoundary.length > 0 &&
      privacy.schemaVersion ===
        "tideproof.release-privacy-verification.v1" &&
      privacy.status === "CURRENT_PUBLIC_HISTORY_PASS" &&
      privacy.finalReleaseReady === false &&
      privacy.sourceCommit === sourceCommit &&
      privacy.treeDigest === treeDigest &&
      /^\d{4}-\d{2}-\d{2}$/.test(privacy.reviewedOn) &&
      privacy.manifestPath === "RELEASE_PRIVACY_MANIFEST.json" &&
      HEX_64.test(privacy.manifestSha256) &&
      Number.isSafeInteger(privacy.commitCount) &&
      privacy.commitCount > 0 &&
      Number.isSafeInteger(privacy.commitIdentityCount) &&
      privacy.commitIdentityCount > 0 &&
      Number.isSafeInteger(privacy.trackedFileCount) &&
      privacy.trackedFileCount > 0 &&
      Number.isSafeInteger(privacy.reachableBlobCount) &&
      privacy.reachableBlobCount >= privacy.trackedFileCount &&
      Number.isSafeInteger(privacy.scannedBytes) &&
      privacy.scannedBytes > 0 &&
      Number.isSafeInteger(privacy.findingCount) &&
      privacy.findingCount >= 0 &&
      Number.isSafeInteger(privacy.allowanceCount) &&
      privacy.allowanceCount > 0 &&
      Array.isArray(privacy.finalReleaseRequirements) &&
      privacy.finalReleaseRequirements.length === 2 &&
      Object.values(privacyChecks).every((value) => value === true) &&
      typeof privacy.claimBoundary === "string" &&
      privacy.claimBoundary.length > 0 &&
      rights.schemaVersion ===
        "tideproof.release-rights-verification.v1" &&
      rights.status === "CURRENT_SURFACES_PASS" &&
      rights.finalReleaseReady === false &&
      /^\d{4}-\d{2}-\d{2}$/.test(rights.reviewedOn) &&
      rights.manifestPath === "docs/media/RIGHTS_MANIFEST.json" &&
      HEX_64.test(rights.manifestSha256) &&
      HEX_64.test(rights.ledgerSha256) &&
      Number.isSafeInteger(rights.distributedFileCount) &&
      rights.distributedFileCount > 0 &&
      Number.isSafeInteger(rights.currentClearedFileCount) &&
      rights.currentClearedFileCount > 0 &&
      Number.isSafeInteger(rights.interimOnlyFileCount) &&
      rights.interimOnlyFileCount === 0 &&
      rights.currentClearedFileCount + rights.interimOnlyFileCount ===
        rights.distributedFileCount &&
      Number.isSafeInteger(rights.repositoryMediaFileCount) &&
      rights.repositoryMediaFileCount > 0 &&
      Number.isSafeInteger(rights.trackedFileCount) &&
      rights.trackedFileCount >= rights.distributedFileCount &&
      Number.isSafeInteger(rights.prohibitedSourceDigestCount) &&
      rights.prohibitedSourceDigestCount > 0 &&
      Array.isArray(rights.finalReleaseRequirements) &&
      rights.finalReleaseRequirements.length === 2 &&
      rights.finalReleaseRequirements[0] ===
        "Exact-release private rights review receipt." &&
      rights.finalReleaseRequirements[1] ===
        "Final-production asset decision recorded as cleared exact hashes or deliberate omission." &&
      typeof rights.claimBoundary === "string" &&
      rights.claimBoundary.length > 0 &&
      Object.values(rightsChecks).every((value) => value === true) &&
      accessibility.schemaVersion ===
        "tideproof.accessibility-static.v1" &&
      accessibility.status === "STATIC_SOURCE_PASS" &&
      accessibility.finalReleaseReady === false &&
      accessibility.standardTarget === "WCAG_2_2_AA" &&
      accessibility.rightsManifestSha256 === rights.manifestSha256 &&
      Array.isArray(accessibility.reviewedFiles) &&
      accessibility.reviewedFiles.length === 4 &&
      accessibility.reviewedFiles.every(
        (file) =>
          exactKeys(file, ["id", "path", "sha256"]) &&
          HEX_64.test(file.sha256)
      ) &&
      accessibility.reviewedFiles
        .map((file) => `${file.id}:${file.path}`)
        .join("\n") ===
        [
          "architecture-svg:docs/media/architecture.svg",
          "browser-app:web/app.js",
          "browser-document:web/index.html",
          "browser-styles:web/styles.css"
        ].join("\n") &&
      Array.isArray(accessibility.contrast) &&
      accessibility.contrast.length === 11 &&
      accessibility.contrast.every(
        (pair) =>
          exactKeys(pair, [
            "background",
            "backgroundToken",
            "foreground",
            "foregroundToken",
            "id",
            "minimumRatio",
            "ratio"
          ]) &&
          /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(pair.id) &&
          /^#[0-9a-f]{6}$/.test(pair.foreground) &&
          /^#[0-9a-f]{6}$/.test(pair.background) &&
          [3, 4.5].includes(pair.minimumRatio) &&
          Number.isFinite(pair.ratio) &&
          pair.ratio >= pair.minimumRatio
      ) &&
      new Set(accessibility.contrast.map((pair) => pair.id)).size === 11 &&
      accessibilitySummary.headingCount === 9 &&
      accessibilitySummary.imageCount === 1 &&
      accessibilitySummary.buttonCount === 7 &&
      accessibilitySummary.landmarkSectionCount === 5 &&
      Array.isArray(accessibility.remainingRequirements) &&
      accessibility.remainingRequirements.length === 3 &&
      accessibility.remainingRequirements[0] ===
        "Automated browser accessibility scan on the exact public release." &&
      accessibility.remainingRequirements[1] ===
        "Keyboard-only, 200% zoom, mobile reflow, and reduced-motion private review on the exact public release." &&
      accessibility.remainingRequirements[2] ===
        "Screen-reader review on the exact public release." &&
      Object.values(accessibilityChecks).every((value) => value === true) &&
      typeof accessibility.claimBoundary === "string" &&
      accessibility.claimBoundary.length > 0 &&
      submission.schemaVersion ===
        "tideproof.release-submission-verification.v1" &&
      submission.status === "DRAFT_SAFELY_BLOCKED" &&
      submission.finalReleaseReady === false &&
      /^\d{4}-\d{2}-\d{2}$/.test(submission.reviewedOn) &&
      submission.manifestPath === "RELEASE_SUBMISSION_MANIFEST.json" &&
      HEX_64.test(submission.manifestSha256) &&
      submission.surfaceCount === 7 &&
      submission.checklistItemCount === 14 &&
      submission.uncheckedChecklistItemCount === 14 &&
      submission.stopTokenOccurrenceCount === 13 &&
      submission.uniqueStopTokenCount === 12 &&
      submission.officialCoordinateCount === 11 &&
      Array.isArray(submission.finalReleaseRequirements) &&
      submission.finalReleaseRequirements.length === 4 &&
      Object.values(submissionChecks).every((value) => value === true) &&
      typeof submission.claimBoundary === "string" &&
      submission.claimBoundary.length > 0 &&
      installedTree.status === "PASS" &&
      HEX_64.test(installedTree.packageLockSha256) &&
      Number.isSafeInteger(installedTree.lockedPackageCount) &&
      installedTree.lockedPackageCount > 0 &&
      Number.isSafeInteger(installedTree.installedPackageCount) &&
      installedTree.installedPackageCount > 0 &&
      Number.isSafeInteger(installedTree.installedRuntimeCount) &&
      installedTree.installedRuntimeCount > 0 &&
      Number.isSafeInteger(installedTree.installedDevelopmentOnlyCount) &&
      installedTree.installedDevelopmentOnlyCount >= 0 &&
      Number.isSafeInteger(installedTree.installedOptionalCount) &&
      installedTree.installedOptionalCount >= 0 &&
      Number.isSafeInteger(installedTree.omittedOptionalCount) &&
      installedTree.omittedOptionalCount >= 0 &&
      installedTree.installedRuntimeCount +
        installedTree.installedDevelopmentOnlyCount ===
        installedTree.installedPackageCount &&
      installedTree.installedPackageCount +
        installedTree.omittedOptionalCount ===
        installedTree.lockedPackageCount &&
      installedTree.extraPackageCount === 0 &&
      installedTree.mismatchedPackageCount === 0 &&
      inventory.schema ===
        "tideproof.dependency-inventory-verification.v1" &&
      inventory.status === "PASS" &&
      inventory.sourceLockSha256 === installedTree.packageLockSha256 &&
      HEX_64.test(inventory.inventorySha256) &&
      inventory.packageCount === installedTree.lockedPackageCount &&
      inventory.runtimeCount + inventory.developmentOnlyCount ===
        inventory.packageCount &&
      inventory.optionalCount ===
        installedTree.installedOptionalCount +
          installedTree.omittedOptionalCount &&
      Number.isSafeInteger(inventory.installScriptCount) &&
      inventory.installScriptCount >= 0 &&
      inventory.licenses &&
      typeof inventory.licenses === "object" &&
      !Array.isArray(inventory.licenses) &&
      Object.entries(inventory.licenses).every(
        ([license, count]) =>
          ["0BSD", "Apache-2.0", "ISC", "MIT", "MPL-2.0"].includes(
            license
          ) &&
          Number.isSafeInteger(count) &&
          count > 0
      ) &&
      Object.values(inventory.licenses).reduce(
        (sum, count) => sum + count,
        0
      ) === inventory.packageCount &&
      notices.status === "PASS" &&
      notices.noticePath === "THIRD_PARTY_NOTICES.txt" &&
      notices.packageLockSha256 === installedTree.packageLockSha256 &&
      HEX_64.test(notices.noticeSha256) &&
      Number.isSafeInteger(notices.noticeBytes) &&
      notices.noticeBytes > 0 &&
      Number.isSafeInteger(notices.licenseTextCount) &&
      notices.licenseTextCount > 0 &&
      Number.isSafeInteger(notices.fallbackCount) &&
      notices.fallbackCount >= 0 &&
      notices.packageCount > 0 &&
      notices.packageCount <= installedTree.installedPackageCount &&
      notices.licenses &&
      typeof notices.licenses === "object" &&
      !Array.isArray(notices.licenses) &&
      Object.entries(notices.licenses).every(
        ([license, count]) =>
          ["0BSD", "Apache-2.0", "ISC", "MIT"].includes(license) &&
          Number.isSafeInteger(count) &&
          count > 0
      ) &&
      Object.values(notices.licenses).reduce(
        (sum, count) => sum + count,
        0
      ) === notices.packageCount &&
      notices.artifactPackages &&
      typeof notices.artifactPackages === "object" &&
      !Array.isArray(notices.artifactPackages) &&
      Object.keys(notices.artifactPackages).sort().join("\n") ===
        [...BUNDLED_COMPONENT_NAMES].sort().join("\n") &&
      Object.values(notices.artifactPackages).every(
        (packages) =>
          Array.isArray(packages) &&
          packages.every(
            (packageName) =>
              typeof packageName === "string" &&
              /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/i.test(
                packageName
              )
          ) &&
          new Set(packages).size === packages.length &&
          JSON.stringify(packages) === JSON.stringify([...packages].sort())
      ) &&
      Object.values(checks).every((value) => value === true),
    "AWS_READINESS_RELEASE_PROVENANCE"
  );
  return receipt;
}

export function validatePreflightReceipt(
  receipt,
  { sourceCommit, treeDigest }
) {
  const controls = receipt?.controls;
  const budget = controls?.budget;
  const currentCost = controls?.currentCost;
  const projectExposure = controls?.projectExposure;
  const artifactBucket = controls?.artifactBucket;
  const bedrock = controls?.bedrock;
  const notificationSet = Array.isArray(budget?.notifications)
    ? budget.notifications
        .map(
          (notification) =>
            `${notification?.metric}:${notification?.thresholdUsd}`
        )
        .sort()
        .join("\n")
    : "";
  requireCondition(
    exactKeys(receipt, [
      "claimBoundary",
      "controls",
      "observedAt",
      "privacy",
      "region",
      "schemaVersion",
      "sourceCommit",
      "status",
      "treeDigest"
    ]) &&
      exactKeys(controls, [
        "artifactBucket",
        "authenticatedAwsCaller",
        "bedrock",
        "bootstrapStack",
        "budget",
        "callerBinding",
        "currentCost",
        "mainGateTwoStack",
        "projectExposure"
      ]) &&
      exactKeys(controls?.bootstrapStack, ["name", "status"]) &&
      exactKeys(controls?.callerBinding, [
        "bindingDigest",
        "callerIdentityDigest",
        "contextDigest",
        "expectedIdentityDigest",
        "expectedPrincipalDigest",
        "principalIdDigest",
        "principalType"
      ]) &&
      exactKeys(budget, [
        "budgetReportedActualUsd",
        "conservativeObservedActualUsd",
        "costBasis",
        "coverageEnd",
        "coverageStart",
        "defaultCostTypes",
        "fixedLimit",
        "limitUsd",
        "name",
        "notifications",
        "scope",
        "timeUnit",
        "type"
      ]) &&
      exactKeys(currentCost, [
        "amountUsd",
        "estimated",
        "periodEndExclusive",
        "periodStart",
        "scope"
      ]) &&
      exactKeys(projectExposure, [
        "autoRenewReportedEnabled",
        "awsCostWindowStart",
        "ceilingUsd",
        "conservativeObservedTotalExposureUsd",
        "effectiveAwsSpendCeilingUsd",
        "recordedNonAwsSpendUsd",
        "recordedSpendBasis",
        "registrarReceiptVerified",
        "remainingExposureUsd",
        "scope"
      ]) &&
      exactKeys(artifactBucket, [
        "aes256AtRest",
        "bucketOwnerEnforced",
        "publicAccessBlocked",
        "tlsOnlyPolicy",
        "versioningEnabled"
      ]) &&
      exactKeys(controls?.mainGateTwoStack, ["name", "state"]) &&
      exactKeys(bedrock, [
        "catalogStatus",
        "modelId",
        "onDemandListed",
        "textInput",
        "textOutput"
      ]) &&
      receipt?.schemaVersion ===
      "tideproof.gate2.aws-preflight.v4" &&
      receipt.status === "PASS" &&
      receipt.sourceCommit === sourceCommit &&
      receipt.treeDigest === treeDigest &&
      receipt.region === EXPECTED_REGION &&
      Number.isFinite(Date.parse(receipt.observedAt)) &&
      typeof receipt.privacy === "string" &&
      receipt.privacy.length > 0 &&
      typeof receipt.claimBoundary === "string" &&
      receipt.claimBoundary.length > 0 &&
      controls?.authenticatedAwsCaller === true &&
      /^[0-9a-f]{64}$/.test(
        controls?.callerBinding?.bindingDigest
      ) &&
      /^[0-9a-f]{64}$/.test(
        controls?.callerBinding?.callerIdentityDigest
      ) &&
      /^[0-9a-f]{64}$/.test(
        controls?.callerBinding?.contextDigest
      ) &&
      controls?.callerBinding?.expectedIdentityDigest ===
        controls?.callerBinding?.callerIdentityDigest &&
      /^[0-9a-f]{64}$/.test(
        controls?.callerBinding?.expectedPrincipalDigest
      ) &&
      /^[0-9a-f]{64}$/.test(
        controls?.callerBinding?.principalIdDigest
      ) &&
      ["assumed-role", "iam-user"].includes(
        controls?.callerBinding?.principalType
      ) &&
      controls.bootstrapStack.name ===
        "tideproof-gate2-artifacts" &&
      ["CREATE_COMPLETE", "UPDATE_COMPLETE"].includes(
        controls.bootstrapStack.status
      ) &&
      controls?.mainGateTwoStack?.state === "ABSENT" &&
      controls?.bedrock?.catalogStatus === "ACTIVE" &&
      controls?.artifactBucket?.versioningEnabled === true &&
      controls?.artifactBucket?.aes256AtRest === true &&
      controls?.artifactBucket?.publicAccessBlocked === true &&
      controls?.artifactBucket?.bucketOwnerEnforced === true &&
      controls?.artifactBucket?.tlsOnlyPolicy === true &&
      Array.isArray(budget.notifications) &&
      budget.notifications.length === 4 &&
      notificationSet ===
        [
          "ACTUAL:1",
          "ACTUAL:5",
          "ACTUAL:10",
          "FORECASTED:15"
        ]
          .sort()
          .join("\n") &&
      budget.notifications.every((notification) =>
        exactKeys(notification, [
          "comparison",
          "emailRecipientCount",
          "metric",
          "thresholdType",
          "thresholdUsd"
        ]) &&
        notification.comparison === "GREATER_THAN" &&
        notification.thresholdType === "ABSOLUTE_VALUE" &&
        Number.isSafeInteger(notification.emailRecipientCount) &&
        notification.emailRecipientCount >= 1
      ) &&
      budget.name ===
        "tideproof-gate2-artifacts-account-safety" &&
      budget.scope === "ACCOUNT_WIDE" &&
      budget.type === "COST" &&
      budget.timeUnit === "MONTHLY" &&
      budget.costBasis === "UnblendedCost" &&
      budget.defaultCostTypes === true &&
      budget.fixedLimit === true &&
      Number(budget.limitUsd) === 15 &&
      currentCost.scope ===
        "ACCOUNT_WIDE_PROJECT_WINDOW_TO_DATE" &&
      Number.isFinite(Number(currentCost.amountUsd)) &&
      Number(currentCost.amountUsd) >= 0 &&
      Number(currentCost.amountUsd) < 13.14 &&
      projectExposure.scope ===
        "TIDEPROOF_TOTAL_APPROVED_EXPOSURE" &&
      Number(
        projectExposure.ceilingUsd
      ) === 25 &&
      Number(
        projectExposure.recordedNonAwsSpendUsd
      ) === 11.86 &&
      Number(
        projectExposure.effectiveAwsSpendCeilingUsd
      ) === 13.14 &&
      Number(
        projectExposure.conservativeObservedTotalExposureUsd
      ) < 25 &&
      projectExposure.registrarReceiptVerified === false &&
      projectExposure.autoRenewReportedEnabled === false &&
      controls.mainGateTwoStack.name === "tideproof-gate2" &&
      bedrock.modelId === "amazon.nova-micro-v1:0" &&
      bedrock.textInput === true &&
      bedrock.textOutput === true &&
      bedrock.onDemandListed === true,
    "AWS_READINESS_PREFLIGHT"
  );
  return receipt;
}

export function parseArguments(args) {
  if (args.length === 0) {
    return { localOnly: false };
  }
  if (args.length === 1 && args[0] === "--local-only") {
    return { localOnly: true };
  }
  throw new Error("AWS_READINESS_ARGUMENT");
}

function childEnvironment(
  sourceEnvironment,
  { awsAuthenticated = false } = {}
) {
  if (awsAuthenticated) {
    assertNoAwsEndpointOverrides(sourceEnvironment);
  }
  const environment = {};
  for (const [name, value] of Object.entries(sourceEnvironment)) {
    const normalizedName = name.toUpperCase();
    if (
      SAFE_CHILD_ENVIRONMENT_NAMES.has(name) ||
      (awsAuthenticated &&
        name === normalizedName &&
        AUTHENTICATED_AWS_ENVIRONMENT_NAMES.has(normalizedName))
    ) {
      environment[name] = value;
    }
  }
  environment.AWS_EC2_METADATA_DISABLED = "true";
  environment.AWS_IGNORE_CONFIGURED_ENDPOINT_URLS = "true";
  environment.AWS_PAGER = "";
  environment.AWS_CONFIG_FILE = "/dev/null";
  environment.AWS_SHARED_CREDENTIALS_FILE = "/dev/null";
  environment.GIT_CONFIG_GLOBAL = "/dev/null";
  environment.GIT_CONFIG_NOSYSTEM = "1";
  environment.GIT_TERMINAL_PROMPT = "0";
  environment.PATH = "/usr/bin:/bin";
  environment.TMPDIR = trustedTemporaryRoot();
  environment.npm_config_always_auth = "false";
  environment.npm_config_globalconfig =
    "/etc/tideproof-npm-globalconfig";
  environment.npm_config_ignore_scripts = "true";
  environment.npm_config_registry = "https://registry.npmjs.org/";
  environment.npm_config_script_shell = "/bin/sh";
  environment.npm_config_update_notifier = "false";
  environment.npm_config_userconfig =
    "/etc/tideproof-npm-userconfig";
  return environment;
}

function defaultRunner(projectRoot, sourceEnvironment = process.env) {
  requireCondition(
    !fs.existsSync("/etc/tideproof-npm-globalconfig") &&
      !fs.existsSync("/etc/tideproof-npm-userconfig"),
    "AWS_READINESS_NPM_CONFIGURATION"
  );
  const gitExecutable = trustedGitExecutable();
  const npmCli = exactNpmCli(sourceEnvironment);
  return (command, args, options = {}) => {
    requireCondition(
      command === "git" || command === "npm",
      "AWS_READINESS_COMMAND"
    );
    const executable = command === "git" ? gitExecutable : process.execPath;
    const exactArguments =
      command === "git"
        ? [...gitInvariantArguments(), ...args]
        : [npmCli, ...args];
    const environment = childEnvironment(sourceEnvironment, options);
    if (command === "git") {
      Object.assign(environment, gitEnvironment(environment));
    }
    return spawnSync(executable, exactArguments, {
      cwd: projectRoot,
      encoding: "utf8",
      env: environment,
      maxBuffer: 32 * 1024 * 1024
    });
  };
}

function checkedCommand(
  run,
  command,
  args,
  code,
  options = {}
) {
  const result = run(command, args, options);
  requireCondition(
    result &&
      !result.error &&
      result.status === 0 &&
      typeof result.stdout === "string",
    code
  );
  return result.stdout;
}

function textCommand(run, command, args, code) {
  return checkedCommand(run, command, args, code).trim();
}

function jsonCommand(
  run,
  command,
  args,
  code,
  options = {}
) {
  const output = checkedCommand(
    run,
    command,
    args,
    code,
    options
  );
  try {
    return JSON.parse(output);
  } catch {
    throw new Error(`${code}_JSON`);
  }
}

function fetchOfficialMain(run) {
  checkedCommand(
    run,
    "git",
    [
      "-c",
      "http.https://github.com/.extraheader=",
      "fetch",
      "--quiet",
      "--no-tags",
      "origin",
      "refs/heads/main:refs/remotes/origin/main"
    ],
    "AWS_READINESS_GIT_FETCH"
  );
}

function isOfficialRemote(value) {
  return (
    value === OFFICIAL_REMOTE ||
    value === OFFICIAL_REMOTE.slice(0, -4)
  );
}

function assertCheckout(run) {
  const remote = textCommand(
    run,
    "git",
    ["remote", "get-url", "origin"],
    "AWS_READINESS_GIT_REMOTE"
  );
  const branch = textCommand(
    run,
    "git",
    ["symbolic-ref", "--short", "HEAD"],
    "AWS_READINESS_GIT_BRANCH"
  );
  const status = textCommand(
    run,
    "git",
    ["status", "--short"],
    "AWS_READINESS_GIT_STATUS"
  );
  requireCondition(
    isOfficialRemote(remote) &&
      branch === EXPECTED_BRANCH &&
      status.length === 0,
    "AWS_READINESS_CHECKOUT"
  );
  fetchOfficialMain(run);
  const sourceCommit = textCommand(
    run,
    "git",
    ["rev-parse", "HEAD"],
    "AWS_READINESS_GIT_HEAD"
  );
  const originMain = textCommand(
    run,
    "git",
    ["rev-parse", "refs/remotes/origin/main"],
    "AWS_READINESS_GIT_ORIGIN_MAIN"
  );
  const treeDigest = textCommand(
    run,
    "git",
    ["rev-parse", "HEAD^{tree}"],
    "AWS_READINESS_GIT_TREE"
  );
  requireCondition(
    HEX_40.test(sourceCommit) &&
      HEX_40.test(originMain) &&
      HEX_40.test(treeDigest) &&
      sourceCommit === originMain,
    "AWS_READINESS_UPSTREAM"
  );
  return {
    sourceCommit,
    treeDigest,
    originMain
  };
}

function assertCheckoutUnchanged(run, initial) {
  fetchOfficialMain(run);
  const current = {
    sourceCommit: textCommand(
      run,
      "git",
      ["rev-parse", "HEAD"],
      "AWS_READINESS_FINAL_HEAD"
    ),
    originMain: textCommand(
      run,
      "git",
      ["rev-parse", "refs/remotes/origin/main"],
      "AWS_READINESS_FINAL_ORIGIN_MAIN"
    ),
    treeDigest: textCommand(
      run,
      "git",
      ["rev-parse", "HEAD^{tree}"],
      "AWS_READINESS_FINAL_TREE"
    ),
    status: textCommand(
      run,
      "git",
      ["status", "--short"],
      "AWS_READINESS_FINAL_STATUS"
    )
  };
  requireCondition(
    current.status.length === 0 &&
      current.sourceCommit === initial.sourceCommit &&
      current.originMain === initial.originMain &&
      current.treeDigest === initial.treeDigest,
    "AWS_READINESS_CHECKOUT_CHANGED"
  );
}

export async function runAwsReadiness({
  projectRoot = root,
  localOnly = false,
  now = () => new Date(),
  run = defaultRunner(projectRoot)
} = {}) {
  const checkout = assertCheckout(run);
  checkedCommand(
    run,
    "npm",
    [
      "ci",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund"
    ],
    "AWS_READINESS_NPM_CI"
  );
  const releaseProvenance = validateReleaseProvenance(
    jsonCommand(
      run,
      "npm",
      ["run", "--silent", "release:provenance"],
      "AWS_READINESS_RELEASE_PROVENANCE"
    ),
    checkout
  );
  checkedCommand(
    run,
    "npm",
    ["test"],
    "AWS_READINESS_TESTS"
  );
  const audit = validateAuditReport(
    jsonCommand(
      run,
      "npm",
      ["audit", "--json", "--audit-level=low"],
      "AWS_READINESS_NPM_AUDIT"
    )
  );
  const build = validateBuildReceipt(
    jsonCommand(
      run,
      "npm",
      ["run", "--silent", "build:gate2"],
      "AWS_READINESS_BUILD"
    ),
    {
      projectRoot,
      sourceCommit: checkout.sourceCommit,
      treeDigest: checkout.treeDigest
    }
  );
  const preflight = localOnly
    ? null
    : validatePreflightReceipt(
        jsonCommand(
          run,
          "npm",
          ["run", "--silent", "gate2:aws-preflight"],
          "AWS_READINESS_AWS_PREFLIGHT",
          { awsAuthenticated: true }
        ),
        checkout
      );
  assertCheckoutUnchanged(run, checkout);

  const observedAt = preflight?.observedAt ?? now().toISOString();
  requireCondition(
    Number.isFinite(Date.parse(observedAt)),
    "AWS_READINESS_OBSERVED_AT"
  );
  return {
    schemaVersion: "tideproof.gate2.aws-readiness.v1",
    status: localOnly ? "LOCAL_ONLY_PASS" : "PASS",
    mode: localOnly
      ? "LOCAL_VALIDATION_NO_AWS"
      : "READ_ONLY_AWS_RELEASE_GATE",
    observedAt,
    source: {
      commit: checkout.sourceCommit,
      tree: checkout.treeDigest,
      branch: EXPECTED_BRANCH,
      originMain: checkout.originMain,
      officialRemote: OFFICIAL_REMOTE
    },
    checks: {
      officialCheckout: true,
      cleanBeforeAndAfter: true,
      lockedInstall: true,
      dependencyLifecycleScripts: false,
      releaseProvenance: true,
      releasePrivacy: true,
      staticAccessibility: true,
      testsPassed: true,
      dependencyAudit: audit,
      exactHeadBuild: true,
      artifactSet: ARTIFACT_NAMES,
      artifactIntegrity: true,
      bundledThirdPartyNotices: true,
      awsPreflight: preflight ? "PASS" : "NOT_RUN"
    },
    releaseProvenance,
    build,
    awsPreflight: preflight,
    claimBoundary: localOnly
      ? "Local-only validation passed. AWS was not queried or mutated, and this is not authorization to upload or deploy."
      : "The exact official checkout, local suite, dependency audit, reproducible artifacts, and read-only AWS preflight passed. No AWS resource was mutated; upload and deployment remain separate reviewed actions."
  };
}

async function main() {
  const { localOnly } = parseArguments(process.argv.slice(2));
  const receipt = await runAwsReadiness({ localOnly });
  process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
}

const invokedPath = process.argv[1]
  ? path.resolve(process.argv[1])
  : "";
if (invokedPath === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    const message = String(error?.message ?? "");
    const code = /^AWS_READINESS_[A-Z0-9_]{1,120}$/.test(message)
      ? message
      : "AWS_READINESS_UNKNOWN";
    process.stderr.write(
      `TIDEPROOF_GATE2_AWS_READINESS_FAILED:${code}\n`
    );
    process.exitCode = 1;
  });
}

export const __test = Object.freeze({
  ARTIFACT_NAMES,
  CLEAN_ROOM_ROOT,
  EXPECTED_BRANCH,
  EXPECTED_REGION,
  OFFICIAL_REMOTE,
  childEnvironment,
  defaultRunner,
  gitBlobId,
  isOfficialRemote,
  validateStoredTwoFileZip
});
