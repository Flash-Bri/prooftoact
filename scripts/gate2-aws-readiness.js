import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

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
const SECRET_ENVIRONMENT_NAME =
  /(TOKEN|SECRET|PASSWORD|API_KEY|PRIVATE_KEY|CREDENTIAL)/i;
const APPLICATION_ENVIRONMENT_NAME = new RegExp(
  [
    "^(",
    "DATABASE_URL",
    "|PG(HOST|PORT|DATABASE|USER|PASSWORD|SERVICE|SERVICEFILE|PASSFILE)",
    "|COCKROACH_.+",
    "|CRDB_.+",
    "|OPENAI_.+",
    "|ANTHROPIC_.+",
    "|GOOGLE_.+",
    "|OPENCLAW_.+",
    "|CODEX_.+",
    "|GH_TOKEN",
    "|GITHUB_TOKEN",
    ")$"
  ].join(""),
  "i"
);
const TOOL_OVERRIDE_ENVIRONMENT_NAME =
  /^(?:BASH_ENV|CDPATH|DYLD_.+|ENV|GIT_.+|LD_PRELOAD|NODE_OPTIONS|NODE_PATH|NPM_CONFIG_.+)$/i;

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
    receipt?.path === expectedPath &&
      HEX_64.test(receipt.templateDigest) &&
      HEX_64.test(receipt.canonicalDigest) &&
      Number.isSafeInteger(receipt.bytes) &&
      receipt.bytes > 0,
    code
  );
  const file = resolvedFile(projectRoot, expectedPath, code);
  requireCondition(
    file.stat.size === receipt.bytes &&
      sha256File(file.resolved) === receipt.templateDigest,
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
    receipt?.schemaVersion === "tideproof.gate2-build.v3" &&
      receipt.mode === "CLEAN_ARTIFACT_BUILD" &&
      receipt.sourceCommit === sourceCommit &&
      receipt.treeDigest === treeDigest &&
      receipt.workingTreeClean === true &&
      receipt.workingTreeCleanBeforeGeneration === true &&
      receipt.archiveFormat === "ZIP_STORED_TWO_FILE_V2" &&
      HEX_64.test(receipt.packageLockDigest),
    "AWS_READINESS_BUILD_RECEIPT"
  );
  const packageLock = resolvedFile(
    projectRoot,
    "package-lock.json",
    "AWS_READINESS_PACKAGE_LOCK"
  );
  const thirdPartyNotices = validateThirdPartyNotices(
    projectRoot,
    receipt.thirdPartyNotices,
    receipt.packageLockDigest
  );
  requireCondition(
    sha256File(packageLock.resolved) ===
      receipt.packageLockDigest,
    "AWS_READINESS_PACKAGE_LOCK"
  );

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
    requireCondition(
      artifact?.sourcePath === expectedSourcePath &&
        HEX_64.test(artifact.sourceDigest) &&
        HEX_64.test(artifact.artifactDigest) &&
        typeof artifact.artifactCodeSha256 === "string" &&
        Number.isSafeInteger(artifact.artifactBytes) &&
        artifact.artifactBytes > 0 &&
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
      suggestedS3Key: artifact.suggestedS3Key
    };
  }
  requireCondition(
    JSON.stringify([...bundledPackageUnion].sort()) ===
      JSON.stringify(thirdPartyNotices.accepted.packageNames),
    "AWS_READINESS_BUNDLED_PACKAGE_UNION"
  );

  return {
    schemaVersion: receipt.schemaVersion,
    mode: receipt.mode,
    packageLockDigest: receipt.packageLockDigest,
    thirdPartyNotices: thirdPartyNotices.accepted,
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
  const dependencies = receipt?.dependencies;
  const installedTree = dependencies?.installedTree;
  const inventory = dependencies?.inventory;
  const notices = dependencies?.bundledThirdPartyNotices;
  const checks = receipt?.checks;
  requireCondition(
    exactKeys(receipt, [
      "checks",
      "claimBoundary",
      "dependencies",
      "history",
      "schemaVersion",
      "source",
      "status",
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
        "headAuthorTime",
        "headCommitterTime",
        "legacyGraftFilePresent",
        "mergeCommitCount",
        "objectIntegrity",
        "replaceRefCount",
        "rootAuthorTime",
        "rootCommit",
        "rootCommitterTime",
        "shallow"
      ]) &&
      exactKeys(trackedTree, [
        "executableFileCount",
        "fileCount",
        "gitlinkCount",
        "regularFileCount",
        "symlinkCount"
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
        "dependencyInventoryMatchesLock",
        "fullSingleRootHistory",
        "installedTreeMatchesLock",
        "legacyGraftsAbsent",
        "objectIntegrity",
        "officialCleanCheckout",
        "replaceRefsAbsent",
        "submodulesAbsent",
        "trackedSymlinksAbsent"
      ]) &&
      receipt.schemaVersion === "tideproof.release-provenance.v1" &&
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
          ["0BSD", "Apache-2.0", "ISC", "MIT"].includes(license) &&
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
        [...ARTIFACT_NAMES].sort().join("\n") &&
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
        "currentCost",
        "mainGateTwoStack",
        "projectExposure"
      ]) &&
      exactKeys(controls?.bootstrapStack, ["name", "status"]) &&
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
      "tideproof.gate2.aws-preflight.v3" &&
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
  const environment = {};
  for (const [name, value] of Object.entries(sourceEnvironment)) {
    if (
      (name.startsWith("AWS_") && !awsAuthenticated) ||
      (!name.startsWith("AWS_") &&
        (SECRET_ENVIRONMENT_NAME.test(name) ||
          APPLICATION_ENVIRONMENT_NAME.test(name) ||
          TOOL_OVERRIDE_ENVIRONMENT_NAME.test(name)))
    ) {
      continue;
    }
    environment[name] = value;
  }
  environment.AWS_EC2_METADATA_DISABLED = "true";
  environment.AWS_PAGER = "";
  environment.GIT_CONFIG_GLOBAL = "/dev/null";
  environment.GIT_CONFIG_NOSYSTEM = "1";
  environment.GIT_TERMINAL_PROMPT = "0";
  environment.npm_config_always_auth = "false";
  environment.npm_config_registry = "https://registry.npmjs.org/";
  environment.npm_config_update_notifier = "false";
  environment.npm_config_userconfig = "/dev/null";
  if (!awsAuthenticated) {
    environment.AWS_CONFIG_FILE = "/dev/null";
    environment.AWS_SHARED_CREDENTIALS_FILE = "/dev/null";
  }
  return environment;
}

function defaultRunner(projectRoot) {
  return (command, args, options) =>
    spawnSync(command, args, {
      cwd: projectRoot,
      encoding: "utf8",
      env: childEnvironment(process.env, options),
      maxBuffer: 32 * 1024 * 1024
    });
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
  isOfficialRemote,
  validateStoredTwoFileZip
});
