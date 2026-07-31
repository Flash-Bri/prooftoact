import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const DEFAULT_ROOT = fileURLToPath(new URL("../..", import.meta.url));
const LOCK_PATH = "package-lock.json";
const NOTICE_PATH = "THIRD_PARTY_NOTICES.txt";
const RECEIPT_SCHEMA = "tideproof.bundled-third-party-notices.v1";
const PACKAGE_NAME = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/i;
const LEGAL_FILE = /^(?:licen[cs]e|copying|notice)(?:\.[a-z0-9._-]+)?$/i;
const PRIMARY_LICENSE_FILE = /^(?:licen[cs]e|copying)(?:\.[a-z0-9._-]+)?$/i;
const ALLOWED_LICENSES = new Set(["0BSD", "Apache-2.0", "ISC", "MIT"]);

const FALLBACKS = Object.freeze({
  "@aws-sdk/credential-provider-http": {
    expectedVersion: "3.972.66",
    license: "Apache-2.0",
    kind: "family-package-file",
    sourcePackage: "@aws-sdk/core",
    sourceFile: "LICENSE",
    reason:
      "The published package omits a license file; its manifest declares Apache-2.0 and the exact AWS SDK for JavaScript v3 family license is used."
  },
  "@aws-sdk/credential-provider-login": {
    expectedVersion: "3.972.71",
    license: "Apache-2.0",
    kind: "family-package-file",
    sourcePackage: "@aws-sdk/core",
    sourceFile: "LICENSE",
    reason:
      "The published package omits a license file; its manifest declares Apache-2.0 and the exact AWS SDK for JavaScript v3 family license is used."
  },
  "@aws-sdk/nested-clients": {
    expectedVersion: "3.997.38",
    license: "Apache-2.0",
    kind: "family-package-file",
    sourcePackage: "@aws-sdk/core",
    sourceFile: "LICENSE",
    reason:
      "The published package omits a license file; its manifest declares Apache-2.0 and the exact AWS SDK for JavaScript v3 family license is used."
  },
  "pg-types": {
    expectedVersion: "2.2.0",
    license: "MIT",
    kind: "readme-section",
    sourcePackage: "pg-types",
    sourceFile: "README.md",
    startMarker: "The MIT License (MIT)\n",
    reason:
      "The published package omits a separate license file; the complete MIT text is extracted from its published README."
  },
  pgpass: {
    expectedVersion: "1.0.5",
    license: "MIT",
    kind: "readme-section",
    sourcePackage: "pgpass",
    sourceFile: "README.md",
    startMarker: "Copyright (c) 2013-2016 Hannes Hörl\n",
    reason:
      "The published package omits a separate license file; the complete MIT text is extracted from its published README."
  }
});

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function sorted(values) {
  return [...values].sort((left, right) =>
    left < right ? -1 : left > right ? 1 : 0
  );
}

function readJson(filePath, label) {
  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch (error) {
    throw new Error(`${label} is not valid JSON: ${error.message}`);
  }
  assert(
    parsed && typeof parsed === "object" && !Array.isArray(parsed),
    `${label} must be an object`
  );
  return parsed;
}

function safePackageRoot(rootDir, packageName) {
  assert(PACKAGE_NAME.test(packageName), `unsafe package name: ${packageName}`);
  const packageRoot = path.join(rootDir, "node_modules", ...packageName.split("/"));
  const stat = fs.lstatSync(packageRoot);
  assert(
    stat.isDirectory() && !stat.isSymbolicLink(),
    `${packageName} must be an installed package directory`
  );
  return packageRoot;
}

function readRegularFile(filePath, label) {
  const stat = fs.lstatSync(filePath);
  assert(stat.isFile() && !stat.isSymbolicLink(), `${label} must be a regular file`);
  const bytes = fs.readFileSync(filePath);
  assert(
    bytes.length > 0 &&
      !bytes.includes(0) &&
      Buffer.from(bytes.toString("utf8"), "utf8").equals(bytes),
    `${label} must be nonempty UTF-8 text`
  );
  return bytes;
}

function packageRecord(rootDir, lock, packageName) {
  const lockPath = `node_modules/${packageName}`;
  const metadata = lock.packages?.[lockPath];
  assert(metadata && typeof metadata === "object", `${packageName} is not locked`);
  assert(
    typeof metadata.version === "string" &&
      typeof metadata.license === "string" &&
      ALLOWED_LICENSES.has(metadata.license) &&
      typeof metadata.resolved === "string" &&
      metadata.resolved.startsWith("https://registry.npmjs.org/") &&
      typeof metadata.integrity === "string" &&
      /^sha512-[A-Za-z0-9+/]+={0,2}$/.test(metadata.integrity) &&
      metadata.dev !== true,
    `${packageName} lock metadata is outside the reviewed runtime boundary`
  );
  const packageRoot = safePackageRoot(rootDir, packageName);
  const manifestPath = path.join(packageRoot, "package.json");
  const manifest = readJson(manifestPath, `${packageName} package.json`);
  assert(
    manifest.name === packageName &&
      manifest.version === metadata.version &&
      manifest.license === metadata.license,
    `${packageName} installed manifest differs from package-lock.json`
  );
  return { lockPath, metadata, packageRoot };
}

function normalizedText(bytes) {
  const text = bytes.toString("utf8").replaceAll("\r\n", "\n");
  return text.endsWith("\n") ? text : `${text}\n`;
}

function packageLicenseFiles(packageRoot) {
  return sorted(
    fs.readdirSync(packageRoot).filter((fileName) => LEGAL_FILE.test(fileName))
  );
}

function sourceRecord({
  appliesTo,
  kind,
  reason,
  sourcePackage,
  sourceFile,
  sourceBytes,
  text
}) {
  return {
    appliesTo,
    kind,
    reason,
    sourcePackage,
    sourceFile,
    sourceSha256: sha256(sourceBytes),
    text,
    textSha256: sha256(text)
  };
}

function fallbackSources(rootDir, lock, packageName, fallback) {
  const target = packageRecord(rootDir, lock, packageName);
  assert(
    target.metadata.version === fallback.expectedVersion &&
      target.metadata.license === fallback.license,
    `${packageName} fallback requires explicit version and license review`
  );
  const source = packageRecord(rootDir, lock, fallback.sourcePackage);
  const sourcePath = path.join(source.packageRoot, fallback.sourceFile);
  const sourceBytes = readRegularFile(
    sourcePath,
    `${fallback.sourcePackage}/${fallback.sourceFile}`
  );
  let text = normalizedText(sourceBytes);
  if (fallback.kind === "readme-section") {
    const start = text.indexOf(fallback.startMarker);
    assert(start !== -1, `${packageName} fallback marker is missing`);
    text = text.slice(start);
  }
  return [
    sourceRecord({
      appliesTo: packageName,
      kind: fallback.kind,
      reason: fallback.reason,
      sourcePackage: fallback.sourcePackage,
      sourceFile: fallback.sourceFile,
      sourceBytes,
      text
    })
  ];
}

function licenseSources(rootDir, lock, packageName, packageRoot) {
  const files = packageLicenseFiles(packageRoot);
  if (!files.some((fileName) => PRIMARY_LICENSE_FILE.test(fileName))) {
    assert(
      files.length === 0,
      `${packageName} has notices but no reviewed primary license text`
    );
    const fallback = FALLBACKS[packageName];
    assert(fallback, `${packageName} has no reviewed license-text source`);
    return fallbackSources(rootDir, lock, packageName, fallback);
  }
  assert(
    FALLBACKS[packageName] === undefined,
    `${packageName} no longer requires its reviewed license fallback`
  );
  return files.map((sourceFile) => {
    const sourceBytes = readRegularFile(
      path.join(packageRoot, sourceFile),
      `${packageName}/${sourceFile}`
    );
    return sourceRecord({
      appliesTo: packageName,
      kind: "package-file",
      reason: "Exact license or notice file from the integrity-locked npm package.",
      sourcePackage: packageName,
      sourceFile,
      sourceBytes,
      text: normalizedText(sourceBytes)
    });
  });
}

function packageNameFromInput(inputPath) {
  const normalized = inputPath.replaceAll("\\", "/");
  const marker = "node_modules/";
  const first = normalized.indexOf(marker);
  assert(first !== -1, `bundle input is not under node_modules: ${inputPath}`);
  assert(
    normalized.indexOf(marker, first + marker.length) === -1,
    `nested bundle dependency requires explicit support: ${inputPath}`
  );
  const segments = normalized.slice(first + marker.length).split("/");
  const packageName = segments[0].startsWith("@")
    ? `${segments[0]}/${segments[1] ?? ""}`
    : segments[0];
  assert(PACKAGE_NAME.test(packageName), `unsafe bundle package: ${inputPath}`);
  return packageName;
}

export function packageNamesFromMetafile(metafile) {
  assert(
    metafile &&
      typeof metafile === "object" &&
      metafile.inputs &&
      typeof metafile.inputs === "object",
    "esbuild metafile inputs are required"
  );
  const packageNames = new Set();
  for (const inputPath of Object.keys(metafile.inputs)) {
    if (inputPath.replaceAll("\\", "/").includes("node_modules/")) {
      packageNames.add(packageNameFromInput(inputPath));
    }
  }
  return sorted(packageNames);
}

export function renderBundledThirdPartyNotices({
  rootDir = DEFAULT_ROOT,
  packageNames
} = {}) {
  const resolvedRoot = path.resolve(rootDir);
  assert(Array.isArray(packageNames), "bundled package names must be an array");
  const names = sorted(packageNames);
  assert(
    names.length > 0 &&
      new Set(names).size === names.length &&
      JSON.stringify(names) === JSON.stringify(packageNames),
    "bundled package names must be a nonempty sorted unique array"
  );
  const lockBytes = readRegularFile(
    path.join(resolvedRoot, LOCK_PATH),
    LOCK_PATH
  );
  const lock = readJson(path.join(resolvedRoot, LOCK_PATH), LOCK_PATH);
  assert(lock.lockfileVersion === 3, "package-lock.json must use lockfileVersion 3");

  const packages = [];
  const sources = [];
  for (const packageName of names) {
    const record = packageRecord(resolvedRoot, lock, packageName);
    const packageSources = licenseSources(
      resolvedRoot,
      lock,
      packageName,
      record.packageRoot
    );
    sources.push(...packageSources);
    packages.push({
      name: packageName,
      version: record.metadata.version,
      license: record.metadata.license,
      resolved: record.metadata.resolved,
      integrity: record.metadata.integrity,
      sources: packageSources
    });
  }

  const textByHash = new Map();
  for (const source of sources) {
    const existing = textByHash.get(source.textSha256);
    if (existing) {
      assert(existing.text === source.text, "license text hash collision");
      existing.appliesTo.push(source.appliesTo);
      existing.sourceLabels.push(
        `${source.sourcePackage}/${source.sourceFile} (${source.kind}; source SHA-256 ${source.sourceSha256})`
      );
    } else {
      textByHash.set(source.textSha256, {
        appliesTo: [source.appliesTo],
        sourceLabels: [
          `${source.sourcePackage}/${source.sourceFile} (${source.kind}; source SHA-256 ${source.sourceSha256})`
        ],
        text: source.text
      });
    }
  }

  const licenseCounts = Object.fromEntries(
    sorted(new Set(packages.map(({ license }) => license))).map((license) => [
      license,
      packages.filter((record) => record.license === license).length
    ])
  );
  const fallbackCount = sources.filter(({ kind }) => kind !== "package-file").length;
  const lines = [
    "TIDEPROOF BUNDLED THIRD-PARTY NOTICES",
    "",
    "This file is generated deterministically from the exact integrity-locked npm",
    "packages whose source is present in the six Gate Two Lambda bundles. It is",
    "embedded byte-for-byte in every release ZIP so each independently distributed",
    "artifact carries the complete reviewed package union and license text set.",
    "Over-inclusion is intentional; an individual ZIP may use only a subset.",
    "",
    "This is a provenance and distribution control, not legal advice. A final audit",
    "must still bind the exact release commit, installed tree, deployed ZIP hashes,",
    "vulnerability report, repository history, and any changed upstream metadata.",
    "",
    `Package lock SHA-256: ${sha256(lockBytes)}`,
    `Bundled package union: ${packages.length}`,
    `Distinct normalized license texts: ${textByHash.size}`,
    `Explicit published-package fallbacks: ${fallbackCount}`,
    `License identifiers: ${Object.entries(licenseCounts)
      .map(([license, count]) => `${license}=${count}`)
      .join(", ")}`,
    "",
    "PACKAGE RECORDS",
    ""
  ];

  for (const record of packages) {
    lines.push(
      `${record.name}@${record.version}`,
      `  License: ${record.license}`,
      `  Registry: ${record.resolved}`,
      `  Integrity: ${record.integrity}`
    );
    for (const source of record.sources) {
      lines.push(
        `  Text: ${source.textSha256}`,
        `    Source: ${source.sourcePackage}/${source.sourceFile}`,
        `    Source SHA-256: ${source.sourceSha256}`,
        `    Source kind: ${source.kind}`,
        `    Review note: ${source.reason}`
      );
    }
    lines.push("");
  }

  lines.push("LICENSE TEXTS", "");
  for (const [textSha256, record] of [...textByHash.entries()].sort(
    ([left], [right]) => (left < right ? -1 : left > right ? 1 : 0)
  )) {
    lines.push(
      "================================================================================",
      `Normalized text SHA-256: ${textSha256}`,
      `Applies to: ${sorted(new Set(record.appliesTo)).join(", ")}`,
      `Sources: ${sorted(new Set(record.sourceLabels)).join("; ")}`,
      "--------------------------------------------------------------------------------",
      record.text.replace(/\n$/, "")
    );
  }
  lines.push("================================================================================", "");

  const content = lines.join("\n");
  return {
    content,
    noticeSha256: sha256(content),
    noticeBytes: Buffer.byteLength(content),
    packageLockSha256: sha256(lockBytes),
    packageNames: names,
    packageCount: packages.length,
    licenseTextCount: textByHash.size,
    fallbackCount,
    licenses: licenseCounts
  };
}

export function verifyBundledThirdPartyNotices({
  rootDir = DEFAULT_ROOT,
  packageNames
} = {}) {
  const resolvedRoot = path.resolve(rootDir);
  const expected = renderBundledThirdPartyNotices({
    rootDir: resolvedRoot,
    packageNames
  });
  const noticePath = path.join(resolvedRoot, NOTICE_PATH);
  const noticeBytes = readRegularFile(noticePath, NOTICE_PATH);
  const actual = noticeBytes.toString("utf8");
  assert(
    actual === expected.content,
    `${NOTICE_PATH} does not match the exact bundled package and license-text inventory`
  );
  return {
    schema: RECEIPT_SCHEMA,
    status: "PASS",
    noticePath: NOTICE_PATH,
    noticeSha256: expected.noticeSha256,
    noticeBytes: expected.noticeBytes,
    packageLockSha256: expected.packageLockSha256,
    packageNames: expected.packageNames,
    packageCount: expected.packageCount,
    licenseTextCount: expected.licenseTextCount,
    fallbackCount: expected.fallbackCount,
    licenses: expected.licenses
  };
}

export const __test = {
  FALLBACKS,
  normalizedText,
  packageNameFromInput
};
