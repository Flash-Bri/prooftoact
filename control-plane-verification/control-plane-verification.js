import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";

import {
  CONTROL_PLANE_PROVENANCE_CONSTANTS,
  validateControlPlaneProvenanceEvidence,
  verifyControlPlaneProvenanceEvidence
} from "./control-plane-provenance.js";

const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const EXACT_VERSION = /^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/u;
const CANDIDATE_SCHEMA = "prooftoact.control-plane-verification-candidate.v1";
const BODY_SCHEMA = "prooftoact.control-plane-verification-body.v1";
const GOVERNANCE_EVIDENCE_SCHEMA =
  "prooftoact.control-plane-governance-evidence.v1";
const PROVENANCE_EVIDENCE_SCHEMA =
  CONTROL_PLANE_PROVENANCE_CONSTANTS.SCHEMA;
const FROZEN_APPLICATION = Object.freeze({
  commit: "963937a9873f0199b91897fe88da1b91bc84b5e3",
  tree: "a330e0d57328e63a568be73c523b2cae6338f26c"
});

const WORKFLOWS = Object.freeze([
  Object.freeze({
    environment: "aws-release-teardown",
    file: "prooftoact-approved-teardown.yml",
    name: "ProofToAct Approved Teardown",
    roleName: "ProofToActReleaseTeardown"
  }),
  Object.freeze({
    environment: "aws-live-drill",
    file: "prooftoact-bounded-live-drill.yml",
    name: "ProofToAct Bounded Live Drill",
    roleName: "ProofToActLiveDrillOperator"
  }),
  Object.freeze({
    environment: "aws-release-execution",
    file: "prooftoact-execute-approved-release.yml",
    name: "ProofToAct Execute Approved Release",
    roleName: "ProofToActReleaseExecution"
  }),
  Object.freeze({
    environment: "aws-release-evidence",
    file: "prooftoact-read-only-release-evidence.yml",
    name: "ProofToAct Read Only Release Evidence",
    roleName: "ProofToActReleaseEvidence"
  }),
  Object.freeze({
    environment: "aws-release-deployment",
    file: "prooftoact-release-candidate.yml",
    name: "ProofToAct Release Candidate",
    roleName: "ProofToActReleaseDeployment",
    sourceJobs: Object.freeze([
      Object.freeze({ environment: null, jobName: "prepare-diagnostic" }),
      Object.freeze({
        environment: "aws-release-coordination",
        jobName: "coordinator-reserve"
      }),
      Object.freeze({
        environment: "aws-release-deployment",
        jobName: "provider-dispatch"
      }),
      Object.freeze({
        environment: "aws-release-coordination",
        jobName: "coordinator-finalize"
      })
    ])
  }),
  Object.freeze({
    environment: "aws-release-terminalization",
    file: "prooftoact-terminalize-expired-release.yml",
    name: "ProofToAct Terminalize Expired Release",
    roleName: "ProofToActReleaseTerminalizer"
  })
]);

const GOVERNANCE_LANES = Object.freeze([
  ...WORKFLOWS.map((item) => Object.freeze({
    ...item,
    jobNames: item.sourceJobs?.filter(({ environment }) =>
      environment === item.environment).map(({ jobName }) => jobName) ??
      [item.environment === "aws-release-terminalization"
        ? "terminalizer-diagnostic" : "controller-diagnostic"]
  })),
  Object.freeze({
    environment: "aws-release-coordination",
    file: "prooftoact-release-candidate.yml",
    jobNames: Object.freeze(["coordinator-reserve", "coordinator-finalize"]),
    name: "ProofToAct Release Candidate",
    roleName: "ProofToActReleaseCoordinator"
  })
]);

const REQUIRED_EXACT_PATHS = Object.freeze([
  ...WORKFLOWS.map(({ file }) => `.github/workflows/${file}`),
  ".github/workflows/prooftoact-hosted-dual-root-verification.yml",
  "config/prooftoact-release-operator-public.pub",
  "control-plane-verification/generate-hosted-dual-root-verification.js",
  "control-plane-verification/hosted-dual-root-verification.js",
  "control-plane-verification/verify-hosted-dual-root-verification.js",
  "infra/aws/release-deployment-roles-template.json",
  "release-control/build-release-control-runtime.js",
  "release-control/DEPENDENCY_INVENTORY.json",
  "release-control/package-lock.json",
  "release-control/package.json",
  "release-control/THIRD_PARTY_NOTICES.txt",
  "release-provider/build-release-provider-runtimes.js",
  "release-provider/DEPENDENCY_INVENTORY.json",
  "release-provider/package-lock.json",
  "release-provider/package.json",
  "release-provider/THIRD_PARTY_NOTICES.txt",
  "scripts/bootstrap-fresh-primary.js",
  "scripts/normalize-release-control-checkouts.js",
  "scripts/prepare-release-control-bootstrap.js",
  "scripts/prepare-release-deployment.js",
  "scripts/release-provider-controller.js",
  "scripts/release-provider-one-shot-broker.js",
  "scripts/run-release-prepare-common.js",
  "scripts/run-release-prepare-diagnostic.js",
  "scripts/run-release-prepare-phase.js",
  "scripts/run-release-prepare-preflight.js",
  "scripts/sign-release-provider-approval.js",
  "test/release-control-bootstrap-plan.test.js",
  "test/hosted-dual-root-verification.test.js",
  "test/release-provider-runtime-loader.test.js",
  "test/release-provider-runtime.test.js",
  "test/release-prepare-runner.test.js"
]);

const DISCOVERY_RULES = Object.freeze([
  Object.freeze({
    directory: ".github/workflows",
    pattern: /^prooftoact-.*\.yml$/u,
    recursive: false
  }),
  Object.freeze({
    directory: "release-control/src",
    pattern: /^release-control-.*\.js$/u,
    recursive: false
  }),
  Object.freeze({
    directory: "release-provider",
    pattern: /^.+$/u,
    recursive: true
  }),
  Object.freeze({
    directory: "scripts",
    pattern:
      /^(?:bootstrap-fresh-primary|normalize-release-control-checkouts|prepare-release-control-bootstrap|prepare-release-deployment|release-provider-.*|run-release-.*|sign-release-provider-approval)\.js$/u,
    recursive: false
  }),
  Object.freeze({
    directory: "scripts/lib",
    pattern: /^release-control-.*\.js$/u,
    recursive: false
  }),
  Object.freeze({
    directory: "test",
    pattern:
      /^(?:control-plane-verification|fresh-primary-bootstrap|hosted-dual-root-verification|release-control-.*|release-deployment-plan|release-prepare-.*|release-provider-.*)\.test\.js$/u,
    recursive: false
  }),
  Object.freeze({
    directory: "control-plane-verification",
    pattern: /^(?!candidate\/).*\.(?:js|json|md)$/u,
    recursive: true
  })
]);

const ALLOWED_LICENSES = Object.freeze(["0BSD", "Apache-2.0", "MIT"]);
const EXPECTED_DIRECT_DEPENDENCIES = Object.freeze({
  "@aws-sdk/client-dynamodb": "3.1098.0",
  "@aws-sdk/client-sts": "3.1098.0",
  "@smithy/node-http-handler": "4.9.13"
});
const EXPECTED_DIRECT_DEV_DEPENDENCIES = Object.freeze({ esbuild: "0.28.1" });
const EXPECTED_PROVIDER_DIRECT_DEPENDENCIES = Object.freeze({
  "@aws-sdk/client-cloudformation": "3.1098.0",
  "@aws-sdk/client-dynamodb": "3.1098.0",
  "@aws-sdk/client-s3": "3.1098.0",
  "@aws-sdk/client-sts": "3.1098.0",
  "@smithy/node-http-handler": "4.9.13"
});
const EXPECTED_PROVIDER_DIRECT_DEV_DEPENDENCIES = Object.freeze({
  esbuild: "0.28.1"
});

function invariant(condition, code) {
  if (!condition) throw new Error(code);
}

function plainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value, keys) {
  return plainObject(value) &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort());
}

function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (!plainObject(value)) return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) =>
    [key, canonicalValue(value[key])]));
}

export function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value));
}

export function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function canonicalDigest(value) {
  return sha256(Buffer.from(canonicalJson(value), "utf8"));
}

function sorted(values) {
  return [...values].sort((left, right) =>
    left < right ? -1 : left > right ? 1 : 0);
}

function safeRoot(rootDir) {
  invariant(path.isAbsolute(rootDir), "CONTROL_PLANE_ROOT_NOT_ABSOLUTE");
  const root = fs.realpathSync(rootDir);
  invariant(root === path.resolve(rootDir), "CONTROL_PLANE_ROOT_ALIAS_REJECTED");
  return root;
}

function safePath(root, relativePath) {
  invariant(typeof relativePath === "string" && relativePath.length > 0 &&
    relativePath === relativePath.replaceAll("\\", "/") &&
    !relativePath.startsWith("/") && !relativePath.split("/").includes(".."),
  "CONTROL_PLANE_PATH_REJECTED");
  const candidate = path.resolve(root, relativePath);
  invariant(candidate.startsWith(`${root}${path.sep}`),
    "CONTROL_PLANE_PATH_ESCAPE_REJECTED");
  return candidate;
}

function readSafeFile(root, relativePath, maximumBytes = 8 * 1024 * 1024) {
  const filePath = safePath(root, relativePath);
  const stat = fs.lstatSync(filePath);
  invariant(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1 &&
    stat.size > 0 && stat.size <= maximumBytes && (stat.mode & 0o022) === 0,
  "CONTROL_PLANE_FILE_SAFETY_REJECTED");
  invariant(fs.realpathSync(filePath) === filePath,
    "CONTROL_PLANE_FILE_ALIAS_REJECTED");
  const bytes = fs.readFileSync(filePath);
  invariant(bytes.length === stat.size,
    "CONTROL_PLANE_FILE_READBACK_REJECTED");
  return { bytes, mode: stat.mode & 0o777 };
}

function listRulePaths(root, rule) {
  const base = safePath(root, rule.directory);
  if (!fs.existsSync(base)) return [];
  const baseStat = fs.lstatSync(base);
  invariant(baseStat.isDirectory() && !baseStat.isSymbolicLink() &&
    fs.realpathSync(base) === base, "CONTROL_PLANE_DIRECTORY_REJECTED");
  const output = [];
  const visit = (directory, relativeDirectory) => {
    for (const name of sorted(fs.readdirSync(directory))) {
      if (["candidate", "dist", "node_modules"].includes(name)) continue;
      const absolute = path.join(directory, name);
      const stat = fs.lstatSync(absolute);
      invariant(!stat.isSymbolicLink(), "CONTROL_PLANE_DISCOVERY_SYMLINK_REJECTED");
      const relativeName = relativeDirectory ? `${relativeDirectory}/${name}` : name;
      if (stat.isDirectory()) {
        if (rule.recursive) visit(absolute, relativeName);
        continue;
      }
      if (stat.isFile() && rule.pattern.test(relativeName)) {
        output.push(`${rule.directory}/${relativeName}`);
      }
    }
  };
  visit(base, "");
  return output;
}

function collectInventory(root) {
  const discovered = new Set();
  const discovery = [];
  for (const rule of DISCOVERY_RULES) {
    const matches = listRulePaths(root, rule);
    matches.forEach((entry) => discovered.add(entry));
    discovery.push({
      directory: rule.directory,
      matches,
      pattern: rule.pattern.source,
      recursive: rule.recursive
    });
  }
  const required = sorted(REQUIRED_EXACT_PATHS);
  const missingPaths = required.filter((entry) =>
    !fs.existsSync(safePath(root, entry)));
  required.filter((entry) => !missingPaths.includes(entry))
    .forEach((entry) => discovered.add(entry));
  const expectedWorkflows = sorted(WORKFLOWS.map(({ file }) =>
    `.github/workflows/${file}`));
  const discoveredWorkflows = sorted([...discovered].filter((entry) =>
    entry.startsWith(".github/workflows/prooftoact-")));
  const unexpectedWorkflowPaths = discoveredWorkflows.filter((entry) =>
    !expectedWorkflows.includes(entry));
  const discoveredPaths = sorted(discovered);
  const untrackedPaths = discoveredPaths.filter((relativePath) =>
    gitOutput(root, ["ls-files", "--error-unmatch", "--", relativePath]) === null);
  const dirtyPaths = discoveredPaths.filter((relativePath) => {
    if (untrackedPaths.includes(relativePath)) return false;
    const headBytes = gitBlob(root, relativePath);
    return headBytes === null ||
      !readSafeFile(root, relativePath).bytes.equals(headBytes);
  });
  const files = discoveredPaths.map((relativePath) => {
    const { bytes, mode } = readSafeFile(root, relativePath);
    return Object.freeze({
      bytes: bytes.length,
      gitMatchesHead: !untrackedPaths.includes(relativePath) &&
        !dirtyPaths.includes(relativePath),
      gitTracked: !untrackedPaths.includes(relativePath),
      mode: mode.toString(8).padStart(3, "0"),
      path: relativePath,
      sha256: sha256(bytes)
    });
  });
  return Object.freeze({
    discovery,
    dirtyPaths,
    files,
    inventorySha256: canonicalDigest(files),
    missingPaths,
    requiredPaths: required,
    untrackedPaths,
    unexpectedWorkflowPaths
  });
}

function packageNameFromLockPath(lockPath) {
  const suffix = lockPath.slice(lockPath.lastIndexOf("node_modules/") + 13);
  const pieces = suffix.split("/");
  return pieces[0].startsWith("@") ? pieces.slice(0, 2).join("/") : pieces[0];
}

function dependencyFailure(error) {
  return Object.freeze({
    directDevelopmentDependencies: [],
    directRuntimeDependencies: [],
    findings: [error instanceof Error ? error.message : String(error)],
    inventorySha256: null,
    inventoryTextBytes: 0,
    inventoryTextSha256: null,
    lockfileVersion: null,
    packageCount: 0,
    packageLockSha256: null,
    packageRecords: [],
    packageSha256: null,
    ready: false
  });
}

function sameRecord(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function collectDependencies(root) {
  try {
    const packageBytes = readSafeFile(root, "release-control/package.json").bytes;
    const lockBytes = readSafeFile(root, "release-control/package-lock.json",
      4 * 1024 * 1024).bytes;
    const packageJson = JSON.parse(packageBytes.toString("utf8"));
    const lock = JSON.parse(lockBytes.toString("utf8"));
    const findings = [];
    const runtime = packageJson.dependencies ?? {};
    const development = packageJson.devDependencies ?? {};
    if (!sameRecord(runtime, EXPECTED_DIRECT_DEPENDENCIES)) {
      findings.push("CONTROL_PLANE_RUNTIME_DEPENDENCIES_REJECTED");
    }
    if (!sameRecord(development, EXPECTED_DIRECT_DEV_DEPENDENCIES)) {
      findings.push("CONTROL_PLANE_DEVELOPMENT_DEPENDENCIES_REJECTED");
    }
    if (packageJson.name !== "@prooftoact/release-control-runtime" ||
      packageJson.private !== true || packageJson.type !== "module") {
      findings.push("CONTROL_PLANE_PACKAGE_IDENTITY_REJECTED");
    }
    if (lock.lockfileVersion !== 3 || !plainObject(lock.packages) ||
      !plainObject(lock.packages[""])) {
      findings.push("CONTROL_PLANE_LOCK_STRUCTURE_REJECTED");
    }
    const directRuntimeDependencies = sorted(Object.keys(runtime)).map((name) => ({
      declared: runtime[name], name,
      locked: lock.packages?.[`node_modules/${name}`]?.version ?? null
    }));
    const directDevelopmentDependencies = sorted(Object.keys(development))
      .map((name) => ({
        declared: development[name], name,
        locked: lock.packages?.[`node_modules/${name}`]?.version ?? null
      }));
    for (const item of [...directRuntimeDependencies,
      ...directDevelopmentDependencies]) {
      if (!EXACT_VERSION.test(item.declared) || item.declared !== item.locked) {
        findings.push(`CONTROL_PLANE_DIRECT_LOCK_MISMATCH:${item.name}`);
      }
    }
    const packageRecords = sorted(Object.keys(lock.packages ?? {})
      .filter((lockPath) => lockPath !== "")).map((lockPath) => {
      const value = lock.packages[lockPath];
      const record = {
        deprecated: value.deprecated ?? null,
        developmentOnly: value.dev === true,
        hasInstallScript: value.hasInstallScript === true,
        integrity: value.integrity ?? null,
        license: value.license ?? null,
        lockPath,
        name: packageNameFromLockPath(lockPath),
        optional: value.optional === true,
        registry: value.resolved ?? null,
        version: value.version ?? null
      };
      if (!EXACT_VERSION.test(record.version ?? "") ||
        !ALLOWED_LICENSES.includes(record.license) ||
        record.deprecated !== null ||
        !/^https:\/\/registry\.npmjs\.org\//u.test(record.registry ?? "") ||
        !/^sha512-[A-Za-z0-9+/]+=*$/u.test(record.integrity ?? "")) {
        findings.push(`CONTROL_PLANE_LOCK_RECORD_REJECTED:${lockPath}`);
      }
      return record;
    });
    const partial = {
      directDevelopmentDependencies,
      directRuntimeDependencies,
      lockfileVersion: lock.lockfileVersion,
      packageCount: packageRecords.length,
      packageLockSha256: sha256(lockBytes),
      packageRecords,
      packageSha256: sha256(packageBytes)
    };
    const inventoryText = renderDependencyInventory(partial);
    return Object.freeze({
      ...partial,
      findings: sorted(new Set(findings)),
      inventorySha256: canonicalDigest(packageRecords),
      inventoryTextBytes: Buffer.byteLength(inventoryText),
      inventoryTextSha256: sha256(Buffer.from(inventoryText, "utf8")),
      ready: findings.length === 0
    });
  } catch (error) {
    return dependencyFailure(error);
  }
}

function collectProviderDependencies(root) {
  try {
    const packageBytes = readSafeFile(root, "release-provider/package.json").bytes;
    const lockBytes = readSafeFile(root, "release-provider/package-lock.json",
      4 * 1024 * 1024).bytes;
    const generatorBytes = readSafeFile(root,
      "release-provider/generate-release-provider-metadata.js").bytes;
    const inventoryBytes = readSafeFile(root,
      "release-provider/DEPENDENCY_INVENTORY.json", 5 * 1024 * 1024).bytes;
    const packageJson = JSON.parse(packageBytes.toString("utf8"));
    const lock = JSON.parse(lockBytes.toString("utf8"));
    const inventory = JSON.parse(inventoryBytes.toString("utf8"));
    const findings = [];
    const runtime = packageJson.dependencies ?? {};
    const development = packageJson.devDependencies ?? {};
    if (!sameRecord(runtime, EXPECTED_PROVIDER_DIRECT_DEPENDENCIES)) {
      findings.push("RELEASE_PROVIDER_RUNTIME_DEPENDENCIES_REJECTED");
    }
    if (!sameRecord(development, EXPECTED_PROVIDER_DIRECT_DEV_DEPENDENCIES)) {
      findings.push("RELEASE_PROVIDER_DEVELOPMENT_DEPENDENCIES_REJECTED");
    }
    if (packageJson.name !== "@prooftoact/release-provider-runtime" ||
      packageJson.private !== true || packageJson.type !== "module") {
      findings.push("RELEASE_PROVIDER_PACKAGE_IDENTITY_REJECTED");
    }
    if (lock.lockfileVersion !== 3 || !plainObject(lock.packages) ||
      !plainObject(lock.packages[""])) {
      findings.push("RELEASE_PROVIDER_LOCK_STRUCTURE_REJECTED");
    }
    const directRuntimeDependencies = sorted(Object.keys(runtime)).map((name) => ({
      declared: runtime[name], name,
      locked: lock.packages?.[`node_modules/${name}`]?.version ?? null
    }));
    const directDevelopmentDependencies = sorted(Object.keys(development))
      .map((name) => ({
        declared: development[name], name,
        locked: lock.packages?.[`node_modules/${name}`]?.version ?? null
      }));
    for (const item of [...directRuntimeDependencies,
      ...directDevelopmentDependencies]) {
      if (!EXACT_VERSION.test(item.declared) || item.declared !== item.locked) {
        findings.push(`RELEASE_PROVIDER_DIRECT_LOCK_MISMATCH:${item.name}`);
      }
    }
    const lockRecords = sorted(Object.keys(lock.packages ?? {})
      .filter((lockPath) => lockPath !== "")).map((lockPath) => {
      const value = lock.packages[lockPath];
      const record = {
        developmentOnly: value.dev === true,
        hasInstallScript: value.hasInstallScript === true,
        integrity: value.integrity ?? null,
        license: value.license ?? null,
        lockPath,
        name: packageNameFromLockPath(lockPath),
        optional: value.optional === true,
        registry: value.resolved ?? null,
        version: value.version ?? null
      };
      if (!EXACT_VERSION.test(record.version ?? "") ||
        !ALLOWED_LICENSES.includes(record.license) ||
        value.deprecated !== undefined ||
        !/^https:\/\/registry\.npmjs\.org\//u.test(record.registry ?? "") ||
        !/^sha512-[A-Za-z0-9+/]+=*$/u.test(record.integrity ?? "")) {
        findings.push(`RELEASE_PROVIDER_LOCK_RECORD_REJECTED:${lockPath}`);
      }
      return record;
    });
    if (!exactKeys(inventory, [
      "directDevelopmentDependencies", "directRuntimeDependencies",
      "generatorSha256", "lockfileVersion", "packageCount",
      "packageInventorySha256", "packageJsonSha256", "packageLockSha256",
      "packages", "runtimeSetSha256", "schemaVersion", "status"
    ]) || inventory.schemaVersion !==
      "prooftoact.release-provider-dependency-inventory.v1" ||
      inventory.status !== "GENERATED_FROM_HERMETIC_LOCK_AND_BUNDLE_METAFILES") {
      findings.push("RELEASE_PROVIDER_INVENTORY_SCHEMA_REJECTED");
    }
    if (inventory.generatorSha256 !== sha256(generatorBytes) ||
      inventory.packageJsonSha256 !== sha256(packageBytes) ||
      inventory.packageLockSha256 !== sha256(lockBytes) ||
      inventory.lockfileVersion !== lock.lockfileVersion ||
      !HEX_64.test(inventory.runtimeSetSha256 ?? "")) {
      findings.push("RELEASE_PROVIDER_INVENTORY_IDENTITY_REJECTED");
    }
    if (!sameRecord(inventory.directRuntimeDependencies,
      directRuntimeDependencies) ||
      !sameRecord(inventory.directDevelopmentDependencies,
        directDevelopmentDependencies)) {
      findings.push("RELEASE_PROVIDER_INVENTORY_DIRECT_SET_REJECTED");
    }
    const capabilities = new Set([
      "PERMIT_READER", "PREPARE_DISPATCHER", "PREPARE_READBACK"
    ]);
    const inventoryRecords = Array.isArray(inventory.packages)
      ? inventory.packages : [];
    if (inventoryRecords.length !== lockRecords.length ||
      inventory.packageCount !== inventoryRecords.length) {
      findings.push("RELEASE_PROVIDER_INVENTORY_COUNT_REJECTED");
    }
    for (let index = 0; index < lockRecords.length; index += 1) {
      const locked = lockRecords[index];
      const recorded = inventoryRecords[index];
      if (!exactKeys(recorded, [
        "bundledCapabilities", "developmentOnly", "hasInstallScript",
        "integrity", "license", "lockPath", "name", "optional",
        "registry", "version"
      ]) || !Array.isArray(recorded.bundledCapabilities) ||
        canonicalJson(recorded.bundledCapabilities) !== canonicalJson(
          sorted(new Set(recorded.bundledCapabilities))) ||
        recorded.bundledCapabilities.some((item) => !capabilities.has(item)) ||
        !sameRecord(Object.fromEntries(Object.entries(recorded)
          .filter(([key]) => key !== "bundledCapabilities")), locked)) {
        findings.push(`RELEASE_PROVIDER_INVENTORY_RECORD_REJECTED:${locked.lockPath}`);
      }
      if ((recorded?.name?.startsWith("@aws-sdk/credential-provider-") ||
        recorded?.name === "@aws-sdk/token-providers" ||
        recorded?.name === "@smithy/credential-provider-imds") &&
        recorded.bundledCapabilities.length !== 0) {
        findings.push(`RELEASE_PROVIDER_CREDENTIAL_CHAIN_BUNDLED:${recorded.name}`);
      }
    }
    if (![...capabilities].every((capability) => inventoryRecords.some((item) =>
      item.bundledCapabilities?.includes(capability)))) {
      findings.push("RELEASE_PROVIDER_CAPABILITY_PACKAGE_SET_REJECTED");
    }
    const inventoryRecordDigest = sha256(Buffer.from(
      `${JSON.stringify(inventoryRecords)}\n`, "utf8"));
    if (inventory.packageInventorySha256 !== inventoryRecordDigest ||
      inventoryBytes.toString("utf8") !== `${JSON.stringify(inventory)}\n`) {
      findings.push("RELEASE_PROVIDER_INVENTORY_CANONICAL_BYTES_REJECTED");
    }
    const partial = {
      directDevelopmentDependencies: inventory.directDevelopmentDependencies,
      directRuntimeDependencies: inventory.directRuntimeDependencies,
      generatorSha256: sha256(generatorBytes),
      lockfileVersion: lock.lockfileVersion,
      packageCount: inventoryRecords.length,
      packageLockSha256: sha256(lockBytes),
      packageRecords: inventoryRecords,
      packageSha256: sha256(packageBytes),
      runtimeSetSha256: inventory.runtimeSetSha256
    };
    return Object.freeze({
      ...partial,
      findings: sorted(new Set(findings)),
      inventoryBytes: inventoryBytes.length,
      inventoryFileSha256: sha256(inventoryBytes),
      inventorySha256: inventoryRecordDigest,
      ready: findings.length === 0
    });
  } catch (error) {
    return dependencyFailure(error);
  }
}

export function renderDependencyInventory(dependencies) {
  const lines = [
    "# ProofToAct release-control dependency inventory",
    "",
    "This inventory is generated from the separate release-control lock. It does not alter or describe the frozen application dependency set.",
    "",
    `Locked package records: ${dependencies.packageRecords.length}`,
    "",
    "| Package | Version | Lock path | Use | Optional | Install script | License |",
    "| --- | --- | --- | --- | --- | --- | --- |"
  ];
  for (const item of dependencies.packageRecords) {
    lines.push(`| \`${item.name}\` | \`${item.version}\` | \`${item.lockPath}\` | ${item.developmentOnly ? "development-only" : "runtime"} | ${item.optional ? "yes" : "no"} | ${item.hasInstallScript ? "yes" : "no"} | \`${item.license}\` |`);
  }
  return `${lines.join("\n")}\n`;
}

export function renderProviderDependencyInventory(dependencies) {
  const lines = [
    "# ProofToAct release-provider dependency inventory",
    "",
    "This inventory is generated from the separate release-provider lock. It does not alter or describe the frozen application or release-control dependency sets.",
    "",
    `Locked package records: ${dependencies.packageRecords.length}`,
    "",
    "| Package | Version | Lock path | Use | Optional | Install script | License |",
    "| --- | --- | --- | --- | --- | --- | --- |"
  ];
  for (const item of dependencies.packageRecords) {
    lines.push(`| \`${item.name}\` | \`${item.version}\` | \`${item.lockPath}\` | ${item.developmentOnly ? "development-only" : "runtime"} | ${item.optional ? "yes" : "no"} | ${item.hasInstallScript ? "yes" : "no"} | \`${item.license}\` |`);
  }
  return `${lines.join("\n")}\n`;
}

export function renderDependencyInventoryJson(dependencies) {
  const value = {
    schemaVersion: "prooftoact.release-control-dependency-inventory.v1",
    status: "GENERATED_FROM_SEPARATE_HERMETIC_LOCK",
    packageJsonSha256: dependencies.packageSha256,
    packageLockSha256: dependencies.packageLockSha256,
    lockfileVersion: dependencies.lockfileVersion,
    directRuntimeDependencies: dependencies.directRuntimeDependencies,
    directDevelopmentDependencies: dependencies.directDevelopmentDependencies,
    packageCount: dependencies.packageCount,
    packageInventorySha256: dependencies.inventorySha256,
    packages: dependencies.packageRecords
  };
  return `${canonicalJson(value)}\n`;
}

export function renderProviderDependencyInventoryJson(dependencies) {
  const value = {
    schemaVersion: "prooftoact.release-provider-dependency-inventory.v1",
    status: "GENERATED_FROM_HERMETIC_LOCK_AND_BUNDLE_METAFILES",
    generatorSha256: dependencies.generatorSha256,
    packageJsonSha256: dependencies.packageSha256,
    packageLockSha256: dependencies.packageLockSha256,
    lockfileVersion: dependencies.lockfileVersion,
    directRuntimeDependencies: dependencies.directRuntimeDependencies,
    directDevelopmentDependencies: dependencies.directDevelopmentDependencies,
    runtimeSetSha256: dependencies.runtimeSetSha256,
    packageCount: dependencies.packageCount,
    packageInventorySha256: dependencies.inventorySha256,
    packages: dependencies.packageRecords
  };
  return `${JSON.stringify(value)}\n`;
}

function normalizedLicenseBytes(bytes) {
  return Buffer.from(bytes.toString("utf8").replaceAll("\r\n", "\n").trim() +
    "\n", "utf8");
}

function licenseCandidates(record) {
  const direct = ["LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE", "LICENCE.md",
    "NOTICE", "NOTICE.txt"].map((name) =>
    `release-control/${record.lockPath}/${name}`);
  const family = record.name.startsWith("@aws-sdk/")
    ? ["release-control/node_modules/@aws-sdk/client-dynamodb/LICENSE"]
    : record.name.startsWith("@smithy/")
      ? ["release-control/node_modules/@smithy/node-http-handler/LICENSE"]
      : record.name.startsWith("@esbuild/")
        ? ["release-control/node_modules/esbuild/LICENSE.md"]
        : [];
  return [...direct, ...family];
}

function collectNotices(root, dependencies) {
  if (!dependencies.ready) return Object.freeze({
    findings: ["CONTROL_PLANE_NOTICE_DEPENDENCIES_NOT_READY"],
    licenseTextCount: 0,
    noticeBytes: 0,
    noticeRecords: [],
    noticesSha256: null,
    ready: false
  });
  const findings = [];
  const textByDigest = new Map();
  const noticeRecords = dependencies.packageRecords.map((record) => {
    const source = licenseCandidates(record).find((candidate) =>
      fs.existsSync(safePath(root, candidate)));
    if (source === undefined) {
      findings.push(`CONTROL_PLANE_LICENSE_TEXT_MISSING:${record.lockPath}`);
      return { ...record, licenseSource: null, licenseTextSha256: null };
    }
    try {
      const bytes = normalizedLicenseBytes(readSafeFile(root, source,
        512 * 1024).bytes);
      const digest = sha256(bytes);
      textByDigest.set(digest, bytes.toString("utf8"));
      return {
        ...record,
        licenseSource: source,
        licenseSourceKind: source.includes(record.lockPath)
          ? "package-file" : "reviewed-family-fallback",
        licenseTextSha256: digest
      };
    } catch (error) {
      findings.push(`${error.message}:${record.lockPath}`);
      return { ...record, licenseSource: null, licenseTextSha256: null };
    }
  });
  const noticeText = renderThirdPartyNotices({ noticeRecords, textByDigest });
  return Object.freeze({
    findings: sorted(new Set(findings)),
    licenseTextCount: textByDigest.size,
    noticeBytes: Buffer.byteLength(noticeText),
    noticeRecords,
    noticesSha256: sha256(Buffer.from(noticeText, "utf8")),
    ready: findings.length === 0
  });
}

function providerLicenseCandidates(record) {
  const direct = ["LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE", "LICENCE.md",
    "NOTICE", "NOTICE.txt"].map((name) =>
    `release-provider/${record.lockPath}/${name}`);
  const family = record.name.startsWith("@aws-sdk/")
    ? ["release-provider/node_modules/@aws-sdk/client-cloudformation/LICENSE"]
    : record.name.startsWith("@smithy/")
      ? ["release-provider/node_modules/@smithy/node-http-handler/LICENSE"]
      : record.name.startsWith("@esbuild/")
        ? ["release-provider/node_modules/esbuild/LICENSE.md"]
        : [];
  return [...direct, ...family];
}

function collectProviderNotices(root, dependencies) {
  if (!dependencies.ready) return Object.freeze({
    findings: ["RELEASE_PROVIDER_NOTICE_DEPENDENCIES_NOT_READY"],
    licenseTextCount: 0,
    noticeBytes: 0,
    noticeFileSha256: null,
    noticeRecords: [],
    noticesSha256: null,
    ready: false
  });
  const findings = [];
  const textByDigest = new Map();
  const noticeRecords = dependencies.packageRecords.map((record) => {
    const source = providerLicenseCandidates(record).find((candidate) =>
      fs.existsSync(safePath(root, candidate)));
    if (source === undefined) {
      findings.push(`RELEASE_PROVIDER_LICENSE_TEXT_MISSING:${record.lockPath}`);
      return { ...record, licenseSource: null, licenseTextSha256: null };
    }
    try {
      const bytes = normalizedLicenseBytes(readSafeFile(root, source,
        512 * 1024).bytes);
      const digest = sha256(bytes);
      textByDigest.set(digest, bytes.toString("utf8"));
      const relativeSource = source.slice("release-provider/".length);
      return {
        ...record,
        licenseSource: relativeSource,
        licenseSourceKind: relativeSource.startsWith(`${record.lockPath}/`)
          ? "package-file" : "reviewed-family-fallback",
        licenseTextSha256: digest
      };
    } catch (error) {
      findings.push(`${error.message}:${record.lockPath}`);
      return { ...record, licenseSource: null, licenseTextSha256: null };
    }
  });
  const noticeText = renderProviderThirdPartyNotices({ noticeRecords,
    textByDigest });
  let noticeFileSha256 = null;
  try {
    const bytes = readSafeFile(root,
      "release-provider/THIRD_PARTY_NOTICES.txt", 5 * 1024 * 1024).bytes;
    noticeFileSha256 = sha256(bytes);
    if (bytes.toString("utf8") !== noticeText) {
      findings.push("RELEASE_PROVIDER_NOTICE_METADATA_MISMATCH");
    }
  } catch (error) {
    findings.push(error instanceof Error ? error.message : String(error));
  }
  return Object.freeze({
    findings: sorted(new Set(findings)),
    licenseTextCount: textByDigest.size,
    noticeBytes: Buffer.byteLength(noticeText),
    noticeFileSha256,
    noticeRecords,
    noticesSha256: sha256(Buffer.from(noticeText, "utf8")),
    ready: findings.length === 0
  });
}

export function renderThirdPartyNotices({ noticeRecords, textByDigest }) {
  const lines = [
    "PROOFTOACT RELEASE-CONTROL THIRD-PARTY NOTICES",
    "",
    "Generated only for the separately locked release-control runtime. This notice does not modify the frozen application notice set.",
    "",
    "PACKAGE RECORDS",
    ""
  ];
  for (const item of noticeRecords) {
    lines.push(`${item.name}@${item.version}`,
      `  License: ${item.license}`,
      `  Registry: ${item.registry}`,
      `  Integrity: ${item.integrity}`,
      `  Text: ${item.licenseTextSha256 ?? "MISSING"}`,
      `  Source: ${item.licenseSource ?? "MISSING"}`, "");
  }
  lines.push("LICENSE TEXTS", "");
  for (const digest of sorted(textByDigest.keys())) {
    lines.push(`----- ${digest} -----`, textByDigest.get(digest).trimEnd(), "");
  }
  return `${lines.join("\n").trimEnd()}\n`;
}

export function renderProviderThirdPartyNotices({ noticeRecords,
  textByDigest }) {
  const lines = [
    "PROOFTOACT RELEASE-PROVIDER THIRD-PARTY NOTICES",
    "",
    "Generated only for the separately locked release-provider toolchain. This notice does not modify the frozen application notice set.",
    "",
    "PACKAGE RECORDS",
    ""
  ];
  for (const item of noticeRecords) {
    lines.push(`${item.name}@${item.version}`,
      `  License: ${item.license}`,
      `  Registry: ${item.registry}`,
      `  Integrity: ${item.integrity}`,
      `  Bundled capabilities: ${item.bundledCapabilities.join(",") || "NONE"}`,
      `  Text: ${item.licenseTextSha256 ?? "MISSING"}`,
      `  Source: ${item.licenseSource ?? "MISSING"}`, "");
  }
  lines.push("LICENSE TEXTS", "");
  for (const digest of sorted(textByDigest.keys())) {
    lines.push(`----- ${digest} -----`, textByDigest.get(digest).trimEnd(), "");
  }
  return `${lines.join("\n").trimEnd()}\n`;
}

export function buildReleaseControlMetadata({ rootDir }) {
  const root = safeRoot(rootDir);
  const dependencies = collectDependencies(root);
  invariant(dependencies.ready, "CONTROL_PLANE_DEPENDENCY_METADATA_NOT_READY");
  const notices = collectNotices(root, dependencies);
  invariant(notices.ready, "CONTROL_PLANE_NOTICE_METADATA_NOT_READY");
  const dependencyInventory = renderDependencyInventoryJson(dependencies);
  const textByDigest = new Map();
  for (const record of notices.noticeRecords) {
    if (record.licenseSource === null) continue;
    const bytes = normalizedLicenseBytes(readSafeFile(root,
      record.licenseSource, 512 * 1024).bytes);
    invariant(sha256(bytes) === record.licenseTextSha256,
      "CONTROL_PLANE_LICENSE_TEXT_CHANGED");
    textByDigest.set(record.licenseTextSha256, bytes.toString("utf8"));
  }
  const thirdPartyNotices = renderThirdPartyNotices({
    noticeRecords: notices.noticeRecords,
    textByDigest
  });
  invariant(sha256(Buffer.from(thirdPartyNotices, "utf8")) ===
    notices.noticesSha256, "CONTROL_PLANE_NOTICE_RENDER_MISMATCH");
  return Object.freeze({
    dependencyInventory,
    dependencyInventoryBytes: Buffer.byteLength(dependencyInventory),
    dependencyInventorySha256:
      sha256(Buffer.from(dependencyInventory, "utf8")),
    thirdPartyNotices,
    thirdPartyNoticesBytes: Buffer.byteLength(thirdPartyNotices),
    thirdPartyNoticesSha256:
      sha256(Buffer.from(thirdPartyNotices, "utf8"))
  });
}

export function verifyReleaseControlMetadata({ rootDir }) {
  const root = safeRoot(rootDir);
  const expected = buildReleaseControlMetadata({ rootDir: root });
  const findings = [];
  const paths = [
    ["release-control/DEPENDENCY_INVENTORY.json", "dependencyInventory",
      "dependencyInventorySha256"],
    ["release-control/THIRD_PARTY_NOTICES.txt", "thirdPartyNotices",
      "thirdPartyNoticesSha256"]
  ];
  const artifacts = paths.map(([relativePath, valueKey, digestKey]) => {
    if (!fs.existsSync(safePath(root, relativePath))) {
      findings.push(`CONTROL_PLANE_METADATA_MISSING:${relativePath}`);
      return { bytes: 0, path: relativePath, sha256: null, status: "MISSING" };
    }
    const bytes = readSafeFile(root, relativePath, 5 * 1024 * 1024).bytes;
    const actual = bytes.toString("utf8");
    const matches = actual === expected[valueKey];
    if (!matches) findings.push(`CONTROL_PLANE_METADATA_MISMATCH:${relativePath}`);
    return {
      bytes: bytes.length,
      expectedSha256: expected[digestKey],
      path: relativePath,
      sha256: sha256(bytes),
      status: matches ? "VERIFIED" : "MISMATCH"
    };
  });
  return Object.freeze({
    artifacts,
    findings,
    ready: findings.length === 0
  });
}

export function verifyReleaseProviderMetadata({ rootDir }) {
  const root = safeRoot(rootDir);
  const dependencies = collectProviderDependencies(root);
  const notices = collectProviderNotices(root, dependencies);
  const findings = [
    ...dependencies.findings.map((item) => `DEPENDENCY:${item}`),
    ...notices.findings.map((item) => `NOTICE:${item}`)
  ];
  const inventoryPath = "release-provider/DEPENDENCY_INVENTORY.json";
  const noticesPath = "release-provider/THIRD_PARTY_NOTICES.txt";
  const inventoryBytes = fs.existsSync(safePath(root, inventoryPath))
    ? readSafeFile(root, inventoryPath, 5 * 1024 * 1024).bytes : null;
  const noticeBytes = fs.existsSync(safePath(root, noticesPath))
    ? readSafeFile(root, noticesPath, 5 * 1024 * 1024).bytes : null;
  if (inventoryBytes === null) findings.push(`MISSING:${inventoryPath}`);
  if (noticeBytes === null) findings.push(`MISSING:${noticesPath}`);
  const expectedInventory = dependencies.ready
    ? renderProviderDependencyInventoryJson(dependencies) : null;
  if (inventoryBytes !== null && expectedInventory !== null &&
    inventoryBytes.toString("utf8") !== expectedInventory) {
    findings.push(`MISMATCH:${inventoryPath}`);
  }
  return Object.freeze({
    artifacts: Object.freeze([
      Object.freeze({
        bytes: inventoryBytes?.length ?? 0,
        expectedSha256: expectedInventory === null ? null :
          sha256(Buffer.from(expectedInventory, "utf8")),
        path: inventoryPath,
        sha256: inventoryBytes === null ? null : sha256(inventoryBytes),
        status: inventoryBytes !== null && expectedInventory !== null &&
          inventoryBytes.toString("utf8") === expectedInventory
          ? "VERIFIED" : "MISMATCH"
      }),
      Object.freeze({
        bytes: noticeBytes?.length ?? 0,
        expectedSha256: notices.noticesSha256,
        path: noticesPath,
        sha256: noticeBytes === null ? null : sha256(noticeBytes),
        status: noticeBytes !== null && notices.ready &&
          sha256(noticeBytes) === notices.noticesSha256
          ? "VERIFIED" : "MISMATCH"
      })
    ]),
    dependencies,
    findings: sorted(new Set(findings)),
    notices,
    ready: findings.length === 0
  });
}

function readText(root, relativePath) {
  return readSafeFile(root, relativePath).bytes.toString("utf8");
}

function collectSecurity(root, inventory) {
  const checks = [];
  const check = (id, passed, detail) => checks.push({ detail, id, passed });
  const productionEntries = inventory.files.filter(({ path: entry }) =>
    !entry.startsWith("test/") && !entry.endsWith(".md") &&
    !entry.includes("schema"));
  check("PUBLIC_KEY_EXTENSION_ONLY",
    inventory.files.every(({ path: entry }) => !entry.endsWith(".pem")),
    "The control-plane inventory must contain no .pem path.");
  let keyValid = false;
  try {
    const key = crypto.createPublicKey(readText(root,
      "config/prooftoact-release-operator-public.pub"));
    keyValid = key.type === "public" && key.asymmetricKeyType === "ec" &&
      key.asymmetricKeyDetails?.namedCurve === "prime256v1";
  } catch {
    keyValid = false;
  }
  check("P256_PUBLIC_TRUST_ANCHOR", keyValid,
    "The source-owned trust anchor must be a P-256 public key only.");
  const secretHits = [];
  for (const item of productionEntries) {
    const text = readText(root, item.path);
    if (/-----BEGIN (?:EC |RSA |OPENSSH )?PRIVATE KEY-----/u.test(text) ||
      /\bAKIA[0-9A-Z]{16}\b/u.test(text)) secretHits.push(item.path);
  }
  check("NO_PRODUCTION_SECRET_MATERIAL", secretHits.length === 0,
    secretHits.length === 0 ? "No private key or static AWS key pattern found." :
      `Hits: ${secretHits.join(", ")}`);
  const workflowChecks = [];
  for (const workflow of WORKFLOWS) {
    const relativePath = `.github/workflows/${workflow.file}`;
    if (!fs.existsSync(safePath(root, relativePath))) {
      workflowChecks.push({ file: workflow.file, passed: false });
      continue;
    }
    const text = readText(root, relativePath);
    const uses = [...text.matchAll(/^\s*uses:\s*[^@\s]+@([^\s#]+)/gmu)]
      .map((match) => match[1]);
    const checkoutCount = (text.match(/uses:\s*actions\/checkout@/gu) ?? [])
      .length;
    const disabledCredentialCount =
      (text.match(/persist-credentials:\s*false/gu) ?? []).length;
    const lines = text.split("\n");
    const sourceJobs = workflow.sourceJobs ?? Object.freeze([
      Object.freeze({
        environment: workflow.environment,
        jobName: workflow.environment === "aws-release-terminalization"
          ? "terminalizer-diagnostic" : "controller-diagnostic"
      })
    ]);
    const sourceJobsBound = sourceJobs.every(({ environment, jobName }) =>
      lines.includes(`  ${jobName}:`) && (environment === null ||
        lines.includes(`    environment: ${environment}`)));
    const phaseWiredDefaultHold = workflow.sourceJobs !== undefined &&
      sourceJobsBound &&
      /^\s*default:\s*true\s*$/mu.test(text) &&
      text.includes("PROOFTOACT_RELEASE_PHASE_ENVIRONMENT: DIAGNOSTIC_NO_PROVIDER") &&
      (text.match(/^\s*id-token:\s*write\s*$/gmu) ?? []).length === 3 &&
      (text.match(/!inputs\.diagnostic_only/gu) ?? []).length >= 3 &&
      (text.match(/node scripts\/run-release-prepare-preflight\.js /gu) ?? [])
        .length === 3;
    workflowChecks.push({
      actionPinsExact: uses.length >= 2 && uses.every((value) => HEX_40.test(value)),
      contentsReadOnly: /^permissions:\s*\n\s+contents:\s+read\s*$/mu.test(text),
      diagnosticFailClosed:
        text.includes("PROVIDER_EXECUTION_DISABLED_RUNTIME_AUTHORITY_RECEIPTS_REQUIRED"),
      environmentBound: sourceJobsBound,
      file: workflow.file,
      idTokenAbsent: !/^\s*id-token:/mu.test(text),
      nameBound: text.startsWith(`name: ${workflow.name}\n`),
      phaseWiredDefaultHold,
      persistedCredentialsDisabled: checkoutCount >= 2 &&
        disabledCredentialCount === checkoutCount,
      providerExecutionEnabled: /^\s*id-token:\s*write\s*$/mu.test(text)
    });
  }
  check("DIAGNOSTIC_WORKFLOWS_FAIL_CLOSED",
    workflowChecks.every((item) => item.actionPinsExact && item.contentsReadOnly &&
      item.environmentBound && item.nameBound && item.persistedCredentialsDisabled &&
      (item.file === "prooftoact-release-candidate.yml"
        ? item.phaseWiredDefaultHold
        : item.diagnosticFailClosed && item.idTokenAbsent)),
  "The release-candidate workflow is phase-wired but defaults to a diagnostic HOLD; the other five workflows remain diagnostic-only. Provider authority is not inferred.");
  let hostedDualRootConstrained = false;
  try {
    const hosted = readText(root,
      ".github/workflows/prooftoact-hosted-dual-root-verification.yml");
    const generator = readText(root,
      "control-plane-verification/hosted-dual-root-verification.js");
    const uses = [...hosted.matchAll(/^\s*uses:\s*[^@\s]+@([^\s#]+)/gmu)]
      .map((match) => match[1]);
    hostedDualRootConstrained =
      hosted.startsWith("name: ProofToAct Hosted Dual Root Verification\n") &&
      /^permissions:\s*\n\s+contents:\s+read\s*$/mu.test(hosted) &&
      (hosted.match(/uses:\s*actions\/checkout@/gu) ?? []).length === 2 &&
      (hosted.match(/persist-credentials:\s*false/gu) ?? []).length === 2 &&
      uses.length === 4 && uses.every((value) => HEX_40.test(value)) &&
      !/^\s*id-token:/mu.test(hosted) &&
      !/^\s*environment:/mu.test(hosted) &&
      !/\$\{\{\s*secrets\./u.test(hosted) &&
      !/configure-aws-credentials|cockroach|execute-change-set/iu.test(hosted) &&
      hosted.includes("ref: 963937a9873f0199b91897fe88da1b91bc84b5e3") &&
      hosted.includes("retention-days: 90") &&
      hosted.includes("if-no-files-found: error") &&
      hosted.includes("verify-hosted-dual-root-verification.js") &&
      generator.includes("ACTIONS_ID_TOKEN_REQUEST_TOKEN") &&
      generator.includes("providerExecutionAuthorized: false") &&
      generator.includes("liveParameterValuesObserved: false") &&
      generator.includes("HOSTED_DUAL_ROOT_REQUIRED_TEST_SKIPPED");
  } catch {
    hostedDualRootConstrained = false;
  }
  check("HOSTED_DUAL_ROOT_NO_OIDC_COMPLETE_EVIDENCE",
    hostedDualRootConstrained,
    "The retained hosted lane must bind separate exact roots, reject OIDC/provider credentials, require zero skipped tests, and publish only a non-authorizing evidence artifact.");
  let credentialChainDisabled = false;
  try {
    const builder = readText(root, "release-control/build-release-control-runtime.js");
    const runtime = readText(root,
      "release-control/src/release-control-aws-runtime.js");
    credentialChainDisabled = builder.includes("denyCredentialChainPlugin") &&
      builder.includes("credential-provider-node") &&
      runtime.includes("maxAttempts: 1");
  } catch {
    credentialChainDisabled = false;
  }
  check("CREDENTIAL_CHAIN_AND_RETRY_DISABLED", credentialChainDisabled,
    "The sealed runtime must deny ambient credential-chain fallback and SDK retries.");
  let providerBundlesConstrained = false;
  try {
    const builder = readText(root,
      "release-provider/build-release-provider-runtimes.js");
    const loader = readText(root,
      "release-provider/src/release-provider-runtime-loader.js");
    providerBundlesConstrained =
      builder.includes("denyCredentialChainPlugin") &&
      builder.includes("RELEASE_PROVIDER_CREDENTIAL_CHAIN_PRESENT") &&
      builder.includes("RELEASE_PROVIDER_EXTERNAL_IMPORT_REJECTED") &&
      loader.includes("value.externalImports.every") &&
      loader.includes("/^node:[a-z0-9_./-]+$/u") &&
      loader.includes("receipt.runtimes.length === 3");
  } catch {
    providerBundlesConstrained = false;
  }
  check("PROVIDER_BUNDLES_DENY_CREDENTIAL_CHAIN_AND_EXTERNAL_IMPORTS",
    providerBundlesConstrained,
    "All three provider capability bundles must reject credential-chain packages and permit only explicit node: builtin external imports.");
  let tableIdentityBound = false;
  try {
    const template = JSON.parse(readText(root,
      "infra/aws/release-deployment-roles-template.json"));
    const attester = readText(root,
      "scripts/lib/release-control-table-identity.js");
    const bundle = readText(root,
      "release-control/src/release-control-bundle-entry.js");
    tableIdentityBound =
      template.Resources?.ReleaseControlTable?.Properties?.SSESpecification
        ?.KMSMasterKeyId === "alias/aws/dynamodb" &&
      attester.includes("table.TableId") &&
      attester.includes("KMSMasterKeyArn") &&
      attester.includes("kmsKeyArnSha256") &&
      bundle.includes("attestReleaseControlTable");
  } catch {
    tableIdentityBound = false;
  }
  check("LIVE_TABLE_ID_KMS_AND_SEALED_ATTESTER_BOUND", tableIdentityBound,
    "The template pins alias/aws/dynamodb and the sealed runtime exports an attester binding live TableId and exact returned KMS ARN.");
  let physicalStackBound = false;
  try {
    const broker = readText(root, "scripts/release-provider-one-shot-broker.js");
    physicalStackBound = broker.includes("value.deleteExactStackId === release.stackId") &&
      broker.includes("value.originatingChangeSetArn === release.changeSetArn") &&
      broker.includes("value.originatingChangeSetSha256 === release.changeSetSha256") &&
      broker.includes("runtime.stackId === approval.claims.release.stackId");
  } catch {
    physicalStackBound = false;
  }
  check("PHYSICAL_STACK_AND_CHANGE_SET_BOUND", physicalStackBound,
    "Teardown and execution bind the exact physical stack ID and originating change-set identity, not only a reusable stack name.");
  return Object.freeze({
    checks,
    ready: checks.every(({ passed }) => passed),
    workflowChecks
  });
}

function collectCost(root) {
  const checks = [];
  const check = (id, passed, detail) => checks.push({ detail, id, passed });
  let broker = "";
  let store = "";
  let template = null;
  try {
    broker = readText(root, "scripts/release-provider-one-shot-broker.js");
    store = readText(root,
      "release-control/src/release-control-dynamodb-store.js");
    template = JSON.parse(readText(root,
      "infra/aws/release-deployment-roles-template.json"));
  } catch (error) {
    check("COST_SOURCE_READABLE", false, error.message);
    return {
      checks,
      controlPlaneCumulativeCapUsd: 20,
      historicalApplicationCostPolicy:
        "UNCHANGED_SEPARATE_FROZEN_APPLICATION_CONTROL",
      ready: false
    };
  }
  check("CUMULATIVE_CAP_20_USD",
    broker.includes("const CUMULATIVE_SPEND_CAP_USD = 20;") &&
      store.includes("const CAP_MICRO_USD = 20_000_000;"),
  "Broker dollars and atomic ledger microdollars must encode one $20 cap.");
  check("ONE_RUN_CONCURRENCY_TWO",
    broker.includes("const MAXIMUM_RUNS = 1;") &&
      broker.includes("const MAXIMUM_CONCURRENCY = 2;") &&
      store.includes("command.maximumRuns === 1") &&
      store.includes("command.maximumConcurrency === 2"),
  "The signed command and durable store must enforce one run and concurrency two.");
  check("STABLE_PROJECT_ACCOUNT_REGION_LEDGER",
    /const budgetKeySha256 = canonicalDigest\(\{\s*currency: "USD",\s*project: "ProofToAct",\s*providerAccountId: approval\.providerAccountId,\s*region: REGION\s*\}\);/su
      .test(broker),
  "Budget occupancy must not reset across approval, cap, or control-plane revisions.");
  check("OCCUPANCY_AND_BUDGET_NEVER_RELEASED",
    broker.includes("effectOccupancyReleased === false") &&
      broker.includes("budgetReservationReleased === false") &&
      store.includes("effectOccupancyReleased: false") &&
      store.includes("budgetReservationReleased: false"),
  "Terminalization cannot release effect occupancy or reserved spend.");
  const table = template?.Resources?.ReleaseControlTable;
  check("RETAINED_PAY_PER_REQUEST_TABLE",
    table?.DeletionPolicy === "Retain" && table?.UpdateReplacePolicy === "Retain" &&
      table?.Properties?.BillingMode === "PAY_PER_REQUEST" &&
      table?.Properties?.DeletionProtectionEnabled === true,
  "The controller table is retained, deletion protected, encrypted separately, and on demand.");
  const coordinator = Object.values(template?.Resources ?? {}).find((resource) =>
    resource?.Type === "AWS::IAM::Role" &&
    resource?.Properties?.RoleName === "ProofToActReleaseCoordinator");
  const coordinatorPolicy = canonicalJson(coordinator?.Properties?.Policies ?? []);
  check("SEPARATE_COORDINATOR_OWNS_ATOMIC_LEDGER",
    coordinatorPolicy.includes("dynamodb:TransactWriteItems") &&
      coordinatorPolicy.includes("dynamodb:UpdateItem") &&
      coordinatorPolicy.includes("DenyProviderMutationAndAuthorityCapabilities") &&
      coordinatorPolicy.includes("cloudformation:Create*") &&
      coordinatorPolicy.includes("lambda:Invoke*") &&
      coordinatorPolicy.includes("sts:AssumeRole"),
  "A seventh protected, credential-isolated coordinator owns store transitions and is denied provider dispatch authority.");
  const explicitTeardownReserve =
    broker.includes("const TEARDOWN_BUDGET_RESERVE_USD = 1;") &&
    broker.includes("value.teardownReserveUsd === TEARDOWN_BUDGET_RESERVE_USD") &&
    broker.includes("value.cumulativeCapUsd - value.teardownReserveUsd") &&
    broker.includes("value.authorizedAdditionalUsd <= value.teardownReserveUsd") &&
    store.includes("command.teardownReserveUsd") &&
    store.includes("exactMoney(command.teardownReserveUsd, code) === 1_000_000");
  check("EXPLICIT_TEARDOWN_BUDGET_RESERVATION", explicitTeardownReserve,
    explicitTeardownReserve
      ? "A named teardown reserve is bound in both command and durable ledger."
      : "HOLD: no explicit named teardown budget reservation is bound yet.");
  return Object.freeze({
    checks,
    controlPlaneCumulativeCapUsd: 20,
    historicalApplicationCostPolicy:
      "UNCHANGED_SEPARATE_FROZEN_APPLICATION_CONTROL",
    ready: checks.every(({ passed }) => passed)
  });
}

function roleTrustEnvironment(template, roleName) {
  for (const resource of Object.values(template?.Resources ?? {})) {
    if (resource?.Type !== "AWS::IAM::Role" ||
      resource?.Properties?.RoleName !== roleName) continue;
    const document = resource.Properties.AssumeRolePolicyDocument;
    const serialized = canonicalJson(document);
    return GOVERNANCE_LANES.find(({ environment }) =>
      serialized.includes(environment))
      ?.environment ?? null;
  }
  return null;
}

function collectGovernance(root, governanceEvidence) {
  const sourceMappings = [];
  let template = null;
  let broker = "";
  try {
    template = JSON.parse(readText(root,
      "infra/aws/release-deployment-roles-template.json"));
    broker = readText(root, "scripts/release-provider-one-shot-broker.js");
  } catch {
    template = null;
  }
  for (const workflow of GOVERNANCE_LANES) {
    const relativePath = `.github/workflows/${workflow.file}`;
    let sourceWorkflowSha256 = null;
    let workflowSourceBound = false;
    if (fs.existsSync(safePath(root, relativePath))) {
      const bytes = readSafeFile(root, relativePath).bytes;
      const text = bytes.toString("utf8");
      const lines = text.split("\n");
      sourceWorkflowSha256 = sha256(bytes);
      workflowSourceBound = text.startsWith(`name: ${workflow.name}\n`) &&
        workflow.jobNames.every((jobName) =>
          lines.includes(`  ${jobName}:`)) &&
        lines.includes(`    environment: ${workflow.environment}`);
    }
    const brokerBound = workflow.environment === "aws-release-coordination"
      ? readText(root, "scripts/release-provider-controller.js")
          .includes(`coordinator: "${workflow.roleName}"`)
      : broker.includes(`environment: "${workflow.environment}"`) &&
        broker.includes(`roleName: "${workflow.roleName}"`) &&
        broker.includes(`workflow: "${workflow.name}"`);
    sourceMappings.push({
      brokerBound,
      environment: workflow.environment,
      jobNames: workflow.jobNames,
      roleName: workflow.roleName,
      sourceWorkflowSha256,
      templateTrustEnvironment: roleTrustEnvironment(template, workflow.roleName),
      workflowFile: workflow.file,
      workflowName: workflow.name,
      workflowRef: `Flash-Bri/prooftoact/.github/workflows/${workflow.file}@refs/heads/main`,
      workflowSourceBound
    });
  }
  let providerEvidence = {
    evidenceSha256: null,
    schemaVersion: GOVERNANCE_EVIDENCE_SCHEMA,
    status: "NOT_PROVIDED"
  };
  if (governanceEvidence !== null) {
    validateGovernanceEvidence(governanceEvidence);
    providerEvidence = {
      evidenceSha256: canonicalDigest(governanceEvidence),
      schemaVersion: GOVERNANCE_EVIDENCE_SCHEMA,
      status: "ACCEPTED"
    };
  }
  const sourceReady = sourceMappings.length === 7 && sourceMappings.every((item) =>
    item.brokerBound && item.workflowSourceBound &&
    item.templateTrustEnvironment === item.environment);
  return Object.freeze({
    providerEvidence,
    providerEvidenceRequired: Object.freeze({
      branchProtectionNoBypass: true,
      environmentCount: 7,
      exactWorkflowRefs: GOVERNANCE_LANES.map(({ file, jobNames }) => ({
        jobNames,
        workflowRef:
          `Flash-Bri/prooftoact/.github/workflows/${file}@refs/heads/main`
      })),
      preventSelfReview: true,
      requiredReviewersPerEnvironmentMinimum: 1,
      schemaVersion: GOVERNANCE_EVIDENCE_SCHEMA
    }),
    sourceMappings,
    sourceReady
  });
}

export function validateGovernanceEvidence(value) {
  invariant(exactKeys(value, [
    "accountIdSha256", "branchProtection", "environments", "observedAt",
    "repository", "repositoryId", "schemaVersion", "status"
  ]) && value.schemaVersion === GOVERNANCE_EVIDENCE_SCHEMA &&
    value.status === "ACCEPTED" && value.repository === "Flash-Bri/prooftoact" &&
    value.repositoryId === "1317716765" && HEX_64.test(value.accountIdSha256 ?? "") &&
    Number.isFinite(Date.parse(value.observedAt)) &&
    exactKeys(value.branchProtection, [
      "administratorsEnforced", "deletionAllowed", "forcePushAllowed",
      "requiredCheck", "strict", "status"
    ]) && value.branchProtection.status === "ACCEPTED" &&
    value.branchProtection.administratorsEnforced === true &&
    value.branchProtection.deletionAllowed === false &&
    value.branchProtection.forcePushAllowed === false &&
    value.branchProtection.requiredCheck === "verify" &&
    value.branchProtection.strict === true && Array.isArray(value.environments) &&
    value.environments.length === GOVERNANCE_LANES.length,
  "CONTROL_PLANE_GOVERNANCE_EVIDENCE_REJECTED");
  const expected = new Map(GOVERNANCE_LANES.map((item) =>
    [item.environment, item]));
  for (const item of value.environments) {
    const mapping = expected.get(item?.environment);
    invariant(mapping !== undefined && exactKeys(item, [
      "adminsCanBypass", "deploymentBranch", "environment", "jobNames", "preventSelfReview",
      "requiredReviewerCount", "roleArnSha256", "trustPolicySha256",
      "workflowRef"
    ]) && item.adminsCanBypass === false && item.preventSelfReview === true &&
      Number.isSafeInteger(item.requiredReviewerCount) &&
      item.requiredReviewerCount >= 1 && item.deploymentBranch === "main" &&
      Array.isArray(item.jobNames) &&
      canonicalJson(item.jobNames) === canonicalJson(mapping.jobNames) &&
      item.workflowRef ===
        `Flash-Bri/prooftoact/.github/workflows/${mapping.file}@refs/heads/main` &&
      HEX_64.test(item.roleArnSha256 ?? "") &&
      HEX_64.test(item.trustPolicySha256 ?? ""),
    "CONTROL_PLANE_GOVERNANCE_ENVIRONMENT_EVIDENCE_REJECTED");
    expected.delete(item.environment);
  }
  invariant(expected.size === 0,
    "CONTROL_PLANE_GOVERNANCE_ENVIRONMENT_SET_REJECTED");
  return value;
}

function gitOutput(root, args) {
  try {
    return execFileSync("/usr/bin/git", ["-C", root, ...args], {
      encoding: "utf8",
      env: {
        GIT_ATTR_NOSYSTEM: "1",
        GIT_CONFIG_GLOBAL: "/dev/null",
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_NO_REPLACE_OBJECTS: "1",
        GIT_OPTIONAL_LOCKS: "0",
        LANG: "C",
        LC_ALL: "C",
        PATH: "/usr/bin:/bin"
      },
      maxBuffer: 4 * 1024 * 1024,
      stdio: ["ignore", "pipe", "pipe"]
    }).trim();
  } catch {
    return null;
  }
}

function gitBlob(root, relativePath) {
  try {
    return execFileSync("/usr/bin/git", ["-C", root, "show", `HEAD:${relativePath}`], {
      env: {
        GIT_ATTR_NOSYSTEM: "1",
        GIT_CONFIG_GLOBAL: "/dev/null",
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_NO_REPLACE_OBJECTS: "1",
        GIT_OPTIONAL_LOCKS: "0",
        LANG: "C",
        LC_ALL: "C",
        PATH: "/usr/bin:/bin"
      },
      maxBuffer: 8 * 1024 * 1024,
      stdio: ["ignore", "pipe", "pipe"]
    });
  } catch {
    return null;
  }
}

function collectProvenance(root, dependencies, providerDependencies,
  provenanceEvidence, provenanceVerification) {
  const gitMarker = path.join(root, ".git");
  let gitDirKind = "missing";
  if (fs.existsSync(gitMarker)) {
    const stat = fs.lstatSync(gitMarker);
    gitDirKind = stat.isDirectory() ? "standalone-directory" :
      stat.isFile() ? "linked-worktree-file" : "unsupported";
  }
  const headCommit = gitOutput(root, ["rev-parse", "HEAD"]);
  const headTree = gitOutput(root, ["rev-parse", "HEAD^{tree}"]);
  const rootPackage = fs.existsSync(path.join(root, "package.json"))
    ? readSafeFile(root, "package.json").bytes : null;
  const rootLock = fs.existsSync(path.join(root, "package-lock.json"))
    ? readSafeFile(root, "package-lock.json", 4 * 1024 * 1024).bytes : null;
  const headPackage = gitBlob(root, "package.json");
  const headLock = gitBlob(root, "package-lock.json");
  const frozenAppDependencyBytesUnchanged = rootPackage !== null && rootLock !== null &&
    headPackage !== null && headLock !== null &&
    rootPackage.equals(headPackage) && rootLock.equals(headLock);
  let providerEvidence = {
    evidenceSha256: null,
    schemaVersion: PROVENANCE_EVIDENCE_SCHEMA,
    status: "NOT_PROVIDED"
  };
  if (provenanceEvidence !== null) {
    validateProvenanceEvidence(provenanceEvidence, dependencies,
      providerDependencies, provenanceVerification);
    providerEvidence = {
      evidenceSha256: canonicalDigest(provenanceEvidence),
      schemaVersion: PROVENANCE_EVIDENCE_SCHEMA,
      status: "ACCEPTED"
    };
  }
  return Object.freeze({
    cleanStandaloneExpectations: Object.freeze({
      auditFindingCount: 0,
      buildReproducible: true,
      controlPlaneCommitDistinctFromFrozenApplication: true,
      gitDirKind: "standalone-directory",
      gitReplacements: false,
      gitShallow: false,
      npmCiArguments: Object.freeze({
        releaseControl: ["ci", "--ignore-scripts"],
        releaseProvider: ["ci", "--ignore-scripts"]
      }),
      npmVersion: "10.9.8",
      nodeVersion: "v22.23.1",
      officialOrigin: "https://github.com/Flash-Bri/prooftoact.git",
      statusClean: true,
      testFailureCount: 0
    }),
    dependenciesReady: dependencies.ready && providerDependencies.ready,
    frozenAppDependencyBytesUnchanged,
    gitDirKind,
    headCommit: HEX_40.test(headCommit ?? "") ? headCommit : null,
    headTree: HEX_40.test(headTree ?? "") ? headTree : null,
    providerEvidence,
    sourceIdentityState: headCommit === FROZEN_APPLICATION.commit &&
      headTree === FROZEN_APPLICATION.tree
      ? "FROZEN_APPLICATION_ONLY_CONTROL_PLANE_UNCOMMITTED"
      : "CONTROL_PLANE_IDENTITY_REQUIRES_INDEPENDENT_VERIFICATION"
  });
}

export function validateProvenanceEvidence(value, dependencies,
  providerDependencies, verificationOptions = null) {
  validateControlPlaneProvenanceEvidence(value);
  const build = value.body.executions.build;
  invariant(build.releaseControl.packageJsonSha256 ===
    dependencies.packageSha256 &&
    build.releaseControl.packageLockSha256 ===
      dependencies.packageLockSha256 &&
    build.releaseProvider.packageJsonSha256 ===
      providerDependencies.packageSha256 &&
    build.releaseProvider.packageLockSha256 ===
      providerDependencies.packageLockSha256 &&
    build.releaseProvider.runtimeSetSha256 ===
      providerDependencies.runtimeSetSha256,
  "CONTROL_PLANE_PROVENANCE_DEPENDENCY_BINDING_REJECTED");
  invariant(plainObject(verificationOptions) &&
    typeof verificationOptions.controlPlaneRoot === "string" &&
    typeof verificationOptions.frozenApplicationRoot === "string" &&
    typeof verificationOptions.npmCli === "string",
  "CONTROL_PLANE_PROVENANCE_INDEPENDENT_REPRODUCTION_REQUIRED");
  const verified = verifyControlPlaneProvenanceEvidence(value,
    verificationOptions);
  invariant(verified.providerExecutionAuthorized === false &&
    verified.status === "LOCAL_PROVENANCE_REPRODUCED",
  "CONTROL_PLANE_PROVENANCE_INDEPENDENT_REPRODUCTION_REJECTED");
  return value;
}

function localFindings({ inventory, dependencies, notices, providerDependencies,
  providerMetadataArtifacts, providerNotices, security, cost, governance,
  metadataArtifacts, provenance }) {
  const findings = [];
  inventory.missingPaths.forEach((item) => findings.push(`MISSING:${item}`));
  inventory.dirtyPaths.forEach((item) => findings.push(`DIRTY:${item}`));
  inventory.untrackedPaths.forEach((item) => findings.push(`UNTRACKED:${item}`));
  inventory.unexpectedWorkflowPaths.forEach((item) =>
    findings.push(`UNEXPECTED_WORKFLOW:${item}`));
  dependencies.findings.forEach((item) => findings.push(`DEPENDENCY:${item}`));
  providerDependencies.findings.forEach((item) =>
    findings.push(`PROVIDER_DEPENDENCY:${item}`));
  notices.findings.forEach((item) => findings.push(`NOTICE:${item}`));
  providerNotices.findings.forEach((item) =>
    findings.push(`PROVIDER_NOTICE:${item}`));
  metadataArtifacts.findings.forEach((item) =>
    findings.push(`METADATA:${item}`));
  providerMetadataArtifacts.findings.forEach((item) =>
    findings.push(`PROVIDER_METADATA:${item}`));
  security.checks.filter(({ passed }) => !passed).forEach(({ id }) =>
    findings.push(`SECURITY:${id}`));
  cost.checks.filter(({ passed }) => !passed).forEach(({ id }) =>
    findings.push(`COST:${id}`));
  if (!governance.sourceReady) findings.push("GOVERNANCE:SOURCE_MAPPING_INCOMPLETE");
  if (!provenance.frozenAppDependencyBytesUnchanged) {
    findings.push("PROVENANCE:FROZEN_APP_DEPENDENCY_BYTES_CHANGED");
  }
  return sorted(new Set(findings));
}

export function buildCandidate({
  frozenApplicationRoot = null,
  governanceEvidence = null,
  npmCli = null,
  provenanceEvidence = null,
  rootDir
}) {
  const root = safeRoot(rootDir);
  const inventory = collectInventory(root);
  const dependencies = collectDependencies(root);
  const notices = collectNotices(root, dependencies);
  const metadataArtifacts = verifyReleaseControlMetadata({ rootDir: root });
  const providerMetadataVerification = verifyReleaseProviderMetadata({
    rootDir: root
  });
  const providerDependencies = providerMetadataVerification.dependencies;
  const providerNotices = providerMetadataVerification.notices;
  const providerMetadataArtifacts = Object.freeze({
    artifacts: providerMetadataVerification.artifacts,
    findings: providerMetadataVerification.findings,
    ready: providerMetadataVerification.ready
  });
  const security = collectSecurity(root, inventory);
  const cost = collectCost(root);
  const governance = collectGovernance(root, governanceEvidence);
  const provenance = collectProvenance(root, dependencies,
    providerDependencies, provenanceEvidence, provenanceEvidence === null
      ? null : {
        controlPlaneRoot: root,
        frozenApplicationRoot,
        npmCli
      });
  const findings = localFindings({ inventory, dependencies, notices,
    providerDependencies, providerMetadataArtifacts, providerNotices, security,
    cost, governance, metadataArtifacts, provenance });
  const localSourceReady = findings.length === 0;
  const providerEvidenceReady =
    governance.providerEvidence.status === "ACCEPTED" &&
    provenance.providerEvidence.status === "ACCEPTED";
  const body = Object.freeze({
    claimBoundary: Object.freeze({
      providerActionsPerformed: false,
      providerExecutionAuthorizedByThisArtifact: false,
      providerFactsInferredFromSource: false,
      sourceConfigurationOnly: true
    }),
    cost,
    dependencies,
    findings,
    frozenApplication: FROZEN_APPLICATION,
    governance,
    inventory,
    metadataArtifacts,
    notices,
    providerDependencies,
    providerMetadataArtifacts,
    providerNotices,
    policy: Object.freeze({
      allowedLicenses: ALLOWED_LICENSES,
      candidateSchema: CANDIDATE_SCHEMA,
      governanceEvidenceSchema: GOVERNANCE_EVIDENCE_SCHEMA,
      provenanceEvidenceSchema: PROVENANCE_EVIDENCE_SCHEMA,
      requiredProtectedEnvironmentCount: GOVERNANCE_LANES.length,
      requiredWorkflowCount: WORKFLOWS.length,
      sourcePolicySha256: canonicalDigest({
        discoveryRules: DISCOVERY_RULES.map((rule) => ({
          directory: rule.directory,
          pattern: rule.pattern.source,
          recursive: rule.recursive
        })),
        directDevelopmentDependencies: EXPECTED_DIRECT_DEV_DEPENDENCIES,
        directRuntimeDependencies: EXPECTED_DIRECT_DEPENDENCIES,
        providerDirectDevelopmentDependencies:
          EXPECTED_PROVIDER_DIRECT_DEV_DEPENDENCIES,
        providerDirectRuntimeDependencies:
          EXPECTED_PROVIDER_DIRECT_DEPENDENCIES,
        governanceLanes: GOVERNANCE_LANES,
        requiredExactPaths: REQUIRED_EXACT_PATHS,
        workflows: WORKFLOWS
      })
    }),
    proof: Object.freeze({
      controlPlaneSurfaceSha256: canonicalDigest({
        costChecks: cost.checks,
        dependencyInventorySha256: dependencies.inventorySha256,
        governanceSourceMappings: governance.sourceMappings,
        inventorySha256: inventory.inventorySha256,
        metadataArtifacts: metadataArtifacts.artifacts,
        noticesSha256: notices.noticesSha256,
        providerDependencyInventorySha256:
          providerDependencies.inventorySha256,
        providerMetadataArtifacts: providerMetadataArtifacts.artifacts,
        providerNoticesSha256: providerNotices.noticesSha256,
        securityChecks: security.checks
      }),
      costContractSha256: canonicalDigest(cost.checks),
      dependencyInventorySha256: dependencies.inventorySha256,
      governanceSourceSha256: canonicalDigest(governance.sourceMappings),
      inventorySha256: inventory.inventorySha256,
      metadataArtifactsSha256: canonicalDigest(metadataArtifacts.artifacts),
      noticesSha256: notices.noticesSha256,
      providerDependencyInventorySha256:
        providerDependencies.inventorySha256,
      providerMetadataArtifactsSha256:
        canonicalDigest(providerMetadataArtifacts.artifacts),
      providerNoticesSha256: providerNotices.noticesSha256,
      securityContractSha256: canonicalDigest(security.checks)
    }),
    provenance,
    readiness: Object.freeze({
      finalDisposition: localSourceReady && providerEvidenceReady
        ? "CANDIDATE_VERIFIED_PROVIDER_ACTION_STILL_SEPARATELY_AUTHORIZED"
        : "HOLD",
      localSourceReady,
      providerEvidenceReady,
      providerExecutionAuthorized: false
    }),
    schemaVersion: BODY_SCHEMA,
    security
  });
  return Object.freeze({
    body,
    bodySha256: canonicalDigest(body),
    schemaVersion: CANDIDATE_SCHEMA
  });
}

export function verifyCandidate(candidate, options) {
  invariant(exactKeys(candidate, ["body", "bodySha256", "schemaVersion"]) &&
    candidate.schemaVersion === CANDIDATE_SCHEMA &&
    HEX_64.test(candidate.bodySha256 ?? "") &&
    candidate.body?.schemaVersion === BODY_SCHEMA &&
    canonicalDigest(candidate.body) === candidate.bodySha256,
  "CONTROL_PLANE_CANDIDATE_ENVELOPE_REJECTED");
  const rebuilt = buildCandidate(options);
  invariant(canonicalJson(rebuilt) === canonicalJson(candidate),
    "CONTROL_PLANE_CANDIDATE_SOURCE_MISMATCH");
  return Object.freeze({
    bodySha256: candidate.bodySha256,
    localSourceReady: candidate.body.readiness.localSourceReady,
    providerEvidenceReady: candidate.body.readiness.providerEvidenceReady,
    providerExecutionAuthorized: false,
    status: candidate.body.readiness.finalDisposition
  });
}

export const CONTROL_PLANE_VERIFICATION_CONSTANTS = Object.freeze({
  BODY_SCHEMA,
  CANDIDATE_SCHEMA,
  GOVERNANCE_EVIDENCE_SCHEMA,
  GOVERNANCE_LANES,
  PROVENANCE_EVIDENCE_SCHEMA,
  WORKFLOWS
});
