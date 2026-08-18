import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import {
  assertCleanExactGitCheckout,
  assertExactGitRepositoryLayout,
  gitEnvironment,
  readExactGitBlob,
  trustedGitExecutable,
  trustedTemporaryRoot
} from "../scripts/lib/exact-git-source.js";
import {
  expectedOfficialNodeRuntime
} from "../src/cloud/official-node-runtime-contract.js";

const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const OFFICIAL_ORIGIN = "https://github.com/Flash-Bri/prooftoact.git";
const OFFICIAL_REPOSITORY = "Flash-Bri/prooftoact";
const SCHEMA = "prooftoact.control-plane-provenance-evidence.v2";
const FROZEN_APPLICATION = Object.freeze({
  commit: "963937a9873f0199b91897fe88da1b91bc84b5e3",
  tree: "a330e0d57328e63a568be73c523b2cae6338f26c"
});
const NODE_VERSION = "v22.23.1";
const NPM_VERSION = "10.9.8";
const NPM_PACKAGE_IDENTITY = Object.freeze({
  cliSha256: "8e5f6f3429f8cdbe693cdc29904e9d5a7b127a494bd15c804bd54c7403bfcbe7",
  fileCount: 1964,
  packageJsonSha256:
    "3f6dff62de33c82d89e986a05ddd5644e6b613344a54ecf2820a612bfbaee7d7",
  treeSha256: "d81bc4bf8e3252c48b5c0c08488c128d1b47dd21b52e25e2d202f8ffb54931bc"
});
const SOURCE_ROOT = fs.realpathSync(fileURLToPath(new URL("..", import.meta.url)));
const PACKAGE_PATHS = Object.freeze([
  "package.json",
  "package-lock.json",
  "release-control/package.json",
  "release-control/package-lock.json",
  "release-provider/package.json",
  "release-provider/package-lock.json"
]);
const APPLICATION_PACKAGE_PATHS = Object.freeze([
  "package.json",
  "package-lock.json"
]);

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

export function canonicalProvenanceJson(value) {
  return JSON.stringify(canonicalValue(value));
}

export function provenanceSha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function canonicalDigest(value) {
  return provenanceSha256(Buffer.from(canonicalProvenanceJson(value), "utf8"));
}

function safeRoot(rootDir, code) {
  invariant(typeof rootDir === "string" && path.isAbsolute(rootDir), code);
  const resolved = path.resolve(rootDir);
  invariant(fs.realpathSync(resolved) === resolved, code);
  const stat = fs.lstatSync(resolved);
  invariant(stat.isDirectory() && !stat.isSymbolicLink(), code);
  return resolved;
}

function rootsAreSeparate(left, right) {
  const relation = path.relative(left, right);
  const reverse = path.relative(right, left);
  const rightOutsideLeft = relation === ".." ||
    relation.startsWith(`..${path.sep}`);
  const leftOutsideRight = reverse === ".." ||
    reverse.startsWith(`..${path.sep}`);
  return relation !== "" && rightOutsideLeft && leftOutsideRight;
}

function commandEnvironment(temporaryRoot) {
  const npmGlobalConfig = path.join(temporaryRoot, "npm-global-config");
  const npmUserConfig = path.join(temporaryRoot, "npm-user-config");
  fs.writeFileSync(npmGlobalConfig, Buffer.alloc(0), {
    flag: "wx",
    mode: 0o600
  });
  fs.writeFileSync(npmUserConfig, Buffer.alloc(0), {
    flag: "wx",
    mode: 0o600
  });
  return {
    AWS_CONFIG_FILE: "/dev/null",
    AWS_EC2_METADATA_DISABLED: "true",
    AWS_SHARED_CREDENTIALS_FILE: "/dev/null",
    GIT_ATTR_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_NO_LAZY_FETCH: "1",
    GIT_NO_REPLACE_OBJECTS: "1",
    GIT_TERMINAL_PROMPT: "0",
    HOME: temporaryRoot,
    LANG: "C",
    LC_ALL: "C",
    NO_COLOR: "1",
    PATH: `${path.dirname(fs.realpathSync(process.execPath))}:/usr/bin:/bin`,
    TEMP: temporaryRoot,
    TMP: temporaryRoot,
    TMPDIR: temporaryRoot,
    npm_config_always_auth: "false",
    npm_config_audit: "false",
    npm_config_cache: path.join(temporaryRoot, "npm-cache"),
    npm_config_fund: "false",
    npm_config_globalconfig: npmGlobalConfig,
    npm_config_registry: "https://registry.npmjs.org/",
    npm_config_update_notifier: "false",
    npm_config_userconfig: npmUserConfig,
    npm_node_execpath: process.execPath
  };
}

function checkedSpawn(executable, args, { cwd, env, code,
  maxBuffer = 96 * 1024 * 1024 }) {
  const result = spawnSync(executable, args, {
    cwd,
    encoding: null,
    env,
    maxBuffer,
    stdio: ["ignore", "pipe", "pipe"]
  });
  invariant(result && !result.error && result.status === 0 &&
    Buffer.isBuffer(result.stdout) && Buffer.isBuffer(result.stderr), code);
  return Object.freeze({
    argumentsSha256: canonicalDigest(args),
    outputBytes: result.stdout.length + result.stderr.length,
    outputSha256: provenanceSha256(Buffer.concat([result.stdout,
      Buffer.from("\n---STDERR---\n", "utf8"), result.stderr])),
    stderr: result.stderr,
    stdout: result.stdout
  });
}

function officialNodeRuntime() {
  let expected;
  try {
    expected = expectedOfficialNodeRuntime(process.platform, process.arch);
  } catch {
    throw new Error("CONTROL_PLANE_PROVENANCE_NODE_RUNTIME_REJECTED");
  }
  const executable = fs.realpathSync(process.execPath);
  const stat = fs.lstatSync(executable);
  const executableSha256 = provenanceSha256(fs.readFileSync(executable));
  invariant(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1 &&
    (stat.mode & 0o022) === 0 && process.version === expected.version &&
    expected.version === NODE_VERSION && executableSha256 === expected.sha256,
  "CONTROL_PLANE_PROVENANCE_NODE_RUNTIME_REJECTED");
  return Object.freeze({
    architecture: expected.architecture,
    distribution: expected.distribution,
    executable,
    executableSha256,
    platform: expected.platform,
    version: expected.version
  });
}

function npmPackageTree(packageRoot) {
  const root = safeRoot(packageRoot,
    "CONTROL_PLANE_PROVENANCE_NPM_PACKAGE_REJECTED");
  const pending = [""];
  const records = [];
  let totalBytes = 0;
  while (pending.length > 0) {
    const relativeDirectory = pending.pop();
    const directory = path.join(root, relativeDirectory);
    const names = fs.readdirSync(directory).sort().reverse();
    for (const name of names) {
      const relativePath = relativeDirectory.length > 0
        ? `${relativeDirectory}/${name}` : name;
      const filePath = path.join(root, relativePath);
      const stat = fs.lstatSync(filePath);
      invariant(!stat.isSymbolicLink() && (stat.mode & 0o022) === 0,
        "CONTROL_PLANE_PROVENANCE_NPM_PACKAGE_REJECTED");
      if (stat.isDirectory()) {
        pending.push(relativePath);
        continue;
      }
      invariant(stat.isFile() && stat.nlink === 1 && stat.size >= 0 &&
        stat.size <= 8 * 1024 * 1024 && fs.realpathSync(filePath) === filePath,
      "CONTROL_PLANE_PROVENANCE_NPM_PACKAGE_REJECTED");
      const bytes = fs.readFileSync(filePath);
      totalBytes += bytes.length;
      invariant(totalBytes <= 64 * 1024 * 1024 && records.length < 4096,
        "CONTROL_PLANE_PROVENANCE_NPM_PACKAGE_REJECTED");
      records.push(Object.freeze({
        bytes: bytes.length,
        path: relativePath,
        sha256: provenanceSha256(bytes)
      }));
    }
  }
  records.sort((left, right) => left.path < right.path ? -1 :
    left.path > right.path ? 1 : 0);
  const packageJson = records.find((item) => item.path === "package.json");
  const cli = records.find((item) => item.path === "bin/npm-cli.js");
  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(path.join(root, "package.json"),
      "utf8"));
  } catch {
    throw new Error("CONTROL_PLANE_PROVENANCE_NPM_PACKAGE_REJECTED");
  }
  const treeSha256 = canonicalDigest(records);
  invariant(records.length === NPM_PACKAGE_IDENTITY.fileCount &&
    packageJson?.sha256 === NPM_PACKAGE_IDENTITY.packageJsonSha256 &&
    cli?.sha256 === NPM_PACKAGE_IDENTITY.cliSha256 &&
    treeSha256 === NPM_PACKAGE_IDENTITY.treeSha256 &&
    manifest?.name === "npm" && manifest?.version === NPM_VERSION,
  "CONTROL_PLANE_PROVENANCE_NPM_PACKAGE_REJECTED");
  return Object.freeze({
    cliSha256: cli.sha256,
    fileCount: records.length,
    packageJsonSha256: packageJson.sha256,
    root,
    treeSha256
  });
}

function trustedNpmCli(npmCli, nodeRuntime) {
  invariant(typeof npmCli === "string" && path.isAbsolute(npmCli),
    "CONTROL_PLANE_PROVENANCE_NPM_CLI_REJECTED");
  const resolved = fs.realpathSync(npmCli);
  const stat = fs.lstatSync(resolved);
  const packageRoot = path.resolve(path.dirname(nodeRuntime.executable),
    "../lib/node_modules/npm");
  const packageIdentity = npmPackageTree(packageRoot);
  const expectedCli = fs.realpathSync(path.join(packageIdentity.root,
    "bin/npm-cli.js"));
  invariant(stat.isFile() && !stat.isSymbolicLink() &&
    stat.nlink === 1 && (stat.mode & 0o022) === 0 && resolved === expectedCli,
  "CONTROL_PLANE_PROVENANCE_NPM_CLI_REJECTED");
  return Object.freeze({ path: resolved, ...packageIdentity });
}

function gitText(root, args, code) {
  const result = checkedSpawn(trustedGitExecutable(), args, {
    code,
    cwd: root,
    env: gitEnvironment()
  });
  return result.stdout.toString("utf8").trim();
}

function exactOrigin(root) {
  const value = gitText(root, ["remote", "get-url", "--", "origin"],
    "CONTROL_PLANE_PROVENANCE_ORIGIN_REJECTED");
  invariant(value === OFFICIAL_ORIGIN || value === OFFICIAL_ORIGIN.slice(0, -4),
    "CONTROL_PLANE_PROVENANCE_ORIGIN_REJECTED");
  return OFFICIAL_ORIGIN;
}

function inspectRoot(rootDir, expectedIdentity, role) {
  const root = safeRoot(rootDir, `CONTROL_PLANE_PROVENANCE_${role}_ROOT_REJECTED`);
  const rootStat = fs.lstatSync(root);
  invariant(rootStat.uid === process.getuid() && (rootStat.mode & 0o022) === 0,
    `CONTROL_PLANE_PROVENANCE_${role}_ROOT_REJECTED`);
  invariant(exactKeys(expectedIdentity, ["commit", "tree"]) &&
    HEX_40.test(expectedIdentity.commit ?? "") &&
    HEX_40.test(expectedIdentity.tree ?? ""),
  `CONTROL_PLANE_PROVENANCE_${role}_IDENTITY_REJECTED`);
  assertExactGitRepositoryLayout({
    expectedOriginRepository: OFFICIAL_REPOSITORY,
    rootDir: root
  });
  exactOrigin(root);
  assertCleanExactGitCheckout({
    rootDir: root,
    sourceCommit: expectedIdentity.commit,
    treeDigest: expectedIdentity.tree
  });
  invariant(gitText(root, ["rev-parse", "--is-shallow-repository"],
    "CONTROL_PLANE_PROVENANCE_SHALLOW_REJECTED") === "false" &&
    gitText(root, ["for-each-ref", "--format=%(refname)", "refs/replace/"],
      "CONTROL_PLANE_PROVENANCE_REPLACEMENT_REJECTED") === "" &&
    !fs.existsSync(path.join(root, ".git", "info", "grafts")),
  "CONTROL_PLANE_PROVENANCE_GIT_HISTORY_REJECTED");
  return Object.freeze({
    clean: true,
    commit: expectedIdentity.commit,
    grafts: false,
    origin: OFFICIAL_ORIGIN,
    replacements: false,
    role,
    rootDevice: rootStat.dev,
    rootInode: rootStat.ino,
    rootMode: rootStat.mode & 0o777,
    rootOwnerUid: rootStat.uid,
    shallow: false,
    standalone: true,
    tree: expectedIdentity.tree
  });
}

function fileRecord(root, sourceCommit, relativePath) {
  invariant(typeof relativePath === "string" && relativePath.length > 0 &&
    !path.isAbsolute(relativePath) && !relativePath.split("/").includes(".."),
  "CONTROL_PLANE_PROVENANCE_FILE_PATH_REJECTED");
  const filePath = path.resolve(root, relativePath);
  invariant(path.relative(root, filePath) === relativePath.split("/").join(path.sep),
    "CONTROL_PLANE_PROVENANCE_FILE_PATH_REJECTED");
  const stat = fs.lstatSync(filePath);
  invariant(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1 &&
    stat.size > 0 && stat.size <= 8 * 1024 * 1024 &&
    fs.realpathSync(filePath) === filePath,
  "CONTROL_PLANE_PROVENANCE_FILE_REJECTED");
  const worktreeBytes = fs.readFileSync(filePath);
  const blob = readExactGitBlob({ filePath, rootDir: root, sourceCommit });
  invariant(worktreeBytes.equals(blob.bytes),
    "CONTROL_PLANE_PROVENANCE_FILE_BLOB_MISMATCH");
  return Object.freeze({
    bytes: worktreeBytes.length,
    gitBlobId: blob.gitBlobId,
    path: relativePath,
    sha256: provenanceSha256(worktreeBytes)
  });
}

function packageRecords(controlRoot, applicationRoot, controlCommit) {
  const control = PACKAGE_PATHS.map((relativePath) =>
    fileRecord(controlRoot, controlCommit, relativePath));
  const application = APPLICATION_PACKAGE_PATHS.map((relativePath) =>
    fileRecord(applicationRoot, FROZEN_APPLICATION.commit, relativePath));
  for (const relativePath of APPLICATION_PACKAGE_PATHS) {
    const left = control.find((item) => item.path === relativePath);
    const right = application.find((item) => item.path === relativePath);
    invariant(left.sha256 === right.sha256 && left.bytes === right.bytes,
      "CONTROL_PLANE_PROVENANCE_FROZEN_PACKAGE_DRIFT");
  }
  return Object.freeze({ application, controlPlane: control });
}

function parseTap(bytes, code) {
  const text = bytes.toString("utf8");
  const value = (label) => {
    const matches = [...text.matchAll(new RegExp(`^# ${label} ([0-9]+)$`, "gmu"))];
    invariant(matches.length > 0, code);
    return Number(matches.at(-1)[1]);
  };
  const result = Object.freeze({
    cancelled: value("cancelled"),
    failed: value("fail"),
    passed: value("pass"),
    skipped: value("skipped"),
    tests: value("tests"),
    todo: value("todo")
  });
  invariant(result.failed === 0 && result.cancelled === 0 &&
    result.tests > 0 && result.passed > 0,
  code);
  return result;
}

function parseAudit(bytes, code) {
  let value;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new Error(code);
  }
  const vulnerabilities = value?.metadata?.vulnerabilities;
  invariant(exactKeys(vulnerabilities,
    ["critical", "high", "info", "low", "moderate", "total"]) &&
    Object.values(vulnerabilities).every((count) =>
      Number.isSafeInteger(count) && count === 0), code);
  return Object.freeze({ auditFindingCount: 0, vulnerabilities });
}

function packageTestScript(root, relativeRoot) {
  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(path.join(root, relativeRoot,
      "package.json"), "utf8"));
  } catch {
    throw new Error("CONTROL_PLANE_PROVENANCE_TEST_SCRIPT_REJECTED");
  }
  invariant(typeof manifest?.scripts?.test === "string" &&
    manifest.scripts.test.length > 0,
  "CONTROL_PLANE_PROVENANCE_TEST_SCRIPT_REJECTED");
  return Object.freeze({
    packageScriptSha256: provenanceSha256(Buffer.from(manifest.scripts.test,
      "utf8")),
    script: "test"
  });
}

function executionRecord(command, result, semantic) {
  return Object.freeze({
    argumentsSha256: result.argumentsSha256,
    command,
    outputBytes: result.outputBytes,
    outputSha256: result.outputSha256,
    semantic,
    stderrBase64: result.stderr.toString("base64"),
    stdoutBase64: result.stdout.toString("base64")
  });
}

function validateReceiptDigest(receipt, code) {
  invariant(plainObject(receipt) && HEX_64.test(receipt.provenanceSha256 ?? ""),
    code);
  const { provenanceSha256: claimed, ...body } = receipt;
  invariant(provenanceSha256(Buffer.from(`${JSON.stringify(body)}\n`, "utf8")) ===
    claimed, code);
}

function reopenReceiptFiles(root, sourceCommit, records, code) {
  invariant(Array.isArray(records) && records.length > 0, code);
  for (const record of records) {
    invariant(exactKeys(record, ["bytes", "path", "sha256"]) &&
      Number.isSafeInteger(record.bytes) && record.bytes > 0 &&
      HEX_64.test(record.sha256 ?? ""), code);
    const reopened = fileRecord(root, sourceCommit, record.path);
    invariant(reopened.bytes === record.bytes && reopened.sha256 === record.sha256,
      code);
  }
}

function reopenRuntime(outputRoot, record, code) {
  invariant(plainObject(record) && typeof record.path === "string" &&
    record.path.startsWith("dist/aws/") && HEX_64.test(record.sha256 ?? "") &&
    Number.isSafeInteger(record.bytes) && record.bytes > 0, code);
  const filePath = path.resolve(outputRoot, record.path);
  invariant(path.relative(outputRoot, filePath) ===
    record.path.split("/").join(path.sep), code);
  const stat = fs.lstatSync(filePath);
  const bytes = fs.readFileSync(filePath);
  invariant(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1 &&
    stat.size === record.bytes && (stat.mode & 0o777) === 0o600 &&
    provenanceSha256(bytes) === record.sha256, code);
}

function summarizeControlBuild(receipt, outputRoot, root, identity, rawOutput) {
  const code = "CONTROL_PLANE_PROVENANCE_CONTROL_BUILD_REJECTED";
  validateReceiptDigest(receipt, code);
  invariant(receipt.controlPlaneCommit === identity.commit &&
    receipt.controlPlaneTree === identity.tree &&
    receipt.nodeVersion === NODE_VERSION &&
    HEX_64.test(receipt.nodeExecutableSha256 ?? "") &&
    HEX_64.test(receipt.packageJsonSha256 ?? "") &&
    HEX_64.test(receipt.packageLockSha256 ?? "") &&
    Array.isArray(receipt.externalImports) && receipt.externalImports.length > 0 &&
    receipt.externalImports.every((item) => /^node:[a-z0-9_./-]+$/u.test(item)),
  code);
  const packageJson = fileRecord(root, identity.commit,
    "release-control/package.json");
  const packageLock = fileRecord(root, identity.commit,
    "release-control/package-lock.json");
  invariant(receipt.packageJsonSha256 === packageJson.sha256 &&
    receipt.packageLockSha256 === packageLock.sha256, code);
  reopenReceiptFiles(root, identity.commit, receipt.sourceInventory, code);
  reopenRuntime(outputRoot, receipt, code);
  return Object.freeze({
    externalImports: [...receipt.externalImports],
    packageJsonSha256: receipt.packageJsonSha256,
    packageLockSha256: receipt.packageLockSha256,
    provenanceSha256: receipt.provenanceSha256,
    rawOutputSha256: provenanceSha256(rawOutput),
    receiptBase64: rawOutput.toString("base64"),
    runtimeSha256: receipt.sha256,
    sourceInventorySha256: receipt.sourceInventorySha256
  });
}

function summarizeProviderBuild(receipt, outputRoot, root, identity, rawOutput) {
  const code = "CONTROL_PLANE_PROVENANCE_PROVIDER_BUILD_REJECTED";
  validateReceiptDigest(receipt, code);
  invariant(receipt.schemaVersion ===
    "prooftoact.release-provider-runtime-build.v1" &&
    receipt.controlPlaneCommit === identity.commit &&
    receipt.controlPlaneTree === identity.tree &&
    receipt.nodeVersion === NODE_VERSION &&
    HEX_64.test(receipt.nodeExecutableSha256 ?? "") &&
    Array.isArray(receipt.runtimes) && receipt.runtimes.length === 3 &&
    HEX_64.test(receipt.runtimeSetSha256 ?? ""), code);
  const packageJson = fileRecord(root, identity.commit,
    "release-provider/package.json");
  const packageLock = fileRecord(root, identity.commit,
    "release-provider/package-lock.json");
  invariant(receipt.packageJsonSha256 === packageJson.sha256 &&
    receipt.packageLockSha256 === packageLock.sha256, code);
  reopenReceiptFiles(root, identity.commit, receipt.sourceInventory, code);
  for (const runtime of receipt.runtimes) reopenRuntime(outputRoot, runtime, code);
  const capabilities = receipt.runtimes.map(({ capability }) => capability).sort();
  invariant(canonicalProvenanceJson(capabilities) === canonicalProvenanceJson([
    "PERMIT_READER", "PREPARE_DISPATCHER", "PREPARE_READBACK"
  ]), code);
  const externalImports = [...new Set(receipt.runtimes.flatMap((runtime) =>
    runtime.externalImports))].sort();
  invariant(externalImports.length > 0 && externalImports.every((item) =>
    /^node:[a-z0-9_./-]+$/u.test(item)), code);
  return Object.freeze({
    externalImports,
    packageJsonSha256: receipt.packageJsonSha256,
    packageLockSha256: receipt.packageLockSha256,
    provenanceSha256: receipt.provenanceSha256,
    rawOutputSha256: provenanceSha256(rawOutput),
    receiptBase64: rawOutput.toString("base64"),
    runtimeCount: receipt.runtimes.length,
    runtimeSetSha256: receipt.runtimeSetSha256,
    sourceInventorySha256: receipt.sourceInventorySha256
  });
}

function parseJsonOutput(result, code) {
  try {
    return JSON.parse(result.stdout.toString("utf8"));
  } catch {
    throw new Error(code);
  }
}

function buildTwice({ root, identity, temporaryRoot, env, runner = checkedSpawn }) {
  const summaries = [];
  for (let attempt = 1; attempt <= 2; attempt += 1) {
    const attemptRoot = path.join(temporaryRoot, `build-${attempt}`);
    fs.mkdirSync(attemptRoot, { mode: 0o700 });
    const controlOutput = path.join(attemptRoot, "release-control");
    const providerOutput = path.join(attemptRoot, "release-provider");
    const control = runner(process.execPath, [
      "release-control/build-release-control-runtime.js", controlOutput,
      identity.commit, identity.tree
    ], { code: "CONTROL_PLANE_PROVENANCE_CONTROL_BUILD_FAILED", cwd: root, env });
    const provider = runner(process.execPath, [
      "release-provider/build-release-provider-runtimes.js", providerOutput,
      identity.commit, identity.tree
    ], { code: "CONTROL_PLANE_PROVENANCE_PROVIDER_BUILD_FAILED", cwd: root, env });
    summaries.push(Object.freeze({
      releaseControl: summarizeControlBuild(parseJsonOutput(control,
        "CONTROL_PLANE_PROVENANCE_CONTROL_BUILD_JSON_REJECTED"), controlOutput,
      root, identity, control.stdout),
      releaseProvider: summarizeProviderBuild(parseJsonOutput(provider,
        "CONTROL_PLANE_PROVENANCE_PROVIDER_BUILD_JSON_REJECTED"), providerOutput,
      root, identity, provider.stdout)
    }));
  }
  invariant(canonicalProvenanceJson(summaries[0]) ===
    canonicalProvenanceJson(summaries[1]),
  "CONTROL_PLANE_PROVENANCE_BUILD_NOT_REPRODUCIBLE");
  return Object.freeze({ ...summaries[0], reproducible: true });
}

function executeGate({ applicationRoot, controlRoot, identity, npmCli,
  temporaryRoot,
  runner = checkedSpawn }) {
  const env = commandEnvironment(temporaryRoot);
  const nodeRuntime = officialNodeRuntime();
  const npmIdentity = trustedNpmCli(npmCli, nodeRuntime);
  const npmVersionResult = runner(nodeRuntime.executable,
    [npmIdentity.path, "--version"], {
    code: "CONTROL_PLANE_PROVENANCE_NPM_VERSION_FAILED", cwd: controlRoot, env
  });
  const npmVersion = npmVersionResult.stdout.toString("utf8").trim();
  invariant(process.version === NODE_VERSION && npmVersion === NPM_VERSION,
    "CONTROL_PLANE_PROVENANCE_TOOLCHAIN_VERSION_REJECTED");

  const lanes = Object.freeze([
    Object.freeze({ command: "control-plane-root", relativeRoot: ".",
      root: controlRoot }),
    Object.freeze({ command: "release-control", relativeRoot: "release-control",
      root: controlRoot }),
    Object.freeze({ command: "release-provider", relativeRoot: "release-provider",
      root: controlRoot }),
    Object.freeze({ command: "frozen-application", relativeRoot: ".",
      root: applicationRoot })
  ]);
  const installations = [];
  for (const lane of lanes) {
    const args = [npmIdentity.path, "ci", "--ignore-scripts", "--no-audit",
      "--no-fund"];
    const result = runner(nodeRuntime.executable, args, {
      code: "CONTROL_PLANE_PROVENANCE_INSTALL_FAILED",
      cwd: path.resolve(lane.root, lane.relativeRoot), env
    });
    installations.push(executionRecord(lane.command, result, {
      arguments: ["ci", "--ignore-scripts", "--no-audit", "--no-fund"],
      status: "PASS"
    }));
  }

  const tests = [];
  for (const lane of lanes) {
    const args = [npmIdentity.path, "--silent", "test"];
    const result = runner(nodeRuntime.executable, args, {
      code: "CONTROL_PLANE_PROVENANCE_TEST_FAILED",
      cwd: path.resolve(lane.root, lane.relativeRoot), env
    });
    tests.push(executionRecord(lane.command, result,
      { ...parseTap(result.stdout, "CONTROL_PLANE_PROVENANCE_TEST_OUTPUT_REJECTED"),
        ...packageTestScript(lane.root, lane.relativeRoot) }));
  }

  const audits = [];
  for (const lane of lanes) {
    const args = [npmIdentity.path, "audit", "--omit=dev", "--json"];
    const result = runner(nodeRuntime.executable, args, {
      code: "CONTROL_PLANE_PROVENANCE_AUDIT_FAILED",
      cwd: path.resolve(lane.root, lane.relativeRoot), env
    });
    audits.push(executionRecord(lane.command, result,
      parseAudit(result.stdout, "CONTROL_PLANE_PROVENANCE_AUDIT_OUTPUT_REJECTED")));
  }
  const build = buildTwice({ env, identity, root: controlRoot,
    runner, temporaryRoot });
  return Object.freeze({
    audits,
    build,
    installations,
    tests,
    toolchain: Object.freeze({
      nodeArch: nodeRuntime.architecture,
      nodeDistribution: nodeRuntime.distribution,
      nodeExecutableSha256: nodeRuntime.executableSha256,
      nodePlatform: nodeRuntime.platform,
      nodeVersion: nodeRuntime.version,
      npmCliSha256: npmIdentity.cliSha256,
      npmPackageFileCount: npmIdentity.fileCount,
      npmPackageJsonSha256: npmIdentity.packageJsonSha256,
      npmPackageTreeSha256: npmIdentity.treeSha256,
      npmVersion
    })
  });
}

function semanticExecutions(executions) {
  return executions.map(({ argumentsSha256, command, semantic }) => ({
    argumentsSha256,
    command,
    semantic
  }));
}

function stableObservation(observation) {
  return {
    audits: semanticExecutions(observation.executions.audits),
    build: observation.executions.build,
    git: observation.git,
    installations: semanticExecutions(observation.executions.installations),
    packages: observation.packages,
    tests: semanticExecutions(observation.executions.tests),
    toolchain: observation.executions.toolchain
  };
}

function observe({ controlPlaneRoot, frozenApplicationRoot, npmCli,
  expectedControlPlane = null, runner = checkedSpawn }) {
  const controlRoot = safeRoot(controlPlaneRoot,
    "CONTROL_PLANE_PROVENANCE_CONTROL_ROOT_REJECTED");
  const applicationRoot = safeRoot(frozenApplicationRoot,
    "CONTROL_PLANE_PROVENANCE_APPLICATION_ROOT_REJECTED");
  invariant(rootsAreSeparate(controlRoot, applicationRoot),
    "CONTROL_PLANE_PROVENANCE_ROOT_SEPARATION_REJECTED");
  invariant(controlRoot === SOURCE_ROOT,
    "CONTROL_PLANE_PROVENANCE_VERIFIER_SOURCE_ROOT_REJECTED");
  const controlIdentity = expectedControlPlane ?? Object.freeze({
    commit: gitText(controlRoot, ["rev-parse", "HEAD"],
      "CONTROL_PLANE_PROVENANCE_CONTROL_HEAD_REJECTED"),
    tree: gitText(controlRoot, ["rev-parse", "HEAD^{tree}"],
      "CONTROL_PLANE_PROVENANCE_CONTROL_TREE_REJECTED")
  });
  invariant(HEX_40.test(controlIdentity.commit ?? "") &&
    HEX_40.test(controlIdentity.tree ?? "") &&
    controlIdentity.commit !== FROZEN_APPLICATION.commit,
  "CONTROL_PLANE_PROVENANCE_CONTROL_IDENTITY_REJECTED");
  const git = Object.freeze({
    controlPlane: inspectRoot(controlRoot, controlIdentity, "CONTROL_PLANE"),
    frozenApplication: inspectRoot(applicationRoot, FROZEN_APPLICATION,
      "FROZEN_APPLICATION")
  });
  const packages = packageRecords(controlRoot, applicationRoot,
    controlIdentity.commit);
  const temporaryRoot = fs.mkdtempSync(path.join(trustedTemporaryRoot(),
    "prooftoact-control-provenance-"));
  fs.chownSync(temporaryRoot, process.getuid(), process.getgid());
  fs.chmodSync(temporaryRoot, 0o700);
  try {
    const executions = executeGate({ applicationRoot, controlRoot,
      identity: controlIdentity, npmCli, runner, temporaryRoot });
    const finalControlRoot = inspectRoot(controlRoot, controlIdentity,
      "CONTROL_PLANE");
    const finalApplicationRoot = inspectRoot(applicationRoot,
      FROZEN_APPLICATION, "FROZEN_APPLICATION");
    invariant(canonicalProvenanceJson(finalControlRoot) ===
      canonicalProvenanceJson(git.controlPlane) &&
      canonicalProvenanceJson(finalApplicationRoot) ===
      canonicalProvenanceJson(git.frozenApplication),
    "CONTROL_PLANE_PROVENANCE_ROOT_IDENTITY_CHANGED");
    return Object.freeze({ executions, git, packages });
  } finally {
    fs.rmSync(temporaryRoot, { force: true, recursive: true });
  }
}

function evidenceBody(observation) {
  return Object.freeze({
    claimBoundary: Object.freeze({
      applicationDeploymentObserved: false,
      hostedCiParityObserved: false,
      privilegedRootStageObserved: false,
      providerActionsPerformed: false,
      providerExecutionAuthorized: false,
      providerFactsAsserted: false,
      sourceAndLocalExecutionEvidenceOnly: true
    }),
    decision: Object.freeze({
      cleanStandaloneProvenanceObserved: true,
      nextGate: "SEPARATE_GOVERNED_PROVIDER_AUTHORIZATION",
      providerExecutionAuthorized: false,
      status: "LOCAL_PROVENANCE_VERIFIED"
    }),
    executions: observation.executions,
    git: observation.git,
    packages: observation.packages,
    schemaVersion: SCHEMA
  });
}

export function generateControlPlaneProvenanceEvidence(options) {
  const body = evidenceBody(observe(options));
  return Object.freeze({
    body,
    bodySha256: canonicalDigest(body),
    schemaVersion: SCHEMA
  });
}

function validateExecutionRecord(value, kind) {
  invariant(exactKeys(value,
    ["argumentsSha256", "command", "outputBytes", "outputSha256", "semantic",
      "stderrBase64", "stdoutBase64"]) &&
    typeof value.command === "string" && value.command.length > 0 &&
    HEX_64.test(value.argumentsSha256 ?? "") &&
    HEX_64.test(value.outputSha256 ?? "") &&
    Number.isSafeInteger(value.outputBytes) && value.outputBytes > 0 &&
    plainObject(value.semantic) && typeof value.stdoutBase64 === "string" &&
    typeof value.stderrBase64 === "string",
  `CONTROL_PLANE_PROVENANCE_${kind}_RECORD_REJECTED`);
  const stdout = Buffer.from(value.stdoutBase64, "base64");
  const stderr = Buffer.from(value.stderrBase64, "base64");
  invariant(stdout.toString("base64") === value.stdoutBase64 &&
    stderr.toString("base64") === value.stderrBase64 &&
    stdout.length + stderr.length === value.outputBytes &&
    provenanceSha256(Buffer.concat([stdout,
      Buffer.from("\n---STDERR---\n", "utf8"), stderr])) === value.outputSha256,
  `CONTROL_PLANE_PROVENANCE_${kind}_OUTPUT_REJECTED`);
  if (kind === "TEST") {
    invariant(canonicalProvenanceJson(parseTap(stdout,
      "CONTROL_PLANE_PROVENANCE_TEST_OUTPUT_REJECTED")) ===
      canonicalProvenanceJson(Object.fromEntries(Object.entries(value.semantic)
        .filter(([key]) => !["packageScriptSha256", "script"].includes(key)))),
    "CONTROL_PLANE_PROVENANCE_TEST_OUTPUT_SEMANTIC_MISMATCH");
  }
  if (kind === "AUDIT") {
    invariant(canonicalProvenanceJson(parseAudit(stdout,
      "CONTROL_PLANE_PROVENANCE_AUDIT_OUTPUT_REJECTED")) ===
      canonicalProvenanceJson(value.semantic),
    "CONTROL_PLANE_PROVENANCE_AUDIT_OUTPUT_SEMANTIC_MISMATCH");
  }
}

export function validateControlPlaneProvenanceEvidence(value) {
  invariant(exactKeys(value, ["body", "bodySha256", "schemaVersion"]) &&
    value.schemaVersion === SCHEMA && HEX_64.test(value.bodySha256 ?? "") &&
    canonicalDigest(value.body) === value.bodySha256 &&
    exactKeys(value.body, ["claimBoundary", "decision", "executions", "git",
      "packages", "schemaVersion"]) && value.body.schemaVersion === SCHEMA &&
    exactKeys(value.body.claimBoundary, ["applicationDeploymentObserved",
      "hostedCiParityObserved", "privilegedRootStageObserved",
      "providerActionsPerformed", "providerExecutionAuthorized",
      "providerFactsAsserted", "sourceAndLocalExecutionEvidenceOnly"]) &&
    value.body.claimBoundary.applicationDeploymentObserved === false &&
    value.body.claimBoundary.hostedCiParityObserved === false &&
    value.body.claimBoundary.privilegedRootStageObserved === false &&
    value.body.claimBoundary.providerActionsPerformed === false &&
    value.body.claimBoundary.providerExecutionAuthorized === false &&
    value.body.claimBoundary.providerFactsAsserted === false &&
    value.body.claimBoundary.sourceAndLocalExecutionEvidenceOnly === true &&
    exactKeys(value.body.decision, ["cleanStandaloneProvenanceObserved",
      "nextGate", "providerExecutionAuthorized", "status"]) &&
    value.body.decision.cleanStandaloneProvenanceObserved === true &&
    value.body.decision.providerExecutionAuthorized === false &&
    value.body.decision.status === "LOCAL_PROVENANCE_VERIFIED" &&
    value.body.decision.nextGate === "SEPARATE_GOVERNED_PROVIDER_AUTHORIZATION",
  "CONTROL_PLANE_PROVENANCE_EVIDENCE_REJECTED");
  invariant(exactKeys(value.body.git, ["controlPlane", "frozenApplication"]),
    "CONTROL_PLANE_PROVENANCE_GIT_EVIDENCE_REJECTED");
  for (const [name, expected, role] of [["controlPlane", null,
    "CONTROL_PLANE"], ["frozenApplication", FROZEN_APPLICATION,
    "FROZEN_APPLICATION"]]) {
    const item = value.body.git[name];
    invariant(exactKeys(item, ["clean", "commit", "grafts", "origin",
      "replacements", "role", "rootDevice", "rootInode", "rootMode",
      "rootOwnerUid", "shallow", "standalone", "tree"]) &&
      item.clean === true && item.grafts === false &&
      item.origin === OFFICIAL_ORIGIN && item.replacements === false &&
      item.role === role &&
      item.shallow === false && item.standalone === true &&
      [item.rootDevice, item.rootInode, item.rootMode, item.rootOwnerUid]
        .every((number) => Number.isSafeInteger(number) && number >= 0) &&
      (item.rootMode & 0o022) === 0 &&
      HEX_40.test(item.commit ?? "") && HEX_40.test(item.tree ?? "") &&
      (expected === null || item.commit === expected.commit &&
        item.tree === expected.tree),
    "CONTROL_PLANE_PROVENANCE_GIT_EVIDENCE_REJECTED");
  }
  invariant(!(value.body.git.controlPlane.rootDevice ===
      value.body.git.frozenApplication.rootDevice &&
      value.body.git.controlPlane.rootInode ===
      value.body.git.frozenApplication.rootInode) &&
    value.body.git.controlPlane.commit !== FROZEN_APPLICATION.commit &&
    exactKeys(value.body.packages, ["application", "controlPlane"]) &&
    Array.isArray(value.body.packages.application) &&
    Array.isArray(value.body.packages.controlPlane),
  "CONTROL_PLANE_PROVENANCE_PACKAGE_EVIDENCE_REJECTED");
  for (const item of [...value.body.packages.application,
    ...value.body.packages.controlPlane]) {
    invariant(exactKeys(item, ["bytes", "gitBlobId", "path", "sha256"]) &&
      Number.isSafeInteger(item.bytes) && item.bytes > 0 &&
      /^[0-9a-f]{40}$/u.test(item.gitBlobId ?? "") &&
      HEX_64.test(item.sha256 ?? "") && typeof item.path === "string",
    "CONTROL_PLANE_PROVENANCE_PACKAGE_EVIDENCE_REJECTED");
  }
  invariant(canonicalProvenanceJson(value.body.packages.application.map(({ path:
    relativePath }) => relativePath)) ===
      canonicalProvenanceJson(APPLICATION_PACKAGE_PATHS) &&
    canonicalProvenanceJson(value.body.packages.controlPlane.map(({ path:
      relativePath }) => relativePath)) === canonicalProvenanceJson(PACKAGE_PATHS),
  "CONTROL_PLANE_PROVENANCE_PACKAGE_SET_REJECTED");
  for (const relativePath of APPLICATION_PACKAGE_PATHS) {
    const application = value.body.packages.application.find((item) =>
      item.path === relativePath);
    const control = value.body.packages.controlPlane.find((item) =>
      item.path === relativePath);
    invariant(application.sha256 === control.sha256 &&
      application.bytes === control.bytes,
    "CONTROL_PLANE_PROVENANCE_FROZEN_PACKAGE_DRIFT");
  }
  const executions = value.body.executions;
  invariant(exactKeys(executions,
    ["audits", "build", "installations", "tests", "toolchain"]) &&
    Array.isArray(executions.audits) && executions.audits.length === 4 &&
    Array.isArray(executions.installations) && executions.installations.length === 4 &&
    Array.isArray(executions.tests) && executions.tests.length === 4 &&
    exactKeys(executions.build, ["releaseControl", "releaseProvider",
      "reproducible"]) && executions.build.reproducible === true &&
    exactKeys(executions.toolchain, ["nodeArch", "nodeDistribution",
      "nodeExecutableSha256", "nodePlatform", "nodeVersion", "npmCliSha256",
      "npmPackageFileCount", "npmPackageJsonSha256", "npmPackageTreeSha256",
      "npmVersion"]),
  "CONTROL_PLANE_PROVENANCE_EXECUTION_EVIDENCE_REJECTED");
  let expectedNode;
  try {
    expectedNode = expectedOfficialNodeRuntime(executions.toolchain.nodePlatform,
      executions.toolchain.nodeArch);
  } catch {
    throw new Error("CONTROL_PLANE_PROVENANCE_EXECUTION_EVIDENCE_REJECTED");
  }
  invariant(executions.toolchain.nodeDistribution === expectedNode.distribution &&
    executions.toolchain.nodeVersion === NODE_VERSION &&
    executions.toolchain.nodeVersion === expectedNode.version &&
    executions.toolchain.nodeExecutableSha256 === expectedNode.sha256 &&
    executions.toolchain.npmVersion === NPM_VERSION &&
    executions.toolchain.npmCliSha256 === NPM_PACKAGE_IDENTITY.cliSha256 &&
    executions.toolchain.npmPackageFileCount ===
      NPM_PACKAGE_IDENTITY.fileCount &&
    executions.toolchain.npmPackageJsonSha256 ===
      NPM_PACKAGE_IDENTITY.packageJsonSha256 &&
    executions.toolchain.npmPackageTreeSha256 ===
      NPM_PACKAGE_IDENTITY.treeSha256,
  "CONTROL_PLANE_PROVENANCE_EXECUTION_EVIDENCE_REJECTED");
  invariant(exactKeys(executions.build.releaseControl, ["externalImports",
    "packageJsonSha256", "packageLockSha256", "provenanceSha256",
    "rawOutputSha256", "receiptBase64", "runtimeSha256",
    "sourceInventorySha256"]) &&
    exactKeys(executions.build.releaseProvider, ["externalImports",
      "packageJsonSha256", "packageLockSha256", "provenanceSha256",
      "rawOutputSha256", "receiptBase64", "runtimeCount", "runtimeSetSha256",
      "sourceInventorySha256"]),
  "CONTROL_PLANE_PROVENANCE_BUILD_EVIDENCE_REJECTED");
  for (const build of [executions.build.releaseControl,
    executions.build.releaseProvider]) {
    invariant(typeof build.receiptBase64 === "string",
      "CONTROL_PLANE_PROVENANCE_BUILD_RECEIPT_REJECTED");
    const rawReceipt = Buffer.from(build.receiptBase64, "base64");
    invariant(rawReceipt.toString("base64") === build.receiptBase64 &&
      provenanceSha256(rawReceipt) === build.rawOutputSha256,
    "CONTROL_PLANE_PROVENANCE_BUILD_RECEIPT_REJECTED");
    let receipt;
    try {
      receipt = JSON.parse(rawReceipt.toString("utf8"));
    } catch {
      throw new Error("CONTROL_PLANE_PROVENANCE_BUILD_RECEIPT_REJECTED");
    }
    validateReceiptDigest(receipt,
      "CONTROL_PLANE_PROVENANCE_BUILD_RECEIPT_REJECTED");
    invariant(build.provenanceSha256 === receipt.provenanceSha256 &&
      rawReceipt.toString("utf8") === `${JSON.stringify(receipt)}\n`,
    "CONTROL_PLANE_PROVENANCE_BUILD_RECEIPT_BINDING_REJECTED");
    invariant(Array.isArray(build.externalImports) &&
      build.externalImports.length > 0 &&
      canonicalProvenanceJson(build.externalImports) ===
        canonicalProvenanceJson([...new Set(build.externalImports)].sort()) &&
      build.externalImports.every((item) =>
        /^node:[a-z0-9_./-]+$/u.test(item)) &&
      [build.packageJsonSha256, build.packageLockSha256,
        build.sourceInventorySha256].every((digest) => HEX_64.test(digest ?? "")),
    "CONTROL_PLANE_PROVENANCE_BUILD_EVIDENCE_REJECTED");
  }
  invariant(HEX_64.test(executions.build.releaseControl.runtimeSha256 ?? "") &&
    executions.build.releaseProvider.runtimeCount === 3 &&
    HEX_64.test(executions.build.releaseProvider.runtimeSetSha256 ?? ""),
  "CONTROL_PLANE_PROVENANCE_BUILD_EVIDENCE_REJECTED");
  executions.audits.forEach((item) => validateExecutionRecord(item, "AUDIT"));
  executions.installations.forEach((item) =>
    validateExecutionRecord(item, "INSTALL"));
  executions.tests.forEach((item) => validateExecutionRecord(item, "TEST"));
  const laneNames = ["control-plane-root", "release-control",
    "release-provider", "frozen-application"];
  invariant([executions.audits, executions.installations, executions.tests]
    .every((records) => canonicalProvenanceJson(records.map(({ command }) =>
      command)) === canonicalProvenanceJson(laneNames)) &&
    executions.installations.every(({ semantic }) =>
      canonicalProvenanceJson(semantic) === canonicalProvenanceJson({
        arguments: ["ci", "--ignore-scripts", "--no-audit", "--no-fund"],
        status: "PASS"
      })) &&
    executions.tests.every(({ semantic }) => semantic.script === "test" &&
      HEX_64.test(semantic.packageScriptSha256 ?? "")),
  "CONTROL_PLANE_PROVENANCE_EXECUTION_SET_REJECTED");
  invariant(executions.audits.every((item) =>
    item.semantic.auditFindingCount === 0) &&
    executions.tests.every((item) => item.semantic.failed === 0 &&
      item.semantic.cancelled === 0 && item.semantic.passed > 0),
  "CONTROL_PLANE_PROVENANCE_EXECUTION_RESULT_REJECTED");
  return value;
}

export function verifyControlPlaneProvenanceEvidence(value, options) {
  validateControlPlaneProvenanceEvidence(value);
  const expectedControlPlane = {
    commit: value.body.git.controlPlane.commit,
    tree: value.body.git.controlPlane.tree
  };
  const observation = observe({ ...options, expectedControlPlane });
  const observedStable = stableObservation(observation);
  const evidenceStable = stableObservation({
    executions: value.body.executions,
    git: value.body.git,
    packages: value.body.packages
  });
  invariant(canonicalProvenanceJson(observedStable) ===
    canonicalProvenanceJson(evidenceStable),
  "CONTROL_PLANE_PROVENANCE_REPRODUCTION_MISMATCH");
  return Object.freeze({
    bodySha256: value.bodySha256,
    cleanStandaloneProvenanceObserved: true,
    controlPlaneCommit: expectedControlPlane.commit,
    controlPlaneTree: expectedControlPlane.tree,
    frozenApplicationCommit: FROZEN_APPLICATION.commit,
    frozenApplicationTree: FROZEN_APPLICATION.tree,
    providerExecutionAuthorized: false,
    status: "LOCAL_PROVENANCE_REPRODUCED"
  });
}

export const CONTROL_PLANE_PROVENANCE_CONSTANTS = Object.freeze({
  APPLICATION_PACKAGE_PATHS,
  FROZEN_APPLICATION,
  NODE_VERSION,
  NPM_PACKAGE_IDENTITY,
  NPM_VERSION,
  OFFICIAL_ORIGIN,
  PACKAGE_PATHS,
  SCHEMA
});

export const __test = Object.freeze({
  commandEnvironment,
  evidenceBody,
  inspectRoot,
  parseAudit,
  parseTap,
  rootsAreSeparate,
  semanticExecutions,
  stableObservation,
  trustedNpmCli,
  validateReceiptDigest
});
