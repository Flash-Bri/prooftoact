import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const ENTRY_PATH = "scripts/run-fresh-cluster-provider.js";
const OFFICIAL_REMOTE = "https://github.com/Flash-Bri/prooftoact.git";
const TRUSTED_GIT = "/usr/bin/git";
const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const EXPECTED_ARGUMENTS = Object.freeze([
  "--admin-password-file",
  "--admin-secret-arn",
  "--admin-secret-version-id",
  "--approval-file",
  "--auditor-secret-arn",
  "--auditor-secret-version-id",
  "--build-receipt",
  "--cloud-api-secret-arn",
  "--cloud-api-secret-version-id",
  "--controller-table-arn",
  "--credential-secret-arn",
  "--credential-secret-version-id",
  "--expected-commit",
  "--expected-tree",
  "--mcp-secret-arn",
  "--mcp-secret-version-id",
  "--mode",
  "--operation-id",
  "--publisher-secret-arn",
  "--publisher-secret-version-id",
  "--receipt-output",
  "--release-control-runtime-receipt",
  "--recovery-security-receipt-sha256",
  "--signer-secret-arn",
  "--signer-secret-version-id"
]);

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
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

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (plainObject(value)) {
    return `{${Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, nested]) => `${JSON.stringify(key)}:${canonicalJson(nested)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function parseArguments(args) {
  const code = "FRESH_CLUSTER_LAUNCH_ARGUMENTS_REJECTED";
  requireCondition(Array.isArray(args) &&
    args.length === EXPECTED_ARGUMENTS.length * 2, code);
  const values = {};
  const accepted = new Set(EXPECTED_ARGUMENTS);
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    const value = args[index + 1];
    requireCondition(accepted.has(name) && !Object.hasOwn(values, name) &&
      typeof value === "string" && value !== "", code);
    values[name] = value;
  }
  requireCondition(Object.keys(values).length === EXPECTED_ARGUMENTS.length &&
    HEX_40.test(values["--expected-commit"] ?? "") &&
    HEX_40.test(values["--expected-tree"] ?? ""), code);
  return Object.freeze(values);
}

function gitBytes(args) {
  try {
    return execFileSync(TRUSTED_GIT, [
      "-c", "core.askPass=",
      "-c", "credential.helper=",
      "-c", "credential.interactive=never",
      "-c", "http.extraHeader=",
      "-c", "http.proxy=",
      "-c", "http.sslVerify=true",
      ...args
    ], {
      cwd: ROOT,
      encoding: "buffer",
      env: {
        GIT_CONFIG_COUNT: "0",
        GIT_CONFIG_GLOBAL: "/dev/null",
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_NO_LAZY_FETCH: "1",
        GIT_NO_REPLACE_OBJECTS: "1",
        LANG: "C",
        LC_ALL: "C",
        PATH: "/usr/bin:/bin"
      },
      maxBuffer: 32 * 1024 * 1024,
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 30_000
    });
  } catch (cause) {
    reject("FRESH_CLUSTER_LAUNCH_GIT_REJECTED", cause);
  }
}

function gitValue(args) {
  return gitBytes(args).toString("utf8").trim();
}

function verifyExactSource(expectedCommit, expectedTree) {
  const code = "FRESH_CLUSTER_LAUNCH_SOURCE_REJECTED";
  const gitStat = fs.lstatSync(TRUSTED_GIT);
  requireCondition(fs.realpathSync(TRUSTED_GIT) === TRUSTED_GIT &&
    gitStat.isFile() && !gitStat.isSymbolicLink() &&
    [OFFICIAL_REMOTE, OFFICIAL_REMOTE.slice(0, -4)].includes(
      gitValue(["remote", "get-url", "origin"])
    ) && gitValue(["rev-parse", "HEAD"]) === expectedCommit &&
    gitValue(["rev-parse", "HEAD^{tree}"]) === expectedTree &&
    gitValue(["rev-parse", "--show-toplevel"]) === ROOT &&
    gitValue(["rev-parse", "--is-shallow-repository"]) === "false" &&
    gitValue(["for-each-ref", "--format=%(refname)", "refs/replace/"]) ===
      "" &&
    gitValue(["status", "--porcelain=v1", "--untracked-files=all"]) === "",
  code);
  if (process.env.GITHUB_ACTIONS === "true") {
    requireCondition(process.env.GITHUB_REPOSITORY ===
        "Flash-Bri/prooftoact" &&
      process.env.GITHUB_REF === "refs/heads/main" &&
      process.env.GITHUB_SHA === expectedCommit,
    "FRESH_CLUSTER_LAUNCH_GITHUB_CONTEXT_REJECTED");
  }
  return Object.freeze({ sourceCommit: expectedCommit, treeDigest: expectedTree });
}

function readPrivateJson(filePath, maximumBytes, code) {
  requireCondition(path.isAbsolute(filePath), code);
  let descriptor;
  try {
    const parent = fs.realpathSync(path.dirname(filePath));
    const parentStat = fs.lstatSync(parent);
    requireCondition(parent === path.dirname(filePath) &&
      parentStat.isDirectory() && !parentStat.isSymbolicLink() &&
      parentStat.uid === process.getuid() && (parentStat.mode & 0o077) === 0,
    code);
    descriptor = fs.openSync(
      filePath,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW
    );
    const before = fs.fstatSync(descriptor);
    requireCondition(before.isFile() && !before.isSymbolicLink() &&
      before.nlink === 1 && before.uid === process.getuid() &&
      (before.mode & 0o077) === 0 && before.size > 0 &&
      before.size <= maximumBytes,
    code);
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor);
    requireCondition(bytes.length === before.size && before.dev === after.dev &&
      before.ino === after.ino && before.mode === after.mode &&
      before.size === after.size,
    code);
    const value = JSON.parse(bytes.toString("utf8"));
    requireCondition(plainObject(value), code);
    return Object.freeze({ bytes, value });
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  } finally {
    if (Number.isSafeInteger(descriptor)) fs.closeSync(descriptor);
  }
}

function parseImportSpecifiers(source, relativePath = null) {
  const code = "FRESH_CLUSTER_LAUNCH_IMPORT_GRAPH_REJECTED";
  requireCondition(typeof source === "string", code);
  const dynamicCount = (source.match(/\bimport\s*\(/gu) ?? []).length;
  const dynamic = [...source.matchAll(
    /\bimport\s*\(\s*["']([^"'\n\\]+)["']\s*\)/gu
  )].map((match) => match[1]);
  const computedCount = dynamicCount - dynamic.length;
  const exactReleaseControlRuntimeLoader =
    relativePath ===
      "release-control/src/release-control-runtime-loader.js" &&
    source.includes(
      "const module = await import(\n" +
      "    `data:text/javascript;base64,${bytes.toString(\"base64\")}`\n" +
      "  );"
    );
  requireCondition(computedCount === 0 ||
    (computedCount === 1 && exactReleaseControlRuntimeLoader), code);
  const staticSpecifiers = [...source.matchAll(
    /(?:\bfrom\s+|\bimport\s+)["']([^"'\n\\]+)["']/gu
  )].map((match) => match[1]);
  return Object.freeze([...new Set([...staticSpecifiers, ...dynamic])].sort());
}

function dependencyName(specifier) {
  if (specifier.startsWith("@")) return specifier.split("/").slice(0, 2).join("/");
  return specifier.split("/")[0];
}

function executableGraph(sourceCommit, verifyCommitted = true) {
  const code = "FRESH_CLUSTER_LAUNCH_IMPORT_GRAPH_REJECTED";
  const pending = [ENTRY_PATH];
  const visited = new Set();
  const external = new Set();
  const records = [];
  while (pending.length > 0) {
    const relativePath = pending.pop();
    if (visited.has(relativePath)) continue;
    visited.add(relativePath);
    requireCondition(/^[A-Za-z0-9][A-Za-z0-9._/-]{0,300}\.js$/u
      .test(relativePath) && !relativePath.includes(".."), code);
    const filePath = path.resolve(ROOT, relativePath);
    requireCondition(path.relative(ROOT, filePath).split(path.sep).join("/") ===
      relativePath && fs.realpathSync(filePath) === filePath, code);
    const stat = fs.lstatSync(filePath);
    requireCondition(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1,
      code);
    const bytes = fs.readFileSync(filePath);
    if (verifyCommitted) {
      requireCondition(HEX_40.test(sourceCommit ?? ""), code);
      const committed = gitBytes([
        "cat-file", "blob", `${sourceCommit}:${relativePath}`
      ]);
      requireCondition(bytes.equals(committed), code);
    }
    const imports = parseImportSpecifiers(bytes.toString("utf8"), relativePath);
    records.push(Object.freeze({
      imports,
      path: relativePath,
      sha256: sha256(bytes),
      size: bytes.length
    }));
    for (const specifier of imports) {
      if (specifier.startsWith("node:")) continue;
      if (!specifier.startsWith(".")) {
        external.add(dependencyName(specifier));
        continue;
      }
      const resolved = path.resolve(path.dirname(filePath), specifier);
      const candidate = path.extname(resolved) === "" ? `${resolved}.js` : resolved;
      const child = path.relative(ROOT, candidate).split(path.sep).join("/");
      requireCondition(!child.startsWith("../") && child.endsWith(".js"), code);
      pending.push(child);
    }
  }
  records.sort((left, right) => left.path.localeCompare(right.path));
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"),
    "utf8"));
  const declared = new Set([
    ...Object.keys(manifest.dependencies ?? {}),
    ...Object.keys(manifest.devDependencies ?? {})
  ]);
  requireCondition([...external].every((name) => declared.has(name)), code);
  return Object.freeze({
    entryPath: ENTRY_PATH,
    externalDependencies: Object.freeze([...external].sort()),
    fileCount: records.length,
    graphSha256: sha256(Buffer.from(`${canonicalJson(records)}\n`, "utf8")),
    records: Object.freeze(records)
  });
}

function dependencyTree(dependencyRoot) {
  const records = [];
  let totalBytes = 0;
  function visit(directory, relativeDirectory = "") {
    for (const name of fs.readdirSync(directory).sort()) {
      if (relativeDirectory === "" && name === ".bin") continue;
      requireCondition(name !== "" && name !== "." && name !== ".." &&
        !name.includes("\0"), "FRESH_CLUSTER_LAUNCH_DEPENDENCY_REJECTED");
      const relativePath = relativeDirectory
        ? `${relativeDirectory}/${name}`
        : name;
      const absolutePath = path.join(directory, name);
      const stat = fs.lstatSync(absolutePath);
      requireCondition(!stat.isSymbolicLink(),
        "FRESH_CLUSTER_LAUNCH_DEPENDENCY_REJECTED");
      if (stat.isDirectory()) {
        visit(absolutePath, relativePath);
        continue;
      }
      requireCondition(stat.isFile(),
        "FRESH_CLUSTER_LAUNCH_DEPENDENCY_REJECTED");
      const bytes = fs.readFileSync(absolutePath);
      requireCondition(bytes.length === stat.size,
        "FRESH_CLUSTER_LAUNCH_DEPENDENCY_REJECTED");
      totalBytes += bytes.length;
      records.push({
        mode: stat.mode & 0o777,
        path: relativePath,
        sha256: sha256(bytes),
        size: bytes.length
      });
    }
  }
  visit(dependencyRoot);
  const treeDigest = sha256(Buffer.from(records.map((record) =>
    `${record.path}\0${record.mode}\0${record.size}\0${record.sha256}\n`
  ).join(""), "utf8"));
  return Object.freeze({ fileCount: records.length, totalBytes, treeDigest });
}

function validateBuildReceipt(receipt, source) {
  const code = "FRESH_CLUSTER_LAUNCH_BUILD_RECEIPT_REJECTED";
  const packageJsonDigest = sha256(fs.readFileSync(path.join(ROOT,
    "package.json")));
  const packageLockDigest = sha256(fs.readFileSync(path.join(ROOT,
    "package-lock.json")));
  requireCondition(exactKeys(receipt, [
    "archiveFormat", "artifacts", "bootstrapTemplate", "buildControlInputs",
    "dependencySnapshot", "evidenceProviderRuntime", "gate2Template",
    "liveDrillRuntime", "mode", "outputPrivacy", "packageJsonDigest",
    "packageLockDigest", "projectSourceMode", "schemaVersion", "sourceCommit",
    "thirdPartyNotices", "toolchain", "treeDigest", "workingTreeClean",
    "workingTreeCleanBeforeGeneration"
  ]) && receipt.schemaVersion === "tideproof.gate2-build.v9" &&
    receipt.mode === "CLEAN_ARTIFACT_BUILD" &&
    receipt.projectSourceMode === "ISOLATED_EXACT_GIT_CHECKOUT_AND_BLOBS" &&
    receipt.sourceCommit === source.sourceCommit &&
    receipt.treeDigest === source.treeDigest &&
    receipt.workingTreeClean === true &&
    receipt.workingTreeCleanBeforeGeneration === true &&
    receipt.packageJsonDigest === packageJsonDigest &&
    receipt.packageLockDigest === packageLockDigest &&
    exactKeys(receipt.dependencySnapshot, [
      "fileCount", "installMode", "packageJsonDigest", "packageLockDigest",
      "schemaVersion", "symlinkCount", "totalBytes", "treeDigest"
    ]) && receipt.dependencySnapshot.schemaVersion ===
      "tideproof.dependency-snapshot.v1" &&
    receipt.dependencySnapshot.installMode ===
      "NPM_CI_IGNORE_SCRIPTS_CLEAN_CACHE" &&
    receipt.dependencySnapshot.symlinkCount === 0 &&
    receipt.dependencySnapshot.packageJsonDigest === packageJsonDigest &&
    receipt.dependencySnapshot.packageLockDigest === packageLockDigest &&
    exactKeys(receipt.toolchain, [
      "architecture", "gitExecutableSha256", "gitVersion",
      "nodeExecutableSha256", "nodeVersion", "npmCliSha256",
      "npmPackageBytes", "npmPackageFileCount", "npmPackageTreeDigest",
      "npmVersion", "platform", "schemaVersion"
    ]) && receipt.toolchain.schemaVersion === "tideproof.build-toolchain.v2" &&
    receipt.toolchain.nodeVersion === process.version &&
    receipt.toolchain.architecture === process.arch &&
    receipt.toolchain.platform === process.platform &&
    receipt.toolchain.nodeExecutableSha256 ===
      sha256(fs.readFileSync(fs.realpathSync(process.execPath))), code);
  const live = dependencyTree(path.join(ROOT, "node_modules"));
  requireCondition(live.fileCount === receipt.dependencySnapshot.fileCount &&
    live.totalBytes === receipt.dependencySnapshot.totalBytes &&
    live.treeDigest === receipt.dependencySnapshot.treeDigest,
  "FRESH_CLUSTER_LAUNCH_DEPENDENCY_REJECTED");
  return Object.freeze({
    buildReceiptSha256: sha256(Buffer.from(`${canonicalJson(receipt)}\n`, "utf8")),
    dependencyTreeSha256: live.treeDigest,
    packageJsonSha256: packageJsonDigest,
    packageLockSha256: packageLockDigest,
    runtimeNodeSha256: receipt.toolchain.nodeExecutableSha256
  });
}

export async function main(args = process.argv.slice(2)) {
  const parsed = parseArguments(args);
  const source = verifyExactSource(
    parsed["--expected-commit"], parsed["--expected-tree"]
  );
  const graph = executableGraph(source.sourceCommit);
  const build = readPrivateJson(
    parsed["--build-receipt"],
    16 * 1024 * 1024,
    "FRESH_CLUSTER_LAUNCH_BUILD_RECEIPT_FILE_REJECTED"
  );
  const binding = validateBuildReceipt(build.value, source);
  requireCondition(graph.fileCount > 0 && HEX_64.test(graph.graphSha256) &&
    HEX_64.test(binding.dependencyTreeSha256),
  "FRESH_CLUSTER_LAUNCH_BINDING_REJECTED");
  const module = await import("./run-fresh-cluster-provider.js");
  requireCondition(typeof module.main === "function",
    "FRESH_CLUSTER_LAUNCH_ENTRY_REJECTED");
  return module.main(args, process.env);
}

const startedDirectly = process.argv[1] && import.meta.url ===
  pathToFileURL(path.resolve(process.argv[1])).href;

if (startedDirectly) {
  main().catch((cause) => {
    const code = /^FRESH_CLUSTER_[A-Z0-9_]{1,120}$/u.test(
      String(cause?.message ?? "")
    ) ? cause.message : "FRESH_CLUSTER_LAUNCH_UNKNOWN";
    process.stderr.write(`${code}\n`);
    process.exitCode = 1;
  });
}

export const __test = Object.freeze({
  ENTRY_PATH,
  EXPECTED_ARGUMENTS,
  canonicalJson,
  dependencyTree,
  executableGraph,
  parseArguments,
  parseImportSpecifiers,
  sha256,
  validateBuildReceipt
});
