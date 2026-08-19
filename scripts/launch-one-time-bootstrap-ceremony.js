import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const ENTRY_PATH = "scripts/run-one-time-bootstrap-ceremony.js";
const LAUNCHER_PATH = "scripts/launch-one-time-bootstrap-ceremony.js";
const OFFICIAL_REMOTE = "https://github.com/Flash-Bri/prooftoact.git";
const TRUSTED_GIT = "/usr/bin/git";
const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const ARGUMENT_NAMES = Object.freeze([
  "--aws-cli-path", "--journal-directory", "--mode", "--plan-file",
  "--source-root"
]);
const COMPUTED_IMPORT_PATHS = Object.freeze([
  "scripts/bootstrap-fresh-primary.js",
  "scripts/fresh-primary-bootstrap-role-readback.js",
  "scripts/fresh-primary-credential-custody-readback.js",
  "scripts/fresh-primary-credential-sealer.js",
  "scripts/prepare-fresh-primary-bootstrap-role.js",
  "scripts/prepare-fresh-primary-credential-custody.js"
]);
const ALLOWED_ENVIRONMENT = Object.freeze(new Set([
  "AWS_DEFAULT_REGION", "AWS_EC2_METADATA_DISABLED", "AWS_PROFILE",
  "AWS_REGION", "AWS_SDK_LOAD_CONFIG", "HOME", "LANG", "LC_ALL", "PATH",
  "TMPDIR"
]));

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

function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (plainObject(value)) {
    return Object.fromEntries(Object.keys(value).sort().map((key) =>
      [key, canonicalValue(value[key])]));
  }
  requireCondition(value === null || typeof value === "string" ||
    typeof value === "boolean" ||
    typeof value === "number" && Number.isSafeInteger(value),
  "ONE_TIME_BOOTSTRAP_LAUNCH_CANONICAL_REJECTED");
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value));
}

function canonicalBytes(value) {
  return Buffer.from(`${canonicalJson(value)}\n`, "utf8");
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function digest(value) {
  return sha256(canonicalBytes(value));
}

function parseArguments(args) {
  const code = "ONE_TIME_BOOTSTRAP_LAUNCH_ARGUMENTS_REJECTED";
  requireCondition(Array.isArray(args) &&
    args.length === ARGUMENT_NAMES.length * 2, code);
  const values = {};
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    const value = args[index + 1];
    requireCondition(ARGUMENT_NAMES.includes(name) &&
      !Object.hasOwn(values, name) && typeof value === "string" &&
      value.length > 0, code);
    values[name] = value;
  }
  requireCondition(Object.keys(values).sort().join("\n") ===
    [...ARGUMENT_NAMES].sort().join("\n") &&
    ["NEW", "RECONCILE_ONLY"].includes(values["--mode"]) &&
    ARGUMENT_NAMES.filter((name) => name !== "--mode").every((name) =>
      path.isAbsolute(values[name])), code);
  return Object.freeze(values);
}

function verifyEnvironment() {
  const code = "ONE_TIME_BOOTSTRAP_LAUNCH_ENVIRONMENT_REJECTED";
  requireCondition(process.execArgv.length === 0 &&
    Object.keys(process.env).every((key) => ALLOWED_ENVIRONMENT.has(key)) &&
    process.env.PATH === "/usr/bin:/bin" && process.env.LANG === "C" &&
    process.env.LC_ALL === "C" && process.env.AWS_REGION === "us-east-1" &&
    process.env.AWS_DEFAULT_REGION === "us-east-1" &&
    process.env.AWS_EC2_METADATA_DISABLED === "true" &&
    process.env.AWS_SDK_LOAD_CONFIG === "1" &&
    typeof process.env.HOME === "string" &&
    path.isAbsolute(process.env.HOME), code);
  return true;
}

function readPrivateBytes(filePath, maximumBytes, code) {
  requireCondition(path.isAbsolute(filePath), code);
  let descriptor;
  try {
    descriptor = fs.openSync(filePath,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const before = fs.fstatSync(descriptor);
    requireCondition(before.isFile() && !before.isSymbolicLink() &&
      before.nlink === 1 && before.uid === process.getuid() &&
      (before.mode & 0o077) === 0 && before.size > 0 &&
      before.size <= maximumBytes, code);
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor);
    requireCondition(bytes.length === before.size && before.dev === after.dev &&
      before.ino === after.ino && before.mode === after.mode &&
      before.size === after.size, code);
    return bytes;
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  } finally {
    if (Number.isSafeInteger(descriptor)) fs.closeSync(descriptor);
  }
}

function readAuthorizationFd(fd = 4) {
  const code = "ONE_TIME_BOOTSTRAP_LAUNCH_AUTHORIZATION_FD_REJECTED";
  let stat;
  try {
    stat = fs.fstatSync(fd);
  } catch (cause) {
    reject(code, cause);
  }
  requireCondition(!stat.isFile() && !stat.isDirectory() &&
    stat.uid === process.getuid() && (stat.mode & 0o077) === 0, code);
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      const buffer = Buffer.alloc(Math.min(16 * 1024, 256 * 1024 + 1 - total));
      const count = fs.readSync(fd, buffer, 0, buffer.length, null);
      if (count === 0) {
        buffer.fill(0);
        break;
      }
      chunks.push(buffer.subarray(0, count));
      total += count;
      requireCondition(total <= 256 * 1024, code);
    }
    return Buffer.concat(chunks, total);
  } catch (cause) {
    for (const chunk of chunks) chunk.fill(0);
    if (cause?.message === code) throw cause;
    reject(code, cause);
  }
}

function gitBytes(args) {
  try {
    return execFileSync(TRUSTED_GIT, [
      "-c", "core.attributesFile=/dev/null",
      "-c", "core.autocrlf=false",
      "-c", "core.eol=lf",
      "-c", "core.fsmonitor=false",
      "-c", "core.hooksPath=/dev/null",
      "-c", "core.untrackedCache=false",
      "-c", "core.askPass=", "-c", "credential.helper=",
      "-c", "credential.interactive=never", "-c", "http.extraHeader=",
      "-c", "http.proxy=", "-c", "http.sslVerify=true", ...args
    ], {
      cwd: ROOT,
      encoding: "buffer",
      env: {
        GIT_CONFIG_COUNT: "0", GIT_CONFIG_GLOBAL: "/dev/null",
        GIT_CONFIG_NOSYSTEM: "1", GIT_NO_LAZY_FETCH: "1",
        GIT_NO_REPLACE_OBJECTS: "1", LANG: "C", LC_ALL: "C",
        PATH: "/usr/bin:/bin"
      },
      maxBuffer: 32 * 1024 * 1024,
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 30_000
    });
  } catch (cause) {
    reject("ONE_TIME_BOOTSTRAP_LAUNCH_GIT_REJECTED", cause);
  }
}

function gitValue(args) {
  return gitBytes(args).toString("utf8").trim();
}

function verifyExactSource(plan, sourceRoot) {
  const code = "ONE_TIME_BOOTSTRAP_LAUNCH_SOURCE_REJECTED";
  requireCondition(sourceRoot === ROOT && HEX_40.test(plan.source?.commit ?? "") &&
    HEX_40.test(plan.source?.tree ?? ""), code);
  const gitStat = fs.lstatSync(TRUSTED_GIT);
  requireCondition(fs.realpathSync(TRUSTED_GIT) === TRUSTED_GIT &&
    gitStat.isFile() && !gitStat.isSymbolicLink() &&
    [OFFICIAL_REMOTE, OFFICIAL_REMOTE.slice(0, -4)].includes(
      gitValue(["remote", "get-url", "origin"])
    ) && gitValue(["rev-parse", "HEAD"]) === plan.source.commit &&
    gitValue(["rev-parse", "HEAD^{tree}"]) === plan.source.tree &&
    gitValue(["rev-parse", "--show-toplevel"]) === ROOT &&
    gitValue(["rev-parse", "--is-shallow-repository"]) === "false" &&
    gitValue(["for-each-ref", "--format=%(refname)", "refs/replace/"]) ===
      "" &&
    gitValue(["status", "--porcelain=v1", "--untracked-files=all"]) === "",
  code);
  const launcher = fs.readFileSync(path.join(ROOT, LAUNCHER_PATH));
  requireCondition(sha256(launcher) === plan.source.ceremonyLauncherSha256 &&
    launcher.equals(gitBytes([
      "cat-file", "blob", `${plan.source.commit}:${LAUNCHER_PATH}`
    ])), code);
  return true;
}

function parseImportSpecifiers(source, relativePath) {
  const code = "ONE_TIME_BOOTSTRAP_LAUNCH_IMPORT_GRAPH_REJECTED";
  const dynamicCount = (source.match(/\bimport\s*\(/gu) ?? []).length;
  const literalDynamic = [...source.matchAll(
    /\bimport\s*\(\s*["']([^"'\n\\]+)["']\s*\)/gu
  )].map((match) => match[1]);
  const computed = dynamicCount - literalDynamic.length;
  const exactComputedA1Loader = relativePath === ENTRY_PATH &&
    source.includes("return import(pathToFileURL(absolutePath).href);");
  requireCondition(computed === 0 ||
    computed === 1 && exactComputedA1Loader, code);
  const statics = [...source.matchAll(
    /(?:\bfrom\s+|\bimport\s+)["']([^"'\n\\]+)["']/gu
  )].map((match) => match[1]);
  return Object.freeze([...new Set([...statics, ...literalDynamic])].sort());
}

function dependencyName(specifier) {
  return specifier.startsWith("@") ?
    specifier.split("/").slice(0, 2).join("/") : specifier.split("/")[0];
}

function executableGraph(sourceCommit, root = ROOT) {
  const code = "ONE_TIME_BOOTSTRAP_LAUNCH_IMPORT_GRAPH_REJECTED";
  const pending = [ENTRY_PATH, ...COMPUTED_IMPORT_PATHS];
  const visited = new Set();
  const external = new Set();
  const records = [];
  while (pending.length > 0) {
    const relativePath = pending.pop();
    if (visited.has(relativePath)) continue;
    visited.add(relativePath);
    requireCondition(/^[A-Za-z0-9][A-Za-z0-9._/-]{0,300}\.js$/u
      .test(relativePath) && !relativePath.includes(".."), code);
    const filePath = path.resolve(root, relativePath);
    requireCondition(path.relative(root, filePath).split(path.sep).join("/") ===
      relativePath && fs.realpathSync(filePath) === filePath, code);
    const stat = fs.lstatSync(filePath);
    requireCondition(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1,
      code);
    const bytes = fs.readFileSync(filePath);
    const committed = gitBytes([
      "cat-file", "blob", `${sourceCommit}:${relativePath}`
    ]);
    requireCondition(bytes.equals(committed), code);
    const imports = parseImportSpecifiers(bytes.toString("utf8"), relativePath);
    records.push({ imports, path: relativePath, sha256: sha256(bytes),
      size: bytes.length });
    for (const specifier of imports) {
      if (specifier.startsWith("node:")) continue;
      if (!specifier.startsWith(".")) {
        external.add(dependencyName(specifier));
        continue;
      }
      const resolved = path.resolve(path.dirname(filePath), specifier);
      const candidate = path.extname(resolved) === "" ? `${resolved}.js` : resolved;
      const child = path.relative(root, candidate).split(path.sep).join("/");
      requireCondition(!child.startsWith("../") && child.endsWith(".js"), code);
      pending.push(child);
    }
  }
  records.sort((left, right) => left.path.localeCompare(right.path));
  const manifest = JSON.parse(fs.readFileSync(path.join(root, "package.json"),
    "utf8"));
  const declared = new Set([
    ...Object.keys(manifest.dependencies ?? {}),
    ...Object.keys(manifest.devDependencies ?? {})
  ]);
  requireCondition([...external].every((name) => declared.has(name)), code);
  return Object.freeze({
    externalDependencies: Object.freeze([...external].sort()),
    graphSha256: digest(records),
    records: Object.freeze(records)
  });
}

function runtimeTree(rootPath, { skipRootBin = false } = {}) {
  const code = "ONE_TIME_BOOTSTRAP_LAUNCH_RUNTIME_TREE_REJECTED";
  const root = fs.realpathSync(rootPath);
  requireCondition(root === path.resolve(rootPath) &&
    fs.lstatSync(rootPath).isDirectory(), code);
  const records = [];
  let totalBytes = 0;
  function visit(directory, relativeDirectory = "") {
    for (const name of fs.readdirSync(directory).sort()) {
      if (skipRootBin && relativeDirectory === "" && name === ".bin") continue;
      const relativePath = relativeDirectory ?
        `${relativeDirectory}/${name}` : name;
      const absolutePath = path.join(directory, name);
      const stat = fs.lstatSync(absolutePath);
      if (stat.isDirectory()) {
        records.push({ mode: stat.mode & 0o777, path: `${relativePath}/`,
          size: 0, type: "directory", valueSha256: sha256("") });
        visit(absolutePath, relativePath);
      } else if (stat.isSymbolicLink()) {
        requireCondition(!skipRootBin, code);
        const bytes = Buffer.from(fs.readlinkSync(absolutePath), "utf8");
        totalBytes += bytes.length;
        records.push({ mode: stat.mode & 0o777, path: relativePath,
          size: bytes.length, type: "symlink", valueSha256: sha256(bytes) });
      } else {
        requireCondition(stat.isFile(), code);
        const bytes = fs.readFileSync(absolutePath);
        requireCondition(bytes.length === stat.size, code);
        totalBytes += bytes.length;
        records.push({ mode: stat.mode & 0o777, path: relativePath,
          size: bytes.length, type: "file", valueSha256: sha256(bytes) });
      }
    }
  }
  visit(root);
  return Object.freeze({
    fileCount: records.filter(({ type }) => type !== "directory").length,
    recordCount: records.length,
    totalBytes,
    treeDigest: sha256(Buffer.from(records.map((record) =>
      `${record.path}\0${record.type}\0${record.mode}\0${record.size}\0` +
      `${record.valueSha256}\n`).join(""), "utf8"))
  });
}

function verifyRuntimeBinding(plan, parsed) {
  const code = "ONE_TIME_BOOTSTRAP_LAUNCH_RUNTIME_BINDING_REJECTED";
  const binding = plan.source?.runtimeExecutionBinding;
  requireCondition(binding?.schemaVersion ===
    "prooftoact.one-time-bootstrap-runtime-execution.v1" &&
    binding.node?.version === process.version &&
    binding.node?.architecture === process.arch &&
    binding.node?.platform === process.platform &&
    binding.node?.realPath === fs.realpathSync(process.execPath) &&
    binding.node?.executableSha256 === sha256(fs.readFileSync(
      fs.realpathSync(process.execPath)
    )) && binding.awsCli?.requestedPath === parsed["--aws-cli-path"] &&
    binding.awsCli?.realPath === fs.realpathSync(parsed["--aws-cli-path"]) &&
    binding.awsCli.entrySha256 === sha256(fs.readFileSync(
      binding.awsCli.realPath
    )), code);
  const dependency = runtimeTree(path.join(ROOT, "node_modules"),
    { skipRootBin: true });
  const awsCli = runtimeTree(binding.awsCli.runtimeRoot);
  requireCondition(canonicalJson(dependency) ===
    canonicalJson(binding.dependencies) && canonicalJson(awsCli) ===
    canonicalJson(Object.fromEntries(Object.entries(binding.awsCli).filter(
      ([key]) => ["fileCount", "recordCount", "totalBytes", "treeDigest"]
        .includes(key)
    ))), code);
  return Object.freeze({
    awsCliTreeSha256: awsCli.treeDigest,
    dependencyTreeSha256: dependency.treeDigest,
    nodeExecutableSha256: binding.node.executableSha256
  });
}

function verifyPlanAndAuthorization(planBytes, authorizationBytes,
  mode = "NEW") {
  const code = "ONE_TIME_BOOTSTRAP_LAUNCH_AUTHORIZATION_REJECTED";
  let plan;
  let receipt;
  try {
    plan = JSON.parse(planBytes.toString("utf8"));
    receipt = JSON.parse(authorizationBytes.toString("utf8"));
  } catch (cause) {
    reject(code, cause);
  }
  const body = { ...plan };
  delete body.planBodySha256;
  requireCondition(plan.schemaVersion ===
    "prooftoact.one-time-bootstrap-authority-plan.v1" &&
    plan.planBodySha256 === digest(body) && canonicalBytes(plan).equals(
      planBytes
    ) && sha256(authorizationBytes) ===
      plan.authorization?.userAuthorizationReceiptSha256 &&
    canonicalBytes(receipt).equals(authorizationBytes) &&
    receipt.schemaVersion ===
      "prooftoact.one-time-bootstrap-authorization.v1" &&
    receipt.status ===
      "AUTHORIZED_EXACT_ROOT_B0_CEREMONY_AND_COST_CEILING" &&
    receipt.accountId === plan.account?.accountId &&
    receipt.operationId === plan.operation?.operationId &&
    receipt.sourceCommit === plan.source?.commit &&
    receipt.treeDigest === plan.source?.tree &&
    receipt.runtimeExecutionBindingSha256 ===
      digest(plan.source?.runtimeExecutionBinding) &&
    receipt.cleanupOnlyAuthorizationApproved === true &&
    canonicalJson(receipt.cleanupOnlyAuthorization) ===
      canonicalJson(plan.authorization?.cleanupOnlyAuthorization) &&
    receipt.costCeiling?.maximumMonthlyUsdCents === 350 &&
    receipt.costCeiling?.maximumOneTimeUsdCents === 500 &&
    receipt.costCeiling?.reconciliationReceipt?.receiptSha256 ===
      receipt.costCeiling?.reconciliationReceiptSha256 &&
    receipt.costCeiling?.reconciliationReceipt?.receiptSha256 ===
      digest(Object.fromEntries(Object.entries(
        receipt.costCeiling.reconciliationReceipt
      ).filter(([key]) => key !== "receiptSha256"))) &&
    canonicalJson(receipt.costCeiling) === canonicalJson(plan.costCeiling) &&
    ["NEW", "RECONCILE_ONLY"].includes(mode) &&
    Date.parse(receipt.approvedAt) <= Date.now() &&
    (mode === "NEW" ? Date.now() < Date.parse(receipt.expiresAt) :
      Date.now() < Date.parse(receipt.cleanupOnlyAuthorization?.expiresAt)) &&
    receipt.expiresAt === plan.notAfter, code);
  requireCondition(process.env.HOME ===
    plan.source?.runtimeExecutionBinding?.homeDirectory, code);
  return Object.freeze({ plan, receipt });
}

function copyTree(source, destination, { skipRootBin = false } = {}) {
  fs.mkdirSync(destination, {
    mode: fs.lstatSync(source).mode & 0o777,
    recursive: true
  });
  function visit(sourceDirectory, destinationDirectory, rootLevel = false) {
    for (const name of fs.readdirSync(sourceDirectory).sort()) {
      if (skipRootBin && rootLevel && name === ".bin") continue;
      const from = path.join(sourceDirectory, name);
      const to = path.join(destinationDirectory, name);
      const stat = fs.lstatSync(from);
      requireCondition(!stat.isSymbolicLink(),
        "ONE_TIME_BOOTSTRAP_LAUNCH_SNAPSHOT_REJECTED");
      if (stat.isDirectory()) {
        fs.mkdirSync(to, { mode: stat.mode & 0o777 });
        visit(from, to, false);
      } else {
        requireCondition(stat.isFile(),
          "ONE_TIME_BOOTSTRAP_LAUNCH_SNAPSHOT_REJECTED");
        fs.copyFileSync(from, to, fs.constants.COPYFILE_EXCL);
        fs.chmodSync(to, stat.mode & 0o777);
      }
    }
  }
  visit(source, destination, true);
}

function sealSnapshotTree(directory) {
  const entries = fs.readdirSync(directory, { recursive: true })
    .map((entry) => path.join(directory, entry))
    .sort((left, right) => right.length - left.length);
  for (const target of entries) {
    const stat = fs.lstatSync(target);
    requireCondition(!stat.isSymbolicLink(),
      "ONE_TIME_BOOTSTRAP_LAUNCH_SNAPSHOT_REJECTED");
    fs.chmodSync(target, stat.isDirectory() ? 0o500 : 0o400);
  }
  fs.chmodSync(directory, 0o500);
}

function createSealedSnapshot(graph, binding) {
  const parent = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()),
    "prooftoact-b0-runtime-"));
  fs.chmodSync(parent, 0o700);
  try {
    for (const record of graph.records) {
      const destination = path.join(parent, record.path);
      fs.mkdirSync(path.dirname(destination), { mode: 0o700, recursive: true });
      const bytes = fs.readFileSync(path.join(ROOT, record.path));
      requireCondition(sha256(bytes) === record.sha256,
        "ONE_TIME_BOOTSTRAP_LAUNCH_SNAPSHOT_REJECTED");
      fs.writeFileSync(destination, bytes, { flag: "wx", mode: 0o400 });
    }
    fs.copyFileSync(path.join(ROOT, "package.json"),
      path.join(parent, "package.json"), fs.constants.COPYFILE_EXCL);
    fs.chmodSync(path.join(parent, "package.json"), 0o400);
    copyTree(path.join(ROOT, "node_modules"), path.join(parent, "node_modules"),
      { skipRootBin: true });
    requireCondition(runtimeTree(path.join(parent, "node_modules"),
      { skipRootBin: true }).treeDigest === binding.dependencies.treeDigest,
    "ONE_TIME_BOOTSTRAP_LAUNCH_SNAPSHOT_REJECTED");
    sealSnapshotTree(parent);
    return parent;
  } catch (cause) {
    fs.chmodSync(parent, 0o700);
    fs.rmSync(parent, { force: true, recursive: true });
    throw cause;
  }
}

function removeSnapshot(directory) {
  if (directory === null) return;
  fs.chmodSync(directory, 0o700);
  for (const entry of fs.readdirSync(directory, { recursive: true })) {
    const target = path.join(directory, entry);
    try {
      const stat = fs.lstatSync(target);
      if (stat.isDirectory()) fs.chmodSync(target, 0o700);
      else fs.chmodSync(target, 0o600);
    } catch {
      // Parent traversal may already expose a descendant; final remove verifies.
    }
  }
  fs.rmSync(directory, { force: true, recursive: true });
}

export async function main(args = process.argv.slice(2)) {
  verifyEnvironment();
  const parsed = parseArguments(args);
  const planBytes = readPrivateBytes(parsed["--plan-file"], 2 * 1024 * 1024,
    "ONE_TIME_BOOTSTRAP_LAUNCH_PLAN_FILE_REJECTED");
  const authorizationBytes = readAuthorizationFd();
  let snapshot = null;
  try {
    const { plan } = verifyPlanAndAuthorization(
      planBytes,
      authorizationBytes,
      parsed["--mode"]
    );
    requireCondition(plan.account.rootProfile === process.env.AWS_PROFILE,
      "ONE_TIME_BOOTSTRAP_LAUNCH_ENVIRONMENT_REJECTED");
    verifyExactSource(plan, parsed["--source-root"]);
    const bindingReceipt = verifyRuntimeBinding(plan, parsed);
    const graph = executableGraph(plan.source.commit);
    snapshot = createSealedSnapshot(graph,
      plan.source.runtimeExecutionBinding);
    const awsCliGuard = () => verifyRuntimeBinding(plan, parsed);
    const module = await import(pathToFileURL(path.join(
      snapshot, ENTRY_PATH
    )).href);
    requireCondition(typeof module.main === "function",
      "ONE_TIME_BOOTSTRAP_LAUNCH_ENTRY_REJECTED");
    return await module.main(args, {
      authorizationBytes,
      awsCliGuard,
      bindingReceipt,
      moduleRoot: snapshot
    });
  } finally {
    authorizationBytes.fill(0);
    removeSnapshot(snapshot);
  }
}

const startedDirectly = process.argv[1] && import.meta.url ===
  pathToFileURL(path.resolve(process.argv[1])).href;

if (startedDirectly) {
  main().catch((cause) => {
    const code = /^ONE_TIME_BOOTSTRAP_[A-Z0-9_]{1,160}$/u.test(
      String(cause?.message ?? "")
    ) ? cause.message : "ONE_TIME_BOOTSTRAP_LAUNCH_UNKNOWN";
    process.stderr.write(`${code}\n`);
    process.exitCode = 1;
  });
}

export const __test = Object.freeze({
  ALLOWED_ENVIRONMENT,
  ARGUMENT_NAMES,
  COMPUTED_IMPORT_PATHS,
  canonicalJson,
  createSealedSnapshot,
  digest,
  executableGraph,
  parseArguments,
  parseImportSpecifiers,
  removeSnapshot,
  runtimeTree,
  sha256,
  verifyEnvironment,
  verifyPlanAndAuthorization,
  verifyRuntimeBinding
});
