import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const RECEIPT_SCHEMA = "tideproof.integrated-live-drill-root-stage.v5";
const RUNTIME_MANIFEST_SCHEMA =
  "tideproof.integrated-live-drill-runtime-manifest.v1";
const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const RUN_INSTANCE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[4-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SYSUSERS_CONTROL_PATH = "infra/sysusers.d/prooftoact.conf";
const SERVICE_ACCOUNTS = Object.freeze([
  Object.freeze({ name: "prooftoact", description: "ProofToAct runtime" }),
  Object.freeze({ name: "prooftoact-broker", description: "ProofToAct dispatch broker" }),
  Object.freeze({ name: "prooftoact-operation", description: "ProofToAct provider operation broker" }),
  Object.freeze({ name: "prooftoact-activate", description: "ProofToAct provider activation gate" }),
  Object.freeze({ name: "prooftoact-provider", description: "ProofToAct provider exchange" }),
  Object.freeze({ name: "prooftoact-terminalize", description: "ProofToAct provider terminalizer" }),
  Object.freeze({ name: "prooftoact-reconcile", description: "ProofToAct resolver" })
]);
const EXACT_SYSUSERS_CONFIG = `${SERVICE_ACCOUNTS.map(({ name, description }) =>
  `u ${name} - ${JSON.stringify(description)} / /usr/sbin/nologin`
).join("\n")}\n`;
const GETENT = "/usr/bin/getent";
const ID = "/usr/bin/id";
const RUNTIME_COMPONENTS = Object.freeze([
  "authority-race", "dispatch-broker", "provider-activation", "provider-exchange", "provider-operation", "provider-terminalizer", "dvi", "finalizer", "orchestrator", "reconciler",
  "supervisor", "worker"
]);
const STAGE_CONTROL_PATHS = Object.freeze([
  "infra/systemd/prooftoact-integrated-live-drill-stage-verify@.service",
  "infra/systemd/prooftoact-integrated-live-drill@.service",
  "infra/systemd/prooftoact-integrated-live-drill-resume@.service",
  "infra/systemd/prooftoact-integrated-live-drill-dispatch-broker@.service",
  "infra/systemd/prooftoact-integrated-live-drill-executor@.service",
  "infra/systemd/prooftoact-integrated-live-drill-provider-operation@.service",
  "infra/systemd/prooftoact-integrated-live-drill-provider-operation@.socket",
  "infra/systemd/prooftoact-integrated-live-drill-provider-activation@.service",
  "infra/systemd/prooftoact-integrated-live-drill-provider-activation@.socket",
  "infra/systemd/prooftoact-integrated-live-drill-provider-callback@.socket",
  "infra/systemd/prooftoact-integrated-live-drill-provider-exchange@.service",
  "infra/systemd/prooftoact-integrated-live-drill-provider-terminalizer@.service",
  "infra/systemd/prooftoact-integrated-live-drill-provider-terminalizer@.timer",
  "infra/systemd/prooftoact-integrated-live-drill-reconcile@.service",
  SYSUSERS_CONTROL_PATH,
  "scripts/install-integrated-live-drill-stage.js",
  "scripts/verify-integrated-live-drill-stage.js",
  "scripts/verify-integrated-live-drill-systemd-boundary.js"
]);
const SYSTEMD_UNIT_PATHS = Object.freeze(STAGE_CONTROL_PATHS.filter(
  (controlPath) => controlPath.startsWith("infra/systemd/")
));

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.entries(value)
      .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
      .map(([key, nested]) => `${JSON.stringify(key)}:${canonicalJson(nested)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function exactKeys(value, keys) {
  return value && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).sort().join("\n") === [...keys].sort().join("\n");
}

function openExact(filePath, code) {
  let descriptor;
  try {
    descriptor = fs.openSync(
      filePath,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW
    );
    const before = fs.fstatSync(descriptor);
    requireCondition(before.isFile() && before.nlink === 1, code);
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor);
    requireCondition(
      before.dev === after.dev && before.ino === after.ino &&
        before.mode === after.mode && before.uid === after.uid &&
        before.gid === after.gid && before.size === after.size &&
        bytes.length === before.size,
      code
    );
    return Object.freeze({ bytes, stat: before });
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  } finally {
    if (Number.isSafeInteger(descriptor)) fs.closeSync(descriptor);
  }
}

function parseJson(opened, code) {
  try {
    return JSON.parse(opened.bytes.toString("utf8"));
  } catch (cause) {
    reject(code, cause);
  }
}

function runBounded(executable, argumentsList, code) {
  const opened = openExact(executable, code);
  requireCondition(
    opened.stat.uid === 0 && opened.stat.gid === 0 &&
      (opened.stat.mode & 0o022) === 0,
    code
  );
  const result = spawnSync(executable, argumentsList, {
    encoding: "utf8",
    env: { LANG: "C.UTF-8", LC_ALL: "C.UTF-8", PATH: "/usr/bin:/bin" },
    maxBuffer: 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"]
  });
  requireCondition(
    !result.error && result.signal === null && result.status === 0 &&
      typeof result.stdout === "string" && typeof result.stderr === "string",
    code
  );
  return result.stdout;
}

function parseAccountDatabase(code) {
  const passwd = runBounded(GETENT, ["passwd"], code)
    .split("\n").filter(Boolean).map((line) => {
      const fields = line.split(":");
      requireCondition(fields.length === 7, code);
      return Object.freeze({
        description: fields[4],
        gid: Number(fields[3]),
        home: fields[5],
        name: fields[0],
        shell: fields[6],
        uid: Number(fields[2])
      });
    });
  const groups = runBounded(GETENT, ["group"], code)
    .split("\n").filter(Boolean).map((line) => {
      const fields = line.split(":");
      requireCondition(fields.length === 4, code);
      return Object.freeze({
        gid: Number(fields[2]),
        members: fields[3] === "" ? Object.freeze([]) :
          Object.freeze(fields[3].split(",")),
        name: fields[0]
      });
    });
  return Object.freeze({ groups: Object.freeze(groups), passwd: Object.freeze(passwd) });
}

function validateAccountRecords(value, code) {
  requireCondition(
    Array.isArray(value) && value.length === SERVICE_ACCOUNTS.length &&
      value.every((record, index) => {
        const expected = SERVICE_ACCOUNTS[index];
        return exactKeys(record, [
          "description", "gid", "group", "home", "name",
          "passwordLocked", "shell", "supplementaryGids", "uid"
        ]) && record.name === expected.name &&
          record.description === expected.description &&
          record.group === expected.name && record.home === "/" &&
          record.shell === "/usr/sbin/nologin" &&
          record.passwordLocked === true &&
          Array.isArray(record.supplementaryGids) &&
          record.supplementaryGids.length === 0 &&
          Number.isSafeInteger(record.uid) && record.uid > 0 &&
          Number.isSafeInteger(record.gid) && record.gid > 0;
      }) &&
      new Set(value.map(({ uid }) => uid)).size === value.length &&
      new Set(value.map(({ gid }) => gid)).size === value.length,
    code
  );
  const database = parseAccountDatabase(code);
  for (const record of value) {
    const account = database.passwd.find(({ name }) => name === record.name);
    const group = database.groups.find(({ name }) => name === record.group);
    requireCondition(
      account?.description === record.description &&
        account?.uid === record.uid && account?.gid === record.gid &&
        account?.home === record.home && account?.shell === record.shell &&
        group?.gid === record.gid && group.members.length === 0 &&
        database.passwd.filter(({ uid }) => uid === record.uid).length === 1 &&
        database.groups.filter(({ gid }) => gid === record.gid).length === 1 &&
        database.groups.every(({ members }) => !members.includes(record.name)) &&
        runBounded(ID, ["-G", record.name], code).trim() === String(record.gid),
      code
    );
  }
  return value;
}

function expectedStatePlan(stateRoot, instance, accounts) {
  const ids = Object.fromEntries(accounts.map((record) => [record.name, record]));
  const root = { uid: 0, gid: 0 };
  const runtime = ids.prooftoact;
  const broker = ids["prooftoact-broker"];
  const operation = ids["prooftoact-operation"];
  const activate = ids["prooftoact-activate"];
  const provider = ids["prooftoact-provider"];
  return [
    ...["evidence", "authorization", "dispatch-broker", "executions",
      "reconciliation-inputs", "provider-activations",
      "provider-operations", "provider-exchanges"].map((name) => ({
      path: path.join(stateRoot, name), mode: 0o755, role: "CATEGORY", ...root
    })),
    ...["evidence", "authorization"].flatMap((name) => [
      { path: path.join(stateRoot, name, instance), mode: 0o700,
        role: "PRIVATE_GUARD", ...runtime },
      { path: path.join(stateRoot, name, instance, "root"), mode: 0o700,
        role: "PRIVATE_ROOT", ...runtime }
    ]),
    ...["dispatch-broker", "executions", "reconciliation-inputs"].map((name) => ({
      path: path.join(stateRoot, name, instance), mode: 0o700,
      role: "BROKER_ROOT", ...broker
    })),
    { path: path.join(stateRoot, "provider-activations", instance), mode: 0o700,
      role: "ACTIVATION_ROOT", ...activate },
    { path: path.join(stateRoot, "provider-operations", instance), mode: 0o700,
      role: "PROVIDER_OPERATION_ROOT", ...operation },
    { path: path.join(stateRoot, "provider-exchanges", instance), mode: 0o700,
      role: "PROVIDER_EXCHANGE_ROOT", ...provider }
  ];
}

function observedStateDirectories(stateRoot, instance, accounts, code) {
  return expectedStatePlan(stateRoot, instance, accounts).map((expected) => {
    const stat = fs.lstatSync(expected.path);
    requireCondition(
      stat.isDirectory() && !stat.isSymbolicLink() &&
        fs.realpathSync(expected.path) === expected.path &&
        stat.uid === expected.uid && stat.gid === expected.gid &&
        (stat.mode & 0o7777) === expected.mode,
      code
    );
    const entries = expected.role === "PRIVATE_GUARD"
      ? fs.readdirSync(expected.path).sort()
      : null;
    if (entries !== null) requireCondition(entries.join("\n") === "root", code);
    return {
      dev: String(stat.dev), entries, gid: stat.gid, ino: String(stat.ino),
      mode: stat.mode & 0o7777, path: expected.path,
      role: expected.role, uid: stat.uid
    };
  });
}

function expectedInventory(buildReceipt) {
  const runtime = buildReceipt?.liveDrillRuntime;
  const records = [
    {
      mode: 0o444,
      name: path.posix.basename(runtime?.manifestPath ?? ""),
      sha256: runtime?.manifestSha256
    },
    {
      mode: 0o555,
      name: path.posix.basename(runtime?.launcher?.path ?? ""),
      sha256: runtime?.launcher?.sha256
    },
    {
      mode: 0o555,
      name: path.posix.basename(runtime?.node?.path ?? ""),
      sha256: runtime?.node?.sha256
    },
    ...RUNTIME_COMPONENTS.map((name) => ({
      mode: 0o555,
      name: path.posix.basename(runtime?.components?.[name]?.path ?? ""),
      sha256: runtime?.components?.[name]?.sha256
    }))
  ];
  requireCondition(
    buildReceipt?.mode === "CLEAN_ARTIFACT_BUILD" &&
      buildReceipt?.projectSourceMode ===
        "ISOLATED_EXACT_GIT_CHECKOUT_AND_BLOBS" &&
      HEX_40.test(buildReceipt?.sourceCommit ?? "") &&
      HEX_40.test(buildReceipt?.treeDigest ?? "") &&
      HEX_64.test(buildReceipt?.packageLockDigest ?? "") &&
      exactKeys(runtime?.components, RUNTIME_COMPONENTS) &&
      records.length === 15 &&
      new Set(records.map(({ name }) => name)).size === records.length &&
      records.every(({ name, sha256: digest }) =>
        /^[a-z0-9][a-z0-9.-]{0,159}$/u.test(name) &&
          HEX_64.test(digest ?? "")
      ),
    "INTEGRATED_LIVE_DRILL_STAGE_BUILD_RECEIPT_REJECTED"
  );
  return Object.freeze(records.map((record) => Object.freeze(record)));
}

function validateRuntimeManifest(value, buildReceipt, code) {
  const runtime = buildReceipt.liveDrillRuntime;
  requireCondition(
    exactKeys(value, [
      "components", "launcher", "node", "packageLockDigest",
      "schemaVersion", "sourceCommit", "toolchainSha256", "treeDigest"
    ]) && value.schemaVersion === RUNTIME_MANIFEST_SCHEMA &&
      value.sourceCommit === buildReceipt.sourceCommit &&
      value.treeDigest === buildReceipt.treeDigest &&
      value.packageLockDigest === buildReceipt.packageLockDigest &&
      value.toolchainSha256 ===
        sha256(Buffer.from(canonicalJson(buildReceipt.toolchain))) &&
      exactKeys(value.launcher, ["file", "sha256"]) &&
      value.launcher.file === "verified-node-bundle-launcher.pl" &&
      value.launcher.sha256 === runtime.launcher.sha256 &&
      exactKeys(value.node, [
        "architecture", "distribution", "file", "platform", "sha256",
        "version"
      ]) && value.node.file === `node-${value.node.sha256}` &&
      value.node.architecture === runtime.node.architecture &&
      value.node.distribution === runtime.node.distribution &&
      value.node.platform === runtime.node.platform &&
      value.node.sha256 === runtime.node.sha256 &&
      value.node.version === runtime.node.version &&
      value.node.distribution === "nodejs.org-release-v22.23.1" &&
      ((value.node.platform === "linux" &&
        value.node.architecture === "x64" &&
        value.node.sha256 ===
          "93956de2e59480474a7b46571da1651180b1a050cdf32641ebec4ce6e478e068") ||
       (value.node.platform === "darwin" &&
        value.node.architecture === "arm64" &&
        value.node.sha256 ===
          "2e3f1286a7eb3736346ed1803e458a0ff909e2b2d5bc746144dcb76970e9b99d")) &&
      exactKeys(value.components, RUNTIME_COMPONENTS),
    code
  );
  for (const name of RUNTIME_COMPONENTS) {
    const component = value.components[name];
    requireCondition(
      exactKeys(component, [
        "bundledPackages", "bytes", "externalImports", "file", "sha256"
      ]) && component.file === `${name}-${component.sha256}.mjs` &&
        component.sha256 === runtime.components[name].sha256 &&
        runtime.components[name].path === `dist/runtime/${component.file}` &&
        Number.isSafeInteger(component.bytes) && component.bytes > 0 &&
        Array.isArray(component.bundledPackages) &&
        Array.isArray(component.externalImports) &&
        component.externalImports.length > 0,
      code
    );
  }
  return value;
}

function expectedStageControls(buildReceipt, code) {
  const byPath = new Map((buildReceipt?.buildControlInputs ?? []).map(
    (record) => [record?.path, record]
  ));
  requireCondition(
    STAGE_CONTROL_PATHS.every((controlPath) => {
      const record = byPath.get(controlPath);
      return record?.path === controlPath &&
        HEX_40.test(record?.gitBlobId ?? "") &&
        HEX_64.test(record?.sha256 ?? "");
    }),
    code
  );
  return STAGE_CONTROL_PATHS.map((controlPath) => {
    const record = byPath.get(controlPath);
    return {
      gitBlobId: record.gitBlobId,
      path: record.path,
      sha256: record.sha256
    };
  });
}

function observedAncestors(stageRoot, code) {
  const values = [];
  for (let current = stageRoot;; current = path.dirname(current)) {
    const stat = fs.lstatSync(current);
    requireCondition(
      stat.isDirectory() && !stat.isSymbolicLink() && stat.uid === 0 &&
        (stat.mode & 0o022) === 0 && fs.realpathSync(current) === current,
      code
    );
    values.push({
      dev: String(stat.dev), gid: stat.gid, ino: String(stat.ino),
      mode: stat.mode & 0o7777, path: current, uid: stat.uid
    });
    if (path.dirname(current) === current) break;
  }
  return values;
}

export function verifyIntegratedLiveDrillStage({
  buildRoot,
  buildReceiptPath,
  expectedBuildReceiptSha256Path,
  expectedStageRoot = null,
  stageReceiptPath,
  stateRoot,
  sysusersRoot,
  unitRoot,
  verifierRoot = null
}) {
  const code = "INTEGRATED_LIVE_DRILL_STAGE_VERIFICATION_REJECTED";
  requireCondition(
    typeof process.geteuid === "function" && process.geteuid() !== 0 &&
      [buildRoot, buildReceiptPath, stageReceiptPath].every(
      (candidate) => typeof candidate === "string" &&
        path.isAbsolute(candidate) && path.resolve(candidate) === candidate
    ) && typeof expectedBuildReceiptSha256Path === "string" &&
      path.isAbsolute(expectedBuildReceiptSha256Path) &&
      path.resolve(expectedBuildReceiptSha256Path) ===
        expectedBuildReceiptSha256Path &&
    (expectedStageRoot === null || (
      typeof expectedStageRoot === "string" &&
      path.isAbsolute(expectedStageRoot) &&
      path.resolve(expectedStageRoot) === expectedStageRoot
    )) && [stateRoot, sysusersRoot, unitRoot, verifierRoot].every((candidate) =>
      typeof candidate === "string" && path.isAbsolute(candidate) &&
        path.resolve(candidate) === candidate
    ) && path.basename(stateRoot) === "prooftoact",
    code
  );
  const buildOpened = openExact(buildReceiptPath, code);
  const acceptedBuildCredentialOpened = openExact(
    expectedBuildReceiptSha256Path,
    code
  );
  const expectedBuildReceiptSha256 = acceptedBuildCredentialOpened.bytes
    .toString("utf8").trim();
  const receiptOpened = openExact(stageReceiptPath, code);
  const buildReceipt = parseJson(buildOpened, code);
  const receipt = parseJson(receiptOpened, code);
  requireCondition(sha256(buildOpened.bytes) === expectedBuildReceiptSha256, code);
  requireCondition(
    path.relative(buildRoot, buildReceiptPath) === "gate2-build-receipt.json" &&
      JSON.stringify(observedAncestors(buildRoot, code)).length > 0,
    code
  );
  requireCondition(
    receiptOpened.stat.uid === 0 && receiptOpened.stat.gid === 0 &&
      (receiptOpened.stat.mode & 0o7777) === 0o444,
    code
  );
  requireCondition(
    exactKeys(receipt, [
      "acceptedBuildReceiptSha256File", "acceptedBuildReceiptSha256Path",
      "accountConfigFile", "accountConfigPath", "accountRecords",
      "buildAncestors", "buildFiles", "buildRoot", "buildReceiptSha256",
      "files", "manifestSha256",
      "packageLockDigest", "receiptSha256", "schemaVersion",
      "sourceCommit", "stageAncestors", "stageControls", "stageInstance", "stageRoot",
      "stateAncestors", "stateDirectories", "stateRoot",
      "systemdDaemonReloaded", "systemdSysusersExecuted",
      "unitAncestors", "unitFiles", "unitRoot",
      "verifierAncestors", "verifierFiles", "verifierRoot",
      "toolchainSha256", "treeDigest"
    ]),
    code
  );
  const { receiptSha256, ...body } = receipt;
  requireCondition(
      receipt.schemaVersion === RECEIPT_SCHEMA &&
      receipt.acceptedBuildReceiptSha256Path === path.join(
        path.dirname(stageReceiptPath), "accepted-build-receipt-sha256"
      ) &&
      path.basename(expectedBuildReceiptSha256Path) ===
        "accepted-build-receipt-sha256" &&
      receipt.systemdDaemonReloaded === true &&
      receipt.systemdSysusersExecuted === true &&
      receipt.buildRoot === buildRoot &&
      receipt.buildReceiptSha256 === sha256(buildOpened.bytes) &&
      receipt.packageLockDigest === buildReceipt.packageLockDigest &&
      receipt.sourceCommit === buildReceipt.sourceCommit &&
      receipt.treeDigest === buildReceipt.treeDigest &&
      JSON.stringify(receipt.stageControls) === JSON.stringify(
        expectedStageControls(buildReceipt, code)
      ) &&
      receipt.toolchainSha256 ===
        sha256(Buffer.from(canonicalJson(buildReceipt.toolchain))) &&
      HEX_64.test(receipt.manifestSha256 ?? "") &&
      HEX_64.test(receiptSha256 ?? "") &&
      receiptSha256 === sha256(Buffer.from(canonicalJson(body))) &&
      typeof receipt.stageRoot === "string" &&
      path.isAbsolute(receipt.stageRoot) &&
      (expectedStageRoot === null || receipt.stageRoot === expectedStageRoot) &&
      RUN_INSTANCE.test(receipt.stageInstance ?? "") &&
      path.basename(receipt.stageRoot) === receipt.stageInstance &&
      fs.realpathSync(receipt.stageRoot) === receipt.stageRoot &&
      fs.realpathSync(receipt.buildRoot) === receipt.buildRoot &&
      receipt.verifierRoot === verifierRoot &&
      receipt.unitRoot === unitRoot &&
      receipt.stateRoot === stateRoot &&
      receipt.accountConfigPath === path.join(sysusersRoot, "prooftoact.conf") &&
      path.basename(receipt.verifierRoot ?? "") === receipt.stageInstance &&
      fs.realpathSync(receipt.verifierRoot) === receipt.verifierRoot &&
      fs.realpathSync(receipt.unitRoot) === receipt.unitRoot,
    code
  );
  const expected = expectedInventory(buildReceipt);
  const acceptedBuildDigestOpened = openExact(
    receipt.acceptedBuildReceiptSha256Path,
    code
  );
  requireCondition(
    acceptedBuildCredentialOpened.bytes.equals(acceptedBuildDigestOpened.bytes) &&
      acceptedBuildDigestOpened.bytes.toString("utf8") ===
        `${expectedBuildReceiptSha256}\n` && HEX_64.test(expectedBuildReceiptSha256),
    code
  );
  const acceptedBuildDigestRecord = {
    bytes: acceptedBuildDigestOpened.bytes.length,
    dev: String(acceptedBuildDigestOpened.stat.dev),
    gid: acceptedBuildDigestOpened.stat.gid,
    ino: String(acceptedBuildDigestOpened.stat.ino),
    mode: acceptedBuildDigestOpened.stat.mode & 0o7777,
    name: path.basename(expectedBuildReceiptSha256Path),
    nlink: acceptedBuildDigestOpened.stat.nlink,
    sha256: sha256(acceptedBuildDigestOpened.bytes),
    uid: acceptedBuildDigestOpened.stat.uid
  };
  requireCondition(
    acceptedBuildDigestRecord.mode === 0o444 &&
      acceptedBuildDigestRecord.uid === 0 &&
      acceptedBuildDigestRecord.gid === 0 &&
      acceptedBuildDigestRecord.nlink === 1 &&
      JSON.stringify(receipt.acceptedBuildReceiptSha256File) ===
        JSON.stringify(acceptedBuildDigestRecord) &&
    Array.isArray(receipt.buildFiles) && receipt.buildFiles.length === 1 &&
      JSON.stringify(receipt.buildAncestors) ===
        JSON.stringify(observedAncestors(receipt.buildRoot, code)) &&
    receipt.manifestSha256 === expected[0].sha256 &&
      fs.readdirSync(receipt.stageRoot).sort().join("\n") ===
        expected.map(({ name }) => name).sort().join("\n") &&
      Array.isArray(receipt.files) && receipt.files.length === expected.length &&
      JSON.stringify(receipt.stageAncestors) ===
        JSON.stringify(observedAncestors(receipt.stageRoot, code)) &&
      JSON.stringify(receipt.unitAncestors) ===
        JSON.stringify(observedAncestors(receipt.unitRoot, code)) &&
      JSON.stringify(receipt.verifierAncestors) ===
        JSON.stringify(observedAncestors(receipt.verifierRoot, code)),
    code
  );
  const accountConfigOpened = openExact(receipt.accountConfigPath, code);
  const accountConfigRecord = {
    bytes: accountConfigOpened.bytes.length,
    dev: String(accountConfigOpened.stat.dev),
    gid: accountConfigOpened.stat.gid,
    ino: String(accountConfigOpened.stat.ino),
    mode: accountConfigOpened.stat.mode & 0o7777,
    name: "prooftoact.conf",
    nlink: accountConfigOpened.stat.nlink,
    sha256: sha256(accountConfigOpened.bytes),
    uid: accountConfigOpened.stat.uid
  };
  const accountRecords = validateAccountRecords(receipt.accountRecords, code);
  requireCondition(
    accountConfigOpened.bytes.toString("utf8") === EXACT_SYSUSERS_CONFIG &&
      accountConfigRecord.uid === 0 && accountConfigRecord.gid === 0 &&
      accountConfigRecord.mode === 0o444 && accountConfigRecord.nlink === 1 &&
      JSON.stringify(receipt.accountConfigFile) ===
        JSON.stringify(accountConfigRecord) &&
      JSON.stringify(receipt.stateAncestors) ===
        JSON.stringify(observedAncestors(receipt.stateRoot, code)) &&
      JSON.stringify(receipt.stateDirectories) === JSON.stringify(
        observedStateDirectories(
          receipt.stateRoot,
          receipt.stageInstance,
          accountRecords,
          code
        )
      ),
    code
  );
  const buildReceiptRecord = openExact(buildReceiptPath, code);
  const observedBuildReceipt = {
    bytes: buildReceiptRecord.bytes.length,
    dev: String(buildReceiptRecord.stat.dev),
    gid: buildReceiptRecord.stat.gid,
    ino: String(buildReceiptRecord.stat.ino),
    mode: buildReceiptRecord.stat.mode & 0o7777,
    name: "gate2-build-receipt.json",
    nlink: buildReceiptRecord.stat.nlink,
    sha256: sha256(buildReceiptRecord.bytes),
    uid: buildReceiptRecord.stat.uid
  };
  requireCondition(
    observedBuildReceipt.sha256 === expectedBuildReceiptSha256 &&
      observedBuildReceipt.mode === 0o444 && observedBuildReceipt.uid === 0 &&
      observedBuildReceipt.gid === 0 && observedBuildReceipt.nlink === 1 &&
      JSON.stringify(receipt.buildFiles[0]) ===
        JSON.stringify(observedBuildReceipt),
    code
  );
  const files = expected.map((record, index) => {
    const opened = openExact(path.join(receipt.stageRoot, record.name), code);
    const observed = {
      bytes: opened.bytes.length,
      dev: String(opened.stat.dev),
      gid: opened.stat.gid,
      ino: String(opened.stat.ino),
      mode: opened.stat.mode & 0o7777,
      name: record.name,
      nlink: opened.stat.nlink,
      sha256: sha256(opened.bytes),
      uid: opened.stat.uid
    };
    requireCondition(
      observed.sha256 === record.sha256 && observed.mode === record.mode &&
        observed.uid === 0 && observed.gid === 0 && observed.nlink === 1 &&
        JSON.stringify(observed) === JSON.stringify(receipt.files[index]),
      code
    );
    return observed;
  });
  const manifest = parseJson(
    openExact(path.join(receipt.stageRoot, expected[0].name), code),
    code
  );
  const acceptedManifest = validateRuntimeManifest(manifest, buildReceipt, code);
  const stageControlsByPath = new Map(receipt.stageControls.map((record) => [
    record.path,
    record
  ]));
  const expectedUnits = SYSTEMD_UNIT_PATHS.map((controlPath) => ({
    mode: 0o444,
    name: path.posix.basename(controlPath),
    sha256: stageControlsByPath.get(controlPath)?.sha256
  }));
  requireCondition(
    Array.isArray(receipt.unitFiles) &&
      receipt.unitFiles.length === expectedUnits.length &&
      fs.readdirSync(receipt.unitRoot).filter((name) => name.startsWith(
        "prooftoact-integrated-live-drill"
      )).every((name) => expectedUnits.some((record) => record.name === name)),
    code
  );
  const unitFiles = expectedUnits.map((record, index) => {
    const opened = openExact(path.join(receipt.unitRoot, record.name), code);
    const observed = {
      bytes: opened.bytes.length,
      dev: String(opened.stat.dev),
      gid: opened.stat.gid,
      ino: String(opened.stat.ino),
      mode: opened.stat.mode & 0o7777,
      name: record.name,
      nlink: opened.stat.nlink,
      sha256: sha256(opened.bytes),
      uid: opened.stat.uid
    };
    requireCondition(
      observed.sha256 === record.sha256 && observed.mode === record.mode &&
        observed.uid === 0 && observed.gid === 0 && observed.nlink === 1 &&
        JSON.stringify(observed) === JSON.stringify(receipt.unitFiles[index]),
      code
    );
    return observed;
  });
  const verifierControl = receipt.stageControls.find(({ path: controlPath }) =>
    controlPath === "scripts/verify-integrated-live-drill-stage.js"
  );
  const expectedVerifier = [
    { mode: 0o555, name: "node", sha256: acceptedManifest.node.sha256 },
    {
      mode: 0o444,
      name: "verify-integrated-live-drill-stage.js",
      sha256: verifierControl?.sha256
    }
  ];
  requireCondition(
    Array.isArray(receipt.verifierFiles) &&
      receipt.verifierFiles.length === expectedVerifier.length &&
      fs.readdirSync(receipt.verifierRoot).sort().join("\n") ===
        expectedVerifier.map(({ name }) => name).sort().join("\n"),
    code
  );
  const verifierFiles = expectedVerifier.map((record, index) => {
    const opened = openExact(path.join(receipt.verifierRoot, record.name), code);
    const observed = {
      bytes: opened.bytes.length,
      dev: String(opened.stat.dev),
      gid: opened.stat.gid,
      ino: String(opened.stat.ino),
      mode: opened.stat.mode & 0o7777,
      name: record.name,
      nlink: opened.stat.nlink,
      sha256: sha256(opened.bytes),
      uid: opened.stat.uid
    };
    requireCondition(
      observed.sha256 === record.sha256 && observed.mode === record.mode &&
        observed.uid === 0 && observed.gid === 0 && observed.nlink === 1 &&
        JSON.stringify(observed) ===
          JSON.stringify(receipt.verifierFiles[index]),
      code
    );
    return observed;
  });
  const self = openExact(fileURLToPath(import.meta.url), code);
  const runtimeNode = openExact(process.execPath, code);
  requireCondition(
    acceptedManifest.sourceCommit === receipt.sourceCommit &&
      acceptedManifest.treeDigest === receipt.treeDigest &&
      acceptedManifest.packageLockDigest === receipt.packageLockDigest &&
      acceptedManifest.toolchainSha256 === receipt.toolchainSha256 &&
      acceptedManifest.launcher.sha256 ===
        buildReceipt.liveDrillRuntime.launcher.sha256 &&
      acceptedManifest.node.sha256 ===
        buildReceipt.liveDrillRuntime.node.sha256 &&
      RUNTIME_COMPONENTS.every((name) =>
        acceptedManifest.components[name].sha256 ===
          buildReceipt.liveDrillRuntime.components[name].sha256
      ) &&
      String(self.stat.dev) === verifierFiles[1].dev &&
      String(self.stat.ino) === verifierFiles[1].ino &&
      sha256(self.bytes) === verifierFiles[1].sha256 &&
      String(runtimeNode.stat.dev) === verifierFiles[0].dev &&
      String(runtimeNode.stat.ino) === verifierFiles[0].ino &&
      sha256(runtimeNode.bytes) === verifierFiles[0].sha256,
    code
  );
  return Object.freeze({
    schemaVersion: "tideproof.integrated-live-drill-root-stage-verification.v1",
    status: "PASS",
    buildReceiptSha256: receipt.buildReceiptSha256,
    accountCount: accountRecords.length,
    fileCount: files.length,
    manifestSha256: receipt.manifestSha256,
    receiptSha256,
    sourceCommit: receipt.sourceCommit,
    stageRoot: receipt.stageRoot,
    stateDirectoryCount: receipt.stateDirectories.length,
    unitCount: unitFiles.length,
    unitRoot: receipt.unitRoot,
    treeDigest: receipt.treeDigest
  });
}

function argumentsFor(argv) {
  requireCondition(
    argv.length === 18,
    "INTEGRATED_LIVE_DRILL_STAGE_ARGUMENTS"
  );
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    requireCondition(
      [
        "--build-root",
        "--build-receipt",
        "--expected-build-receipt-sha256-path",
        "--expected-stage-root",
        "--stage-receipt",
        "--state-root",
        "--sysusers-root",
        "--unit-root",
        "--verifier-root"
      ].includes(argv[index]) &&
        !Object.hasOwn(values, argv[index]),
      "INTEGRATED_LIVE_DRILL_STAGE_ARGUMENTS"
    );
    values[argv[index]] = path.resolve(argv[index + 1]);
  }
  return Object.freeze({
    buildRoot: values["--build-root"],
    buildReceiptPath: values["--build-receipt"],
    expectedBuildReceiptSha256Path:
      values["--expected-build-receipt-sha256-path"],
    expectedStageRoot: values["--expected-stage-root"] ?? null,
    stageReceiptPath: values["--stage-receipt"],
    stateRoot: values["--state-root"],
    sysusersRoot: values["--sysusers-root"],
    unitRoot: values["--unit-root"],
    verifierRoot: values["--verifier-root"]
  });
}

const startedDirectly =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (startedDirectly) {
  try {
    process.stdout.write(
      `${canonicalJson(verifyIntegratedLiveDrillStage(
        argumentsFor(process.argv.slice(2))
      ))}\n`
    );
  } catch (error) {
    const code = /^INTEGRATED_LIVE_DRILL_STAGE_[A-Z0-9_]{1,100}$/u.test(
      String(error?.message ?? "")
    ) ? error.message : "INTEGRATED_LIVE_DRILL_STAGE_UNKNOWN";
    process.stderr.write(`${code}\n`);
    process.exitCode = 1;
  }
}
