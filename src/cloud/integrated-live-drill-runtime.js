import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { validateOfficialNodeRuntimeMetadata } from
  "./official-node-runtime-contract.js";

export const INTEGRATED_LIVE_DRILL_RUNTIME_MANIFEST_SCHEMA =
  "tideproof.integrated-live-drill-runtime-manifest.v1";
export const INTEGRATED_LIVE_DRILL_RUNTIME_MANIFEST_SHA256_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_RUNTIME_MANIFEST_SHA256";
export const INTEGRATED_LIVE_DRILL_RUNTIME_STAGE_ROOT_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_RUNTIME_STAGE_ROOT";
export const INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT";
export const INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_SHA256_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_SHA256";

const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const COMPONENTS = Object.freeze([
  "authority-race",
  "dvi",
  "finalizer",
  "orchestrator",
  "reconciler",
  "recovery",
  "supervisor",
  "worker"
]);
const SCRIPT_COMPONENTS = Object.freeze({
  "gate1-admissible-vector.js": "dvi",
  "gate1-integrated-live-drill-provider-supervisor.js": "supervisor",
  "gate1-integrated-live-drill-provider-worker.js": "worker",
  "gate1-integrated-live-drill-provider-reconciler.js": "reconciler",
  "gate1-recovery-broker.js": "recovery",
  "gate2-authority-race.js": "authority-race",
  "gate2-integrated-live-drill-provider-finalizer.js": "finalizer"
});

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function exactKeys(value, keys) {
  return value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join("\n") === [...keys].sort().join("\n");
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function assertRootOwnedRegular(stat, code) {
  requireCondition(
    stat.isFile() &&
      !stat.isSymbolicLink() &&
      stat.nlink === 1 &&
      stat.uid === 0 &&
      (stat.mode & 0o022) === 0,
    code
  );
}

function readRootOwnedExactFile(filePath, expectedSha256, code) {
  let descriptor;
  try {
    descriptor = fs.openSync(
      filePath,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW
    );
    const before = fs.fstatSync(descriptor);
    assertRootOwnedRegular(before, code);
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor);
    requireCondition(
      before.dev === after.dev &&
        before.ino === after.ino &&
        before.size === after.size &&
        before.mode === after.mode &&
        before.uid === after.uid &&
        sha256(bytes) === expectedSha256,
      code
    );
    return bytes;
  } catch (cause) {
    if (String(cause?.message ?? "") === code) throw cause;
    reject(code, cause);
  } finally {
    if (Number.isSafeInteger(descriptor)) fs.closeSync(descriptor);
  }
}

function assertRootOwnedStagePath(
  stageRoot,
  {
    lstat = fs.lstatSync,
    realpath = fs.realpathSync
  } = {}
) {
  const code = "INTEGRATED_LIVE_DRILL_RUNTIME_STAGE_REJECTED";
  requireCondition(
    typeof stageRoot === "string" &&
      path.isAbsolute(stageRoot) &&
      path.resolve(stageRoot) === stageRoot &&
      stageRoot !== path.parse(stageRoot).root &&
      realpath(stageRoot) === stageRoot,
    code
  );
  let current = stageRoot;
  for (;;) {
    const stat = lstat(current);
    requireCondition(
      stat.isDirectory() &&
        !stat.isSymbolicLink() &&
        stat.uid === 0 &&
        (stat.mode & 0o022) === 0,
      code
    );
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
}

export function validateIntegratedLiveDrillRuntimeManifest(
  value,
  { validateNodeMetadata = validateOfficialNodeRuntimeMetadata } = {}
) {
  const code = "INTEGRATED_LIVE_DRILL_RUNTIME_MANIFEST_REJECTED";
  requireCondition(
    exactKeys(value, [
      "components",
      "launcher",
      "node",
      "packageLockDigest",
      "schemaVersion",
      "sourceCommit",
      "toolchainSha256",
      "treeDigest"
    ]) &&
      value.schemaVersion === INTEGRATED_LIVE_DRILL_RUNTIME_MANIFEST_SCHEMA &&
      HEX_40.test(value.sourceCommit ?? "") &&
      HEX_40.test(value.treeDigest ?? "") &&
      HEX_64.test(value.packageLockDigest ?? "") &&
      HEX_64.test(value.toolchainSha256 ?? "") &&
      exactKeys(value.launcher, ["file", "sha256"]) &&
      value.launcher.file === "verified-node-bundle-launcher.pl" &&
      HEX_64.test(value.launcher.sha256 ?? "") &&
      exactKeys(value.node, [
        "architecture",
        "distribution",
        "file",
        "platform",
        "sha256",
        "version"
      ]) &&
      value.node.file === `node-${value.node.sha256}` &&
      HEX_64.test(value.node.sha256 ?? "") &&
      ["darwin", "linux"].includes(value.node.platform) &&
      ["arm64", "x64"].includes(value.node.architecture) &&
      ["darwin-arm64", "linux-x64"].includes(
        `${value.node.platform}-${value.node.architecture}`
      ) &&
      value.node.distribution === "nodejs.org-release-v22.23.1" &&
      /^v22\.[0-9]+\.[0-9]+$/u.test(value.node.version ?? "") &&
      exactKeys(value.components, COMPONENTS),
    code
  );
  for (const name of COMPONENTS) {
    const component = value.components[name];
    requireCondition(
      exactKeys(component, [
        "bundledPackages",
        "bytes",
        "externalImports",
        "file",
        "sha256"
      ]) &&
        component.file === `${name}-${component.sha256}.mjs` &&
        HEX_64.test(component.sha256 ?? "") &&
        Number.isSafeInteger(component.bytes) &&
        component.bytes > 0 &&
        Array.isArray(component.bundledPackages) &&
        component.bundledPackages.every((entry) =>
          typeof entry === "string" && /^[a-z0-9@/_.-]+$/u.test(entry)
        ) &&
        Array.isArray(component.externalImports) &&
        component.externalImports.length > 0 &&
        component.externalImports.every((entry) =>
          typeof entry === "string" && /^node:[a-z0-9_./-]+$/u.test(entry)
        ),
      code
    );
  }
  try {
    validateNodeMetadata({
      architecture: value.node.architecture,
      distribution: value.node.distribution,
      platform: value.node.platform,
      sha256: value.node.sha256,
      version: value.node.version
    });
  } catch (cause) {
    reject(code, cause);
  }
  return Object.freeze(value);
}

export function assertIntegratedLiveDrillRuntime({
  environment,
  expectedComponent,
  spec
}) {
  const code = "INTEGRATED_LIVE_DRILL_RUNTIME_REJECTED";
  const manifestSha256 = environment?.[
    INTEGRATED_LIVE_DRILL_RUNTIME_MANIFEST_SHA256_ENVIRONMENT
  ];
  const stageRoot = environment?.[
    INTEGRATED_LIVE_DRILL_RUNTIME_STAGE_ROOT_ENVIRONMENT
  ];
  requireCondition(
    HEX_64.test(manifestSha256 ?? "") &&
      manifestSha256 === spec?.runtimeBundleManifestSha256 &&
      typeof stageRoot === "string" &&
      path.isAbsolute(stageRoot) &&
      path.resolve(stageRoot) === stageRoot &&
      COMPONENTS.includes(expectedComponent) &&
      environment?.[INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_ENVIRONMENT] ===
        expectedComponent &&
      HEX_64.test(environment?.[
        INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_SHA256_ENVIRONMENT
      ] ?? "") &&
      typeof process.getuid === "function" &&
      process.getuid() !== 0,
    code
  );
  try {
    assertRootOwnedStagePath(stageRoot);
  } catch (cause) {
    reject(code, cause);
  }
  const manifestPath = path.join(
    stageRoot,
    `runtime-manifest-${manifestSha256}.json`
  );
  const manifestBytes = readRootOwnedExactFile(
    manifestPath,
    manifestSha256,
    "INTEGRATED_LIVE_DRILL_RUNTIME_MANIFEST_REJECTED"
  );
  let manifest;
  try {
    manifest = validateIntegratedLiveDrillRuntimeManifest(JSON.parse(manifestBytes.toString(
      "utf8"
    )));
  } catch (cause) {
    reject("INTEGRATED_LIVE_DRILL_RUNTIME_MANIFEST_REJECTED", cause);
  }
  requireCondition(
    `${JSON.stringify(manifest, null, 2)}\n` === manifestBytes.toString("utf8") &&
      manifest.sourceCommit === spec.sourceCommit &&
      manifest.treeDigest === spec.treeDigest &&
      manifest.packageLockDigest === spec.packageLockDigest &&
      manifest.components[expectedComponent].sha256 === environment[
        INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_SHA256_ENVIRONMENT
      ],
    code
  );
  readRootOwnedExactFile(
    path.join(stageRoot, manifest.launcher.file),
    manifest.launcher.sha256,
    "INTEGRATED_LIVE_DRILL_RUNTIME_LAUNCHER_REJECTED"
  );
  readRootOwnedExactFile(
    path.join(stageRoot, manifest.node.file),
    manifest.node.sha256,
    "INTEGRATED_LIVE_DRILL_RUNTIME_NODE_REJECTED"
  );
  readRootOwnedExactFile(
    path.join(stageRoot, manifest.components[expectedComponent].file),
    manifest.components[expectedComponent].sha256,
    "INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_REJECTED"
  );
  return Object.freeze({ manifest, manifestSha256, stageRoot });
}

export function stagedRuntimeComponentForScript(script) {
  const component = SCRIPT_COMPONENTS[path.basename(script)];
  requireCondition(
    component !== undefined,
    "INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_REJECTED"
  );
  return component;
}

export const __test = Object.freeze({
  COMPONENTS,
  SCRIPT_COMPONENTS,
  assertRootOwnedStagePath,
  validateRuntimeManifest: validateIntegratedLiveDrillRuntimeManifest
});
