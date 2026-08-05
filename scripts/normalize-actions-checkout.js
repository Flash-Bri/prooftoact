import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  assertCleanExactGitCheckout,
  assertExactGitRepositoryLayout,
  gitEnvironment,
  gitInvariantArguments,
  trustedGitExecutable
} from "./lib/exact-git-source.js";

const DEFAULT_ROOT = fileURLToPath(new URL("..", import.meta.url));
const RECEIPT_SCHEMA = "tideproof.actions-checkout-normalization.v1";
const OFFICIAL_REPOSITORY = "Flash-Bri/prooftoact";
const OFFICIAL_REPOSITORY_ID = "1317716765";
const EXPECTED_WORKTREE_CONFIG_BYTES = Buffer.from(
  [
    "[core]",
    "\tsparseCheckout = false",
    "\tsparseCheckoutCone = false",
    "[index]",
    "\tsparse = false",
    ""
  ].join("\n"),
  "utf8"
);
const HEX_40 = /^[0-9a-f]{40}$/;
const PULL_REQUEST_REF = /^refs\/pull\/[1-9][0-9]*\/merge$/;
const PUBLIC_DIAGNOSTIC_CODES = Object.freeze([
  "ACTIONS_CHECKOUT_NORMALIZATION_ARGUMENT",
  "ACTIONS_CHECKOUT_NORMALIZATION_CONTEXT",
  "ACTIONS_CHECKOUT_NORMALIZATION_POSTCONDITION",
  "ACTIONS_CHECKOUT_NORMALIZATION_RACE",
  "ACTIONS_CHECKOUT_NORMALIZATION_RESIDUE",
  "ACTIONS_CHECKOUT_NORMALIZATION_SOURCE",
  "ACTIONS_CHECKOUT_NORMALIZATION_UNLINK",
  "ACTIONS_CHECKOUT_NORMALIZATION_WORKSPACE"
]);

function assert(condition, code) {
  if (!condition) {
    throw new Error(code);
  }
}

function errorMessage(error) {
  try {
    return typeof error?.message === "string" ? error.message : "";
  } catch {
    return "";
  }
}

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function actionsGitEnvironment() {
  return {
    ...gitEnvironment(),
    GIT_OPTIONAL_LOCKS: "0"
  };
}

function gitValue(rootDir, args, code) {
  const result = spawnSync(
    trustedGitExecutable(),
    [...gitInvariantArguments(), ...args],
    {
      cwd: rootDir,
      encoding: "utf8",
      env: actionsGitEnvironment(),
      maxBuffer: 1024 * 1024,
      stdio: ["ignore", "pipe", "ignore"]
    }
  );
  assert(
    !result.error &&
      result.status === 0 &&
      typeof result.stdout === "string",
    code
  );
  return result.stdout.trim();
}

function resolveActionsContext({ rootDir, environment, platform }) {
  const expectedWorkflowRef = `${OFFICIAL_REPOSITORY}/.github/workflows/ci.yml@${environment?.GITHUB_REF ?? ""}`;
  assert(
    environment &&
      typeof environment === "object" &&
      platform === "linux" &&
      environment.GITHUB_ACTIONS === "true" &&
      environment.CI === "true" &&
      environment.RUNNER_OS === "Linux" &&
      environment.RUNNER_ENVIRONMENT === "github-hosted" &&
      environment.GITHUB_SERVER_URL === "https://github.com" &&
      environment.GITHUB_API_URL === "https://api.github.com" &&
      environment.GITHUB_GRAPHQL_URL === "https://api.github.com/graphql" &&
      environment.GITHUB_REPOSITORY === OFFICIAL_REPOSITORY &&
      environment.GITHUB_REPOSITORY_ID === OFFICIAL_REPOSITORY_ID &&
      environment.GITHUB_WORKFLOW === "CI" &&
      environment.GITHUB_WORKFLOW_REF === expectedWorkflowRef &&
      environment.GITHUB_JOB === "verify" &&
      [
        "NODE_COMPILE_CACHE",
        "NODE_EXTRA_CA_CERTS",
        "NODE_OPTIONS",
        "NODE_PATH",
        "NODE_REPL_EXTERNAL_MODULE",
        "NODE_V8_COVERAGE"
      ].every(
        (name) =>
          environment[name] === undefined || environment[name] === ""
      ) &&
      HEX_40.test(environment.GITHUB_SHA ?? "") &&
      typeof environment.GITHUB_WORKSPACE === "string" &&
      environment.GITHUB_WORKSPACE.length > 0,
    "ACTIONS_CHECKOUT_NORMALIZATION_CONTEXT"
  );
  assert(
    (environment.GITHUB_EVENT_NAME === "pull_request" &&
      PULL_REQUEST_REF.test(environment.GITHUB_REF ?? "")) ||
      (environment.GITHUB_EVENT_NAME === "push" &&
        environment.GITHUB_REF === "refs/heads/main"),
    "ACTIONS_CHECKOUT_NORMALIZATION_CONTEXT"
  );

  let resolvedRoot;
  let workspaceRealpath;
  let rootStat;
  try {
    resolvedRoot = path.resolve(rootDir);
    workspaceRealpath = fs.realpathSync(environment.GITHUB_WORKSPACE);
    rootStat = fs.lstatSync(resolvedRoot);
  } catch {
    throw new Error("ACTIONS_CHECKOUT_NORMALIZATION_WORKSPACE");
  }
  assert(
    path.resolve(environment.GITHUB_WORKSPACE) === resolvedRoot &&
      workspaceRealpath === resolvedRoot &&
      fs.realpathSync(resolvedRoot) === resolvedRoot &&
      rootStat.isDirectory() &&
      !rootStat.isSymbolicLink() &&
      (rootStat.mode & 0o700) === 0o700 &&
      (rootStat.mode & 0o7022) === 0,
    "ACTIONS_CHECKOUT_NORMALIZATION_WORKSPACE"
  );
  return Object.freeze({
    expectedSourceCommit: environment.GITHUB_SHA,
    eventName: environment.GITHUB_EVENT_NAME,
    ref: environment.GITHUB_REF,
    rootDir: resolvedRoot
  });
}

function assertRepositoryOwnership({ context, layout }) {
  let rootStat;
  let gitDirStat;
  let effectiveUserId;
  let effectiveGroupId;
  try {
    rootStat = fs.lstatSync(context.rootDir);
    gitDirStat = fs.lstatSync(layout.gitDir);
    effectiveUserId = process.geteuid();
    effectiveGroupId = process.getegid();
  } catch {
    throw new Error("ACTIONS_CHECKOUT_NORMALIZATION_WORKSPACE");
  }
  assert(
    Number.isSafeInteger(effectiveUserId) &&
      effectiveUserId >= 0 &&
      Number.isSafeInteger(effectiveGroupId) &&
      effectiveGroupId >= 0 &&
    rootStat.isDirectory() &&
      !rootStat.isSymbolicLink() &&
      gitDirStat.isDirectory() &&
      !gitDirStat.isSymbolicLink() &&
      rootStat.uid === effectiveUserId &&
      gitDirStat.uid === effectiveUserId &&
      rootStat.gid === effectiveGroupId &&
      gitDirStat.gid === effectiveGroupId &&
      rootStat.uid === gitDirStat.uid &&
      rootStat.gid === gitDirStat.gid &&
      (rootStat.mode & 0o700) === 0o700 &&
      (gitDirStat.mode & 0o700) === 0o700 &&
      (rootStat.mode & 0o7022) === 0 &&
      (gitDirStat.mode & 0o7022) === 0,
    "ACTIONS_CHECKOUT_NORMALIZATION_WORKSPACE"
  );
  return Object.freeze({ gitDirStat, rootStat });
}

function sameRepositoryOwnership(left, right) {
  return ["dev", "ino", "uid", "gid", "mode", "nlink"].every(
    (field) =>
      left.rootStat[field] === right.rootStat[field] &&
      left.gitDirStat[field] === right.gitDirStat[field]
  );
}

function checkoutIdentity(context) {
  const sourceCommit = gitValue(
    context.rootDir,
    ["rev-parse", "HEAD"],
    "ACTIONS_CHECKOUT_NORMALIZATION_SOURCE"
  );
  const treeDigest = gitValue(
    context.rootDir,
    ["rev-parse", "HEAD^{tree}"],
    "ACTIONS_CHECKOUT_NORMALIZATION_SOURCE"
  );
  assert(
    sourceCommit === context.expectedSourceCommit &&
      HEX_40.test(sourceCommit) &&
      HEX_40.test(treeDigest),
    "ACTIONS_CHECKOUT_NORMALIZATION_SOURCE"
  );
  return Object.freeze({ sourceCommit, treeDigest });
}

function gitOutput(rootDir, args, code) {
  const result = spawnSync(
    trustedGitExecutable(),
    [...gitInvariantArguments(), ...args],
    {
      cwd: rootDir,
      encoding: "utf8",
      env: actionsGitEnvironment(),
      maxBuffer: 32 * 1024 * 1024,
      stdio: ["ignore", "pipe", "ignore"]
    }
  );
  assert(
    !result.error &&
      result.status === 0 &&
      typeof result.stdout === "string",
    code
  );
  return result.stdout;
}

function checkoutState(context, layout) {
  const commonConfigSha256 = sha256(fs.readFileSync(layout.config));
  const indexSha256 = sha256(fs.readFileSync(layout.index));
  const identity = checkoutIdentity(context);
  const status = gitOutput(
    context.rootDir,
    ["status", "--porcelain=v1", "--untracked-files=all"],
    "ACTIONS_CHECKOUT_NORMALIZATION_SOURCE"
  );
  const verboseIndex = gitOutput(
    context.rootDir,
    ["ls-files", "-v", "-z", "--cached"],
    "ACTIONS_CHECKOUT_NORMALIZATION_SOURCE"
  );
  const stagedIndex = gitOutput(
    context.rootDir,
    ["ls-files", "--stage", "-z"],
    "ACTIONS_CHECKOUT_NORMALIZATION_SOURCE"
  );
  const verboseRecords = verboseIndex.split("\0").filter(Boolean);
  const stagedRecords = stagedIndex.split("\0").filter(Boolean);
  assert(
    status === "" &&
      verboseRecords.length > 0 &&
      stagedRecords.length === verboseRecords.length &&
      verboseRecords.every((record) => record.startsWith("H ")) &&
      stagedRecords.every((record) =>
        /^(?:100644|100755|120000) [0-9a-f]{40} 0\t[^\0]+$/.test(
          record
        )
      ),
    "ACTIONS_CHECKOUT_NORMALIZATION_SOURCE"
  );
  return Object.freeze({
    ...identity,
    commonConfigSha256,
    indexSha256,
    stagedIndexSha256: sha256(Buffer.from(stagedIndex, "utf8")),
    status,
    verboseIndexSha256: sha256(Buffer.from(verboseIndex, "utf8"))
  });
}

function assertCleanCheckout(context, layout) {
  const stateBefore = checkoutState(context, layout);
  const checkout = assertCleanExactGitCheckout({
    rootDir: context.rootDir,
    sourceCommit: stateBefore.sourceCommit,
    treeDigest: stateBefore.treeDigest
  });
  const stateAfter = checkoutState(context, layout);
  assert(
    checkout.sourceCommit === stateBefore.sourceCommit &&
      checkout.treeDigest === stateBefore.treeDigest &&
      JSON.stringify(stateAfter) === JSON.stringify(stateBefore),
    "ACTIONS_CHECKOUT_NORMALIZATION_POSTCONDITION"
  );
  return stateAfter;
}

function openResidueSnapshot({ candidate, gitDirStat, keepOpen = false }) {
  let descriptor;
  let returnedOpenDescriptor = false;
  try {
    const noFollow = fs.constants.O_NOFOLLOW;
    assert(
      Number.isInteger(noFollow),
      "ACTIONS_CHECKOUT_NORMALIZATION_RESIDUE"
    );
    descriptor = fs.openSync(
      candidate,
      fs.constants.O_RDONLY | noFollow
    );
    const descriptorStat = fs.fstatSync(descriptor);
    const pathStat = fs.lstatSync(candidate);
    assert(
      descriptorStat.isFile() &&
        !descriptorStat.isSymbolicLink() &&
        pathStat.isFile() &&
        !pathStat.isSymbolicLink() &&
        descriptorStat.dev === pathStat.dev &&
        descriptorStat.ino === pathStat.ino &&
        descriptorStat.uid === gitDirStat.uid &&
        descriptorStat.gid === gitDirStat.gid &&
        descriptorStat.nlink === 1 &&
        descriptorStat.size === EXPECTED_WORKTREE_CONFIG_BYTES.length &&
        [0o600, 0o644].includes(descriptorStat.mode & 0o7777) &&
        fs.realpathSync(candidate) === candidate,
      "ACTIONS_CHECKOUT_NORMALIZATION_RESIDUE"
    );
    const bytes = fs.readFileSync(descriptor);
    assert(
      bytes.length === EXPECTED_WORKTREE_CONFIG_BYTES.length &&
        bytes.equals(EXPECTED_WORKTREE_CONFIG_BYTES),
      "ACTIONS_CHECKOUT_NORMALIZATION_RESIDUE"
    );
    const snapshot = Object.freeze({
      bytes,
      ctimeMs: descriptorStat.ctimeMs,
      dev: descriptorStat.dev,
      gid: descriptorStat.gid,
      ino: descriptorStat.ino,
      mode: descriptorStat.mode,
      mtimeMs: descriptorStat.mtimeMs,
      nlink: descriptorStat.nlink,
      size: descriptorStat.size,
      uid: descriptorStat.uid
    });
    if (keepOpen) {
      returnedOpenDescriptor = true;
      return Object.freeze({ descriptor, snapshot });
    }
    return Object.freeze({ descriptor: null, snapshot });
  } catch (error) {
    if (
      errorMessage(error) ===
      "ACTIONS_CHECKOUT_NORMALIZATION_RESIDUE"
    ) {
      throw error;
    }
    throw new Error("ACTIONS_CHECKOUT_NORMALIZATION_RESIDUE");
  } finally {
    if (descriptor !== undefined && !returnedOpenDescriptor) {
      fs.closeSync(descriptor);
    }
  }
}

function sameSnapshot(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.uid === right.uid &&
    left.gid === right.gid &&
    left.mode === right.mode &&
    left.nlink === right.nlink &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs &&
    left.bytes.equals(right.bytes)
  );
}

function pathAbsent(candidate) {
  try {
    fs.lstatSync(candidate);
    return false;
  } catch (error) {
    return error && typeof error === "object" && error.code === "ENOENT";
  }
}

function normalizeCheckout({
  rootDir,
  environment,
  platform,
  beforeUnlink = null
}) {
  assert(
    beforeUnlink === null || typeof beforeUnlink === "function",
    "ACTIONS_CHECKOUT_NORMALIZATION_ARGUMENT"
  );
  const context = resolveActionsContext({
    rootDir,
    environment,
    platform
  });

  try {
    const strictLayout = assertExactGitRepositoryLayout({
      rootDir: context.rootDir
    });
    assertRepositoryOwnership({ context, layout: strictLayout });
    const state = assertCleanCheckout(context, strictLayout);
    return Object.freeze({
      schemaVersion: RECEIPT_SCHEMA,
      status: "ALREADY_STRICT",
      eventName: context.eventName,
      ref: context.ref,
      sourceCommit: state.sourceCommit,
      treeDigest: state.treeDigest,
      removedPath: null,
      residueSha256: null
    });
  } catch (error) {
    if (errorMessage(error) !== "EXACT_GIT_SOURCE_OBJECT_PATH") {
      throw new Error("ACTIONS_CHECKOUT_NORMALIZATION_SOURCE");
    }
  }

  let permissiveLayout;
  try {
    permissiveLayout = assertExactGitRepositoryLayout({
      rootDir: context.rootDir,
      allowInactiveActionsWorktreeConfig: true
    });
  } catch {
    throw new Error("ACTIONS_CHECKOUT_NORMALIZATION_RESIDUE");
  }
  const ownershipBefore = assertRepositoryOwnership({
    context,
    layout: permissiveLayout
  });
  const candidate = path.join(
    permissiveLayout.gitDir,
    "config.worktree"
  );
  const expectedCandidate = path.join(
    context.rootDir,
    ".git",
    "config.worktree"
  );
  assert(
    candidate === expectedCandidate,
    "ACTIONS_CHECKOUT_NORMALIZATION_RESIDUE"
  );

  const commonConfigBefore = fs.readFileSync(permissiveLayout.config);
  const firstSnapshot = openResidueSnapshot({
    candidate,
    gitDirStat: ownershipBefore.gitDirStat
  }).snapshot;
  const stateBefore = checkoutState(context, permissiveLayout);

  if (beforeUnlink) {
    try {
      beforeUnlink(candidate);
    } catch {
      throw new Error("ACTIONS_CHECKOUT_NORMALIZATION_RACE");
    }
  }

  let unlinkHandle;
  try {
    unlinkHandle = openResidueSnapshot({
      candidate,
      gitDirStat: ownershipBefore.gitDirStat,
      keepOpen: true
    });
  } catch {
    throw new Error("ACTIONS_CHECKOUT_NORMALIZATION_RACE");
  }
  try {
    let decisionState;
    let decisionOwnership;
    let decisionResidue;
    try {
      assert(
        sameSnapshot(firstSnapshot, unlinkHandle.snapshot) &&
          fs.readFileSync(permissiveLayout.config).equals(
            commonConfigBefore
          ),
        "ACTIONS_CHECKOUT_NORMALIZATION_RACE"
      );
      decisionState = checkoutState(context, permissiveLayout);
      decisionOwnership = assertRepositoryOwnership({
        context,
        layout: permissiveLayout
      });
      decisionResidue = openResidueSnapshot({
        candidate,
        gitDirStat: decisionOwnership.gitDirStat
      }).snapshot;
      assert(
        JSON.stringify(decisionState) === JSON.stringify(stateBefore) &&
          sameRepositoryOwnership(ownershipBefore, decisionOwnership) &&
          sameSnapshot(firstSnapshot, decisionResidue) &&
          fs.readFileSync(permissiveLayout.config).equals(
            commonConfigBefore
          ),
        "ACTIONS_CHECKOUT_NORMALIZATION_RACE"
      );
    } catch (error) {
      if (
        errorMessage(error) ===
        "ACTIONS_CHECKOUT_NORMALIZATION_SOURCE"
      ) {
        throw error;
      }
      throw new Error("ACTIONS_CHECKOUT_NORMALIZATION_RACE");
    }
    try {
      fs.unlinkSync(candidate);
    } catch {
      throw new Error("ACTIONS_CHECKOUT_NORMALIZATION_UNLINK");
    }
    assert(
      fs.fstatSync(unlinkHandle.descriptor).nlink === 0,
      "ACTIONS_CHECKOUT_NORMALIZATION_POSTCONDITION"
    );
  } finally {
    fs.closeSync(unlinkHandle.descriptor);
  }
  assert(
    pathAbsent(candidate) &&
      fs.readFileSync(permissiveLayout.config).equals(commonConfigBefore),
    "ACTIONS_CHECKOUT_NORMALIZATION_POSTCONDITION"
  );

  let strictLayout;
  try {
    strictLayout = assertExactGitRepositoryLayout({
      rootDir: context.rootDir
    });
    assertRepositoryOwnership({ context, layout: strictLayout });
  } catch {
    throw new Error("ACTIONS_CHECKOUT_NORMALIZATION_POSTCONDITION");
  }
  const stateAfter = assertCleanCheckout(context, strictLayout);
  assert(
    JSON.stringify(stateAfter) === JSON.stringify(stateBefore) &&
      fs.readFileSync(permissiveLayout.config).equals(commonConfigBefore),
    "ACTIONS_CHECKOUT_NORMALIZATION_POSTCONDITION"
  );

  return Object.freeze({
    schemaVersion: RECEIPT_SCHEMA,
    status: "NORMALIZED_INACTIVE_ACTIONS_RESIDUE",
    eventName: context.eventName,
    ref: context.ref,
    sourceCommit: stateAfter.sourceCommit,
    treeDigest: stateAfter.treeDigest,
    removedPath: ".git/config.worktree",
    residueSha256: sha256(firstSnapshot.bytes)
  });
}

export function normalizeGitHubActionsCheckout({
  rootDir = DEFAULT_ROOT,
  environment = process.env
} = {}) {
  return normalizeCheckout({
    rootDir,
    environment,
    platform: process.platform
  });
}

export const __test = Object.freeze({
  EXPECTED_WORKTREE_CONFIG_BYTES,
  normalizeWithHook({
    rootDir,
    environment,
    platform = "linux",
    beforeUnlink = null
  }) {
    return normalizeCheckout({
      rootDir,
      environment,
      platform,
      beforeUnlink
    });
  }
});

async function main() {
  assert(
    process.argv.length === 2,
    "ACTIONS_CHECKOUT_NORMALIZATION_ARGUMENT"
  );
  process.stdout.write(
    `${JSON.stringify(normalizeGitHubActionsCheckout(), null, 2)}\n`
  );
}

const startedDirectly =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (startedDirectly) {
  main().catch((error) => {
    const message = errorMessage(error);
    const code = PUBLIC_DIAGNOSTIC_CODES.includes(message)
      ? message
      : "ACTIONS_CHECKOUT_NORMALIZATION_UNKNOWN";
    process.stderr.write(`TIDEPROOF_ACTIONS_CHECKOUT_FAILED:${code}\n`);
    process.exitCode = 1;
  });
}
