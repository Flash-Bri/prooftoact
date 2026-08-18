import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

import { normalizeGitHubActionsCheckout } from "./normalize-actions-checkout.js";
import {
  gitEnvironment,
  gitInvariantArguments,
  trustedGitExecutable
} from "./lib/exact-git-source.js";

const DEFAULT_CONTROL_ROOT = fileURLToPath(new URL("..", import.meta.url));
const RECEIPT_SCHEMA = "prooftoact.release-control-checkout-normalization.v1";
const OFFICIAL_REPOSITORY = "Flash-Bri/prooftoact";
const OFFICIAL_REPOSITORY_ID = "1317716765";
const OFFICIAL_OWNER = "Flash-Bri";
const OFFICIAL_OWNER_ID = "252500266";
const FROZEN_APPLICATION_COMMIT =
  "963937a9873f0199b91897fe88da1b91bc84b5e3";
const HEX_40 = /^[0-9a-f]{40}$/u;
const OFFICIAL_ORIGIN = /^https:\/\/github\.com\/Flash-Bri\/prooftoact(?:\.git)?$/u;
const WORKFLOWS = Object.freeze({
  "ProofToAct Release Candidate": Object.freeze({
    jobs: Object.freeze([
      "prepare-diagnostic",
      "coordinator-reserve",
      "provider-dispatch",
      "coordinator-finalize"
    ]),
    path: ".github/workflows/prooftoact-release-candidate.yml"
  }),
  "ProofToAct Execute Approved Release": Object.freeze({
    jobs: Object.freeze([
      "controller-diagnostic",
      "execute-diagnostic",
      "coordinator-reserve",
      "provider-dispatch",
      "coordinator-finalize"
    ]),
    path: ".github/workflows/prooftoact-execute-approved-release.yml"
  }),
  "ProofToAct Bounded Live Drill": Object.freeze({
    jobs: Object.freeze(["controller-diagnostic"]),
    path: ".github/workflows/prooftoact-bounded-live-drill.yml"
  }),
  "ProofToAct Read Only Release Evidence": Object.freeze({
    jobs: Object.freeze(["controller-diagnostic"]),
    path: ".github/workflows/prooftoact-read-only-release-evidence.yml"
  }),
  "ProofToAct Approved Teardown": Object.freeze({
    jobs: Object.freeze(["controller-diagnostic"]),
    path: ".github/workflows/prooftoact-approved-teardown.yml"
  }),
  "ProofToAct Terminalize Expired Release": Object.freeze({
    jobs: Object.freeze(["terminalizer-diagnostic"]),
    path: ".github/workflows/prooftoact-terminalize-expired-release.yml"
  }),
  "ProofToAct Hosted Dual Root Verification": Object.freeze({
    jobs: Object.freeze(["verify-dual-root"]),
    path: ".github/workflows/prooftoact-hosted-dual-root-verification.yml"
  })
});
const PUBLIC_CODES = Object.freeze([
  "RELEASE_CONTROL_CHECKOUT_ARGUMENT",
  "RELEASE_CONTROL_CHECKOUT_CONTEXT",
  "RELEASE_CONTROL_CHECKOUT_IDENTITY",
  "RELEASE_CONTROL_CHECKOUT_NORMALIZATION",
  "RELEASE_CONTROL_CHECKOUT_ORIGIN",
  "RELEASE_CONTROL_CHECKOUT_WORKSPACE"
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

function gitText(rootDir, args, code) {
  const result = spawnSync(
    trustedGitExecutable(),
    [...gitInvariantArguments(), ...args],
    {
      cwd: rootDir,
      encoding: "utf8",
      env: { ...gitEnvironment(), GIT_OPTIONAL_LOCKS: "0" },
      maxBuffer: 1024 * 1024,
      stdio: ["ignore", "pipe", "ignore"]
    }
  );
  assert(
    !result.error && result.status === 0 && typeof result.stdout === "string",
    code
  );
  return result.stdout.trim();
}

function assertDirectory(candidate, code) {
  let resolved;
  let stat;
  try {
    resolved = path.resolve(candidate);
    stat = fs.lstatSync(resolved);
    assert(fs.realpathSync(resolved) === resolved, code);
  } catch (error) {
    if (errorMessage(error) === code) {
      throw error;
    }
    throw new Error(code);
  }
  assert(
    stat.isDirectory() &&
      !stat.isSymbolicLink() &&
      stat.uid === process.geteuid() &&
      stat.gid === process.getegid() &&
      (stat.mode & 0o700) === 0o700 &&
      (stat.mode & 0o7022) === 0,
    code
  );
  return Object.freeze({ path: resolved, stat });
}

function assertSafeEnvironment(environment) {
  const forbidden = [
    "BASH_ENV",
    "ENV",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_CEILING_DIRECTORIES",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_NOSYSTEM",
    "GIT_DIR",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_WORK_TREE",
    "LD_PRELOAD",
    "NODE_COMPILE_CACHE",
    "NODE_EXTRA_CA_CERTS",
    "NODE_OPTIONS",
    "NODE_PATH",
    "NODE_REPL_EXTERNAL_MODULE",
    "NODE_V8_COVERAGE"
  ];
  assert(
    forbidden.every(
      (name) => environment[name] === undefined || environment[name] === ""
    ) &&
      Object.keys(environment).every(
        (name) =>
          !name.startsWith("DYLD_") &&
          !/^GIT_CONFIG_KEY_[0-9]+$/u.test(name) &&
          !/^GIT_CONFIG_VALUE_[0-9]+$/u.test(name)
      ),
    "RELEASE_CONTROL_CHECKOUT_CONTEXT"
  );
}

function assertOfficialRepository(rootDir, expectedCommit) {
  const head = gitText(
    rootDir,
    ["rev-parse", "HEAD"],
    "RELEASE_CONTROL_CHECKOUT_IDENTITY"
  );
  const top = gitText(
    rootDir,
    ["rev-parse", "--show-toplevel"],
    "RELEASE_CONTROL_CHECKOUT_IDENTITY"
  );
  const origin = gitText(
    rootDir,
    ["config", "--local", "--get", "remote.origin.url"],
    "RELEASE_CONTROL_CHECKOUT_ORIGIN"
  );
  assert(
    head === expectedCommit && top === rootDir && OFFICIAL_ORIGIN.test(origin),
    head === expectedCommit && top === rootDir
      ? "RELEASE_CONTROL_CHECKOUT_ORIGIN"
      : "RELEASE_CONTROL_CHECKOUT_IDENTITY"
  );
  return Object.freeze({ head, origin });
}

function validateReleaseControlContext({
  applicationCommit,
  controlRoot,
  environment,
  platform
}) {
  assert(
    environment &&
      typeof environment === "object" &&
      typeof controlRoot === "string" &&
      controlRoot.length > 0 &&
      HEX_40.test(applicationCommit),
    "RELEASE_CONTROL_CHECKOUT_ARGUMENT"
  );
  const workflow = WORKFLOWS[environment.GITHUB_WORKFLOW];
  const sealedCallerJob = environment.PROOFTOACT_RELEASE_CALLER_JOB;
  const expectedSealedWorkflow = sealedCallerJob === "provider-dispatch"
    ? "prooftoact-sealed-execute.yml"
    : "prooftoact-sealed-coordinator.yml";
  const sealedContext = environment.GITHUB_JOB ===
      "sealed-credential-boundary" &&
    environment.GITHUB_WORKFLOW === "ProofToAct Execute Approved Release" &&
    workflow?.jobs.includes(sealedCallerJob) &&
    environment.PROOFTOACT_RELEASE_SEALED_WORKFLOW ===
      expectedSealedWorkflow &&
    environment.PROOFTOACT_RELEASE_SEALED_AUTHORITY_COMMIT ===
      environment.GITHUB_SHA;
  const executeDirectJob = environment.GITHUB_WORKFLOW !==
      "ProofToAct Execute Approved Release" ||
    ["controller-diagnostic", "execute-diagnostic"]
      .includes(environment.GITHUB_JOB);
  const directContext = workflow?.jobs.includes(environment.GITHUB_JOB) &&
    executeDirectJob &&
    environment.PROOFTOACT_RELEASE_CALLER_JOB === undefined &&
    environment.PROOFTOACT_RELEASE_SEALED_WORKFLOW === undefined &&
    environment.PROOFTOACT_RELEASE_SEALED_AUTHORITY_COMMIT === undefined;
  assertSafeEnvironment(environment);
  assert(
    platform === "linux" &&
      environment.CI === "true" &&
      environment.GITHUB_ACTIONS === "true" &&
      environment.RUNNER_OS === "Linux" &&
      environment.RUNNER_ENVIRONMENT === "github-hosted" &&
      environment.GITHUB_EVENT_NAME === "workflow_dispatch" &&
      environment.GITHUB_REF === "refs/heads/main" &&
      environment.GITHUB_REF_NAME === "main" &&
      environment.GITHUB_REF_TYPE === "branch" &&
      environment.GITHUB_SERVER_URL === "https://github.com" &&
      environment.GITHUB_API_URL === "https://api.github.com" &&
      environment.GITHUB_GRAPHQL_URL === "https://api.github.com/graphql" &&
      environment.GITHUB_REPOSITORY === OFFICIAL_REPOSITORY &&
      environment.GITHUB_REPOSITORY_ID === OFFICIAL_REPOSITORY_ID &&
      environment.GITHUB_REPOSITORY_OWNER === OFFICIAL_OWNER &&
      environment.GITHUB_REPOSITORY_OWNER_ID === OFFICIAL_OWNER_ID &&
      /^[1-9][0-9]{0,19}$/u.test(environment.GITHUB_RUN_ID ?? "") &&
      environment.GITHUB_RUN_ATTEMPT === "1" &&
      workflow &&
      (directContext || sealedContext) &&
      environment.GITHUB_WORKFLOW_REF ===
        `${OFFICIAL_REPOSITORY}/${workflow.path}@refs/heads/main` &&
      HEX_40.test(environment.GITHUB_SHA ?? "") &&
      environment.EXPECTED_OFFICIAL_MAIN_COMMIT === environment.GITHUB_SHA &&
      environment.GITHUB_WORKFLOW_SHA === environment.GITHUB_SHA &&
      typeof environment.GITHUB_WORKSPACE === "string" &&
      environment.GITHUB_WORKSPACE.length > 0,
    "RELEASE_CONTROL_CHECKOUT_CONTEXT"
  );

  const workspace = assertDirectory(
    environment.GITHUB_WORKSPACE,
    "RELEASE_CONTROL_CHECKOUT_WORKSPACE"
  );
  const control = assertDirectory(
    controlRoot,
    "RELEASE_CONTROL_CHECKOUT_WORKSPACE"
  );
  const application = assertDirectory(
    path.join(workspace.path, "frozen-application"),
    "RELEASE_CONTROL_CHECKOUT_WORKSPACE"
  );
  assert(
    control.path === path.join(workspace.path, "control-plane") &&
      path.dirname(control.path) === workspace.path &&
      path.dirname(application.path) === workspace.path &&
      control.path !== application.path &&
      (control.stat.dev !== application.stat.dev ||
        control.stat.ino !== application.stat.ino),
    "RELEASE_CONTROL_CHECKOUT_WORKSPACE"
  );

  const controlIdentity = assertOfficialRepository(
    control.path,
    environment.GITHUB_SHA
  );
  const applicationIdentity = assertOfficialRepository(
    application.path,
    applicationCommit
  );
  return Object.freeze({
    application,
    applicationIdentity,
    control,
    controlIdentity,
    workflow,
    workspace
  });
}

function normalizerEnvironment({ sourceCommit, targetRoot }) {
  return Object.freeze({
    CI: "true",
    EXPECTED_OFFICIAL_MAIN_COMMIT: sourceCommit,
    GITHUB_ACTIONS: "true",
    GITHUB_API_URL: "https://api.github.com",
    GITHUB_EVENT_NAME: "workflow_dispatch",
    GITHUB_GRAPHQL_URL: "https://api.github.com/graphql",
    GITHUB_JOB: "read-only-preflight",
    GITHUB_REF: "refs/heads/main",
    GITHUB_REPOSITORY: OFFICIAL_REPOSITORY,
    GITHUB_REPOSITORY_ID: OFFICIAL_REPOSITORY_ID,
    GITHUB_SERVER_URL: "https://github.com",
    GITHUB_SHA: sourceCommit,
    GITHUB_WORKFLOW: "AWS Read-Only OIDC Preflight",
    GITHUB_WORKFLOW_REF:
      `${OFFICIAL_REPOSITORY}/.github/workflows/` +
      "aws-oidc-read-only-preflight.yml@refs/heads/main",
    GITHUB_WORKSPACE: targetRoot,
    RUNNER_ENVIRONMENT: "github-hosted",
    RUNNER_OS: "Linux"
  });
}

function normalizeReleaseControlCheckouts({
  applicationCommit,
  controlRoot,
  environment,
  normalizer,
  platform
}) {
  assert(
    typeof normalizer === "function",
    "RELEASE_CONTROL_CHECKOUT_ARGUMENT"
  );
  const context = validateReleaseControlContext({
    applicationCommit,
    controlRoot,
    environment,
    platform
  });
  let controlReceipt;
  let applicationReceipt;
  try {
    controlReceipt = normalizer({
      rootDir: context.control.path,
      environment: normalizerEnvironment({
        sourceCommit: environment.GITHUB_SHA,
        targetRoot: context.control.path
      })
    });
    applicationReceipt = normalizer({
      rootDir: context.application.path,
      environment: normalizerEnvironment({
        sourceCommit: applicationCommit,
        targetRoot: context.application.path
      })
    });
  } catch {
    throw new Error("RELEASE_CONTROL_CHECKOUT_NORMALIZATION");
  }
  assert(
    controlReceipt?.sourceCommit === environment.GITHUB_SHA &&
      applicationReceipt?.sourceCommit === applicationCommit,
    "RELEASE_CONTROL_CHECKOUT_NORMALIZATION"
  );
  return Object.freeze({
    schemaVersion: RECEIPT_SCHEMA,
    status: "EXACT_SEPARATE_CHECKOUTS_NORMALIZED",
    workflow: environment.GITHUB_WORKFLOW,
    workflowRef: environment.GITHUB_WORKFLOW_REF,
    control: controlReceipt,
    application: applicationReceipt
  });
}

export function normalizeReleaseControlActionsCheckouts({
  controlRoot = DEFAULT_CONTROL_ROOT,
  environment = process.env
} = {}) {
  return normalizeReleaseControlCheckouts({
    applicationCommit: FROZEN_APPLICATION_COMMIT,
    controlRoot,
    environment,
    normalizer: normalizeGitHubActionsCheckout,
    platform: process.platform
  });
}

export const __test = Object.freeze({
  FROZEN_APPLICATION_COMMIT,
  WORKFLOWS,
  normalizeWithDependencies({
    applicationCommit = FROZEN_APPLICATION_COMMIT,
    controlRoot,
    environment,
    normalizer,
    platform = "linux"
  }) {
    return normalizeReleaseControlCheckouts({
      applicationCommit,
      controlRoot,
      environment,
      normalizer,
      platform
    });
  },
  validate({
    applicationCommit = FROZEN_APPLICATION_COMMIT,
    controlRoot,
    environment,
    platform = "linux"
  }) {
    return validateReleaseControlContext({
      applicationCommit,
      controlRoot,
      environment,
      platform
    });
  }
});

async function main() {
  assert(process.argv.length === 2, "RELEASE_CONTROL_CHECKOUT_ARGUMENT");
  process.stdout.write(
    `${JSON.stringify(normalizeReleaseControlActionsCheckouts(), null, 2)}\n`
  );
}

const startedDirectly =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (startedDirectly) {
  main().catch((error) => {
    const message = errorMessage(error);
    const code = PUBLIC_CODES.includes(message)
      ? message
      : "RELEASE_CONTROL_CHECKOUT_UNKNOWN";
    process.stderr.write(`PROOFTOACT_CONTROL_CHECKOUT_FAILED:${code}\n`);
    process.exitCode = 1;
  });
}
