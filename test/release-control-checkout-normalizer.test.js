import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import test from "node:test";

import { __test } from "../scripts/normalize-release-control-checkouts.js";
import {
  gitEnvironment,
  gitInvariantArguments,
  trustedGitExecutable
} from "../scripts/lib/exact-git-source.js";

const OFFICIAL_REPOSITORY = "Flash-Bri/prooftoact";

function git(rootDir, ...args) {
  return execFileSync(
    trustedGitExecutable(),
    [...gitInvariantArguments(), ...args],
    {
      cwd: rootDir,
      encoding: "utf8",
      env: gitEnvironment(),
      stdio: ["ignore", "pipe", "ignore"]
    }
  ).trim();
}

function initializeRepository(rootDir, marker) {
  fs.mkdirSync(rootDir, { mode: 0o700, recursive: false });
  fs.writeFileSync(path.join(rootDir, "marker.txt"), `${marker}\n`, {
    mode: 0o600
  });
  git(rootDir, "init", "--quiet");
  git(rootDir, "add", "--all");
  git(
    rootDir,
    "-c",
    "user.name=Release Control Fixture",
    "-c",
    "user.email=release-control-fixture@invalid",
    "commit",
    "--quiet",
    "-m",
    marker
  );
  git(rootDir, "remote", "add", "origin", "https://github.com/Flash-Bri/prooftoact.git");
  return git(rootDir, "rev-parse", "HEAD");
}

function fixture() {
  const workspace = fs.mkdtempSync(
    path.join(os.tmpdir(), "prooftoact-release-control-checkouts-")
  );
  fs.chmodSync(workspace, 0o700);
  const controlRoot = path.join(workspace, "control-plane");
  const applicationRoot = path.join(workspace, "frozen-application");
  const controlCommit = initializeRepository(controlRoot, "control");
  const applicationCommit = initializeRepository(applicationRoot, "application");
  return {
    applicationCommit,
    applicationRoot,
    cleanup() {
      fs.rmSync(workspace, { force: true, recursive: true });
    },
    controlCommit,
    controlRoot,
    workspace
  };
}

function actionsEnvironment(
  current,
  workflow = "ProofToAct Release Candidate"
) {
  const contract = __test.WORKFLOWS[workflow];
  assert(contract);
  return {
    CI: "true",
    EXPECTED_OFFICIAL_MAIN_COMMIT: current.controlCommit,
    GITHUB_ACTIONS: "true",
    GITHUB_API_URL: "https://api.github.com",
    GITHUB_EVENT_NAME: "workflow_dispatch",
    GITHUB_GRAPHQL_URL: "https://api.github.com/graphql",
    GITHUB_JOB: contract.jobs[0],
    GITHUB_REF: "refs/heads/main",
    GITHUB_REF_NAME: "main",
    GITHUB_REF_TYPE: "branch",
    GITHUB_REPOSITORY: OFFICIAL_REPOSITORY,
    GITHUB_REPOSITORY_ID: "1317716765",
    GITHUB_REPOSITORY_OWNER: "Flash-Bri",
    GITHUB_REPOSITORY_OWNER_ID: "252500266",
    GITHUB_RUN_ATTEMPT: "1",
    GITHUB_RUN_ID: "1234567890",
    GITHUB_SERVER_URL: "https://github.com",
    GITHUB_SHA: current.controlCommit,
    GITHUB_WORKFLOW: workflow,
    GITHUB_WORKFLOW_REF:
      `${OFFICIAL_REPOSITORY}/${contract.path}@refs/heads/main`,
    GITHUB_WORKFLOW_SHA: current.controlCommit,
    GITHUB_WORKSPACE: current.workspace,
    RUNNER_ENVIRONMENT: "github-hosted",
    RUNNER_OS: "Linux"
  };
}

function sealedExecuteEnvironment(current, callerJob) {
  assert([
    "coordinator-reserve",
    "provider-dispatch",
    "coordinator-finalize"
  ].includes(callerJob));
  return {
    ...actionsEnvironment(current, "ProofToAct Execute Approved Release"),
    GITHUB_JOB: "sealed-credential-boundary",
    PROOFTOACT_RELEASE_CALLER_JOB: callerJob,
    PROOFTOACT_RELEASE_SEALED_AUTHORITY_COMMIT: current.controlCommit,
    PROOFTOACT_RELEASE_SEALED_WORKFLOW: callerJob === "provider-dispatch"
      ? "prooftoact-sealed-execute.yml"
      : "prooftoact-sealed-coordinator.yml"
  };
}

function exactFakeNormalizer(calls) {
  return ({ rootDir, environment }) => {
    assert.equal(environment.GITHUB_WORKSPACE, rootDir);
    assert.equal(environment.GITHUB_EVENT_NAME, "workflow_dispatch");
    assert.equal(environment.GITHUB_WORKFLOW, "AWS Read-Only OIDC Preflight");
    calls.push({ rootDir, sourceCommit: environment.GITHUB_SHA });
    return Object.freeze({
      schemaVersion: "fixture",
      sourceCommit: environment.GITHUB_SHA,
      status: "ALREADY_STRICT",
      treeDigest: "0".repeat(40)
    });
  };
}

test("all seven exact workflow tuples normalize distinct checkouts", () => {
  const current = fixture();
  try {
    for (const workflow of Object.keys(__test.WORKFLOWS)) {
      const calls = [];
      const receipt = __test.normalizeWithDependencies({
        applicationCommit: current.applicationCommit,
        controlRoot: current.controlRoot,
        environment: actionsEnvironment(current, workflow),
        normalizer: exactFakeNormalizer(calls)
      });
      assert.equal(receipt.status, "EXACT_SEPARATE_CHECKOUTS_NORMALIZED");
      assert.equal(receipt.workflow, workflow);
      assert.deepEqual(calls, [
        {
          rootDir: current.controlRoot,
          sourceCommit: current.controlCommit
        },
        {
          rootDir: current.applicationRoot,
          sourceCommit: current.applicationCommit
        }
      ]);
    }
  } finally {
    current.cleanup();
  }
});

test("release candidate admits only the exact phase-separated jobs", () => {
  const current = fixture();
  try {
    for (const job of [
      "prepare-diagnostic",
      "coordinator-reserve",
      "provider-dispatch",
      "coordinator-finalize"
    ]) {
      const environment = {
        ...actionsEnvironment(current, "ProofToAct Release Candidate"),
        GITHUB_JOB: job
      };
      const calls = [];
      const receipt = __test.normalizeWithDependencies({
        applicationCommit: current.applicationCommit,
        controlRoot: current.controlRoot,
        environment,
        normalizer: exactFakeNormalizer(calls)
      });
      assert.equal(receipt.status, "EXACT_SEPARATE_CHECKOUTS_NORMALIZED");
      assert.equal(calls.length, 2);
    }
  } finally {
    current.cleanup();
  }
});

test("sealed execute admits only the exact caller and reusable-workflow tuple", () => {
  const current = fixture();
  try {
    for (const callerJob of [
      "coordinator-reserve",
      "provider-dispatch",
      "coordinator-finalize"
    ]) {
      const calls = [];
      const receipt = __test.normalizeWithDependencies({
        applicationCommit: current.applicationCommit,
        controlRoot: current.controlRoot,
        environment: sealedExecuteEnvironment(current, callerJob),
        normalizer: exactFakeNormalizer(calls)
      });
      assert.equal(receipt.status, "EXACT_SEPARATE_CHECKOUTS_NORMALIZED");
      assert.equal(receipt.workflow, "ProofToAct Execute Approved Release");
      assert.equal(calls.length, 2);
    }

    const base = sealedExecuteEnvironment(current, "provider-dispatch");
    for (const mutation of [
      { PROOFTOACT_RELEASE_CALLER_JOB: "execute-diagnostic" },
      { PROOFTOACT_RELEASE_SEALED_AUTHORITY_COMMIT: "f".repeat(40) },
      { PROOFTOACT_RELEASE_SEALED_WORKFLOW:
        "prooftoact-sealed-coordinator.yml" },
      { GITHUB_JOB: "provider-dispatch" }
    ]) {
      assert.throws(
        () => __test.validate({
          applicationCommit: current.applicationCommit,
          controlRoot: current.controlRoot,
          environment: { ...base, ...mutation }
        }),
        /RELEASE_CONTROL_CHECKOUT_CONTEXT/u
      );
    }
    for (const job of [
      "coordinator-reserve",
      "provider-dispatch",
      "coordinator-finalize"
    ]) {
      assert.throws(
        () => __test.validate({
          applicationCommit: current.applicationCommit,
          controlRoot: current.controlRoot,
          environment: {
            ...actionsEnvironment(
              current,
              "ProofToAct Execute Approved Release"
            ),
            GITHUB_JOB: job
          }
        }),
        /RELEASE_CONTROL_CHECKOUT_CONTEXT/u
      );
    }
  } finally {
    current.cleanup();
  }
});

test("wrong workflow, job, ref, workflow SHA, and repository identity reject", () => {
  const current = fixture();
  try {
    const base = actionsEnvironment(current);
    const mutations = [
      { GITHUB_WORKFLOW: "CI" },
      { GITHUB_JOB: "terminalizer-diagnostic" },
      { GITHUB_REF: "refs/heads/release" },
      { GITHUB_WORKFLOW_SHA: "f".repeat(40) },
      { GITHUB_RUN_ATTEMPT: "2" },
      { GITHUB_RUN_ID: "0" },
      { GITHUB_REPOSITORY_ID: "1" },
      { GITHUB_REPOSITORY_OWNER_ID: "1" },
      {
        GITHUB_WORKFLOW_REF:
          `${OFFICIAL_REPOSITORY}/.github/workflows/ci.yml@refs/heads/main`
      }
    ];
    for (const mutation of mutations) {
      assert.throws(
        () =>
          __test.validate({
            applicationCommit: current.applicationCommit,
            controlRoot: current.controlRoot,
            environment: { ...base, ...mutation }
          }),
        /RELEASE_CONTROL_CHECKOUT_CONTEXT/u
      );
    }
  } finally {
    current.cleanup();
  }
});

test("wrong root, swapped role, alias, and missing sibling reject", () => {
  const current = fixture();
  try {
    const environment = actionsEnvironment(current);
    assert.throws(
      () =>
        __test.validate({
          applicationCommit: current.applicationCommit,
          controlRoot: current.applicationRoot,
          environment
        }),
      /RELEASE_CONTROL_CHECKOUT_(?:IDENTITY|WORKSPACE)/u
    );
    const alias = path.join(current.workspace, "control-alias");
    fs.symlinkSync(current.controlRoot, alias, "dir");
    assert.throws(
      () =>
        __test.validate({
          applicationCommit: current.applicationCommit,
          controlRoot: alias,
          environment
        }),
      /RELEASE_CONTROL_CHECKOUT_WORKSPACE/u
    );
    const wrongWorkspace = fs.mkdtempSync(
      path.join(os.tmpdir(), "prooftoact-wrong-workspace-")
    );
    fs.chmodSync(wrongWorkspace, 0o700);
    try {
      assert.throws(
        () =>
          __test.validate({
            applicationCommit: current.applicationCommit,
            controlRoot: current.controlRoot,
            environment: {
              ...environment,
              GITHUB_WORKSPACE: wrongWorkspace
            }
          }),
        /RELEASE_CONTROL_CHECKOUT_WORKSPACE/u
      );
    } finally {
      fs.rmSync(wrongWorkspace, { force: true, recursive: true });
    }
  } finally {
    current.cleanup();
  }
});

test("commit, origin, loader, and normalizer failure reject closed", () => {
  const current = fixture();
  try {
    const environment = actionsEnvironment(current);
    assert.throws(
      () =>
        __test.validate({
          applicationCommit: "f".repeat(40),
          controlRoot: current.controlRoot,
          environment
        }),
      /RELEASE_CONTROL_CHECKOUT_IDENTITY/u
    );
    git(current.applicationRoot, "remote", "set-url", "origin", "https://example.invalid/copied.git");
    assert.throws(
      () =>
        __test.validate({
          applicationCommit: current.applicationCommit,
          controlRoot: current.controlRoot,
          environment
        }),
      /RELEASE_CONTROL_CHECKOUT_ORIGIN/u
    );
    git(current.applicationRoot, "remote", "set-url", "origin", "https://github.com/Flash-Bri/prooftoact.git");
    assert.throws(
      () =>
        __test.validate({
          applicationCommit: current.applicationCommit,
          controlRoot: current.controlRoot,
          environment: { ...environment, NODE_OPTIONS: "--require=/tmp/hostile" }
        }),
      /RELEASE_CONTROL_CHECKOUT_CONTEXT/u
    );
    assert.throws(
      () =>
        __test.normalizeWithDependencies({
          applicationCommit: current.applicationCommit,
          controlRoot: current.controlRoot,
          environment,
          normalizer() {
            throw new Error("injected normalization failure");
          }
        }),
      /RELEASE_CONTROL_CHECKOUT_NORMALIZATION/u
    );
  } finally {
    current.cleanup();
  }
});
