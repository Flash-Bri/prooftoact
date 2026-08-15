import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { __test as actionsCheckoutTest } from "../scripts/normalize-actions-checkout.js";
import {
  gitEnvironment,
  gitInvariantArguments,
  trustedGitExecutable
} from "../scripts/lib/exact-git-source.js";
import {
  __test,
  verifyReleaseRights
} from "../scripts/verify-release-rights.js";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const FIXTURE_FILES = Object.freeze([
  "CLAIMS.md",
  "README.md",
  "RENAME_MIGRATION_MANIFEST.json",
  "docs/RENAME_MIGRATION.md",
  "docs/VISUAL_RELEASE_SYSTEM.md",
  "docs/media/RIGHTS.md",
  "docs/media/RIGHTS_MANIFEST.json",
  "docs/media/architecture.png",
  "docs/media/architecture.svg",
  "evidence/architecture-asset-rename-2026-08-03.md",
  "evidence/gate1-ambiguity-2026-07-30.md",
  "evidence/gate1-authority-2026-07-30.md",
  "evidence/gate1-recovery-broker-2026-07-30.md",
  "infra/aws/lambda/demo.js",
  "scripts/gate2-public-demo-verify.js",
  "src/cloud/public-demo-verifier.js",
  "src/cloud/public-demo.js",
  "src/server.js",
  "web/app.js",
  "web/index.html",
  "web/styles.css"
]);

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function copyFixture() {
  const rootDir = fs.mkdtempSync(
    path.join(os.tmpdir(), "tideproof-release-rights-")
  );
  fs.chownSync(rootDir, process.geteuid(), process.getegid());
  fs.chmodSync(rootDir, 0o700);
  for (const relativePath of FIXTURE_FILES) {
    const destination = path.join(rootDir, relativePath);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.copyFileSync(path.join(ROOT, relativePath), destination);
  }
  return {
    rootDir,
    trackedFiles: [...FIXTURE_FILES],
    cleanup() {
      fs.rmSync(rootDir, { recursive: true, force: true });
    }
  };
}

function manifestPath(rootDir) {
  return path.join(rootDir, __test.MANIFEST_PATH);
}

function readManifest(rootDir) {
  return JSON.parse(fs.readFileSync(manifestPath(rootDir), "utf8"));
}

function writeManifest(rootDir, manifest) {
  fs.writeFileSync(
    manifestPath(rootDir),
    `${JSON.stringify(manifest, null, 2)}\n`
  );
}

function refreshControl(rootDir, relativePath) {
  const manifest = readManifest(rootDir);
  const control = manifest.controlFiles.find(
    (entry) => entry.path === relativePath
  );
  assert(control, `missing control ${relativePath}`);
  control.sha256 = sha256(
    fs.readFileSync(path.join(rootDir, relativePath))
  );
  writeManifest(rootDir, manifest);
}

function refreshDistributed(rootDir, relativePath) {
  const manifest = readManifest(rootDir);
  const entry = manifest.distributedFiles.find(
    (candidate) => candidate.path === relativePath
  );
  assert(entry, `missing distributed file ${relativePath}`);
  const nextDigest = sha256(
    fs.readFileSync(path.join(rootDir, relativePath))
  );
  const ledgerPath = path.join(rootDir, "docs/media/RIGHTS.md");
  const ledger = fs.readFileSync(ledgerPath, "utf8");
  assert(ledger.includes(entry.sha256));
  fs.writeFileSync(ledgerPath, ledger.replaceAll(entry.sha256, nextDigest));
  entry.sha256 = nextDigest;
  const ledgerControl = manifest.controlFiles.find(
    (control) => control.path === "docs/media/RIGHTS.md"
  );
  ledgerControl.sha256 = sha256(fs.readFileSync(ledgerPath));
  writeManifest(rootDir, manifest);
}

function verifyFixture(fixture) {
  return verifyReleaseRights({
    rootDir: fixture.rootDir,
    trackedFiles: fixture.trackedFiles
  });
}

function git(rootDir, ...args) {
  return execFileSync(
    trustedGitExecutable(),
    [...gitInvariantArguments(), ...args],
    {
      cwd: rootDir,
      encoding: "utf8",
      env: gitEnvironment()
    }
  ).trim();
}

function initializeExactRepository(rootDir) {
  git(rootDir, "init", "--quiet");
  git(rootDir, "add", "--all");
  git(
    rootDir,
    "-c",
    "user.name=Actions Fixture",
    "-c",
    "user.email=actions-fixture@invalid",
    "commit",
    "--quiet",
    "-m",
    "fixture"
  );
  return git(rootDir, "rev-parse", "HEAD");
}

function actionsEnvironment(
  rootDir,
  {
    eventName = "pull_request",
    headRepository = null,
    headSha = null,
    job = "verify",
    sourceCommit
  } = {}
) {
  const resolvedSourceCommit =
    sourceCommit ?? git(rootDir, "rev-parse", "HEAD");
  return {
    CI: "true",
    GITHUB_ACTIONS: "true",
    GITHUB_API_URL: "https://api.github.com",
    GITHUB_EVENT_NAME: eventName,
    GITHUB_GRAPHQL_URL: "https://api.github.com/graphql",
    GITHUB_JOB: job,
    GITHUB_REF:
      eventName === "pull_request"
        ? "refs/pull/61/merge"
        : "refs/heads/main",
    GITHUB_REPOSITORY: "Flash-Bri/prooftoact",
    GITHUB_REPOSITORY_ID: "1317716765",
    GITHUB_SERVER_URL: "https://github.com",
    GITHUB_SHA: resolvedSourceCommit,
    GITHUB_WORKFLOW: "CI",
    GITHUB_WORKFLOW_REF: `Flash-Bri/prooftoact/.github/workflows/ci.yml@${
      eventName === "pull_request"
        ? "refs/pull/61/merge"
        : "refs/heads/main"
    }`,
    GITHUB_WORKSPACE: rootDir,
    RUNNER_ENVIRONMENT: "github-hosted",
    RUNNER_OS: "Linux",
    ...(headRepository === null
      ? {}
      : { EXPECTED_PULL_REQUEST_HEAD_REPOSITORY: headRepository }),
    ...(headSha === null
      ? {}
      : { EXPECTED_PULL_REQUEST_HEAD_SHA: headSha })
  };
}

function readOnlyPreflightActionsEnvironment(
  rootDir,
  { sourceCommit } = {}
) {
  const environment = actionsEnvironment(rootDir, {
    eventName: "push",
    sourceCommit
  });
  return {
    ...environment,
    EXPECTED_OFFICIAL_MAIN_COMMIT: environment.GITHUB_SHA,
    GITHUB_EVENT_NAME: "workflow_dispatch",
    GITHUB_JOB: "read-only-preflight",
    GITHUB_REF: "refs/heads/main",
    GITHUB_WORKFLOW: "AWS Read-Only OIDC Preflight",
    GITHUB_WORKFLOW_REF:
      "Flash-Bri/prooftoact/.github/workflows/" +
      "aws-oidc-read-only-preflight.yml@refs/heads/main"
  };
}

function worktreeConfigPath(rootDir) {
  return path.join(rootDir, ".git", "config.worktree");
}

function writeExactActionsResidue(rootDir) {
  const candidate = worktreeConfigPath(rootDir);
  fs.writeFileSync(
    candidate,
    actionsCheckoutTest.EXPECTED_WORKTREE_CONFIG_BYTES,
    { mode: 0o644 }
  );
  fs.chmodSync(candidate, 0o644);
  return candidate;
}

function candidateIdentity(candidate) {
  const stat = fs.lstatSync(candidate);
  return {
    bytesSha256: stat.isFile()
      ? sha256(fs.readFileSync(candidate))
      : null,
    dev: stat.dev,
    ino: stat.ino,
    linkTarget: stat.isSymbolicLink()
      ? fs.readlinkSync(candidate)
      : null,
    mode: stat.mode,
    nlink: stat.nlink,
    type: stat.isSymbolicLink()
      ? "symlink"
      : stat.isFile()
        ? "file"
        : "other"
  };
}

function normalizeFixture(
  rootDir,
  environment,
  { beforeUnlink = null, platform = "linux" } = {}
) {
  return actionsCheckoutTest.normalizeWithHook({
    rootDir,
    environment,
    platform,
    beforeUnlink
  });
}

test("current rights inventory passes without claiming final release", () => {
  const receipt = verifyReleaseRights({ rootDir: ROOT });

  assert.equal(receipt.status, "CURRENT_SURFACES_PASS");
  assert.equal(receipt.finalReleaseReady, false);
  assert.equal(receipt.distributedFileCount, 5);
  assert.equal(receipt.currentClearedFileCount, 5);
  assert.equal(receipt.interimOnlyFileCount, 0);
  assert.equal(receipt.repositoryMediaFileCount, 2);
  assert.equal(receipt.prohibitedSourceDigestCount, 3);
  assert.equal(receipt.checks.awsDistributionBindingsExact, true);
});

test("Actions PR normalization removes only exact inert residue before strict rights verification", () => {
  const fixture = copyFixture();
  try {
    initializeExactRepository(fixture.rootDir);
    const candidate = writeExactActionsResidue(fixture.rootDir);
    const commonConfig = path.join(fixture.rootDir, ".git", "config");
    const index = path.join(fixture.rootDir, ".git", "index");
    const commonConfigBefore = sha256(fs.readFileSync(commonConfig));
    const indexBefore = sha256(fs.readFileSync(index));
    const statusBefore = git(
      fixture.rootDir,
      "status",
      "--porcelain=v1",
      "--untracked-files=all"
    );

    assert.throws(
      () => verifyReleaseRights({ rootDir: fixture.rootDir }),
      /EXACT_GIT_SOURCE_OBJECT_PATH/
    );
    const receipt = normalizeFixture(
      fixture.rootDir,
      actionsEnvironment(fixture.rootDir)
    );

    assert.equal(receipt.status, "NORMALIZED_INACTIVE_ACTIONS_RESIDUE");
    assert.equal(receipt.eventName, "pull_request");
    assert.equal(receipt.ref, "refs/pull/61/merge");
    assert.equal(receipt.removedPath, ".git/config.worktree");
    assert.equal(fs.existsSync(candidate), false);
    assert.equal(sha256(fs.readFileSync(commonConfig)), commonConfigBefore);
    assert.equal(sha256(fs.readFileSync(index)), indexBefore);
    assert.equal(
      git(
        fixture.rootDir,
        "status",
        "--porcelain=v1",
        "--untracked-files=all"
      ),
      statusBefore
    );
    assert.equal(
      verifyReleaseRights({ rootDir: fixture.rootDir }).status,
      "CURRENT_SURFACES_PASS"
    );
  } finally {
    fixture.cleanup();
  }
});

test("Actions main-push normalization is a strict no-op without residue", () => {
  const fixture = copyFixture();
  try {
    initializeExactRepository(fixture.rootDir);
    const commonConfig = path.join(fixture.rootDir, ".git", "config");
    const index = path.join(fixture.rootDir, ".git", "index");
    const before = {
      commonConfig: sha256(fs.readFileSync(commonConfig)),
      index: sha256(fs.readFileSync(index))
    };
    const receipt = normalizeFixture(
      fixture.rootDir,
      actionsEnvironment(fixture.rootDir, { eventName: "push" })
    );

    assert.equal(receipt.status, "ALREADY_STRICT");
    assert.equal(receipt.eventName, "push");
    assert.equal(receipt.ref, "refs/heads/main");
    assert.equal(receipt.removedPath, null);
    assert.equal(receipt.residueSha256, null);
    assert.equal(fs.existsSync(worktreeConfigPath(fixture.rootDir)), false);
    assert.equal(sha256(fs.readFileSync(commonConfig)), before.commonConfig);
    assert.equal(sha256(fs.readFileSync(index)), before.index);
    assert.equal(
      verifyReleaseRights({ rootDir: fixture.rootDir }).status,
      "CURRENT_SURFACES_PASS"
    );
  } finally {
    fixture.cleanup();
  }
});

test("Actions exact PR-head normalization binds head separately from merge SHA", () => {
  const fixture = copyFixture();
  try {
    initializeExactRepository(fixture.rootDir);
    const headSha = git(fixture.rootDir, "rev-parse", "HEAD");
    const mergeSha = "a".repeat(40);
    const environment = actionsEnvironment(fixture.rootDir, {
      headRepository: "Flash-Bri/prooftoact",
      headSha,
      job: "verify-pr-head-no-secrets",
      sourceCommit: mergeSha
    });
    const receipt = normalizeFixture(fixture.rootDir, environment);

    assert.equal(receipt.status, "ALREADY_STRICT");
    assert.equal(receipt.checkoutMode, "PULL_REQUEST_HEAD");
    assert.equal(receipt.githubEventSha, mergeSha);
    assert.equal(receipt.sourceCommit, headSha);
    assert.equal(receipt.headRepository, "Flash-Bri/prooftoact");
    assert.equal(receipt.normalizedOrigin, null);
    assert.notEqual(receipt.githubEventSha, receipt.sourceCommit);

    assert.throws(
      () => normalizeFixture(fixture.rootDir, {
        ...environment,
        EXPECTED_PULL_REQUEST_HEAD_SHA: mergeSha
      }),
      /ACTIONS_CHECKOUT_NORMALIZATION_SOURCE/u
    );
    assert.throws(
      () => normalizeFixture(fixture.rootDir, {
        ...environment,
        GITHUB_JOB: "verify"
      }),
      /ACTIONS_CHECKOUT_NORMALIZATION_SOURCE/u
    );
  } finally {
    fixture.cleanup();
  }
});

test("Actions fork PR-head normalization validates then removes fork origin", () => {
  const fixture = copyFixture();
  try {
    initializeExactRepository(fixture.rootDir);
    const headSha = git(fixture.rootDir, "rev-parse", "HEAD");
    const forkRepository = "example-contributor/prooftoact-fork";
    git(
      fixture.rootDir,
      "remote",
      "add",
      "origin",
      `https://github.com/${forkRepository}.git`
    );
    const environment = actionsEnvironment(fixture.rootDir, {
      headRepository: forkRepository,
      headSha,
      job: "verify-pr-head-no-secrets",
      sourceCommit: "b".repeat(40)
    });
    const receipt = normalizeFixture(fixture.rootDir, environment);

    assert.equal(receipt.checkoutMode, "PULL_REQUEST_HEAD");
    assert.equal(receipt.sourceCommit, headSha);
    assert.equal(receipt.headRepository, forkRepository);
    assert.equal(
      receipt.normalizedOrigin,
      `https://github.com/${forkRepository}.git`
    );
    assert.equal(git(fixture.rootDir, "remote"), "");

    const hostile = copyFixture();
    try {
      initializeExactRepository(hostile.rootDir);
      git(
        hostile.rootDir,
        "remote",
        "add",
        "origin",
        "https://github.com/attacker/substitution.git"
      );
      const hostileHead = git(hostile.rootDir, "rev-parse", "HEAD");
      assert.throws(
        () => normalizeFixture(
          hostile.rootDir,
          actionsEnvironment(hostile.rootDir, {
            headRepository: forkRepository,
            headSha: hostileHead,
            job: "verify-pr-head-no-secrets",
            sourceCommit: "c".repeat(40)
          })
        ),
        /ACTIONS_CHECKOUT_NORMALIZATION_SOURCE/u
      );
      assert.equal(
        git(hostile.rootDir, "remote", "get-url", "origin"),
        "https://github.com/attacker/substitution.git"
      );
    } finally {
      hostile.cleanup();
    }
  } finally {
    fixture.cleanup();
  }
});

test("protected read-only preflight normalization removes only exact inert residue", () => {
  const fixture = copyFixture();
  try {
    initializeExactRepository(fixture.rootDir);
    const candidate = writeExactActionsResidue(fixture.rootDir);
    const environment = readOnlyPreflightActionsEnvironment(
      fixture.rootDir
    );
    const receipt = normalizeFixture(fixture.rootDir, environment);

    assert.equal(receipt.status, "NORMALIZED_INACTIVE_ACTIONS_RESIDUE");
    assert.equal(receipt.eventName, "workflow_dispatch");
    assert.equal(receipt.ref, "refs/heads/main");
    assert.equal(receipt.sourceCommit, environment.GITHUB_SHA);
    assert.equal(receipt.removedPath, ".git/config.worktree");
    assert.equal(fs.existsSync(candidate), false);
    assert.equal(
      verifyReleaseRights({ rootDir: fixture.rootDir }).status,
      "CURRENT_SURFACES_PASS"
    );
  } finally {
    fixture.cleanup();
  }
});

test("protected read-only preflight normalization rejects context drift", () => {
  const fixture = copyFixture();
  try {
    initializeExactRepository(fixture.rootDir);
    const candidate = writeExactActionsResidue(fixture.rootDir);
    const environment = readOnlyPreflightActionsEnvironment(
      fixture.rootDir
    );
    const contextMutations = [
      { EXPECTED_OFFICIAL_MAIN_COMMIT: "0".repeat(40) },
      { GITHUB_EVENT_NAME: "push" },
      { GITHUB_JOB: "verify" },
      { GITHUB_REF: "refs/heads/feature" },
      { GITHUB_WORKFLOW: "CI" },
      {
        GITHUB_WORKFLOW_REF:
          "Flash-Bri/prooftoact/.github/workflows/ci.yml@refs/heads/main"
      }
    ];

    for (const mutation of contextMutations) {
      const before = candidateIdentity(candidate);
      assert.throws(
        () =>
          normalizeFixture(fixture.rootDir, {
            ...environment,
            ...mutation
          }),
        /ACTIONS_CHECKOUT_NORMALIZATION_CONTEXT/
      );
      assert.deepEqual(candidateIdentity(candidate), before);
    }
  } finally {
    fixture.cleanup();
  }
});

test("Actions normalization rejects hostile residue without changing its path identity", () => {
  const cases = [
    {
      name: "noncanonical order",
      mutate(rootDir, candidate) {
        fs.writeFileSync(
          candidate,
          [
            "[index]",
            "\tsparse = false",
            "[core]",
            "\tsparseCheckout = false",
            "\tsparseCheckoutCone = false",
            ""
          ].join("\n")
        );
      }
    },
    {
      name: "extra include",
      mutate(rootDir, candidate) {
        fs.appendFileSync(candidate, "[include]\n\tpath = /tmp/ignored\n");
      }
    },
    {
      name: "active sparse value",
      mutate(rootDir, candidate) {
        fs.writeFileSync(
          candidate,
          actionsCheckoutTest.EXPECTED_WORKTREE_CONFIG_BYTES
            .toString("utf8")
            .replace("sparse = false", "sparse = true")
        );
      }
    },
    {
      name: "group writable",
      mutate(rootDir, candidate) {
        fs.chmodSync(candidate, 0o664);
      }
    },
    {
      name: "noncanonical non-writable mode",
      mutate(rootDir, candidate) {
        fs.chmodSync(candidate, 0o640);
      }
    },
    {
      name: "executable mode",
      mutate(rootDir, candidate) {
        fs.chmodSync(candidate, 0o755);
      }
    },
    {
      name: "symlink",
      mutate(rootDir, candidate) {
        const target = path.join(rootDir, ".git", "residue-target");
        fs.writeFileSync(
          target,
          actionsCheckoutTest.EXPECTED_WORKTREE_CONFIG_BYTES
        );
        fs.rmSync(candidate);
        fs.symlinkSync(target, candidate);
      }
    },
    {
      name: "hardlink",
      mutate(rootDir, candidate) {
        const target = path.join(rootDir, ".git", "residue-target");
        fs.renameSync(candidate, target);
        fs.linkSync(target, candidate);
      }
    },
    {
      name: "active extension",
      mutate(rootDir) {
        git(
          rootDir,
          "config",
          "--file",
          path.join(rootDir, ".git", "config"),
          "extensions.worktreeConfig",
          "true"
        );
      }
    },
    {
      name: "sparse checkout file",
      mutate(rootDir) {
        fs.writeFileSync(
          path.join(rootDir, ".git", "info", "sparse-checkout"),
          "README.md\n"
        );
      }
    }
  ];

  for (const candidateCase of cases) {
    const fixture = copyFixture();
    try {
      initializeExactRepository(fixture.rootDir);
      const candidate = writeExactActionsResidue(fixture.rootDir);
      candidateCase.mutate(fixture.rootDir, candidate);
      const before = candidateIdentity(candidate);

      assert.throws(
        () =>
          normalizeFixture(
            fixture.rootDir,
            actionsEnvironment(fixture.rootDir)
          ),
        /ACTIONS_CHECKOUT_NORMALIZATION_(?:RESIDUE|SOURCE)/,
        candidateCase.name
      );
      assert.deepEqual(
        candidateIdentity(candidate),
        before,
        candidateCase.name
      );
    } finally {
      fixture.cleanup();
    }
  }
});

test("Actions normalization rejects wrong context and pathname replacement before unlink", () => {
  const fixture = copyFixture();
  try {
    initializeExactRepository(fixture.rootDir);
    const candidate = writeExactActionsResidue(fixture.rootDir);
    const baseEnvironment = actionsEnvironment(fixture.rootDir);
    const contextMutations = [
      { GITHUB_REPOSITORY: "other/repository" },
      { GITHUB_REPOSITORY_ID: "1" },
      { GITHUB_API_URL: "https://example.invalid" },
      { GITHUB_JOB: "other" },
      {
        GITHUB_WORKFLOW_REF:
          "Flash-Bri/prooftoact/.github/workflows/other.yml@refs/pull/61/merge"
      },
      { GITHUB_REF: "refs/pull/0/merge" },
      { GITHUB_SHA: "0".repeat(40) },
      { RUNNER_ENVIRONMENT: "self-hosted" },
      { NODE_OPTIONS: "--require=/tmp/hostile.cjs" },
      { NODE_PATH: "/tmp/hostile-modules" }
    ];

    for (const mutation of contextMutations) {
      const before = candidateIdentity(candidate);
      assert.throws(
        () =>
          normalizeFixture(fixture.rootDir, {
            ...baseEnvironment,
            ...mutation
          }),
        /ACTIONS_CHECKOUT_NORMALIZATION_(?:CONTEXT|SOURCE)/
      );
      assert.deepEqual(candidateIdentity(candidate), before);
    }
    const beforePlatform = candidateIdentity(candidate);
    assert.throws(
      () =>
        normalizeFixture(fixture.rootDir, baseEnvironment, {
          platform: "darwin"
        }),
      /ACTIONS_CHECKOUT_NORMALIZATION_CONTEXT/
    );
    assert.deepEqual(candidateIdentity(candidate), beforePlatform);

    let replacementIdentity;
    assert.throws(
      () =>
        normalizeFixture(fixture.rootDir, baseEnvironment, {
          beforeUnlink(candidatePath) {
            const replacement = `${candidatePath}.replacement`;
            fs.writeFileSync(
              replacement,
              actionsCheckoutTest.EXPECTED_WORKTREE_CONFIG_BYTES,
              { mode: 0o644 }
            );
            fs.chmodSync(replacement, 0o644);
            fs.renameSync(replacement, candidatePath);
            replacementIdentity = candidateIdentity(candidatePath);
          }
        }),
      /ACTIONS_CHECKOUT_NORMALIZATION_RACE/
    );
    assert.deepEqual(candidateIdentity(candidate), replacementIdentity);
  } finally {
    fixture.cleanup();
  }
});

test("Actions normalization preserves residue when pre-unlink checkout state drifts", () => {
  const cases = [
    {
      name: "tracked byte drift",
      expected: /ACTIONS_CHECKOUT_NORMALIZATION_SOURCE/,
      mutate(rootDir) {
        fs.appendFileSync(path.join(rootDir, "README.md"), "\ndrift\n");
      }
    },
    {
      name: "index flag drift",
      expected: /ACTIONS_CHECKOUT_NORMALIZATION_SOURCE/,
      mutate(rootDir) {
        git(rootDir, "update-index", "--skip-worktree", "README.md");
      }
    },
    {
      name: "staged index drift",
      expected: /ACTIONS_CHECKOUT_NORMALIZATION_SOURCE/,
      mutate(rootDir) {
        fs.appendFileSync(path.join(rootDir, "README.md"), "\nstaged\n");
        git(rootDir, "add", "--", "README.md");
      }
    },
    {
      name: "HEAD ref and tree drift",
      expected: /ACTIONS_CHECKOUT_NORMALIZATION_SOURCE/,
      mutate(rootDir) {
        fs.appendFileSync(path.join(rootDir, "README.md"), "\ncommitted\n");
        git(rootDir, "add", "--", "README.md");
        git(
          rootDir,
          "-c",
          "user.name=Actions Fixture",
          "-c",
          "user.email=actions-fixture@invalid",
          "commit",
          "--quiet",
          "-m",
          "drift"
        );
      }
    },
    {
      name: "common config drift",
      expected: /ACTIONS_CHECKOUT_NORMALIZATION_RACE/,
      mutate(rootDir) {
        git(rootDir, "config", "--local", "gc.auto", "0");
      }
    }
  ];

  for (const candidateCase of cases) {
    const fixture = copyFixture();
    try {
      initializeExactRepository(fixture.rootDir);
      const candidate = writeExactActionsResidue(fixture.rootDir);
      const before = candidateIdentity(candidate);

      assert.throws(
        () =>
          normalizeFixture(
            fixture.rootDir,
            actionsEnvironment(fixture.rootDir),
            {
              beforeUnlink() {
                candidateCase.mutate(fixture.rootDir);
              }
            }
          ),
        candidateCase.expected,
        candidateCase.name
      );
      assert.equal(fs.existsSync(candidate), true, candidateCase.name);
      assert.equal(fs.realpathSync(candidate), candidate, candidateCase.name);
      assert.deepEqual(
        candidateIdentity(candidate),
        before,
        candidateCase.name
      );
    } finally {
      fixture.cleanup();
    }
  }
});

test("Actions normalization rejects dirty and hidden index state before unlink", () => {
  const cases = [
    {
      name: "all-untracked status",
      mutate(rootDir) {
        fs.writeFileSync(path.join(rootDir, "unexpected.txt"), "unexpected\n");
      }
    },
    {
      name: "skip-worktree index flag",
      mutate(rootDir) {
        git(rootDir, "update-index", "--skip-worktree", "README.md");
      }
    },
    {
      name: "assume-unchanged index flag",
      mutate(rootDir) {
        git(rootDir, "update-index", "--assume-unchanged", "README.md");
      }
    }
  ];

  for (const candidateCase of cases) {
    const fixture = copyFixture();
    try {
      initializeExactRepository(fixture.rootDir);
      const candidate = writeExactActionsResidue(fixture.rootDir);
      candidateCase.mutate(fixture.rootDir);
      const before = candidateIdentity(candidate);
      assert.throws(
        () =>
          normalizeFixture(
            fixture.rootDir,
            actionsEnvironment(fixture.rootDir)
          ),
        /ACTIONS_CHECKOUT_NORMALIZATION_SOURCE/,
        candidateCase.name
      );
      assert.deepEqual(
        candidateIdentity(candidate),
        before,
        candidateCase.name
      );
    } finally {
      fixture.cleanup();
    }
  }
});

test("CI head, merge, and read-only lanes normalize before strict verification", () => {
  const workflow = fs.readFileSync(
    path.join(ROOT, ".github", "workflows", "ci.yml"),
    "utf8"
  );
  const orderedMarkers = [
    "uses: actions/checkout@",
    "uses: actions/setup-node@",
    "name: Normalize exact GitHub Actions checkout",
    "run: node scripts/normalize-actions-checkout.js",
    "name: Install locked dependencies",
    "name: Verify proof manifest"
  ];
  let prior = -1;
  for (const marker of orderedMarkers) {
    const index = workflow.indexOf(marker);
    assert(index > prior, marker);
    prior = index;
  }
  assert.equal(
    workflow.match(/node scripts\/normalize-actions-checkout\.js/g)?.length,
    2
  );
  for (const marker of [
    "verify-pr-head-no-secrets:",
    "if: github.event_name == 'pull_request'",
    "repository: ${{ github.event.pull_request.head.repo.full_name }}",
    "ref: ${{ github.event.pull_request.head.sha }}",
    "EXPECTED_PULL_REQUEST_HEAD_REPOSITORY: ${{ github.event.pull_request.head.repo.full_name }}",
    "EXPECTED_PULL_REQUEST_HEAD_SHA: ${{ github.event.pull_request.head.sha }}",
    "lfs: false",
    "submodules: false"
  ]) {
    assert(workflow.includes(marker), marker);
  }
  for (const forbidden of [
    "pull_request_target:",
    "id-token: write",
    "contents: write",
    "secrets.",
    "environment:"
  ]) {
    assert.equal(workflow.includes(forbidden), false, forbidden);
  }
  assert.equal(workflow.includes("npm run ci:normalize-actions-checkout"), false);
  for (const marker of [
    'GIT_OPTIONAL_LOCKS: "0"',
    'NODE_COMPILE_CACHE: ""',
    'NODE_EXTRA_CA_CERTS: ""',
    'NODE_OPTIONS: ""',
    'NODE_PATH: ""',
    'NODE_REPL_EXTERNAL_MODULE: ""',
    'NODE_V8_COVERAGE: ""'
  ]) {
    assert(workflow.includes(marker), marker);
  }
  assert.equal(workflow.includes("continue-on-error"), false);

  const readOnlyWorkflow = fs.readFileSync(
    path.join(
      ROOT,
      ".github",
      "workflows",
      "aws-oidc-read-only-preflight.yml"
    ),
    "utf8"
  );
  const readOnlyOrderedMarkers = [
    "uses: actions/checkout@",
    "uses: actions/setup-node@",
    "name: Normalize exact GitHub Actions checkout",
    "run: node scripts/normalize-actions-checkout.js",
    "name: Capture encrypted sanitized read-only preflight receipt"
  ];
  prior = -1;
  for (const marker of readOnlyOrderedMarkers) {
    const index = readOnlyWorkflow.indexOf(marker);
    assert(index > prior, marker);
    prior = index;
  }
  assert.equal(
    readOnlyWorkflow.match(
      /node scripts\/normalize-actions-checkout\.js/g
    )?.length,
    1
  );
  for (const marker of [
    "EXPECTED_OFFICIAL_MAIN_COMMIT: ${{ inputs.official_main_commit }}",
    'GIT_OPTIONAL_LOCKS: "0"',
    'NODE_COMPILE_CACHE: ""',
    'NODE_EXTRA_CA_CERTS: ""',
    'NODE_OPTIONS: ""',
    'NODE_PATH: ""',
    'NODE_REPL_EXTERNAL_MODULE: ""',
    'NODE_V8_COVERAGE: ""'
  ]) {
    assert(readOnlyWorkflow.includes(marker), marker);
  }
  assert.equal(readOnlyWorkflow.includes("continue-on-error"), false);

  const normalizer = fs.readFileSync(
    path.join(ROOT, "scripts", "normalize-actions-checkout.js"),
    "utf8"
  );
  for (const marker of [
    "process.geteuid()",
    "process.getegid()",
    "decisionState = checkoutState(context, permissiveLayout)",
    "sameRepositoryOwnership(ownershipBefore, decisionOwnership)"
  ]) {
    assert(normalizer.includes(marker), marker);
  }

  const productionOptIns = [];
  for (const name of fs.readdirSync(path.join(ROOT, "scripts"), {
    recursive: true
  })) {
    if (!/\.(?:js|mjs|cjs)$/.test(name)) {
      continue;
    }
    const relativePath = path.posix.join(
      "scripts",
      name.split(path.sep).join("/")
    );
    const source = fs.readFileSync(path.join(ROOT, relativePath), "utf8");
    if (/allowInactiveActionsWorktreeConfig\s*:\s*true/.test(source)) {
      productionOptIns.push(relativePath);
    }
  }
  assert.deepEqual(productionOptIns, [
    "scripts/normalize-actions-checkout.js"
  ]);
});

test("Actions normalization CLI rejects arguments with one fixed diagnostic", () => {
  const result = spawnSync(
    process.execPath,
    [path.join(ROOT, "scripts", "normalize-actions-checkout.js"), "extra"],
    { encoding: "utf8" }
  );
  assert.equal(result.status, 1);
  assert.equal(result.stdout, "");
  assert.equal(
    result.stderr,
    "TIDEPROOF_ACTIONS_CHECKOUT_FAILED:ACTIONS_CHECKOUT_NORMALIZATION_ARGUMENT\n"
  );
});

test("rights inventory rejects one-byte drift across browser source and media", () => {
  for (const relativePath of [
    "web/app.js",
    "web/index.html",
    "web/styles.css"
  ]) {
    const fixture = copyFixture();
    try {
      fs.appendFileSync(path.join(fixture.rootDir, relativePath), "\n");
      assert.throws(
        () => verifyFixture(fixture),
        /RELEASE_RIGHTS_DISTRIBUTED_DIGEST/
      );
    } finally {
      fixture.cleanup();
    }
  }
});

test("rights inventory rejects extensionless and uncommon media signatures", () => {
  const candidates = [
    {
      relativePath: "notes/preview.bin",
      bytes: Buffer.from([137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 0])
    },
    {
      relativePath: "notes/preview.heic",
      bytes: Buffer.from([0, 0, 0, 24, 102, 116, 121, 112, 104, 101, 105, 99])
    }
  ];
  for (const { relativePath, bytes } of candidates) {
    const fixture = copyFixture();
    try {
      const destination = path.join(fixture.rootDir, relativePath);
      fs.mkdirSync(path.dirname(destination), { recursive: true });
      fs.writeFileSync(destination, bytes);
      fixture.trackedFiles.push(relativePath);
      assert.throws(
        () => verifyFixture(fixture),
        /RELEASE_RIGHTS_MEDIA_INVENTORY/
      );
    } finally {
      fixture.cleanup();
    }
  }
});

test("rights inventory rejects a tracked blocked planned-asset path", () => {
  const fixture = copyFixture();
  try {
    const relativePath = "web/brand/reference.txt";
    const destination = path.join(fixture.rootDir, relativePath);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.writeFileSync(destination, "reference only\n");
    fixture.trackedFiles.push(relativePath);
    assert.throws(
      () => verifyFixture(fixture),
      /RELEASE_RIGHTS_BLOCKED_PATH/
    );
  } finally {
    fixture.cleanup();
  }
});

test("rights inventory rejects cross-row ledger substitution", () => {
  const fixture = copyFixture();
  try {
    const manifest = readManifest(fixture.rootDir);
    const cssDigest = manifest.distributedFiles.find(
      (entry) => entry.path === "web/styles.css"
    ).sha256;
    const htmlDigest = manifest.distributedFiles.find(
      (entry) => entry.path === "web/index.html"
    ).sha256;
    const ledgerPath = path.join(fixture.rootDir, "docs/media/RIGHTS.md");
    const lines = fs.readFileSync(ledgerPath, "utf8").split("\n");
    const changed = lines.map((line) => {
      if (line.startsWith("| `C03` |")) {
        return line.replace(cssDigest, htmlDigest);
      }
      if (line.startsWith("| `C04` |")) {
        return `${line} \`${cssDigest}\``;
      }
      return line;
    });
    fs.writeFileSync(ledgerPath, changed.join("\n"));
    refreshControl(fixture.rootDir, "docs/media/RIGHTS.md");
    assert.throws(
      () => verifyFixture(fixture),
      /RELEASE_RIGHTS_LEDGER_BINDING/
    );
  } finally {
    fixture.cleanup();
  }
});

test("rights inventory rejects remote CSS resources and font drift", () => {
  const mutations = [
    '@import url("https://example.test/theme.css");\n',
    '.unsafe { background-image: url("/extra.png"); }\n',
    '@font-face { font-family: "Remote"; }\n',
    '.unsafe { font: 700 1rem "Comic Sans MS", cursive; }\n'
  ];
  for (const mutation of mutations) {
    const fixture = copyFixture();
    try {
      fs.appendFileSync(
        path.join(fixture.rootDir, "web/styles.css"),
        mutation
      );
      refreshDistributed(fixture.rootDir, "web/styles.css");
      assert.throws(
        () => verifyFixture(fixture),
        /RELEASE_RIGHTS_STYLESHEET_(?:RESOURCE|SHORTHAND)/
      );
    } finally {
      fixture.cleanup();
    }
  }
});

test("rights inventory rejects data media and unsafe navigation schemes", () => {
  const replacements = [
    [
      "</main>",
      '<img src="data:image/png;base64,AA==" alt="unsafe">\n</main>',
      /RELEASE_RIGHTS_BROWSER_ASSETS/
    ],
    [
      "https://github.com/Flash-Bri/prooftoact",
      "//trustagentic.ai",
      /RELEASE_RIGHTS_BROWSER_NAVIGATION/
    ],
    [
      "https://github.com/Flash-Bri/prooftoact",
      "javascript:alert(1)",
      /RELEASE_RIGHTS_BROWSER_NAVIGATION/
    ],
    [
      "https://github.com/Flash-Bri/prooftoact",
      "&#104;ttps://trustagentic.ai",
      /RELEASE_RIGHTS_BROWSER_NAVIGATION/
    ]
  ];
  for (const [before, after, expected] of replacements) {
    const fixture = copyFixture();
    try {
      const htmlPath = path.join(fixture.rootDir, "web/index.html");
      const source = fs.readFileSync(htmlPath, "utf8");
      assert(source.includes(before));
      fs.writeFileSync(htmlPath, source.replace(before, after));
      refreshDistributed(fixture.rootDir, "web/index.html");
      assert.throws(() => verifyFixture(fixture), expected);
    } finally {
      fixture.cleanup();
    }
  }
});

test("rights inventory rejects browser metadata and dynamic media creation", () => {
  const fixture = copyFixture();
  try {
    const htmlPath = path.join(fixture.rootDir, "web/index.html");
    fs.appendFileSync(
      htmlPath,
      '<meta property="og:image" content="https://example.test/preview.png">\n'
    );
    refreshDistributed(fixture.rootDir, "web/index.html");
    assert.throws(
      () => verifyFixture(fixture),
      /RELEASE_RIGHTS_BROWSER_EMBED/
    );
  } finally {
    fixture.cleanup();
  }

  const scriptFixture = copyFixture();
  try {
    fs.appendFileSync(
      path.join(scriptFixture.rootDir, "web/app.js"),
      '\nconst unsafeImage = new Image(); unsafeImage.src = "/extra.png";\n'
    );
    refreshDistributed(scriptFixture.rootDir, "web/app.js");
    assert.throws(
      () => verifyFixture(scriptFixture),
      /RELEASE_RIGHTS_BROWSER_SCRIPT/
    );
  } finally {
    scriptFixture.cleanup();
  }
});

test("rights inventory rejects reference-style and inline README media", () => {
  const additions = [
    "\n![Unreviewed][preview]\n\n[preview]: https://example.test/preview.png\n",
    "\n<svg><text>Unreviewed</text></svg>\n"
  ];
  for (const addition of additions) {
    const fixture = copyFixture();
    try {
      fs.appendFileSync(path.join(fixture.rootDir, "README.md"), addition);
      refreshControl(fixture.rootDir, "README.md");
      assert.throws(
        () => verifyFixture(fixture),
        /RELEASE_RIGHTS_README_MEDIA/
      );
    } finally {
      fixture.cleanup();
    }
  }
});

test("rights inventory rejects local-server and AWS-only route drift", () => {
  const serverFixture = copyFixture();
  try {
    const serverPath = path.join(serverFixture.rootDir, "src/server.js");
    const source = fs.readFileSync(serverPath, "utf8");
    fs.writeFileSync(
      serverPath,
      source.replace(
        "const assets = new Map([",
        'const assets = new Map([\n  ["/extra", ["../README.md", "text/plain"]],'
      )
    );
    refreshControl(serverFixture.rootDir, "src/server.js");
    assert.throws(
      () => verifyFixture(serverFixture),
      /RELEASE_RIGHTS_SERVER_BINDING/
    );
  } finally {
    serverFixture.cleanup();
  }

  const awsFixture = copyFixture();
  try {
    const entryPath = path.join(
      awsFixture.rootDir,
      "infra/aws/lambda/demo.js"
    );
    let source = fs.readFileSync(entryPath, "utf8");
    source = `import extraRaw from "../../../README.md?raw";\n${source}`;
    source = source.replace(
      "assets: {",
      'assets: {\n    "/extra": extraRaw,'
    );
    fs.writeFileSync(entryPath, source);
    refreshControl(awsFixture.rootDir, "infra/aws/lambda/demo.js");
    assert.throws(
      () => verifyFixture(awsFixture),
      /RELEASE_RIGHTS_AWS_ENTRY/
    );
  } finally {
    awsFixture.cleanup();
  }
});

test("rights inventory rejects re-enabling data images in the AWS CSP", () => {
  const fixture = copyFixture();
  try {
    const runtimePath = path.join(
      fixture.rootDir,
      "src/cloud/public-demo.js"
    );
    const source = fs.readFileSync(runtimePath, "utf8");
    fs.writeFileSync(
      runtimePath,
      source.replace("img-src 'self'", "img-src 'self' data:")
    );
    refreshControl(fixture.rootDir, "src/cloud/public-demo.js");
    assert.throws(
      () => verifyFixture(fixture),
      /RELEASE_RIGHTS_AWS_RUNTIME_CSP/
    );
  } finally {
    fixture.cleanup();
  }
});

test("rights inventory rejects a reintroduced favicon or altered protected hashes", () => {
  const fixture = copyFixture();
  try {
    const relativePath = "web/favicon.svg";
    fs.writeFileSync(
      path.join(fixture.rootDir, relativePath),
      '<svg xmlns="http://www.w3.org/2000/svg"></svg>\n'
    );
    fixture.trackedFiles.push(relativePath);
    assert.throws(
      () => verifyFixture(fixture),
      /RELEASE_RIGHTS_MEDIA_INVENTORY/
    );
  } finally {
    fixture.cleanup();
  }

  const digestFixture = copyFixture();
  try {
    const manifest = readManifest(digestFixture.rootDir);
    manifest.prohibitedSourceDigests[0].sha256 = "0".repeat(64);
    writeManifest(digestFixture.rootDir, manifest);
    assert.throws(
      () => verifyFixture(digestFixture),
      /RELEASE_RIGHTS_PROHIBITED_BOUNDARY/
    );
  } finally {
    digestFixture.cleanup();
  }
});
