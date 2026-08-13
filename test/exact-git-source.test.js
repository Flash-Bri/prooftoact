import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import test from "node:test";
import { build } from "esbuild";

import {
  __test as exactGitTest,
  assertExactWorktreeBytes,
  assertExactGitRepositoryLayout,
  assertSafeLocalGitConfiguration,
  assertSafeExactTreePaths,
  assertSafeProjectPath,
  assertCleanExactGitCheckout,
  exactGitSourcePlugin,
  gitInvariantArguments,
  readExactGitBlob,
  trustedGitExecutable,
  trustedTemporaryRoot
} from "../scripts/lib/exact-git-source.js";
import {
  __test as exactBuildTest,
  createStandaloneExactCheckout
} from "../scripts/build-gate2-exact.js";

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function installedNpmCliForTest() {
  const bundledCandidate = path.resolve(
    path.dirname(fs.realpathSync(process.execPath)),
    "../lib/node_modules/npm/bin/npm-cli.js"
  );
  const candidates = [
    bundledCandidate,
    process.env.npm_execpath,
    "/opt/homebrew/lib/node_modules/npm/bin/npm-cli.js",
    "/usr/local/lib/node_modules/npm/bin/npm-cli.js"
  ];
  for (const candidate of candidates) {
    if (
      typeof candidate === "string" &&
      path.isAbsolute(candidate) &&
      fs.existsSync(candidate)
    ) {
      return exactBuildTest.exactNpmCli({
        npm_execpath: candidate,
        npm_node_execpath: process.execPath
      });
    }
  }
  throw new Error("EXACT_GIT_TEST_NPM_CLI");
}

test("exact build validates every staged output before copying", (t) => {
  const stagingRoot = fs.realpathSync(fs.mkdtempSync(
    path.join(os.tmpdir(), "tideproof-staged-output-")
  ));
  t.after(() => fs.rmSync(stagingRoot, { recursive: true, force: true }));
  const expectedPaths = Array.from(
    { length: 21 },
    (_, index) => `dist/output-${String(index + 1).padStart(2, "0")}.bin`
  );
  const outputs = expectedPaths.map((relativePath, index) => {
    const bytes = Buffer.from(`output-${index + 1}`, "utf8");
    const outputPath = path.join(stagingRoot, relativePath);
    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
    fs.writeFileSync(outputPath, bytes, { flag: "wx" });
    return {
      bytes: bytes.length,
      path: relativePath,
      sha256: sha256(bytes)
    };
  });
  const privacy = {
    schemaVersion: "tideproof.gate2-build-output-privacy.v1",
    status: "PASS",
    allowedUpstreamAttributionFindingCount: 0,
    findingCount: 0,
    inventorySha256: sha256(JSON.stringify(outputs)),
    outputCount: outputs.length,
    outputs,
    pinnedOfficialToolchainBytes: outputs[0].bytes,
    pinnedOfficialToolchainOutputCount: 1,
    scannedBytes: outputs.slice(1).reduce(
      (total, output) => total + output.bytes,
      0
    )
  };
  assert.equal(
    exactBuildTest.validateStagedOutputInventory(
      stagingRoot,
      expectedPaths,
      privacy
    ).length,
    21
  );
  fs.appendFileSync(path.join(stagingRoot, expectedPaths[0]), "tamper");
  assert.throws(
    () => exactBuildTest.validateStagedOutputInventory(
      stagingRoot,
      expectedPaths,
      privacy
    ),
    /EXACT_BUILD_STAGED_OUTPUT_INVENTORY/u
  );
});

function git(rootDir, ...args) {
  return execFileSync("git", args, {
    cwd: rootDir,
    encoding: "utf8",
    env: {
      ...process.env,
      GIT_AUTHOR_EMAIL: "tideproof@invalid",
      GIT_AUTHOR_NAME: "ProofToAct Test",
      GIT_COMMITTER_EMAIL: "tideproof@invalid",
      GIT_COMMITTER_NAME: "ProofToAct Test"
    },
    stdio: ["ignore", "pipe", "ignore"]
  }).trim();
}

test("Gate Two bundling reads project inputs from immutable Git blobs", async () => {
  const rootDir = fs.mkdtempSync(
    path.join(os.tmpdir(), "tideproof-exact-git-test-")
  );
  try {
    git(rootDir, "init", "--quiet");
    fs.writeFileSync(
      path.join(rootDir, "entry.js"),
      'import message from "./message.txt?raw";\nconsole.log(message);\n'
    );
    fs.writeFileSync(path.join(rootDir, "message.txt"), "committed bytes\n");
    git(rootDir, "add", "entry.js", "message.txt");
    git(rootDir, "commit", "--quiet", "-m", "fixture");
    const sourceCommit = git(rootDir, "rev-parse", "HEAD");
    const treeDigest = git(rootDir, "rev-parse", "HEAD^{tree}");
    assert.deepEqual(
      assertExactWorktreeBytes({ rootDir, sourceCommit }),
      { fileCount: 2, sourceCommit }
    );
    assert.deepEqual(
      assertSafeExactTreePaths({ rootDir, sourceCommit }),
      ["entry.js", "message.txt"]
    );
    assert.deepEqual(
      assertCleanExactGitCheckout({
        rootDir,
        sourceCommit,
        treeDigest
      }),
      { rootDir, sourceCommit, treeDigest }
    );

    fs.writeFileSync(path.join(rootDir, "message.txt"), "dirty bytes\n");
    assert.throws(
      () =>
        assertCleanExactGitCheckout({
          rootDir,
          sourceCommit,
          treeDigest
        }),
      /EXACT_GIT_SOURCE_DIRTY/
    );
    const exactSource = exactGitSourcePlugin({ rootDir, sourceCommit });
    const result = await build({
      absWorkingDir: rootDir,
      entryPoints: ["entry.js"],
      bundle: true,
      format: "cjs",
      logLevel: "silent",
      platform: "node",
      plugins: [exactSource.plugin],
      target: "node22",
      write: false
    });
    const output = result.outputFiles[0].text;
    assert.match(output, /committed bytes/);
    assert.doesNotMatch(output, /dirty bytes/);
    assert.match(output, /tideproof-exact-git-raw:message\.txt/);
    assert.doesNotMatch(output, new RegExp(rootDir.replaceAll("/", "\\/")));
    assert.deepEqual(
      exactSource.inputRecords().map((record) => record.path),
      ["entry.js", "message.txt"]
    );
    for (const record of exactSource.inputRecords()) {
      assert.match(record.gitBlobId, /^[0-9a-f]{40}$/);
      assert.match(record.sha256, /^[0-9a-f]{64}$/);
    }

    fs.writeFileSync(path.join(rootDir, "untracked.js"), "export default 1;\n");
    assert.throws(
      () =>
        readExactGitBlob({
          rootDir,
          sourceCommit,
          filePath: path.join(rootDir, "untracked.js")
        }),
      /EXACT_GIT_SOURCE_TREE/
    );
    assert.throws(
      () =>
        readExactGitBlob({
          rootDir,
          sourceCommit,
          filePath: path.join(rootDir, "..", "outside.js")
        }),
      /EXACT_GIT_SOURCE_PATH/
    );
  } finally {
    fs.rmSync(rootDir, { force: true, recursive: true });
  }
});

test("exact checkout validation rejects hidden index mutations", () => {
  const rootDir = fs.mkdtempSync(
    path.join(os.tmpdir(), "tideproof-exact-git-index-")
  );
  try {
    git(rootDir, "init", "--quiet");
    fs.writeFileSync(path.join(rootDir, "entry.js"), "export default 1;\n");
    git(rootDir, "add", "entry.js");
    git(rootDir, "commit", "--quiet", "-m", "fixture");
    const sourceCommit = git(rootDir, "rev-parse", "HEAD");
    const treeDigest = git(rootDir, "rev-parse", "HEAD^{tree}");
    git(rootDir, "update-index", "--assume-unchanged", "entry.js");
    fs.writeFileSync(path.join(rootDir, "entry.js"), "export default 2;\n");
    assert.equal(git(rootDir, "status", "--porcelain=v1"), "");
    assert.throws(
      () =>
        assertCleanExactGitCheckout({ rootDir, sourceCommit, treeDigest }),
      /EXACT_GIT_SOURCE_INDEX/
    );
  } finally {
    fs.rmSync(rootDir, { force: true, recursive: true });
  }
});

test("exact checkout rejects skip-worktree and hidden untracked files", () => {
  for (const attack of ["skip-worktree", "hidden-untracked"]) {
    const rootDir = fs.mkdtempSync(
      path.join(os.tmpdir(), `tideproof-exact-git-${attack}-`)
    );
    try {
      git(rootDir, "init", "--quiet");
      fs.writeFileSync(path.join(rootDir, "entry.js"), "export default 1;\n");
      git(rootDir, "add", "entry.js");
      git(rootDir, "commit", "--quiet", "-m", "fixture");
      const sourceCommit = git(rootDir, "rev-parse", "HEAD");
      const treeDigest = git(rootDir, "rev-parse", "HEAD^{tree}");
      if (attack === "skip-worktree") {
        git(rootDir, "update-index", "--skip-worktree", "entry.js");
      } else {
        git(rootDir, "config", "status.showUntrackedFiles", "no");
        fs.writeFileSync(path.join(rootDir, "hidden.js"), "untracked\n");
      }
      assert.equal(git(rootDir, "status", "--short"), "");
      assert.throws(
        () =>
          assertCleanExactGitCheckout({
            rootDir,
            sourceCommit,
            treeDigest
          }),
        /EXACT_GIT_SOURCE_(?:DIRTY|INDEX|LOCAL_CONFIG)/
      );
    } finally {
      fs.rmSync(rootDir, { force: true, recursive: true });
    }
  }
});

test("brand-only layout opt-in accepts only inactive Actions worktree residue", () => {
  const fixtureRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "tideproof-actions-worktree-config-")
  );
  const rootDir = path.join(fixtureRoot, "repository");
  try {
    fs.mkdirSync(rootDir);
    git(rootDir, "init", "--quiet");
    fs.writeFileSync(path.join(rootDir, "entry.js"), "export default 1;\n");
    git(rootDir, "add", "entry.js");
    git(rootDir, "commit", "--quiet", "-m", "fixture");

    const gitDir = path.join(rootDir, ".git");
    const commonConfig = path.join(gitDir, "config");
    const worktreeConfig = path.join(gitDir, "config.worktree");
    const sparseCheckout = path.join(gitDir, "info", "sparse-checkout");
    const exactInactiveConfiguration = [
      "[core]",
      "\tsparseCheckout = false",
      "\tsparseCheckoutCone = false",
      "[index]",
      "\tsparse = false",
      ""
    ].join("\n");
    const assertOptInRejects = (source, pattern) => {
      fs.rmSync(worktreeConfig, { force: true });
      fs.writeFileSync(worktreeConfig, source);
      assert.throws(
        () =>
          assertExactGitRepositoryLayout({
            rootDir,
            allowInactiveActionsWorktreeConfig: true
          }),
        pattern
      );
    };

    assert.throws(
      () =>
        assertExactGitRepositoryLayout({
          rootDir,
          allowInactiveActionsWorktreeConfig: "true"
        }),
      /EXACT_GIT_SOURCE_LAYOUT/
    );
    fs.writeFileSync(worktreeConfig, exactInactiveConfiguration);
    assert.throws(
      () => assertExactGitRepositoryLayout({ rootDir }),
      /EXACT_GIT_SOURCE_OBJECT_PATH/
    );
    assert.doesNotThrow(() =>
      assertExactGitRepositoryLayout({
        rootDir,
        allowInactiveActionsWorktreeConfig: true
      })
    );

    for (const source of [
      [
        "[core]",
        "\tsparseCheckoutCone = false",
        "[index]",
        "\tsparse = false",
        ""
      ].join("\n"),
      [
        "[core]",
        "\tsparseCheckout = false",
        "[index]",
        "\tsparse = false",
        ""
      ].join("\n"),
      [
        "[core]",
        "\tsparseCheckout = false",
        "\tsparseCheckoutCone = false",
        ""
      ].join("\n"),
      exactInactiveConfiguration.replace(
        "\tsparseCheckout = false",
        "\tsparseCheckout = false\n\tsparseCheckout = false"
      ),
      exactInactiveConfiguration.replace(
        "\tsparseCheckout = false",
        "\tsparseCheckout = true"
      ),
      exactInactiveConfiguration.replace("\tsparse = false", "\tsparse = 0"),
      `${exactInactiveConfiguration}[gc]\n\tauto = 0\n`,
      `${exactInactiveConfiguration}[include]\n\tpath = /tmp/ignored\n`,
      `${exactInactiveConfiguration}[includeIf "gitdir:/tmp/"]\n\tpath = /tmp/ignored\n`
    ]) {
      assertOptInRejects(source, /EXACT_GIT_SOURCE_WORKTREE_CONFIG/);
    }

    const symlinkTarget = path.join(fixtureRoot, "config.worktree-target");
    fs.rmSync(worktreeConfig, { force: true });
    fs.writeFileSync(symlinkTarget, exactInactiveConfiguration);
    fs.symlinkSync(symlinkTarget, worktreeConfig);
    assert.throws(
      () =>
        assertExactGitRepositoryLayout({
          rootDir,
          allowInactiveActionsWorktreeConfig: true
        }),
      /EXACT_GIT_SOURCE_WORKTREE_CONFIG/
    );
    fs.rmSync(worktreeConfig, { force: true });
    fs.writeFileSync(worktreeConfig, exactInactiveConfiguration);

    git(
      rootDir,
      "config",
      "--file",
      commonConfig,
      "extensions.worktreeConfig",
      "true"
    );
    assert.throws(
      () =>
        assertExactGitRepositoryLayout({
          rootDir,
          allowInactiveActionsWorktreeConfig: true
        }),
      /EXACT_GIT_SOURCE_LOCAL_CONFIG/
    );
    git(
      rootDir,
      "config",
      "--file",
      commonConfig,
      "--unset-all",
      "extensions.worktreeConfig"
    );

    fs.writeFileSync(sparseCheckout, "entry.js\n");
    assert.throws(
      () =>
        assertExactGitRepositoryLayout({
          rootDir,
          allowInactiveActionsWorktreeConfig: true
        }),
      /EXACT_GIT_SOURCE_WORKTREE_CONFIG/
    );
    fs.rmSync(worktreeConfig, { force: true });
    assert.throws(
      () =>
        assertExactGitRepositoryLayout({
          rootDir,
          allowInactiveActionsWorktreeConfig: true
        }),
      /EXACT_GIT_SOURCE_WORKTREE_CONFIG/
    );
    fs.writeFileSync(worktreeConfig, exactInactiveConfiguration);
    fs.rmSync(sparseCheckout, { force: true });
    assert.doesNotThrow(() =>
      assertExactGitRepositoryLayout({
        rootDir,
        allowInactiveActionsWorktreeConfig: true
      })
    );
  } finally {
    fs.rmSync(fixtureRoot, { force: true, recursive: true });
  }
});

test("exact checkout rejects linked worktrees and repository object indirection", () => {
  const fixtureRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "tideproof-exact-git-layout-")
  );
  const rootDir = path.join(fixtureRoot, "repository");
  const linkedRoot = path.join(fixtureRoot, "linked");
  try {
    fs.mkdirSync(rootDir);
    git(rootDir, "init", "--quiet");
    fs.writeFileSync(path.join(rootDir, "entry.js"), "export default 1;\n");
    git(rootDir, "add", "entry.js");
    git(rootDir, "commit", "--quiet", "-m", "fixture one");
    fs.writeFileSync(path.join(rootDir, "entry.js"), "export default 2;\n");
    git(rootDir, "add", "entry.js");
    git(rootDir, "commit", "--quiet", "-m", "fixture two");
    const sourceCommit = git(rootDir, "rev-parse", "HEAD");
    const parentCommit = git(rootDir, "rev-parse", "HEAD^");
    const treeDigest = git(rootDir, "rev-parse", "HEAD^{tree}");
    assert.deepEqual(assertExactGitRepositoryLayout({ rootDir }), {
      rootDir,
      gitDir: path.join(rootDir, ".git"),
      config: path.join(rootDir, ".git", "config"),
      objectDirectory: path.join(rootDir, ".git", "objects"),
      index: path.join(rootDir, ".git", "index")
    });

    git(rootDir, "worktree", "add", "--quiet", "--detach", linkedRoot);
    assert.throws(
      () => assertExactGitRepositoryLayout({ rootDir: linkedRoot }),
      /EXACT_GIT_SOURCE_LAYOUT/
    );

    git(rootDir, "replace", sourceCommit, parentCommit);
    assert.throws(
      () =>
        assertCleanExactGitCheckout({
          rootDir,
          sourceCommit,
          treeDigest
        }),
      /EXACT_GIT_SOURCE_REPLACE/
    );
    git(rootDir, "replace", "-d", sourceCommit);

    const alternates = path.join(
      rootDir,
      ".git",
      "objects",
      "info",
      "alternates"
    );
    fs.writeFileSync(alternates, `${path.join(fixtureRoot, "objects")}\n`);
    assert.throws(
      () =>
        assertCleanExactGitCheckout({
          rootDir,
          sourceCommit,
          treeDigest
        }),
      /EXACT_GIT_SOURCE_(?:OBJECT_PATH|HEAD|LAYOUT)/
    );
  } finally {
    fs.rmSync(fixtureRoot, { force: true, recursive: true });
  }
});

test("exact build Git bundle materialization and import are network-free", () => {
  const fixtureRoot = fs.mkdtempSync(
    path.join(trustedTemporaryRoot(), "tideproof-standalone-build-")
  );
  const sourceRoot = path.join(fixtureRoot, "source");
  try {
    fs.mkdirSync(sourceRoot);
    git(sourceRoot, "init", "--quiet");
    fs.writeFileSync(path.join(sourceRoot, "entry.js"), "export default 1;\n");
    git(sourceRoot, "add", "entry.js");
    git(sourceRoot, "commit", "--quiet", "-m", "fixture one");
    fs.writeFileSync(path.join(sourceRoot, "entry.js"), "export default 2;\n");
    git(sourceRoot, "add", "entry.js");
    git(sourceRoot, "commit", "--quiet", "-m", "fixture two");
    const sourceCommit = git(sourceRoot, "rev-parse", "HEAD");
    const treeDigest = git(sourceRoot, "rev-parse", "HEAD^{tree}");
    const isolatedRoot = fs.mkdtempSync(
      path.join(trustedTemporaryRoot(), "tideproof-standalone-output-")
    );
    try {
      const receipt = createStandaloneExactCheckout({
        sourceRoot,
        temporaryRoot: isolatedRoot,
        sourceCommit,
        treeDigest
      });
      assert.deepEqual(receipt, {
        bundlePath: path.join(isolatedRoot, "source.bundle"),
        checkoutRoot: path.join(isolatedRoot, "checkout")
      });
      assert.equal(fs.lstatSync(receipt.bundlePath).isFile(), true);
      assert.equal(fs.lstatSync(path.join(receipt.checkoutRoot, ".git")).isDirectory(), true);
      assert.equal(git(receipt.checkoutRoot, "rev-parse", "HEAD"), sourceCommit);
      assert.equal(
        git(receipt.checkoutRoot, "rev-parse", "HEAD^{tree}"),
        treeDigest
      );
      assert.equal(
        git(receipt.checkoutRoot, "rev-parse", "--is-shallow-repository"),
        "false"
      );
      assert.equal(
        fs.existsSync(
          path.join(receipt.checkoutRoot, ".git", "objects", "info", "alternates")
        ),
        false
      );
      assert.equal(
        git(receipt.checkoutRoot, "config", "--local", "--name-only", "--list")
          .split("\n")
          .some((name) => /^remote\./.test(name)),
        false
      );
      assert.deepEqual(
        assertCleanExactGitCheckout({
          rootDir: receipt.checkoutRoot,
          sourceCommit,
          treeDigest
        }),
        { rootDir: receipt.checkoutRoot, sourceCommit, treeDigest }
      );
      assert.equal(fs.existsSync(path.join(sourceRoot, ".git", "worktrees")), false);
    } finally {
      fs.rmSync(isolatedRoot, { force: true, recursive: true });
    }

    const sharedRoot = fs.mkdtempSync(
      path.join(trustedTemporaryRoot(), "tideproof-standalone-shared-")
    );
    try {
      fs.chmodSync(sharedRoot, 0o755);
      assert.throws(
        () =>
          createStandaloneExactCheckout({
            sourceRoot,
            temporaryRoot: sharedRoot,
            sourceCommit,
            treeDigest
          }),
        /EXACT_BUILD_STANDALONE_ROOT/
      );
    } finally {
      fs.chmodSync(sharedRoot, 0o700);
      fs.rmSync(sharedRoot, { force: true, recursive: true });
    }
  } finally {
    fs.rmSync(fixtureRoot, { force: true, recursive: true });
  }
});

test("exact source rejects partial-clone state without transport or hydration", () => {
  const fixtureRoot = fs.mkdtempSync(
    path.join(trustedTemporaryRoot(), "tideproof-partial-clone-")
  );
  const sourceRoot = path.join(fixtureRoot, "source");
  const helperMarker = path.join(fixtureRoot, "helper-invoked");
  const uploadPack = path.join(fixtureRoot, "sentinel-upload-pack.sh");
  try {
    fs.mkdirSync(sourceRoot);
    git(sourceRoot, "init", "--quiet");
    fs.writeFileSync(path.join(sourceRoot, "entry.js"), "historical\n");
    git(sourceRoot, "add", "entry.js");
    git(sourceRoot, "commit", "--quiet", "-m", "historical fixture");
    fs.writeFileSync(path.join(sourceRoot, "entry.js"), "current\n");
    git(sourceRoot, "add", "entry.js");
    git(sourceRoot, "commit", "--quiet", "-m", "current fixture");
    const sourceCommit = git(sourceRoot, "rev-parse", "HEAD");
    const treeDigest = git(sourceRoot, "rev-parse", "HEAD^{tree}");
    const historicalBlob = git(
      sourceRoot,
      "rev-parse",
      "HEAD^:entry.js"
    );
    const missingObject = path.join(
      sourceRoot,
      ".git",
      "objects",
      historicalBlob.slice(0, 2),
      historicalBlob.slice(2)
    );
    assert.equal(fs.lstatSync(missingObject).isFile(), true);
    fs.unlinkSync(missingObject);
    fs.writeFileSync(
      uploadPack,
      `#!/bin/sh\n: > ${JSON.stringify(helperMarker)}\nexit 91\n`
    );
    fs.chmodSync(uploadPack, 0o700);
    git(sourceRoot, "config", "extensions.partialClone", "origin");
    git(sourceRoot, "config", "remote.origin.url", `file://${sourceRoot}`);
    git(
      sourceRoot,
      "config",
      "remote.origin.fetch",
      "+refs/heads/*:refs/remotes/origin/*"
    );
    git(sourceRoot, "config", "remote.origin.promisor", "true");
    git(
      sourceRoot,
      "config",
      "remote.origin.partialCloneFilter",
      "blob:none"
    );
    git(sourceRoot, "config", "remote.origin.uploadpack", uploadPack);
    git(sourceRoot, "config", "remote.origin.vcs", "sentinel");
    const promisorMarker = path.join(
      sourceRoot,
      ".git",
      "objects",
      "pack",
      "sentinel.promisor"
    );
    fs.writeFileSync(promisorMarker, "");
    const objectRoot = path.join(sourceRoot, ".git", "objects");
    const objectInventory = () =>
      fs.readdirSync(objectRoot, { recursive: true }).map(String).sort();
    const beforeConfigurationRejection = objectInventory();
    assert.throws(
      () =>
        assertCleanExactGitCheckout({
          rootDir: sourceRoot,
          sourceCommit,
          treeDigest
        }),
      /EXACT_GIT_SOURCE_LOCAL_CONFIG/
    );
    assert.equal(fs.existsSync(helperMarker), false);
    assert.equal(fs.existsSync(missingObject), false);
    assert.deepEqual(objectInventory(), beforeConfigurationRejection);

    for (const name of [
      "extensions.partialClone",
      "remote.origin.url",
      "remote.origin.fetch",
      "remote.origin.promisor",
      "remote.origin.partialCloneFilter",
      "remote.origin.uploadpack",
      "remote.origin.vcs"
    ]) {
      git(sourceRoot, "config", "--unset-all", name);
    }
    const beforePromisorRejection = objectInventory();
    assert.throws(
      () =>
        assertCleanExactGitCheckout({
          rootDir: sourceRoot,
          sourceCommit,
          treeDigest
        }),
      /EXACT_GIT_SOURCE_PROMISOR/
    );
    assert.equal(fs.existsSync(helperMarker), false);
    assert.equal(fs.existsSync(missingObject), false);
    assert.deepEqual(objectInventory(), beforePromisorRejection);

    fs.unlinkSync(promisorMarker);
    const beforeClosureRejection = objectInventory();
    assert.throws(
      () =>
        assertCleanExactGitCheckout({
          rootDir: sourceRoot,
          sourceCommit,
          treeDigest
        }),
      /EXACT_GIT_SOURCE_OBJECT_CLOSURE/
    );
    assert.equal(fs.existsSync(helperMarker), false);
    assert.equal(fs.existsSync(missingObject), false);
    assert.deepEqual(objectInventory(), beforeClosureRejection);
  } finally {
    fs.rmSync(fixtureRoot, { force: true, recursive: true });
  }
});

test("artifact paths reject symlinked parent components", () => {
  const fixtureRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "tideproof-safe-project-path-")
  );
  const repositoryRoot = path.join(fixtureRoot, "repository");
  const outsideRoot = path.join(fixtureRoot, "outside");
  try {
    fs.mkdirSync(repositoryRoot);
    fs.mkdirSync(outsideRoot);
    fs.symlinkSync(outsideRoot, path.join(repositoryRoot, "dist"), "dir");
    assert.throws(
      () =>
        assertSafeProjectPath({
          rootDir: repositoryRoot,
          filePath: path.join(
            repositoryRoot,
            "dist/aws/evidence-provider-fixture.mjs"
          )
        }),
      /EXACT_GIT_PROJECT_PATH/
    );
    assert.doesNotThrow(() =>
      assertSafeProjectPath({
        rootDir: repositoryRoot,
        filePath: path.join(repositoryRoot, "safe/new/file.txt")
      })
    );
  } finally {
    fs.rmSync(fixtureRoot, { force: true, recursive: true });
  }
});

test("exact Git bundling rejects every non-dependency path escape", async () => {
  const fixtureRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "tideproof-exact-git-escape-")
  );
  const repositoryRoot = path.join(fixtureRoot, "repository");
  const outsidePath = path.join(fixtureRoot, "outside.js");
  try {
    fs.mkdirSync(repositoryRoot);
    git(repositoryRoot, "init", "--quiet");
    fs.writeFileSync(outsidePath, "export default 'outside bytes';\n");
    fs.writeFileSync(
      path.join(repositoryRoot, "entry.js"),
      `import value from ${JSON.stringify(outsidePath)};\nconsole.log(value);\n`
    );
    git(repositoryRoot, "add", "entry.js");
    git(repositoryRoot, "commit", "--quiet", "-m", "fixture");
    const sourceCommit = git(repositoryRoot, "rev-parse", "HEAD");
    const exactSource = exactGitSourcePlugin({
      rootDir: repositoryRoot,
      sourceCommit
    });
    await assert.rejects(
      build({
        absWorkingDir: repositoryRoot,
        entryPoints: ["entry.js"],
        bundle: true,
        format: "cjs",
        logLevel: "silent",
        platform: "node",
        plugins: [exactSource.plugin],
        target: "node22",
        write: false
      }),
      /EXACT_GIT_SOURCE_PATH/
    );
    assert.deepEqual(
      exactSource.inputRecords().map((record) => record.path),
      ["entry.js"]
    );
  } finally {
    fs.rmSync(fixtureRoot, { force: true, recursive: true });
  }
});

test("exact build Git processes reject ambient repository redirection", () => {
  const hostile = {
    PATH: process.env.PATH,
    GIT_DIR: "/tmp/attacker.git",
    GIT_WORK_TREE: "/tmp/attacker-worktree",
    GIT_CONFIG_GLOBAL: "/tmp/attacker-config",
    GIT_ALTERNATE_OBJECT_DIRECTORIES: "/tmp/attacker-objects",
    NODE_OPTIONS: "--require=/tmp/attacker.cjs"
  };
  for (const environment of [
    exactGitTest.gitEnvironment(hostile),
    exactBuildTest.isolatedEnvironment(hostile)
  ]) {
    assert.equal(environment.GIT_DIR, undefined);
    assert.equal(environment.GIT_WORK_TREE, undefined);
    assert.equal(environment.GIT_ALTERNATE_OBJECT_DIRECTORIES, undefined);
    assert.equal(environment.NODE_OPTIONS, undefined);
    assert.equal(environment.PATH, "/usr/bin:/bin");
    assert.equal(environment.GIT_ATTR_NOSYSTEM, "1");
    assert.equal(environment.GIT_CONFIG_GLOBAL, "/dev/null");
    assert.equal(environment.GIT_CONFIG_NOSYSTEM, "1");
    assert.equal(environment.GIT_NO_LAZY_FETCH, "1");
    assert.equal(environment.GIT_NO_REPLACE_OBJECTS, "1");
  }
  assert.match(
    trustedGitExecutable(),
    process.platform === "darwin"
      ? /^\/Applications\/Xcode[^/]*\.app\/Contents\/Developer\/usr\/bin\/git$/
      : /^\/usr\/bin\/git$/
  );
  assert.deepEqual(gitInvariantArguments(), [
    "-c",
    "core.attributesFile=/dev/null",
    "-c",
    "core.autocrlf=false",
    "-c",
    "core.eol=lf",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "core.untrackedCache=false"
  ]);
  const ordinaryCore = [
    { name: "core.repositoryformatversion", value: "0" },
    { name: "core.filemode", value: "true" },
    { name: "core.bare", value: "false" },
    { name: "core.logallrefupdates", value: "true" }
  ];
  const ordinaryOfficialClone = [
    ...ordinaryCore,
    { name: "core.ignorecase", value: "true" },
    { name: "core.precomposeunicode", value: "true" },
    {
      name: "remote.origin.url",
      value: "https://github.com/Flash-Bri/prooftoact.git"
    },
    {
      name: "remote.origin.fetch",
      value: "+refs/heads/*:refs/remotes/origin/*"
    },
    { name: "branch.main.remote", value: "origin" },
    { name: "branch.main.merge", value: "refs/heads/main" }
  ];
  assert.deepEqual(
    assertSafeLocalGitConfiguration(ordinaryCore),
    {
      entryCount: 4,
      mainBranchConfigured: false,
      officialOriginConfigured: false,
      remote: null
    }
  );
  for (const remote of [
    "https://github.com/Flash-Bri/prooftoact.git",
    "https://github.com/Flash-Bri/prooftoact"
  ]) {
    const configuration = ordinaryOfficialClone.map((entry) =>
      entry.name === "remote.origin.url"
        ? { ...entry, value: remote }
        : entry
    );
    assert.equal(
      assertSafeLocalGitConfiguration(configuration, {
        requireOfficialOrigin: true,
        requireMainBranch: true
      }).remote,
      remote
    );
  }
  const actionsOfficialCheckout = [
    ...ordinaryCore,
    { name: "core.ignorecase", value: "true" },
    { name: "core.precomposeunicode", value: "true" },
    { name: "gc.auto", value: "0" },
    {
      name: "remote.origin.url",
      value: "https://github.com/Flash-Bri/prooftoact"
    },
    {
      name: "remote.origin.fetch",
      value: "+refs/heads/*:refs/remotes/origin/*"
    }
  ];
  assert.deepEqual(
    assertSafeLocalGitConfiguration(actionsOfficialCheckout, {
      requireOfficialOrigin: true
    }),
    {
      entryCount: 9,
      mainBranchConfigured: false,
      officialOriginConfigured: true,
      remote: "https://github.com/Flash-Bri/prooftoact"
    }
  );
  for (const value of ["1", "false", "00", "-1"]) {
    assert.throws(
      () =>
        assertSafeLocalGitConfiguration(
          actionsOfficialCheckout.map((entry) =>
            entry.name === "gc.auto" ? { ...entry, value } : entry
          ),
          { requireOfficialOrigin: true }
        ),
      /EXACT_GIT_SOURCE_LOCAL_CONFIG/
    );
  }
  assert.throws(
    () =>
      assertSafeLocalGitConfiguration(
        [
          ...actionsOfficialCheckout,
          { name: "gc.auto", value: "0" }
        ],
        { requireOfficialOrigin: true }
      ),
    /EXACT_GIT_SOURCE_LOCAL_CONFIG/
  );
  for (const name of [
    "core.attributesfile",
    "core.autocrlf",
    "core.eol",
    "core.hookspath",
    "core.fsmonitor",
    "core.sparsecheckout",
    "core.sparsecheckoutcone",
    "core.untrackedcache",
    "core.worktree",
    "core.safecrlf",
    "gc.autodetach",
    "extensions.worktreeconfig",
    "filter.inject.clean",
    "include.path",
    "includeif.gitdir:/tmp/.path",
    "extensions.partialclone",
    "remote.origin.partialclonefilter",
    "remote.origin.promisor",
    "remote.origin.uploadpack",
    "remote.origin.vcs",
    "remote.origin.proxy",
    "remote.attacker.url",
    "url.file:///tmp/attacker.insteadof",
    "status.showuntrackedfiles",
    "FILTER.inject.smudge"
  ]) {
    assert.throws(
      () =>
        assertSafeLocalGitConfiguration([
          ...ordinaryCore,
          { name: name.toLowerCase(), value: "attacker" }
        ]),
      /EXACT_GIT_SOURCE_LOCAL_CONFIG/
    );
  }
  for (const [name, value] of [
    ["core.filemode", "false"],
    ["branch.main.merge", "refs/heads/attacker"]
  ]) {
    assert.throws(
      () =>
        assertSafeLocalGitConfiguration(
          ordinaryOfficialClone.map((entry) =>
            entry.name === name ? { name, value } : entry
          ),
          { requireOfficialOrigin: true, requireMainBranch: true }
        ),
      /EXACT_GIT_SOURCE_LOCAL_CONFIG/
    );
  }
  for (const remote of [
    "https://github.com/Flash-Bri/prooftoact/",
    "https://github.com/Flash-Bri/prooftoact.git/",
    "https://github.com/Flash-Bri/prooftoact.git?ref=main",
    "https://github.com/Flash-Bri/prooftoact-fork",
    "https://github.com/flash-bri/prooftoact",
    "http://github.com/Flash-Bri/prooftoact",
    ["https://token", "@github.com/Flash-Bri/prooftoact"].join(""),
    [
      "https://x-access-token:secret",
      "@github.com/Flash-Bri/prooftoact.git"
    ].join(""),
    ["git", "@github.com:Flash-Bri/prooftoact.git"].join(""),
    ["ssh://git", "@github.com/Flash-Bri/prooftoact.git"].join(""),
    "file:///tmp/prooftoact"
  ]) {
    assert.throws(
      () =>
        assertSafeLocalGitConfiguration(
          ordinaryOfficialClone.map((entry) =>
            entry.name === "remote.origin.url"
              ? { ...entry, value: remote }
              : entry
          ),
          { requireOfficialOrigin: true, requireMainBranch: true }
        ),
      /EXACT_GIT_SOURCE_LOCAL_CONFIG/
    );
  }
  assert.throws(
    () =>
      assertSafeLocalGitConfiguration([
        ...ordinaryOfficialClone,
        {
          name: "url.https://attacker.invalid/.insteadof",
          value: "https://github.com/"
        }
      ]),
    /EXACT_GIT_SOURCE_LOCAL_CONFIG/
  );
});

test("exact build rejects committed checkout transforms", () => {
  const rootDir = fs.mkdtempSync(
    path.join(os.tmpdir(), "tideproof-exact-git-attributes-")
  );
  try {
    git(rootDir, "init", "--quiet");
    fs.writeFileSync(path.join(rootDir, ".gitattributes"), "*.js ident\n");
    fs.writeFileSync(path.join(rootDir, "entry.js"), "export default 1;\n");
    git(rootDir, "add", ".gitattributes", "entry.js");
    git(rootDir, "commit", "--quiet", "-m", "fixture");
    assert.throws(
      () =>
        assertSafeExactTreePaths({
          rootDir,
          sourceCommit: git(rootDir, "rev-parse", "HEAD")
        }),
      /EXACT_GIT_SOURCE_TREE_PATHS/
    );
    git(rootDir, "rm", "--quiet", ".gitattributes");
    fs.writeFileSync(path.join(rootDir, ".npmrc"), "script-shell=/tmp/inject\n");
    git(rootDir, "add", ".npmrc");
    git(rootDir, "commit", "--quiet", "-m", "npm config fixture");
    assert.throws(
      () =>
        assertSafeExactTreePaths({
          rootDir,
          sourceCommit: git(rootDir, "rev-parse", "HEAD")
        }),
      /EXACT_GIT_SOURCE_TREE_PATHS/
    );
  } finally {
    fs.rmSync(rootDir, { force: true, recursive: true });
  }
});

test("exact build rejects case-variant checkout transforms", () => {
  for (const filename of [".GitAttributes", ".GITMODULES", ".NPMRC"]) {
    const rootDir = fs.mkdtempSync(
      path.join(os.tmpdir(), "tideproof-exact-git-case-")
    );
    try {
      git(rootDir, "init", "--quiet");
      fs.writeFileSync(path.join(rootDir, filename), "hostile=true\n");
      fs.writeFileSync(path.join(rootDir, "entry.js"), "export default 1;\n");
      git(rootDir, "add", filename, "entry.js");
      git(rootDir, "commit", "--quiet", "-m", "fixture");
      assert.throws(
        () =>
          assertSafeExactTreePaths({
            rootDir,
            sourceCommit: git(rootDir, "rev-parse", "HEAD")
          }),
        /EXACT_GIT_SOURCE_TREE_PATHS/
      );
    } finally {
      fs.rmSync(rootDir, { force: true, recursive: true });
    }
  }
});

test("outer exact build revalidates the detached checkout before accepting output", () => {
  const source = fs.readFileSync(
    path.resolve(import.meta.dirname, "../scripts/build-gate2-exact.js"),
    "utf8"
  );
  const childExecution = source.indexOf(
    'const output = run(\n      process.execPath'
  );
  const standaloneCheckout = source.indexOf(
    "createStandaloneExactCheckout({"
  );
  const postBuildValidation = source.indexOf(
    "const postBuildCheckout = assertCleanExactGitCheckout({"
  );
  const receiptAcceptance = source.indexOf("const receipt = JSON.parse(output)");
  const outputCopy = source.indexOf(
    "copyOutputs(stagingRoot, receipt)",
    receiptAcceptance
  );
  assert.equal(standaloneCheckout >= 0, true);
  assert.equal(childExecution > standaloneCheckout, true);
  assert.doesNotMatch(source, /"worktree",\s*"add"/);
  assert.equal(postBuildValidation > childExecution, true);
  assert.equal(receiptAcceptance > postBuildValidation, true);
  assert.equal(outputCopy > receiptAcceptance, true);
  assert.match(
    source,
    /liveRuntimePaths\.length === GATE2_LIVE_RUNTIME_COMPONENTS\.length \+ 3/u
  );
  assert.doesNotMatch(source, /liveRuntimePaths\.length === \d+/u);
});

test("npm scripts use the invoking Node instead of node_modules bin", () => {
  const rootDir = fs.mkdtempSync(
    path.join(os.tmpdir(), "tideproof-npm-node-bootstrap-")
  );
  try {
    fs.mkdirSync(path.join(rootDir, "node_modules", ".bin"), {
      recursive: true
    });
    fs.writeFileSync(
      path.join(rootDir, "package.json"),
      JSON.stringify({
        private: true,
        scripts: {
          probe:
            '\"$npm_node_execpath\" -e "process.stdout.write(\'RECEIPT_NODE\\n\')"'
        }
      })
    );
    const shim = path.join(rootDir, "node_modules", ".bin", "node");
    fs.writeFileSync(shim, "#!/bin/sh\necho SHADOWED_NODE_SHIM\n", {
      mode: 0o755
    });
    const npmCli = installedNpmCliForTest();
    const stdout = execFileSync(
      process.execPath,
      [npmCli, "run", "--silent", "probe"],
      {
        cwd: rootDir,
        encoding: "utf8",
        env: {
          ...process.env,
          npm_execpath: npmCli,
          npm_node_execpath: process.execPath
        }
      }
    );
    assert.equal(stdout, "RECEIPT_NODE\n");
  } finally {
    fs.rmSync(rootDir, { force: true, recursive: true });
  }
});

test("exact build selects one canonical npm CLI and sanitized install environment", () => {
  const fixtureRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "tideproof-exact-npm-")
  );
  try {
    const npmCli = path.join(fixtureRoot, "npm-cli.js");
    fs.writeFileSync(npmCli, "export {};\n");
    assert.equal(
      exactBuildTest.exactNpmCli({
        npm_execpath: npmCli,
        npm_node_execpath: process.execPath
      }),
      npmCli
    );
    assert.throws(
      () =>
        exactBuildTest.exactNpmCli({
          npm_execpath: "npm",
          npm_node_execpath: process.execPath
        }),
      /EXACT_BUILD_NPM_CLI/
    );
    const environment = exactBuildTest.npmEnvironment(
      path.join(fixtureRoot, "cache")
    );
    assert.equal(environment.npm_config_ignore_scripts, "true");
    assert.equal(environment.npm_config_audit, "false");
    assert.equal(environment.npm_config_fund, "false");
    assert.equal(
      environment.npm_config_userconfig,
      path.join(fixtureRoot, "cache", "user.npmrc")
    );
    assert.equal(
      environment.npm_config_globalconfig,
      path.join(fixtureRoot, "cache", "global.npmrc")
    );
    assert.notEqual(
      environment.npm_config_userconfig,
      environment.npm_config_globalconfig
    );
    assert.equal(environment.AWS_ACCESS_KEY_ID, undefined);
    assert.equal(environment.NODE_OPTIONS, undefined);
  } finally {
    fs.rmSync(fixtureRoot, { force: true, recursive: true });
  }
});
