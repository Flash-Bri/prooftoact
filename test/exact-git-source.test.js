import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import test from "node:test";
import { build } from "esbuild";

import {
  __test as exactGitTest,
  assertCleanExactGitCheckout,
  exactGitSourcePlugin,
  readExactGitBlob
} from "../scripts/lib/exact-git-source.js";
import { __test as exactBuildTest } from "../scripts/build-gate2-exact.js";

function git(rootDir, ...args) {
  return execFileSync("git", args, {
    cwd: rootDir,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"]
  }).trim();
}

test("Gate Two bundling reads project inputs from immutable Git blobs", async () => {
  const rootDir = fs.mkdtempSync(
    path.join(os.tmpdir(), "tideproof-exact-git-test-")
  );
  try {
    git(rootDir, "init", "--quiet");
    git(rootDir, "config", "user.name", "Tideproof Test");
    git(rootDir, "config", "user.email", "tideproof@invalid");
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

test("exact Git bundling rejects every non-dependency path escape", async () => {
  const fixtureRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "tideproof-exact-git-escape-")
  );
  const repositoryRoot = path.join(fixtureRoot, "repository");
  const outsidePath = path.join(fixtureRoot, "outside.js");
  try {
    fs.mkdirSync(repositoryRoot);
    git(repositoryRoot, "init", "--quiet");
    git(repositoryRoot, "config", "user.name", "Tideproof Test");
    git(repositoryRoot, "config", "user.email", "tideproof@invalid");
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
    assert.equal(environment.GIT_CONFIG_GLOBAL, "/dev/null");
    assert.equal(environment.GIT_CONFIG_NOSYSTEM, "1");
    assert.equal(environment.GIT_NO_REPLACE_OBJECTS, "1");
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
