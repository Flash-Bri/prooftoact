import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import test from "node:test";
import { build } from "esbuild";

import {
  __test as exactGitTest,
  assertExactWorktreeBytes,
  assertSafeLocalGitConfiguration,
  assertSafeExactTreePaths,
  assertSafeProjectPath,
  assertCleanExactGitCheckout,
  exactGitSourcePlugin,
  gitInvariantArguments,
  readExactGitBlob,
  trustedGitExecutable
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
    git(rootDir, "config", "user.name", "Tideproof Test");
    git(rootDir, "config", "user.email", "tideproof@invalid");
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
    assert.equal(environment.PATH, "/usr/bin:/bin");
    assert.equal(environment.GIT_ATTR_NOSYSTEM, "1");
    assert.equal(environment.GIT_CONFIG_GLOBAL, "/dev/null");
    assert.equal(environment.GIT_CONFIG_NOSYSTEM, "1");
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
    "core.hooksPath=/dev/null"
  ]);
  assert.doesNotThrow(() =>
    assertSafeLocalGitConfiguration([
      "core.bare",
      "core.repositoryformatversion",
      "remote.origin.url"
    ])
  );
  for (const name of [
    "core.attributesfile",
    "core.autocrlf",
    "core.eol",
    "core.hookspath",
    "core.worktree",
    "core.safecrlf",
    "extensions.worktreeconfig",
    "filter.inject.clean",
    "include.path",
    "includeif.gitdir:/tmp/.path",
    "FILTER.inject.smudge"
  ]) {
    assert.throws(
      () => assertSafeLocalGitConfiguration([name]),
      /EXACT_GIT_SOURCE_LOCAL_CONFIG/
    );
  }
});

test("exact build rejects committed checkout transforms", () => {
  const rootDir = fs.mkdtempSync(
    path.join(os.tmpdir(), "tideproof-exact-git-attributes-")
  );
  try {
    git(rootDir, "init", "--quiet");
    git(rootDir, "config", "user.name", "Tideproof Test");
    git(rootDir, "config", "user.email", "tideproof@invalid");
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
      git(rootDir, "config", "user.name", "Tideproof Test");
      git(rootDir, "config", "user.email", "tideproof@invalid");
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
  const postBuildValidation = source.indexOf(
    "const postBuildCheckout = assertCleanExactGitCheckout({"
  );
  const receiptAcceptance = source.indexOf("const receipt = JSON.parse(output)");
  const outputCopy = source.indexOf(
    "copyOutputs(stagingRoot, receipt)",
    receiptAcceptance
  );
  assert.equal(childExecution >= 0, true);
  assert.equal(postBuildValidation > childExecution, true);
  assert.equal(receiptAcceptance > postBuildValidation, true);
  assert.equal(outputCopy > receiptAcceptance, true);
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
    const stdout = execFileSync("npm", ["run", "--silent", "probe"], {
      cwd: rootDir,
      encoding: "utf8"
    });
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
