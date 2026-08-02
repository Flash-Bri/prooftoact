import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import {
  createBuildToolchain,
  createDependencySnapshot
} from "./lib/dependency-snapshot.js";
import {
  assertCleanExactGitCheckout,
  assertExactWorktreeBytes,
  assertSafeLocalGitConfiguration,
  assertSafeExactTreePaths,
  assertSafeProjectPath,
  gitInvariantArguments,
  trustedGitExecutable,
  trustedTemporaryRoot
} from "./lib/exact-git-source.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");
const SAFE_ENVIRONMENT_NAMES = new Set([
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "NO_COLOR"
]);

function requireCondition(condition, code) {
  if (!condition) {
    throw new Error(code);
  }
}

export function isolatedEnvironment(source = process.env) {
  return {
    ...Object.fromEntries(
      Object.entries(source).filter(([name]) =>
        SAFE_ENVIRONMENT_NAMES.has(name)
      )
    ),
    PATH: "/usr/bin:/bin",
    GIT_ATTR_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_NO_REPLACE_OBJECTS: "1",
    GIT_TERMINAL_PROMPT: "0"
  };
}

export function npmEnvironment(cacheRoot) {
  return {
    ...isolatedEnvironment(),
    npm_config_audit: "false",
    npm_config_cache: cacheRoot,
    npm_config_fund: "false",
    npm_config_globalconfig: path.join(cacheRoot, "global.npmrc"),
    npm_config_ignore_scripts: "true",
    npm_config_registry: "https://registry.npmjs.org/",
    npm_config_update_notifier: "false",
    npm_config_userconfig: path.join(cacheRoot, "user.npmrc")
  };
}

function run(command, args, { cwd = root, env, encoding = "utf8" } = {}) {
  const result = spawnSync(command, args, {
    cwd,
    encoding,
    env: env ?? isolatedEnvironment(),
    maxBuffer: 64 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"]
  });
  requireCondition(!result.error && result.status === 0, "EXACT_BUILD_CHILD");
  return result.stdout;
}

function git(args, cwd = root, gitExecutable = trustedGitExecutable()) {
  return run(
    gitExecutable,
    [...gitInvariantArguments(), ...args],
    { cwd }
  ).trim();
}

function sha256(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function copyExactFile(source, destination, { sourceRoot, destinationRoot }) {
  assertSafeProjectPath({
    rootDir: sourceRoot,
    filePath: source,
    code: "EXACT_BUILD_OUTPUT_PATH"
  });
  assertSafeProjectPath({
    rootDir: destinationRoot,
    filePath: destination,
    code: "EXACT_BUILD_OUTPUT_PATH"
  });
  const stat = fs.lstatSync(source);
  requireCondition(stat.isFile() && !stat.isSymbolicLink(), "EXACT_BUILD_OUTPUT");
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  if (fs.existsSync(destination)) {
    const destinationStat = fs.lstatSync(destination);
    requireCondition(
      destinationStat.isFile() &&
        !destinationStat.isSymbolicLink() &&
        sha256(destination) === sha256(source),
      "EXACT_BUILD_OUTPUT_CONFLICT"
    );
    return;
  }
  fs.copyFileSync(source, destination, fs.constants.COPYFILE_EXCL);
}

export function exactNpmCli(source = process.env) {
  const candidate = source.npm_execpath;
  requireCondition(
    typeof candidate === "string" && path.isAbsolute(candidate),
    "EXACT_BUILD_NPM_CLI"
  );
  const resolved = fs.realpathSync(candidate);
  const stat = fs.lstatSync(resolved);
  requireCondition(
    stat.isFile() &&
      !stat.isSymbolicLink() &&
      typeof source.npm_node_execpath === "string" &&
      fs.realpathSync(source.npm_node_execpath) ===
        fs.realpathSync(process.execPath),
    "EXACT_BUILD_NPM_CLI"
  );
  return resolved;
}

function copyOutputs(stagingRoot, receipt) {
  const expectedTemplates = [
    receipt.bootstrapTemplate?.path,
    receipt.gate2Template?.path
  ];
  requireCondition(
    expectedTemplates.join("\n") ===
      "infra/aws/bootstrap-template.json\ninfra/aws/gate2-template.json",
    "EXACT_BUILD_TEMPLATE_OUTPUTS"
  );
  for (const relativePath of expectedTemplates) {
    copyExactFile(
      path.join(stagingRoot, relativePath),
      path.join(root, relativePath),
      { sourceRoot: stagingRoot, destinationRoot: root }
    );
  }
  for (const artifact of receipt.artifacts ?? []) {
    requireCondition(
      typeof artifact.artifactPath === "string" &&
        /^dist\/aws\/[a-z]+-[0-9a-f]{64}\.zip$/.test(
          artifact.artifactPath
        ),
      "EXACT_BUILD_ARTIFACT_OUTPUT"
    );
    copyExactFile(
      path.join(stagingRoot, artifact.artifactPath),
      path.join(root, artifact.artifactPath),
      { sourceRoot: stagingRoot, destinationRoot: root }
    );
  }
  const runtime = receipt.evidenceProviderRuntime;
  requireCondition(
    runtime &&
      typeof runtime.path === "string" &&
      /^dist\/aws\/evidence-provider-[0-9a-f]{64}\.mjs$/.test(runtime.path),
    "EXACT_BUILD_PROVIDER_RUNTIME_OUTPUT"
  );
  copyExactFile(
    path.join(stagingRoot, runtime.path),
    path.join(root, runtime.path),
    { sourceRoot: stagingRoot, destinationRoot: root }
  );
}

export function main(argv = process.argv.slice(2)) {
  requireCondition(argv.length === 0, "EXACT_BUILD_ARGUMENTS");
  const gitExecutable = trustedGitExecutable();
  const gitBuiltins = new Set(
    run(gitExecutable, ["--list-cmds=builtins"])
      .trim()
      .split(/\s+/)
      .filter(Boolean)
  );
  requireCondition(
    [
      "cat-file",
      "config",
      "ls-files",
      "ls-tree",
      "replace",
      "rev-parse",
      "status",
      "worktree"
    ].every((name) => gitBuiltins.has(name)),
    "EXACT_BUILD_GIT_BUILTINS"
  );
  const sourceCommit = git(["rev-parse", "HEAD"], root, gitExecutable);
  const treeDigest = git(["rev-parse", "HEAD^{tree}"], root, gitExecutable);
  requireCondition(/^[0-9a-f]{40}$/.test(sourceCommit), "EXACT_BUILD_HEAD");
  requireCondition(/^[0-9a-f]{40}$/.test(treeDigest), "EXACT_BUILD_TREE");
  requireCondition(
    git(["rev-parse", "--show-toplevel"], root, gitExecutable) === root,
    "EXACT_BUILD_ROOT"
  );
  requireCondition(
    git(
      ["status", "--porcelain=v1", "--untracked-files=all"],
      root,
      gitExecutable
    ) === "",
    "EXACT_BUILD_DIRTY_TREE"
  );
  requireCondition(
    git(
      ["rev-parse", "--is-shallow-repository"],
      root,
      gitExecutable
    ) === "false" && git(["replace", "-l"], root, gitExecutable) === "",
    "EXACT_BUILD_OBJECT_STORE"
  );
  const localConfigNames = git(
    ["config", "--local", "--includes", "--name-only", "--list"],
    root,
    gitExecutable
  )
    .split("\n")
    .filter(Boolean);
  assertSafeLocalGitConfiguration(localConfigNames);
  assertSafeExactTreePaths({ rootDir: root, sourceCommit });
  const indexEntries = git(
    ["ls-files", "-v", "-z"],
    root,
    gitExecutable
  )
    .split("\0")
    .filter(Boolean);
  requireCondition(
    indexEntries.length > 0 &&
      indexEntries.every((entry) => /^H .+/.test(entry)),
    "EXACT_BUILD_INDEX_FLAGS"
  );
  for (const gitPath of [
    "info/attributes",
    "info/grafts",
    "info/sparse-checkout",
    "objects/info/alternates"
  ]) {
    const candidatePath = git(
      ["rev-parse", "--git-path", gitPath],
      root,
      gitExecutable
    );
    const candidate = path.isAbsolute(candidatePath)
      ? candidatePath
      : path.resolve(root, candidatePath);
    requireCondition(!fs.existsSync(candidate), "EXACT_BUILD_OBJECT_STORE");
  }
  const npmCli = exactNpmCli();
  const npmVersion = run(process.execPath, [npmCli, "--version"]).trim();
  let packageManager;
  try {
    packageManager = JSON.parse(
      fs.readFileSync(path.join(root, "package.json"), "utf8")
    ).packageManager;
  } catch {
    throw new Error("EXACT_BUILD_PACKAGE_MANAGER");
  }
  requireCondition(
    /^[0-9]+\.[0-9]+\.[0-9]+$/.test(npmVersion) &&
      packageManager === `npm@${npmVersion}`,
    "EXACT_BUILD_NPM_VERSION"
  );

  const temporaryRoot = fs.mkdtempSync(
    path.join(trustedTemporaryRoot(), "tideproof-exact-build-")
  );
  const checkoutRoot = path.join(temporaryRoot, "checkout");
  const stagingRoot = path.join(temporaryRoot, "output");
  let worktreeAdded = false;
  try {
    run(
      gitExecutable,
      [
        ...gitInvariantArguments(),
        "worktree",
        "add",
        "--detach",
        checkoutRoot,
        sourceCommit
      ],
      { cwd: root }
    );
    worktreeAdded = true;
    assertExactWorktreeBytes({
      rootDir: checkoutRoot,
      sourceCommit
    });
    run(
      process.execPath,
      [
        npmCli,
        "ci",
        "--ignore-scripts",
        "--no-audit",
        "--no-fund"
      ],
      {
        cwd: checkoutRoot,
        env: npmEnvironment(path.join(temporaryRoot, "npm-cache"))
      }
    );
    const dependencyRoot = path.join(checkoutRoot, "node_modules");
    fs.rmSync(path.join(dependencyRoot, ".bin"), {
      force: true,
      recursive: true
    });
    const dependencySnapshot = createDependencySnapshot({
      dependencyRoot,
      packageJsonDigest: sha256(path.join(checkoutRoot, "package.json")),
      packageLockDigest: sha256(path.join(checkoutRoot, "package-lock.json"))
    });
    const toolchain = createBuildToolchain({ gitExecutable, npmCli });
    requireCondition(
      toolchain.npmVersion === npmVersion,
      "EXACT_BUILD_NPM_VERSION"
    );
    const childEnvironment = {
      ...isolatedEnvironment(),
      TIDEPROOF_EXACT_BUILD_DEPENDENCY_SNAPSHOT:
        JSON.stringify(dependencySnapshot),
      TIDEPROOF_EXACT_BUILD_SOURCE_COMMIT: sourceCommit,
      TIDEPROOF_EXACT_BUILD_TOOLCHAIN: JSON.stringify(toolchain),
      TIDEPROOF_EXACT_BUILD_TREE_DIGEST: treeDigest
    };
    const output = run(
      process.execPath,
      [
        "scripts/build-gate2-template.js",
        "--isolated-output",
        stagingRoot
      ],
      { cwd: checkoutRoot, env: childEnvironment }
    );
    const postBuildCheckout = assertCleanExactGitCheckout({
      rootDir: checkoutRoot,
      sourceCommit,
      treeDigest
    });
    requireCondition(
      postBuildCheckout.sourceCommit === sourceCommit &&
        postBuildCheckout.treeDigest === treeDigest,
      "EXACT_BUILD_POST_CHECKOUT"
    );
    const receipt = JSON.parse(output);
    const postBuildDependencySnapshot = createDependencySnapshot({
      dependencyRoot,
      packageJsonDigest: sha256(path.join(checkoutRoot, "package.json")),
      packageLockDigest: sha256(path.join(checkoutRoot, "package-lock.json"))
    });
    const postBuildToolchain = createBuildToolchain({
      gitExecutable,
      npmCli
    });
    requireCondition(
      receipt?.schemaVersion === "tideproof.gate2-build.v6" &&
        receipt.mode === "CLEAN_ARTIFACT_BUILD" &&
        receipt.projectSourceMode ===
          "ISOLATED_EXACT_GIT_CHECKOUT_AND_BLOBS" &&
        receipt.sourceCommit === sourceCommit &&
        receipt.treeDigest === treeDigest &&
        JSON.stringify(postBuildDependencySnapshot) ===
          JSON.stringify(dependencySnapshot) &&
        JSON.stringify(postBuildToolchain) === JSON.stringify(toolchain),
      "EXACT_BUILD_RECEIPT"
    );
    copyOutputs(stagingRoot, receipt);
    requireCondition(
      git(
        ["status", "--porcelain=v1", "--untracked-files=all"],
        root,
        gitExecutable
      ) === "",
      "EXACT_BUILD_POST_DIRTY_TREE"
    );
    process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
  } finally {
    let cleanupError = null;
    if (worktreeAdded) {
      const removed = spawnSync(
        gitExecutable,
        [
          ...gitInvariantArguments(),
          "worktree",
          "remove",
          "--force",
          checkoutRoot
        ],
        {
          cwd: root,
          encoding: "utf8",
          env: isolatedEnvironment(),
          stdio: ["ignore", "pipe", "pipe"]
        }
      );
      if (removed.error || removed.status !== 0) {
        cleanupError = new Error("EXACT_BUILD_WORKTREE_CLEANUP");
      }
    }
    fs.rmSync(temporaryRoot, { force: true, recursive: true });
    if (cleanupError) {
      throw cleanupError;
    }
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    const code = /^EXACT_BUILD_[A-Z0-9_]{1,100}$/.test(
      String(error?.message ?? "")
    )
      ? error.message
      : "EXACT_BUILD_UNKNOWN";
    process.stderr.write(`${code}\n`);
    process.exitCode = 1;
  }
}

export const __test = Object.freeze({
  exactNpmCli,
  isolatedEnvironment,
  npmEnvironment
});
