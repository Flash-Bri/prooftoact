import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const COMMIT = /^[0-9a-f]{40}$/;
const BLOB = /^[0-9a-f]{40}$/;
const SAFE_ENVIRONMENT_NAMES = new Set([
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "NO_COLOR",
  "PATH",
  "TMPDIR"
]);
const LOADERS = Object.freeze({
  ".cjs": "js",
  ".css": "css",
  ".html": "text",
  ".js": "js",
  ".json": "json",
  ".mjs": "js",
  ".svg": "text",
  ".txt": "text"
});

function requireCondition(condition, code) {
  if (!condition) {
    throw new Error(code);
  }
}

export function gitEnvironment(source = process.env) {
  return {
    ...Object.fromEntries(
      Object.entries(source).filter(([name]) =>
        SAFE_ENVIRONMENT_NAMES.has(name)
      )
    ),
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_NO_REPLACE_OBJECTS: "1",
    GIT_TERMINAL_PROMPT: "0"
  };
}

function git(rootDir, args, code) {
  const result = spawnSync(
    "git",
    ["-c", "core.fsmonitor=false", ...args],
    {
      cwd: rootDir,
      encoding: null,
      env: gitEnvironment(),
      maxBuffer: 64 * 1024 * 1024,
      stdio: ["ignore", "pipe", "ignore"]
    }
  );
  requireCondition(
    !result.error && result.status === 0 && Buffer.isBuffer(result.stdout),
    code
  );
  return result.stdout;
}

function gitText(rootDir, args, code) {
  return git(rootDir, args, code).toString("utf8").trim();
}

function safeRelativePath(rootDir, filePath) {
  const resolvedRoot = path.resolve(rootDir);
  const resolved = path.resolve(filePath);
  const relative = path.relative(resolvedRoot, resolved);
  requireCondition(
    relative.length > 0 &&
      relative !== ".." &&
      !relative.startsWith(`..${path.sep}`) &&
      !path.isAbsolute(relative),
    "EXACT_GIT_SOURCE_PATH"
  );
  const normalized = relative.split(path.sep).join("/");
  requireCondition(
    !normalized.includes("\0") &&
      !normalized.split("/").includes("node_modules"),
    "EXACT_GIT_SOURCE_PATH"
  );
  return { resolved, relative: normalized };
}

export function assertExactGitSourceContext({ rootDir, sourceCommit }) {
  const resolvedRoot = path.resolve(rootDir);
  requireCondition(COMMIT.test(sourceCommit), "EXACT_GIT_SOURCE_COMMIT");
  requireCondition(
    gitText(resolvedRoot, ["rev-parse", "HEAD"], "EXACT_GIT_SOURCE_HEAD") ===
      sourceCommit,
    "EXACT_GIT_SOURCE_HEAD"
  );
  requireCondition(
    gitText(
      resolvedRoot,
      ["rev-parse", "--is-shallow-repository"],
      "EXACT_GIT_SOURCE_SHALLOW"
    ) === "false",
    "EXACT_GIT_SOURCE_SHALLOW"
  );
  requireCondition(
    gitText(resolvedRoot, ["replace", "-l"], "EXACT_GIT_SOURCE_REPLACE") ===
      "",
    "EXACT_GIT_SOURCE_REPLACE"
  );
  for (const gitPath of ["info/grafts", "objects/info/alternates"]) {
    const candidatePath = gitText(
      resolvedRoot,
      ["rev-parse", "--git-path", gitPath],
      "EXACT_GIT_SOURCE_OBJECT_PATH"
    );
    const candidate = path.isAbsolute(candidatePath)
      ? candidatePath
      : path.resolve(resolvedRoot, candidatePath);
    requireCondition(!fs.existsSync(candidate), "EXACT_GIT_SOURCE_OBJECT_PATH");
  }
  return Object.freeze({ rootDir: resolvedRoot, sourceCommit });
}

export function assertCleanExactGitCheckout({
  rootDir,
  sourceCommit,
  treeDigest
}) {
  const context = assertExactGitSourceContext({ rootDir, sourceCommit });
  requireCondition(BLOB.test(treeDigest), "EXACT_GIT_SOURCE_TREE_DIGEST");
  requireCondition(
    gitText(
      context.rootDir,
      ["rev-parse", "--show-toplevel"],
      "EXACT_GIT_SOURCE_ROOT"
    ) === context.rootDir,
    "EXACT_GIT_SOURCE_ROOT"
  );
  requireCondition(
    gitText(
      context.rootDir,
      ["rev-parse", "HEAD^{tree}"],
      "EXACT_GIT_SOURCE_TREE_DIGEST"
    ) === treeDigest,
    "EXACT_GIT_SOURCE_TREE_DIGEST"
  );
  requireCondition(
    gitText(
      context.rootDir,
      ["status", "--porcelain=v1", "--untracked-files=all"],
      "EXACT_GIT_SOURCE_DIRTY"
    ) === "",
    "EXACT_GIT_SOURCE_DIRTY"
  );
  return Object.freeze({ ...context, treeDigest });
}

export function readExactGitBlob({ rootDir, sourceCommit, filePath }) {
  const context = assertExactGitSourceContext({ rootDir, sourceCommit });
  const target = safeRelativePath(context.rootDir, filePath);
  const listing = git(
    context.rootDir,
    ["ls-tree", "-z", sourceCommit, "--", target.relative],
    "EXACT_GIT_SOURCE_TREE"
  );
  const match = /^100(?:644|755) blob ([0-9a-f]{40})\t([^\0]+)\0$/.exec(
    listing.toString("utf8")
  );
  requireCondition(
    match && BLOB.test(match[1]) && match[2] === target.relative,
    "EXACT_GIT_SOURCE_TREE"
  );
  const bytes = git(
    context.rootDir,
    ["cat-file", "blob", match[1]],
    "EXACT_GIT_SOURCE_BLOB"
  );
  return Object.freeze({
    bytes,
    gitBlobId: match[1],
    path: target.relative,
    sha256: crypto.createHash("sha256").update(bytes).digest("hex")
  });
}

export function exactGitSourcePlugin({
  rootDir,
  sourceCommit,
  dependencyRoot
}) {
  const context = assertExactGitSourceContext({ rootDir, sourceCommit });
  const resolvedDependencyRoot = dependencyRoot
    ? path.resolve(dependencyRoot)
    : path.join(context.rootDir, "node_modules");
  const inputs = new Map();

  function isWithin(parent, candidate) {
    const relative = path.relative(parent, candidate);
    return (
      relative === "" ||
      (relative !== ".." &&
        !relative.startsWith(`..${path.sep}`) &&
        !path.isAbsolute(relative))
    );
  }

  function exactInput(filePath, loader) {
    const record = readExactGitBlob({
      rootDir: context.rootDir,
      sourceCommit,
      filePath
    });
    inputs.set(record.path, {
      gitBlobId: record.gitBlobId,
      path: record.path,
      sha256: record.sha256
    });
    return {
      contents: record.bytes,
      loader,
      resolveDir: path.dirname(path.resolve(context.rootDir, record.path))
    };
  }

  const plugin = {
    name: "tideproof-exact-git-source",
    setup(build) {
      build.onResolve({ filter: /\?raw$/ }, (args) => {
        const target = path.resolve(args.resolveDir, args.path.slice(0, -4));
        safeRelativePath(context.rootDir, target);
        return {
          namespace: "tideproof-exact-git-raw",
          path: target
        };
      });
      build.onLoad(
        { filter: /.*/, namespace: "tideproof-exact-git-raw" },
        (args) => exactInput(args.path, "text")
      );
      build.onLoad({ filter: /.*/, namespace: "file" }, (args) => {
        const resolved = path.resolve(args.path);
        const relative = path.relative(context.rootDir, resolved);
        if (isWithin(resolvedDependencyRoot, resolved)) {
          return null;
        }
        requireCondition(
          relative.length > 0 &&
            relative !== ".." &&
            !relative.startsWith(`..${path.sep}`) &&
            !path.isAbsolute(relative) &&
            !relative.split(path.sep).includes("node_modules"),
          "EXACT_GIT_SOURCE_PATH"
        );
        const loader = LOADERS[path.extname(resolved).toLowerCase()];
        requireCondition(loader, "EXACT_GIT_SOURCE_LOADER");
        return exactInput(resolved, loader);
      });
    }
  };

  return Object.freeze({
    plugin,
    inputRecords() {
      return [...inputs.values()].sort((left, right) =>
        left.path.localeCompare(right.path)
      );
    }
  });
}

export const __test = Object.freeze({
  COMMIT,
  LOADERS,
  gitEnvironment,
  isWithinRoot(rootDir, candidate) {
    const relative = path.relative(path.resolve(rootDir), path.resolve(candidate));
    return (
      relative === "" ||
      (relative !== ".." &&
        !relative.startsWith(`..${path.sep}`) &&
        !path.isAbsolute(relative))
    );
  },
  safeRelativePath
});
