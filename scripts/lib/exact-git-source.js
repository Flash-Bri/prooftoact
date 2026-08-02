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
  "NO_COLOR"
]);
const TRUSTED_GIT_PATH = "/usr/bin/git";
const FORBIDDEN_LOCAL_GIT_CONFIG =
  /^(?:filter\.|include(?:if)?\.|extensions\.worktreeconfig$|core\.(?:attributesfile|autocrlf|eol|hookspath|safecrlf|worktree)$)/i;
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
const FORBIDDEN_TREE_PATH =
  /(^|\/)(?:\.gitattributes|\.gitmodules|\.npmrc)$/i;

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
    PATH: "/usr/bin:/bin",
    GIT_ATTR_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_NO_REPLACE_OBJECTS: "1",
    GIT_TERMINAL_PROMPT: "0"
  };
}

export function gitInvariantArguments() {
  return [
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
  ];
}

export function assertSafeLocalGitConfiguration(names) {
  requireCondition(
    Array.isArray(names) &&
      names.every(
        (name) =>
          typeof name === "string" &&
          name.length > 0 &&
          !FORBIDDEN_LOCAL_GIT_CONFIG.test(name)
      ),
    "EXACT_GIT_SOURCE_LOCAL_CONFIG"
  );
}

export function assertSafeExactTreePaths({ rootDir, sourceCommit }) {
  requireCondition(COMMIT.test(sourceCommit), "EXACT_GIT_SOURCE_COMMIT");
  const paths = git(
    path.resolve(rootDir),
    ["ls-tree", "-r", "--name-only", "-z", sourceCommit],
    "EXACT_GIT_SOURCE_TREE_PATHS"
  )
    .toString("utf8")
    .split("\0")
    .filter(Boolean);
  requireCondition(
    paths.length > 0 &&
      paths.every(
        (candidate) =>
          typeof candidate === "string" &&
          candidate.length > 0 &&
          !FORBIDDEN_TREE_PATH.test(candidate)
      ),
    "EXACT_GIT_SOURCE_TREE_PATHS"
  );
  return Object.freeze([...paths]);
}

export function assertExactWorktreeBytes({ rootDir, sourceCommit }) {
  const resolvedRoot = path.resolve(rootDir);
  requireCondition(COMMIT.test(sourceCommit), "EXACT_GIT_WORKTREE_COMMIT");
  const entries = git(
    resolvedRoot,
    ["ls-files", "--stage", "-z"],
    "EXACT_GIT_WORKTREE_INDEX"
  )
    .toString("utf8")
    .split("\0")
    .filter(Boolean);
  requireCondition(entries.length > 0, "EXACT_GIT_WORKTREE_INDEX");
  for (const entry of entries) {
    const match = /^(100644|100755|120000) ([0-9a-f]{40}) 0\t([^\0]+)$/.exec(
      entry
    );
    requireCondition(match, "EXACT_GIT_WORKTREE_INDEX");
    const [, mode, objectId, relativePath] = match;
    requireCondition(
      !FORBIDDEN_TREE_PATH.test(relativePath),
      "EXACT_GIT_SOURCE_TREE_PATHS"
    );
    const candidate = path.resolve(resolvedRoot, relativePath);
    const relative = path.relative(resolvedRoot, candidate);
    requireCondition(
      relative === relativePath.split("/").join(path.sep) &&
        relative !== ".." &&
        !relative.startsWith(`..${path.sep}`) &&
        !path.isAbsolute(relative),
      "EXACT_GIT_WORKTREE_PATH"
    );
    const expected = git(
      resolvedRoot,
      ["cat-file", "blob", objectId],
      "EXACT_GIT_WORKTREE_BLOB"
    );
    const stat = fs.lstatSync(candidate);
    const observed =
      mode === "120000"
        ? Buffer.from(fs.readlinkSync(candidate), "utf8")
        : fs.readFileSync(candidate);
    requireCondition(
      (mode === "120000"
        ? stat.isSymbolicLink()
        : stat.isFile() && !stat.isSymbolicLink()) &&
        observed.equals(expected),
      "EXACT_GIT_WORKTREE_BYTES"
    );
  }
  requireCondition(
    gitText(
      resolvedRoot,
      ["rev-parse", "HEAD"],
      "EXACT_GIT_WORKTREE_HEAD"
    ) === sourceCommit,
    "EXACT_GIT_WORKTREE_HEAD"
  );
  return Object.freeze({ fileCount: entries.length, sourceCommit });
}

export function trustedGitExecutable() {
  let candidate = TRUSTED_GIT_PATH;
  if (process.platform === "darwin") {
    const xcrun = "/usr/bin/xcrun";
    const xcrunStat = fs.lstatSync(xcrun);
    requireCondition(
      xcrunStat.isFile() &&
        !xcrunStat.isSymbolicLink() &&
        xcrunStat.uid === 0 &&
        (xcrunStat.mode & 0o022) === 0,
      "EXACT_GIT_SOURCE_EXECUTABLE"
    );
    const discovered = spawnSync(xcrun, ["--find", "git"], {
      encoding: "utf8",
      env: gitEnvironment(),
      stdio: ["ignore", "pipe", "ignore"]
    });
    requireCondition(
      !discovered.error &&
        discovered.status === 0 &&
        /^\/(?:Applications\/Xcode[^/]*\.app\/Contents\/Developer|Library\/Developer\/CommandLineTools)\/usr\/bin\/git\n?$/.test(
          discovered.stdout
        ),
      "EXACT_GIT_SOURCE_EXECUTABLE"
    );
    candidate = discovered.stdout.trim();
  }
  const resolved = fs.realpathSync(candidate);
  const stat = fs.lstatSync(resolved);
  requireCondition(
    resolved === candidate &&
      stat.isFile() &&
      !stat.isSymbolicLink() &&
      stat.uid === 0 &&
      (stat.mode & 0o022) === 0,
    "EXACT_GIT_SOURCE_EXECUTABLE"
  );
  return resolved;
}

export function trustedTemporaryRoot() {
  const resolved = fs.realpathSync("/tmp");
  const stat = fs.lstatSync(resolved);
  requireCondition(
    ["/tmp", "/private/tmp"].includes(resolved) &&
      stat.isDirectory() &&
      !stat.isSymbolicLink() &&
      stat.uid === 0 &&
      (stat.mode & 0o1000) !== 0,
    "EXACT_GIT_TEMPORARY_ROOT"
  );
  return resolved;
}

function git(rootDir, args, code) {
  const result = spawnSync(
    trustedGitExecutable(),
    [...gitInvariantArguments(), ...args],
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

export function assertSafeProjectPath({
  rootDir,
  filePath,
  code = "EXACT_GIT_PROJECT_PATH"
}) {
  const resolvedRoot = path.resolve(rootDir);
  const resolved = path.resolve(filePath);
  const relative = path.relative(resolvedRoot, resolved);
  const rootStat = fs.lstatSync(resolvedRoot);
  requireCondition(
    fs.realpathSync(resolvedRoot) === resolvedRoot &&
      rootStat.isDirectory() &&
      !rootStat.isSymbolicLink() &&
      relative.length > 0 &&
      relative !== ".." &&
      !relative.startsWith(`..${path.sep}`) &&
      !path.isAbsolute(relative),
    code
  );
  let current = resolvedRoot;
  for (const component of relative.split(path.sep)) {
    current = path.join(current, component);
    if (!fs.existsSync(current)) {
      continue;
    }
    const stat = fs.lstatSync(current);
    requireCondition(!stat.isSymbolicLink(), code);
    if (current !== resolved) {
      requireCondition(stat.isDirectory(), code);
    }
  }
  return resolved;
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
  const localConfigNames = gitText(
    context.rootDir,
    ["config", "--local", "--includes", "--name-only", "--list"],
    "EXACT_GIT_SOURCE_LOCAL_CONFIG"
  )
    .split("\n")
    .filter(Boolean);
  assertSafeLocalGitConfiguration(localConfigNames);
  const indexEntries = git(
    context.rootDir,
    ["ls-files", "-v", "-z"],
    "EXACT_GIT_SOURCE_INDEX"
  )
    .toString("utf8")
    .split("\0")
    .filter(Boolean);
  requireCondition(
    indexEntries.length > 0 &&
      indexEntries.every((entry) => /^H .+/.test(entry)),
    "EXACT_GIT_SOURCE_INDEX"
  );
  assertSafeExactTreePaths({ rootDir: context.rootDir, sourceCommit });
  for (const gitPath of ["info/attributes", "info/sparse-checkout"]) {
    const candidatePath = gitText(
      context.rootDir,
      ["rev-parse", "--git-path", gitPath],
      "EXACT_GIT_SOURCE_CHECKOUT_PATH"
    );
    const candidate = path.isAbsolute(candidatePath)
      ? candidatePath
      : path.resolve(context.rootDir, candidatePath);
    requireCondition(
      !fs.existsSync(candidate),
      "EXACT_GIT_SOURCE_CHECKOUT_PATH"
    );
  }
  assertExactWorktreeBytes({ rootDir: context.rootDir, sourceCommit });
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
        const exactTarget = safeRelativePath(context.rootDir, target);
        return {
          namespace: "tideproof-exact-git-raw",
          path: exactTarget.relative
        };
      });
      build.onLoad(
        { filter: /.*/, namespace: "tideproof-exact-git-raw" },
        (args) =>
          exactInput(path.join(context.rootDir, args.path), "text")
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
  FORBIDDEN_TREE_PATH,
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
