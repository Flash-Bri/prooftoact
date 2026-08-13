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
const OFFICIAL_REMOTE =
  "https://github.com/Flash-Bri/prooftoact.git";
const OFFICIAL_REMOTE_VALUES = Object.freeze([
  OFFICIAL_REMOTE,
  "https://github.com/Flash-Bri/prooftoact"
]);
const OFFICIAL_FETCH_REFSPEC =
  "+refs/heads/*:refs/remotes/origin/*";
const ALLOWED_LOCAL_GIT_CONFIGURATION = new Map([
  ["branch.main.merge", "refs/heads/main"],
  ["branch.main.remote", "origin"],
  ["core.bare", "false"],
  ["core.filemode", "true"],
  ["core.ignorecase", "true"],
  ["core.logallrefupdates", "true"],
  ["core.precomposeunicode", "true"],
  ["core.repositoryformatversion", "0"],
  ["gc.auto", "0"],
  ["remote.origin.fetch", OFFICIAL_FETCH_REFSPEC],
  ["remote.origin.url", OFFICIAL_REMOTE]
]);
const INACTIVE_ACTIONS_WORKTREE_CONFIGURATION = new Map([
  ["core.sparsecheckout", "false"],
  ["core.sparsecheckoutcone", "false"],
  ["index.sparse", "false"]
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
const FORBIDDEN_TREE_PATH =
  /(^|\/)(?:\.gitattributes|\.gitmodules|\.npmrc)$/i;

function originValuesForRepository(repository) {
  if (repository === null) return OFFICIAL_REMOTE_VALUES;
  requireCondition(
    typeof repository === "string" &&
      /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(repository) &&
      repository.split("/").every(
        (part) => part !== "." && part !== ".." && !part.endsWith(".lock")
      ),
    "EXACT_GIT_SOURCE_LOCAL_CONFIG"
  );
  const base = `https://github.com/${repository}`;
  return Object.freeze([base, `${base}.git`]);
}

function isAllowedLocalGitConfiguration(
  name,
  value,
  expectedOriginValues
) {
  return name === "remote.origin.url"
    ? expectedOriginValues.includes(value)
    : ALLOWED_LOCAL_GIT_CONFIGURATION.get(name) === value;
}

function assertInactiveActionsWorktreeConfiguration(entries) {
  const code = "EXACT_GIT_SOURCE_WORKTREE_CONFIG";
  requireCondition(
    Array.isArray(entries) &&
      entries.length === INACTIVE_ACTIONS_WORKTREE_CONFIGURATION.size,
    code
  );
  const configuration = new Set();
  for (const entry of entries) {
    requireCondition(
      entry &&
        typeof entry === "object" &&
        Object.keys(entry).sort().join("\n") === "name\nvalue" &&
        typeof entry.name === "string" &&
        entry.name === entry.name.toLowerCase() &&
        typeof entry.value === "string" &&
        INACTIVE_ACTIONS_WORKTREE_CONFIGURATION.get(entry.name) ===
          entry.value &&
        !configuration.has(entry.name),
      code
    );
    configuration.add(entry.name);
  }
  requireCondition(
    [...INACTIVE_ACTIONS_WORKTREE_CONFIGURATION.keys()].every((name) =>
      configuration.has(name)
    ),
    code
  );
}

function requireCondition(condition, code) {
  if (!condition) {
    throw new Error(code);
  }
}

function lstatOrReject(candidate, code) {
  try {
    return fs.lstatSync(candidate);
  } catch {
    throw new Error(code);
  }
}

function lstatIfPresent(candidate, code) {
  try {
    return fs.lstatSync(candidate);
  } catch (error) {
    if (error && typeof error === "object" && error.code === "ENOENT") {
      return null;
    }
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
    GIT_NO_LAZY_FETCH: "1",
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
    "core.hooksPath=/dev/null",
    "-c",
    "core.untrackedCache=false"
  ];
}

export function parseLocalGitConfiguration(
  output,
  code = "EXACT_GIT_SOURCE_LOCAL_CONFIG"
) {
  const text = Buffer.isBuffer(output)
    ? output.toString("utf8")
    : output;
  requireCondition(
    typeof text === "string" && text.length > 0 && text.endsWith("\0"),
    code
  );
  const entries = text
    .split("\0")
    .filter(Boolean)
    .map((record) => {
      const separator = record.indexOf("\n");
      requireCondition(separator > 0, code);
      const name = record.slice(0, separator).toLowerCase();
      const value = record.slice(separator + 1);
      requireCondition(name.length > 0 && value.length > 0, code);
      return Object.freeze({ name, value });
    });
  requireCondition(entries.length > 0, code);
  return Object.freeze(entries);
}

export function assertSafeLocalGitConfiguration(
  entries,
  {
    expectedOriginRepository = null,
    requireOfficialOrigin = false,
    requireMainBranch = false
  } = {}
) {
  const code = "EXACT_GIT_SOURCE_LOCAL_CONFIG";
  requireCondition(
      Array.isArray(entries) &&
      (expectedOriginRepository === null ||
        typeof expectedOriginRepository === "string") &&
      typeof requireOfficialOrigin === "boolean" &&
      typeof requireMainBranch === "boolean",
    code
  );
  const expectedOriginValues = originValuesForRepository(
    expectedOriginRepository
  );
  const configuration = new Map();
  for (const entry of entries) {
    requireCondition(
      entry &&
        typeof entry === "object" &&
        Object.keys(entry).sort().join("\n") === "name\nvalue" &&
        typeof entry.name === "string" &&
        entry.name === entry.name.toLowerCase() &&
        typeof entry.value === "string" &&
        isAllowedLocalGitConfiguration(
          entry.name,
          entry.value,
          expectedOriginValues
        ) &&
        !configuration.has(entry.name),
      code
    );
    configuration.set(entry.name, entry.value);
  }
  for (const name of [
    "core.bare",
    "core.filemode",
    "core.logallrefupdates",
    "core.repositoryformatversion"
  ]) {
    requireCondition(configuration.has(name), code);
  }
  const hasOrigin = [
    "remote.origin.fetch",
    "remote.origin.url"
  ].some((name) => configuration.has(name));
  const hasCompleteOrigin = [
    "remote.origin.fetch",
    "remote.origin.url"
  ].every((name) => configuration.has(name));
  const hasMainBranch = [
    "branch.main.merge",
    "branch.main.remote"
  ].some((name) => configuration.has(name));
  const hasCompleteMainBranch = [
    "branch.main.merge",
    "branch.main.remote"
  ].every((name) => configuration.has(name));
  requireCondition(
    hasOrigin === hasCompleteOrigin &&
      hasMainBranch === hasCompleteMainBranch &&
      (!hasCompleteMainBranch || hasCompleteOrigin) &&
      (!requireOfficialOrigin || hasCompleteOrigin) &&
      (!requireMainBranch || hasCompleteMainBranch),
    code
  );
  return Object.freeze({
    entryCount: entries.length,
    mainBranchConfigured: hasCompleteMainBranch,
    officialOriginConfigured: hasCompleteOrigin,
    remote: configuration.get("remote.origin.url") ?? null
  });
}

export function assertSafeExactTreePaths({ rootDir, sourceCommit }) {
  requireCondition(COMMIT.test(sourceCommit), "EXACT_GIT_SOURCE_COMMIT");
  const context = assertExactGitSourceContext({ rootDir, sourceCommit });
  const paths = git(
    context.rootDir,
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

function absoluteGitPath(rootDir, candidate) {
  return path.resolve(
    path.isAbsolute(candidate) ? candidate : path.join(rootDir, candidate)
  );
}

function assertLocalObjectStore({ gitDir, objectDirectory }) {
  for (const candidate of [
    path.join(gitDir, "info", "grafts"),
    path.join(gitDir, "shallow"),
    path.join(objectDirectory, "info", "alternates"),
    path.join(objectDirectory, "info", "http-alternates")
  ]) {
    requireCondition(
      !fs.existsSync(candidate),
      "EXACT_GIT_SOURCE_OBJECT_PATH"
    );
  }
  const pending = [objectDirectory];
  while (pending.length > 0) {
    const current = pending.pop();
    const stat = fs.lstatSync(current);
    requireCondition(
      !stat.isSymbolicLink() &&
        (stat.isDirectory() || stat.isFile()),
      "EXACT_GIT_SOURCE_OBJECT_PATH"
    );
    requireCondition(
      !/\.promisor$/i.test(path.basename(current)),
      "EXACT_GIT_SOURCE_PROMISOR"
    );
    if (stat.isDirectory()) {
      for (const name of fs.readdirSync(current)) {
        pending.push(path.join(current, name));
      }
    }
  }
}

function readLocalGitConfiguration({
  rootDir,
  config,
  code = "EXACT_GIT_SOURCE_LOCAL_CONFIG"
}) {
  return parseLocalGitConfiguration(
    git(
      rootDir,
      [
        "config",
        "--file",
        config,
        "--no-includes",
        "--null",
        "--list"
      ],
      code
    ),
    code
  );
}

export function assertExactGitRepositoryLayout({
  rootDir,
  allowInactiveActionsWorktreeConfig = false,
  expectedOriginRepository = null
}) {
  requireCondition(
    typeof allowInactiveActionsWorktreeConfig === "boolean" &&
      (expectedOriginRepository === null ||
        typeof expectedOriginRepository === "string"),
    "EXACT_GIT_SOURCE_LAYOUT"
  );
  const resolvedRoot = path.resolve(rootDir);
  const expectedGitDir = path.join(resolvedRoot, ".git");
  const expectedConfig = path.join(expectedGitDir, "config");
  const expectedWorktreeConfig = path.join(
    expectedGitDir,
    "config.worktree"
  );
  const expectedSparseCheckout = path.join(
    expectedGitDir,
    "info",
    "sparse-checkout"
  );
  const expectedObjectDirectory = path.join(expectedGitDir, "objects");
  const expectedIndex = path.join(expectedGitDir, "index");
  const rootStat = lstatOrReject(resolvedRoot, "EXACT_GIT_SOURCE_LAYOUT");
  const gitDirStat = lstatOrReject(expectedGitDir, "EXACT_GIT_SOURCE_LAYOUT");
  const configStat = lstatOrReject(expectedConfig, "EXACT_GIT_SOURCE_LAYOUT");
  const objectDirectoryStat = lstatOrReject(
    expectedObjectDirectory,
    "EXACT_GIT_SOURCE_LAYOUT"
  );
  const indexStat = lstatOrReject(expectedIndex, "EXACT_GIT_SOURCE_LAYOUT");
  requireCondition(
    fs.realpathSync(resolvedRoot) === resolvedRoot &&
      rootStat.isDirectory() &&
      !rootStat.isSymbolicLink() &&
      gitDirStat.isDirectory() &&
      !gitDirStat.isSymbolicLink() &&
      configStat.isFile() &&
      !configStat.isSymbolicLink() &&
      objectDirectoryStat.isDirectory() &&
      !objectDirectoryStat.isSymbolicLink() &&
      indexStat.isFile() &&
      !indexStat.isSymbolicLink(),
    "EXACT_GIT_SOURCE_LAYOUT"
  );
  assertSafeLocalGitConfiguration(
    readLocalGitConfiguration({
      rootDir: resolvedRoot,
      config: expectedConfig
    }),
    { expectedOriginRepository }
  );
  const worktreeConfigStat = lstatIfPresent(
    expectedWorktreeConfig,
    "EXACT_GIT_SOURCE_WORKTREE_CONFIG"
  );
  const sparseCheckoutStat = allowInactiveActionsWorktreeConfig
    ? lstatIfPresent(
        expectedSparseCheckout,
        "EXACT_GIT_SOURCE_WORKTREE_CONFIG"
      )
    : null;
  requireCondition(
    !allowInactiveActionsWorktreeConfig || sparseCheckoutStat === null,
    "EXACT_GIT_SOURCE_WORKTREE_CONFIG"
  );
  if (worktreeConfigStat) {
    if (!allowInactiveActionsWorktreeConfig) {
      throw new Error("EXACT_GIT_SOURCE_OBJECT_PATH");
    }
    requireCondition(
      worktreeConfigStat.isFile() &&
        !worktreeConfigStat.isSymbolicLink() &&
        fs.realpathSync(expectedWorktreeConfig) === expectedWorktreeConfig,
      "EXACT_GIT_SOURCE_WORKTREE_CONFIG"
    );
    assertInactiveActionsWorktreeConfiguration(
      readLocalGitConfiguration({
        rootDir: resolvedRoot,
        config: expectedWorktreeConfig,
        code: "EXACT_GIT_SOURCE_WORKTREE_CONFIG"
      })
    );
  }
  assertLocalObjectStore({
    gitDir: expectedGitDir,
    objectDirectory: expectedObjectDirectory
  });
  requireCondition(
    fs.realpathSync(resolvedRoot) === resolvedRoot &&
      gitText(
        resolvedRoot,
        ["rev-parse", "--show-toplevel"],
        "EXACT_GIT_SOURCE_ROOT"
      ) === resolvedRoot &&
      absoluteGitPath(
        resolvedRoot,
        gitText(
          resolvedRoot,
          ["rev-parse", "--absolute-git-dir"],
          "EXACT_GIT_SOURCE_GIT_DIR"
        )
      ) === expectedGitDir &&
      absoluteGitPath(
        resolvedRoot,
        gitText(
          resolvedRoot,
          ["rev-parse", "--git-common-dir"],
          "EXACT_GIT_SOURCE_COMMON_DIR"
        )
      ) === expectedGitDir &&
      absoluteGitPath(
        resolvedRoot,
        gitText(
          resolvedRoot,
          ["rev-parse", "--git-path", "objects"],
          "EXACT_GIT_SOURCE_OBJECT_DIRECTORY"
        )
      ) === expectedObjectDirectory &&
      absoluteGitPath(
        resolvedRoot,
        gitText(
          resolvedRoot,
          ["rev-parse", "--git-path", "index"],
          "EXACT_GIT_SOURCE_INDEX_PATH"
        )
      ) === expectedIndex,
    "EXACT_GIT_SOURCE_LAYOUT"
  );
  return Object.freeze({
    rootDir: resolvedRoot,
    gitDir: expectedGitDir,
    config: expectedConfig,
    objectDirectory: expectedObjectDirectory,
    index: expectedIndex
  });
}

export function assertExactWorktreeBytes({ rootDir, sourceCommit }) {
  requireCondition(COMMIT.test(sourceCommit), "EXACT_GIT_WORKTREE_COMMIT");
  const context = assertExactGitSourceContext({ rootDir, sourceCommit });
  const resolvedRoot = context.rootDir;
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

function git(rootDir, args, code, { input } = {}) {
  const result = spawnSync(
    trustedGitExecutable(),
    [...gitInvariantArguments(), ...args],
    {
      cwd: rootDir,
      encoding: null,
      env: gitEnvironment(),
      input,
      maxBuffer: 64 * 1024 * 1024,
      stdio: [input === undefined ? "ignore" : "pipe", "pipe", "ignore"]
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

export function assertCompleteLocalObjectClosure({
  rootDir,
  sourceCommit
}) {
  requireCondition(COMMIT.test(sourceCommit), "EXACT_GIT_SOURCE_COMMIT");
  const context = assertExactGitSourceContext({ rootDir, sourceCommit });
  const records = gitText(
    context.rootDir,
    [
      "rev-list",
      "--objects",
      "--no-object-names",
      "--missing=print",
      sourceCommit
    ],
    "EXACT_GIT_SOURCE_OBJECT_CLOSURE"
  )
    .split("\n")
    .filter(Boolean);
  requireCondition(
    records.length > 0 &&
      records.includes(sourceCommit) &&
      new Set(records).size === records.length &&
      records.every((objectId) => BLOB.test(objectId)),
    "EXACT_GIT_SOURCE_OBJECT_CLOSURE"
  );
  const batch = git(
    context.rootDir,
    [
      "cat-file",
      "--batch-check=%(objectname) %(objecttype) %(objectsize)"
    ],
    "EXACT_GIT_SOURCE_OBJECT_CLOSURE",
    { input: Buffer.from(`${records.join("\n")}\n`, "utf8") }
  )
    .toString("utf8")
    .trim()
    .split("\n");
  requireCondition(
    batch.length === records.length &&
      batch.every((record, index) => {
        const match =
          /^([0-9a-f]{40}) (blob|commit|tag|tree) ([0-9]+)$/.exec(record);
        return (
          match &&
          match[1] === records[index] &&
          Number.isSafeInteger(Number(match[3])) &&
          Number(match[3]) >= 0
        );
      }),
    "EXACT_GIT_SOURCE_OBJECT_CLOSURE"
  );
  git(
    context.rootDir,
    ["fsck", "--strict", "--no-dangling", sourceCommit],
    "EXACT_GIT_SOURCE_OBJECT_CLOSURE"
  );
  return Object.freeze({
    objectCount: records.length,
    sourceCommit
  });
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
  const layout = assertExactGitRepositoryLayout({ rootDir: resolvedRoot });
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
    gitText(
      resolvedRoot,
      ["for-each-ref", "--format=%(refname)", "refs/replace/"],
      "EXACT_GIT_SOURCE_REPLACE"
    ) ===
      "",
    "EXACT_GIT_SOURCE_REPLACE"
  );
  for (const candidate of [
    path.join(layout.gitDir, "info", "grafts"),
    path.join(layout.objectDirectory, "info", "alternates")
  ]) {
    requireCondition(
      !fs.existsSync(candidate),
      "EXACT_GIT_SOURCE_OBJECT_PATH"
    );
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
  assertCompleteLocalObjectClosure({
    rootDir: context.rootDir,
    sourceCommit
  });
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
  for (const candidate of [
    path.join(context.rootDir, ".git", "info", "attributes"),
    path.join(context.rootDir, ".git", "info", "sparse-checkout")
  ]) {
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
