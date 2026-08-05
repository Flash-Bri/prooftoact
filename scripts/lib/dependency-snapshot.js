import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const HEX_64 = /^[0-9a-f]{64}$/;
const SNAPSHOT_SCHEMA = "tideproof.dependency-snapshot.v1";
const TOOLCHAIN_SCHEMA = "tideproof.build-toolchain.v2";

function requireCondition(condition, code) {
  if (!condition) {
    throw new Error(code);
  }
}

function exactKeys(value, keys) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join("\n") === [...keys].sort().join("\n")
  );
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function recordsDigest(records) {
  return sha256(
    Buffer.from(
      records
        .map(
          (record) =>
            `${record.path}\0${record.mode}\0${record.size}\0${record.sha256}\n`
        )
        .join(""),
      "utf8"
    )
  );
}

function walkDependencyTree(rootDir) {
  const records = [];
  let totalBytes = 0;

  function visit(directory, relativeDirectory = "") {
    const names = fs.readdirSync(directory).sort();
    for (const name of names) {
      if (relativeDirectory === "" && name === ".bin") {
        continue;
      }
      requireCondition(
        name.length > 0 && name !== "." && name !== ".." && !name.includes("\0"),
        "DEPENDENCY_SNAPSHOT_PATH"
      );
      const relativePath = relativeDirectory
        ? `${relativeDirectory}/${name}`
        : name;
      const absolutePath = path.join(directory, name);
      const stat = fs.lstatSync(absolutePath);
      requireCondition(
        !stat.isSymbolicLink(),
        "DEPENDENCY_SNAPSHOT_SYMLINK"
      );
      if (stat.isDirectory()) {
        visit(absolutePath, relativePath);
        continue;
      }
      requireCondition(stat.isFile(), "DEPENDENCY_SNAPSHOT_FILE_TYPE");
      const bytes = fs.readFileSync(absolutePath);
      requireCondition(bytes.length === stat.size, "DEPENDENCY_SNAPSHOT_SIZE");
      totalBytes += bytes.length;
      requireCondition(
        Number.isSafeInteger(totalBytes),
        "DEPENDENCY_SNAPSHOT_SIZE"
      );
      records.push({
        mode: stat.mode & 0o777,
        path: relativePath,
        sha256: sha256(bytes),
        size: bytes.length
      });
    }
  }

  visit(rootDir);
  return { records, totalBytes };
}

export function createDependencySnapshot({
  dependencyRoot,
  packageJsonDigest,
  packageLockDigest
}) {
  const resolvedRoot = path.resolve(dependencyRoot);
  const rootStat = fs.lstatSync(resolvedRoot);
  requireCondition(
    rootStat.isDirectory() && !rootStat.isSymbolicLink(),
    "DEPENDENCY_SNAPSHOT_ROOT"
  );
  requireCondition(
    HEX_64.test(packageJsonDigest) && HEX_64.test(packageLockDigest),
    "DEPENDENCY_SNAPSHOT_MANIFEST_DIGEST"
  );
  const { records, totalBytes } = walkDependencyTree(resolvedRoot);
  requireCondition(records.length > 0, "DEPENDENCY_SNAPSHOT_EMPTY");
  const treeDigest = recordsDigest(records);
  return Object.freeze({
    schemaVersion: SNAPSHOT_SCHEMA,
    installMode: "NPM_CI_IGNORE_SCRIPTS_CLEAN_CACHE",
    fileCount: records.length,
    totalBytes,
    symlinkCount: 0,
    packageJsonDigest,
    packageLockDigest,
    treeDigest
  });
}

function npmPackageRoot(npmCli) {
  const resolvedCli = fs.realpathSync(npmCli);
  let candidate = path.dirname(resolvedCli);
  while (true) {
    const manifestPath = path.join(candidate, "package.json");
    if (fs.existsSync(manifestPath)) {
      const stat = fs.lstatSync(manifestPath);
      requireCondition(
        stat.isFile() && !stat.isSymbolicLink(),
        "DEPENDENCY_SNAPSHOT_NPM_ROOT"
      );
      let manifest;
      try {
        manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
      } catch {
        throw new Error("DEPENDENCY_SNAPSHOT_NPM_ROOT");
      }
      if (manifest?.name === "npm") {
        const relativeCli = path.relative(candidate, resolvedCli);
        requireCondition(
          relativeCli === "bin/npm-cli.js" &&
            /^[0-9]+\.[0-9]+\.[0-9]+$/.test(manifest.version),
          "DEPENDENCY_SNAPSHOT_NPM_ROOT"
        );
        return Object.freeze({
          manifest,
          root: candidate
        });
      }
    }
    const parent = path.dirname(candidate);
    requireCondition(parent !== candidate, "DEPENDENCY_SNAPSHOT_NPM_ROOT");
    candidate = parent;
  }
}

export function createBuildToolchain({
  architecture = process.arch,
  gitExecutable,
  nodeExecutable = process.execPath,
  nodeVersion = process.version,
  npmCli,
  platform = process.platform
}) {
  const resolvedGit = fs.realpathSync(gitExecutable);
  const gitStat = fs.lstatSync(resolvedGit);
  requireCondition(
    path.isAbsolute(gitExecutable) &&
      resolvedGit === gitExecutable &&
      gitStat.isFile() &&
      !gitStat.isSymbolicLink(),
    "DEPENDENCY_SNAPSHOT_GIT_EXECUTABLE"
  );
  const gitResult = spawnSync(resolvedGit, ["--version"], {
    encoding: "utf8",
    env: {
      GIT_NO_LAZY_FETCH: "1",
      LANG: "C",
      LC_ALL: "C",
      PATH: "/usr/bin:/bin"
    },
    stdio: ["ignore", "pipe", "ignore"]
  });
  requireCondition(
    !gitResult.error &&
      gitResult.status === 0 &&
      /^git version [0-9]+\.[0-9]+\.[0-9]+(?: \(.+\))?$/.test(
        gitResult.stdout.trim()
      ),
    "DEPENDENCY_SNAPSHOT_GIT_VERSION"
  );
  const resolvedNode = fs.realpathSync(nodeExecutable);
  const nodeStat = fs.lstatSync(resolvedNode);
  requireCondition(
    nodeStat.isFile() && !nodeStat.isSymbolicLink(),
    "DEPENDENCY_SNAPSHOT_NODE_EXECUTABLE"
  );
  const npm = npmPackageRoot(npmCli);
  const { records, totalBytes } = walkDependencyTree(npm.root);
  requireCondition(records.length > 0, "DEPENDENCY_SNAPSHOT_NPM_EMPTY");
  return Object.freeze({
    schemaVersion: TOOLCHAIN_SCHEMA,
    architecture,
    gitExecutableSha256: sha256(fs.readFileSync(resolvedGit)),
    gitVersion: gitResult.stdout.trim().slice("git version ".length),
    nodeExecutableSha256: sha256(fs.readFileSync(resolvedNode)),
    nodeVersion,
    npmCliSha256: sha256(fs.readFileSync(fs.realpathSync(npmCli))),
    npmPackageBytes: totalBytes,
    npmPackageFileCount: records.length,
    npmPackageTreeDigest: recordsDigest(records),
    npmVersion: npm.manifest.version,
    platform
  });
}

export function validateDependencySnapshot(
  value,
  { packageJsonDigest, packageLockDigest }
) {
  requireCondition(
    exactKeys(value, [
      "fileCount",
      "installMode",
      "packageJsonDigest",
      "packageLockDigest",
      "schemaVersion",
      "symlinkCount",
      "totalBytes",
      "treeDigest"
    ]) &&
      value.schemaVersion === SNAPSHOT_SCHEMA &&
      value.installMode === "NPM_CI_IGNORE_SCRIPTS_CLEAN_CACHE" &&
      Number.isSafeInteger(value.fileCount) &&
      value.fileCount > 0 &&
      Number.isSafeInteger(value.totalBytes) &&
      value.totalBytes > 0 &&
      value.symlinkCount === 0 &&
      value.packageJsonDigest === packageJsonDigest &&
      value.packageLockDigest === packageLockDigest &&
      HEX_64.test(value.treeDigest),
    "DEPENDENCY_SNAPSHOT_RECEIPT"
  );
  return Object.freeze({ ...value });
}

export function validateBuildToolchain(value) {
  requireCondition(
    exactKeys(value, [
      "architecture",
      "gitExecutableSha256",
      "gitVersion",
      "nodeExecutableSha256",
      "nodeVersion",
      "npmCliSha256",
      "npmPackageBytes",
      "npmPackageFileCount",
      "npmPackageTreeDigest",
      "npmVersion",
      "platform",
      "schemaVersion"
    ]) &&
      value.schemaVersion === TOOLCHAIN_SCHEMA &&
      /^[0-9]+\.[0-9]+\.[0-9]+(?: \(.+\))?$/.test(value.gitVersion) &&
      /^v22\.[0-9]+\.[0-9]+$/.test(value.nodeVersion) &&
      /^[0-9]+\.[0-9]+\.[0-9]+$/.test(value.npmVersion) &&
      ["arm64", "x64"].includes(value.architecture) &&
      ["darwin", "linux"].includes(value.platform) &&
      HEX_64.test(value.nodeExecutableSha256) &&
      HEX_64.test(value.gitExecutableSha256) &&
      HEX_64.test(value.npmCliSha256) &&
      Number.isSafeInteger(value.npmPackageBytes) &&
      value.npmPackageBytes > 0 &&
      Number.isSafeInteger(value.npmPackageFileCount) &&
      value.npmPackageFileCount > 0 &&
      HEX_64.test(value.npmPackageTreeDigest),
    "DEPENDENCY_SNAPSHOT_TOOLCHAIN"
  );
  return Object.freeze({ ...value });
}

export const __test = Object.freeze({
  SNAPSHOT_SCHEMA,
  TOOLCHAIN_SCHEMA,
  npmPackageRoot,
  recordsDigest,
  walkDependencyTree
});
