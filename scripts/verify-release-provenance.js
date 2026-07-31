import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

import { verifyDependencyInventory } from "./verify-dependency-inventory.js";
import { verifyCurrentBundledThirdPartyNotices } from "./verify-bundled-third-party-notices.js";
import { verifyAccessibility } from "./verify-accessibility.js";
import { verifyReleaseClaims } from "./verify-release-claims.js";
import { verifyReleasePrivacy } from "./verify-release-privacy.js";
import { verifyReleaseRights } from "./verify-release-rights.js";
import { verifyReleaseSecurity } from "./verify-release-security.js";

const DEFAULT_ROOT = fileURLToPath(new URL("..", import.meta.url));
const OFFICIAL_REMOTE = "https://github.com/Flash-Bri/tideproof.git";
const EXPECTED_BRANCH = "main";
const CLEAN_ROOM_ROOT = "e198f4146d3d769ebdaf62927d3bbe92025e8340";
const SCHEMA = "tideproof.release-provenance.v5";
const HEX_40 = /^[0-9a-f]{40}$/;
const HEX_64 = /^[0-9a-f]{64}$/;

function assert(condition, code) {
  if (!condition) {
    throw new Error(code);
  }
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function isOfficialRemote(value) {
  return value === OFFICIAL_REMOTE || value === OFFICIAL_REMOTE.slice(0, -4);
}

function childEnvironment(source) {
  const environment = {};
  for (const [name, value] of Object.entries(source)) {
    if (
      name.startsWith("GIT_") ||
      /^(?:BASH_ENV|CDPATH|DYLD_.+|ENV|LD_PRELOAD|NODE_OPTIONS|NODE_PATH|NPM_CONFIG_.+)$/i.test(
        name
      ) ||
      /^(?:AWS_|DATABASE_URL$|PG(?:HOST|PORT|DATABASE|USER|PASSWORD|SERVICE|SERVICEFILE|PASSFILE)$|COCKROACH_.+|CRDB_.+|OPENAI_.+|ANTHROPIC_.+|GOOGLE_.+|OPENCLAW_.+|CODEX_.+|GH_TOKEN$|GITHUB_TOKEN$)/i.test(
        name
      ) ||
      /(TOKEN|SECRET|PASSWORD|API_KEY|PRIVATE_KEY|CREDENTIAL)/i.test(name)
    ) {
      continue;
    }
    environment[name] = value;
  }
  environment.AWS_CONFIG_FILE = "/dev/null";
  environment.AWS_EC2_METADATA_DISABLED = "true";
  environment.AWS_SHARED_CREDENTIALS_FILE = "/dev/null";
  environment.GIT_CONFIG_GLOBAL = "/dev/null";
  environment.GIT_CONFIG_NOSYSTEM = "1";
  environment.GIT_TERMINAL_PROMPT = "0";
  environment.npm_config_always_auth = "false";
  environment.npm_config_registry = "https://registry.npmjs.org/";
  environment.npm_config_update_notifier = "false";
  environment.npm_config_userconfig = "/dev/null";
  return environment;
}

function defaultRunner(projectRoot) {
  return (command, args, options = {}) =>
    spawnSync(command, args, {
      cwd: projectRoot,
      encoding: Object.hasOwn(options, "encoding")
        ? options.encoding
        : "utf8",
      env: childEnvironment(process.env),
      input: options.input,
      maxBuffer: options.maxBuffer ?? 32 * 1024 * 1024
    });
}

function checkedCommand(run, command, args, code) {
  const result = run(command, args);
  assert(
    result &&
      !result.error &&
      result.status === 0 &&
      typeof result.stdout === "string",
    code
  );
  return result.stdout;
}

function textCommand(run, command, args, code) {
  return checkedCommand(run, command, args, code).trim();
}

function jsonCommand(run, command, args, code) {
  const output = checkedCommand(run, command, args, code);
  try {
    return JSON.parse(output);
  } catch {
    throw new Error(`${code}_JSON`);
  }
}

function fetchOfficialMain(run) {
  checkedCommand(
    run,
    "git",
    [
      "-c",
      "http.https://github.com/.extraheader=",
      "fetch",
      "--quiet",
      "--no-tags",
      "origin",
      "refs/heads/main:refs/remotes/origin/main"
    ],
    "RELEASE_PROVENANCE_GIT_FETCH"
  );
}

function positiveInteger(value, code) {
  assert(/^[1-9][0-9]*$/.test(value), code);
  const parsed = Number(value);
  assert(Number.isSafeInteger(parsed), code);
  return parsed;
}

function nonnegativeInteger(value, code) {
  assert(/^(?:0|[1-9][0-9]*)$/.test(value), code);
  const parsed = Number(value);
  assert(Number.isSafeInteger(parsed), code);
  return parsed;
}

function readJson(filePath, code) {
  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch {
    throw new Error(code);
  }
  assert(parsed && typeof parsed === "object" && !Array.isArray(parsed), code);
  return parsed;
}

function packageNameFromLockPath(lockPath) {
  assert(
    typeof lockPath === "string" &&
      lockPath === lockPath.trim() &&
      !path.isAbsolute(lockPath) &&
      !/[\\\r\n\0]/.test(lockPath) &&
      lockPath.split("/").every((segment) => segment !== "" && segment !== ".."),
    "RELEASE_PROVENANCE_LOCK_PATH"
  );
  const marker = "node_modules/";
  const markerIndex = lockPath.lastIndexOf(marker);
  assert(markerIndex !== -1, "RELEASE_PROVENANCE_LOCK_PATH");
  const name = lockPath.slice(markerIndex + marker.length);
  assert(
    /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/i.test(name),
    "RELEASE_PROVENANCE_PACKAGE_NAME"
  );
  return name;
}

export function validateInstalledTree({ projectRoot, packageLock, query }) {
  assert(
    packageLock?.lockfileVersion === 3 &&
      packageLock.packages &&
      typeof packageLock.packages === "object" &&
      !Array.isArray(packageLock.packages),
    "RELEASE_PROVENANCE_LOCK"
  );
  assert(Array.isArray(query), "RELEASE_PROVENANCE_NPM_QUERY");

  const lockRoot = packageLock.packages[""];
  const queryRoots = query.filter((entry) => entry?.location === "");
  assert(
    lockRoot &&
      queryRoots.length === 1 &&
      queryRoots[0].name === lockRoot.name &&
      queryRoots[0].version === lockRoot.version,
    "RELEASE_PROVENANCE_NPM_ROOT"
  );

  const lockEntries = Object.entries(packageLock.packages)
    .filter(([lockPath]) => lockPath !== "")
    .sort(([left], [right]) => left.localeCompare(right));
  assert(lockEntries.length > 0, "RELEASE_PROVENANCE_LOCK_EMPTY");
  const actualEntries = query
    .filter((entry) => entry?.location !== "")
    .sort((left, right) => String(left.location).localeCompare(String(right.location)));
  const actualLocations = actualEntries.map((entry) => entry.location);
  assert(
    new Set(actualLocations).size === actualLocations.length,
    "RELEASE_PROVENANCE_NPM_DUPLICATE"
  );

  const lockByPath = new Map(lockEntries);
  for (const entry of actualEntries) {
    const lockPath = entry.location;
    const metadata = lockByPath.get(lockPath);
    const packageName = packageNameFromLockPath(lockPath);
    assert(
      metadata &&
        typeof metadata.version === "string" &&
        entry.name === packageName &&
        entry.version === metadata.version &&
        entry.resolved === metadata.resolved &&
        entry.inBundle === false &&
        entry.overridden === false,
      "RELEASE_PROVENANCE_NPM_PACKAGE"
    );

    const packageRoot = path.resolve(projectRoot, lockPath);
    const relative = path.relative(projectRoot, packageRoot);
    assert(
      relative === lockPath.split("/").join(path.sep) &&
        entry.path === packageRoot &&
        entry.realpath === packageRoot,
      "RELEASE_PROVENANCE_NPM_LOCATION"
    );
    let rootStat;
    let manifestStat;
    try {
      rootStat = fs.lstatSync(packageRoot);
      manifestStat = fs.lstatSync(path.join(packageRoot, "package.json"));
    } catch {
      throw new Error("RELEASE_PROVENANCE_NPM_FILES");
    }
    assert(
      rootStat.isDirectory() &&
        !rootStat.isSymbolicLink() &&
        manifestStat.isFile() &&
        !manifestStat.isSymbolicLink() &&
        fs.realpathSync(packageRoot) === packageRoot,
      "RELEASE_PROVENANCE_NPM_FILES"
    );
    const manifest = readJson(
      path.join(packageRoot, "package.json"),
      "RELEASE_PROVENANCE_NPM_MANIFEST"
    );
    assert(
      manifest.name === packageName && manifest.version === metadata.version,
      "RELEASE_PROVENANCE_NPM_MANIFEST"
    );
  }

  const actualSet = new Set(actualLocations);
  const requiredMissing = lockEntries
    .filter(([lockPath, metadata]) => !metadata.optional && !actualSet.has(lockPath))
    .map(([lockPath]) => lockPath);
  const omittedOptional = lockEntries
    .filter(([lockPath, metadata]) => metadata.optional && !actualSet.has(lockPath))
    .map(([lockPath]) => lockPath);
  assert(requiredMissing.length === 0, "RELEASE_PROVENANCE_NPM_REQUIRED_MISSING");

  return {
    status: "PASS",
    lockedPackageCount: lockEntries.length,
    installedPackageCount: actualEntries.length,
    installedRuntimeCount: actualEntries.filter(
      (entry) => lockByPath.get(entry.location).dev !== true
    ).length,
    installedDevelopmentOnlyCount: actualEntries.filter(
      (entry) => lockByPath.get(entry.location).dev === true
    ).length,
    installedOptionalCount: actualEntries.filter(
      (entry) => lockByPath.get(entry.location).optional === true
    ).length,
    omittedOptionalCount: omittedOptional.length,
    extraPackageCount: 0,
    mismatchedPackageCount: 0
  };
}

export function validateTrackedTree(output) {
  assert(typeof output === "string" && output.endsWith("\0"), "RELEASE_PROVENANCE_TREE");
  const records = output.slice(0, -1).split("\0");
  assert(records.length > 0, "RELEASE_PROVENANCE_TREE_EMPTY");
  const paths = new Set();
  let executableFileCount = 0;
  for (const record of records) {
    const tab = record.indexOf("\t");
    assert(tab > 0, "RELEASE_PROVENANCE_TREE_RECORD");
    const header = record.slice(0, tab).split(" ");
    const filePath = record.slice(tab + 1);
    assert(
      header.length === 3 &&
        (header[0] === "100644" || header[0] === "100755") &&
        header[1] === "blob" &&
        HEX_40.test(header[2]) &&
        filePath.length > 0 &&
        !filePath.includes("\0") &&
        !paths.has(filePath),
      "RELEASE_PROVENANCE_TREE_RECORD"
    );
    paths.add(filePath);
    if (header[0] === "100755") {
      executableFileCount += 1;
    }
  }
  assert(!paths.has(".gitmodules"), "RELEASE_PROVENANCE_SUBMODULE_METADATA");
  return {
    fileCount: records.length,
    regularFileCount: records.length,
    executableFileCount,
    symlinkCount: 0,
    gitlinkCount: 0
  };
}

function checkoutSnapshot(run) {
  return {
    branch: textCommand(
      run,
      "git",
      ["symbolic-ref", "--short", "HEAD"],
      "RELEASE_PROVENANCE_GIT_BRANCH"
    ),
    status: textCommand(
      run,
      "git",
      ["status", "--porcelain=v1", "--untracked-files=all"],
      "RELEASE_PROVENANCE_GIT_STATUS"
    ),
    commit: textCommand(
      run,
      "git",
      ["rev-parse", "HEAD"],
      "RELEASE_PROVENANCE_GIT_HEAD"
    ),
    originMain: textCommand(
      run,
      "git",
      ["rev-parse", "refs/remotes/origin/main"],
      "RELEASE_PROVENANCE_GIT_ORIGIN_MAIN"
    ),
    tree: textCommand(
      run,
      "git",
      ["rev-parse", "HEAD^{tree}"],
      "RELEASE_PROVENANCE_GIT_TREE"
    )
  };
}

function assertGitMetadataFileAbsent(run, projectRoot, gitPath, code) {
  const candidate = textCommand(
    run,
    "git",
    ["rev-parse", "--git-path", gitPath],
    code
  );
  assert(candidate.length > 0 && !candidate.includes("\0"), code);
  const resolved = path.isAbsolute(candidate)
    ? path.normalize(candidate)
    : path.resolve(projectRoot, candidate);
  try {
    fs.lstatSync(resolved);
  } catch (error) {
    if (error?.code === "ENOENT") {
      return;
    }
    throw new Error(code);
  }
  throw new Error(code);
}

function assertExactCheckout(run) {
  const remote = textCommand(
    run,
    "git",
    ["remote", "get-url", "origin"],
    "RELEASE_PROVENANCE_GIT_REMOTE"
  );
  assert(isOfficialRemote(remote), "RELEASE_PROVENANCE_GIT_REMOTE");
  fetchOfficialMain(run);
  const snapshot = checkoutSnapshot(run);
  assert(
    snapshot.branch === EXPECTED_BRANCH &&
      snapshot.status === "" &&
      HEX_40.test(snapshot.commit) &&
      HEX_40.test(snapshot.originMain) &&
      HEX_40.test(snapshot.tree) &&
      snapshot.commit === snapshot.originMain,
    "RELEASE_PROVENANCE_CHECKOUT"
  );
  return { ...snapshot, officialRemote: OFFICIAL_REMOTE };
}

function assertCheckoutUnchanged(run, initial) {
  fetchOfficialMain(run);
  const current = checkoutSnapshot(run);
  assert(
    current.branch === initial.branch &&
      current.status === "" &&
      current.commit === initial.commit &&
      current.originMain === initial.originMain &&
      current.tree === initial.tree,
    "RELEASE_PROVENANCE_CHECKOUT_CHANGED"
  );
}

export function verifyRepositoryHistory({ run, projectRoot = DEFAULT_ROOT }) {
  const checkout = assertExactCheckout(run);
  assert(
    textCommand(
      run,
      "git",
      ["rev-parse", "--is-shallow-repository"],
      "RELEASE_PROVENANCE_GIT_SHALLOW"
    ) === "false",
    "RELEASE_PROVENANCE_GIT_SHALLOW"
  );
  assert(
    textCommand(run, "git", ["replace", "-l"], "RELEASE_PROVENANCE_GIT_REPLACE") === "",
    "RELEASE_PROVENANCE_GIT_REPLACE"
  );
  assertGitMetadataFileAbsent(
    run,
    projectRoot,
    "info/grafts",
    "RELEASE_PROVENANCE_GIT_GRAFTS"
  );
  assertGitMetadataFileAbsent(
    run,
    projectRoot,
    "objects/info/alternates",
    "RELEASE_PROVENANCE_GIT_ALTERNATES"
  );
  const roots = textCommand(
    run,
    "git",
    ["rev-list", "--max-parents=0", "HEAD"],
    "RELEASE_PROVENANCE_GIT_ROOT"
  ).split("\n");
  assert(
    roots.length === 1 && roots[0] === CLEAN_ROOM_ROOT,
    "RELEASE_PROVENANCE_GIT_ROOT"
  );
  const commitCount = positiveInteger(
    textCommand(
      run,
      "git",
      ["rev-list", "--count", "HEAD"],
      "RELEASE_PROVENANCE_GIT_COMMIT_COUNT"
    ),
    "RELEASE_PROVENANCE_GIT_COMMIT_COUNT"
  );
  const mergeCommitCount = nonnegativeInteger(
    textCommand(
      run,
      "git",
      ["rev-list", "--count", "--merges", "HEAD"],
      "RELEASE_PROVENANCE_GIT_MERGE_COUNT"
    ),
    "RELEASE_PROVENANCE_GIT_MERGE_COUNT"
  );
  assert(mergeCommitCount < commitCount, "RELEASE_PROVENANCE_GIT_MERGE_COUNT");
  const [rootAuthorTime, rootCommitterTime] = textCommand(
    run,
    "git",
    ["show", "-s", "--format=%aI%x09%cI", CLEAN_ROOM_ROOT],
    "RELEASE_PROVENANCE_GIT_ROOT_TIME"
  ).split("\t");
  const [headAuthorTime, headCommitterTime] = textCommand(
    run,
    "git",
    ["show", "-s", "--format=%aI%x09%cI", "HEAD"],
    "RELEASE_PROVENANCE_GIT_HEAD_TIME"
  ).split("\t");
  assert(
    rootAuthorTime.startsWith("2026-07-29T") &&
      rootCommitterTime.startsWith("2026-07-29T") &&
      [rootAuthorTime, rootCommitterTime, headAuthorTime, headCommitterTime].every(
        (value) => Number.isFinite(Date.parse(value))
      ),
    "RELEASE_PROVENANCE_GIT_TIME"
  );
  const trackedTree = validateTrackedTree(
    checkedCommand(
      run,
      "git",
      ["ls-tree", "-r", "-z", "--full-tree", "HEAD"],
      "RELEASE_PROVENANCE_GIT_LS_TREE"
    )
  );
  checkedCommand(
    run,
    "git",
    ["fsck", "--strict", "--no-dangling", "HEAD"],
    "RELEASE_PROVENANCE_GIT_FSCK"
  );
  return {
    checkout,
    history: {
      rootCommit: CLEAN_ROOM_ROOT,
      commitCount,
      mergeCommitCount,
      rootAuthorTime,
      rootCommitterTime,
      headAuthorTime,
      headCommitterTime,
      shallow: false,
      replaceRefCount: 0,
      legacyGraftFilePresent: false,
      alternateObjectDatabaseCount: 0,
      objectIntegrity: true
    },
    trackedTree
  };
}

export async function runReleaseProvenance({
  projectRoot = DEFAULT_ROOT,
  run = defaultRunner(projectRoot),
  verifyAccessibilityReceipt = verifyAccessibility,
  verifyClaims = verifyReleaseClaims,
  verifyInventory = verifyDependencyInventory,
  verifyNotices = verifyCurrentBundledThirdPartyNotices,
  verifyPrivacy = verifyReleasePrivacy,
  verifyRights = verifyReleaseRights,
  verifySecurity = verifyReleaseSecurity
} = {}) {
  const source = verifyRepositoryHistory({ run, projectRoot });
  const claims = verifyClaims({ rootDir: projectRoot });
  assert(
    claims?.schemaVersion ===
      "tideproof.release-claims-verification.v1" &&
      claims.status === "CURRENT_PUBLIC_CLAIMS_PASS" &&
      claims.finalReleaseReady === false &&
      /^\d{4}-\d{2}-\d{2}$/.test(claims.reviewedOn) &&
      claims.manifestPath === "RELEASE_CLAIMS_MANIFEST.json" &&
      HEX_64.test(claims.manifestSha256) &&
      HEX_64.test(claims.proofManifestSha256) &&
      claims.claimCount === 11 &&
      claims.claimStates?.VERIFIED === 7 &&
      claims.claimStates?.PARTIAL === 4 &&
      claims.claimStates?.PENDING === 0 &&
      claims.surfaceCount === 13 &&
      claims.stopTokenCount === 13 &&
      claims.uncheckedGateCount === 14 &&
      Array.isArray(claims.externalUrls) &&
      claims.externalUrls.length === 6 &&
      Array.isArray(claims.finalReleaseRequirements) &&
      claims.finalReleaseRequirements.length === 2 &&
      claims.checks &&
      Object.values(claims.checks).every((value) => value === true) &&
      typeof claims.claimBoundary === "string" &&
      claims.claimBoundary.length > 0,
    "RELEASE_PROVENANCE_CLAIMS"
  );
  const privacy = verifyPrivacy({ rootDir: projectRoot, run });
  assert(
    privacy?.schemaVersion ===
      "tideproof.release-privacy-verification.v1" &&
      privacy.status === "CURRENT_PUBLIC_HISTORY_PASS" &&
      privacy.finalReleaseReady === false &&
      privacy.sourceCommit === source.checkout.commit &&
      privacy.treeDigest === source.checkout.tree &&
      /^\d{4}-\d{2}-\d{2}$/.test(privacy.reviewedOn) &&
      privacy.manifestPath === "RELEASE_PRIVACY_MANIFEST.json" &&
      HEX_64.test(privacy.manifestSha256) &&
      Number.isSafeInteger(privacy.commitCount) &&
      privacy.commitCount > 0 &&
      Number.isSafeInteger(privacy.commitIdentityCount) &&
      privacy.commitIdentityCount > 0 &&
      Number.isSafeInteger(privacy.trackedFileCount) &&
      privacy.trackedFileCount > 0 &&
      Number.isSafeInteger(privacy.reachableBlobCount) &&
      privacy.reachableBlobCount >= privacy.trackedFileCount &&
      Number.isSafeInteger(privacy.scannedBytes) &&
      privacy.scannedBytes > 0 &&
      Number.isSafeInteger(privacy.findingCount) &&
      privacy.findingCount >= 0 &&
      Number.isSafeInteger(privacy.allowanceCount) &&
      privacy.allowanceCount > 0 &&
      Array.isArray(privacy.finalReleaseRequirements) &&
      privacy.finalReleaseRequirements.length === 2 &&
      privacy.checks &&
      Object.values(privacy.checks).every((value) => value === true) &&
      typeof privacy.claimBoundary === "string" &&
      privacy.claimBoundary.length > 0,
    "RELEASE_PROVENANCE_PRIVACY"
  );
  const rights = verifyRights({ rootDir: projectRoot });
  assert(
    rights?.schemaVersion ===
      "tideproof.release-rights-verification.v1" &&
      rights.status === "CURRENT_SURFACES_PASS" &&
      rights.finalReleaseReady === false &&
      HEX_64.test(rights.manifestSha256) &&
      HEX_64.test(rights.ledgerSha256) &&
      Number.isSafeInteger(rights.distributedFileCount) &&
      rights.distributedFileCount > 0 &&
      Number.isSafeInteger(rights.currentClearedFileCount) &&
      rights.currentClearedFileCount > 0 &&
      Number.isSafeInteger(rights.interimOnlyFileCount) &&
      rights.interimOnlyFileCount === 0 &&
      rights.currentClearedFileCount + rights.interimOnlyFileCount ===
        rights.distributedFileCount &&
      Number.isSafeInteger(rights.repositoryMediaFileCount) &&
      rights.repositoryMediaFileCount > 0 &&
      Number.isSafeInteger(rights.trackedFileCount) &&
      rights.trackedFileCount >= rights.distributedFileCount &&
      Number.isSafeInteger(rights.prohibitedSourceDigestCount) &&
      rights.prohibitedSourceDigestCount > 0 &&
      Array.isArray(rights.finalReleaseRequirements) &&
      rights.finalReleaseRequirements.length > 0 &&
      rights.checks &&
      Object.values(rights.checks).every((value) => value === true),
    "RELEASE_PROVENANCE_RIGHTS"
  );
  const accessibility = verifyAccessibilityReceipt({
    rootDir: projectRoot,
    verifyRights: () => rights
  });
  assert(
    accessibility?.schemaVersion ===
      "tideproof.accessibility-static.v1" &&
      accessibility.status === "STATIC_SOURCE_PASS" &&
      accessibility.finalReleaseReady === false &&
      accessibility.standardTarget === "WCAG_2_2_AA" &&
      accessibility.rightsManifestSha256 === rights.manifestSha256 &&
      Array.isArray(accessibility.reviewedFiles) &&
      accessibility.reviewedFiles.length === 4 &&
      accessibility.reviewedFiles.every(
        (file) =>
          typeof file?.id === "string" &&
          typeof file.path === "string" &&
          HEX_64.test(file.sha256)
      ) &&
      Array.isArray(accessibility.contrast) &&
      accessibility.contrast.length === 11 &&
      accessibility.contrast.every(
        (pair) =>
          Number.isFinite(pair?.ratio) &&
          Number.isFinite(pair.minimumRatio) &&
          pair.ratio >= pair.minimumRatio
      ) &&
      Array.isArray(accessibility.remainingRequirements) &&
      accessibility.remainingRequirements.length === 3 &&
      accessibility.checks &&
      Object.values(accessibility.checks).every((value) => value === true) &&
      typeof accessibility.claimBoundary === "string" &&
      accessibility.claimBoundary.length > 0,
    "RELEASE_PROVENANCE_ACCESSIBILITY"
  );
  const security = verifySecurity({ rootDir: projectRoot });
  assert(
    security?.schemaVersion ===
      "tideproof.release-security-verification.v1" &&
      security.status === "CURRENT_SOURCE_SECURITY_PASS" &&
      security.finalReleaseReady === false &&
      /^\d{4}-\d{2}-\d{2}$/.test(security.reviewedOn) &&
      security.manifestPath === "RELEASE_SECURITY_MANIFEST.json" &&
      HEX_64.test(security.manifestSha256) &&
      security.surfaceCount === 18 &&
      security.publicPathCount === 10 &&
      security.securityHeaderCount === 9 &&
      security.negativeProbeCount === 6 &&
      security.publicRouteCount === 10 &&
      security.iamRoleCount === 7 &&
      security.lambdaPermissionCount === 3 &&
      security.boundedFunctionCount === 5 &&
      security.logGroupCount === 11 &&
      Array.isArray(security.finalReleaseRequirements) &&
      security.finalReleaseRequirements.length === 2 &&
      security.checks &&
      Object.values(security.checks).every((value) => value === true) &&
      typeof security.claimBoundary === "string" &&
      security.claimBoundary.length > 0,
    "RELEASE_PROVENANCE_SECURITY"
  );
  const lockBytes = fs.readFileSync(path.join(projectRoot, "package-lock.json"));
  const packageLock = readJson(
    path.join(projectRoot, "package-lock.json"),
    "RELEASE_PROVENANCE_LOCK"
  );
  const installedTree = validateInstalledTree({
    projectRoot: path.resolve(projectRoot),
    packageLock,
    query: jsonCommand(
      run,
      "npm",
      ["query", "*", "--json"],
      "RELEASE_PROVENANCE_NPM_QUERY"
    )
  });
  installedTree.packageLockSha256 = sha256(lockBytes);

  const inventory = verifyInventory({ rootDir: projectRoot });
  assert(
    inventory?.status === "PASS" &&
      inventory.sourceLockSha256 === installedTree.packageLockSha256 &&
      inventory.packageCount === installedTree.lockedPackageCount,
    "RELEASE_PROVENANCE_INVENTORY"
  );
  const notices = await verifyNotices({ rootDir: projectRoot });
  assert(
    notices?.status === "PASS" &&
      notices.packageLockSha256 === installedTree.packageLockSha256 &&
      HEX_64.test(notices.noticeSha256) &&
      notices.packageCount > 0 &&
      notices.packageCount <= installedTree.installedPackageCount &&
      notices.artifactPackages &&
      typeof notices.artifactPackages === "object",
    "RELEASE_PROVENANCE_NOTICES"
  );
  assertCheckoutUnchanged(run, source.checkout);

  return {
    schemaVersion: SCHEMA,
    status: "PASS",
    source: {
      commit: source.checkout.commit,
      tree: source.checkout.tree,
      branch: source.checkout.branch,
      originMain: source.checkout.originMain,
      officialRemote: source.checkout.officialRemote,
      cleanRoomRoot: source.history.rootCommit
    },
    history: source.history,
    trackedTree: source.trackedTree,
    claims,
    privacy,
    rights,
    accessibility,
    security,
    dependencies: {
      installedTree,
      inventory,
      bundledThirdPartyNotices: {
        status: notices.status,
        noticePath: notices.noticePath,
        noticeSha256: notices.noticeSha256,
        noticeBytes: notices.noticeBytes,
        packageLockSha256: notices.packageLockSha256,
        packageCount: notices.packageCount,
        licenseTextCount: notices.licenseTextCount,
        fallbackCount: notices.fallbackCount,
        licenses: notices.licenses,
        artifactPackages: notices.artifactPackages
      }
    },
    checks: {
      officialCleanCheckout: true,
      fullSingleRootHistory: true,
      objectIntegrity: true,
      replaceRefsAbsent: true,
      legacyGraftsAbsent: true,
      alternateObjectDatabasesAbsent: true,
      trackedSymlinksAbsent: true,
      submodulesAbsent: true,
      installedTreeMatchesLock: true,
      dependencyInventoryMatchesLock: true,
      bundledThirdPartyNoticesMatchInputs: true,
      currentClaimSurfacesVerified: true,
      releasePrivacyVerified: true,
      currentSurfaceRightsVerified: true,
      staticAccessibilityVerified: true,
      currentSourceSecurityVerified: true,
      cleanBeforeAndAfter: true
    },
    claimBoundary:
      "This receipt binds Git ancestry, tracked file modes, the reviewed pending-state public claim surfaces, the bounded current-history privacy scan, the current-surface rights inventory, the bounded static accessibility receipt, the current source security and abuse-boundary receipt, installed package identities, the dependency inventory, and bundle notice inputs to the exact official checkout. The claims, privacy, rights, accessibility, and security controls remain explicitly non-final; they do not prove claim truth, exhaustive secret or personal-data absence, grant rights, establish WCAG conformance, or establish vulnerability absence. This receipt does not independently prove originality, legal clearance, deployed bytes, live AWS behavior, human accessibility, or final submission approval."
  };
}

async function main() {
  assert(process.argv.length === 2, "RELEASE_PROVENANCE_ARGUMENT");
  const receipt = await runReleaseProvenance();
  process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
}

const startedDirectly =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (startedDirectly) {
  main().catch((error) => {
    const message = String(error?.message ?? "");
    const code = /^RELEASE_PROVENANCE_[A-Z0-9_]{1,120}$/.test(message)
      ? message
      : "RELEASE_PROVENANCE_UNKNOWN";
    process.stderr.write(`TIDEPROOF_RELEASE_PROVENANCE_FAILED:${code}\n`);
    process.exitCode = 1;
  });
}

export const __test = Object.freeze({
  CLEAN_ROOM_ROOT,
  EXPECTED_BRANCH,
  OFFICIAL_REMOTE,
  childEnvironment,
  isOfficialRemote
});
