import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const DEFAULT_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  ".."
);
const MANIFEST_PATH = "RENAME_MIGRATION_MANIFEST.json";
const FORMER_REPOSITORY_URL = "https://github.com/Flash-Bri/tideproof";

const EXPECTED_MANIFEST = Object.freeze({
  schema: "prooftoact.rename-migration.v1",
  status: "SOURCE_MIGRATION_IN_PROGRESS",
  decisionDate: "2026-08-03",
  approvedName: "ProofToAct",
  subtitle: "Admissibility Memory for High-Stakes Agents",
  formerWorkingName: "Tideproof",
  repository: "https://github.com/Flash-Bri/prooftoact",
  packageName: "prooftoact-admissibility-memory",
  futureAwsMainStack: "prooftoact-gate2",
  legacyAwsBootstrapStack: "tideproof-gate2-artifacts",
  legacyAwsMainStackBlocked: "tideproof-gate2"
});

const EXPECTED_EVIDENCE_BASELINE = Object.freeze([
  ["evidence/accessibility-browser-review-2026-07-31.md", "ae5a322ed307d4a6c34640d1c685bf3460fd8a3d03e4a5caddabc3207a7c0677"],
  ["evidence/accessibility-static-review-2026-07-31.md", "f00edccd11c1cd0d1a7abf0a2b28ae75dbe96ebc1626bfcc5515a72d2f27a28b"],
  ["evidence/architecture-asset-release-2026-07-31.md", "44fba1df65a6a5d0ad4b57ab4478f1bc210c119bc19e870d6bce43580b4839ef"],
  ["evidence/domain-cost-owner-record-2026-07-30.md", "752cdbbb2488c51e6d47ed80c748b653d731f1b7eea7d0cf2d34dc4e701ce566"],
  ["evidence/gate1-ambiguity-2026-07-30.md", "6ce3446ce19c82ecb52b178c4d00d080fa9281a11bfecefdd5fb8050a3ae0a1b"],
  ["evidence/gate1-authority-2026-07-30.md", "418a53cf3ef62d4abd19a65f2f2abb2b2355652b90ec7e72438fd69b6aa8f29d"],
  ["evidence/gate1-managed-mcp-2026-07-29.md", "0608b7ededc94c4b79197f7fe6f1b033fcb2ec20915ec67d244847467e3d4d38"],
  ["evidence/gate1-recovery-broker-2026-07-30.md", "819f510dc62d289b2cbdab268abfe7440ff0a50cca18e457efe776b5a17be51c"],
  ["evidence/gate1-recovery-mcp-2026-07-29.md", "fcad5ddb51ad66347425cff93497cb321e7a3697178a683b0a032eee9273268e"],
  ["evidence/gate1-vector-2026-07-29.md", "83271ec1b62a800b533a92d7c3cd2c191b104de2c47cec7c5aecd4404f8ddc45"],
  ["evidence/gate2-authority-local-validation-79476df-2026-07-31.md", "2f6fa495ec54e36bb858477c264f8100358bbc772f43c49a93c37daf7e83ad8b"],
  ["evidence/gate2-console-stop-receipt-2026-07-30.md", "7a891b1810d8343e19c3cff40591302b2c483b8fdacf7b68edf68596ad18258d"],
  ["evidence/gate2-cost-guard-2026-07-30.json", "b9e0e8487329d86b9c8fd614ce65fc0dd859ab6035701acff3d079a1be693b14"],
  ["evidence/gate2-historical-upload-receipt-0ef4dba-2026-07-30.json", "25fc1edfd633dfcab417ea1d94ce8a5b87c31a36050e0fbf4311fd2d6081f276"],
  ["evidence/gate2-predeployment-local-validation-9aa7f2e-2026-07-30.md", "cfa7d93b458e4aebd254dfddf7e88a0c98f0dc2ecb2f65e6e9da5c1505278ac3"],
  ["evidence/gate2-release-build-4acafa9-2026-07-30.md", "8c4aaca79057413aac27a296dd3f0c46793b9fdb19917ade8974d8bab735ec1b"],
  ["evidence/github-release-governance-2026-08-01.json", "527eeea8909f1006fa4337e7517ded81907e46548fa395eacad9ec38284a65a8"],
  ["evidence/local-judge-path-e2b247a-2026-07-30.md", "b3ed9414195b224482228e1ea22a4fcf513766551c5d082f976376e69b7f026e"],
  ["evidence/proof-manifest-baseline-2026-07-31.md", "35d743fe89a3f1fc13499bd9df509e9f922fe3a659231db840a842d01af2a489"],
  ["evidence/public-source-release-081b580-2026-07-30.md", "2b1d58371034fc394ff5ca203391529a15c039f91f7dab691ec2b7b07c8f238a"]
].map(([itemPath, itemSha256]) =>
  Object.freeze({ path: itemPath, sha256: itemSha256 })
));

const EXPECTED_HISTORICAL_NAME_COUNTS = Object.freeze({
  "RENAME_MIGRATION_MANIFEST.json": 1,
  "docs/PRIOR_ART.md": 3,
  "docs/RENAME_MIGRATION.md": 3,
  "docs/SUBMISSION_PACKET.md": 2,
  "docs/media/RIGHTS.md": 1,
  "evidence/architecture-asset-release-2026-07-31.md": 4,
  "evidence/architecture-asset-rename-2026-08-03.md": 1,
  "evidence/domain-cost-owner-record-2026-07-30.md": 4,
  "evidence/gate1-ambiguity-2026-07-30.md": 3,
  "evidence/gate1-authority-2026-07-30.md": 1,
  "evidence/gate1-managed-mcp-2026-07-29.md": 2,
  "evidence/gate1-recovery-broker-2026-07-30.md": 1,
  "evidence/gate1-recovery-mcp-2026-07-29.md": 1,
  "evidence/gate1-vector-2026-07-29.md": 1,
  "evidence/gate2-release-build-4acafa9-2026-07-30.md": 1,
  "evidence/local-judge-path-e2b247a-2026-07-30.md": 1,
  "evidence/proof-manifest-baseline-2026-07-31.md": 1,
  "evidence/public-source-release-081b580-2026-07-30.md": 1,
  "infra/aws/bootstrap-template.json": 2,
  "scripts/verify-brand-migration.js": 3,
  "src/cloud/aws-gate2-template.js": 2
});

const EXPECTED_FORMER_REPOSITORY_COUNTS = Object.freeze({
  "CLEAN_ROOM.md": 1,
  "evidence/github-release-governance-2026-08-01.json": 2,
  "evidence/public-source-release-081b580-2026-07-30.md": 2,
  "scripts/verify-brand-migration.js": 1,
  "scripts/verify-release-governance.js": 2
});

const EXPECTED_DOMAIN_REFERENCE_COUNTS = Object.freeze({
  "docs/COST_GATES.md": 2,
  "docs/PRIOR_ART.md": 2,
  "docs/RELEASE_COST.md": 1,
  "docs/RENAME_MIGRATION.md": 1,
  "evidence/domain-cost-owner-record-2026-07-30.md": 1,
  "src/cloud/aws-gate2-preflight.js": 1,
  "test/release-claims.test.js": 1
});

const DOMAIN_SELF_REFERENCE_PATHS = new Set([
  "scripts/verify-brand-migration.js",
  "test/brand-migration.test.js"
]);

const STRICT_CURRENT_BRAND_SURFACES = Object.freeze([
  "CONTRIBUTING.md",
  "LICENSE",
  "README.md",
  "SECURITY.md",
  "docs/ARCHITECTURE.md",
  "docs/DEMO_SCRIPT.md",
  "docs/GOAL.md",
  "docs/RELEASE_SUBMISSION.md",
  "docs/WINNING_PLAN.md",
  "package-lock.json",
  "package.json",
  "web/app.js",
  "web/index.html"
]);

function requireCondition(condition, code) {
  if (!condition) {
    throw new Error(code);
  }
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function sorted(values) {
  return [...values].sort((left, right) => left.localeCompare(right));
}

function safeRelativePath(relativePath, code) {
  requireCondition(
    typeof relativePath === "string" &&
      relativePath.length > 0 &&
      relativePath === relativePath.replaceAll("\\", "/") &&
      !path.posix.isAbsolute(relativePath) &&
      relativePath.split("/").every((part) => part !== "" && part !== ".."),
    code
  );
}

function readRegularFile(rootDir, relativePath, code) {
  safeRelativePath(relativePath, code);
  let current = path.resolve(rootDir);
  let stat;
  try {
    for (const part of relativePath.split("/")) {
      current = path.join(current, part);
      stat = fs.lstatSync(current);
      requireCondition(!stat.isSymbolicLink(), code);
    }
  } catch {
    throw new Error(code);
  }
  requireCondition(stat?.isFile(), code);
  return fs.readFileSync(current);
}

function parseCanonicalJson(bytes, code) {
  let parsed;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new Error(code);
  }
  requireCondition(
    parsed &&
      typeof parsed === "object" &&
      !Array.isArray(parsed) &&
      bytes.toString("utf8") === `${JSON.stringify(parsed, null, 2)}\n`,
    code
  );
  return parsed;
}

function trackedFiles(rootDir) {
  return execFileSync(
    "git",
    ["ls-files", "--cached", "--others", "--exclude-standard", "-z"],
    { cwd: rootDir }
  )
    .toString("utf8")
    .split("\0")
    .filter(Boolean);
}

function exactManifest(manifest) {
  const expectedKeys = sorted([
    ...Object.keys(EXPECTED_MANIFEST),
    "evidenceBaseline"
  ]);
  requireCondition(
    JSON.stringify(sorted(Object.keys(manifest))) === JSON.stringify(expectedKeys),
    "BRAND_MANIFEST_KEYS"
  );
  for (const [key, expected] of Object.entries(EXPECTED_MANIFEST)) {
    requireCondition(manifest[key] === expected, `BRAND_MANIFEST_FIELD:${key}`);
  }
  requireCondition(
    JSON.stringify(manifest.evidenceBaseline) ===
      JSON.stringify(EXPECTED_EVIDENCE_BASELINE),
    "BRAND_EVIDENCE_BASELINE"
  );
}

export function verifyBrandMigration({
  rootDir = DEFAULT_ROOT,
  trackedFileList
} = {}) {
  const resolvedRoot = path.resolve(rootDir);
  const readBytes = (relativePath, code = "BRAND_FILE") =>
    readRegularFile(resolvedRoot, relativePath, code);
  const readText = (relativePath, code) =>
    readBytes(relativePath, code).toString("utf8");
  const manifest = parseCanonicalJson(
    readBytes(MANIFEST_PATH, "BRAND_MANIFEST_FILE"),
    "BRAND_MANIFEST_JSON"
  );
  exactManifest(manifest);

  for (const item of EXPECTED_EVIDENCE_BASELINE) {
    requireCondition(
      sha256(readBytes(item.path, "HISTORICAL_EVIDENCE_FILE")) === item.sha256,
      `HISTORICAL_EVIDENCE_DRIFT:${item.path}`
    );
  }

  const files = trackedFileList ?? trackedFiles(resolvedRoot);
  requireCondition(Array.isArray(files), "BRAND_TRACKED_FILES");
  const seenPaths = new Set();
  let domainReferenceFileCount = 0;
  let domainReferenceOccurrenceCount = 0;
  for (const relativePath of files) {
    safeRelativePath(relativePath, "BRAND_TRACKED_PATH");
    requireCondition(!seenPaths.has(relativePath), "BRAND_TRACKED_DUPLICATE");
    seenPaths.add(relativePath);
    const bytes = readBytes(relativePath, `BRAND_TRACKED_FILE:${relativePath}`);
    if (bytes.includes(0)) {
      continue;
    }
    const text = bytes.toString("utf8");
    const historicalNameCount = [
      ...text.matchAll(/\b(?:Tideproof|TideProof)\b/g)
    ].length;
    requireCondition(
      historicalNameCount ===
        (EXPECTED_HISTORICAL_NAME_COUNTS[relativePath] ?? 0),
      `FORMER_PUBLIC_NAME:${relativePath}`
    );
    const formerRepositoryCount = text.split(FORMER_REPOSITORY_URL).length - 1;
    requireCondition(
      formerRepositoryCount ===
        (EXPECTED_FORMER_REPOSITORY_COUNTS[relativePath] ?? 0),
      `FORMER_REPOSITORY_URL:${relativePath}`
    );
    if (!DOMAIN_SELF_REFERENCE_PATHS.has(relativePath)) {
      const domainReferenceCount = [
        ...text.matchAll(/tideproof\.net/gi)
      ].length;
      requireCondition(
        domainReferenceCount ===
          (EXPECTED_DOMAIN_REFERENCE_COUNTS[relativePath] ?? 0),
        `DOMAIN_REFERENCE_DRIFT:${relativePath}`
      );
      if (domainReferenceCount > 0) {
        domainReferenceFileCount += 1;
        domainReferenceOccurrenceCount += domainReferenceCount;
      }
    }
  }
  for (const relativePath of [
    ...Object.keys(EXPECTED_HISTORICAL_NAME_COUNTS),
    ...Object.keys(EXPECTED_FORMER_REPOSITORY_COUNTS),
    ...Object.keys(EXPECTED_DOMAIN_REFERENCE_COUNTS),
    ...STRICT_CURRENT_BRAND_SURFACES
  ]) {
    requireCondition(
      seenPaths.has(relativePath),
      `BRAND_REQUIRED_FILE:${relativePath}`
    );
  }
  for (const relativePath of STRICT_CURRENT_BRAND_SURFACES) {
    requireCondition(
      !readText(relativePath).toLowerCase().includes("tideproof"),
      `FORMER_NAME_ON_CURRENT_SURFACE:${relativePath}`
    );
  }
  requireCondition(domainReferenceFileCount === 7, "DOMAIN_REFERENCE_FILE_COUNT");
  requireCondition(
    domainReferenceOccurrenceCount === 9,
    "DOMAIN_REFERENCE_OCCURRENCE_COUNT"
  );

  requireCondition(
    readText("README.md").startsWith("# ProofToAct\n"),
    "README_NAME"
  );
  requireCondition(
    readText("web/index.html").includes(
      "<title>ProofToAct — Admissibility Memory</title>"
    ),
    "BROWSER_TITLE"
  );
  requireCondition(
    readText("package.json").includes(
      '"name": "prooftoact-admissibility-memory"'
    ) &&
      readText("package-lock.json").includes(
        '"name": "prooftoact-admissibility-memory"'
      ),
    "PACKAGE_NAME_BINDING"
  );
  const submission = parseCanonicalJson(
    readBytes("RELEASE_SUBMISSION_MANIFEST.json"),
    "BRAND_SUBMISSION_JSON"
  );
  requireCondition(
    submission.coordinates?.projectName === "ProofToAct" &&
      submission.coordinates?.publicSource ===
        "https://github.com/Flash-Bri/prooftoact",
    "SUBMISSION_COORDINATES"
  );

  return {
    schemaVersion: "prooftoact.brand-migration-verification.v1",
    status: "CURRENT_BRAND_MIGRATION_PASS",
    approvedName: manifest.approvedName,
    repository: manifest.repository,
    preservedEvidenceCount: manifest.evidenceBaseline.length,
    domainReferenceFileCount,
    domainReferenceOccurrenceCount
  };
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
) {
  try {
    process.stdout.write(`${JSON.stringify(verifyBrandMigration(), null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`PROOFTOACT_BRAND_MIGRATION_FAILED:${error.message}\n`);
    process.exitCode = 1;
  }
}
