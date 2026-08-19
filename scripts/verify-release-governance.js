import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const DEFAULT_ROOT = fileURLToPath(new URL("..", import.meta.url));
const MANIFEST_PATH = "RELEASE_GOVERNANCE_MANIFEST.json";
const MANIFEST_SCHEMA = "tideproof.release-governance-manifest.v1";
const MANIFEST_STATUS =
  "CURRENT_REPOSITORY_GOVERNANCE_REVIEWED_FINAL_RECHECK_PENDING";
const SNAPSHOT_SCHEMA = "tideproof.github-release-governance-snapshot.v1";
const SNAPSHOT_STATUS = "OBSERVED_NONFINAL_GITHUB_GOVERNANCE";
const POST_RENAME_SNAPSHOT_SCHEMA =
  "prooftoact.github-release-governance-snapshot.v1";
const POST_RENAME_SNAPSHOT_STATUS =
  "OBSERVED_POST_RENAME_NONFINAL_GITHUB_GOVERNANCE";
const RECEIPT_SCHEMA = "tideproof.release-governance-verification.v1";
const HEX_40 = /^[0-9a-f]{40}$/;
const HEX_64 = /^[0-9a-f]{64}$/;

const EXPECTED_REPOSITORY = Object.freeze({
  fullName: "Flash-Bri/prooftoact",
  htmlUrl: "https://github.com/Flash-Bri/prooftoact",
  visibility: "public",
  defaultBranch: "main",
  requiredWorkflow: "CI",
  requiredCheck: "verify",
  candidateHeadCheck: "verify-pr-head-no-secrets"
});

const EXPECTED_SNAPSHOT_REPOSITORY = Object.freeze({
  fullName: "Flash-Bri/tideproof",
  htmlUrl: "https://github.com/Flash-Bri/tideproof",
  visibility: "public",
  defaultBranch: "main",
  licenseSpdxId: "MIT",
  description:
    "Admissibility memory for high-stakes agents: similarity proposes, CockroachDB commits.",
  topics: Object.freeze([
    "agentic-memory",
    "aws",
    "cockroachdb",
    "distributed-systems",
    "hackathon"
  ])
});

const EXPECTED_SOURCE = Object.freeze({
  commit: "68f112f97e7439ac2ab1ecdde4c6379453c825c6",
  tree: "eee1f22f99fb7b5edd4113e622f177510388dea8",
  branch: "main"
});

const EXPECTED_POST_RENAME_REPOSITORY = Object.freeze({
  id: 1317716765,
  nodeId: "R_kgDOTorDHQ",
  fullName: "Flash-Bri/prooftoact",
  htmlUrl: "https://github.com/Flash-Bri/prooftoact",
  visibility: "public",
  defaultBranch: "main",
  licenseSpdxId: "MIT",
  description:
    "ProofToAct — admissibility memory for high-stakes agents: similarity proposes, CockroachDB commits.",
  topics: Object.freeze([
    "agentic-memory",
    "aws",
    "cockroachdb",
    "distributed-systems",
    "hackathon"
  ])
});

const EXPECTED_POST_RENAME_SOURCE = Object.freeze({
  commit: "df4da95358324ab95b8556650f4c639c7cee21f5",
  tree: "d6683f1d1cea18f7ddb36ea8053d01a54b568643",
  branch: "rename/prooftoact"
});

const EXPECTED_RENAME_CONTINUITY = Object.freeze({
  preRenameFullName: "Flash-Bri/tideproof",
  preRenameId: 1317716765,
  preRenameNodeId: "R_kgDOTorDHQ",
  postRenameFullName: "Flash-Bri/prooftoact",
  postRenameId: 1317716765,
  postRenameNodeId: "R_kgDOTorDHQ",
  formerWebUrl: "https://github.com/Flash-Bri/tideproof",
  formerWebStatus: 301,
  formerWebLocation: "https://github.com/Flash-Bri/prooftoact"
});

const EXPECTED_RENAME_PULL_REQUEST = Object.freeze({
  number: 52,
  url: "https://github.com/Flash-Bri/prooftoact/pull/52",
  state: "open",
  isDraft: true,
  baseRef: "main",
  baseSha: "0d048a4e0e893d947c9a70c7189bfb164a9d1f59",
  headRef: "rename/prooftoact",
  headSha: EXPECTED_POST_RENAME_SOURCE.commit
});

const EXPECTED_BRANCH_PROTECTION = Object.freeze({
  pullRequestRequired: true,
  requiredApprovingReviewCount: 0,
  dismissStaleReviews: false,
  requireCodeOwnerReviews: false,
  requireLastPushApproval: false,
  strictStatusChecks: true,
  requiredChecks: Object.freeze([
    Object.freeze({ context: "verify", appId: 15368 })
  ]),
  administratorsEnforced: true,
  conversationResolutionRequired: true,
  forcePushAllowed: false,
  deletionAllowed: false,
  signaturesRequired: false,
  linearHistoryRequired: false
});

const EXPECTED_SECURITY = Object.freeze({
  vulnerabilityAlerts: "enabled",
  secretScanning: "enabled",
  secretScanningPushProtection: "enabled",
  dependabotSecurityUpdates: "disabled",
  dependabotSecurityUpdatesBoundary:
    "Deliberately disabled at this checkpoint to preserve the single-writer release lane; vulnerability alerts remain enabled and dependency review remains an explicit release gate."
});

const EXPECTED_CONTINUOUS_INTEGRATION = Object.freeze({
  workflow: "CI",
  requiredCheck: "verify",
  runId: 30674588891,
  runUrl: "https://github.com/Flash-Bri/tideproof/actions/runs/30674588891",
  headSha: EXPECTED_SOURCE.commit,
  status: "completed",
  conclusion: "success"
});

const EXPECTED_POST_RENAME_CONTINUOUS_INTEGRATION = Object.freeze({
  workflow: "CI",
  requiredCheck: "verify",
  runId: 30827066820,
  runUrl:
    "https://github.com/Flash-Bri/prooftoact/actions/runs/30827066820",
  headSha: EXPECTED_POST_RENAME_SOURCE.commit,
  status: "completed",
  conclusion: "success"
});

const EXPECTED_FINAL_RELEASE_REQUIREMENTS = Object.freeze([
  "Requery repository visibility, security settings, and complete branch protection at the exact final release commit.",
  "Verify the required CI run succeeds at the exact final release commit and that the protected check identity still matches the intended GitHub Actions workflow.",
  "Complete signed-out repository, release metadata, and public-link review before publication and submission."
]);

const EXPECTED_MANIFEST_BOUNDARY =
  "This manifest binds sanitized historical and post-rename GitHub governance observations, the approved repository rename boundary, and reviewed repository surfaces. It does not query GitHub, prove settings remain unchanged, require human approval, establish vulnerability absence, authorize deployment, or approve publication or submission.";

const EXPECTED_SNAPSHOT_BOUNDARY =
  "This sanitized snapshot records read-only GitHub API observations at one time for one commit. It does not prove that settings remain unchanged, require a human approval, establish vulnerability absence, authorize deployment or submission, or replace final signed-out repository and governance review.";

const EXPECTED_POST_RENAME_SNAPSHOT_BOUNDARY =
  "This sanitized snapshot records bounded read-only GitHub API and public HTTP observations immediately before and after the approved in-place repository rename. The stable repository identity remained constant across those observations, but this snapshot does not prove that settings remain unchanged, require a human approval, establish vulnerability absence, authorize deployment or submission, or replace final exact-main CI and signed-out repository review.";

const EXPECTED_SURFACES = Object.freeze({
  "brand-migration-ledger": Object.freeze({
    path: "docs/RENAME_MIGRATION.md",
    role: "REPOSITORY_RENAME_BOUNDARY"
  }),
  "brand-migration-manifest": Object.freeze({
    path: "RENAME_MIGRATION_MANIFEST.json",
    role: "REPOSITORY_RENAME_CONTROL"
  }),
  "ci-workflow": Object.freeze({
    path: ".github/workflows/ci.yml",
    role: "REQUIRED_CHECK_SOURCE"
  }),
  "governance-ledger": Object.freeze({
    path: "docs/RELEASE_GOVERNANCE.md",
    role: "NONFINAL_CONTROL_BOUNDARY"
  }),
  "governance-snapshot": Object.freeze({
    path: "evidence/github-release-governance-2026-08-01.json",
    role: "SANITIZED_HISTORICAL_READ_ONLY_OBSERVATION"
  }),
  "post-rename-governance-snapshot": Object.freeze({
    path: "evidence/github-release-governance-rename-2026-08-03.json",
    role: "SANITIZED_POST_RENAME_READ_ONLY_OBSERVATION"
  }),
  "public-readme": Object.freeze({
    path: "README.md",
    role: "PUBLIC_PROJECT_SURFACE"
  }),
  "security-policy": Object.freeze({
    path: "SECURITY.md",
    role: "PUBLIC_SECURITY_BOUNDARY"
  })
});

function assert(condition, code) {
  if (!condition) {
    throw new Error(code);
  }
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function sorted(values) {
  return [...values].sort((left, right) => left.localeCompare(right));
}

function sameJson(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function exactKeys(value, keys, code) {
  assert(
    value &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      sameJson(sorted(Object.keys(value)), sorted(keys)),
    code
  );
}

function safeRelativePath(value, code) {
  assert(
    typeof value === "string" &&
      value.length > 0 &&
      value === value.replaceAll("\\", "/") &&
      !path.posix.isAbsolute(value) &&
      value.split("/").every((part) => part !== "" && part !== ".."),
    code
  );
}

function readRegularFile(rootDir, relativePath, code) {
  safeRelativePath(relativePath, code);
  const resolvedRoot = path.resolve(rootDir);
  const resolved = path.resolve(resolvedRoot, relativePath);
  const relative = path.relative(resolvedRoot, resolved);
  assert(
    relative !== "" &&
      relative !== ".." &&
      !relative.startsWith(`..${path.sep}`),
    code
  );
  let current = resolvedRoot;
  let stat;
  for (const segment of relativePath.split("/")) {
    current = path.join(current, segment);
    stat = fs.lstatSync(current);
    assert(!stat.isSymbolicLink(), code);
  }
  assert(stat.isFile(), code);
  return fs.readFileSync(resolved);
}

function parseCanonicalJson(bytes, code) {
  let parsed;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new Error(code);
  }
  assert(parsed && typeof parsed === "object" && !Array.isArray(parsed), code);
  assert(
    bytes.toString("utf8") === `${JSON.stringify(parsed, null, 2)}\n`,
    `${code}_CANONICAL`
  );
  return parsed;
}

function assertMarkers(value, markers, code) {
  assert(markers.every((marker) => value.includes(marker)), code);
}

export function validateManifest(manifest) {
  exactKeys(
    manifest,
    [
      "claimBoundary",
      "finalReleaseReady",
      "finalReleaseRequirements",
      "repository",
      "reviewedOn",
      "schema",
      "status",
      "surfaces"
    ],
    "RELEASE_GOVERNANCE_MANIFEST_KEYS"
  );
  exactKeys(
    manifest.repository,
    Object.keys(EXPECTED_REPOSITORY),
    "RELEASE_GOVERNANCE_REPOSITORY_KEYS"
  );
  assert(
    manifest.schema === MANIFEST_SCHEMA &&
      manifest.status === MANIFEST_STATUS &&
      /^\d{4}-\d{2}-\d{2}$/.test(manifest.reviewedOn) &&
      manifest.claimBoundary === EXPECTED_MANIFEST_BOUNDARY &&
      manifest.finalReleaseReady === false &&
      sameJson(manifest.repository, EXPECTED_REPOSITORY) &&
      sameJson(
        manifest.finalReleaseRequirements,
        EXPECTED_FINAL_RELEASE_REQUIREMENTS
      ) &&
      Array.isArray(manifest.surfaces) &&
      manifest.surfaces.length === Object.keys(EXPECTED_SURFACES).length,
    "RELEASE_GOVERNANCE_MANIFEST_BOUNDARY"
  );

  const expectedIds = Object.keys(EXPECTED_SURFACES);
  assert(
    sameJson(
      manifest.surfaces.map((surface) => surface.id),
      expectedIds
    ),
    "RELEASE_GOVERNANCE_MANIFEST_SURFACE_ORDER"
  );
  for (const surface of manifest.surfaces) {
    exactKeys(
      surface,
      ["id", "path", "role", "sha256"],
      "RELEASE_GOVERNANCE_MANIFEST_SURFACE_KEYS"
    );
    const expected = EXPECTED_SURFACES[surface.id];
    assert(
      expected &&
        surface.path === expected.path &&
        surface.role === expected.role &&
        HEX_64.test(surface.sha256),
      "RELEASE_GOVERNANCE_MANIFEST_SURFACE"
    );
  }
  return manifest;
}

export function validateSnapshot(snapshot) {
  exactKeys(
    snapshot,
    [
      "branchProtection",
      "claimBoundary",
      "continuousIntegration",
      "finalReleaseReady",
      "finalReleaseRequirements",
      "observedAt",
      "repository",
      "schema",
      "security",
      "source",
      "status"
    ],
    "RELEASE_GOVERNANCE_SNAPSHOT_KEYS"
  );
  exactKeys(
    snapshot.source,
    Object.keys(EXPECTED_SOURCE),
    "RELEASE_GOVERNANCE_SNAPSHOT_SOURCE_KEYS"
  );
  exactKeys(
    snapshot.repository,
    Object.keys(EXPECTED_SNAPSHOT_REPOSITORY),
    "RELEASE_GOVERNANCE_SNAPSHOT_REPOSITORY_KEYS"
  );
  exactKeys(
    snapshot.branchProtection,
    Object.keys(EXPECTED_BRANCH_PROTECTION),
    "RELEASE_GOVERNANCE_SNAPSHOT_PROTECTION_KEYS"
  );
  exactKeys(
    snapshot.security,
    Object.keys(EXPECTED_SECURITY),
    "RELEASE_GOVERNANCE_SNAPSHOT_SECURITY_KEYS"
  );
  exactKeys(
    snapshot.continuousIntegration,
    Object.keys(EXPECTED_CONTINUOUS_INTEGRATION),
    "RELEASE_GOVERNANCE_SNAPSHOT_CI_KEYS"
  );
  assert(
    snapshot.schema === SNAPSHOT_SCHEMA &&
      snapshot.status === SNAPSHOT_STATUS &&
      snapshot.observedAt === "2026-08-01T01:45:38Z" &&
      Number.isFinite(Date.parse(snapshot.observedAt)) &&
      snapshot.claimBoundary === EXPECTED_SNAPSHOT_BOUNDARY &&
      snapshot.finalReleaseReady === false &&
      sameJson(snapshot.source, EXPECTED_SOURCE) &&
      HEX_40.test(snapshot.source.commit) &&
      HEX_40.test(snapshot.source.tree) &&
      sameJson(snapshot.repository, EXPECTED_SNAPSHOT_REPOSITORY) &&
      sameJson(snapshot.branchProtection, EXPECTED_BRANCH_PROTECTION) &&
      sameJson(snapshot.security, EXPECTED_SECURITY) &&
      sameJson(
        snapshot.continuousIntegration,
        EXPECTED_CONTINUOUS_INTEGRATION
      ) &&
      sameJson(
        snapshot.finalReleaseRequirements,
        EXPECTED_FINAL_RELEASE_REQUIREMENTS
      ),
    "RELEASE_GOVERNANCE_SNAPSHOT_BOUNDARY"
  );
  return snapshot;
}

export function validatePostRenameSnapshot(snapshot) {
  exactKeys(
    snapshot,
    [
      "branchProtection",
      "claimBoundary",
      "continuousIntegration",
      "finalReleaseReady",
      "finalReleaseRequirements",
      "observedAt",
      "pullRequest",
      "renameContinuity",
      "repository",
      "schema",
      "security",
      "source",
      "status"
    ],
    "POST_RENAME_GOVERNANCE_SNAPSHOT_KEYS"
  );
  exactKeys(
    snapshot.source,
    Object.keys(EXPECTED_POST_RENAME_SOURCE),
    "POST_RENAME_GOVERNANCE_SNAPSHOT_SOURCE_KEYS"
  );
  exactKeys(
    snapshot.repository,
    Object.keys(EXPECTED_POST_RENAME_REPOSITORY),
    "POST_RENAME_GOVERNANCE_SNAPSHOT_REPOSITORY_KEYS"
  );
  exactKeys(
    snapshot.renameContinuity,
    Object.keys(EXPECTED_RENAME_CONTINUITY),
    "POST_RENAME_GOVERNANCE_SNAPSHOT_CONTINUITY_KEYS"
  );
  exactKeys(
    snapshot.branchProtection,
    Object.keys(EXPECTED_BRANCH_PROTECTION),
    "POST_RENAME_GOVERNANCE_SNAPSHOT_PROTECTION_KEYS"
  );
  exactKeys(
    snapshot.security,
    Object.keys(EXPECTED_SECURITY),
    "POST_RENAME_GOVERNANCE_SNAPSHOT_SECURITY_KEYS"
  );
  exactKeys(
    snapshot.continuousIntegration,
    Object.keys(EXPECTED_POST_RENAME_CONTINUOUS_INTEGRATION),
    "POST_RENAME_GOVERNANCE_SNAPSHOT_CI_KEYS"
  );
  exactKeys(
    snapshot.pullRequest,
    Object.keys(EXPECTED_RENAME_PULL_REQUEST),
    "POST_RENAME_GOVERNANCE_SNAPSHOT_PULL_REQUEST_KEYS"
  );
  assert(
    snapshot.schema === POST_RENAME_SNAPSHOT_SCHEMA &&
      snapshot.status === POST_RENAME_SNAPSHOT_STATUS &&
      snapshot.observedAt === "2026-08-03T15:23:23Z" &&
      Number.isFinite(Date.parse(snapshot.observedAt)) &&
      snapshot.claimBoundary === EXPECTED_POST_RENAME_SNAPSHOT_BOUNDARY &&
      snapshot.finalReleaseReady === false &&
      sameJson(snapshot.source, EXPECTED_POST_RENAME_SOURCE) &&
      HEX_40.test(snapshot.source.commit) &&
      HEX_40.test(snapshot.source.tree) &&
      sameJson(snapshot.repository, EXPECTED_POST_RENAME_REPOSITORY) &&
      sameJson(snapshot.renameContinuity, EXPECTED_RENAME_CONTINUITY) &&
      snapshot.renameContinuity.preRenameId ===
        snapshot.renameContinuity.postRenameId &&
      snapshot.renameContinuity.preRenameNodeId ===
        snapshot.renameContinuity.postRenameNodeId &&
      snapshot.renameContinuity.postRenameId === snapshot.repository.id &&
      snapshot.renameContinuity.postRenameNodeId ===
        snapshot.repository.nodeId &&
      sameJson(snapshot.branchProtection, EXPECTED_BRANCH_PROTECTION) &&
      sameJson(snapshot.security, EXPECTED_SECURITY) &&
      sameJson(
        snapshot.continuousIntegration,
        EXPECTED_POST_RENAME_CONTINUOUS_INTEGRATION
      ) &&
      sameJson(snapshot.pullRequest, EXPECTED_RENAME_PULL_REQUEST) &&
      snapshot.pullRequest.headSha === snapshot.source.commit &&
      snapshot.continuousIntegration.headSha === snapshot.source.commit &&
      sameJson(
        snapshot.finalReleaseRequirements,
        EXPECTED_FINAL_RELEASE_REQUIREMENTS
      ),
    "POST_RENAME_GOVERNANCE_SNAPSHOT_BOUNDARY"
  );
  return snapshot;
}

export function verifyReleaseGovernance({ rootDir = DEFAULT_ROOT } = {}) {
  const manifestBytes = readRegularFile(
    rootDir,
    MANIFEST_PATH,
    "RELEASE_GOVERNANCE_MANIFEST_FILE"
  );
  const manifest = validateManifest(
    parseCanonicalJson(manifestBytes, "RELEASE_GOVERNANCE_MANIFEST_JSON")
  );

  const surfaceBytes = new Map();
  for (const surface of manifest.surfaces) {
    const bytes = readRegularFile(
      rootDir,
      surface.path,
      `RELEASE_GOVERNANCE_SURFACE_${surface.id}`
    );
    assert(
      sha256(bytes) === surface.sha256,
      `RELEASE_GOVERNANCE_SURFACE_HASH_${surface.id}`
    );
    surfaceBytes.set(surface.id, bytes);
  }

  const snapshot = validateSnapshot(
    parseCanonicalJson(
      surfaceBytes.get("governance-snapshot"),
      "RELEASE_GOVERNANCE_SNAPSHOT_JSON"
    )
  );
  const postRenameSnapshot = validatePostRenameSnapshot(
    parseCanonicalJson(
      surfaceBytes.get("post-rename-governance-snapshot"),
      "POST_RENAME_GOVERNANCE_SNAPSHOT_JSON"
    )
  );
  const workflow = surfaceBytes.get("ci-workflow").toString("utf8");
  const ledger = surfaceBytes.get("governance-ledger").toString("utf8");
  const readme = surfaceBytes.get("public-readme").toString("utf8");
  const securityPolicy = surfaceBytes
    .get("security-policy")
    .toString("utf8");

  assertMarkers(
    workflow,
    [
      "name: CI",
      "  verify:",
      "persist-credentials: false",
      "run: npm run governance:verify",
      "run: npm run release:provenance"
    ],
    "RELEASE_GOVERNANCE_WORKFLOW"
  );
  assertMarkers(
    ledger,
    [
      "OBSERVED_POST_RENAME_NONFINAL_GITHUB_GOVERNANCE",
      "OBSERVED_NONFINAL_GITHUB_GOVERNANCE",
      "required approving-review count was zero",
      "repository ID `1317716765`",
      "does not query GitHub",
      "exact final commit"
    ],
    "RELEASE_GOVERNANCE_LEDGER"
  );
  assertMarkers(
    readme,
    [
      "live, signed-out AWS Lambda → CockroachDB",
      "npm run governance:verify",
      "CURRENT_REPOSITORY_GOVERNANCE_PASS",
      "not current GitHub state or final release approval",
      "verify-pr-head-no-secrets"
    ],
    "RELEASE_GOVERNANCE_README"
  );
  assertMarkers(
    securityPolicy,
    [
      "## Repository governance gate",
      "npm run governance:verify",
      "CURRENT_REPOSITORY_GOVERNANCE_PASS",
      "Requery and review the complete GitHub settings"
    ],
    "RELEASE_GOVERNANCE_SECURITY_POLICY"
  );

  return {
    schemaVersion: RECEIPT_SCHEMA,
    status: "CURRENT_REPOSITORY_GOVERNANCE_PASS",
    finalReleaseReady: false,
    reviewedOn: manifest.reviewedOn,
    manifestPath: MANIFEST_PATH,
    manifestSha256: sha256(manifestBytes),
    snapshotPath:
      EXPECTED_SURFACES["post-rename-governance-snapshot"].path,
    snapshotSha256: sha256(
      surfaceBytes.get("post-rename-governance-snapshot")
    ),
    observedAt: postRenameSnapshot.observedAt,
    sourceCommit: postRenameSnapshot.source.commit,
    sourceTree: postRenameSnapshot.source.tree,
    surfaceCount: manifest.surfaces.length,
    requiredCheckCount:
      postRenameSnapshot.branchProtection.requiredChecks.length,
    requiredApprovingReviewCount:
      postRenameSnapshot.branchProtection.requiredApprovingReviewCount,
    finalReleaseRequirements: [...manifest.finalReleaseRequirements],
    checks: {
      canonicalManifest: true,
      canonicalSnapshot: true,
      exactSurfaceHashes: true,
      publicRepositoryCoordinatesExact:
        snapshot.repository.fullName === "Flash-Bri/tideproof" &&
        postRenameSnapshot.repository.id === 1317716765 &&
        postRenameSnapshot.repository.nodeId === "R_kgDOTorDHQ" &&
        postRenameSnapshot.repository.fullName ===
          EXPECTED_REPOSITORY.fullName,
      branchProtectionSnapshotExact: true,
      securitySnapshotExact: true,
      requiredCiSnapshotExact: true,
      localWorkflowIdentityExact: true,
      publicBoundariesExplicit: true,
      nonfinalBoundaryPreserved: true
    },
    claimBoundary: manifest.claimBoundary
  };
}

async function main() {
  assert(process.argv.length === 2, "RELEASE_GOVERNANCE_ARGUMENT");
  const receipt = verifyReleaseGovernance();
  process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
}

export const __test = Object.freeze({
  EXPECTED_BRANCH_PROTECTION,
  EXPECTED_CONTINUOUS_INTEGRATION,
  EXPECTED_FINAL_RELEASE_REQUIREMENTS,
  EXPECTED_MANIFEST_BOUNDARY,
  EXPECTED_POST_RENAME_CONTINUOUS_INTEGRATION,
  EXPECTED_POST_RENAME_REPOSITORY,
  EXPECTED_POST_RENAME_SNAPSHOT_BOUNDARY,
  EXPECTED_POST_RENAME_SOURCE,
  EXPECTED_RENAME_CONTINUITY,
  EXPECTED_RENAME_PULL_REQUEST,
  EXPECTED_REPOSITORY,
  EXPECTED_SECURITY,
  EXPECTED_SNAPSHOT_BOUNDARY,
  EXPECTED_SNAPSHOT_REPOSITORY,
  EXPECTED_SOURCE,
  EXPECTED_SURFACES,
  MANIFEST_SCHEMA,
  MANIFEST_STATUS,
  POST_RENAME_SNAPSHOT_SCHEMA,
  POST_RENAME_SNAPSHOT_STATUS,
  SNAPSHOT_SCHEMA,
  SNAPSHOT_STATUS
});

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main().catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
