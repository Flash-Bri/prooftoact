import crypto from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { verifyBrandMigration } from "./verify-brand-migration.js";
import { verifyReleaseSecurity } from "./verify-release-security.js";
import {
  localFullDrillSourceBindings,
  validateLocalFullDrillReceiptBytes,
} from "../src/local-full-drill.js";

const DEFAULT_ROOT = fileURLToPath(new URL("..", import.meta.url));
const MANIFEST_NAME = "PROOF_MANIFEST.json";
const SCHEMA = "tideproof.proof-manifest.v1";
const RECEIPT_SCHEMA = "tideproof.proof-manifest-verification.v1";
const MANIFEST_STATUS = "INCOMPLETE_LIVE_GATES_PENDING";
const PROOF_STATES = new Set(["VERIFIED", "PARTIAL", "PENDING"]);
const ARTIFACT_KINDS = new Set([
  "accepted-evidence",
  "boundary-ledger",
  "local-validation",
  "release-receipt",
  "released-asset",
  "stop-receipt",
  "verification-code",
]);

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function sorted(values) {
  return [...values].sort((left, right) =>
    left < right ? -1 : left > right ? 1 : 0
  );
}

function assertExactKeys(value, expected, label) {
  assert(
    value && typeof value === "object" && !Array.isArray(value),
    `${label} must be an object`
  );
  const actual = sorted(Object.keys(value));
  const wanted = sorted(expected);
  assert(
    JSON.stringify(actual) === JSON.stringify(wanted),
    `${label} keys must be exactly: ${wanted.join(", ")}`
  );
}

function assertIdentifier(value, label) {
  assert(
    typeof value === "string" && /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(value),
    `${label} must be a lowercase kebab-case identifier`
  );
}

function assertNonemptyString(value, label) {
  assert(
    typeof value === "string" && value.trim() === value && value.length > 0,
    `${label} must be a nonempty trimmed string`
  );
}

function assertStringList(value, label, { requireSorted = false } = {}) {
  assert(Array.isArray(value), `${label} must be an array`);
  value.forEach((entry, index) =>
    assertNonemptyString(entry, `${label}[${index}]`)
  );
  assert(
    new Set(value).size === value.length,
    `${label} must not contain duplicates`
  );
  if (requireSorted) {
    assert(
      JSON.stringify(value) === JSON.stringify(sorted(value)),
      `${label} must be sorted`
    );
  }
}

function parseClaimsLedger(source) {
  const lines = source.split("\n");
  const header =
    "| Claim | Current status | Required artifact | Acceptance condition |";
  const headerIndexes = lines.flatMap((line, index) =>
    line === header ? [index] : []
  );
  assert(
    headerIndexes.length === 1,
    "CLAIMS.md canonical claim-table header must appear exactly once"
  );
  const [headerIndex] = headerIndexes;
  assert(
    /^\|\s*-+\s*\|\s*-+\s*\|\s*-+\s*\|\s*-+\s*\|$/.test(
      lines[headerIndex + 1] ?? ""
    ),
    "CLAIMS.md claim table is missing its separator"
  );

  const claims = [];
  const claimTexts = new Set();
  for (let index = headerIndex + 2; index < lines.length; index += 1) {
    const line = lines[index];
    if (!line.startsWith("|")) {
      break;
    }
    assert(
      line.endsWith("|"),
      `CLAIMS.md row ${index + 1} must end with a pipe`
    );
    const cells = line
      .slice(1, -1)
      .split("|")
      .map((cell) => cell.trim());
    assert(cells.length === 4, `CLAIMS.md row ${index + 1} must have four cells`);
    for (const [cellIndex, label] of [
      "claim",
      "current status",
      "required artifact",
      "acceptance condition",
    ].entries()) {
      assert(
        cells[cellIndex].length > 0,
        `CLAIMS.md row ${index + 1} ${label} must not be empty`
      );
    }
    assert(
      !claimTexts.has(cells[0]),
      "CLAIMS.md claim text must be unique"
    );
    claimTexts.add(cells[0]);
    claims.push({
      claim: cells[0],
      currentStatus: cells[1],
      requiredArtifact: cells[2],
      acceptanceCondition: cells[3],
    });
  }
  assert(claims.length > 0, "CLAIMS.md claim table must not be empty");
  return claims;
}

function claimsLedgerRowSha256(claim) {
  return sha256(
    JSON.stringify([
      claim.claim,
      claim.currentStatus,
      claim.requiredArtifact,
      claim.acceptanceCondition,
    ])
  );
}

function resolveArtifact(rootDir, relativePath, label) {
  assertNonemptyString(relativePath, `${label}.path`);
  assert(
    relativePath === relativePath.replaceAll("\\", "/"),
    `${label}.path must use POSIX separators`
  );
  assert(!path.posix.isAbsolute(relativePath), `${label}.path must be relative`);
  assert(
    relativePath.split("/").every((part) => part !== "" && part !== ".."),
    `${label}.path must not contain empty or parent segments`
  );
  assert(relativePath !== MANIFEST_NAME, `${label}.path must not self-reference`);

  const resolved = path.resolve(rootDir, relativePath);
  const fromRoot = path.relative(rootDir, resolved);
  assert(
    fromRoot !== "" && !fromRoot.startsWith(`..${path.sep}`) && fromRoot !== "..",
    `${label}.path escapes the repository root`
  );
  let currentPath = rootDir;
  let stat;
  for (const segment of relativePath.split("/")) {
    currentPath = path.join(currentPath, segment);
    stat = lstatSync(currentPath);
    assert(
      !stat.isSymbolicLink(),
      `${label}.path must not contain symbolic links`
    );
  }
  assert(stat.isFile(), `${label}.path must be a regular file`);
  return resolved;
}

function verifyReferences({
  item,
  label,
  artifactById,
  usedArtifactIds,
  acceptedEvidenceRequired,
}) {
  assertIdentifier(item.id, `${label}.id`);
  assert(PROOF_STATES.has(item.proofState), `${label}.proofState is invalid`);
  assertNonemptyString(item.acceptanceBoundary ?? item.boundary, `${label}.boundary`);
  assertStringList(item.artifacts, `${label}.artifacts`, { requireSorted: true });
  assertStringList(item.remainingRequirements, `${label}.remainingRequirements`);
  assert(item.artifacts.length > 0, `${label}.artifacts must not be empty`);

  const referenced = item.artifacts.map((artifactId) => {
    const artifact = artifactById.get(artifactId);
    assert(artifact, `${label} references unknown artifact ${artifactId}`);
    usedArtifactIds.add(artifactId);
    return artifact;
  });

  if (item.proofState === "VERIFIED") {
    assert(
      item.remainingRequirements.length === 0,
      `${label} is VERIFIED but still has remaining requirements`
    );
    if (acceptedEvidenceRequired) {
      assert(
        referenced.some((artifact) => artifact.kind === "accepted-evidence"),
        `${label} is VERIFIED without accepted evidence`
      );
    }
  } else {
    assert(
      item.remainingRequirements.length > 0,
      `${label} is ${item.proofState} without a remaining requirement`
    );
  }
}

export function verifyProofManifest({
  rootDir = DEFAULT_ROOT,
  manifestPath = path.join(rootDir, MANIFEST_NAME),
  verifySecurity = verifyReleaseSecurity,
} = {}) {
  const resolvedRoot = path.resolve(rootDir);
  const resolvedManifest = path.resolve(manifestPath);
  assert(
    resolvedManifest === path.join(resolvedRoot, MANIFEST_NAME),
    `proof manifest path must be ${path.join(resolvedRoot, MANIFEST_NAME)}`
  );
  const manifestStat = lstatSync(resolvedManifest);
  assert(
    manifestStat.isFile() && !manifestStat.isSymbolicLink(),
    "proof manifest must be a regular file"
  );
  const rawManifest = readFileSync(resolvedManifest, "utf8");
  let manifest;
  try {
    manifest = JSON.parse(rawManifest);
  } catch (error) {
    throw new Error(`proof manifest is not valid JSON: ${error.message}`);
  }

  assert(
    `${JSON.stringify(manifest, null, 2)}\n` === rawManifest,
    "proof manifest must use canonical two-space JSON with one trailing newline"
  );
  assertExactKeys(
    manifest,
    [
      "schema",
      "status",
      "reviewedOn",
      "claimBoundary",
      "artifacts",
      "claims",
      "releaseControls",
    ],
    "proof manifest"
  );
  assert(manifest.schema === SCHEMA, `proof manifest schema must be ${SCHEMA}`);
  assert(
    manifest.status === MANIFEST_STATUS,
    `proof manifest status must be ${MANIFEST_STATUS}`
  );
  assert(
    /^\d{4}-\d{2}-\d{2}$/.test(manifest.reviewedOn),
    "proof manifest reviewedOn must be YYYY-MM-DD"
  );
  assertNonemptyString(manifest.claimBoundary, "proof manifest claimBoundary");
  assert(Array.isArray(manifest.artifacts), "proof manifest artifacts must be an array");
  assert(Array.isArray(manifest.claims), "proof manifest claims must be an array");
  assert(
    Array.isArray(manifest.releaseControls),
    "proof manifest releaseControls must be an array"
  );

  const artifactById = new Map();
  manifest.artifacts.forEach((artifact, index) => {
    const label = `artifacts[${index}]`;
    assertExactKeys(artifact, ["id", "path", "sha256", "kind"], label);
    assertIdentifier(artifact.id, `${label}.id`);
    assert(!artifactById.has(artifact.id), `duplicate artifact id ${artifact.id}`);
    assert(ARTIFACT_KINDS.has(artifact.kind), `${label}.kind is invalid`);
    assert(/^[a-f0-9]{64}$/.test(artifact.sha256), `${label}.sha256 is invalid`);
    const artifactPath = resolveArtifact(resolvedRoot, artifact.path, label);
    const actualHash = sha256(readFileSync(artifactPath));
    assert(
      actualHash === artifact.sha256,
      `${artifact.id} SHA-256 mismatch: expected ${artifact.sha256}, received ${actualHash}`
    );
    artifactById.set(artifact.id, artifact);
  });
  const artifactIds = [...artifactById.keys()];
  assert(
    JSON.stringify(artifactIds) === JSON.stringify(sorted(artifactIds)),
    "proof manifest artifacts must be sorted by id"
  );
  if (artifactById.has("release-security-manifest")) {
    try {
      verifySecurity({ rootDir: resolvedRoot });
    } catch {
      throw new Error("proof manifest nested release-security verification failed");
    }
  }
  if (artifactById.has("brand-migration-manifest")) {
    try {
      verifyBrandMigration({ rootDir: resolvedRoot });
    } catch {
      throw new Error("proof manifest nested brand-migration verification failed");
    }
  }
  if (artifactById.has("local-full-drill-receipt")) {
    try {
      const artifact = artifactById.get("local-full-drill-receipt");
      validateLocalFullDrillReceiptBytes(
        readFileSync(
          resolveArtifact(resolvedRoot, artifact.path, "local-full-drill-receipt")
        ),
        { sourceBindings: localFullDrillSourceBindings(resolvedRoot) }
      );
    } catch {
      throw new Error("proof manifest nested local-full-drill verification failed");
    }
  }

  const claimsLedgerArtifact = artifactById.get("claims-ledger");
  assert(claimsLedgerArtifact, "proof manifest must include claims-ledger");
  const claimsLedgerPath = resolveArtifact(
    resolvedRoot,
    claimsLedgerArtifact.path,
    "claims-ledger"
  );
  const ledgerClaims = parseClaimsLedger(readFileSync(claimsLedgerPath, "utf8"));
  assert(
    manifest.claims.length === ledgerClaims.length,
    `proof manifest has ${manifest.claims.length} claims but CLAIMS.md has ${ledgerClaims.length}`
  );

  const usedArtifactIds = new Set();
  const itemIds = new Set();
  manifest.claims.forEach((claim, index) => {
    const label = `claims[${index}]`;
    assertExactKeys(
      claim,
      [
        "id",
        "claim",
        "currentStatus",
        "claimsLedgerRowSha256",
        "proofState",
        "artifacts",
        "acceptanceBoundary",
        "remainingRequirements",
      ],
      label
    );
    assertNonemptyString(claim.claim, `${label}.claim`);
    assertNonemptyString(claim.currentStatus, `${label}.currentStatus`);
    assert(
      /^[a-f0-9]{64}$/.test(claim.claimsLedgerRowSha256),
      `${label}.claimsLedgerRowSha256 is invalid`
    );
    assert(
      claim.claim === ledgerClaims[index].claim,
      `${label}.claim does not match CLAIMS.md`
    );
    assert(
      claim.currentStatus === ledgerClaims[index].currentStatus,
      `${label}.currentStatus does not match CLAIMS.md`
    );
    assert(
      claim.claimsLedgerRowSha256 === claimsLedgerRowSha256(ledgerClaims[index]),
      `${label}.claimsLedgerRowSha256 does not match CLAIMS.md`
    );
    verifyReferences({
      item: claim,
      label,
      artifactById,
      usedArtifactIds,
      acceptedEvidenceRequired: true,
    });
    assert(!itemIds.has(claim.id), `duplicate manifest item id ${claim.id}`);
    itemIds.add(claim.id);
  });

  manifest.releaseControls.forEach((control, index) => {
    const label = `releaseControls[${index}]`;
    assertExactKeys(
      control,
      ["id", "proofState", "artifacts", "boundary", "remainingRequirements"],
      label
    );
    verifyReferences({
      item: control,
      label,
      artifactById,
      usedArtifactIds,
      acceptedEvidenceRequired: false,
    });
    assert(!itemIds.has(control.id), `duplicate manifest item id ${control.id}`);
    itemIds.add(control.id);
  });
  const releaseControlIds = manifest.releaseControls.map((control) => control.id);
  assert(
    JSON.stringify(releaseControlIds) === JSON.stringify(sorted(releaseControlIds)),
    "proof manifest releaseControls must be sorted by id"
  );

  const unusedArtifactIds = artifactIds.filter((id) => !usedArtifactIds.has(id));
  assert(
    unusedArtifactIds.length === 0,
    `proof manifest contains unused artifacts: ${unusedArtifactIds.join(", ")}`
  );

  const claimStates = manifest.claims.reduce(
    (counts, claim) => ({
      ...counts,
      [claim.proofState]: counts[claim.proofState] + 1,
    }),
    { VERIFIED: 0, PARTIAL: 0, PENDING: 0 }
  );

  return {
    schema: RECEIPT_SCHEMA,
    status: "PASS",
    manifestStatus: manifest.status,
    manifestSha256: sha256(rawManifest),
    reviewedOn: manifest.reviewedOn,
    claimCount: manifest.claims.length,
    claimStates,
    artifactCount: manifest.artifacts.length,
    releaseControlCount: manifest.releaseControls.length,
  };
}

function isMainModule() {
  return (
    process.argv[1] &&
    pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url
  );
}

if (isMainModule()) {
  try {
    console.log(JSON.stringify(verifyProofManifest(), null, 2));
  } catch (error) {
    console.error(
      JSON.stringify(
        {
          schema: RECEIPT_SCHEMA,
          status: "FAIL",
          error: error.message,
        },
        null,
        2
      )
    );
    process.exitCode = 1;
  }
}
