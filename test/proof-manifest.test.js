import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { AUTHORITY_RACE_RECEIPT_SCHEMA } from "../src/cloud/aws-authority-race.js";
import { verifyProofManifest } from "../scripts/verify-proof-manifest.js";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const DVI_AWS_SOURCE_BOUNDARY =
  "The source path now consumes database-authorized DVI proposal identities and the exact selected-evidence digest, but no provider-backed receipt yet proves the live DVI-to-AWS handoff.";

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function oneIntegerMatch(source, pattern, label) {
  const matches = [...source.matchAll(pattern)];
  assert.equal(matches.length, 1, `${label} must appear exactly once`);
  const value = Number(matches[0][1]);
  assert(Number.isSafeInteger(value), `${label} must be an integer`);
  return value;
}

function makeFixture() {
  const rootDir = mkdtempSync(path.join(tmpdir(), "tideproof-proof-manifest-"));
  const claims = [
    "# Claims",
    "",
    "| Claim | Current status | Required artifact | Acceptance condition |",
    "| --- | --- | --- | --- |",
    "| Fixture claim. | Fixture verified | fixture | fixture |",
    "",
  ].join("\n");
  const evidence = "fixture evidence\n";
  writeFileSync(path.join(rootDir, "CLAIMS.md"), claims);
  writeFileSync(path.join(rootDir, "evidence.md"), evidence);

  const manifest = {
    schema: "tideproof.proof-manifest.v1",
    status: "INCOMPLETE_LIVE_GATES_PENDING",
    reviewedOn: "2026-07-31",
    claimBoundary: "Fixture only.",
    artifacts: [
      {
        id: "claims-ledger",
        path: "CLAIMS.md",
        sha256: sha256(claims),
        kind: "boundary-ledger",
      },
      {
        id: "fixture-evidence",
        path: "evidence.md",
        sha256: sha256(evidence),
        kind: "accepted-evidence",
      },
    ],
    claims: [
      {
        id: "fixture-claim",
        claim: "Fixture claim.",
        currentStatus: "Fixture verified",
        proofState: "VERIFIED",
        artifacts: ["fixture-evidence"],
        acceptanceBoundary: "Fixture acceptance only.",
        remainingRequirements: [],
      },
    ],
    releaseControls: [
      {
        id: "claim-ledger-control",
        proofState: "VERIFIED",
        artifacts: ["claims-ledger"],
        boundary: "Fixture ledger only.",
        remainingRequirements: [],
      },
    ],
  };
  const manifestPath = path.join(rootDir, "PROOF_MANIFEST.json");
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  return { rootDir, manifest, manifestPath };
}

function makeRepositoryFixture() {
  const rootDir = mkdtempSync(path.join(tmpdir(), "prooftoact-proof-repo-"));
  const trackedFiles = execFileSync(
    "git",
    ["ls-files", "--cached", "--others", "--exclude-standard", "-z"],
    { cwd: ROOT }
  )
    .toString("utf8")
    .split("\0")
    .filter(Boolean);
  for (const relativePath of trackedFiles) {
    const destination = path.join(rootDir, relativePath);
    mkdirSync(path.dirname(destination), { recursive: true });
    copyFileSync(path.join(ROOT, relativePath), destination);
  }
  execFileSync("git", ["init", "-q"], { cwd: rootDir });
  execFileSync("git", ["add", "--", "."], { cwd: rootDir });
  return rootDir;
}

test("current proof manifest binds every claim and exact artifact", () => {
  const receipt = verifyProofManifest({ rootDir: ROOT });

  assert.equal(receipt.status, "PASS");
  assert.equal(receipt.manifestStatus, "INCOMPLETE_LIVE_GATES_PENDING");
  assert.equal(receipt.claimCount, 12);
  assert.deepEqual(receipt.claimStates, {
    VERIFIED: 5,
    PARTIAL: 7,
    PENDING: 0,
  });
  assert.equal(receipt.artifactCount, 95);
  assert.equal(receipt.releaseControlCount, 17);
  assert.match(receipt.manifestSha256, /^[a-f0-9]{64}$/);
});

test("proof manifest propagates nested brand-migration failure", () => {
  const rootDir = makeRepositoryFixture();
  try {
    const migrationPath = path.join(rootDir, "RENAME_MIGRATION_MANIFEST.json");
    const migration = JSON.parse(readFileSync(migrationPath, "utf8"));
    migration.futureAwsMainStack = "wrong-stack";
    const migrationBytes = `${JSON.stringify(migration, null, 2)}\n`;
    writeFileSync(migrationPath, migrationBytes);

    const proofPath = path.join(rootDir, "PROOF_MANIFEST.json");
    const proof = JSON.parse(readFileSync(proofPath, "utf8"));
    proof.artifacts.find(
      (artifact) => artifact.id === "brand-migration-manifest"
    ).sha256 = sha256(migrationBytes);
    writeFileSync(proofPath, `${JSON.stringify(proof, null, 2)}\n`);

    assert.throws(
      () => verifyProofManifest({ rootDir }),
      /proof manifest nested brand-migration verification failed/
    );
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test("release copy matches executable and generated source contracts", () => {
  const read = (relativePath) =>
    readFileSync(path.join(ROOT, relativePath), "utf8");
  const readme = read("README.md");
  const claims = read("CLAIMS.md");
  const fullDrill = read("docs/FULL_DRILL_EVIDENCE.md");
  const awsBoundary = read("docs/AWS_GATE2.md");
  const notices = read("THIRD_PARTY_NOTICES.txt");
  const inventory = read("docs/DEPENDENCY_INVENTORY.md");
  const manifest = JSON.parse(read("PROOF_MANIFEST.json"));

  const noticeCount = oneIntegerMatch(
    notices,
    /^Bundled package union: (\d+)$/gmu,
    "notice package count"
  );
  const inventoryCount = oneIntegerMatch(
    inventory,
    /^- Complete locked package records: \*\*(\d+)\*\*$/gmu,
    "inventory package count"
  );
  const readmeCount = oneIntegerMatch(
    readme,
    /binds the (\d+)-package union/gu,
    "README package count"
  );
  assert.equal(readmeCount, noticeCount);

  const dependencyControl = manifest.releaseControls.find(
    ({ id }) => id === "dependency-inventory-control"
  );
  assert(dependencyControl, "dependency inventory proof control missing");
  assert.equal(
    oneIntegerMatch(
      dependencyControl.boundary,
      /complete (\d+)-package inventory/gu,
      "proof inventory package count"
    ),
    inventoryCount
  );

  for (const [label, source] of [
    ["CLAIMS.md", claims],
    ["docs/FULL_DRILL_EVIDENCE.md", fullDrill],
    ["docs/AWS_GATE2.md", awsBoundary],
  ]) {
    const schemas = [
      ...new Set(
        [...source.matchAll(/tideproof\.aws-authority-race-receipt\.v\d+/gu)].map(
          ([schema]) => schema
        )
      ),
    ];
    assert.deepEqual(schemas, [AUTHORITY_RACE_RECEIPT_SCHEMA], label);
  }

  const fullDrillClaim = manifest.claims.find(
    ({ id }) => id === "full-highwater-drills"
  );
  assert(fullDrillClaim, "full drill proof claim missing");
  const claimRows = claims.split("\n");
  const dviClaimRows = [
    [
      "DVI ranking claim",
      claimRows.find((line) =>
        line.startsWith(
          "| CockroachDB Distributed Vector Indexing ranks a database-produced snapshot"
        )
      ),
    ],
    [
      "full high-water drill claim",
      claimRows.find((line) =>
        line.startsWith("| One hundred full high-water drills bind")
      ),
    ],
  ];
  for (const [label, row] of dviClaimRows) {
    assert(row, `${label} missing from CLAIMS.md`);
  }

  for (const [label, source] of [
    ...dviClaimRows,
    ["docs/FULL_DRILL_EVIDENCE.md", fullDrill],
    ["PROOF_MANIFEST.json", fullDrillClaim.acceptanceBoundary],
  ]) {
    const normalized = source.replace(/\s+/gu, " ");
    assert.equal(
      normalized.split(DVI_AWS_SOURCE_BOUNDARY).length - 1,
      1,
      label
    );
    assert.doesNotMatch(
      normalized,
      /\bAWS(?: authority request| path)? does not yet consume\b/u,
      label
    );
  }
});

test("current proof manifest recursively requires release-security PASS", () => {
  assert.throws(
    () => verifyProofManifest({
      rootDir: ROOT,
      verifySecurity: () => {
        throw new Error("simulated nested security failure");
      }
    }),
    /proof manifest nested release-security verification failed/
  );
});

test("proof manifest rejects changed evidence bytes", () => {
  const fixture = makeFixture();
  try {
    writeFileSync(path.join(fixture.rootDir, "evidence.md"), "changed evidence\n");
    assert.throws(
      () => verifyProofManifest(fixture),
      /fixture-evidence SHA-256 mismatch/
    );
  } finally {
    rmSync(fixture.rootDir, { recursive: true, force: true });
  }
});

test("proof manifest rejects paths outside the repository", () => {
  const fixture = makeFixture();
  try {
    fixture.manifest.artifacts[0].path = "../CLAIMS.md";
    writeFileSync(
      fixture.manifestPath,
      `${JSON.stringify(fixture.manifest, null, 2)}\n`
    );
    assert.throws(
      () => verifyProofManifest(fixture),
      /must not contain empty or parent segments/
    );
  } finally {
    rmSync(fixture.rootDir, { recursive: true, force: true });
  }
});

test("proof manifest rejects a symbolic artifact path", () => {
  const fixture = makeFixture();
  try {
    symlinkSync(
      path.join(fixture.rootDir, "evidence.md"),
      path.join(fixture.rootDir, "linked-evidence.md")
    );
    fixture.manifest.artifacts[1].path = "linked-evidence.md";
    writeFileSync(
      fixture.manifestPath,
      `${JSON.stringify(fixture.manifest, null, 2)}\n`
    );
    assert.throws(
      () => verifyProofManifest(fixture),
      /must not contain symbolic links/
    );
  } finally {
    rmSync(fixture.rootDir, { recursive: true, force: true });
  }
});

test("proof manifest rejects a claim omitted from the claims ledger mapping", () => {
  const fixture = makeFixture();
  try {
    const claimsPath = path.join(fixture.rootDir, "CLAIMS.md");
    const expandedClaims = [
      "# Claims",
      "",
      "| Claim | Current status | Required artifact | Acceptance condition |",
      "| --- | --- | --- | --- |",
      "| Fixture claim. | Fixture verified | fixture | fixture |",
      "| Omitted claim. | Pending | fixture | fixture |",
      "",
    ].join("\n");
    writeFileSync(claimsPath, expandedClaims);
    fixture.manifest.artifacts[0].sha256 = sha256(expandedClaims);
    writeFileSync(
      fixture.manifestPath,
      `${JSON.stringify(fixture.manifest, null, 2)}\n`
    );
    assert.throws(
      () => verifyProofManifest(fixture),
      /proof manifest has 1 claims but CLAIMS.md has 2/
    );
  } finally {
    rmSync(fixture.rootDir, { recursive: true, force: true });
  }
});
