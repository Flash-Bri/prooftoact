import assert from "node:assert/strict";
import crypto from "node:crypto";
import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { verifyProofManifest } from "../scripts/verify-proof-manifest.js";

const ROOT = fileURLToPath(new URL("..", import.meta.url));

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
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

test("current proof manifest binds every claim and exact artifact", () => {
  const receipt = verifyProofManifest({ rootDir: ROOT });

  assert.equal(receipt.status, "PASS");
  assert.equal(receipt.manifestStatus, "INCOMPLETE_LIVE_GATES_PENDING");
  assert.equal(receipt.claimCount, 11);
  assert.deepEqual(receipt.claimStates, {
    VERIFIED: 7,
    PARTIAL: 4,
    PENDING: 0,
  });
  assert.equal(receipt.artifactCount, 71);
  assert.equal(receipt.releaseControlCount, 16);
  assert.match(receipt.manifestSha256, /^[a-f0-9]{64}$/);
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
