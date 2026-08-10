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
        claimsLedgerRowSha256: sha256(
          JSON.stringify([
            "Fixture claim.",
            "Fixture verified",
            "fixture",
            "fixture",
          ])
        ),
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
  assert.equal(receipt.artifactCount, 126);
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
      /proof manifest nested brand-migration verification failed:UNCLASSIFIED$/
    );
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test("proof manifest exposes only fixed allowlisted nested brand failure codes", () => {
  const rootDir = makeRepositoryFixture();
  try {
    const verifyWithBrandFailure = (message) =>
      verifyProofManifest({
        rootDir,
        verifySecurity: () => {},
        verifyBrand: () => {
          throw new Error(message);
        },
      });

    for (const knownCode of [
      "BRAND_MANIFEST_JSON",
      "EXACT_GIT_SOURCE_OBJECT_PATH",
    ]) {
      assert.throws(() => verifyWithBrandFailure(knownCode), {
        message:
          "proof manifest nested brand-migration verification failed:" +
          knownCode,
      });
    }

    for (const unsafeMessage of [
      ["AS", "IA", "ABCDEFGHIJKLMNOP"].join(""),
      "FAKE_SECRET_MARKER",
      "A".repeat(40),
      "EXACT_GIT_SOURCE_OBJECT_PATH\n\t\u001b[31mCONTROL_TEXT",
      "A".repeat(129),
    ]) {
      let captured;
      try {
        verifyWithBrandFailure(unsafeMessage);
      } catch (error) {
        captured = error;
      }
      assert(captured instanceof Error);
      assert.equal(
        captured.message,
        "proof manifest nested brand-migration verification failed:UNCLASSIFIED"
      );
      assert.equal(captured.message.includes(unsafeMessage), false);
      assert.equal([...captured.message].some((character) =>
        character.charCodeAt(0) < 32
      ), false);
    }
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test("proof manifest propagates nested local full-drill failure", () => {
  const rootDir = makeRepositoryFixture();
  try {
    const receiptPath = path.join(
      rootDir,
      "evidence/local-full-drill-100-2026-08-04.json"
    );
    const receipt = JSON.parse(readFileSync(receiptPath, "utf8"));
    receipt.execution.providerBacked = true;
    const receiptBytes = `${JSON.stringify(receipt, null, 2)}\n`;
    writeFileSync(receiptPath, receiptBytes);

    const proofPath = path.join(rootDir, "PROOF_MANIFEST.json");
    const proof = JSON.parse(readFileSync(proofPath, "utf8"));
    proof.artifacts.find(
      ({ id }) => id === "local-full-drill-receipt"
    ).sha256 = sha256(receiptBytes);
    writeFileSync(proofPath, `${JSON.stringify(proof, null, 2)}\n`);

    assert.throws(
      () => verifyProofManifest({ rootDir }),
      /proof manifest nested local-full-drill verification failed/
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
  const proofManifestSource = read("PROOF_MANIFEST.json");
  const manifest = JSON.parse(proofManifestSource);

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
    ["PROOF_MANIFEST.json", proofManifestSource],
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
  const dviClaim = manifest.claims.find(
    ({ id }) => id === "distributed-vector-index"
  );
  assert(fullDrillClaim, "full drill proof claim missing");
  assert(dviClaim, "DVI proof claim missing");
  assert.deepEqual(fullDrillClaim.artifacts, [
    "full-drill-evidence",
    "integrated-live-drill-harness",
    "integrated-live-drill-runner",
    "integrated-live-drill-tests",
    "local-full-drill-harness",
    "local-full-drill-receipt",
    "local-full-drill-runner",
    "local-full-drill-tests",
    "local-full-drill-verifier",
    "recovery-bundle-persistence-tests",
  ]);
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
        line.startsWith("| The approved 100+1 high-water target binds")
      ),
    ],
  ];
  for (const [label, row] of dviClaimRows) {
    assert(row, `${label} missing from CLAIMS.md`);
  }

  for (const [label, source] of [
    ...dviClaimRows,
    ["docs/FULL_DRILL_EVIDENCE.md", fullDrill],
    ["PROOF_MANIFEST.json distributed-vector-index", dviClaim.acceptanceBoundary],
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

test("proof manifest rejects required-artifact drift in the claims ledger mapping", () => {
  const fixture = makeFixture();
  try {
    const claimsPath = path.join(fixture.rootDir, "CLAIMS.md");
    const changedClaims = readFileSync(claimsPath, "utf8").replace(
      "| Fixture claim. | Fixture verified | fixture | fixture |",
      "| Fixture claim. | Fixture verified | changed fixture | fixture |"
    );
    writeFileSync(claimsPath, changedClaims);
    fixture.manifest.artifacts[0].sha256 = sha256(changedClaims);
    writeFileSync(
      fixture.manifestPath,
      `${JSON.stringify(fixture.manifest, null, 2)}\n`
    );

    assert.throws(
      () => verifyProofManifest(fixture),
      /claims\[0\]\.claimsLedgerRowSha256 does not match CLAIMS\.md/
    );
  } finally {
    rmSync(fixture.rootDir, { recursive: true, force: true });
  }
});

test("proof manifest rejects acceptance-condition drift in the claims ledger mapping", () => {
  const fixture = makeFixture();
  try {
    const claimsPath = path.join(fixture.rootDir, "CLAIMS.md");
    const changedClaims = readFileSync(claimsPath, "utf8").replace(
      "| Fixture claim. | Fixture verified | fixture | fixture |",
      "| Fixture claim. | Fixture verified | fixture | changed fixture |"
    );
    writeFileSync(claimsPath, changedClaims);
    fixture.manifest.artifacts[0].sha256 = sha256(changedClaims);
    writeFileSync(
      fixture.manifestPath,
      `${JSON.stringify(fixture.manifest, null, 2)}\n`
    );

    assert.throws(
      () => verifyProofManifest(fixture),
      /claims\[0\]\.claimsLedgerRowSha256 does not match CLAIMS\.md/
    );
  } finally {
    rmSync(fixture.rootDir, { recursive: true, force: true });
  }
});

test("proof manifest rejects a claims row without its terminal pipe", () => {
  const fixture = makeFixture();
  try {
    const claimsPath = path.join(fixture.rootDir, "CLAIMS.md");
    const changedClaims = readFileSync(claimsPath, "utf8").replace(
      "| Fixture claim. | Fixture verified | fixture | fixture |",
      "| Fixture claim. | Fixture verified | fixture | fixture X"
    );
    writeFileSync(claimsPath, changedClaims);
    fixture.manifest.artifacts[0].sha256 = sha256(changedClaims);
    writeFileSync(
      fixture.manifestPath,
      `${JSON.stringify(fixture.manifest, null, 2)}\n`
    );

    assert.throws(
      () => verifyProofManifest(fixture),
      /CLAIMS\.md row \d+ must end with a pipe/
    );
  } finally {
    rmSync(fixture.rootDir, { recursive: true, force: true });
  }
});

test("proof manifest rejects duplicate claim rows", () => {
  const fixture = makeFixture();
  try {
    const claimsPath = path.join(fixture.rootDir, "CLAIMS.md");
    const originalRow =
      "| Fixture claim. | Fixture verified | fixture | fixture |";
    const changedClaims = readFileSync(claimsPath, "utf8").replace(
      originalRow,
      `${originalRow}\n${originalRow}`
    );
    writeFileSync(claimsPath, changedClaims);
    fixture.manifest.artifacts[0].sha256 = sha256(changedClaims);
    fixture.manifest.claims.push({
      ...fixture.manifest.claims[0],
      id: "fixture-claim-duplicate",
    });
    writeFileSync(
      fixture.manifestPath,
      `${JSON.stringify(fixture.manifest, null, 2)}\n`
    );

    assert.throws(
      () => verifyProofManifest(fixture),
      /CLAIMS\.md claim text must be unique/
    );
  } finally {
    rmSync(fixture.rootDir, { recursive: true, force: true });
  }
});

test("proof manifest rejects duplicate canonical claim tables", () => {
  const fixture = makeFixture();
  try {
    const claimsPath = path.join(fixture.rootDir, "CLAIMS.md");
    const canonicalTable = [
      "| Claim | Current status | Required artifact | Acceptance condition |",
      "| --- | --- | --- | --- |",
      "| Fixture claim. | Fixture verified | fixture | fixture |",
    ].join("\n");
    const changedClaims = readFileSync(claimsPath, "utf8").replace(
      canonicalTable,
      `${canonicalTable}\n\n${canonicalTable}`
    );
    writeFileSync(claimsPath, changedClaims);
    fixture.manifest.artifacts[0].sha256 = sha256(changedClaims);
    writeFileSync(
      fixture.manifestPath,
      `${JSON.stringify(fixture.manifest, null, 2)}\n`
    );

    assert.throws(
      () => verifyProofManifest(fixture),
      /CLAIMS\.md canonical claim-table header must appear exactly once/
    );
  } finally {
    rmSync(fixture.rootDir, { recursive: true, force: true });
  }
});

test("proof manifest rejects empty required-artifact and acceptance-condition cells", () => {
  const cases = [
    {
      label: "required artifact",
      row: "| Fixture claim. | Fixture verified | | fixture |",
      digestCells: ["Fixture claim.", "Fixture verified", "", "fixture"],
    },
    {
      label: "acceptance condition",
      row: "| Fixture claim. | Fixture verified | fixture | |",
      digestCells: ["Fixture claim.", "Fixture verified", "fixture", ""],
    },
  ];

  for (const testCase of cases) {
    const fixture = makeFixture();
    try {
      const claimsPath = path.join(fixture.rootDir, "CLAIMS.md");
      const changedClaims = readFileSync(claimsPath, "utf8").replace(
        "| Fixture claim. | Fixture verified | fixture | fixture |",
        testCase.row
      );
      writeFileSync(claimsPath, changedClaims);
      fixture.manifest.artifacts[0].sha256 = sha256(changedClaims);
      fixture.manifest.claims[0].claimsLedgerRowSha256 = sha256(
        JSON.stringify(testCase.digestCells)
      );
      writeFileSync(
        fixture.manifestPath,
        `${JSON.stringify(fixture.manifest, null, 2)}\n`
      );

      assert.throws(
        () => verifyProofManifest(fixture),
        new RegExp(`CLAIMS\\.md row \\d+ ${testCase.label} must not be empty`)
      );
    } finally {
      rmSync(fixture.rootDir, { recursive: true, force: true });
    }
  }
});
