import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { verifyBrandMigration } from "../scripts/verify-brand-migration.js";

const ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  ".."
);
const TRACKED_FILES = execFileSync(
  "git",
  ["ls-files", "--cached", "--others", "--exclude-standard", "-z"],
  { cwd: ROOT }
)
  .toString("utf8")
  .split("\0")
  .filter(Boolean);

function fixture() {
  const fixtureRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "prooftoact-brand-")
  );
  for (const relativePath of TRACKED_FILES) {
    const source = path.join(ROOT, relativePath);
    const destination = path.join(fixtureRoot, relativePath);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.copyFileSync(source, destination);
  }
  return fixtureRoot;
}

function writeCanonicalJson(filePath, value) {
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function rejectsFixture(mutate, expected) {
  const fixtureRoot = fixture();
  try {
    mutate(fixtureRoot);
    assert.throws(
      () =>
        verifyBrandMigration({
          rootDir: fixtureRoot,
          trackedFileList: TRACKED_FILES
        }),
      expected
    );
  } finally {
    fs.rmSync(fixtureRoot, { recursive: true, force: true });
  }
}

test("ProofToAct brand migration preserves history and binds current surfaces", () => {
  const receipt = verifyBrandMigration();
  assert.equal(receipt.status, "CURRENT_BRAND_MIGRATION_PASS");
  assert.equal(receipt.approvedName, "ProofToAct");
  assert.equal(receipt.preservedEvidenceCount, 20);
  assert.equal(receipt.domainReferenceFileCount, 7);
  assert.equal(receipt.domainReferenceOccurrenceCount, 9);
});

test("ProofToAct brand migration rejects manifest field and baseline drift", () => {
  rejectsFixture((fixtureRoot) => {
    const manifestPath = path.join(
      fixtureRoot,
      "RENAME_MIGRATION_MANIFEST.json"
    );
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    manifest.futureAwsMainStack = "wrong-stack";
    writeCanonicalJson(manifestPath, manifest);
  }, /BRAND_MANIFEST_FIELD:futureAwsMainStack/);

  rejectsFixture((fixtureRoot) => {
    const manifestPath = path.join(
      fixtureRoot,
      "RENAME_MIGRATION_MANIFEST.json"
    );
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    manifest.evidenceBaseline.pop();
    writeCanonicalJson(manifestPath, manifest);
  }, /BRAND_EVIDENCE_BASELINE/);
});

test("ProofToAct brand migration rejects historical evidence drift", () => {
  rejectsFixture((fixtureRoot) => {
    fs.appendFileSync(
      path.join(
        fixtureRoot,
        "evidence/gate1-authority-2026-07-30.md"
      ),
      "\ndrift\n"
    );
  }, /HISTORICAL_EVIDENCE_DRIFT:evidence\/gate1-authority/);
});

test("ProofToAct brand migration rejects former-name and domain spread", () => {
  rejectsFixture((fixtureRoot) => {
    fs.appendFileSync(path.join(fixtureRoot, "README.md"), "\nTideproof\n");
  }, /FORMER_PUBLIC_NAME:README\.md/);

  rejectsFixture((fixtureRoot) => {
    fs.appendFileSync(
      path.join(fixtureRoot, "docs/CONTEST_MATRIX.md"),
      "\nhttps:\/\/tideproof.net\n"
    );
  }, /DOMAIN_REFERENCE_DRIFT:docs\/CONTEST_MATRIX\.md/);
});

test("ProofToAct brand migration rejects unsafe tracked paths and symlinks", () => {
  const fixtureRoot = fixture();
  try {
    assert.throws(
      () =>
        verifyBrandMigration({
          rootDir: fixtureRoot,
          trackedFileList: [...TRACKED_FILES, "../README.md"]
        }),
      /BRAND_TRACKED_PATH/
    );
  } finally {
    fs.rmSync(fixtureRoot, { recursive: true, force: true });
  }

  rejectsFixture((symlinkRoot) => {
    const readmePath = path.join(symlinkRoot, "README.md");
    fs.unlinkSync(readmePath);
    fs.symlinkSync("package.json", readmePath);
  }, /BRAND_TRACKED_FILE:README\.md/);
});
