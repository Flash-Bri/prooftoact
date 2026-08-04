import assert from "node:assert/strict";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  RELEASE_CLAIMS_STOP_TOKEN_COUNT,
  RELEASE_CLAIMS_SURFACE_COUNT,
  RELEASE_CLAIMS_UNCHECKED_GATE_COUNT,
  __test,
  assertRequiredMarkers,
  validateAllowedUrls,
  validateManifest,
  validateReleaseClaimsReceipt,
  validateSubmissionDraft,
  verifyReleaseClaims
} from "../scripts/verify-release-claims.js";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const HEX = "a".repeat(64);

function fixtureManifest(overrides = {}) {
  return {
    schema: __test.MANIFEST_SCHEMA,
    status: __test.MANIFEST_STATUS,
    reviewedOn: "2026-07-31",
    claimBoundary: "Fixture pending claim boundary.",
    finalReleaseRequirements: [
      ...__test.EXPECTED_FINAL_RELEASE_REQUIREMENTS
    ],
    surfaces: Object.entries(__test.EXPECTED_SURFACES).map(
      ([id, surface]) => ({
        id,
        path: surface.path,
        role: surface.role,
        sha256: HEX
      })
    ),
    finalReleaseReady: false,
    ...overrides
  };
}

function markerFixture() {
  return new Map(
    Object.entries(__test.REQUIRED_MARKERS).map(([id, markers]) => [
      id,
      markers.join("\n")
    ])
  );
}

function submissionFixture() {
  const tokens = Object.entries(__test.EXPECTED_STOP_TOKENS).flatMap(
    ([name, count]) => Array.from({ length: count }, () => `[[${name}]]`)
  );
  return [
    "# Draft",
    "",
    ...tokens,
    "",
    "## Hard publish gate",
    "",
    ...Array.from({ length: 14 }, (_, index) =>
      `- [ ] Fixture release gate ${index + 1}.`
    ),
    "",
    "## Next section",
    ""
  ].join("\n");
}

test("current release claim surfaces match the reviewed pending state", () => {
  const receipt = verifyReleaseClaims({ rootDir: ROOT });
  assert.equal(receipt.status, "CURRENT_PUBLIC_CLAIMS_PASS");
  assert.equal(receipt.finalReleaseReady, false);
  assert.equal(receipt.claimCount, 12);
  assert.deepEqual(receipt.claimStates, {
    VERIFIED: 5,
    PARTIAL: 7,
    PENDING: 0
  });
  assert.equal(receipt.surfaceCount, RELEASE_CLAIMS_SURFACE_COUNT);
  assert.equal(receipt.stopTokenCount, RELEASE_CLAIMS_STOP_TOKEN_COUNT);
  assert.equal(
    receipt.uncheckedGateCount,
    RELEASE_CLAIMS_UNCHECKED_GATE_COUNT
  );
  assert.equal(
    Object.values(receipt.checks).every((value) => value === true),
    true
  );
});

test("claims receipt contract is source-derived and fails closed on drift", () => {
  const receipt = verifyReleaseClaims({ rootDir: ROOT });
  assert.equal(validateReleaseClaimsReceipt(receipt), receipt);
  for (const field of [
    "surfaceCount",
    "stopTokenCount",
    "uncheckedGateCount"
  ]) {
    for (const offset of [-1, 1]) {
      const stale = structuredClone(receipt);
      stale[field] += offset;
      assert.throws(
        () => validateReleaseClaimsReceipt(stale),
        /RELEASE_CLAIMS_RECEIPT_CONTRACT/
      );
    }
  }
});

test("claims inventory binds the full-drill evidence boundary", () => {
  assert.deepEqual(__test.EXPECTED_SURFACES["full-drill-evidence"], {
    path: "docs/FULL_DRILL_EVIDENCE.md",
    role: "EVIDENCE_BOUNDARY"
  });
  assert.equal(
    __test.REQUIRED_MARKERS["full-drill-evidence"].length,
    4
  );
});

test("manifest rejects final approval and any changed surface contract", () => {
  assert.equal(validateManifest(fixtureManifest()).finalReleaseReady, false);
  assert.throws(
    () => validateManifest(fixtureManifest({ finalReleaseReady: true })),
    /RELEASE_CLAIMS_MANIFEST_BOUNDARY/
  );
  const changed = fixtureManifest();
  changed.surfaces[0].path = "docs/OTHER.md";
  assert.throws(
    () => validateManifest(changed),
    /RELEASE_CLAIMS_MANIFEST_SURFACE/
  );
});

test("required proof boundaries fail closed when one marker disappears", () => {
  const sources = markerFixture();
  assert.equal(assertRequiredMarkers(sources), true);
  sources.set("browser-document", "Synthetic scenario only");
  assert.throws(
    () => assertRequiredMarkers(sources),
    /RELEASE_CLAIMS_MARKER_BROWSER_DOCUMENT/
  );
});

test("submission draft requires every stop token and unchecked hard gate", () => {
  const source = submissionFixture();
  assert.deepEqual(validateSubmissionDraft(source), {
    stopTokenCount: RELEASE_CLAIMS_STOP_TOKEN_COUNT,
    uncheckedGateCount: RELEASE_CLAIMS_UNCHECKED_GATE_COUNT
  });
  assert.throws(
    () =>
      validateSubmissionDraft(
        source.replace(
          "[[FINAL_RELEASE_COMMIT_REQUIRED]]",
          "deadbeef"
        )
      ),
    /RELEASE_CLAIMS_SUBMISSION_STOP_TOKENS/
  );
  assert.throws(
    () =>
      validateSubmissionDraft(
        source.replace("- [ ] Fixture release gate 1.", "- [x] Approved")
      ),
    /RELEASE_CLAIMS_SUBMISSION_PREMATURE_APPROVAL/
  );
});

test("absolute URL policy rejects a premature public destination", () => {
  const sources = new Map([
    ["fixture", "https://github.com/Flash-Bri/prooftoact"]
  ]);
  assert.deepEqual(validateAllowedUrls(sources), [
    "https://github.com/Flash-Bri/prooftoact"
  ]);
  sources.set("fixture", "https://tideproof.net");
  assert.throws(
    () => validateAllowedUrls(sources),
    /RELEASE_CLAIMS_UNREVIEWED_URL/
  );
});
