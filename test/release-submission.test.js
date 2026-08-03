import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  __test,
  parseSubmissionPacket,
  validateManifest,
  verifyReleaseSubmission
} from "../scripts/verify-release-submission.js";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const HEX = "a".repeat(64);

function fixtureManifest(overrides = {}) {
  return {
    schema: __test.MANIFEST_SCHEMA,
    status: __test.MANIFEST_STATUS,
    reviewedOn: "2026-07-31",
    claimBoundary: "Fixture draft submission boundary.",
    coordinates: { ...__test.EXPECTED_COORDINATES },
    finalReleaseRequirements: [
      ...__test.EXPECTED_FINAL_RELEASE_REQUIREMENTS
    ],
    gateMarkers: [...__test.EXPECTED_GATE_MARKERS],
    stopTokens: [...__test.EXPECTED_STOP_TOKENS],
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

function packetSource() {
  return fs.readFileSync(`${ROOT}/docs/SUBMISSION_PACKET.md`, "utf8");
}

function supportingSources() {
  return new Map(
    Object.entries(__test.EXPECTED_SURFACES).map(([id, surface]) => [
      id,
      fs.readFileSync(`${ROOT}/${surface.path}`, "utf8")
    ])
  );
}

test("current Devpost draft remains safely and explicitly blocked", () => {
  const receipt = verifyReleaseSubmission({ rootDir: ROOT });
  assert.equal(receipt.status, "DRAFT_SAFELY_BLOCKED");
  assert.equal(receipt.finalReleaseReady, false);
  assert.equal(receipt.surfaceCount, 10);
  assert.equal(receipt.checklistItemCount, 14);
  assert.equal(receipt.uncheckedChecklistItemCount, 14);
  assert.equal(receipt.stopTokenOccurrenceCount, 13);
  assert.equal(receipt.uniqueStopTokenCount, 12);
  assert.equal(receipt.officialCoordinateCount, 11);
  assert.equal(
    Object.values(receipt.checks).every((value) => value === true),
    true
  );
});

test("submission manifest rejects final approval and surface drift", () => {
  assert.equal(validateManifest(fixtureManifest()).finalReleaseReady, false);
  assert.throws(
    () => validateManifest(fixtureManifest({ finalReleaseReady: true })),
    /RELEASE_SUBMISSION_MANIFEST_BOUNDARY/
  );
  const changed = fixtureManifest();
  changed.surfaces[0].path = "docs/other.md";
  assert.throws(
    () => validateManifest(changed),
    /RELEASE_SUBMISSION_MANIFEST_SURFACE/
  );
});

test("submission packet rejects a checked publish gate", () => {
  const changed = packetSource().replace(
    "- [ ] Hosted CI passes",
    "- [x] Hosted CI passes"
  );
  assert.throws(
    () => parseSubmissionPacket(changed),
    /RELEASE_SUBMISSION_GATE_CHECKED/
  );
});

test("submission packet rejects missing or unknown stop tokens", () => {
  const missing = packetSource().replace(
    "[[LIVE_AWS_SERVICE_COPY_REQUIRED]]",
    "LIVE AWS COPY PENDING"
  );
  assert.throws(
    () => parseSubmissionPacket(missing),
    /RELEASE_SUBMISSION_STOP_TOKEN_COUNT/
  );
  const unknown = packetSource().replace(
    "[[LIVE_AWS_SERVICE_COPY_REQUIRED]]",
    "[[UNREVIEWED_RELEASE_TOKEN]]"
  );
  assert.throws(
    () => parseSubmissionPacket(unknown),
    /RELEASE_SUBMISSION_STOP_TOKEN_SET/
  );
});

test("submission packet rejects release-coordinate drift", () => {
  const changed = packetSource().replace(
    "| Public source | https://github.com/Flash-Bri/prooftoact |",
    "| Public source | https://example.invalid/tideproof |"
  );
  assert.throws(
    () => parseSubmissionPacket(changed),
    /RELEASE_SUBMISSION_COORDINATES_VALUES/
  );
});

test("submission control rejects a stale release-claims packet binding", () => {
  const sources = supportingSources();
  assert.equal(__test.assertSupportingSurfaces(sources), true);
  const claims = JSON.parse(sources.get("release-claims-manifest"));
  claims.surfaces.find(
    (surface) => surface.id === "submission-packet"
  ).sha256 = "0".repeat(64);
  sources.set("release-claims-manifest", JSON.stringify(claims));
  assert.throws(
    () => __test.assertSupportingSurfaces(sources),
    /RELEASE_SUBMISSION_CLAIMS_MANIFEST_PACKET/
  );
});
