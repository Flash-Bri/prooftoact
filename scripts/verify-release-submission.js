import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const DEFAULT_ROOT = fileURLToPath(new URL("..", import.meta.url));
const MANIFEST_PATH = "RELEASE_SUBMISSION_MANIFEST.json";
const MANIFEST_SCHEMA = "tideproof.release-submission-manifest.v1";
const MANIFEST_STATUS =
  "DRAFT_SAFELY_BLOCKED_FINAL_RELEASE_RECEIPTS_PENDING";
const RECEIPT_SCHEMA = "tideproof.release-submission-verification.v1";
const HEX_64 = /^[0-9a-f]{64}$/;

const EXPECTED_COORDINATES = Object.freeze({
  competitionOverview: "https://cockroachdb-ai.devpost.com/",
  competitionResources: "https://cockroachdb-ai.devpost.com/resources",
  competitionRules: "https://cockroachdb-ai.devpost.com/rules",
  internalDeadline: "2026-08-16 at 5:00 PM ET",
  judgeAccessThrough: "2026-09-15 at 5:00 PM ET",
  license: "MIT",
  officialDeadline: "2026-08-18 at 5:00 PM ET",
  officialPageCheckDate: "2026-07-30",
  projectName: "Tideproof",
  publicSource: "https://github.com/Flash-Bri/tideproof",
  subtitle: "Admissibility memory for high-stakes agents"
});

const EXPECTED_FINAL_RELEASE_REQUIREMENTS = Object.freeze([
  "Accepted live AWS, public-demo, public-video, cost, and teardown receipts bound to the exact official-main commit and deployed artifact hashes.",
  "Exact-release private human review of claims, privacy, security, accessibility, rights, URLs, repository metadata, video, and every submitted field.",
  "Explicit authorized-entrant confirmation of eligibility, identity, representation, registration, and final submission authority.",
  "Timestamped final preview, submission, submitted-field, public-URL, and signed-out post-submit verification receipts."
]);

const EXPECTED_GATE_MARKERS = Object.freeze([
  "The public repository, MIT license",
  "Hosted CI passes at the exact final source commit",
  "The AWS application is deployed",
  "Live evidence proves the named AWS services actually used",
  "The live demo is free, stable, signed-out, resettable, synthetic-only",
  "A separate signed-out reviewer completes",
  "The video is under three minutes",
  "Every visual, font, trademark, music track, voice",
  "The architecture diagram, screenshots, README, website, video",
  "`CLAIMS.md`, `CLEAN_ROOM.md`",
  "The Devpost preview contains no secrets",
  "Brian or the authorized entrant confirms eligibility",
  "A private preview is approved",
  "A final timestamped receipt records every submitted URL and field"
]);

const EXPECTED_STOP_TOKENS = Object.freeze([
  "ACCEPTED_LIVE_AUTHORITY_RACE_RECEIPT_REQUIRED",
  "ACCEPTED_LIVE_AWS_RECEIPT_REQUIRED",
  "ALL_REQUIRED_ROWS_RELEASE_CLEARED",
  "FINAL_AWS_ARCHITECTURE_COPY_REQUIRED_FROM_LIVE_RECEIPT",
  "FINAL_RELEASE_COMMIT_REQUIRED",
  "LIVE_AWS_EVIDENCE_REQUIRED",
  "LIVE_AWS_SERVICE_COPY_REQUIRED",
  "OWNER_CONFIRMATION_REQUIRED",
  "PUBLIC_DEMO_REQUIRED",
  "PUBLIC_SIGNED_OUT_DEMO_URL_REQUIRED",
  "PUBLIC_YOUTUBE_OR_VIMEO_URL_REQUIRED",
  "REPLACE_WITH_POST_RELEASE_ROADMAP_AFTER_FINAL_SCOPE_AUDIT"
]);

const EXPECTED_SURFACES = Object.freeze({
  "claims-ledger": Object.freeze({
    path: "CLAIMS.md",
    role: "CLAIMS_BOUNDARY"
  }),
  "contest-matrix": Object.freeze({
    path: "docs/CONTEST_MATRIX.md",
    role: "CONTEST_REQUIREMENT_MATRIX"
  }),
  "release-claims-manifest": Object.freeze({
    path: "RELEASE_CLAIMS_MANIFEST.json",
    role: "PUBLIC_CLAIM_INVENTORY"
  }),
  "release-submission-ledger": Object.freeze({
    path: "docs/RELEASE_SUBMISSION.md",
    role: "SUBMISSION_CONTROL_LEDGER"
  }),
  "rights-ledger": Object.freeze({
    path: "docs/media/RIGHTS.md",
    role: "MEDIA_RIGHTS_BOUNDARY"
  }),
  "submission-packet": Object.freeze({
    path: "docs/SUBMISSION_PACKET.md",
    role: "DEVPOST_DRAFT"
  }),
  "winning-plan": Object.freeze({
    path: "docs/WINNING_PLAN.md",
    role: "RELEASE_PLAN"
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

function normalizeWhitespace(value) {
  return value.replace(/\s+/g, " ").trim();
}

function stripCode(value) {
  const trimmed = value.trim();
  return trimmed.startsWith("`") && trimmed.endsWith("`")
    ? trimmed.slice(1, -1)
    : trimmed;
}

function parseCoordinatesTable(source) {
  const lines = source.split("\n");
  const header = "| Field | Release value |";
  const headerIndex = lines.indexOf(header);
  assert(headerIndex !== -1, "RELEASE_SUBMISSION_COORDINATES_HEADER");
  assert(
    /^\|\s*-+\s*\|\s*-+\s*\|$/.test(lines[headerIndex + 1] ?? ""),
    "RELEASE_SUBMISSION_COORDINATES_SEPARATOR"
  );
  const values = {};
  for (let index = headerIndex + 2; index < lines.length; index += 1) {
    const line = lines[index];
    if (!line.startsWith("|")) {
      break;
    }
    const cells = line
      .slice(1, -1)
      .split("|")
      .map((cell) => cell.trim());
    assert(cells.length === 2, "RELEASE_SUBMISSION_COORDINATES_ROW");
    assert(!Object.hasOwn(values, cells[0]), "RELEASE_SUBMISSION_COORDINATES_DUPLICATE");
    values[cells[0]] = stripCode(cells[1]);
  }
  assert(
    sameJson(Object.keys(values), [
      "Project name",
      "Subtitle",
      "Public source",
      "License",
      "Source commit",
      "Functional demo",
      "Public video",
      "Entrant / authorized representative"
    ]),
    "RELEASE_SUBMISSION_COORDINATES_SET"
  );
  return values;
}

function hardGateSection(source) {
  const start = source.indexOf("## Hard publish gate");
  const end = source.indexOf("## Official requirement mapping");
  assert(start !== -1 && end > start, "RELEASE_SUBMISSION_HARD_GATE_SECTION");
  return source.slice(start, end);
}

export function parseSubmissionPacket(source) {
  assert(typeof source === "string", "RELEASE_SUBMISSION_PACKET_SOURCE");
  const normalized = normalizeWhitespace(source);
  assert(
    source.startsWith("# Devpost submission packet\n\n**Status: DRAFT — NOT READY TO SUBMIT**\n"),
    "RELEASE_SUBMISSION_DRAFT_STATUS"
  );
  assert(
    normalized.includes(
      `The official competition overview, rules, and resources were rechecked on ${EXPECTED_COORDINATES.officialPageCheckDate}:`
    ) &&
      normalized.includes(EXPECTED_COORDINATES.competitionOverview) &&
      normalized.includes(EXPECTED_COORDINATES.competitionRules) &&
      normalized.includes(EXPECTED_COORDINATES.competitionResources) &&
      normalized.includes(
        `The official submission period ends on ${EXPECTED_COORDINATES.officialDeadline}.`
      ) &&
      normalized.includes(
        `internal deadline is ${EXPECTED_COORDINATES.internalDeadline}`
      ) &&
      normalized.includes(
        `available through the end of judging on ${EXPECTED_COORDINATES.judgeAccessThrough}.`
      ),
    "RELEASE_SUBMISSION_OFFICIAL_COORDINATES"
  );

  const coordinates = parseCoordinatesTable(source);
  assert(
    sameJson(coordinates, {
      "Project name": EXPECTED_COORDINATES.projectName,
      Subtitle: EXPECTED_COORDINATES.subtitle,
      "Public source": EXPECTED_COORDINATES.publicSource,
      License: EXPECTED_COORDINATES.license,
      "Source commit": "[[FINAL_RELEASE_COMMIT_REQUIRED]]",
      "Functional demo": "[[PUBLIC_SIGNED_OUT_DEMO_URL_REQUIRED]]",
      "Public video": "[[PUBLIC_YOUTUBE_OR_VIMEO_URL_REQUIRED]]",
      "Entrant / authorized representative": "[[OWNER_CONFIRMATION_REQUIRED]]"
    }),
    "RELEASE_SUBMISSION_COORDINATES_VALUES"
  );

  const gate = hardGateSection(source);
  const checklist = [...gate.matchAll(/^- \[([ xX])\] (.+)$/gm)].map(
    (match) => ({ state: match[1], firstLine: match[2] })
  );
  assert(checklist.length === 14, "RELEASE_SUBMISSION_GATE_COUNT");
  assert(
    checklist.every((item) => item.state === " "),
    "RELEASE_SUBMISSION_GATE_CHECKED"
  );
  assert(
    EXPECTED_GATE_MARKERS.every((marker) =>
      checklist.some((item) => item.firstLine.includes(marker))
    ),
    "RELEASE_SUBMISSION_GATE_MARKER"
  );

  const stopTokens = [...source.matchAll(/\[\[([A-Z0-9_]+)\]\]/g)].map(
    (match) => match[1]
  );
  assert(stopTokens.length === 13, "RELEASE_SUBMISSION_STOP_TOKEN_COUNT");
  assert(
    sameJson(sorted(new Set(stopTokens)), EXPECTED_STOP_TOKENS),
    "RELEASE_SUBMISSION_STOP_TOKEN_SET"
  );
  assert(
    stopTokens.filter(
      (token) => token === "PUBLIC_SIGNED_OUT_DEMO_URL_REQUIRED"
    ).length === 2 &&
      EXPECTED_STOP_TOKENS.filter(
        (token) => token !== "PUBLIC_SIGNED_OUT_DEMO_URL_REQUIRED"
      ).every((token) => stopTokens.filter((value) => value === token).length === 1),
    "RELEASE_SUBMISSION_STOP_TOKEN_OCCURRENCES"
  );
  assert(
    normalized.includes(
      "Do not substitute a localhost URL, private preview, repository page, AWS console URL, or credentialed environment for the functional demo."
    ) &&
      normalized.includes(
        "Do not add AWS accomplishments until a live exact-commit receipt exists."
      ) &&
      normalized.includes(
        "The second paragraph may be used only after the live AWS receipt proves the final implementation. Until then, the submission remains blocked."
      ),
    "RELEASE_SUBMISSION_STOP_BOUNDARY"
  );
  return {
    checklistItemCount: checklist.length,
    uncheckedChecklistItemCount: checklist.filter((item) => item.state === " ").length,
    stopTokenOccurrenceCount: stopTokens.length,
    uniqueStopTokenCount: new Set(stopTokens).size
  };
}

function assertSupportingSurfaces(sources) {
  const contest = normalizeWhitespace(sources.get("contest-matrix"));
  assert(
    contest.includes(`Deadline: ${EXPECTED_COORDINATES.officialDeadline}.`) &&
      contest.includes(
        `Internal submission target: ${EXPECTED_COORDINATES.internalDeadline}.`
      ) &&
      contest.includes(
        `Free judge access through judging | Budgeted low-volume environment through 2026-09-15 | Not provisioned`
      ) &&
      contest.includes(
        "Functional AWS-hosted demo | Ten exact signed-out API Gateway `GET` routes to a logs-only Demo Lambda serving the deterministic scenario | Local candidate passed; not deployed"
      ),
    "RELEASE_SUBMISSION_CONTEST_BOUNDARY"
  );

  const plan = normalizeWhitespace(sources.get("winning-plan"));
  assert(
    plan.includes("### Gate 4 — submission") &&
      plan.includes("publish only after brand, legal, secret, and claim review") &&
      plan.includes("require a complete visual-rights ledger") &&
      plan.includes("verify unrestricted judge access in a signed-out browser") &&
      plan.includes("submit at least 48 hours before deadline"),
    "RELEASE_SUBMISSION_PLAN_BOUNDARY"
  );

  const ledger = normalizeWhitespace(sources.get("release-submission-ledger"));
  assert(
    ledger.includes(
      "DRAFT SAFELY BLOCKED — FINAL RECEIPTS AND OWNER AUTHORITY PENDING"
    ) &&
      ledger.includes("does not query Devpost") &&
      ledger.includes("it is not a submission-readiness result") &&
      ledger.includes(
        "keeps publication and submission blocked"
      ),
    "RELEASE_SUBMISSION_LEDGER_BOUNDARY"
  );

  const rights = normalizeWhitespace(sources.get("rights-ledger"));
  assert(
    rights.includes("CURRENT_SURFACES_PASS") &&
      rights.includes("keeps `finalReleaseReady: false`") &&
      rights.includes("exact-release private review"),
    "RELEASE_SUBMISSION_RIGHTS_BOUNDARY"
  );

  const claims = normalizeWhitespace(sources.get("claims-ledger"));
  assert(
    claims.includes("synthetic and non-operational") &&
      claims.includes("live AWS") &&
      claims.includes("submission surfaces are hash-bound") &&
      claims.includes("does not prove truth, authorize publication"),
    "RELEASE_SUBMISSION_CLAIMS_BOUNDARY"
  );

  let releaseClaims;
  try {
    releaseClaims = JSON.parse(sources.get("release-claims-manifest"));
  } catch {
    throw new Error("RELEASE_SUBMISSION_CLAIMS_MANIFEST_JSON");
  }
  assert(
    releaseClaims?.schema === "tideproof.release-claims-manifest.v1" &&
      releaseClaims.status ===
        "CURRENT_PUBLIC_CLAIMS_REVIEWED_FINAL_LIVE_GATES_PENDING" &&
      releaseClaims.finalReleaseReady === false &&
      Array.isArray(releaseClaims.surfaces),
    "RELEASE_SUBMISSION_CLAIMS_MANIFEST_BOUNDARY"
  );
  const packet = releaseClaims.surfaces.find(
    (surface) => surface.id === "submission-packet"
  );
  assert(
    packet?.path === "docs/SUBMISSION_PACKET.md" &&
      packet.role === "SUBMISSION_DRAFT" &&
      packet.sha256 === sha256(sources.get("submission-packet")),
    "RELEASE_SUBMISSION_CLAIMS_MANIFEST_PACKET"
  );
  return true;
}

export function validateManifest(value) {
  exactKeys(
    value,
    [
      "claimBoundary",
      "coordinates",
      "finalReleaseReady",
      "finalReleaseRequirements",
      "gateMarkers",
      "reviewedOn",
      "schema",
      "status",
      "stopTokens",
      "surfaces"
    ],
    "RELEASE_SUBMISSION_MANIFEST_SHAPE"
  );
  assert(
    value.schema === MANIFEST_SCHEMA &&
      value.status === MANIFEST_STATUS &&
      /^\d{4}-\d{2}-\d{2}$/.test(value.reviewedOn) &&
      typeof value.claimBoundary === "string" &&
      value.claimBoundary.length > 0 &&
      value.finalReleaseReady === false &&
      sameJson(value.coordinates, EXPECTED_COORDINATES) &&
      sameJson(value.finalReleaseRequirements, EXPECTED_FINAL_RELEASE_REQUIREMENTS) &&
      sameJson(value.gateMarkers, EXPECTED_GATE_MARKERS) &&
      sameJson(value.stopTokens, EXPECTED_STOP_TOKENS),
    "RELEASE_SUBMISSION_MANIFEST_BOUNDARY"
  );
  assert(Array.isArray(value.surfaces), "RELEASE_SUBMISSION_MANIFEST_SURFACES");
  const expectedIds = Object.keys(EXPECTED_SURFACES);
  assert(
    sameJson(value.surfaces.map((surface) => surface.id), expectedIds),
    "RELEASE_SUBMISSION_MANIFEST_SURFACE_SET"
  );
  for (const surface of value.surfaces) {
    exactKeys(
      surface,
      ["id", "path", "role", "sha256"],
      "RELEASE_SUBMISSION_MANIFEST_SURFACE_SHAPE"
    );
    const expected = EXPECTED_SURFACES[surface.id];
    assert(
      expected &&
        surface.path === expected.path &&
        surface.role === expected.role &&
        HEX_64.test(surface.sha256),
      "RELEASE_SUBMISSION_MANIFEST_SURFACE"
    );
    safeRelativePath(surface.path, "RELEASE_SUBMISSION_MANIFEST_SURFACE_PATH");
  }
  return value;
}

export function verifyReleaseSubmission({ rootDir = DEFAULT_ROOT } = {}) {
  const manifestBytes = readRegularFile(
    rootDir,
    MANIFEST_PATH,
    "RELEASE_SUBMISSION_MANIFEST_FILE"
  );
  let manifest;
  try {
    manifest = JSON.parse(manifestBytes.toString("utf8"));
  } catch {
    throw new Error("RELEASE_SUBMISSION_MANIFEST_JSON");
  }
  assert(
    `${JSON.stringify(manifest, null, 2)}\n` === manifestBytes.toString("utf8"),
    "RELEASE_SUBMISSION_MANIFEST_CANONICAL"
  );
  validateManifest(manifest);

  const sources = new Map();
  for (const surface of manifest.surfaces) {
    const bytes = readRegularFile(
      rootDir,
      surface.path,
      "RELEASE_SUBMISSION_SURFACE_FILE"
    );
    assert(
      sha256(bytes) === surface.sha256,
      "RELEASE_SUBMISSION_SURFACE_DIGEST"
    );
    sources.set(surface.id, bytes.toString("utf8"));
  }
  const packet = parseSubmissionPacket(sources.get("submission-packet"));
  assertSupportingSurfaces(sources);

  return {
    schemaVersion: RECEIPT_SCHEMA,
    status: "DRAFT_SAFELY_BLOCKED",
    finalReleaseReady: false,
    reviewedOn: manifest.reviewedOn,
    manifestPath: MANIFEST_PATH,
    manifestSha256: sha256(manifestBytes),
    surfaceCount: manifest.surfaces.length,
    ...packet,
    officialCoordinateCount: Object.keys(EXPECTED_COORDINATES).length,
    finalReleaseRequirements: manifest.finalReleaseRequirements,
    checks: {
      canonicalManifest: true,
      exactSurfaceHashes: true,
      canonicalDraftStatus: true,
      submissionCoordinatesExact: true,
      officialScheduleInternallyConsistent: true,
      allHardPublishGatesUnchecked: true,
      exactStopTokenVocabulary: true,
      liveAndOwnerFieldsUnresolved: true,
      contestMatrixRemainsBlocked: true,
      releasePlanRemainsFailClosed: true,
      rightsAndClaimsRemainNonfinal: true,
      releaseClaimsPacketBindingExact: true
    },
    claimBoundary:
      "This receipt proves only that the current hash-bound source draft is internally consistent, explicitly incomplete, and fail-closed against premature Devpost publication or submission. It does not query Devpost or the competition pages, determine entrant eligibility, verify identity or authority, prove live AWS or public-demo behavior, approve rights or claims, or authorize deployment, publication, or submission."
  };
}

async function main() {
  assert(process.argv.length === 2, "RELEASE_SUBMISSION_ARGUMENT");
  process.stdout.write(`${JSON.stringify(verifyReleaseSubmission(), null, 2)}\n`);
}

const startedDirectly =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (startedDirectly) {
  main().catch((error) => {
    const message = String(error?.message ?? "");
    const code = /^RELEASE_SUBMISSION_[A-Z0-9_]{1,120}$/.test(message)
      ? message
      : "RELEASE_SUBMISSION_UNKNOWN";
    process.stderr.write(`TIDEPROOF_RELEASE_SUBMISSION_FAILED:${code}\n`);
    process.exitCode = 1;
  });
}

export const __test = Object.freeze({
  EXPECTED_COORDINATES,
  EXPECTED_FINAL_RELEASE_REQUIREMENTS,
  EXPECTED_GATE_MARKERS,
  EXPECTED_STOP_TOKENS,
  EXPECTED_SURFACES,
  MANIFEST_PATH,
  MANIFEST_SCHEMA,
  MANIFEST_STATUS,
  assertSupportingSurfaces,
  parseCoordinatesTable
});
