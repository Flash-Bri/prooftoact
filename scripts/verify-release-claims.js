import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { verifyProofManifest } from "./verify-proof-manifest.js";

const DEFAULT_ROOT = fileURLToPath(new URL("..", import.meta.url));
const MANIFEST_PATH = "RELEASE_CLAIMS_MANIFEST.json";
const MANIFEST_SCHEMA = "tideproof.release-claims-manifest.v1";
const MANIFEST_STATUS =
  "CURRENT_PUBLIC_CLAIMS_REVIEWED_FINAL_LIVE_GATES_PENDING";
const RECEIPT_SCHEMA = "tideproof.release-claims-verification.v1";
const HEX_64 = /^[0-9a-f]{64}$/;

const EXPECTED_FINAL_RELEASE_REQUIREMENTS = Object.freeze([
  "Accepted live AWS, public-demo, video, and submission receipts bound to the exact final release.",
  "Exact-release private human review of every public claim surface and submitted field."
]);

const EXPECTED_SURFACES = Object.freeze({
  "architecture-boundary": Object.freeze({
    path: "docs/ARCHITECTURE.md",
    role: "TECHNICAL_BOUNDARY"
  }),
  "aws-boundary": Object.freeze({
    path: "docs/AWS_GATE2.md",
    role: "TECHNICAL_BOUNDARY"
  }),
  "aws-demo-entry": Object.freeze({
    path: "infra/aws/lambda/demo.js",
    role: "DISTRIBUTION_ENTRY"
  }),
  "browser-app": Object.freeze({
    path: "web/app.js",
    role: "PUBLIC_BROWSER_CONTROLLER"
  }),
  "browser-document": Object.freeze({
    path: "web/index.html",
    role: "PUBLIC_BROWSER"
  }),
  "claims-ledger": Object.freeze({
    path: "CLAIMS.md",
    role: "CLAIMS_LEDGER"
  }),
  "contest-matrix": Object.freeze({
    path: "docs/CONTEST_MATRIX.md",
    role: "CONTEST_DRAFT"
  }),
  "demo-script": Object.freeze({
    path: "docs/DEMO_SCRIPT.md",
    role: "VIDEO_DRAFT"
  }),
  "full-drill-evidence": Object.freeze({
    path: "docs/FULL_DRILL_EVIDENCE.md",
    role: "EVIDENCE_BOUNDARY"
  }),
  "public-demo-runtime": Object.freeze({
    path: "src/cloud/public-demo.js",
    role: "AWS_PUBLIC_RUNTIME"
  }),
  "readme-surface": Object.freeze({
    path: "README.md",
    role: "PUBLIC_SOURCE"
  }),
  "release-claims-ledger": Object.freeze({
    path: "docs/RELEASE_CLAIMS.md",
    role: "CONTROL_LEDGER"
  }),
  "scenario-source": Object.freeze({
    path: "src/scenario.js",
    role: "SCENARIO_SOURCE"
  }),
  "submission-packet": Object.freeze({
    path: "docs/SUBMISSION_PACKET.md",
    role: "SUBMISSION_DRAFT"
  })
});

const REQUIRED_MARKERS = Object.freeze({
  "architecture-boundary": Object.freeze([
    "It proves the intended software and IAM shape locally, not live AWS hosting or a live CockroachDB-to-AWS handoff.",
    "its monitored alias is not invocation authority",
    "None of those cloud or database boundaries are proven live until the accepted race receipt includes the later durable-state observation and its private database evidence."
  ]),
  "aws-boundary": Object.freeze([
    "The strongest current claim is that this software, the bundled public-demo artifact path, the isolated CockroachDB authority candidate, and generated CloudFormation passed local review.",
    "Do not claim live public hosting, Bedrock inference, KMS-backed evidence, IAM denial, API authentication, an overlapping Lambda race, or CockroachDB-to-AWS handoff until their cloud receipts exist.",
    "These controls are unrun and do not exclude administrators or the independently protected receipt-key custodian.",
    "That mode includes the hash-bound public claim-surface control, emits `LOCAL_ONLY_PASS`, records `awsPreflight: NOT_RUN`, and is never authorization to upload or deploy."
  ]),
  "aws-demo-entry": Object.freeze([
    "import claimsMarkdown from \"../../../CLAIMS.md?raw\";",
    "\"/claims\": claimsMarkdown",
    "createPublicDemoHandler"
  ]),
  "browser-app": Object.freeze([
    "This local replay models the same one-winner invariant proven by the linked recorded CockroachDB receipt.",
    "The successor receives evidence and receipt lineage, but no inherited right to act; the linked cloud receipt proves the bounded recovery path."
  ]),
  "browser-document": Object.freeze([
    "Synthetic scenario · Not operational emergency software",
    "GATE TWO — local AWS candidate; live AWS evidence pending",
    "It is not a live AWS claim.",
    "Main stack not deployed",
    "ProofToAct makes no production, disaster-readiness, truth-detection, or exactly-once real-world-effect claim."
  ]),
  "claims-ledger": Object.freeze([
    "Every public claim must remain **unverified** until the listed artifact exists and its acceptance condition passes.",
    "Synthetic scenarios are always labeled synthetic and non-operational.",
    "the unrun deployment-attestation contract do not prove Lambda concurrency",
    "The repository does not claim invention of provenance-aware memory, temporal memory, fencing, replay protection, or exactly-once real-world effects."
  ]),
  "contest-matrix": Object.freeze([
    "Deadline: 2026-08-18 at 5:00 PM ET.",
    "Internal submission target: 2026-08-16 at 5:00 PM ET.",
    "Local candidates passed; live deployment and race pending",
    "Local candidate passed; not deployed"
  ]),
  "demo-script": Object.freeze([
    "GATE TWO — local AWS candidate; live AWS evidence pending",
    "GATE TWO HOST — AWS Lambda + API Gateway; advisory evidence pending",
    "That proves hosting only.",
    "The final video must not be recorded until the accepted advisory receipt supplies the exact final Gate Two wording and this scene map is relocked to the release commit."
  ]),
  "full-drill-evidence": Object.freeze([
    "Status: **provider-backed batch pending**.",
    "Its receipt must identify itself as local and synthetic. It cannot satisfy, substitute for, or unlock the provider-backed claim.",
    "The source path now consumes database-authorized DVI proposal identities and the exact selected-evidence digest, but no provider-backed receipt yet proves the live DVI-to-AWS handoff.",
    "No provider-backed receipt from this lane exists yet."
  ]),
  "public-demo-runtime": Object.freeze([
    "GATE TWO HOST — AWS Lambda + API Gateway; advisory evidence pending",
    "This signed-out AWS route serves only the deterministic replay.",
    "The separate proposal path remains IAM-authenticated and unproved live until its receipts pass review.",
    "ProofToAct makes no production, disaster-readiness, truth-detection, or exactly-once real-world-effect claim."
  ]),
  "readme-surface": Object.freeze([
    "**Public clean-room source. Not yet a contest submission or live AWS claim.**",
    "This repository contains a deterministic local vertical slice, an accepted CockroachDB Cloud Gate One proof, and a locally tested AWS Gate Two candidate:",
    "It does **not** yet contain or claim:",
    "a deployed public AWS judge URL;",
    "monitored aliases are not invocation authority",
    "ProofToAct is a synthetic demonstration, not operational emergency software."
  ]),
  "release-claims-ledger": Object.freeze([
    "**Status: CURRENT PUBLIC CLAIM SURFACES PASS — FINAL LIVE GATES AND PRIVATE REVIEW PENDING**",
    "`CURRENT_PUBLIC_CLAIMS_PASS` is not final publish approval",
    "The control does not prove that a claim is true"
  ]),
  "scenario-source": Object.freeze([
    "GATE TWO — local AWS candidate; live AWS evidence pending",
    "The candidate binds receipts to one exact KMS public key, separates proposal from authority, logs the API path, and fails closed. It is not a live AWS claim.",
    "Main stack not deployed"
  ]),
  "submission-packet": Object.freeze([
    "**Status: DRAFT — NOT READY TO SUBMIT**",
    "`PROOF_MANIFEST.json` is the machine-checked index for the current claims and exact evidence bytes. Its `INCOMPLETE_LIVE_GATES_PENDING` status is a stop state, not a publish authorization.",
    "Do not substitute a localhost URL, private preview, repository page, AWS console URL, or credentialed environment for the functional demo."
  ])
});

const EXPECTED_STOP_TOKENS = Object.freeze({
  ACCEPTED_LIVE_AUTHORITY_RACE_RECEIPT_REQUIRED: 1,
  ACCEPTED_LIVE_AWS_RECEIPT_REQUIRED: 1,
  ALL_REQUIRED_ROWS_RELEASE_CLEARED: 1,
  FINAL_AWS_ARCHITECTURE_COPY_REQUIRED_FROM_LIVE_RECEIPT: 1,
  FINAL_RELEASE_COMMIT_REQUIRED: 1,
  LIVE_AWS_EVIDENCE_REQUIRED: 1,
  LIVE_AWS_SERVICE_COPY_REQUIRED: 1,
  OWNER_CONFIRMATION_REQUIRED: 1,
  PUBLIC_DEMO_REQUIRED: 1,
  PUBLIC_SIGNED_OUT_DEMO_URL_REQUIRED: 2,
  PUBLIC_YOUTUBE_OR_VIMEO_URL_REQUIRED: 1,
  REPLACE_WITH_POST_RELEASE_ROADMAP_AFTER_FINAL_SCOPE_AUDIT: 1
});

const ALLOWED_ABSOLUTE_URLS = new Set([
  "http://127.0.0.1:4173",
  "https://cockroachdb-ai.devpost.com/",
  "https://cockroachdb-ai.devpost.com/resources",
  "https://cockroachdb-ai.devpost.com/rules",
  "https://github.com/Flash-Bri/prooftoact",
  "https://github.com/Flash-Bri/prooftoact.git"
]);

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
  const fromRoot = path.relative(resolvedRoot, resolved);
  assert(
    fromRoot !== "" &&
      fromRoot !== ".." &&
      !fromRoot.startsWith(`..${path.sep}`),
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

export function validateManifest(value) {
  exactKeys(
    value,
    [
      "claimBoundary",
      "finalReleaseReady",
      "finalReleaseRequirements",
      "reviewedOn",
      "schema",
      "status",
      "surfaces"
    ],
    "RELEASE_CLAIMS_MANIFEST_SHAPE"
  );
  assert(
    value.schema === MANIFEST_SCHEMA &&
      value.status === MANIFEST_STATUS &&
      /^\d{4}-\d{2}-\d{2}$/.test(value.reviewedOn) &&
      typeof value.claimBoundary === "string" &&
      value.claimBoundary.length > 0 &&
      value.finalReleaseReady === false &&
      sameJson(
        value.finalReleaseRequirements,
        EXPECTED_FINAL_RELEASE_REQUIREMENTS
      ),
    "RELEASE_CLAIMS_MANIFEST_BOUNDARY"
  );
  assert(Array.isArray(value.surfaces), "RELEASE_CLAIMS_MANIFEST_SURFACES");
  const expectedIds = Object.keys(EXPECTED_SURFACES);
  assert(
    sameJson(
      value.surfaces.map((surface) => surface.id),
      expectedIds
    ),
    "RELEASE_CLAIMS_MANIFEST_SURFACE_SET"
  );
  for (const surface of value.surfaces) {
    exactKeys(
      surface,
      ["id", "path", "role", "sha256"],
      "RELEASE_CLAIMS_MANIFEST_SURFACE_SHAPE"
    );
    const expected = EXPECTED_SURFACES[surface.id];
    assert(
      expected &&
        surface.path === expected.path &&
        surface.role === expected.role &&
        HEX_64.test(surface.sha256),
      "RELEASE_CLAIMS_MANIFEST_SURFACE"
    );
    safeRelativePath(surface.path, "RELEASE_CLAIMS_MANIFEST_SURFACE_PATH");
  }
  return value;
}

export function assertRequiredMarkers(sources) {
  for (const [id, markers] of Object.entries(REQUIRED_MARKERS)) {
    const source = sources.get(id);
    assert(typeof source === "string", "RELEASE_CLAIMS_MARKER_SOURCE");
    const normalized = normalizeWhitespace(source);
    for (const marker of markers) {
      assert(
        normalized.includes(normalizeWhitespace(marker)),
        `RELEASE_CLAIMS_MARKER_${id.replaceAll("-", "_").toUpperCase()}`
      );
    }
  }
  return true;
}

export function validateSubmissionDraft(source) {
  const stopTokens = {};
  for (const match of source.matchAll(/\[\[([A-Z0-9_]+)\]\]/g)) {
    stopTokens[match[1]] = (stopTokens[match[1]] ?? 0) + 1;
  }
  const expectedTokenNames = Object.keys(EXPECTED_STOP_TOKENS);
  assert(
    sameJson(sorted(Object.keys(stopTokens)), expectedTokenNames) &&
      expectedTokenNames.every(
        (name) => stopTokens[name] === EXPECTED_STOP_TOKENS[name]
      ),
    "RELEASE_CLAIMS_SUBMISSION_STOP_TOKENS"
  );
  const hardGate = source.match(
    /## Hard publish gate\n([\s\S]*?)(?=\n## )/
  )?.[1];
  assert(typeof hardGate === "string", "RELEASE_CLAIMS_SUBMISSION_GATE");
  assert(
    !/^- \[[xX]\]/m.test(hardGate) &&
      (hardGate.match(/^- \[ \]/gm) ?? []).length >= 14,
    "RELEASE_CLAIMS_SUBMISSION_PREMATURE_APPROVAL"
  );
  return {
    stopTokenCount: Object.values(stopTokens).reduce(
      (sum, count) => sum + count,
      0
    ),
    uncheckedGateCount: (hardGate.match(/^- \[ \]/gm) ?? []).length
  };
}

function absoluteUrls(source) {
  return [...source.matchAll(/https?:\/\/[^\s<>\"'`)]+/g)].map(
    (match) => match[0].replace(/[.,;:]+$/g, "")
  );
}

export function validateAllowedUrls(sources) {
  const urls = sorted(
    new Set(
      [...sources.values()].flatMap((source) => absoluteUrls(source))
    )
  );
  assert(
    urls.every((url) => ALLOWED_ABSOLUTE_URLS.has(url)),
    "RELEASE_CLAIMS_UNREVIEWED_URL"
  );
  const combined = [...sources.values()].join("\n");
  assert(
    !/https?:\/\/(?:www\.)?trustagentic\.ai\b/i.test(combined) &&
      !/https?:\/\/(?:www\.)?tideproof\.net\b/i.test(combined),
    "RELEASE_CLAIMS_PREMATURE_PUBLIC_LINK"
  );
  return urls;
}

export function verifyReleaseClaims({
  rootDir = DEFAULT_ROOT,
  verifyProof = verifyProofManifest
} = {}) {
  const manifestBytes = readRegularFile(
    rootDir,
    MANIFEST_PATH,
    "RELEASE_CLAIMS_MANIFEST_FILE"
  );
  let manifest;
  try {
    manifest = JSON.parse(manifestBytes.toString("utf8"));
  } catch {
    throw new Error("RELEASE_CLAIMS_MANIFEST_JSON");
  }
  assert(
    `${JSON.stringify(manifest, null, 2)}\n` === manifestBytes.toString("utf8"),
    "RELEASE_CLAIMS_MANIFEST_CANONICAL"
  );
  validateManifest(manifest);

  const sources = new Map();
  for (const surface of manifest.surfaces) {
    const bytes = readRegularFile(
      rootDir,
      surface.path,
      "RELEASE_CLAIMS_SURFACE_FILE"
    );
    assert(
      sha256(bytes) === surface.sha256,
      "RELEASE_CLAIMS_SURFACE_DIGEST"
    );
    sources.set(surface.id, bytes.toString("utf8"));
  }
  assertRequiredMarkers(sources);
  const submission = validateSubmissionDraft(
    sources.get("submission-packet")
  );
  const externalUrls = validateAllowedUrls(sources);

  const proof = verifyProof({ rootDir });
  assert(
    proof?.schema === "tideproof.proof-manifest-verification.v1" &&
      proof.status === "PASS" &&
      proof.manifestStatus === "INCOMPLETE_LIVE_GATES_PENDING" &&
      HEX_64.test(proof.manifestSha256) &&
      proof.claimCount === 12 &&
      sameJson(proof.claimStates, {
        VERIFIED: 5,
        PARTIAL: 7,
        PENDING: 0
      }),
    "RELEASE_CLAIMS_PROOF_MANIFEST"
  );

  return {
    schemaVersion: RECEIPT_SCHEMA,
    status: "CURRENT_PUBLIC_CLAIMS_PASS",
    finalReleaseReady: false,
    reviewedOn: manifest.reviewedOn,
    manifestPath: MANIFEST_PATH,
    manifestSha256: sha256(manifestBytes),
    proofManifestSha256: proof.manifestSha256,
    claimCount: proof.claimCount,
    claimStates: proof.claimStates,
    surfaceCount: manifest.surfaces.length,
    stopTokenCount: submission.stopTokenCount,
    uncheckedGateCount: submission.uncheckedGateCount,
    externalUrls,
    finalReleaseRequirements: manifest.finalReleaseRequirements,
    checks: {
      canonicalManifest: true,
      exactSurfaceHashes: true,
      claimsLedgerMatchesProofManifest: true,
      currentDraftStateExplicit: true,
      localAndHostedAwsBoundariesExplicit: true,
      syntheticScopeExplicit: true,
      submissionStopTokensPreserved: true,
      publicLinksConstrained: true
    },
    claimBoundary:
      "This receipt proves only that the current hash-bound claim surfaces match the reviewed pending-state copy, the claims ledger still matches the proof manifest, required synthetic and local/live boundaries remain present, submission stop tokens remain unresolved, and absolute URLs stay within the reviewed set. It does not prove that a claim is true, authorize deployment or publication, establish production suitability, or replace the exact-release private human review."
  };
}

async function main() {
  assert(process.argv.length === 2, "RELEASE_CLAIMS_ARGUMENT");
  process.stdout.write(`${JSON.stringify(verifyReleaseClaims(), null, 2)}\n`);
}

const startedDirectly =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (startedDirectly) {
  main().catch((error) => {
    const message = String(error?.message ?? "");
    const code = /^RELEASE_CLAIMS_[A-Z0-9_]{1,120}$/.test(message)
      ? message
      : "RELEASE_CLAIMS_UNKNOWN";
    process.stderr.write(`TIDEPROOF_RELEASE_CLAIMS_FAILED:${code}\n`);
    process.exitCode = 1;
  });
}

export const __test = Object.freeze({
  ALLOWED_ABSOLUTE_URLS,
  EXPECTED_FINAL_RELEASE_REQUIREMENTS,
  EXPECTED_STOP_TOKENS,
  EXPECTED_SURFACES,
  MANIFEST_PATH,
  MANIFEST_SCHEMA,
  MANIFEST_STATUS,
  REQUIRED_MARKERS
});
