import { createHash } from "node:crypto";
import { canonicalJson } from "./canonical-json.js";

export const DVI_SELECTION_RECEIPT_SCHEMA =
  "tideproof.authority.dvi-selection-receipt.v2";

const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const GIT_OBJECT_ID = /^[0-9a-f]{40}$/u;

function requirePattern(value, pattern, name) {
  if (typeof value !== "string" || !pattern.test(value)) {
    throw new TypeError(`${name} is not canonical`);
  }
  return value;
}

function requireTimestamp(value, name) {
  if (
    typeof value !== "string" ||
    !Number.isFinite(Date.parse(value)) ||
    new Date(value).toISOString() !== value
  ) {
    throw new TypeError(`${name} must be canonical UTC milliseconds`);
  }
  return value;
}

export function dviRankedSequenceSha256For(rows) {
  if (!Array.isArray(rows) || rows.length < 1 || rows.length > 100) {
    throw new TypeError("DVI_RANKED_SEQUENCE_SIZE");
  }
  const lines = rows.map((row, index) => {
    if (
      !row ||
      typeof row !== "object" ||
      Array.isArray(row) ||
      Object.keys(row).sort().join(",") !==
        "evidenceDigest,evidenceId" ||
      index > 99
    ) {
      throw new TypeError("DVI_RANKED_SEQUENCE_SHAPE");
    }
    return `${requirePattern(row.evidenceId, UUID, "evidenceId")}:${requirePattern(
      row.evidenceDigest,
      SHA256,
      "evidenceDigest"
    )}`;
  });
  return createHash("sha256")
    .update(`${lines.join("\n")}\n`)
    .digest("hex");
}

export function dviSelectionReceiptFor(input) {
  const admittedAt = requireTimestamp(input.admittedAt, "admittedAt");
  const expiresAt = requireTimestamp(input.expiresAt, "expiresAt");
  if (Date.parse(expiresAt) <= Date.parse(admittedAt)) {
    throw new TypeError("DVI_SELECTION_RECEIPT_TIME");
  }
  if (input.selectedRank !== 1) {
    throw new TypeError("DVI_SELECTION_RECEIPT_RANK");
  }
  if (
    !Number.isSafeInteger(input.resultLimit) ||
    input.resultLimit < 1 ||
    input.resultLimit > 100
  ) {
    throw new TypeError("DVI_SELECTION_RECEIPT_LIMIT");
  }
  if (
    typeof input.agency !== "string" ||
    input.agency.length < 1 ||
    input.agency.length > 128 ||
    input.agency !== input.agency.trim()
  ) {
    throw new TypeError("agency is not canonical");
  }
  if (input.policyVersion !== "g1-admissibility-v2") {
    throw new TypeError("DVI_SELECTION_RECEIPT_POLICY");
  }
  return Object.freeze({
    schemaVersion: DVI_SELECTION_RECEIPT_SCHEMA,
    sourceCommit: requirePattern(
      input.sourceCommit,
      GIT_OBJECT_ID,
      "sourceCommit"
    ),
    treeDigest: requirePattern(
      input.treeDigest,
      GIT_OBJECT_ID,
      "treeDigest"
    ),
    specSha256: requirePattern(input.specSha256, SHA256, "specSha256"),
    runId: requirePattern(input.runId, UUID, "runId"),
    tenantId: requirePattern(input.tenantId, UUID, "tenantId"),
    incidentId: requirePattern(input.incidentId, UUID, "incidentId"),
    retrievalId: requirePattern(input.retrievalId, UUID, "retrievalId"),
    agency: input.agency,
    policyVersion: input.policyVersion,
    snapshot: Object.freeze({ admittedAt, expiresAt }),
    rankedSequenceSha256: requirePattern(
      input.rankedSequenceSha256,
      SHA256,
      "rankedSequenceSha256"
    ),
    queryEmbeddingSha256: requirePattern(
      input.queryEmbeddingSha256,
      SHA256,
      "queryEmbeddingSha256"
    ),
    resultLimit: input.resultLimit,
    selected: Object.freeze({
      rank: 1,
      evidenceId: requirePattern(
        input.selectedEvidenceId,
        UUID,
        "selectedEvidenceId"
      ),
      evidenceDigest: requirePattern(
        input.selectedEvidenceDigest,
        SHA256,
        "selectedEvidenceDigest"
      )
    })
  });
}

export function dviSelectionBindingSha256For(input) {
  return createHash("sha256")
    .update(canonicalJson(dviSelectionReceiptFor(input)))
    .digest("hex");
}
