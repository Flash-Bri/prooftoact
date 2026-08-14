import { createHash } from "node:crypto";
import { canonicalJson } from "./canonical-json.js";

export const LOGICAL_ACTION_SCHEMA =
  "tideproof.authority.logical-action.v1";
export const DVI_PROPOSAL_IDENTITY_SCHEMA =
  "tideproof.authority.dvi-proposal-identity.v1";
export const LOGICAL_AUTHORITY_KEY_SCHEMA =
  "tideproof.authority.logical-authority-key.v1";
export const AUTHORIZATION_BINDING_SCHEMA =
  "tideproof.authority.authorization-binding.v1";

const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA256 = /^[0-9a-f]{64}$/;
const CONTROL_CHARACTER = /[\u0000-\u001f\u007f]/u;
const ACTION_KIND = "dispatch_rescue_unit";
const DISPATCH_PAYLOAD_REQUIRED_FIELDS = Object.freeze([
  "action",
  "scenario"
]);
const DISPATCH_PAYLOAD_OPTIONAL_FIELDS = Object.freeze([
  "destination",
  "logicalDispatch"
]);
const DISPATCH_PAYLOAD_ALLOWED_FIELDS = Object.freeze([
  ...DISPATCH_PAYLOAD_REQUIRED_FIELDS,
  ...DISPATCH_PAYLOAD_OPTIONAL_FIELDS
]);
const DISPATCH_PAYLOAD_SAFE_TEXT = /^[A-Za-z0-9._:-]+$/u;
const DISPATCH_PAYLOAD_TEXT_MAXIMUM = 128;
const MAX_AUTHORIZATION_EPOCH = 9_007_199_254_740_991;

const LOGICAL_ACTION_FIELDS = Object.freeze([
  "tenantId",
  "incidentId",
  "resourceId",
  "agency",
  "actionKind",
  "payloadDigest"
]);
const PROPOSAL_FIELDS = Object.freeze([
  "tenantId",
  "runId",
  "incidentId",
  "retrievalId",
  "logicalActionDigest",
  "authorityEvidenceBindingSha256",
  "selectedEvidenceId",
  "selectedEvidenceDigest",
  "policyVersion",
  "selectedRank",
  "admittedAt",
  "expiresAt"
]);

export const AUTHORITY_IDENTITY_CONTRACT = Object.freeze({
  schemaVersion: "tideproof.authority.identity-contract.v1",
  logicalActionFields: LOGICAL_ACTION_FIELDS,
  proposalFields: PROPOSAL_FIELDS,
  logicalAuthorityKeyFields: Object.freeze([
    "logicalActionDigest",
    "authorizationEpoch"
  ]),
  authorizationBindingFields: Object.freeze([
    "logicalActionDigest",
    "proposalDigest",
    "authorizationEpoch"
  ]),
  proposalContextOnlyFields: Object.freeze([
    "runId",
    "retrievalId",
    "authorityEvidenceBindingSha256",
    "selectedEvidenceId",
    "selectedEvidenceDigest",
    "policyVersion",
    "selectedRank",
    "admittedAt",
    "expiresAt"
  ]),
  attemptOnlyFields: Object.freeze([
    "operationId",
    "agentId",
    "intentNonce",
    "effectKey",
    "leaseMs",
    "raceId",
    "callerSubjectHash"
  ]),
  databaseOwnedFields: Object.freeze([
    "authorizationEpoch",
    "logicalAuthorityKeySha256"
  ])
});

function assert(condition, code) {
  if (!condition) {
    throw new Error(code);
  }
}

function exactKeys(value, expected, code) {
  assert(
    value &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      JSON.stringify(Object.keys(value).sort()) ===
        JSON.stringify([...expected].sort()),
    code
  );
}

function requireText(value, name, maximum) {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > maximum ||
    value !== value.trim() ||
    CONTROL_CHARACTER.test(value)
  ) {
    throw new TypeError(`${name} must be bounded canonical text`);
  }
  return value;
}

function requireUuid(value, name) {
  const text = requireText(value, name, 36).toLowerCase();
  if (!UUID.test(text)) {
    throw new TypeError(`${name} must be a UUID`);
  }
  return text;
}

function requireSha256(value, name) {
  const text = requireText(value, name, 64);
  if (!SHA256.test(text)) {
    throw new TypeError(`${name} must be lowercase SHA-256 hex`);
  }
  return text;
}

function requireTimestamp(value, name) {
  const text = requireText(value, name, 24);
  const parsed = Date.parse(text);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== text) {
    throw new TypeError(`${name} must be canonical UTC milliseconds`);
  }
  return { text, milliseconds: parsed };
}

function requireAuthorizationEpoch(value) {
  if (
    !Number.isSafeInteger(value) ||
    value < 1 ||
    value > MAX_AUTHORIZATION_EPOCH
  ) {
    throw new RangeError("authorizationEpoch outside policy");
  }
  return value;
}

function requireDispatchPayloadText(value, name) {
  const text = requireText(value, name, DISPATCH_PAYLOAD_TEXT_MAXIMUM);
  assert(
    DISPATCH_PAYLOAD_SAFE_TEXT.test(text),
    "AUTHORITY_DISPATCH_PAYLOAD_TEXT"
  );
  return text;
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function identityDigest(value) {
  return sha256(canonicalJson(value));
}

export function dispatchPayloadFor(input) {
  assert(
    input && typeof input === "object" && !Array.isArray(input),
    "AUTHORITY_DISPATCH_PAYLOAD_SHAPE"
  );
  const keys = Object.keys(input);
  assert(
    DISPATCH_PAYLOAD_REQUIRED_FIELDS.every((field) =>
      Object.hasOwn(input, field)
    ) &&
      keys.every((field) => DISPATCH_PAYLOAD_ALLOWED_FIELDS.includes(field)) &&
      keys.length >= DISPATCH_PAYLOAD_REQUIRED_FIELDS.length &&
      keys.length <= DISPATCH_PAYLOAD_ALLOWED_FIELDS.length,
    "AUTHORITY_DISPATCH_PAYLOAD_SHAPE"
  );
  const action = requireDispatchPayloadText(input.action, "payload.action");
  assert(action === ACTION_KIND, "AUTHORITY_ACTION_KIND_UNSUPPORTED");
  const payload = { action };
  if (Object.hasOwn(input, "destination")) {
    payload.destination = requireDispatchPayloadText(
      input.destination,
      "payload.destination"
    );
  }
  if (Object.hasOwn(input, "logicalDispatch")) {
    payload.logicalDispatch = requireDispatchPayloadText(
      input.logicalDispatch,
      "payload.logicalDispatch"
    );
  }
  payload.scenario = requireDispatchPayloadText(
    input.scenario,
    "payload.scenario"
  );
  return Object.freeze(payload);
}

export function logicalActionIdentityFor(input) {
  exactKeys(input, LOGICAL_ACTION_FIELDS, "AUTHORITY_LOGICAL_ACTION_SHAPE");
  const actionKind = requireText(input.actionKind, "actionKind", 64);
  assert(actionKind === ACTION_KIND, "AUTHORITY_ACTION_KIND_UNSUPPORTED");
  return Object.freeze({
    schemaVersion: LOGICAL_ACTION_SCHEMA,
    tenantId: requireUuid(input.tenantId, "tenantId"),
    incidentId: requireUuid(input.incidentId, "incidentId"),
    resourceId: requireText(input.resourceId, "resourceId", 256),
    agency: requireText(input.agency, "agency", 128),
    actionKind,
    payloadDigest: requireSha256(input.payloadDigest, "payloadDigest")
  });
}

export function logicalActionDigestFor(input) {
  return identityDigest(logicalActionIdentityFor(input));
}

export function dviProposalIdentityFor(input) {
  exactKeys(input, PROPOSAL_FIELDS, "AUTHORITY_DVI_PROPOSAL_SHAPE");
  const admittedAt = requireTimestamp(input.admittedAt, "admittedAt");
  const expiresAt = requireTimestamp(input.expiresAt, "expiresAt");
  assert(
    expiresAt.milliseconds > admittedAt.milliseconds,
    "AUTHORITY_DVI_PROPOSAL_TIME"
  );
  assert(input.selectedRank === 1, "AUTHORITY_DVI_SELECTED_RANK");
  return Object.freeze({
    schemaVersion: DVI_PROPOSAL_IDENTITY_SCHEMA,
    tenantId: requireUuid(input.tenantId, "tenantId"),
    runId: requireUuid(input.runId, "runId"),
    incidentId: requireUuid(input.incidentId, "incidentId"),
    retrievalId: requireUuid(input.retrievalId, "retrievalId"),
    logicalActionDigest: requireSha256(
      input.logicalActionDigest,
      "logicalActionDigest"
    ),
    authorityEvidenceBindingSha256: requireSha256(
      input.authorityEvidenceBindingSha256,
      "authorityEvidenceBindingSha256"
    ),
    selectedEvidenceId: requireUuid(
      input.selectedEvidenceId,
      "selectedEvidenceId"
    ),
    selectedEvidenceDigest: requireSha256(
      input.selectedEvidenceDigest,
      "selectedEvidenceDigest"
    ),
    policyVersion: requireText(input.policyVersion, "policyVersion", 128),
    selectedRank: 1,
    admittedAt: admittedAt.text,
    expiresAt: expiresAt.text
  });
}

export function dviProposalIdentityDigestFor(input) {
  return identityDigest(dviProposalIdentityFor(input));
}

export function logicalAuthorityKeyFor(input) {
  exactKeys(
    input,
    AUTHORITY_IDENTITY_CONTRACT.logicalAuthorityKeyFields,
    "AUTHORITY_LOGICAL_KEY_SHAPE"
  );
  const identity = Object.freeze({
    schemaVersion: LOGICAL_AUTHORITY_KEY_SCHEMA,
    logicalActionDigest: requireSha256(
      input.logicalActionDigest,
      "logicalActionDigest"
    ),
    authorizationEpoch: requireAuthorizationEpoch(input.authorizationEpoch)
  });
  return Object.freeze({
    ...identity,
    logicalAuthorityKeySha256: identityDigest(identity)
  });
}

export function authorizationBindingFor(input) {
  exactKeys(
    input,
    AUTHORITY_IDENTITY_CONTRACT.authorizationBindingFields,
    "AUTHORITY_BINDING_SHAPE"
  );
  const logicalActionDigest = requireSha256(
    input.logicalActionDigest,
    "logicalActionDigest"
  );
  const proposalDigest = requireSha256(input.proposalDigest, "proposalDigest");
  const authorizationEpoch = requireAuthorizationEpoch(
    input.authorizationEpoch
  );
  const logicalAuthorityKey = logicalAuthorityKeyFor({
    logicalActionDigest,
    authorizationEpoch
  });
  const identity = Object.freeze({
    schemaVersion: AUTHORIZATION_BINDING_SCHEMA,
    logicalActionDigest,
    proposalDigest,
    authorizationEpoch,
    logicalAuthorityKeySha256:
      logicalAuthorityKey.logicalAuthorityKeySha256
  });
  return Object.freeze({
    ...identity,
    authorizationBindingSha256: identityDigest(identity)
  });
}

export const __test = Object.freeze({ canonicalJson, identityDigest });
