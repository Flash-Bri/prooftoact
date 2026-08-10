import { createHash, createPublicKey, verify } from "node:crypto";

const SAFE_BUNDLE_BYTES = 24_576;

export const RECOVERY_MAX_TTL_MS = 24 * 60 * 60 * 1_000;
export const RECOVERY_SIGNATURE_ALGORITHM = "ecdsa-p256-sha256";
export const RECOVERY_PUBLISHER_VERSION = "tideproof-recovery-publisher-v2";

const SIGNED_RECOVERY_BUNDLE_KEYS = Object.freeze([
  "authorityTransferred",
  "bundleDigest",
  "checkpointSummary",
  "conflictSummary",
  "evidenceSummary",
  "expiresAt",
  "policyVersion",
  "publisherKeyId",
  "publisherVersion",
  "receiptSummary",
  "recoverySessionId",
  "requiresFreshAuthorization",
  "schemaVersion",
  "signatureAlgorithm",
  "signatureDigest",
  "snapshotVersion",
  "sourceClusterId",
  "sourceCommitTs",
  "sourceDigest",
  "sourceSignatureBase64",
  "subjectBindingHash",
  "tenantId"
]);

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (value && typeof value === "object") {
    const entries = Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, nested]) => `${JSON.stringify(key)}:${canonicalJson(nested)}`);
    return `{${entries.join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function requireText(value, name) {
  if (typeof value !== "string" || value.trim() === "") {
    throw new TypeError(`${name} must be a non-empty string`);
  }
  return value.trim();
}

function requireUuid(value, name) {
  const text = requireText(value, name);
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      text
    )
  ) {
    throw new TypeError(`${name} must be a UUID`);
  }
  return text.toLowerCase();
}

function requireSha256(value, name) {
  const text = requireText(value, name).toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(text)) {
    throw new TypeError(`${name} must be a SHA-256 hex digest`);
  }
  return text;
}

function requirePositiveInteger(value, name) {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new TypeError(`${name} must be a positive safe integer`);
  }
  return value;
}

function requireNonNegativeInteger(
  value,
  name,
  maximum = Number.MAX_SAFE_INTEGER
) {
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) {
    throw new TypeError(
      `${name} must be a non-negative safe integer no greater than ${maximum}`
    );
  }
  return value;
}

function requireBoolean(value, name) {
  if (typeof value !== "boolean") {
    throw new TypeError(`${name} must be a boolean`);
  }
  return value;
}

function requireBoundedText(value, name, maximum = 128) {
  const text = requireText(value, name);
  if (Buffer.byteLength(text, "utf8") > maximum) {
    throw new RangeError(`${name} exceeds ${maximum} bytes`);
  }
  return text;
}

function requireNullableBoundedText(value, name, maximum = 128) {
  if (value === null) {
    return null;
  }
  return requireBoundedText(value, name, maximum);
}

function requireEnum(value, name, allowed) {
  const text = requireBoundedText(value, name);
  if (!allowed.includes(text)) {
    throw new TypeError(`${name} must be one of ${allowed.join(", ")}`);
  }
  return text;
}

function requireTimestamp(value, name) {
  const text = value instanceof Date
    ? value.toISOString()
    : requireText(value, name);
  if (!Number.isFinite(Date.parse(text))) {
    throw new TypeError(`${name} must be an ISO-compatible timestamp`);
  }
  return new Date(text).toISOString();
}

function requireExactKeys(value, name, expectedKeys) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${name} must be a JSON object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (canonicalJson(actual) !== canonicalJson(expected)) {
    throw new TypeError(`${name} has an unexpected shape`);
  }
}

function requireExactSignedBundle(value) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))
  ) {
    throw new TypeError("signedRecoveryBundle must be a plain JSON object");
  }
  requireExactKeys(
    value,
    "signedRecoveryBundle",
    SIGNED_RECOVERY_BUNDLE_KEYS
  );
  if (value.schemaVersion !== 2) {
    throw new TypeError("schemaVersion must be 2");
  }
  if (value.authorityTransferred !== false) {
    throw new TypeError("authorityTransferred must be false");
  }
  if (value.requiresFreshAuthorization !== true) {
    throw new TypeError("requiresFreshAuthorization must be true");
  }
  return value;
}

function requireCheckpointSummary(value) {
  requireExactKeys(value, "checkpointSummary", [
    "checkpointVersion",
    "failedAgent",
    "phase",
    "scenario"
  ]);
  return {
    checkpointVersion: requirePositiveInteger(
      value.checkpointVersion,
      "checkpointSummary.checkpointVersion"
    ),
    failedAgent: requireBoundedText(
      value.failedAgent,
      "checkpointSummary.failedAgent"
    ),
    phase: requireEnum(value.phase, "checkpointSummary.phase", [
      "successor-context-recovery"
    ]),
    scenario: requireEnum(value.scenario, "checkpointSummary.scenario", [
      "synthetic-highwater"
    ])
  };
}

function requireEvidenceSummary(value) {
  requireExactKeys(value, "evidenceSummary", [
    "admittedCount",
    "classification",
    "evidenceDigest"
  ]);
  return {
    admittedCount: requireNonNegativeInteger(
      value.admittedCount,
      "evidenceSummary.admittedCount",
      100
    ),
    classification: requireEnum(
      value.classification,
      "evidenceSummary.classification",
      ["synthetic"]
    ),
    evidenceDigest: requireSha256(
      value.evidenceDigest,
      "evidenceSummary.evidenceDigest"
    )
  };
}

function requireConflictSummary(value) {
  requireExactKeys(value, "conflictSummary", [
    "status",
    "unresolvedCount"
  ]);
  return {
    status: requireEnum(value.status, "conflictSummary.status", [
      "none",
      "quarantined",
      "resolved"
    ]),
    unresolvedCount: requireNonNegativeInteger(
      value.unresolvedCount,
      "conflictSummary.unresolvedCount",
      100
    )
  };
}

function requireReceiptSummary(value) {
  requireExactKeys(value, "receiptSummary", [
    "durableIntentPresent",
    "outcome",
    "reason",
    "resourceLabel"
  ]);
  return {
    durableIntentPresent: requireBoolean(
      value.durableIntentPresent,
      "receiptSummary.durableIntentPresent"
    ),
    outcome: requireEnum(value.outcome, "receiptSummary.outcome", [
      "resource_reserved",
      "resource_held_denied",
      "authorization_denied"
    ]),
    reason: requireNullableBoundedText(value.reason, "receiptSummary.reason"),
    resourceLabel: requireBoundedText(
      value.resourceLabel,
      "receiptSummary.resourceLabel"
    )
  };
}

function requireBase64(value, name) {
  const text = requireText(value, name);
  const bytes = Buffer.from(text, "base64");
  if (bytes.length === 0 || bytes.toString("base64") !== text) {
    throw new TypeError(`${name} must be canonical base64`);
  }
  return { text, bytes };
}

function normalizeUnsignedBundle(input) {
  const normalized = {
    tenantId: requireUuid(input.tenantId, "tenantId"),
    recoverySessionId: requireUuid(
      input.recoverySessionId,
      "recoverySessionId"
    ),
    subjectBindingHash: requireSha256(
      input.subjectBindingHash,
      "subjectBindingHash"
    ),
    schemaVersion: requirePositiveInteger(input.schemaVersion, "schemaVersion"),
    snapshotVersion: requirePositiveInteger(
      input.snapshotVersion,
      "snapshotVersion"
    ),
    sourceClusterId: requireUuid(input.sourceClusterId, "sourceClusterId"),
    sourceCommitTs: requireTimestamp(input.sourceCommitTs, "sourceCommitTs"),
    sourceDigest: requireSha256(input.sourceDigest, "sourceDigest"),
    policyVersion: requireBoundedText(input.policyVersion, "policyVersion"),
    publisherKeyId: requireBoundedText(
      input.publisherKeyId,
      "publisherKeyId"
    ),
    publisherVersion: requireEnum(
      input.publisherVersion,
      "publisherVersion",
      [RECOVERY_PUBLISHER_VERSION]
    ),
    signatureAlgorithm: requireEnum(
      input.signatureAlgorithm,
      "signatureAlgorithm",
      [RECOVERY_SIGNATURE_ALGORITHM]
    ),
    checkpointSummary: requireCheckpointSummary(input.checkpointSummary),
    evidenceSummary: requireEvidenceSummary(input.evidenceSummary),
    conflictSummary: requireConflictSummary(input.conflictSummary),
    receiptSummary: requireReceiptSummary(input.receiptSummary),
    authorityTransferred: requireBoolean(
      input.authorityTransferred,
      "authorityTransferred"
    ),
    requiresFreshAuthorization: requireBoolean(
      input.requiresFreshAuthorization,
      "requiresFreshAuthorization"
    ),
    expiresAt: requireTimestamp(input.expiresAt, "expiresAt")
  };
  if (normalized.schemaVersion !== 2) {
    throw new TypeError("schemaVersion must be 2");
  }
  if (normalized.authorityTransferred !== false) {
    throw new TypeError("authorityTransferred must be false");
  }
  if (normalized.requiresFreshAuthorization !== true) {
    throw new TypeError("requiresFreshAuthorization must be true");
  }
  const sourceMs = Date.parse(normalized.sourceCommitTs);
  const expiresMs = Date.parse(normalized.expiresAt);
  if (expiresMs <= sourceMs) {
    throw new RangeError("expiresAt must be later than sourceCommitTs");
  }
  if (expiresMs - sourceMs > RECOVERY_MAX_TTL_MS) {
    throw new RangeError(
      `recovery bundle TTL exceeds ${RECOVERY_MAX_TTL_MS} milliseconds`
    );
  }
  const encoded = canonicalJson(normalized);
  if (Buffer.byteLength(encoded, "utf8") > SAFE_BUNDLE_BYTES) {
    throw new RangeError(`recovery bundle exceeds ${SAFE_BUNDLE_BYTES} bytes`);
  }
  return normalized;
}

function normalizeBundle(input) {
  const unsigned = normalizeUnsignedBundle(input);
  const bundleDigest = sha256(canonicalJson(unsigned));
  if (
    input.bundleDigest !== undefined &&
    requireSha256(input.bundleDigest, "bundleDigest") !== bundleDigest
  ) {
    throw new Error("RECOVERY_BUNDLE_DIGEST_MISMATCH");
  }
  const signature = requireBase64(
    input.sourceSignatureBase64,
    "sourceSignatureBase64"
  );
  const signatureDigest = sha256(signature.bytes);
  if (
    input.signatureDigest !== undefined &&
    requireSha256(input.signatureDigest, "signatureDigest") !== signatureDigest
  ) {
    throw new Error("RECOVERY_SIGNATURE_DIGEST_MISMATCH");
  }
  return {
    ...unsigned,
    bundleDigest,
    sourceSignatureBase64: signature.text,
    signatureDigest
  };
}

function publisherPublicKeyFor(trustedPublisherKeys, publisherKeyId) {
  const value = trustedPublisherKeys instanceof Map
    ? trustedPublisherKeys.get(publisherKeyId)
    : trustedPublisherKeys?.[publisherKeyId];
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error("RECOVERY_PUBLISHER_KEY_UNKNOWN");
  }
  const publicKey = createPublicKey({
    key: Buffer.from(value, "base64"),
    format: "der",
    type: "spki"
  });
  if (
    publicKey.asymmetricKeyType !== "ec" ||
    !["prime256v1", "P-256"].includes(publicKey.asymmetricKeyDetails?.namedCurve)
  ) {
    throw new Error("RECOVERY_PUBLISHER_KEY_INVALID");
  }
  return publicKey;
}

export function bundleDigestFor(input) {
  return sha256(canonicalJson(normalizeUnsignedBundle(input)));
}

export function normalizedRecoveryBundleFor(input) {
  return normalizeBundle(input);
}

export function recoverySignaturePayloadFor(input) {
  return `tideproof-recovery-bundle-v2\n${bundleDigestFor(input)}`;
}

export function verifyRecoveryBundleSourceSignature(
  input,
  trustedPublisherKeys
) {
  const normalized = normalizeBundle(requireExactSignedBundle(input));
  const publicKey = publisherPublicKeyFor(
    trustedPublisherKeys,
    normalized.publisherKeyId
  );
  const signatureValid = verify(
    "sha256",
    Buffer.from(recoverySignaturePayloadFor(normalized), "utf8"),
    publicKey,
    Buffer.from(normalized.sourceSignatureBase64, "base64")
  );
  if (!signatureValid) {
    throw new Error("RECOVERY_SIGNATURE_INVALID");
  }
  return normalized;
}
