import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify
} from "node:crypto";
import path from "node:path";

import { canonicalJson } from "./canonical-json.js";
import {
  validateDeploymentExpectation,
  validateSignedDeploymentAttestationPair
} from
  "./aws-deployment-attestation.js";
import { trustedPublisherKeysDigest } from
  "./recovery-publisher-trust.js";

export const INTEGRATED_LIVE_DRILL_RUN_AUTHORIZATION_SCHEMA =
  "tideproof.highwater-drill-live-run-authorization.v2";
export const INTEGRATED_LIVE_DRILL_HUMAN_AUTHORIZATION_TRUST_ROOT_SCHEMA =
  "tideproof.highwater-drill-human-authorization-trust-root.v1";
export const INTEGRATED_LIVE_DRILL_SPEND_AUTHORIZATION_SCHEMA =
  "tideproof.highwater-drill-spend-authorization.v1";
export const INTEGRATED_LIVE_DRILL_CLAIM_AUTHORITY_SCHEMA =
  "tideproof.highwater-drill-claim-authority.v1";
export const INTEGRATED_LIVE_DRILL_CROSS_HOST_CLAIM_BLOCKER =
  "CROSS_HOST_STRONGLY_CONSISTENT_AUTHORIZATION_CLAIM_AUTHORITY_NOT_PROVEN";
export const INTEGRATED_LIVE_DRILL_FINALIZATION_STATEMENT_SCHEMA =
  "tideproof.highwater-drill-live-finalization-statement.v1";
export const INTEGRATED_LIVE_DRILL_ACCEPTANCE_CORE_SCHEMA =
  "tideproof.highwater-drill-live-acceptance-core.v1";
export const INTEGRATED_LIVE_DRILL_AUTHORIZED_EXPECTATION_SCHEMA =
  "tideproof.highwater-drill-human-authorized-deployment-expectation.v1";
export const INTEGRATED_LIVE_DRILL_COMMITTED_RECOVERY_TRUST_ROOT_SCHEMA =
  "tideproof.highwater-drill-child-committed-recovery-trust-root.v1";
export const INTEGRATED_LIVE_DRILL_SIGNED_EVIDENCE_SCHEMA =
  "tideproof.highwater-drill-live-signed-evidence.v2";
export const INTEGRATED_LIVE_DRILL_TYPED_EVIDENCE = Object.freeze({
  acceptedReceipt: Object.freeze({
    schemaVersion: "tideproof.highwater-drill-candidate-receipt-binding.v1",
    status: "CANDIDATE_RECEIPT_BOUND_NOT_ACCEPTED",
    subjectSchemaVersion:
      "tideproof.highwater-drill-candidate-receipt-subject.v1"
  }),
  billingSettlement: Object.freeze({
    schemaVersion: "tideproof.highwater-drill-billing-settlement.v1",
    status: "BILLING_PENDING",
    subjectSchemaVersion:
      "tideproof.highwater-drill-billing-pending-subject.v1"
  }),
  costUpperBound: Object.freeze({
    schemaVersion: "tideproof.highwater-drill-cost-upper-bound.v1",
    status: "AUTHORIZED_COST_CEILING_BOUND_BILLING_PENDING",
    subjectSchemaVersion:
      "tideproof.highwater-drill-authorized-cost-ceiling-subject.v1"
  }),
  privateEvidence: Object.freeze({
    schemaVersion: "tideproof.highwater-drill-private-evidence-attestation.v1",
    status: "PRIVATE_EVIDENCE_REFERENCE_BOUND",
    subjectSchemaVersion:
      "tideproof.highwater-drill-private-evidence-subject.v1"
  }),
  recoveryContinuity: Object.freeze({
    schemaVersion: "tideproof.highwater-drill-recovery-continuity.v1",
    status: "RECOVERY_CURRENT_BYTES_BOUND_CRASH_RESTART_PENDING",
    subjectSchemaVersion:
      "tideproof.highwater-drill-recovery-continuity-subject.v1"
  })
});

export const INTEGRATED_LIVE_DRILL_EVIDENCE_KEY_NAMES = Object.freeze([
  "acceptedReceipt",
  "billingSettlement",
  "costUpperBound",
  "privateEvidence",
  "recoveryContinuity"
]);
export const INTEGRATED_LIVE_DRILL_RECOVERY_WORKERS = Object.freeze([
  "W1_PRE_READ_CHECKPOINT",
  "W2_SINGLE_MCP_READ_AND_DURABLE_RESULT",
  "W3_TERMINAL_AUDIT_ACK_LOSS",
  "W4_RECEIPT_PUBLICATION_LOSS",
  "W5_NO_PROVIDER_RECONCILIATION"
]);
export const INTEGRATED_LIVE_DRILL_RECOVERY_FAILPOINTS = Object.freeze([
  "PRE_READ_CHECKPOINT",
  "MCP_RESULT_AND_CLOSE_DURABLE",
  "TERMINAL_AUDIT_ROW_VISIBLE_ACK_LOSS",
  "RECEIPT_DURABLE_PUBLICATION_LOSS"
]);
export const INTEGRATED_LIVE_DRILL_SPEND_SCOPES = Object.freeze([
  Object.freeze({
    component: "gate1-admissible-vector",
    maximumExecutions: 1,
    provider: "COCKROACHDB",
    scopeId: "DVI_PROOF",
    sequence: 1
  }),
  Object.freeze({
    component: "gate2-authority-race",
    maximumExecutions: 1,
    provider: "AWS",
    scopeId: "AWS_AUTHORITY_RACE",
    sequence: 2
  }),
  Object.freeze({
    component: "gate1-recovery-broker",
    maximumExecutions: 1,
    provider: "COCKROACHDB_MANAGED_MCP",
    scopeId: "MANAGED_MCP_RECOVERY",
    sequence: 3
  })
]);
export const INTEGRATED_LIVE_DRILL_AUTHORITY_DESIGN_GAP = Object.freeze({
  status: "PARTIAL_FAIL_CLOSED",
  blockers: Object.freeze([
    INTEGRATED_LIVE_DRILL_CROSS_HOST_CLAIM_BLOCKER
  ]),
  claimBoundary:
    "The signed run authorization is accepted only under a separately supplied, human-controlled Ed25519 trust root whose key is cryptographically distinct from every runtime, child-launch, evidence, and recovery publisher signer. Provider execution additionally requires a create-only authorization claim, ordered spend reservations, and a one-use signed child-launch token under one exact authoritative owner-only ledger root and declared runner identity. Those files are atomic and restart-durable on that root, but are not a strongly consistent cross-host claim authority and cannot defeat a replay from an independently copied pre-launch ledger. The software proves possession of the configured human key, not the civil identity of its custodian; key ceremony, runner identity, shared durable claim authority, and custody remain operational controls."
});

const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const MAX_AUTHORIZATION_AGE_MS = 4 * 60 * 60 * 1_000;
const USD_MICROS = /^(?:0|[1-9][0-9]{0,5})\.[0-9]{6}$/u;
const SIGNATURE_DOMAIN =
  "ProofToAct integrated live drill signed evidence v2\0";
const AUTHORIZATION_ATTESTATION_SELF_REFERENCE_MARKER =
  "DERIVED_FROM_THIS_SIGNED_RUN_AUTHORIZATION_ATTESTATION_SHA256";

function reject(code) {
  throw new Error(code);
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function exactKeys(value, keys) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join("\n") === [...keys].sort().join("\n")
  );
}

export function integratedLiveDrillSha256(value) {
  return createHash("sha256")
    .update(Buffer.isBuffer(value) ? value : String(value))
    .digest("hex");
}

export function integratedLiveDrillCanonicalSha256(value) {
  return integratedLiveDrillSha256(canonicalJson(value));
}

export function integratedLiveDrillAuthorizedExpectation(expectation) {
  const validated = validateDeploymentExpectation(expectation);
  return Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_AUTHORIZED_EXPECTATION_SCHEMA,
    deploymentExpectation: Object.freeze({
      ...validated,
      integratedLiveDrillAuthorizationAttestationSha256:
        AUTHORIZATION_ATTESTATION_SELF_REFERENCE_MARKER
    })
  });
}

function isoMilliseconds(value, code) {
  if (typeof value !== "string") reject(code);
  const milliseconds = Date.parse(value);
  requireCondition(
    Number.isFinite(milliseconds) &&
      new Date(milliseconds).toISOString() === value,
    code
  );
  return milliseconds;
}

function canonicalBase64(value, code, maximumBytes = 4096) {
  if (typeof value !== "string" || value.length === 0) reject(code);
  const bytes = Buffer.from(value, "base64");
  requireCondition(
    bytes.length > 0 &&
      bytes.length <= maximumBytes &&
      bytes.toString("base64") === value,
    code
  );
  return bytes;
}

export function integratedLiveDrillEvidencePublicKey(record, code) {
  requireCondition(
    exactKeys(record, ["keyIdSha256", "publicKeySpkiDerBase64"]) &&
      HEX_64.test(record.keyIdSha256 ?? ""),
    code
  );
  const bytes = canonicalBase64(record.publicKeySpkiDerBase64, code, 256);
  requireCondition(integratedLiveDrillSha256(bytes) === record.keyIdSha256, code);
  let key;
  try {
    key = createPublicKey({ key: bytes, format: "der", type: "spki" });
  } catch {
    reject(code);
  }
  requireCondition(
    key.asymmetricKeyType === "ed25519" &&
      key.export({ format: "der", type: "spki" }).equals(bytes),
    code
  );
  return key;
}

function deploymentKeyRecord(value, code) {
  const bytes = canonicalBase64(value, code, 256);
  let key;
  try {
    key = createPublicKey({ key: bytes, format: "der", type: "spki" });
  } catch {
    reject(code);
  }
  requireCondition(
    key.asymmetricKeyType === "ed25519" &&
      key.export({ format: "der", type: "spki" }).equals(bytes),
    code
  );
  return Object.freeze({
    keyIdSha256: integratedLiveDrillSha256(bytes),
    publicKeySpkiDerBase64: value
  });
}

function signaturePayload(payload) {
  return Buffer.from(`${SIGNATURE_DOMAIN}${canonicalJson(payload)}`, "utf8");
}

export function signIntegratedLiveDrillEvidence(
  payload,
  privateKeyPkcs8DerBase64,
  expectedPublicKey
) {
  const publicRecord =
    typeof expectedPublicKey === "string"
      ? deploymentKeyRecord(
          expectedPublicKey,
          "INTEGRATED_LIVE_DRILL_SIGNING_PUBLIC_KEY_REJECTED"
        )
      : expectedPublicKey;
  const publicKey = integratedLiveDrillEvidencePublicKey(
    publicRecord,
    "INTEGRATED_LIVE_DRILL_SIGNING_PUBLIC_KEY_REJECTED"
  );
  const privateBytes = canonicalBase64(
    privateKeyPkcs8DerBase64,
    "INTEGRATED_LIVE_DRILL_SIGNING_PRIVATE_KEY_REJECTED",
    256
  );
  let privateKey;
  try {
    privateKey = createPrivateKey({
      key: privateBytes,
      format: "der",
      type: "pkcs8"
    });
  } catch {
    reject("INTEGRATED_LIVE_DRILL_SIGNING_PRIVATE_KEY_REJECTED");
  }
  requireCondition(
    privateKey.asymmetricKeyType === "ed25519" &&
      createPublicKey(privateKey).equals(publicKey),
    "INTEGRATED_LIVE_DRILL_SIGNING_KEY_MISMATCH"
  );
  const signature = sign(null, signaturePayload(payload), privateKey);
  requireCondition(signature.length === 64, "INTEGRATED_LIVE_DRILL_SIGNATURE_REJECTED");
  return Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_SIGNED_EVIDENCE_SCHEMA,
    payload,
    signature: Object.freeze({
      algorithm: "Ed25519",
      keyIdSha256: publicRecord.keyIdSha256,
      value: signature.toString("base64")
    })
  });
}

export function verifyIntegratedLiveDrillEvidence(
  attestation,
  expectedPublicKey,
  expectedPayloadSchema,
  code
) {
  const publicRecord =
    typeof expectedPublicKey === "string"
      ? deploymentKeyRecord(expectedPublicKey, code)
      : expectedPublicKey;
  const publicKey = integratedLiveDrillEvidencePublicKey(publicRecord, code);
  requireCondition(
    exactKeys(attestation, ["payload", "schemaVersion", "signature"]) &&
      attestation.schemaVersion === INTEGRATED_LIVE_DRILL_SIGNED_EVIDENCE_SCHEMA &&
      attestation.payload?.schemaVersion === expectedPayloadSchema &&
      exactKeys(attestation.signature, ["algorithm", "keyIdSha256", "value"]) &&
      attestation.signature.algorithm === "Ed25519" &&
      attestation.signature.keyIdSha256 === publicRecord.keyIdSha256,
    code
  );
  const signature = canonicalBase64(attestation.signature.value, code, 64);
  requireCondition(
    signature.length === 64 &&
      verify(null, signaturePayload(attestation.payload), publicKey, signature),
    code
  );
  return attestation.payload;
}

export function integratedLiveDrillAuthorizationAttestationDigest(attestation) {
  return integratedLiveDrillCanonicalSha256(attestation);
}

export function integratedLiveDrillAuthorizationLedgerRootDigest(rootPath) {
  requireCondition(
    typeof rootPath === "string" &&
      path.isAbsolute(rootPath) &&
      path.resolve(rootPath) === rootPath &&
      rootPath.length <= 4096 &&
      !/[\0\r\n]/u.test(rootPath),
    "INTEGRATED_LIVE_DRILL_AUTHORIZATION_LEDGER_ROOT_REJECTED"
  );
  return integratedLiveDrillSha256(
    `ProofToAct authorization ledger root v1\0${rootPath}`
  );
}

export function integratedLiveDrillRunnerIdentityDigest(value) {
  requireCondition(
    typeof value === "string" &&
      value.length > 0 &&
      value.length <= 512 &&
      !/[\0\r\n]/u.test(value),
    "INTEGRATED_LIVE_DRILL_RUNNER_IDENTITY_REJECTED"
  );
  return integratedLiveDrillSha256(
    `ProofToAct authorized runner identity v1\0${value}`
  );
}

export function integratedLiveDrillHumanAuthorizationTrustRootCommitment(
  trustRoot
) {
  return integratedLiveDrillSha256(
    `ProofToAct human authorization trust root v1\0${canonicalJson(trustRoot)}`
  );
}

export function validateIntegratedLiveDrillHumanAuthorizationTrustRoot(
  trustRoot
) {
  requireCondition(
    exactKeys(trustRoot, [
      "authorityId",
      "custody",
      "keyIdSha256",
      "publicKeySpkiDerBase64",
      "schemaVersion"
    ]) &&
      trustRoot.schemaVersion ===
        INTEGRATED_LIVE_DRILL_HUMAN_AUTHORIZATION_TRUST_ROOT_SCHEMA &&
      trustRoot.authorityId === "PROOFTOACT_OWNER" &&
      trustRoot.custody === "HUMAN_CONTROLLED_OFFLINE",
    "INTEGRATED_LIVE_DRILL_HUMAN_TRUST_ROOT_REJECTED"
  );
  integratedLiveDrillEvidencePublicKey(
    {
      keyIdSha256: trustRoot.keyIdSha256,
      publicKeySpkiDerBase64: trustRoot.publicKeySpkiDerBase64
    },
    "INTEGRATED_LIVE_DRILL_HUMAN_TRUST_ROOT_REJECTED"
  );
  return Object.freeze({ ...trustRoot });
}

export function validateIntegratedLiveDrillCommittedRecoveryTrustRoot(value) {
  requireCondition(
    exactKeys(value, [
      "publisherKeySetDigest",
      "schemaVersion",
      "trustRootCommitment",
      "trustedPublisherKeys"
    ]) &&
      value.schemaVersion ===
        INTEGRATED_LIVE_DRILL_COMMITTED_RECOVERY_TRUST_ROOT_SCHEMA &&
      HEX_64.test(value.publisherKeySetDigest ?? "") &&
      HEX_64.test(value.trustRootCommitment ?? "") &&
      value.trustedPublisherKeys &&
      typeof value.trustedPublisherKeys === "object" &&
      !Array.isArray(value.trustedPublisherKeys),
    "INTEGRATED_LIVE_DRILL_COMMITTED_RECOVERY_TRUST_ROOT_REJECTED"
  );
  let digest;
  try {
    digest = trustedPublisherKeysDigest(value.trustedPublisherKeys);
    for (const encoded of Object.values(value.trustedPublisherKeys)) {
      const bytes = canonicalBase64(
        encoded,
        "INTEGRATED_LIVE_DRILL_COMMITTED_RECOVERY_TRUST_ROOT_REJECTED",
        4096
      );
      const key = createPublicKey({ key: bytes, format: "der", type: "spki" });
      requireCondition(
        key.asymmetricKeyType === "ec" &&
          ["prime256v1", "P-256"].includes(
            key.asymmetricKeyDetails?.namedCurve
          ),
        "INTEGRATED_LIVE_DRILL_COMMITTED_RECOVERY_TRUST_ROOT_REJECTED"
      );
    }
  } catch (cause) {
    if (cause?.message ===
      "INTEGRATED_LIVE_DRILL_COMMITTED_RECOVERY_TRUST_ROOT_REJECTED") {
      throw cause;
    }
    throw new Error(
      "INTEGRATED_LIVE_DRILL_COMMITTED_RECOVERY_TRUST_ROOT_REJECTED",
      { cause }
    );
  }
  requireCondition(
    digest === value.publisherKeySetDigest,
    "INTEGRATED_LIVE_DRILL_COMMITTED_RECOVERY_TRUST_ROOT_REJECTED"
  );
  return Object.freeze({
    publisherKeySetDigest: value.publisherKeySetDigest,
    schemaVersion: value.schemaVersion,
    trustRootCommitment: value.trustRootCommitment,
    trustedPublisherKeys: Object.freeze({ ...value.trustedPublisherKeys })
  });
}

function usdMicros(value, code) {
  requireCondition(typeof value === "string" && USD_MICROS.test(value), code);
  const [whole, fractional] = value.split(".");
  const micros = BigInt(whole) * 1_000_000n + BigInt(fractional);
  requireCondition(micros >= 0n && micros <= 1_000_000_000n, code);
  return micros;
}

export function validateIntegratedLiveDrillSpendAuthorization(
  value,
  expectedMaximumUsd
) {
  requireCondition(
    exactKeys(value, [
      "currency",
      "maximumCumulativeExposureUsd",
      "schemaVersion",
      "scopes"
    ]) &&
      value.schemaVersion === INTEGRATED_LIVE_DRILL_SPEND_AUTHORIZATION_SCHEMA &&
      value.currency === "USD" &&
      Array.isArray(value.scopes) &&
      value.scopes.length === INTEGRATED_LIVE_DRILL_SPEND_SCOPES.length,
    "INTEGRATED_LIVE_DRILL_SPEND_AUTHORIZATION_REJECTED"
  );
  const maximumMicros = usdMicros(
    value.maximumCumulativeExposureUsd,
    "INTEGRATED_LIVE_DRILL_SPEND_AUTHORIZATION_REJECTED"
  );
  requireCondition(
    maximumMicros === usdMicros(
      expectedMaximumUsd,
      "INTEGRATED_LIVE_DRILL_SPEND_AUTHORIZATION_REJECTED"
    ),
    "INTEGRATED_LIVE_DRILL_SPEND_AUTHORIZATION_REJECTED"
  );
  let cumulativeMicros = 0n;
  for (const [index, expected] of
    INTEGRATED_LIVE_DRILL_SPEND_SCOPES.entries()) {
    const scope = value.scopes[index];
    requireCondition(
      exactKeys(scope, [
        "component",
        "maximumExecutions",
        "maximumExposureUsd",
        "provider",
        "scopeId",
        "sequence"
      ]) &&
        scope.component === expected.component &&
        scope.maximumExecutions === expected.maximumExecutions &&
        scope.provider === expected.provider &&
        scope.scopeId === expected.scopeId &&
        scope.sequence === expected.sequence,
      "INTEGRATED_LIVE_DRILL_SPEND_AUTHORIZATION_REJECTED"
    );
    cumulativeMicros += usdMicros(
      scope.maximumExposureUsd,
      "INTEGRATED_LIVE_DRILL_SPEND_AUTHORIZATION_REJECTED"
    );
  }
  requireCondition(
    cumulativeMicros <= maximumMicros,
    "INTEGRATED_LIVE_DRILL_SPEND_AUTHORIZATION_REJECTED"
  );
  return Object.freeze({
    cumulativeMicros,
    maximumMicros,
    value
  });
}

function validateExpectationSpecBinding(expectation, spec) {
  requireCondition(
    expectation?.sourceCommit === spec?.sourceCommit &&
      expectation?.treeDigest === spec?.treeDigest &&
      expectation?.configDigest === spec?.configDigest &&
      expectation?.functions?.authority?.numericVersionArn ===
        spec?.functionArn,
    "INTEGRATED_LIVE_DRILL_AUTHORIZATION_EXPECTATION_REJECTED"
  );
}

export function validateIntegratedLiveDrillRunAuthorization(
  attestation,
  {
    spec,
    expectation,
    committedTrustRoot,
    humanAuthorizationTrustRoot,
    authorizationLedgerRootPath,
    now = Date.now()
  }
) {
  const validatedExpectation = validateDeploymentExpectation(expectation);
  validateExpectationSpecBinding(validatedExpectation, spec);
  const recoveryTrustRoot =
    validateIntegratedLiveDrillCommittedRecoveryTrustRoot(
      committedTrustRoot
    );
  const humanTrustRoot =
    validateIntegratedLiveDrillHumanAuthorizationTrustRoot(
      humanAuthorizationTrustRoot
    );
  const payload = verifyIntegratedLiveDrillEvidence(
    attestation,
    {
      keyIdSha256: humanTrustRoot.keyIdSha256,
      publicKeySpkiDerBase64: humanTrustRoot.publicKeySpkiDerBase64
    },
    INTEGRATED_LIVE_DRILL_RUN_AUTHORIZATION_SCHEMA,
    "INTEGRATED_LIVE_DRILL_AUTHORIZATION_SIGNATURE_REJECTED"
  );
  requireCondition(
    exactKeys(payload, [
      "authorityNumericVersionArnSha256",
      "authorizationClaimAuthority",
      "authorizationLedgerRootSha256",
      "authorizationId",
      "childLaunchPublicKey",
      "evidencePublicKeys",
      "expectationSha256",
      "expiresAt",
      "humanAuthorizationTrustRootCommitment",
      "issuedAt",
      "maximumAwsCostUsd",
      "maximumRecoverySourceAgeSeconds",
      "publisherKeySetDigest",
      "recoveryPublisherTrustRootCommitment",
      "requiredManagedMcpToolCallCount",
      "requiredRecoveryFailpoints",
      "requiredRecoveryJournalEntryCount",
      "requiredRecoveryWorkers",
      "runId",
      "schemaVersion",
      "sourceCommit",
      "spendAuthorization",
      "specSha256",
      "treeDigest",
      "configDigest"
    ]) &&
      UUID.test(payload.authorizationId ?? "") &&
      payload.sourceCommit === spec.sourceCommit &&
      payload.treeDigest === spec.treeDigest &&
      payload.configDigest === spec.configDigest &&
      payload.runId === spec.runId &&
      payload.specSha256 === integratedLiveDrillCanonicalSha256(spec) &&
      payload.expectationSha256 === integratedLiveDrillCanonicalSha256(
        integratedLiveDrillAuthorizedExpectation(validatedExpectation)
      ) &&
      payload.authorityNumericVersionArnSha256 ===
        integratedLiveDrillSha256(spec.functionArn) &&
      exactKeys(payload.authorizationClaimAuthority, [
        "authorizationLedgerRootSha256",
        "crossHostStrongConsistencyProven",
        "durabilityScope",
        "runnerIdentitySha256",
        "schemaVersion"
      ]) &&
      payload.authorizationClaimAuthority.schemaVersion ===
        INTEGRATED_LIVE_DRILL_CLAIM_AUTHORITY_SCHEMA &&
      payload.authorizationClaimAuthority.authorizationLedgerRootSha256 ===
        payload.authorizationLedgerRootSha256 &&
      payload.authorizationClaimAuthority.durabilityScope ===
        "SINGLE_AUTHORITATIVE_LEDGER_ROOT" &&
      payload.authorizationClaimAuthority.crossHostStrongConsistencyProven ===
        false &&
      HEX_64.test(
        payload.authorizationClaimAuthority.runnerIdentitySha256 ?? ""
      ) &&
      payload.authorizationLedgerRootSha256 ===
        integratedLiveDrillAuthorizationLedgerRootDigest(
          authorizationLedgerRootPath
        ) &&
      payload.maximumAwsCostUsd === "0.020000" &&
      payload.humanAuthorizationTrustRootCommitment ===
        integratedLiveDrillHumanAuthorizationTrustRootCommitment(
          humanTrustRoot
        ) &&
      payload.maximumRecoverySourceAgeSeconds === 3600 &&
      payload.requiredManagedMcpToolCallCount === 1 &&
      payload.requiredRecoveryJournalEntryCount === 17 &&
      canonicalJson(payload.requiredRecoveryWorkers) ===
        canonicalJson(INTEGRATED_LIVE_DRILL_RECOVERY_WORKERS) &&
      canonicalJson(payload.requiredRecoveryFailpoints) ===
        canonicalJson(INTEGRATED_LIVE_DRILL_RECOVERY_FAILPOINTS) &&
      exactKeys(payload.evidencePublicKeys, INTEGRATED_LIVE_DRILL_EVIDENCE_KEY_NAMES) &&
      payload.recoveryPublisherTrustRootCommitment ===
        recoveryTrustRoot.trustRootCommitment &&
      payload.publisherKeySetDigest === recoveryTrustRoot.publisherKeySetDigest &&
      validatedExpectation.integratedLiveDrillAuthorizationAttestationSha256 ===
        integratedLiveDrillAuthorizationAttestationDigest(attestation),
    "INTEGRATED_LIVE_DRILL_AUTHORIZATION_REJECTED"
  );
  validateIntegratedLiveDrillSpendAuthorization(
    payload.spendAuthorization,
    payload.maximumAwsCostUsd
  );
  integratedLiveDrillEvidencePublicKey(
    payload.childLaunchPublicKey,
    "INTEGRATED_LIVE_DRILL_AUTHORIZATION_CHILD_LAUNCH_KEY_REJECTED"
  );
  const childLaunchKeyId = payload.childLaunchPublicKey.keyIdSha256;
  const evidenceKeyIds = INTEGRATED_LIVE_DRILL_EVIDENCE_KEY_NAMES.map((name) => {
    integratedLiveDrillEvidencePublicKey(
      payload.evidencePublicKeys[name],
      "INTEGRATED_LIVE_DRILL_AUTHORIZATION_EVIDENCE_KEY_REJECTED"
    );
    return payload.evidencePublicKeys[name].keyIdSha256;
  });
  const deploymentKeyIds = Object.values(
    validatedExpectation.receiptPublicKeys
  ).map(
    (value) => integratedLiveDrillSha256(Buffer.from(value, "base64"))
  );
  const recoveryPublisherKeyIds = Object.values(
    recoveryTrustRoot.trustedPublisherKeys
  ).map((value) => integratedLiveDrillSha256(Buffer.from(value, "base64")));
  requireCondition(
    new Set(evidenceKeyIds).size === evidenceKeyIds.length &&
      !deploymentKeyIds.includes(childLaunchKeyId) &&
      !recoveryPublisherKeyIds.includes(childLaunchKeyId) &&
      childLaunchKeyId !== humanTrustRoot.keyIdSha256 &&
      !evidenceKeyIds.includes(childLaunchKeyId) &&
      !deploymentKeyIds.includes(humanTrustRoot.keyIdSha256) &&
      !recoveryPublisherKeyIds.includes(humanTrustRoot.keyIdSha256) &&
      evidenceKeyIds.every(
        (value) =>
          !deploymentKeyIds.includes(value) &&
          !recoveryPublisherKeyIds.includes(value) &&
          value !== humanTrustRoot.keyIdSha256
      ),
    "INTEGRATED_LIVE_DRILL_AUTHORIZATION_KEY_SEPARATION_REJECTED"
  );
  const issuedAt = isoMilliseconds(
    payload.issuedAt,
    "INTEGRATED_LIVE_DRILL_AUTHORIZATION_TIME_REJECTED"
  );
  const expiresAt = isoMilliseconds(
    payload.expiresAt,
    "INTEGRATED_LIVE_DRILL_AUTHORIZATION_TIME_REJECTED"
  );
  requireCondition(
    Number.isSafeInteger(now) &&
      expiresAt > issuedAt &&
      expiresAt - issuedAt <= MAX_AUTHORIZATION_AGE_MS &&
      now >= issuedAt &&
      now <= expiresAt,
    "INTEGRATED_LIVE_DRILL_AUTHORIZATION_TIME_REJECTED"
  );
  return Object.freeze({
    attestation,
    expiresAt,
    humanAuthorizationKeyIdSha256: humanTrustRoot.keyIdSha256,
    issuedAt,
    payload
  });
}

export function validateIntegratedLiveDrillPreAuthorizationBinding(
  authorization,
  preReceipt,
  { now = Date.now() } = {}
) {
  const preStartedAt = isoMilliseconds(
    preReceipt?.observationStartedAt,
    "INTEGRATED_LIVE_DRILL_AUTHORIZATION_PRE_TIME_REJECTED"
  );
  const preObservedAt = isoMilliseconds(
    preReceipt?.observedAt,
    "INTEGRATED_LIVE_DRILL_AUTHORIZATION_PRE_TIME_REJECTED"
  );
  requireCondition(
    preReceipt.integratedLiveDrillAuthorizationAttestationSha256 ===
        integratedLiveDrillAuthorizationAttestationDigest(
          authorization.attestation
        ) &&
      authorization.issuedAt < preStartedAt &&
      preObservedAt >= preStartedAt &&
      preObservedAt <= authorization.expiresAt &&
      Number.isSafeInteger(now) &&
      preObservedAt <= now,
    "INTEGRATED_LIVE_DRILL_AUTHORIZATION_PRE_BINDING_REJECTED"
  );
  return Object.freeze({ preObservedAt, preStartedAt });
}

export function integratedLiveDrillAcceptanceCore({
  authorization,
  evidenceDigests,
  candidateReceiptSha256
}) {
  requireCondition(
    exactKeys(evidenceDigests, [
      "acceptedReceipt",
      "billingSettlement",
      "costUpperBound",
      "deploymentPair",
      "latestObservedAt",
      "privateEvidence",
      "recoveryContinuity"
    ]) &&
      [
        candidateReceiptSha256,
        evidenceDigests.acceptedReceipt,
        evidenceDigests.billingSettlement,
        evidenceDigests.costUpperBound,
        evidenceDigests.deploymentPair,
        evidenceDigests.privateEvidence,
        evidenceDigests.recoveryContinuity
      ].every((value) => HEX_64.test(value ?? "")) &&
      Number.isSafeInteger(evidenceDigests.latestObservedAt) &&
      evidenceDigests.latestObservedAt >= authorization.issuedAt &&
      evidenceDigests.latestObservedAt <= authorization.expiresAt,
    "INTEGRATED_LIVE_DRILL_ACCEPTANCE_CORE_REJECTED"
  );
  return Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_ACCEPTANCE_CORE_SCHEMA,
    authorizationAttestationSha256:
      integratedLiveDrillAuthorizationAttestationDigest(
        authorization.attestation
      ),
    authorizationId: authorization.payload.authorizationId,
    acceptedReceiptAttestationSha256: evidenceDigests.acceptedReceipt,
    billingSettlementAttestationSha256: evidenceDigests.billingSettlement,
    billingStatus: "PENDING",
    candidateReceiptSha256,
    configDigest: authorization.payload.configDigest,
    costUpperBoundAttestationSha256: evidenceDigests.costUpperBound,
    deploymentAttestationPairSha256: evidenceDigests.deploymentPair,
    latestObservedAt: new Date(
      evidenceDigests.latestObservedAt
    ).toISOString(),
    privateEvidenceAttestationSha256: evidenceDigests.privateEvidence,
    recoveryContinuityAttestationSha256:
      evidenceDigests.recoveryContinuity,
    runId: authorization.payload.runId,
    sourceCommit: authorization.payload.sourceCommit,
    treeDigest: authorization.payload.treeDigest
  });
}

function integratedLiveDrillTypedEvidenceSubject({
  artifact,
  authorization,
  candidateReceiptSha256,
  context,
  name
}) {
  const contract = INTEGRATED_LIVE_DRILL_TYPED_EVIDENCE[name];
  return Object.freeze({
    schemaVersion: contract.subjectSchemaVersion,
    authorizationAttestationSha256:
      integratedLiveDrillAuthorizationAttestationDigest(
        authorization.attestation
      ),
    authorizationId: authorization.payload.authorizationId,
    candidateReceiptSha256,
    configDigest: authorization.payload.configDigest,
    controlLedgerReceiptSha256: context.controlLedgerReceiptSha256,
    deploymentAttestationPairSha256:
      context.deploymentAttestationPairSha256,
    evidenceName: name,
    expectationSha256: authorization.payload.expectationSha256,
    runId: authorization.payload.runId,
    sourceCommit: authorization.payload.sourceCommit,
    status: contract.status,
    treeDigest: authorization.payload.treeDigest,
    artifact: Object.freeze(artifact)
  });
}

export function integratedLiveDrillTypedEvidenceSubjects({
  authorization,
  candidateReceipt,
  controlLedgerReceipt,
  deploymentAttestationPair,
  expectation
}) {
  const code = "INTEGRATED_LIVE_DRILL_EVIDENCE_SUBJECT_REJECTED";
  const { receiptSha256: candidateReceiptSha256, ...candidateBody } =
    candidateReceipt ?? {};
  const { receiptSha256: controlLedgerReceiptSha256, ...controlLedgerBody } =
    controlLedgerReceipt ?? {};
  const packetBBlocker =
    "DURABLE_EXACT_ONE_MCP_CRASH_RESTART_AMBIGUOUS_RESULT_RECONCILIATION_NOT_PROVEN";
  requireCondition(
    authorization?.payload &&
      HEX_64.test(candidateReceiptSha256 ?? "") &&
      candidateReceiptSha256 ===
        integratedLiveDrillCanonicalSha256(candidateBody) &&
      candidateReceipt.sourceCommit === authorization.payload.sourceCommit &&
      candidateReceipt.treeDigest === authorization.payload.treeDigest &&
      candidateReceipt.configDigest === authorization.payload.configDigest &&
      candidateReceipt.runId === authorization.payload.runId &&
      candidateReceipt.status === "INCOMPLETE_LIVE_GATES_PENDING" &&
      candidateReceipt.providerBacked === false &&
      exactKeys(candidateReceipt.acceptance, [
        "accepted",
        "blockers",
        "crashSafeRecoveryProven",
        "deploymentAttestationBound",
        "finalReceiptSchema",
        "preProviderJournalPersisted",
        "privateEvidencePersisted"
      ]) &&
      candidateReceipt.acceptance?.accepted === false &&
      Array.isArray(candidateReceipt.acceptance.blockers) &&
      candidateReceipt.acceptance.blockers.includes(
        INTEGRATED_LIVE_DRILL_CROSS_HOST_CLAIM_BLOCKER
      ) &&
      candidateReceipt.acceptance.blockers.includes(packetBBlocker) &&
      candidateReceipt.recovery?.managedMcpCallCount === 1 &&
      exactKeys(candidateReceipt.recovery, [
        "auditsCommitted",
        "exactWinnerBound",
        "managedMcpCallCount",
        "operationalCapabilitiesReturned",
        "restartStableSignedBundleReuseProven",
        "signedBundleCurrentBytesBound",
        "signedBundleSourceControlReceiptSha256",
        "unauthorizedPrincipalDenied"
      ]) &&
      candidateReceipt.recovery?.restartStableSignedBundleReuseProven ===
        false &&
      candidateReceipt.recovery.signedBundleCurrentBytesBound === true &&
      HEX_64.test(
        candidateReceipt.recovery
          .signedBundleSourceControlReceiptSha256 ?? ""
      ) &&
      exactKeys(candidateReceipt.privateEvidence, [
        "bundleSha256",
        "currentBytesBound",
        "sourceControlReceiptSha256"
      ]) &&
      HEX_64.test(candidateReceipt.privateEvidence.bundleSha256 ?? "") &&
      candidateReceipt.privateEvidence.currentBytesBound === true &&
      HEX_64.test(
        candidateReceipt.privateEvidence.sourceControlReceiptSha256 ?? ""
      ) &&
      exactKeys(candidateReceipt.costControl, [
        "actualAwsSpendVerified",
        "actualProviderBillingReceiptRequiredSeparately",
        "authorizationControlLedgerReceiptSha256",
        "completeProviderRequestAccounting",
        "fixedTopLevelProviderOperationCount",
        "operatorDeclaredMaximumAwsCostUsd",
        "providerPricingVerified",
        "spendAuthorizationProvenByReceipt"
      ]) &&
      candidateReceipt.costControl?.spendAuthorizationProvenByReceipt ===
        true &&
      candidateReceipt.costControl.actualAwsSpendVerified === false &&
      candidateReceipt.costControl.providerPricingVerified === false &&
      candidateReceipt.costControl
        .actualProviderBillingReceiptRequiredSeparately === true &&
      HEX_64.test(controlLedgerReceiptSha256 ?? "") &&
      controlLedgerReceiptSha256 ===
        integratedLiveDrillCanonicalSha256(controlLedgerBody) &&
      exactKeys(controlLedgerReceipt, [
        "authorizationAttestationSha256",
        "authorizationClaimSha256",
        "authorizationId",
        "authorizedMaximumCumulativeExposureUsd",
        "childLaunchDigests",
        "exactChildLaunchCount",
        "exactScopeCount",
        "receiptSha256",
        "reservationDigests",
        "reservedCumulativeExposureUsd",
        "runId",
        "schemaVersion",
        "spendAuthorizationSha256"
      ]) &&
      controlLedgerReceipt.schemaVersion ===
        "tideproof.highwater-drill-control-ledger-receipt.v1" &&
      controlLedgerReceipt.authorizationAttestationSha256 ===
        integratedLiveDrillAuthorizationAttestationDigest(
          authorization.attestation
        ) &&
      controlLedgerReceipt.authorizationId ===
        authorization.payload.authorizationId &&
      controlLedgerReceipt.runId === authorization.payload.runId &&
      controlLedgerReceipt.authorizedMaximumCumulativeExposureUsd ===
        authorization.payload.maximumAwsCostUsd &&
      controlLedgerReceipt.exactChildLaunchCount ===
        INTEGRATED_LIVE_DRILL_SPEND_SCOPES.length &&
      controlLedgerReceipt.exactScopeCount ===
        INTEGRATED_LIVE_DRILL_SPEND_SCOPES.length &&
      Array.isArray(controlLedgerReceipt.childLaunchDigests) &&
      controlLedgerReceipt.childLaunchDigests.length ===
        INTEGRATED_LIVE_DRILL_SPEND_SCOPES.length &&
      Array.isArray(controlLedgerReceipt.reservationDigests) &&
      controlLedgerReceipt.reservationDigests.length ===
        INTEGRATED_LIVE_DRILL_SPEND_SCOPES.length &&
      [
        controlLedgerReceipt.authorizationClaimSha256,
        controlLedgerReceipt.spendAuthorizationSha256,
        ...controlLedgerReceipt.childLaunchDigests,
        ...controlLedgerReceipt.reservationDigests
      ].every((value) => HEX_64.test(value ?? "")) &&
      candidateReceipt.costControl
        .authorizationControlLedgerReceiptSha256 ===
        controlLedgerReceiptSha256 &&
      authorization.payload.expectationSha256 ===
        integratedLiveDrillCanonicalSha256(
          integratedLiveDrillAuthorizedExpectation(expectation)
        ) &&
      deploymentAttestationPair &&
      typeof deploymentAttestationPair === "object" &&
      !Array.isArray(deploymentAttestationPair),
    code
  );
  const context = Object.freeze({
    controlLedgerReceiptSha256,
    deploymentAttestationPairSha256: integratedLiveDrillCanonicalSha256(
      deploymentAttestationPair
    )
  });
  const common = {
    authorization,
    candidateReceiptSha256,
    context
  };
  return Object.freeze({
    acceptedReceipt: integratedLiveDrillTypedEvidenceSubject({
      ...common,
      name: "acceptedReceipt",
      artifact: {
        acceptanceAccepted: false,
        candidateReceiptSchemaVersion: candidateReceipt.schemaVersion,
        candidateReceiptStatus: candidateReceipt.status,
        providerBacked: false,
        receiptSha256: candidateReceiptSha256
      }
    }),
    billingSettlement: integratedLiveDrillTypedEvidenceSubject({
      ...common,
      name: "billingSettlement",
      artifact: {
        authorizedMaximumCumulativeExposureUsd:
          controlLedgerReceipt.authorizedMaximumCumulativeExposureUsd,
        billingStatus: "PENDING",
        providerBillingEvidencePresent: false,
        reservedCumulativeExposureUsd:
          controlLedgerReceipt.reservedCumulativeExposureUsd,
        spendAuthorizationSha256:
          controlLedgerReceipt.spendAuthorizationSha256
      }
    }),
    costUpperBound: integratedLiveDrillTypedEvidenceSubject({
      ...common,
      name: "costUpperBound",
      artifact: {
        authorizedMaximumCumulativeExposureUsd:
          controlLedgerReceipt.authorizedMaximumCumulativeExposureUsd,
        candidateControlLedgerReceiptSha256:
          candidateReceipt.costControl
            .authorizationControlLedgerReceiptSha256,
        maximumAwsCostUsd: authorization.payload.maximumAwsCostUsd,
        providerBillingEvidencePresent: false,
        reservedCumulativeExposureUsd:
          controlLedgerReceipt.reservedCumulativeExposureUsd,
        spendAuthorizationProvenByReceipt: true
      }
    }),
    privateEvidence: integratedLiveDrillTypedEvidenceSubject({
      ...common,
      name: "privateEvidence",
      artifact: {
        bundleSha256: candidateReceipt.privateEvidence.bundleSha256,
        candidatePrivateEvidenceSha256:
          integratedLiveDrillCanonicalSha256(candidateReceipt.privateEvidence),
        currentBytesBound: true,
        sourceControlReceiptSha256:
          candidateReceipt.privateEvidence.sourceControlReceiptSha256
      }
    }),
    recoveryContinuity: integratedLiveDrillTypedEvidenceSubject({
      ...common,
      name: "recoveryContinuity",
      artifact: {
        candidateRecoverySha256:
          integratedLiveDrillCanonicalSha256(candidateReceipt.recovery),
        managedMcpCallCount: 1,
        packetBStatus: "CRASH_RESTART_RECONCILIATION_PENDING",
        restartStableSignedBundleReuseProven: false,
        signedBundleCurrentBytesBound:
          candidateReceipt.recovery.signedBundleCurrentBytesBound,
        signedBundleSourceControlReceiptSha256:
          candidateReceipt.recovery
            .signedBundleSourceControlReceiptSha256
      }
    })
  });
}

export function validateIntegratedLiveDrillTypedEvidenceAttestations(
  attestations,
  {
    authorization,
    candidateReceipt,
    controlLedgerReceipt,
    deploymentAttestationPair,
    expectation,
    now = Date.now()
  }
) {
  const subjects = integratedLiveDrillTypedEvidenceSubjects({
    authorization,
    candidateReceipt,
    controlLedgerReceipt,
    deploymentAttestationPair,
    expectation
  });
  const candidateReceiptSha256 = candidateReceipt?.receiptSha256;
  requireCondition(
    exactKeys(attestations, INTEGRATED_LIVE_DRILL_EVIDENCE_KEY_NAMES) &&
      HEX_64.test(candidateReceiptSha256 ?? "") &&
      Number.isSafeInteger(now),
    "INTEGRATED_LIVE_DRILL_EVIDENCE_SET_REJECTED"
  );
  const evidenceDigests = {};
  const observedTimes = [];
  for (const name of INTEGRATED_LIVE_DRILL_EVIDENCE_KEY_NAMES) {
    const contract = INTEGRATED_LIVE_DRILL_TYPED_EVIDENCE[name];
    const payload = verifyIntegratedLiveDrillEvidence(
      attestations[name],
      authorization.payload.evidencePublicKeys[name],
      contract.schemaVersion,
      `INTEGRATED_LIVE_DRILL_${name.toUpperCase()}_ATTESTATION_REJECTED`
    );
    requireCondition(
      exactKeys(payload, [
        "authorizationAttestationSha256",
        "authorizationId",
        "candidateReceiptSha256",
        "configDigest",
        "observedAt",
        "runId",
        "schemaVersion",
        "sourceCommit",
        "status",
        "subject",
        "subjectSha256",
        "treeDigest"
      ]) &&
        payload.authorizationAttestationSha256 ===
          integratedLiveDrillAuthorizationAttestationDigest(
            authorization.attestation
          ) &&
        payload.authorizationId === authorization.payload.authorizationId &&
        payload.candidateReceiptSha256 === candidateReceiptSha256 &&
        payload.configDigest === authorization.payload.configDigest &&
        payload.runId === authorization.payload.runId &&
        payload.sourceCommit === authorization.payload.sourceCommit &&
        payload.status === contract.status &&
        canonicalJson(payload.subject) === canonicalJson(subjects[name]) &&
        payload.subjectSha256 ===
          integratedLiveDrillCanonicalSha256(payload.subject) &&
        payload.treeDigest === authorization.payload.treeDigest,
      `INTEGRATED_LIVE_DRILL_${name.toUpperCase()}_ATTESTATION_REJECTED`
    );
    const observedAt = isoMilliseconds(
      payload.observedAt,
      `INTEGRATED_LIVE_DRILL_${name.toUpperCase()}_ATTESTATION_TIME_REJECTED`
    );
    requireCondition(
      observedAt >= authorization.issuedAt &&
        observedAt <= authorization.expiresAt &&
        observedAt <= now,
      `INTEGRATED_LIVE_DRILL_${name.toUpperCase()}_ATTESTATION_TIME_REJECTED`
    );
    observedTimes.push(observedAt);
    evidenceDigests[name] = integratedLiveDrillCanonicalSha256(
      attestations[name]
    );
  }
  return Object.freeze({
    acceptedReceipt: evidenceDigests.acceptedReceipt,
    billingSettlement: evidenceDigests.billingSettlement,
    costUpperBound: evidenceDigests.costUpperBound,
    latestObservedAt: Math.max(...observedTimes),
    privateEvidence: evidenceDigests.privateEvidence,
    recoveryContinuity: evidenceDigests.recoveryContinuity
  });
}

export function validateIntegratedLiveDrillEvidenceSet(
  attestations,
  deploymentAttestationPair,
  {
    authorization,
    candidateReceipt,
    controlLedgerReceipt,
    expectation,
    now = Date.now()
  }
) {
  const typedEvidence =
    validateIntegratedLiveDrillTypedEvidenceAttestations(attestations, {
      authorization,
      candidateReceipt,
      controlLedgerReceipt,
      deploymentAttestationPair,
      expectation,
      now
    });
  let deployment;
  try {
    deployment = validateSignedDeploymentAttestationPair(
      deploymentAttestationPair,
      expectation
    );
  } catch (cause) {
    throw new Error("INTEGRATED_LIVE_DRILL_DEPLOYMENT_PAIR_REJECTED", {
      cause
    });
  }
  const deploymentObservedAt = isoMilliseconds(
    deployment.observedAt,
    "INTEGRATED_LIVE_DRILL_DEPLOYMENT_PAIR_TIME_REJECTED"
  );
  requireCondition(
    deployment.integratedLiveDrillAuthorizationAttestationSha256 ===
      integratedLiveDrillAuthorizationAttestationDigest(
        authorization.attestation
      ) &&
      deploymentObservedAt >= authorization.issuedAt &&
      deploymentObservedAt <= authorization.expiresAt &&
      deploymentObservedAt <= now,
    "INTEGRATED_LIVE_DRILL_DEPLOYMENT_PAIR_TIME_REJECTED"
  );
  return Object.freeze({
    acceptedReceipt: typedEvidence.acceptedReceipt,
    billingSettlement: typedEvidence.billingSettlement,
    costUpperBound: typedEvidence.costUpperBound,
    deploymentPair: integratedLiveDrillCanonicalSha256(
      deploymentAttestationPair
    ),
    latestObservedAt: Math.max(
      typedEvidence.latestObservedAt,
      deploymentObservedAt
    ),
    privateEvidence: typedEvidence.privateEvidence,
    recoveryContinuity: typedEvidence.recoveryContinuity
  });
}

export function validateIntegratedLiveDrillFinalizationStatement(
  attestation,
  { expectation, authorization, evidenceDigests, candidateReceiptSha256, now }
) {
  const acceptanceCore = integratedLiveDrillAcceptanceCore({
    authorization,
    evidenceDigests,
    candidateReceiptSha256
  });
  const payload = verifyIntegratedLiveDrillEvidence(
    attestation,
    expectation.receiptPublicKeys.post,
    INTEGRATED_LIVE_DRILL_FINALIZATION_STATEMENT_SCHEMA,
    "INTEGRATED_LIVE_DRILL_FINALIZATION_STATEMENT_SIGNATURE_REJECTED"
  );
  requireCondition(
    exactKeys(payload, [
      "acceptanceCoreSha256",
      "acceptedReceiptAttestationSha256",
      "authorizationAttestationSha256",
      "authorizationId",
      "billingStatus",
      "billingSettlementAttestationSha256",
      "candidateReceiptSha256",
      "configDigest",
      "costUpperBoundAttestationSha256",
      "deploymentAttestationPairSha256",
      "issuedAt",
      "privateEvidenceAttestationSha256",
      "recoveryContinuityAttestationSha256",
      "runId",
      "schemaVersion",
      "sourceCommit",
      "statementId",
      "treeDigest"
    ]) &&
      UUID.test(payload.statementId ?? "") &&
      payload.authorizationId === authorization.payload.authorizationId &&
      payload.authorizationAttestationSha256 ===
        integratedLiveDrillAuthorizationAttestationDigest(
          authorization.attestation
        ) &&
      payload.sourceCommit === authorization.payload.sourceCommit &&
      payload.treeDigest === authorization.payload.treeDigest &&
      payload.configDigest === authorization.payload.configDigest &&
      payload.runId === authorization.payload.runId &&
      payload.candidateReceiptSha256 === candidateReceiptSha256 &&
      payload.acceptedReceiptAttestationSha256 ===
        evidenceDigests.acceptedReceipt &&
      payload.billingSettlementAttestationSha256 ===
        evidenceDigests.billingSettlement &&
      payload.billingStatus === "PENDING" &&
      payload.privateEvidenceAttestationSha256 === evidenceDigests.privateEvidence &&
      payload.recoveryContinuityAttestationSha256 ===
        evidenceDigests.recoveryContinuity &&
      payload.costUpperBoundAttestationSha256 === evidenceDigests.costUpperBound &&
      payload.deploymentAttestationPairSha256 === evidenceDigests.deploymentPair &&
      payload.acceptanceCoreSha256 ===
        integratedLiveDrillCanonicalSha256(acceptanceCore),
    "INTEGRATED_LIVE_DRILL_FINALIZATION_STATEMENT_REJECTED"
  );
  const issuedAt = isoMilliseconds(
    payload.issuedAt,
    "INTEGRATED_LIVE_DRILL_FINALIZATION_STATEMENT_TIME_REJECTED"
  );
  requireCondition(
    Number.isSafeInteger(now) &&
      evidenceDigests.latestObservedAt <= now &&
      issuedAt >= evidenceDigests.latestObservedAt &&
      issuedAt <= now &&
      issuedAt <= authorization.expiresAt,
    "INTEGRATED_LIVE_DRILL_FINALIZATION_STATEMENT_TIME_REJECTED"
  );
  return Object.freeze({ attestation, issuedAt, payload });
}

export const __test = Object.freeze({
  exactKeys,
  isoMilliseconds,
  signaturePayload
});
