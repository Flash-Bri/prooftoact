import crypto from "node:crypto";
import { Client } from "pg";

import {
  AuthorityStore,
  normalizedAuthorityRequestFor
} from "../src/cloud/authority-store.js";
import { authorizeDviProposalWithClient } from
  "../src/cloud/dvi-proposal-authorization.js";
import { connectionStringForUser } from "../src/cloud/primary-security.js";
import { authorizeSyntheticProposal } from
  "./lib/synthetic-authority-proposal.js";
import { createSyntheticEvidenceSigner } from
  "./lib/synthetic-evidence.js";

const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const SPEND_AUTHORITY_SQL = `
  SELECT *
  FROM tp_api.g1_spend_authority_v1(
    $1::UUID, $2::UUID, $3, $4::JSONB, $5, $6, $7,
    $8::UUID, $9::UUID, $10, $11, $12, $13::UUID, $14::UUID,
    $15::JSONB, $16, $17, $18::INT8
  )
`;

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function plainObject(value) {
  return value !== null && typeof value === "object" &&
    !Array.isArray(value) && [Object.prototype, null].includes(
      Object.getPrototypeOf(value)
    );
}

function exactKeys(value, expected) {
  return plainObject(value) && Object.keys(value).sort().join("\n") ===
    [...expected].sort().join("\n");
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (plainObject(value)) {
    return `{${Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, nested]) => `${JSON.stringify(key)}:${canonicalJson(nested)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function derivedUuid(operationId, label) {
  requireCondition(UUID.test(operationId ?? "") &&
    /^[a-z][a-z0-9-]{0,62}$/u.test(label),
  "FRESH_RECOVERY_SOURCE_IDENTITY_REJECTED");
  const bytes = crypto.createHash("sha256")
    .update(`prooftoact-fresh-recovery-source-v1\n${operationId}\n${label}\n`)
    .digest().subarray(0, 16);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  return [
    bytes.subarray(0, 4).toString("hex"),
    bytes.subarray(4, 6).toString("hex"),
    bytes.subarray(6, 8).toString("hex"),
    bytes.subarray(8, 10).toString("hex"),
    bytes.subarray(10, 16).toString("hex")
  ].join("-");
}

export function freshRecoverySourceIdentity(operationId) {
  return Object.freeze({
    tenantId: derivedUuid(operationId, "tenant"),
    runId: derivedUuid(operationId, "run"),
    incidentId: derivedUuid(operationId, "incident"),
    evidenceId: derivedUuid(operationId, "evidence"),
    retrievalId: derivedUuid(operationId, "retrieval"),
    effectKey: derivedUuid(operationId, "effect"),
    intentNonce: derivedUuid(operationId, "intent"),
    resourceId: `prooftoact-fresh-recovery-${operationId}`
  });
}

function spendValues(request) {
  return [
    request.tenantId,
    request.operationId,
    request.requestDigest,
    JSON.stringify(request.requestPayload),
    request.proposalDigest,
    request.logicalActionDigest,
    request.selectedEvidenceDigest,
    request.runId,
    request.incidentId,
    request.resourceId,
    request.agentId,
    request.agency,
    request.evidenceId,
    request.effectKey,
    JSON.stringify(request.payload),
    request.payloadDigest,
    request.policyVersion,
    request.leaseMs
  ];
}

async function withClient(connectionString, operation) {
  const client = new Client({
    application_name: "prooftoact-fresh-recovery-source",
    connectionString,
    connectionTimeoutMillis: 10_000,
    query_timeout: 20_000,
    statement_timeout: 20_000
  });
  try {
    await client.connect();
    return await operation(client);
  } finally {
    await client.end().catch(() => {});
  }
}

function defaultDependencies(adminConnectionString, credentialBundle) {
  const authorizerUrl = connectionStringForUser(
    adminConnectionString,
    "tp_authorizer_user",
    credentialBundle.passwords.tp_authorizer_user
  );
  return Object.freeze({
    authorizeProposal: (store, request, options) =>
      authorizeSyntheticProposal(store, request, {
        ...options,
        proposalAuthorizer: (input) => withClient(
          authorizerUrl,
          (client) => authorizeDviProposalWithClient(client, input)
        )
      }),
    createSigner: createSyntheticEvidenceSigner,
    createStore: () => new AuthorityStore({
      connectionString: adminConnectionString,
      databaseName: "tideproof",
      maxConnections: 2
    }),
    spendAuthority: (request) => withClient(authorizerUrl, async (client) => {
      await client.query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE");
      try {
        const result = await client.query(SPEND_AUTHORITY_SQL,
          spendValues(request));
        await client.query("COMMIT");
        return result;
      } catch (cause) {
        await client.query("ROLLBACK").catch(() => {});
        throw cause;
      }
    })
  });
}

function validateDependencies(value) {
  const expected = [
    "authorizeProposal", "createSigner", "createStore", "spendAuthority"
  ];
  requireCondition(exactKeys(value, expected) && expected.every((name) =>
    typeof value[name] === "function"),
  "FRESH_RECOVERY_SOURCE_DEPENDENCIES_REJECTED");
  return value;
}

export async function produceFreshRecoverySource({
  adminConnectionString,
  clock = Date.now,
  credentialBundle,
  dependencies,
  operationId,
  sourceCommit,
  treeDigest
}) {
  requireCondition(typeof adminConnectionString === "string" &&
    adminConnectionString.length > 0 && plainObject(credentialBundle) &&
    plainObject(credentialBundle.passwords) && UUID.test(operationId ?? "") &&
    HEX_40.test(sourceCommit ?? "") && HEX_40.test(treeDigest ?? "") &&
    typeof clock === "function",
  "FRESH_RECOVERY_SOURCE_CONFIGURATION_REJECTED");
  const resolved = validateDependencies(dependencies ??
    defaultDependencies(adminConnectionString, credentialBundle));
  const identity = freshRecoverySourceIdentity(operationId);
  const now = clock();
  requireCondition(Number.isFinite(now), "FRESH_RECOVERY_SOURCE_CLOCK_REJECTED");
  const observedAt = new Date(now - 60_000).toISOString();
  const validFrom = new Date(now - 120_000).toISOString();
  const validUntil = new Date(now + 30 * 60_000).toISOString();
  const admittedAt = new Date(now - 1_000).toISOString();
  const expiresAt = new Date(now + 5 * 60_000).toISOString();
  const store = resolved.createStore();
  requireCondition(store && [
    "appendSignedEvidence", "close", "prepareResource",
    "recordDviSelectionReceiptForTest", "registerVerificationKey",
    "verificationSnapshot"
  ].every((name) => typeof store[name] === "function"),
  "FRESH_RECOVERY_SOURCE_STORE_REJECTED");
  try {
    const signer = resolved.createSigner();
    requireCondition(signer && typeof signer.register === "function" &&
      typeof signer.append === "function",
    "FRESH_RECOVERY_SOURCE_SIGNER_REJECTED");
    const registered = await signer.register(store, identity.tenantId);
    requireCondition(["verification_key_registered", "verification_key_replay"]
      .includes(registered?.outcome),
    "FRESH_RECOVERY_SOURCE_KEY_REJECTED");
    const evidence = await signer.append(store, {
      tenantId: identity.tenantId,
      evidenceId: identity.evidenceId,
      incidentId: identity.incidentId,
      agencyScope: "rescue",
      claimKey: "rescue_unit_status",
      claimValue: "available",
      observedAt,
      validFrom,
      validUntil,
      conflictStatus: "none",
      assertion: "Synthetic exact-source fresh recovery fixture.",
      embedding: [0.78, 0.14, 0.08]
    });
    requireCondition(["evidence_verified", "evidence_verification_replay"]
      .includes(evidence?.outcome),
    "FRESH_RECOVERY_SOURCE_EVIDENCE_REJECTED");
    const snapshot = await store.verificationSnapshot({
      tenantId: identity.tenantId,
      evidenceId: identity.evidenceId
    });
    const evidenceDigest = snapshot?.evidence?.evidence_digest;
    requireCondition(snapshot?.verification?.outcome === "verified" &&
      HEX_64.test(evidenceDigest ?? ""),
    "FRESH_RECOVERY_SOURCE_EVIDENCE_READBACK_REJECTED");
    await store.prepareResource(identity);
    const request = {
      ...identity,
      operationId,
      agentId: "prooftoact-fresh-recovery-producer",
      agency: "rescue",
      leaseMs: 300_000,
      payload: {
        action: "dispatch_rescue_unit",
        destination: "synthetic-zone-fresh-recovery",
        scenario: "synthetic-highwater"
      }
    };
    const authorization = await resolved.authorizeProposal(store, request, {
      admittedAt,
      evidenceDigest,
      expiresAt,
      retrievalId: identity.retrievalId,
      sourceCommit,
      treeDigest
    });
    requireCondition(authorization?.authorization?.outcome ===
        "proposal_authorized" &&
      plainObject(authorization.dviAuthorization),
    "FRESH_RECOVERY_SOURCE_DVI_REJECTED");
    const normalized = normalizedAuthorityRequestFor({
      ...request,
      dviAuthorization: authorization.dviAuthorization
    });
    const spent = await resolved.spendAuthority(normalized);
    const row = spent?.rows?.[0];
    requireCondition(spent?.rowCount === 1 &&
      row?.decision_outcome === "resource_reserved" &&
      String(row.decision_fencing_token) === "1" &&
      HEX_64.test(row.decision_authorization_binding_sha256 ?? "") &&
      HEX_64.test(row.decision_logical_authority_key_sha256 ?? ""),
    "FRESH_RECOVERY_SOURCE_AUTHORITY_REJECTED");
    const authorityEvidenceBindingSha256 = authorization.dviAuthorization
      .dviProposal.authorityEvidenceBindingSha256;
    const selectedEvidenceBindingSha256 = sha256(canonicalJson({
      evidenceId: identity.evidenceId,
      evidenceDigest
    }));
    const sourceBinding = Object.freeze({
      authorityEvidenceBindingSha256,
      evidenceId: identity.evidenceId,
      incidentId: identity.incidentId,
      operationId,
      requestDigest: normalized.requestDigest,
      resourceId: identity.resourceId,
      runId: identity.runId,
      selectedEvidenceBindingSha256,
      tenantId: identity.tenantId
    });
    return Object.freeze({
      schemaVersion: "prooftoact.fresh-recovery-source-receipt.v1",
      status: "PASS",
      operationId,
      sourceCommit,
      treeDigest,
      authorityOutcome: row.decision_outcome,
      dviPolicyVersion: "g1-admissibility-v2",
      durableAuthorityReceipt: true,
      evidenceDigest,
      evidenceVerified: true,
      sourceBinding,
      sourceBindingSha256: sha256(`${canonicalJson(sourceBinding)}\n`)
    });
  } finally {
    await store.close().catch(() => {});
  }
}

export const __test = Object.freeze({
  SPEND_AUTHORITY_SQL,
  canonicalJson,
  derivedUuid,
  sha256,
  spendValues
});
