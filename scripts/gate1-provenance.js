import { randomUUID } from "node:crypto";
import {
  AuthorityStore,
  EvidenceVerificationMismatchError
} from "../src/cloud/authority-store.js";
import { createSyntheticEvidenceSigner } from "./lib/synthetic-evidence.js";

function requiredDatabaseUrl() {
  if (!process.env.DATABASE_URL) {
    throw new Error("DATABASE_URL is required");
  }
  return process.env.DATABASE_URL;
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function isoFromNow(offsetMs) {
  return new Date(Date.now() + offsetMs).toISOString();
}

function evidenceFor({
  tenantId = randomUUID(),
  evidenceId = randomUUID(),
  incidentId = randomUUID(),
  issuer = "synthetic-county-sensor",
  assertion = "Synthetic provenance fixture is admissible."
} = {}) {
  return {
    tenantId,
    evidenceId,
    incidentId,
    issuer,
    agencyScope: "rescue",
    claimKey: "rescue_unit_status",
    claimValue: "available",
    observedAt: isoFromNow(-60_000),
    validFrom: isoFromNow(-120_000),
    validUntil: isoFromNow(30 * 60_000),
    conflictStatus: "none",
    assertion,
    embedding: [0.81, 0.12, 0.07]
  };
}

function requestFor(evidence, resourceId, runId) {
  return {
    tenantId: evidence.tenantId,
    runId,
    incidentId: evidence.incidentId,
    resourceId,
    evidenceId: evidence.evidenceId,
    operationId: randomUUID(),
    agentId: "synthetic-provenance-agent",
    agency: "rescue",
    intentNonce: randomUUID(),
    effectKey: randomUUID(),
    leaseMs: 300_000,
    payload: {
      scenario: "synthetic-highwater",
      action: "dispatch_rescue_unit",
      destination: "synthetic-zone-provenance"
    }
  };
}

async function assertRejected(store, evidence, result, expectedReason) {
  assert(result.outcome === "evidence_rejected", "evidence was not rejected");
  assert(result.reason === expectedReason, `expected ${expectedReason}`);
  const snapshot = await store.verificationSnapshot(evidence);
  assert(
    snapshot.verification?.outcome === "rejected" &&
      snapshot.verification.reason === expectedReason,
    "rejection receipt was not durable"
  );
  assert(snapshot.evidence === null, "rejected evidence was partially admitted");
  return {
    case: expectedReason,
    outcome: result.outcome,
    durableReceipt: snapshot.verification.outcome,
    admittedEvidenceRows: 0
  };
}

async function main() {
  const store = new AuthorityStore({
    connectionString: requiredDatabaseUrl(),
    databaseName: "tideproof",
    maxConnections: 8
  });
  const signer = createSyntheticEvidenceSigner();
  try {
    await store.migrate();
    const validEvidence = evidenceFor();
    await signer.register(store, validEvidence.tenantId);
    const valid = await signer.append(store, validEvidence);
    const validSnapshot = await store.verificationSnapshot(validEvidence);
    assert(valid.outcome === "evidence_verified", "valid signature was rejected");
    assert(
      validSnapshot.verification?.outcome === "verified" &&
        validSnapshot.evidence !== null,
      "verified evidence was not atomically admitted"
    );

    const altered = evidenceFor();
    await signer.register(store, altered.tenantId);
    const originalSignature = signer.sign(altered);
    const alteredResult = await store.appendSignedEvidence({
      ...altered,
      assertion: `${altered.assertion} altered`,
      verificationKeyId: signer.verificationKeyId,
      verifierVersion: signer.verifierVersion,
      signatureBase64: originalSignature
    });

    const unknownKeyEvidence = evidenceFor();
    const unknownKeyResult = await store.appendSignedEvidence({
      ...unknownKeyEvidence,
      verificationKeyId: signer.verificationKeyId,
      verifierVersion: signer.verifierVersion,
      signatureBase64: signer.sign(unknownKeyEvidence)
    });

    const revokedEvidence = evidenceFor();
    await signer.register(store, revokedEvidence.tenantId);
    await store.revokeVerificationKey({
      tenantId: revokedEvidence.tenantId,
      verificationKeyId: signer.verificationKeyId
    });
    const revokedResult = await store.appendSignedEvidence({
      ...revokedEvidence,
      verificationKeyId: signer.verificationKeyId,
      verifierVersion: signer.verifierVersion,
      signatureBase64: signer.sign(revokedEvidence)
    });

    const wrongIssuerEvidence = evidenceFor({
      issuer: "synthetic-impostor-sensor"
    });
    await signer.register(store, wrongIssuerEvidence.tenantId);
    const wrongIssuerResult = await store.appendSignedEvidence({
      ...wrongIssuerEvidence,
      verificationKeyId: signer.verificationKeyId,
      verifierVersion: signer.verifierVersion,
      signatureBase64: signer.sign(wrongIssuerEvidence)
    });

    const badSignatureEvidence = evidenceFor();
    await signer.register(store, badSignatureEvidence.tenantId);
    const badSignatureResult = await store.appendSignedEvidence({
      ...badSignatureEvidence,
      verificationKeyId: signer.verificationKeyId,
      verifierVersion: signer.verifierVersion,
      signatureBase64: Buffer.alloc(64).toString("base64"),
      signatureValid: true
    });

    const rejections = [
      await assertRejected(
        store,
        altered,
        alteredResult,
        "signature_invalid"
      ),
      await assertRejected(
        store,
        unknownKeyEvidence,
        unknownKeyResult,
        "verification_key_unknown"
      ),
      await assertRejected(
        store,
        revokedEvidence,
        revokedResult,
        "verification_key_revoked"
      ),
      await assertRejected(
        store,
        wrongIssuerEvidence,
        wrongIssuerResult,
        "verification_issuer_mismatch"
      ),
      await assertRejected(
        store,
        badSignatureEvidence,
        badSignatureResult,
        "signature_invalid"
      )
    ];

    let changedEvidenceDenied = false;
    try {
      await store.appendSignedEvidence({
        ...badSignatureEvidence,
        assertion: `${badSignatureEvidence.assertion} changed`,
        verificationKeyId: signer.verificationKeyId,
        verifierVersion: signer.verifierVersion,
        signatureBase64: signer.sign({
          ...badSignatureEvidence,
          assertion: `${badSignatureEvidence.assertion} changed`
        })
      });
    } catch (error) {
      changedEvidenceDenied =
        error instanceof EvidenceVerificationMismatchError;
    }
    assert(
      changedEvidenceDenied,
      "evidence ID reuse with changed content was not denied"
    );

    const laterRevokedEvidence = evidenceFor();
    await signer.register(store, laterRevokedEvidence.tenantId);
    const initiallyVerified = await signer.append(store, laterRevokedEvidence);
    assert(
      initiallyVerified.outcome === "evidence_verified",
      "revocation fixture did not verify initially"
    );
    const runId = randomUUID();
    const resourceId = `gate1-provenance-${randomUUID()}`;
    await store.prepareResource({
      tenantId: laterRevokedEvidence.tenantId,
      runId,
      resourceId
    });
    await store.revokeVerificationKey({
      tenantId: laterRevokedEvidence.tenantId,
      verificationKeyId: signer.verificationKeyId
    });
    const revokedDecision = await store.spendAuthority(
      requestFor(laterRevokedEvidence, resourceId, runId)
    );
    const revokedSnapshot = await store.snapshot({
      tenantId: laterRevokedEvidence.tenantId,
      resourceId
    });
    assert(
      revokedDecision.outcome === "authorization_denied" &&
        revokedDecision.reason === "verification_key_revoked",
      "post-ingest key revocation did not deny authority"
    );
    assert(
      revokedSnapshot.resource.current_fence === "0" &&
        revokedSnapshot.outbox.length === 0,
      "revoked evidence changed authority state"
    );

    console.log(
      JSON.stringify(
        {
          gate: "signed-evidence-provenance",
          passed: true,
          algorithm: "ed25519",
          valid: {
            outcome: valid.outcome,
            durableReceipt: validSnapshot.verification.outcome,
            admittedEvidenceRows: 1
          },
          rejections,
          changedEvidenceIdReuseDenied: changedEvidenceDenied,
          postIngestRevocation: {
            outcome: revokedDecision.outcome,
            reason: revokedDecision.reason,
            fenceAfter: revokedSnapshot.resource.current_fence,
            outboxCount: revokedSnapshot.outbox.length
          },
          clientSignatureBooleanIgnored: true,
          invariantViolations: 0
        },
        null,
        2
      )
    );
  } finally {
    await store.close();
  }
}

main().catch((error) => {
  console.error(
    JSON.stringify({
      gate: "signed-evidence-provenance",
      passed: false,
      name: error.name,
      code: error.code,
      message: error.message
    })
  );
  process.exitCode = 1;
});
