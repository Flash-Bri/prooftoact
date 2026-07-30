import { randomUUID } from "node:crypto";
import { Client } from "pg";
import { connectionStringForDatabase } from "../src/cloud/authority-store.js";
import {
  assertSeparatedDatabaseEndpoints,
  principalBindingHash
} from "../src/cloud/recovery-broker.js";
import {
  bootstrapRecoverySecurity,
  connectionStringForRecoveryUser,
  RecoveryPublisher
} from "../src/cloud/recovery-security.js";
import {
  createRecoveryDatabase,
  recoveryQueryTemplateDigest,
  RecoveryStore,
  renderRecoveryQuery
} from "../src/cloud/recovery-store.js";
import { createSyntheticRecoverySigner } from "./lib/synthetic-recovery-signer.js";

const SYNTHETIC_PRINCIPAL = "principal://tideproof-demo-successor";

function requiredEnvironment(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is required`);
  }
  return value;
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(`Gate One recovery invariant failed: ${message}`);
  }
}

async function latestSyntheticReceipt(connectionString) {
  const client = new Client({
    connectionString: connectionStringForDatabase(connectionString, "tideproof")
  });
  try {
    await client.connect();
    await client.query(
      "BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE READ ONLY"
    );
    const result = await client.query(`
      SELECT
        receipt.tenant_id,
        receipt.incident_id,
        receipt.evidence_id,
        receipt.recorded_at,
        receipt.request_digest,
        receipt.policy_version,
        receipt.agent_id,
        receipt.agency,
        receipt.outcome,
        receipt.reason,
        receipt.evidence_digest,
        receipt.resource_id,
        outbox.intent_id IS NOT NULL AS has_durable_intent,
        verification.outcome AS verification_outcome,
        verification.public_key_digest,
        evidence.evidence_digest AS current_evidence_digest
      FROM tp_ledger.g1_authority_receipts AS receipt
      JOIN tp_private.g1_evidence AS evidence
        ON evidence.tenant_id = receipt.tenant_id
       AND evidence.evidence_id = receipt.evidence_id
      JOIN tp_ledger.g1_evidence_verification_receipts AS verification
        ON verification.tenant_id = evidence.tenant_id
       AND verification.evidence_id = evidence.evidence_id
      LEFT JOIN tp_ledger.g1_outbox_intents AS outbox
        ON outbox.tenant_id = receipt.tenant_id
       AND outbox.operation_id = receipt.operation_id
      WHERE receipt.outcome = 'resource_reserved'
        AND receipt.recorded_at >
          transaction_timestamp() - INTERVAL '45 minutes'
      ORDER BY receipt.recorded_at DESC
      LIMIT 1
    `);
    if (result.rowCount !== 1) {
      throw new Error("no fresh committed synthetic authority receipt exists");
    }
    const receipt = result.rows[0];
    const observed = await client.query(
      `
        SELECT *
        FROM tp_api.g1_observe_admissibility_v2(
          $1::UUID, $2::UUID, $3::UUID, $4
        )
      `,
      [
        receipt.tenant_id,
        receipt.evidence_id,
        receipt.incident_id,
        receipt.agency
      ]
    );
    await client.query("COMMIT");
    const admissible = observed.rows.filter(
      (row) => row.admissibility === "admissible"
    );
    const conflicted = observed.rows.filter(
      (row) => row.admissibility === "conflicted"
    );
    assert(
      receipt.verification_outcome === "verified" &&
        receipt.public_key_digest &&
        receipt.evidence_digest === receipt.current_evidence_digest,
      "source receipt is not bound to currently verified evidence"
    );
    assert(admissible.length === 1, "source evidence is not admissible");
    assert(conflicted.length === 0, "source evidence has an unresolved conflict");
    return {
      ...receipt,
      admittedCount: admissible.length,
      unresolvedCount: conflicted.length
    };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    await client.end().catch(() => {});
  }
}

async function expectPublisherBaseReadDenied(connectionString) {
  const client = new Client({ connectionString });
  try {
    await client.connect();
    try {
      await client.query(
        "SELECT * FROM mcp_private.recovery_bundles_v2 LIMIT 1"
      );
    } catch (error) {
      if (error.code === "42501") {
        return { denied: true, sqlstate: error.code };
      }
      throw error;
    }
    throw new Error("publisher unexpectedly read the base recovery table");
  } finally {
    await client.end().catch(() => {});
  }
}

async function main() {
  const primaryUrl = requiredEnvironment("PRIMARY_DATABASE_URL");
  const recoveryUrl = requiredEnvironment("RECOVERY_DATABASE_URL");
  const publisherPassword = requiredEnvironment(
    "RECOVERY_PUBLISHER_PASSWORD"
  );
  const primaryClusterId = requiredEnvironment("PRIMARY_CLUSTER_ID");
  const recoveryClusterId = requiredEnvironment("RECOVERY_CLUSTER_ID");
  const endpointSeparation = assertSeparatedDatabaseEndpoints({
    primaryConnectionString: primaryUrl,
    recoveryConnectionString: recoveryUrl,
    expectedPrimaryHostname: requiredEnvironment("EXPECTED_PRIMARY_HOSTNAME"),
    expectedRecoveryHostname: requiredEnvironment("EXPECTED_RECOVERY_HOSTNAME"),
    primaryClusterId,
    recoveryClusterId
  });
  const receipt = await latestSyntheticReceipt(primaryUrl);
  const recoverySessionId =
    process.env.RECOVERY_SESSION_ID?.trim() || randomUUID();
  const sourceCommitMs = Date.parse(receipt.recorded_at);
  const snapshotVersion = Number(
    process.env.SNAPSHOT_VERSION ?? String(Math.max(1, sourceCommitMs))
  );
  const subjectBindingHash = principalBindingHash(SYNTHETIC_PRINCIPAL);
  const signer = createSyntheticRecoverySigner();

  await createRecoveryDatabase(recoveryUrl);
  const store = new RecoveryStore({ connectionString: recoveryUrl });
  try {
    await store.migrate();
    const security = await bootstrapRecoverySecurity({
      adminConnectionString: recoveryUrl,
      publisherPassword
    });
    const publisherConnectionString = connectionStringForRecoveryUser(
      recoveryUrl,
      "tp_recovery_publisher_user",
      publisherPassword
    );
    const publisher = new RecoveryPublisher({
      connectionString: publisherConnectionString
    });
    const bundle = signer.sign({
      tenantId: receipt.tenant_id,
      recoverySessionId,
      subjectBindingHash,
      schemaVersion: 2,
      snapshotVersion,
      sourceClusterId: primaryClusterId,
      sourceCommitTs: new Date(sourceCommitMs).toISOString(),
      sourceDigest: receipt.request_digest,
      policyVersion: receipt.policy_version,
      checkpointSummary: {
        checkpointVersion: 1,
        failedAgent: receipt.agent_id,
        phase: "successor-context-recovery",
        scenario: "synthetic-highwater"
      },
      evidenceSummary: {
        admittedCount: receipt.admittedCount,
        classification: "synthetic",
        evidenceDigest: receipt.evidence_digest
      },
      conflictSummary: {
        unresolvedCount: receipt.unresolvedCount,
        status: receipt.unresolvedCount === 0 ? "none" : "quarantined"
      },
      receiptSummary: {
        durableIntentPresent: receipt.has_durable_intent,
        outcome: receipt.outcome,
        reason: receipt.reason,
        resourceLabel: receipt.resource_id
      },
      expiresAt: new Date(
        Math.min(
          sourceCommitMs + 24 * 60 * 60 * 1_000,
          Date.now() + 30 * 60 * 1_000
        )
      ).toISOString()
    });

    const appended = await publisher.appendSignedBundle(bundle);
    const replay = await publisher.appendSignedBundle(bundle);
    const recovered = await store.readLatest({
      tenantId: receipt.tenant_id,
      recoverySessionId,
      subjectBindingHash,
      expectedSourceClusterId: primaryClusterId,
      trustedPublisherKeys: {
        [signer.publisherKeyId]: signer.publicKeySpkiBase64
      }
    });
    const publisherBaseRead = await expectPublisherBaseReadDenied(
      publisherConnectionString
    );

    assert(
      ["bundle_appended", "bundle_replay"].includes(appended.outcome),
      "bundle append did not return a terminal outcome"
    );
    assert(replay.outcome === "bundle_replay", "bundle replay was not idempotent");
    assert(
      recovered.status === "RECOVERED_CONTEXT_ONLY",
      "recovery did not return context-only state"
    );
    assert(
      recovered.authorityTransferred === false,
      "recovery transferred authority"
    );
    assert(
      recovered.requiresFreshAuthorization === true,
      "recovery omitted fresh-authorization requirement"
    );

    console.log(
      JSON.stringify(
        {
          gate: "CockroachDB signed isolated recovery bundle",
          passed: true,
          database: "tideproof_recovery",
          endpointSeparation: {
            distinctHostnames:
              endpointSeparation.primaryHostname !==
              endpointSeparation.recoveryHostname,
            distinctClusterIds:
              endpointSeparation.primaryClusterId !==
              endpointSeparation.recoveryClusterId
          },
          recoverySessionId,
          tenantBound: recovered.tenantId === receipt.tenant_id,
          subjectBound: recovered.subjectBindingHash === subjectBindingHash,
          publisherRoles: security.roles,
          publisherBaseRead,
          appendOutcome: appended.outcome,
          replayOutcome: replay.outcome,
          queryTemplateDigest: recoveryQueryTemplateDigest(),
          fixedQuery: renderRecoveryQuery({
            tenantId: receipt.tenant_id,
            recoverySessionId,
            subjectBindingHash
          }),
          recoveryStatus: recovered.status,
          sourceDigest: recovered.sourceDigest,
          bundleDigest: recovered.bundleDigest,
          signatureAlgorithm: bundle.signatureAlgorithm,
          sourceFacts: {
            admittedCount: receipt.admittedCount,
            unresolvedCount: receipt.unresolvedCount,
            durableIntentPresent: receipt.has_durable_intent
          },
          authorityTransferred: recovered.authorityTransferred,
          requiresFreshAuthorization: recovered.requiresFreshAuthorization,
          claimBoundary:
            "This proves signed, principal-bound, isolated recovery publication and direct validation through a least-privilege publisher. Noninteractive Managed MCP broker execution and primary audit are separate evidence gates."
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
      gate: "CockroachDB signed isolated recovery bundle",
      passed: false,
      name: error.name,
      code: error.code,
      message: error.message
    })
  );
  process.exitCode = 1;
});
