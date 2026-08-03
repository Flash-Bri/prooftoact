import { randomUUID } from "node:crypto";
import { Client } from "pg";
import { runtimeDatabaseConfig } from "../src/cloud/database-runtime.js";
import {
  assertRecoveryPublisherTrustRootWriteDenied,
  assertSeparatedDatabaseEndpoints,
  principalBindingHash,
  resolveCommittedRecoveryPublisherTrustRoot,
  resolveCommittedRecoverySourceReceipt,
  trustedPublisherKeysDigest
} from "../src/cloud/recovery-broker.js";
import {
  bootstrapRecoverySecurity,
  connectionStringForRecoveryUser,
  RecoveryPublisher
} from "../src/cloud/recovery-security.js";
import {
  createRecoveryDatabase,
  recoverySourceBindingDigestFor,
  recoveryQueryTemplateDigest,
  RecoveryStore,
  renderRecoveryQuery
} from "../src/cloud/recovery-store.js";
import { loadCommittedRecoveryPublisherSigner } from "./lib/recovery-publisher-key.js";

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

function exactSourceBinding() {
  return {
    tenantId: requiredEnvironment("RECOVERY_SOURCE_TENANT_ID"),
    runId: requiredEnvironment("RECOVERY_SOURCE_RUN_ID"),
    incidentId: requiredEnvironment("RECOVERY_SOURCE_INCIDENT_ID"),
    evidenceId: requiredEnvironment("RECOVERY_SOURCE_EVIDENCE_ID"),
    resourceId: requiredEnvironment("RECOVERY_SOURCE_RESOURCE_ID"),
    operationId: requiredEnvironment("RECOVERY_SOURCE_OPERATION_ID"),
    requestDigest: requiredEnvironment("RECOVERY_SOURCE_REQUEST_DIGEST")
  };
}

async function expectPublisherBaseReadDenied(connectionString) {
  const client = new Client(runtimeDatabaseConfig({
    connectionString,
    max: 1,
    applicationName: "tideproof-recovery-publisher-probe"
  }));
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
  const primarySourceUrl = requiredEnvironment(
    "PRIMARY_RECOVERY_SOURCE_DATABASE_URL"
  );
  const primaryAuditUrl = requiredEnvironment("PRIMARY_AUDIT_DATABASE_URL");
  const recoveryUrl = requiredEnvironment("RECOVERY_DATABASE_URL");
  const publisherPassword = requiredEnvironment(
    "RECOVERY_PUBLISHER_PASSWORD"
  );
  const primaryClusterId = requiredEnvironment("PRIMARY_CLUSTER_ID");
  const recoveryClusterId = requiredEnvironment("RECOVERY_CLUSTER_ID");
  const endpointSeparation = assertSeparatedDatabaseEndpoints({
    primaryConnectionString: primarySourceUrl,
    recoveryConnectionString: recoveryUrl,
    expectedPrimaryHostname: requiredEnvironment("EXPECTED_PRIMARY_HOSTNAME"),
    expectedRecoveryHostname: requiredEnvironment("EXPECTED_RECOVERY_HOSTNAME"),
    primaryClusterId,
    recoveryClusterId
  });
  const [sourceTrustRootWrite, auditTrustRootWrite] = await Promise.all([
    assertRecoveryPublisherTrustRootWriteDenied({
      connectionString: primarySourceUrl,
      credentialLabel: "recovery-source"
    }),
    assertRecoveryPublisherTrustRootWriteDenied({
      connectionString: primaryAuditUrl,
      credentialLabel: "recovery-audit"
    })
  ]);
  const receipt = await resolveCommittedRecoverySourceReceipt({
    connectionString: primarySourceUrl,
    binding: exactSourceBinding()
  });
  const recoverySessionId =
    process.env.RECOVERY_SESSION_ID?.trim() || randomUUID();
  const sourceCommitMs = Date.parse(receipt.recorded_at);
  const snapshotVersion = Number(
    process.env.SNAPSHOT_VERSION ?? String(Math.max(1, sourceCommitMs))
  );
  const subjectBindingHash = principalBindingHash(SYNTHETIC_PRINCIPAL);
  const sourceDigest = recoverySourceBindingDigestFor({
    tenantId: receipt.tenant_id,
    runId: receipt.run_id,
    incidentId: receipt.incident_id,
    evidenceDigest: receipt.evidence_digest,
    resourceId: receipt.resource_id,
    operationId: receipt.operation_id,
    requestDigest: receipt.request_digest,
    proposalDigest: receipt.proposal_digest,
    logicalActionDigest: receipt.logical_action_digest,
    authorizationEpoch: Number(receipt.authorization_epoch),
    logicalAuthorityKeySha256: receipt.logical_authority_key_sha256,
    authorizationBindingSha256: receipt.authorization_binding_sha256,
    outcome: receipt.outcome
  });
  const signer = loadCommittedRecoveryPublisherSigner();
  const publisherKeySetDigest = trustedPublisherKeysDigest(
    signer.trustedPublisherKeys
  );
  const committedPublisherTrustRoot =
    await resolveCommittedRecoveryPublisherTrustRoot({
      connectionString: primaryAuditUrl,
      trustRootCommitment: signer.trustRootCommitment,
      publisherKeySetDigest
    });

  await createRecoveryDatabase(recoveryUrl);
  const security = await bootstrapRecoverySecurity({
    adminConnectionString: recoveryUrl,
    publisherPassword
  });
  const store = new RecoveryStore({ connectionString: recoveryUrl });
  try {
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
      sourceDigest,
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
    const recovered = await store.readExact({
      tenantId: receipt.tenant_id,
      recoverySessionId,
      subjectBindingHash,
      sourceDigest,
      expectedSourceClusterId: primaryClusterId,
      trustedPublisherKeys: signer.trustedPublisherKeys
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
    assert(
      recovered.sourceDigest === sourceDigest,
      "recovery selected context outside the exact cross-act source binding"
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
            subjectBindingHash,
            sourceDigest
          }),
          recoveryStatus: recovered.status,
          sourceDigest: recovered.sourceDigest,
          bundleDigest: recovered.bundleDigest,
          publisherTrustRootCommitment: signer.trustRootCommitment,
          publisherKeySetDigest,
          publisherTrustRootCommittedAt:
            committedPublisherTrustRoot.committedAt,
          runnerCredentialDenials: {
            sourceTrustRootWrite,
            auditTrustRootWrite
          },
          signatureAlgorithm: bundle.signatureAlgorithm,
          sourceFacts: {
            admittedCount: receipt.admittedCount,
            unresolvedCount: receipt.unresolvedCount,
            durableIntentPresent: receipt.has_durable_intent
          },
          authorityTransferred: recovered.authorityTransferred,
          requiresFreshAuthorization: recovered.requiresFreshAuthorization,
          claimBoundary:
            "This proves signed, principal-bound, exact-source recovery publication and direct validation through a least-privilege publisher. Noninteractive Managed MCP broker execution, the 100-drill batch, and primary audit are separate evidence gates."
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
