import { createHash, randomUUID } from "node:crypto";
import { Client } from "pg";
import { connectionStringForDatabase } from "../src/cloud/authority-store.js";
import { runtimeDatabaseConfig } from "../src/cloud/database-runtime.js";
import {
  assertSeparatedDatabaseEndpoints,
  DeterministicRecoveryBroker,
  principalBindingHash,
  RecoveryAuditSink,
  recoveryAuditEventDigest,
  recoveryBrokerConfigDigest,
  resolveCommittedRecoveryPublisherTrustRoot,
  trustedPublisherKeysDigest
} from "../src/cloud/recovery-broker.js";
import { CockroachManagedMcpRecoveryClient } from "../src/cloud/managed-mcp-client.js";
import { RecoveryPublisher } from "../src/cloud/recovery-security.js";
import {
  recoveryQueryTemplateDigest,
  recoverySourceBindingDigestFor
} from "../src/cloud/recovery-store.js";
import { loadCommittedRecoveryPublisherSigner } from "./lib/recovery-publisher-key.js";

const SYNTHETIC_PRINCIPAL = "principal://tideproof-demo-successor";
const UNAUTHORIZED_PRINCIPAL = "principal://tideproof-demo-unbound";

function requiredEnvironment(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is required`);
  }
  return value;
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(`Gate One recovery broker invariant failed: ${message}`);
  }
}

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, nested]) => `${JSON.stringify(key)}:${canonicalJson(nested)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
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

async function exactSyntheticReceipt(connectionString, binding) {
  const client = new Client(runtimeDatabaseConfig({
    connectionString: connectionStringForDatabase(connectionString, "tideproof"),
    max: 1,
    applicationName: "tideproof-recovery-broker-source"
  }));
  try {
    await client.connect();
    await client.query(
      "BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE READ ONLY"
    );
    const result = await client.query(`
      SELECT
        receipt.tenant_id,
        receipt.run_id,
        receipt.incident_id,
        receipt.evidence_id,
        receipt.operation_id,
        receipt.recorded_at,
        receipt.request_digest,
        receipt.proposal_digest,
        receipt.logical_action_digest,
        receipt.authorization_epoch,
        receipt.logical_authority_key_sha256,
        receipt.authorization_binding_sha256,
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
      WHERE receipt.tenant_id = $1::UUID
        AND receipt.run_id = $2::UUID
        AND receipt.incident_id = $3::UUID
        AND receipt.evidence_id = $4::UUID
        AND receipt.resource_id = $5
        AND receipt.operation_id = $6::UUID
        AND receipt.request_digest = $7
        AND receipt.outcome = 'resource_reserved'
        AND receipt.recorded_at >
          transaction_timestamp() - INTERVAL '50 minutes'
    `, [
      binding.tenantId,
      binding.runId,
      binding.incidentId,
      binding.evidenceId,
      binding.resourceId,
      binding.operationId,
      binding.requestDigest
    ]);
    assert(result.rowCount === 1, "fresh signed authority receipt is absent");
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
    const admittedCount = observed.rows.filter(
      (row) => row.admissibility === "admissible"
    ).length;
    const unresolvedCount = observed.rows.filter(
      (row) => row.admissibility === "conflicted"
    ).length;
    assert(
      receipt.verification_outcome === "verified" &&
        receipt.public_key_digest &&
        receipt.evidence_digest === receipt.current_evidence_digest,
      "source receipt is not bound to currently verified evidence"
    );
    assert(admittedCount === 1, "source evidence is not currently admissible");
    assert(unresolvedCount === 0, "source evidence has an unresolved conflict");
    assert(receipt.has_durable_intent, "source receipt lacks a durable intent");
    return { ...receipt, admittedCount, unresolvedCount };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    await client.end().catch(() => {});
  }
}

async function readAuditEvents({
  connectionString,
  tenantId,
  interactionId
}) {
  const client = new Client(runtimeDatabaseConfig({
    connectionString: connectionStringForDatabase(connectionString, "tideproof"),
    max: 1,
    applicationName: "tideproof-recovery-broker-audit"
  }));
  try {
    await client.connect();
    const result = await client.query(
      `
        SELECT
          tenant_id,
          event_id,
          interaction_id,
          recovery_session_id,
          caller_subject_hash,
          phase,
          tool_name,
          recovery_cluster_id,
          broker_config_digest,
          query_template_digest,
          bound_input_digest,
          result_digest,
          source_watermark,
          outcome,
          error_code,
          event_digest,
          started_at,
          completed_at
        FROM tp_ledger.g1_recovery_audit_events_v3
        WHERE tenant_id = $1::UUID
          AND interaction_id = $2::UUID
        ORDER BY phase
      `,
      [tenantId, interactionId]
    );
    assert(
      result.rowCount === 2,
      "primary pre-read and terminal audit events were not both committed"
    );
    return result.rows;
  } finally {
    await client.end().catch(() => {});
  }
}

async function main() {
  const primaryUrl = requiredEnvironment("PRIMARY_DATABASE_URL");
  const recoveryPublisherUrl = requiredEnvironment(
    "RECOVERY_PUBLISHER_DATABASE_URL"
  );
  const primaryAuditUrl = requiredEnvironment("PRIMARY_AUDIT_DATABASE_URL");
  const primaryClusterId = requiredEnvironment("PRIMARY_CLUSTER_ID");
  const recoveryClusterId = requiredEnvironment("RECOVERY_CLUSTER_ID");
  const mcpApiKey = requiredEnvironment("MCP_API_KEY");
  const sourceBuildIdentity = requiredEnvironment("SOURCE_BUILD_IDENTITY");

  const endpointSeparation = assertSeparatedDatabaseEndpoints({
    primaryConnectionString: primaryUrl,
    recoveryConnectionString: recoveryPublisherUrl,
    expectedPrimaryHostname: requiredEnvironment("EXPECTED_PRIMARY_HOSTNAME"),
    expectedRecoveryHostname: requiredEnvironment("EXPECTED_RECOVERY_HOSTNAME"),
    primaryClusterId,
    recoveryClusterId
  });
  const receipt = await exactSyntheticReceipt(
    primaryUrl,
    exactSourceBinding()
  );
  const recoverySessionId = randomUUID();
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
  const sourceCommitMs = new Date(receipt.recorded_at).getTime();
  assert(
    Number.isFinite(sourceCommitMs),
    "source receipt timestamp could not be normalized"
  );
  const bundle = signer.sign({
    tenantId: receipt.tenant_id,
    recoverySessionId,
    subjectBindingHash,
    schemaVersion: 2,
    snapshotVersion: Math.max(1, Date.now()),
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
      status: "none"
    },
    receiptSummary: {
      durableIntentPresent: true,
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

  const publisher = new RecoveryPublisher({
    connectionString: recoveryPublisherUrl
  });
  const appended = await publisher.appendSignedBundle(bundle);
  const replay = await publisher.appendSignedBundle(bundle);
  assert(
    ["bundle_appended", "bundle_replay"].includes(appended.outcome),
    "signed recovery bundle did not reach a terminal append outcome"
  );
  assert(replay.outcome === "bundle_replay", "bundle replay was not idempotent");

  const rawMcpClient = new CockroachManagedMcpRecoveryClient({
    apiKey: mcpApiKey,
    clusterId: recoveryClusterId
  });
  let mcpCallCount = 0;
  let capturedMcpResult = null;
  const meteredMcpClient = {
    async selectQuery(input) {
      mcpCallCount += 1;
      capturedMcpResult = await rawMcpClient.selectQuery(input);
      return capturedMcpResult;
    }
  };
  const broker = new DeterministicRecoveryBroker({
    buildIdentity: sourceBuildIdentity,
    recoveryClusterId,
    expectedSourceClusterId: primaryClusterId,
    trustedPublisherKeys: signer.trustedPublisherKeys,
    mcpClient: meteredMcpClient,
    sessionResolver: {
      async resolve({ authenticatedPrincipal }) {
        if (authenticatedPrincipal !== SYNTHETIC_PRINCIPAL) {
          throw new Error("RECOVERY_SESSION_NOT_BOUND");
        }
        return {
          tenantId: receipt.tenant_id,
          recoverySessionId,
          subjectBindingHash,
          sourceDigest
        };
      }
    },
    auditSink: new RecoveryAuditSink({
      connectionString: primaryAuditUrl
    })
  });

  let recovered;
  let unauthorized;
  try {
    recovered = await broker.recover({
      authenticatedPrincipal: SYNTHETIC_PRINCIPAL
    });
    unauthorized = await broker.recover({
      authenticatedPrincipal: UNAUTHORIZED_PRINCIPAL
    });
  } finally {
    await rawMcpClient.close();
  }

  assert(
    recovered.status === "RECOVERED_CONTEXT_ONLY",
    "broker did not release verified context-only recovery"
  );
  assert(
    recovered.authorityTransferred === false &&
      recovered.requiresFreshAuthorization === true,
    "broker violated the successor authority boundary"
  );
  assert(
    recovered.sourceDigest === sourceDigest,
    "broker released context outside the exact cross-act source binding"
  );
  assert(
    unauthorized.status === "UNKNOWN_DO_NOT_ACT",
    "unbound principal did not fail closed"
  );
  assert(mcpCallCount === 1, "unbound principal reached Managed MCP");
  assert(
    !("fencingToken" in recovered) &&
      !("operationId" in recovered) &&
      !("effectKey" in recovered),
    "recovery response leaked an operational capability"
  );

  const auditEvents = await readAuditEvents({
    connectionString: primaryUrl,
    tenantId: receipt.tenant_id,
    interactionId: recovered.auditInteractionId
  });
  const preReadAudit = auditEvents.find(({ phase }) => phase === "pre_read");
  const terminalAudit = auditEvents.find(({ phase }) => phase === "terminal");
  const expectedBrokerDigest = recoveryBrokerConfigDigest({
    recoveryClusterId,
    expectedSourceClusterId: primaryClusterId,
    buildIdentity: sourceBuildIdentity,
    trustedPublisherKeys: signer.trustedPublisherKeys
  });
  const expectedBoundInputDigest = sha256(
    canonicalJson({
      tenantId: receipt.tenant_id,
      recoverySessionId,
      subjectBindingHash,
      sourceDigest
    })
  );
  const mcpRows = JSON.parse(capturedMcpResult.content[0].text).rows;
  assert(mcpRows.length === 1, "captured MCP result did not contain one row");
  const expectedResultDigest = sha256(canonicalJson(mcpRows[0]));
  const expectedAuditCommon = (event) =>
    event.tenant_id === receipt.tenant_id &&
    event.interaction_id === recovered.auditInteractionId &&
    event.recovery_session_id === recoverySessionId &&
    event.caller_subject_hash === subjectBindingHash &&
    event.tool_name === "select_query" &&
    event.recovery_cluster_id === recoveryClusterId &&
    event.broker_config_digest === expectedBrokerDigest &&
    event.query_template_digest === recoveryQueryTemplateDigest() &&
    event.bound_input_digest === expectedBoundInputDigest;
  assert(
    expectedAuditCommon(preReadAudit) &&
      preReadAudit.event_id === recovered.preReadAuditId &&
      preReadAudit.result_digest === null &&
      preReadAudit.source_watermark === null &&
      preReadAudit.outcome === "read_authorized" &&
      preReadAudit.error_code === null,
    "pre-read audit did not authorize the exact broker input"
  );
  const terminalChecks = {
    common: expectedAuditCommon(terminalAudit),
    eventId: terminalAudit.event_id === recovered.auditId,
    resultDigest: terminalAudit.result_digest === expectedResultDigest,
    sourceWatermark:
      new Date(terminalAudit.source_watermark).toISOString() ===
      new Date(receipt.recorded_at).toISOString(),
    outcome: terminalAudit.outcome === "recovered_context_only",
    errorCode: terminalAudit.error_code === null
  };
  assert(
    Object.values(terminalChecks).every(Boolean),
    `terminal audit did not bind the exact released result (${Object.entries(
      terminalChecks
    )
      .filter(([, passed]) => !passed)
      .map(([name]) => name)
      .join(",")})`
  );
  for (const event of auditEvents) {
    assert(
      event.event_digest ===
        recoveryAuditEventDigest({
          eventId: event.event_id,
          tenantId: event.tenant_id,
          interactionId: event.interaction_id,
          recoverySessionId: event.recovery_session_id,
          callerSubjectHash: event.caller_subject_hash,
          phase: event.phase,
          recoveryClusterId: event.recovery_cluster_id,
          brokerConfigDigest: event.broker_config_digest,
          queryTemplateDigest: event.query_template_digest,
          boundInputDigest: event.bound_input_digest,
          resultDigest: event.result_digest,
          sourceWatermark: event.source_watermark,
          outcome: event.outcome,
          errorCode: event.error_code,
          startedAt: event.started_at,
          completedAt: event.completed_at
        }),
      `${event.phase} audit event digest did not match`
    );
  }

  console.log(
    JSON.stringify(
      {
        gate: "noninteractive Managed MCP deterministic recovery broker",
        passed: true,
        endpointSeparation: {
          distinctHostnames:
            endpointSeparation.primaryHostname !==
            endpointSeparation.recoveryHostname,
          distinctClusterIds:
            endpointSeparation.primaryClusterId !==
            endpointSeparation.recoveryClusterId
        },
        recoverySessionId,
        tenantId: receipt.tenant_id,
        appendOutcome: appended.outcome,
        replayOutcome: replay.outcome,
        mcpTool: "select_query",
        mcpCallCount,
        queryTemplateDigest: recoveryQueryTemplateDigest(),
        brokerConfigDigest: expectedBrokerDigest,
        sourceBuildIdentity,
        publisherKeySetDigest,
        publisherTrustRootCommitment: signer.trustRootCommitment,
        publisherTrustRootCommittedAt:
          committedPublisherTrustRoot.committedAt,
        recoveryStatus: recovered.status,
        unauthorizedStatus: unauthorized.status,
        sourceDigest: recovered.sourceDigest,
        bundleDigest: recovered.bundleDigest,
        auditInteractionId: recovered.auditInteractionId,
        preReadAuditId: recovered.preReadAuditId,
        terminalAuditId: recovered.auditId,
        preReadAuditCommitted: true,
        terminalAuditCommitted: true,
        boundInputDigest: expectedBoundInputDigest,
        resultDigest: expectedResultDigest,
        authorityTransferred: recovered.authorityTransferred,
        requiresFreshAuthorization: recovered.requiresFreshAuthorization,
        operationalCapabilitiesReturned: false,
        claimBoundary:
          "This proves a noninteractive, cluster-scoped Managed MCP read through a deterministic fixed query bound to the exact tenant, run, incident, evidence, resource, operation, request digest, outcome, and successor principal; signed context validation; context-only recovery; and a separate primary-cluster audit receipt. It does not transfer authority, satisfy the 100-drill batch, or prove a real-world external effect."
      },
      null,
      2
    )
  );
}

main().catch((error) => {
  console.error(
    JSON.stringify({
      gate: "noninteractive Managed MCP deterministic recovery broker",
      passed: false,
      name: error.name,
      code: error.code,
      message: error.message
    })
  );
  process.exitCode = 1;
});
