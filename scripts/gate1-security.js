import { createHash, randomUUID } from "node:crypto";
import { Client } from "pg";
import {
  AuthorityStore,
  normalizedAuthorityRequestFor
} from "../src/cloud/authority-store.js";
import {
  bootstrapPrimarySecurity,
  connectionStringForUser
} from "../src/cloud/primary-security.js";
import { SignedEvidenceIngest } from "../src/cloud/signed-ingest.js";
import { createSyntheticEvidenceSigner } from "./lib/synthetic-evidence.js";

const USERS = [
  "tp_ingest_user",
  "tp_authorizer_user",
  "tp_dispatch_user",
  "tp_recovery_audit_user",
  "tp_audit_user"
];

const SPEND_AUTHORITY_SQL = `
  SELECT *
  FROM tp_api.g1_spend_authority_v1(
    $1::UUID,
    $2::UUID,
    $3,
    $4::JSONB,
    $5::UUID,
    $6::UUID,
    $7,
    $8,
    $9,
    $10,
    $11::UUID,
    $12::UUID,
    $13::JSONB,
    $14,
    $15,
    $16::INT8
  )
`;

const OBSERVE_AUTHORITY_RACE_SQL = `
  SELECT *
  FROM tp_api.g1_observe_authority_race_v1(
    $1::UUID, $2::UUID, $3,
    $4::UUID, $5, $6::UUID, $7
  )
`;

function spendAuthorityValues(request, authenticatedAgentId) {
  return [
    request.tenantId,
    request.operationId,
    request.requestDigest,
    JSON.stringify(request.requestPayload),
    request.runId,
    request.incidentId,
    request.resourceId,
    request.agentId,
    authenticatedAgentId,
    request.agency,
    request.evidenceId,
    request.effectKey,
    JSON.stringify(request.payload),
    request.payloadDigest,
    request.policyVersion,
    request.leaseMs
  ];
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function requireEnvironment(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is required`);
  }
  return value;
}

async function withClient(connectionString, work) {
  const client = new Client({ connectionString });
  try {
    await client.connect();
    return await work(client);
  } finally {
    await client.end().catch(() => {});
  }
}

async function expectPrivilegeDenied(client, query, values = []) {
  try {
    await client.query(query, values);
  } catch (error) {
    if (error.code === "42501") {
      return { denied: true, sqlstate: error.code };
    }
    throw error;
  }
  throw new Error("expected SQLSTATE 42501 privilege denial");
}

async function main() {
  const adminConnectionString = requireEnvironment("DATABASE_URL");
  const passwords = Object.fromEntries(
    USERS.map((user) => [
      user,
      requireEnvironment(
        `TIDEPROOF_${user.toUpperCase()}_PASSWORD`
      )
    ])
  );
  const bootstrap = await bootstrapPrimarySecurity({
    adminConnectionString,
    passwords
  });

  const tenantId = randomUUID();
  const evidenceId = randomUUID();
  const incidentId = randomUUID();
  const observedAt = new Date(Date.now() - 60_000).toISOString();
  const validFrom = new Date(Date.now() - 120_000).toISOString();
  const validUntil = new Date(Date.now() + 30 * 60_000).toISOString();
  const signedPayloadDigest = sha256(
    JSON.stringify({ tenantId, evidenceId, incidentId, observedAt })
  );
  const evidenceDigest = sha256(
    JSON.stringify({
      syntheticCapabilityProbe: true,
      tenantId,
      evidenceId,
      incidentId
    })
  );

  const ingest = await withClient(
    connectionStringForUser(
      adminConnectionString,
      "tp_ingest_user",
      passwords.tp_ingest_user
    ),
    async (client) => {
      const directRead = await expectPrivilegeDenied(
        client,
        "SELECT * FROM tp_private.g1_evidence LIMIT 1"
      );
      const legacyFunctionDenied = await expectPrivilegeDenied(
        client,
        `
          SELECT tp_api.g1_append_verified_evidence_v1(
            $1::UUID,
            $2::UUID,
            $3::UUID,
            $4,
            $5,
            $6,
            $7,
            $8,
            $9,
            $10::TIMESTAMPTZ,
            $11::TIMESTAMPTZ,
            $12::TIMESTAMPTZ,
            $13,
            $14,
            $15
          ) AS evidence_id
        `,
        [
          tenantId,
          evidenceId,
          incidentId,
          "synthetic-capability-probe",
          "rescue",
          "gate1-synthetic-key-v1",
          "gate1-verifier-v1",
          signedPayloadDigest,
          evidenceDigest,
          observedAt,
          validFrom,
          validUntil,
          "none",
          "Synthetic capability-shaped ingest probe.",
          "[0.7,0.2,0.1]"
        ]
      );
      return {
        directRead,
        legacyFunctionDenied,
        failClosedUntilSignedIngestSurface: true
      };
    }
  );

  const authorityStore = new AuthorityStore({
    connectionString: adminConnectionString,
    databaseName: "tideproof",
    maxConnections: 4
  });
  const signer = createSyntheticEvidenceSigner();
  const signedIngestFixture = {
    tenantId: randomUUID(),
    evidenceId: randomUUID(),
    incidentId: randomUUID(),
    issuer: signer.issuer,
    agencyScope: "rescue",
    claimKey: "rescue_unit_status",
    claimValue: "available",
    observedAt,
    validFrom,
    validUntil,
    conflictStatus: "none",
    assertion: "Synthetic signed-ingest capability fixture.",
    embedding: [0.79, 0.13, 0.08]
  };
  await signer.register(authorityStore, signedIngestFixture.tenantId);
  const signedIngest = new SignedEvidenceIngest({
    connectionString: connectionStringForUser(
      adminConnectionString,
      "tp_ingest_user",
      passwords.tp_ingest_user
    )
  });
  const signedIngestResult = await signedIngest.appendVerified({
    ...signedIngestFixture,
    verificationKeyId: signer.verificationKeyId,
    verifierVersion: signer.verifierVersion,
    signatureBase64: signer.sign(signedIngestFixture)
  });
  const badSignatureFixture = {
    ...signedIngestFixture,
    evidenceId: randomUUID(),
    assertion: "Synthetic invalid-signature capability fixture."
  };
  let badSignatureRejected = false;
  try {
    await signedIngest.appendVerified({
      ...badSignatureFixture,
      verificationKeyId: signer.verificationKeyId,
      verifierVersion: signer.verifierVersion,
      signatureBase64: Buffer.alloc(64).toString("base64")
    });
  } catch (error) {
    badSignatureRejected = error.message === "SIGNATURE_INVALID";
  }
  await signedIngest.close();
  const signedIngestSnapshot = await authorityStore.verificationSnapshot(
    signedIngestFixture
  );
  const badSignatureSnapshot = await authorityStore.verificationSnapshot(
    badSignatureFixture
  );
  if (
    signedIngestResult.outcome !== "evidence_verified" ||
    signedIngestSnapshot.verification?.outcome !== "verified" ||
    signedIngestSnapshot.evidence === null ||
    !badSignatureRejected ||
    badSignatureSnapshot.verification !== null ||
    badSignatureSnapshot.evidence !== null
  ) {
    throw new Error("signed-ingest capability invariant failed");
  }
  ingest.signedSurfaceOutcome = signedIngestResult.outcome;
  ingest.badSignatureRejected = badSignatureRejected;
  ingest.badSignatureDurableRows = 0;
  ingest.failClosedUntilSignedIngestSurface = false;

  const authorityFixture = {
    tenantId: randomUUID(),
    runId: randomUUID(),
    incidentId: randomUUID(),
    evidenceId: randomUUID(),
    resourceId: `capability-resource-${randomUUID()}`
  };
  await signer.register(authorityStore, authorityFixture.tenantId);
  const verifiedEvidence = await signer.append(authorityStore, {
    tenantId: authorityFixture.tenantId,
    evidenceId: authorityFixture.evidenceId,
    incidentId: authorityFixture.incidentId,
    agencyScope: "rescue",
    claimKey: "rescue_unit_status",
    claimValue: "available",
    observedAt,
    validFrom,
    validUntil,
    conflictStatus: "none",
    assertion: "Synthetic least-privilege authority fixture.",
    embedding: [0.78, 0.14, 0.08]
  });
  if (verifiedEvidence.outcome !== "evidence_verified") {
    throw new Error("least-privilege evidence fixture did not verify");
  }
  await authorityStore.prepareResource(authorityFixture);
  const capabilityRequest = {
    tenantId: authorityFixture.tenantId,
    runId: authorityFixture.runId,
    incidentId: authorityFixture.incidentId,
    resourceId: authorityFixture.resourceId,
    evidenceId: authorityFixture.evidenceId,
    operationId: randomUUID(),
    agentId: "synthetic-capability-authorizer",
    agency: "rescue",
    intentNonce: randomUUID(),
    effectKey: randomUUID(),
    leaseMs: 300_000,
    payload: {
      scenario: "synthetic-highwater",
      action: "dispatch_rescue_unit",
      destination: "synthetic-zone-capability"
    }
  };
  const normalizedCapabilityRequest =
    normalizedAuthorityRequestFor(capabilityRequest);
  const normalizedDeniedRequest = normalizedAuthorityRequestFor({
    ...capabilityRequest,
    operationId: randomUUID(),
    agentId: "synthetic-capability-authorizer-bravo",
    intentNonce: randomUUID(),
    effectKey: randomUUID()
  });

  const authorizer = await withClient(
    connectionStringForUser(
      adminConnectionString,
      "tp_authorizer_user",
      passwords.tp_authorizer_user
    ),
    async (client) => {
      const directRead = await expectPrivilegeDenied(
        client,
        "SELECT * FROM tp_private.g1_resources LIMIT 1"
      );
      const directWrite = await expectPrivilegeDenied(
        client,
        `
          UPDATE tp_private.g1_resources
          SET current_fence = current_fence + 1
          WHERE false
        `
      );
      const observed = await client.query(
        `
          SELECT *
          FROM tp_api.g1_observe_admissibility_v2(
            $1::UUID,
            $2::UUID,
            $3::UUID,
            $4
          )
        `,
        [
          authorityFixture.tenantId,
          authorityFixture.evidenceId,
          authorityFixture.incidentId,
          "rescue"
        ]
      );
      await client.query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE");
      let spent;
      try {
        spent = await client.query(
          SPEND_AUTHORITY_SQL,
          spendAuthorityValues(
            normalizedCapabilityRequest,
            normalizedCapabilityRequest.agentId
          )
        );
        await client.query("COMMIT");
      } catch (error) {
        await client.query("ROLLBACK").catch(() => {});
        throw error;
      }
      const replay = await client.query(
        SPEND_AUTHORITY_SQL,
        spendAuthorityValues(
          normalizedCapabilityRequest,
          normalizedCapabilityRequest.agentId
        )
      );
      const denied = await client.query(
        SPEND_AUTHORITY_SQL,
        spendAuthorityValues(
          normalizedDeniedRequest,
          normalizedDeniedRequest.agentId
        )
      );
      const durableProof = await client.query(
        OBSERVE_AUTHORITY_RACE_SQL,
        [
          authorityFixture.tenantId,
          authorityFixture.runId,
          authorityFixture.resourceId,
          normalizedCapabilityRequest.operationId,
          normalizedCapabilityRequest.requestDigest,
          normalizedDeniedRequest.operationId,
          normalizedDeniedRequest.requestDigest
        ]
      );
      const wrongActorRequest = normalizedAuthorityRequestFor({
        ...capabilityRequest,
        operationId: randomUUID(),
        intentNonce: randomUUID(),
        effectKey: randomUUID()
      });
      const wrongActor = await expectPrivilegeDenied(
        client,
        SPEND_AUTHORITY_SQL,
        spendAuthorityValues(
          wrongActorRequest,
          "synthetic-capability-impostor"
        )
      );
      return {
        directRead,
        directWrite,
        observeRows: observed.rowCount,
        admissibility: observed.rows[0]?.admissibility,
        spendOutcome: spent.rows[0]?.decision_outcome,
        spendFence: spent.rows[0]?.decision_fencing_token,
        replayKind: replay.rows[0]?.decision_replay_kind,
        deniedOutcome: denied.rows[0]?.decision_outcome,
        durableProof: durableProof.rows[0],
        wrongActor
      };
    }
  );
  const capabilitySnapshot = await authorityStore.snapshot({
    tenantId: authorityFixture.tenantId,
    resourceId: authorityFixture.resourceId
  });
  await authorityStore.close();
  if (
    authorizer.spendOutcome !== "resource_reserved" ||
    authorizer.spendFence !== "1" ||
    authorizer.replayKind !== "operation_replay" ||
    authorizer.deniedOutcome !== "resource_held_denied" ||
    authorizer.durableProof?.race_receipt_count !== "2" ||
    authorizer.durableProof?.resource_receipt_count !== "2" ||
    authorizer.durableProof?.reserved_count !== "1" ||
    authorizer.durableProof?.held_denial_count !== "1" ||
    authorizer.durableProof?.pending_count !== "0" ||
    authorizer.durableProof?.outbox_count !== "1" ||
    authorizer.durableProof?.protected_effect_count !== "0" ||
    authorizer.durableProof
      ?.bravo_observed_holder_operation_id !==
      normalizedCapabilityRequest.operationId ||
    authorizer.durableProof?.bravo_observed_fence !== "1" ||
    capabilitySnapshot.receipts.length !== 2 ||
    capabilitySnapshot.outbox.length !== 1 ||
    capabilitySnapshot.effects.length !== 0 ||
    capabilitySnapshot.resource.current_fence !== "1"
  ) {
    throw new Error("least-privilege authority spend invariant failed");
  }

  const dispatch = await withClient(
    connectionStringForUser(
      adminConnectionString,
      "tp_dispatch_user",
      passwords.tp_dispatch_user
    ),
    async (client) => {
      const directWrite = await expectPrivilegeDenied(
        client,
        `
          INSERT INTO tp_ledger.g1_protected_effects (
            tenant_id,
            effect_key,
            operation_id,
            request_digest,
            run_id,
            incident_id,
            resource_id,
            agent_id,
            fencing_token,
            payload_digest
          )
          VALUES (
            $1::UUID,
            $2::UUID,
            $3::UUID,
            $4,
            $5::UUID,
            $6::UUID,
            $7,
            $8,
            1,
            $9
          )
        `,
        [
          randomUUID(),
          randomUUID(),
          randomUUID(),
          "a".repeat(64),
          randomUUID(),
          randomUUID(),
          "synthetic-missing-resource",
          "synthetic-missing-agent",
          "b".repeat(64)
        ]
      );
      const bounded = await client.query(
        `
          SELECT *
          FROM tp_api.g1_record_protected_effect_v1(
            $1::UUID,
            $2::UUID,
            $3::UUID,
            $4,
            $5::UUID,
            $6::UUID,
            $7,
            $8,
            1,
            $9
          )
        `,
        [
          randomUUID(),
          randomUUID(),
          randomUUID(),
          "a".repeat(64),
          randomUUID(),
          randomUUID(),
          "synthetic-missing-resource",
          "synthetic-missing-agent",
          "b".repeat(64)
        ]
      );
      return {
        directWrite,
        unauthorizedFunctionRows: bounded.rowCount
      };
    }
  );

  const recoveryAudit = await withClient(
    connectionStringForUser(
      adminConnectionString,
      "tp_recovery_audit_user",
      passwords.tp_recovery_audit_user
    ),
    async (client) => {
      const directRead = await expectPrivilegeDenied(
        client,
        "SELECT * FROM tp_ledger.g1_authority_receipts LIMIT 1"
      );
      const directWrite = await expectPrivilegeDenied(
        client,
        `
          INSERT INTO tp_ledger.g1_recovery_audit_receipts (
            audit_id,
            recovery_session_id,
            caller_subject_hash,
            tool_name,
            query_template_digest,
            bound_input_digest,
            result_digest,
            source_watermark,
            outcome
          )
          VALUES (
            $1::UUID,
            $2::UUID,
            $3,
            'select_query',
            $4,
            $5,
            $6,
            transaction_timestamp(),
            'rejected'
          )
        `,
        [
          randomUUID(),
          randomUUID(),
          "a".repeat(64),
          "b".repeat(64),
          "c".repeat(64),
          "d".repeat(64)
        ]
      );
      const directWriteV2 = await expectPrivilegeDenied(
        client,
        `
          INSERT INTO tp_ledger.g1_recovery_audit_receipts_v2 (
            audit_id,
            tenant_id,
            recovery_session_id,
            caller_subject_hash,
            tool_name,
            recovery_cluster_id,
            broker_config_digest,
            query_template_digest,
            bound_input_digest,
            result_digest,
            source_watermark,
            started_at,
            completed_at,
            outcome
          )
          VALUES (
            $1::UUID,
            $2::UUID,
            $3::UUID,
            $4,
            'select_query',
            $5::UUID,
            $6,
            $7,
            $8,
            $9,
            transaction_timestamp(),
            transaction_timestamp(),
            transaction_timestamp(),
            'rejected'
          )
        `,
        [
          randomUUID(),
          randomUUID(),
          randomUUID(),
          "a".repeat(64),
          randomUUID(),
          "b".repeat(64),
          "c".repeat(64),
          "d".repeat(64),
          "e".repeat(64)
        ]
      );
      const directWriteV3 = await expectPrivilegeDenied(
        client,
        `
          INSERT INTO tp_ledger.g1_recovery_audit_events_v3 (
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
            event_digest,
            started_at,
            completed_at,
            outcome
          )
          VALUES (
            $1::UUID,
            $2::UUID,
            $3::UUID,
            $4::UUID,
            $5,
            'pre_read',
            'select_query',
            $6::UUID,
            $7,
            $8,
            $9,
            $10,
            $11::TIMESTAMPTZ,
            $12::TIMESTAMPTZ,
            'read_authorized'
          )
        `,
        [
          randomUUID(),
          randomUUID(),
          randomUUID(),
          randomUUID(),
          "a".repeat(64),
          randomUUID(),
          "b".repeat(64),
          "c".repeat(64),
          "d".repeat(64),
          "e".repeat(64),
          new Date().toISOString(),
          new Date().toISOString()
        ]
      );
      const legacyFunctionV1Denied = await expectPrivilegeDenied(
        client,
        `
          SELECT tp_api.g1_append_recovery_audit_v1(
            $1::UUID,
            $2::UUID,
            $3,
            'select_query',
            $4,
            $5,
            $6,
            transaction_timestamp(),
            'recovered_context_only'
          ) AS audit_id
        `,
        [
          randomUUID(),
          randomUUID(),
          "a".repeat(64),
          "b".repeat(64),
          "c".repeat(64),
          "d".repeat(64)
        ]
      );
      const legacyFunctionV2Denied = await expectPrivilegeDenied(
        client,
        `
          SELECT tp_api.g1_append_recovery_audit_v2(
            $1::UUID,
            $2::UUID,
            $3::UUID,
            $4,
            'select_query',
            $5::UUID,
            $6,
            $7,
            $8,
            $9,
            transaction_timestamp(),
            transaction_timestamp(),
            transaction_timestamp(),
            'recovered_context_only',
            NULL
          ) AS audit_id
        `,
        [
          randomUUID(),
          randomUUID(),
          randomUUID(),
          "a".repeat(64),
          randomUUID(),
          "b".repeat(64),
          "c".repeat(64),
          "d".repeat(64),
          "e".repeat(64)
        ]
      );
      const auditEventIdV3 = randomUUID();
      const tenantIdV3 = randomUUID();
      const interactionIdV3 = randomUUID();
      const recoverySessionIdV3 = randomUUID();
      const recoveryClusterIdV3 = randomUUID();
      const startedAtV3 = new Date().toISOString();
      const completedAtV3 = new Date().toISOString();
      const eventDigestV3 = "f".repeat(64);
      const eventValuesV3 = [
        auditEventIdV3,
        tenantIdV3,
        interactionIdV3,
        recoverySessionIdV3,
        "a".repeat(64),
        "pre_read",
        "select_query",
        recoveryClusterIdV3,
        "b".repeat(64),
        "c".repeat(64),
        "d".repeat(64),
        null,
        null,
        "read_authorized",
        null,
        eventDigestV3,
        startedAtV3,
        completedAtV3
      ];
      const appendAuditEventV3 = `
        SELECT tp_api.g1_append_recovery_audit_event_v3(
          $1::UUID,
          $2::UUID,
          $3::UUID,
          $4::UUID,
          $5,
          $6,
          $7,
          $8::UUID,
          $9,
          $10,
          $11,
          $12,
          $13::TIMESTAMPTZ,
          $14,
          $15,
          $16,
          $17::TIMESTAMPTZ,
          $18::TIMESTAMPTZ
        ) AS event_id
      `;
      const appendedV3 = await client.query(
        appendAuditEventV3,
        eventValuesV3
      );
      const replayedV3 = await client.query(
        appendAuditEventV3,
        eventValuesV3
      );
      let changedReplayV3 = null;
      try {
        await client.query(appendAuditEventV3, [
          ...eventValuesV3.slice(0, 15),
          "0".repeat(64),
          ...eventValuesV3.slice(16)
        ]);
      } catch (error) {
        changedReplayV3 = {
          denied: error.code === "22000",
          sqlstate: error.code
        };
      }
      if (!changedReplayV3?.denied) {
        throw new Error("changed recovery audit v3 replay was not denied");
      }
      let changedFieldSameDigestV3 = null;
      try {
        await client.query(appendAuditEventV3, [
          ...eventValuesV3.slice(0, 4),
          "9".repeat(64),
          ...eventValuesV3.slice(5)
        ]);
      } catch (error) {
        changedFieldSameDigestV3 = {
          denied: error.code === "22000",
          sqlstate: error.code
        };
      }
      if (!changedFieldSameDigestV3?.denied) {
        throw new Error(
          "changed recovery audit v3 field with old digest was not denied"
        );
      }
      let orphanTerminalV3 = null;
      try {
        await client.query(appendAuditEventV3, [
          randomUUID(),
          randomUUID(),
          randomUUID(),
          randomUUID(),
          "a".repeat(64),
          "terminal",
          "select_query",
          randomUUID(),
          "b".repeat(64),
          "c".repeat(64),
          "d".repeat(64),
          "e".repeat(64),
          new Date().toISOString(),
          "unknown_do_not_act",
          "SYNTHETIC_ORPHAN",
          "f".repeat(64),
          startedAtV3,
          completedAtV3
        ]);
      } catch (error) {
        orphanTerminalV3 = {
          denied: error.code === "22000",
          sqlstate: error.code
        };
      }
      if (!orphanTerminalV3?.denied) {
        throw new Error("orphan recovery audit v3 terminal was not denied");
      }
      return {
        directRead,
        directWrite,
        directWriteV2,
        directWriteV3,
        legacyFunctionV1Denied,
        legacyFunctionV2Denied,
        functionAuditEventIdV3: appendedV3.rows[0].event_id,
        replayAuditEventIdV3: replayedV3.rows[0].event_id,
        changedReplayV3,
        changedFieldSameDigestV3,
        orphanTerminalV3
      };
    }
  );

  const audit = await withClient(
    connectionStringForUser(
      adminConnectionString,
      "tp_audit_user",
      passwords.tp_audit_user
    ),
    async (client) => {
      const directRead = await expectPrivilegeDenied(
        client,
        "SELECT * FROM tp_ledger.g1_authority_receipts LIMIT 1"
      );
      const sanitized = await client.query(
        "SELECT count(*)::INT8 AS receipt_count FROM tp_api.g1_receipt_audit_v1"
      );
      return {
        directRead,
        sanitizedReceiptCount: sanitized.rows[0].receipt_count
      };
    }
  );

  console.log(
    JSON.stringify(
      {
        gate: "primary-capability-boundaries",
        passed: true,
        roles: bootstrap.roles,
        ingest,
        authorizer,
        dispatch,
        recoveryAudit,
        audit,
        capabilityAuthority: {
          receiptCount: capabilitySnapshot.receipts.length,
          outboxCount: capabilitySnapshot.outbox.length,
          protectedEffectCount: capabilitySnapshot.effects.length,
          resourceFence: capabilitySnapshot.resource.current_fence
        },
        claimBoundary:
          "The signed-ingest and authority runtimes can execute only typed SECURITY DEFINER surfaces while direct base-table reads and writes are denied. The 50-session capability race and deployed AWS IAM remain separate evidence gates."
      },
      null,
      2
    )
  );
}

main().catch((error) => {
  console.error(
    JSON.stringify({
      gate: "primary-capability-boundaries",
      passed: false,
      name: error.name,
      code: error.code,
      message: error.message
    })
  );
  process.exitCode = 1;
});
