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
import {
  authorizeDviProposalWithClient,
  DVI_PROPOSAL_AUTHORIZATION_SQL
} from "../src/cloud/dvi-proposal-authorization.js";
import {
  assertRecoveryPublisherTrustRootWriteDeniedWithClient
} from "../src/cloud/recovery-broker.js";
import { SignedEvidenceIngest } from "../src/cloud/signed-ingest.js";
import { authorizeSyntheticProposal } from "./lib/synthetic-authority-proposal.js";
import { createSyntheticEvidenceSigner } from "./lib/synthetic-evidence.js";

const USERS = [
  "tp_ingest_user",
  "tp_authorizer_user",
  "tp_gate2_authorizer_user",
  "tp_dispatch_user",
  "tp_recovery_source_user",
  "tp_recovery_audit_user",
  "tp_provider_claim_user",
  "tp_provider_begin_user",
  "tp_provider_redeem_user",
  "tp_provider_activate_user",
  "tp_provider_finalize_user",
  "tp_provider_terminalize_user",
  "tp_provider_reconcile_user",
  "tp_audit_user"
];

const RECOVERY_SOURCE_STABLE_COLUMNS = Object.freeze([
  "admissibility",
  "agency",
  "agent_id",
  "authority_evidence_binding_sha256",
  "authorization_binding_sha256",
  "authorization_epoch",
  "evidence_digest",
  "evidence_id",
  "has_durable_intent",
  "incident_id",
  "logical_action_digest",
  "logical_authority_key_sha256",
  "operation_id",
  "outcome",
  "policy_version",
  "proposal_digest",
  "reason",
  "recorded_at",
  "request_digest",
  "resource_id",
  "run_id",
  "tenant_id"
]);

function sameStableDatabaseValue(left, right) {
  const normalized = (value) => {
    if (value instanceof Date) {
      const milliseconds = value.getTime();
      if (!Number.isFinite(milliseconds)) {
        throw new TypeError("stable database timestamp invalid");
      }
      return ["timestamptz", new Date(milliseconds).toISOString()];
    }
    if (value === null) return ["null", ""];
    if (
      typeof value === "string" ||
      typeof value === "boolean" ||
      (typeof value === "number" && Number.isFinite(value))
    ) {
      return [typeof value, value];
    }
    throw new TypeError("stable database value invalid");
  };
  const [leftType, leftValue] = normalized(left);
  const [rightType, rightValue] = normalized(right);
  return leftType === rightType && leftValue === rightValue;
}

const SPEND_AUTHORITY_SQL = `
  SELECT *
  FROM tp_api.g1_spend_authority_v1(
    $1::UUID,
    $2::UUID,
    $3,
    $4::JSONB,
    $5,
    $6,
    $7,
    $8::UUID,
    $9::UUID,
    $10,
    $11,
    $12,
    $13::UUID,
    $14::UUID,
    $15::JSONB,
    $16,
    $17,
    $18::INT8
  )
`;

const GATE2_SPEND_AUTHORITY_SQL = SPEND_AUTHORITY_SQL.replace(
  "tp_api.g1_spend_authority_v1",
  "tp_api.g2_spend_authority_race_v1"
);

const OBSERVE_AUTHORITY_RACE_SQL = `
  SELECT *
  FROM tp_api.g1_observe_authority_race_v1(
    $1::UUID, $2::UUID, $3,
    $4::UUID, $5, $6::UUID, $7
  )
`;

function spendAuthorityValues(request) {
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

function assertSqlProbeRequestBindings(values) {
  if (!Array.isArray(values) || values.length !== 18) {
    throw new TypeError("SQL authority probe values must contain 18 fields");
  }
  const requestPayload = JSON.parse(values[3]);
  const payload = JSON.parse(values[14]);
  const expectedBindings = {
    tenantId: values[0],
    proposalDigest: values[4],
    logicalActionDigest: values[5],
    selectedEvidenceDigest: values[6],
    runId: values[7],
    incidentId: values[8],
    resourceId: values[9],
    agentId: values[10],
    agency: values[11],
    evidenceId: values[12],
    selectedEvidenceId: values[12],
    effectKey: values[13],
    payloadDigest: values[15],
    policyVersion: values[16],
    leaseMs: values[17]
  };
  if (
    Object.keys(requestPayload).length !== 18 ||
    Object.entries(expectedBindings).some(
      ([field, expected]) => requestPayload[field] !== expected
    ) ||
    requestPayload.actionKind !== payload.action
  ) {
    throw new Error("SQL authority probe request bindings diverged");
  }
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

async function expectSqlState(
  client,
  query,
  values,
  sqlstate,
  expectedMessage
) {
  try {
    await client.query(query, values);
  } catch (error) {
    if (
      error.code === sqlstate &&
      (expectedMessage === undefined || error.message === expectedMessage)
    ) {
      return {
        denied: true,
        sqlstate: error.code,
        message: error.message
      };
    }
    throw error;
  }
  throw new Error(`expected SQLSTATE ${sqlstate}`);
}

async function expectPrivilegeDenied(client, query, values = []) {
  return expectSqlState(client, query, values, "42501");
}

async function expectPrivilegeDeniedOrUndefined(client, query, values = []) {
  try {
    await client.query(query, values);
  } catch (error) {
    if (error.code === "42501" || error.code === "42883") {
      return {
        denied: true,
        legacyObjectPresent: error.code === "42501",
        sqlstate: error.code
      };
    }
    throw error;
  }
  throw new Error("expected legacy resolver denial or absence");
}

const PROVIDER_PROBE = Object.freeze({
  authorizationId: "11111111-1111-4111-8111-111111111111",
  bindingSha256: "a".repeat(64),
  completionCapability: "b".repeat(64),
  completionCapabilitySha256: "c".repeat(64),
  executionCapability: "d".repeat(64),
  executionCapabilitySha256: "e".repeat(64),
  grantId: "22222222-2222-4222-8222-222222222222",
  interactionId: "33333333-3333-4333-8333-333333333333",
  issuedAt: "2026-08-12T00:00:00.000Z",
  expiresAt: "2026-08-13T00:00:00.000Z",
  runId: "44444444-4444-4444-8444-444444444444",
  tenantId: "55555555-5555-4555-8555-555555555555",
  workerSpecSha256: "f".repeat(64)
});

const FORBIDDEN_PROVIDER_MUTATIONS = Object.freeze([
  Object.freeze({
    name: "claim",
    sql: `
      SELECT * FROM tp_api.g1_claim_provider_dispatch_v2(
        $1::UUID, $2::UUID, $3::UUID, $4::UUID, $5::UUID,
        $6, $7, $8, $9, $10, $11, $12,
        $13::TIMESTAMPTZ, $14::TIMESTAMPTZ, $15, $16
      )
    `,
    values: [
      PROVIDER_PROBE.authorizationId,
      PROVIDER_PROBE.grantId,
      PROVIDER_PROBE.tenantId,
      PROVIDER_PROBE.runId,
      PROVIDER_PROBE.interactionId,
      PROVIDER_PROBE.bindingSha256,
      "1".repeat(64),
      "2".repeat(64),
      "3".repeat(64),
      "4".repeat(40),
      "5".repeat(40),
      "6".repeat(64),
      PROVIDER_PROBE.issuedAt,
      PROVIDER_PROBE.expiresAt,
      PROVIDER_PROBE.executionCapabilitySha256,
      PROVIDER_PROBE.workerSpecSha256
    ]
  }),
  Object.freeze({
    name: "begin",
    sql: `SELECT * FROM tp_api.g1_begin_provider_dispatch_v2(
      $1::UUID, $2::UUID, $3, $4, $5
    )`,
    values: [
      PROVIDER_PROBE.authorizationId,
      PROVIDER_PROBE.grantId,
      PROVIDER_PROBE.bindingSha256,
      PROVIDER_PROBE.executionCapability,
      PROVIDER_PROBE.workerSpecSha256
    ]
  }),
  Object.freeze({
    name: "redeem",
    sql: `SELECT * FROM tp_api.g1_redeem_provider_dispatch_v2(
      $1::UUID, $2::UUID, $3, $4, $5, $6
    )`,
    values: [
      PROVIDER_PROBE.authorizationId,
      PROVIDER_PROBE.grantId,
      PROVIDER_PROBE.bindingSha256,
      PROVIDER_PROBE.executionCapability,
      PROVIDER_PROBE.completionCapabilitySha256,
      PROVIDER_PROBE.workerSpecSha256
    ]
  }),
  Object.freeze({
    name: "complete",
    sql: `SELECT * FROM tp_api.g1_complete_provider_dispatch_v2(
      $1::UUID, $2::UUID, $3, $4, $5, $6
    )`,
    values: [
      PROVIDER_PROBE.authorizationId,
      PROVIDER_PROBE.grantId,
      PROVIDER_PROBE.bindingSha256,
      PROVIDER_PROBE.completionCapability,
      "7".repeat(64),
      "8".repeat(64)
    ]
  }),
  Object.freeze({
    name: "markUnknown",
    sql: `SELECT * FROM tp_api.g1_mark_provider_dispatch_unknown_v2(
      $1::UUID, $2::UUID, $3, $4
    )`,
    values: [
      PROVIDER_PROBE.authorizationId,
      PROVIDER_PROBE.grantId,
      PROVIDER_PROBE.bindingSha256,
      PROVIDER_PROBE.completionCapability
    ]
  })
]);

const LEGACY_PROVIDER_TRANSITION_SQL = `
  SELECT * FROM tp_api.g1_transition_provider_dispatch_v1(
    'CONSUME', $1::UUID, $2::UUID, $3::UUID, $4::UUID, $5::UUID,
    $6, $7, $8, $9, $10, $11, $12,
    $13::TIMESTAMPTZ, $14::TIMESTAMPTZ, NULL, NULL
  )
`;
const LEGACY_PROVIDER_TRANSITION_VALUES = Object.freeze([
  PROVIDER_PROBE.authorizationId,
  PROVIDER_PROBE.tenantId,
  PROVIDER_PROBE.runId,
  PROVIDER_PROBE.interactionId,
  PROVIDER_PROBE.grantId,
  PROVIDER_PROBE.bindingSha256,
  "1".repeat(64),
  "2".repeat(64),
  "3".repeat(64),
  "4".repeat(40),
  "5".repeat(40),
  "6".repeat(64),
  PROVIDER_PROBE.issuedAt,
  PROVIDER_PROBE.expiresAt
]);

async function providerMutationDenials(client) {
  const denials = {};
  for (const probe of FORBIDDEN_PROVIDER_MUTATIONS) {
    denials[probe.name] = await expectPrivilegeDeniedOrUndefined(
      client,
      probe.sql,
      probe.values
    );
  }
  denials.legacyTransition = await expectPrivilegeDeniedOrUndefined(
    client,
    LEGACY_PROVIDER_TRANSITION_SQL,
    LEGACY_PROVIDER_TRANSITION_VALUES
  );
  return denials;
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
  const recoveryPublisherTrustRootCommitment = requireEnvironment(
    "TIDEPROOF_RECOVERY_PUBLISHER_TRUST_ROOT_COMMITMENT"
  );
  const recoveryPublisherKeySetDigest = requireEnvironment(
    "TIDEPROOF_RECOVERY_PUBLISHER_KEY_SET_DIGEST"
  );
  const bootstrap = await bootstrapPrimarySecurity({
    adminConnectionString,
    passwords,
    recoveryPublisherTrustRootCommitment,
    recoveryPublisherKeySetDigest
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
  const proposalAuthorizer = (input) => withClient(
    connectionStringForUser(
      adminConnectionString,
      "tp_authorizer_user",
      passwords.tp_authorizer_user
    ),
    (client) => authorizeDviProposalWithClient(client, input)
  );
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
  const mismatchSelectionNow = Date.now();
  const mismatchSelectionWindow = {
    retrievalId: randomUUID(),
    admittedAt: new Date(mismatchSelectionNow - 1_000).toISOString(),
    expiresAt: new Date(
      mismatchSelectionNow + 5 * 60_000
    ).toISOString()
  };
  const beforeSelectionMismatch =
    await authorityStore.authorityIdentityStateForTest(authorityFixture);
  const selectionMismatch = await authorizeSyntheticProposal(
    authorityStore,
    capabilityRequest,
    {
      allowDenied: true,
      proposalAuthorizer,
      ...mismatchSelectionWindow,
      requestedSelectedEvidenceId: randomUUID(),
      requestedSelectedEvidenceDigest: "f".repeat(64)
    }
  );
  const afterSelectionMismatch =
    await authorityStore.authorityIdentityStateForTest(authorityFixture);
  if (
    selectionMismatch.authorization.outcome !==
      "proposal_authorization_denied" ||
    selectionMismatch.authorization.reason !==
      "dvi_selection_request_mismatch" ||
    Number(afterSelectionMismatch.selection_receipt_count) !==
      Number(beforeSelectionMismatch.selection_receipt_count) + 1 ||
    Number(afterSelectionMismatch.proposal_receipt_count) !==
      Number(beforeSelectionMismatch.proposal_receipt_count) ||
    Number(afterSelectionMismatch.epoch_count) !==
      Number(beforeSelectionMismatch.epoch_count) ||
    Number(afterSelectionMismatch.authority_receipt_count) !==
      Number(beforeSelectionMismatch.authority_receipt_count) ||
    Number(afterSelectionMismatch.outbox_count) !==
      Number(beforeSelectionMismatch.outbox_count) ||
    Number(afterSelectionMismatch.protected_effect_count) !==
      Number(beforeSelectionMismatch.protected_effect_count) ||
    Number(afterSelectionMismatch.current_fence) !==
      Number(beforeSelectionMismatch.current_fence)
  ) {
    throw new Error("DVI selection mismatch mutated authority state");
  }
  const capabilityAuthorization = await authorizeSyntheticProposal(
    authorityStore,
    capabilityRequest,
    {
      proposalAuthorizer,
      ...mismatchSelectionWindow
    }
  );
  const payloadVariantAuthorizations = [];
  for (const [name, payload] of [
    ["required-only", {
      action: "dispatch_rescue_unit",
      scenario: "synthetic-highwater"
    }],
    ["logical-dispatch-only", {
      action: "dispatch_rescue_unit",
      logicalDispatch: "contender-001",
      scenario: "synthetic-highwater"
    }],
    ["all-fields", {
      action: "dispatch_rescue_unit",
      destination: "synthetic-zone-capability",
      logicalDispatch: "contender-001",
      scenario: "synthetic-highwater"
    }]
  ]) {
    const variant = await authorizeSyntheticProposal(
      authorityStore,
      { ...capabilityRequest, payload },
      { proposalAuthorizer, ...mismatchSelectionWindow }
    );
    payloadVariantAuthorizations.push({
      name,
      outcome: variant.authorization.outcome,
      proposalDigest: variant.authorization.identity.proposalDigest
    });
  }
  payloadVariantAuthorizations.unshift({
    name: "destination-only",
    outcome: capabilityAuthorization.authorization.outcome,
    proposalDigest:
      capabilityAuthorization.authorization.identity.proposalDigest
  });

  const beforePayloadCanonicalizationNegatives =
    await authorityStore.authorityIdentityStateForTest(authorityFixture);
  const payloadCanonicalizationDatabase = await withClient(
    connectionStringForUser(
      adminConnectionString,
      "tp_authorizer_user",
      passwords.tp_authorizer_user
    ),
    async (client) => {
      const values = [
        authorityFixture.tenantId,
        mismatchSelectionWindow.retrievalId,
        authorityFixture.runId,
        authorityFixture.incidentId,
        authorityFixture.evidenceId,
        capabilityAuthorization.dviAuthorization.selectedEvidenceDigest,
        authorityFixture.resourceId,
        "rescue",
        "dispatch_rescue_unit",
        '{ "scenario" : "synthetic-highwater", "destination" : "synthetic-zone-capability", "action" : "dispatch_rescue_unit" }'
      ];
      const replay = await client.query(
        DVI_PROPOSAL_AUTHORIZATION_SQL,
        values
      );
      const invalidPayloads = [
        {
          action: "dispatch_rescue_unit",
          scenario: "synthetic-highwater",
          extra: "alternate-identity"
        },
        { action: "dispatch_rescue_unit" },
        {
          action: "dispatch_rescue_unit",
          scenario: 123
        },
        {
          action: "dispatch_rescue_unit",
          destination: null,
          scenario: "synthetic-highwater"
        },
        {
          action: "dispatch_rescue_unit",
          scenario: "unsafe/value"
        },
        {
          action: "dispatch_rescue_unit",
          scenario: "x".repeat(129)
        }
      ];
      const invalidSqlstates = [];
      for (const payload of invalidPayloads) {
        const invalidValues = [...values];
        invalidValues[9] = JSON.stringify(payload);
        const rejected = await expectSqlState(
          client,
          DVI_PROPOSAL_AUTHORIZATION_SQL,
          invalidValues,
          "22023"
        );
        invalidSqlstates.push(rejected.sqlstate);
      }
      return {
        outcome: replay.rows[0]?.decision_outcome,
        proposalDigest: replay.rows[0]?.decision_proposal_digest,
        logicalActionDigest:
          replay.rows[0]?.decision_logical_action_digest,
        payloadDigest: replay.rows[0]?.decision_payload_digest,
        authorityCurrent: replay.rows[0]?.decision_authority_current,
        invalidSqlstates
      };
    }
  );
  const afterPayloadCanonicalizationNegatives =
    await authorityStore.authorityIdentityStateForTest(authorityFixture);
  if (
    payloadVariantAuthorizations.length !== 4 ||
    payloadVariantAuthorizations.some(({ outcome }) =>
      !["proposal_authorized", "proposal_authorization_replay"].includes(
        outcome
      )
    ) ||
    new Set(
      payloadVariantAuthorizations.map(({ proposalDigest }) => proposalDigest)
    ).size !== 4 ||
    payloadCanonicalizationDatabase.outcome !==
      "proposal_authorization_replay" ||
    payloadCanonicalizationDatabase.proposalDigest !==
      capabilityAuthorization.authorization.identity.proposalDigest ||
    payloadCanonicalizationDatabase.logicalActionDigest !==
      capabilityAuthorization.authorization.identity.logicalActionDigest ||
    payloadCanonicalizationDatabase.payloadDigest !==
      "5d1c79211961c5702709a3219cb1e533761d64f22cb022a8ef8c291b456d4986" ||
    payloadCanonicalizationDatabase.authorityCurrent !== true ||
    payloadCanonicalizationDatabase.invalidSqlstates.length !== 6 ||
    payloadCanonicalizationDatabase.invalidSqlstates.some(
      (sqlstate) => sqlstate !== "22023"
    ) ||
    JSON.stringify(afterPayloadCanonicalizationNegatives) !==
      JSON.stringify(beforePayloadCanonicalizationNegatives)
  ) {
    throw new Error("DVI payload canonicalization invariant failed");
  }
  const payloadCanonicalization = {
    acceptedVariants: payloadVariantAuthorizations.map(({ name }) => name),
    replayOutcome: payloadCanonicalizationDatabase.outcome,
    payloadDigest: payloadCanonicalizationDatabase.payloadDigest,
    invalidPayloadsRejectedWithoutMutation: 6
  };
  const authorizedCapabilityRequest = {
    ...capabilityRequest,
    dviAuthorization: capabilityAuthorization.dviAuthorization
  };
  const deniedRequest = {
    ...capabilityRequest,
    operationId: randomUUID(),
    agentId: "synthetic-capability-authorizer-bravo",
    intentNonce: randomUUID(),
    effectKey: randomUUID(),
    payload: {
      ...capabilityRequest.payload,
      destination: "synthetic-zone-capability-denied"
    }
  };
  const deniedAuthorization = await authorizeSyntheticProposal(
    authorityStore,
    deniedRequest,
    { proposalAuthorizer }
  );
  const normalizedCapabilityRequest = normalizedAuthorityRequestFor(
    authorizedCapabilityRequest
  );
  const normalizedDeniedRequest = normalizedAuthorityRequestFor({
    ...deniedRequest,
    dviAuthorization: deniedAuthorization.dviAuthorization
  });

  const beforeSqlBindingNegatives =
    await authorityStore.authorityIdentityStateForTest(authorityFixture);
  const sqlBindingNegatives = await withClient(
    connectionStringForUser(
      adminConnectionString,
      "tp_authorizer_user",
      passwords.tp_authorizer_user
    ),
    async (client) => {
      const payloadSubstitution = spendAuthorityValues(
        normalizedCapabilityRequest
      );
      const substitutedPayload = {
        ...normalizedCapabilityRequest.payload,
        destination: "synthetic-zone-attacker-substitution"
      };
      payloadSubstitution[1] = randomUUID();
      payloadSubstitution[2] = "a".repeat(64);
      payloadSubstitution[3] = JSON.stringify({
        ...normalizedCapabilityRequest.requestPayload,
        payloadDigest: "b".repeat(64)
      });
      payloadSubstitution[14] = JSON.stringify(substitutedPayload);
      payloadSubstitution[15] = "b".repeat(64);
      assertSqlProbeRequestBindings(payloadSubstitution);
      const substituted = await client.query(
        SPEND_AUTHORITY_SQL,
        payloadSubstitution
      );

      const proposalAlias = spendAuthorityValues(
        normalizedCapabilityRequest
      );
      proposalAlias[1] = randomUUID();
      proposalAlias[2] = "c".repeat(64);
      proposalAlias[3] = JSON.stringify({
        ...normalizedCapabilityRequest.requestPayload,
        proposalDigest: normalizedDeniedRequest.proposalDigest
      });
      proposalAlias[4] = normalizedDeniedRequest.proposalDigest;
      assertSqlProbeRequestBindings(proposalAlias);
      const aliased = await client.query(
        SPEND_AUTHORITY_SQL,
        proposalAlias
      );

      const forgedRequestDigest = spendAuthorityValues(
        normalizedCapabilityRequest
      );
      forgedRequestDigest[1] = randomUUID();
      forgedRequestDigest[2] = "d".repeat(64);
      assertSqlProbeRequestBindings(forgedRequestDigest);
      const requestDigestRejected = await expectSqlState(
        client,
        SPEND_AUTHORITY_SQL,
        forgedRequestDigest,
        "22023",
        "database-derived authority identity mismatch"
      );

      const nullIntentNonce = spendAuthorityValues(
        normalizedCapabilityRequest
      );
      nullIntentNonce[1] = randomUUID();
      nullIntentNonce[2] = "e".repeat(64);
      nullIntentNonce[3] = JSON.stringify({
        ...normalizedCapabilityRequest.requestPayload,
        intentNonce: null
      });
      assertSqlProbeRequestBindings(nullIntentNonce);
      const nullIntentNonceRejected = await expectSqlState(
        client,
        SPEND_AUTHORITY_SQL,
        nullIntentNonce,
        "22023",
        "authority request identity binding mismatch"
      );
      return {
        payloadSubstitutionOutcome:
          substituted.rows[0]?.decision_outcome,
        payloadSubstitutionReason:
          substituted.rows[0]?.decision_reason,
        proposalAliasOutcome: aliased.rows[0]?.decision_outcome,
        proposalAliasReason: aliased.rows[0]?.decision_reason,
        requestDigestRejected,
        nullIntentNonceRejected
      };
    }
  );
  const afterSqlBindingNegatives =
    await authorityStore.authorityIdentityStateForTest(authorityFixture);
  if (
    sqlBindingNegatives.payloadSubstitutionOutcome !==
        "authorization_denied" ||
    sqlBindingNegatives.payloadSubstitutionReason !==
        "proposal_authorization_missing_or_stale" ||
    sqlBindingNegatives.proposalAliasOutcome !== "authorization_denied" ||
    sqlBindingNegatives.proposalAliasReason !==
        "proposal_authorization_missing_or_stale" ||
    sqlBindingNegatives.requestDigestRejected?.sqlstate !== "22023" ||
    sqlBindingNegatives.requestDigestRejected?.message !==
        "database-derived authority identity mismatch" ||
    sqlBindingNegatives.nullIntentNonceRejected?.sqlstate !== "22023" ||
    sqlBindingNegatives.nullIntentNonceRejected?.message !==
        "authority request identity binding mismatch" ||
    JSON.stringify(afterSqlBindingNegatives) !==
      JSON.stringify(beforeSqlBindingNegatives)
  ) {
    throw new Error("least-privilege SQL identity binding invariant failed");
  }

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
          spendAuthorityValues(normalizedCapabilityRequest)
        );
        await client.query("COMMIT");
      } catch (error) {
        await client.query("ROLLBACK").catch(() => {});
        throw error;
      }
      const replay = await client.query(
        SPEND_AUTHORITY_SQL,
        spendAuthorityValues(normalizedCapabilityRequest)
      );
      const denied = await client.query(
        SPEND_AUTHORITY_SQL,
        spendAuthorityValues(normalizedDeniedRequest)
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
      const gateTwoDirect = await expectPrivilegeDenied(
        client,
        GATE2_SPEND_AUTHORITY_SQL,
        spendAuthorityValues(normalizedCapabilityRequest)
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
        gateTwoDirect
      };
    }
  );
  const gateTwoProbeRequest = normalizedAuthorityRequestFor({
    ...authorizedCapabilityRequest,
    operationId: randomUUID(),
    agentId: "aws-authority-alpha",
    intentNonce: randomUUID(),
    effectKey: randomUUID()
  });
  const gateTwoAuthorizer = await withClient(
    connectionStringForUser(
      adminConnectionString,
      "tp_gate2_authorizer_user",
      passwords.tp_gate2_authorizer_user
    ),
    async (client) => {
      const gateOneDirect = await expectPrivilegeDenied(
        client,
        SPEND_AUTHORITY_SQL,
        spendAuthorityValues(gateTwoProbeRequest)
      );
      const invalidDigestValues = spendAuthorityValues(gateTwoProbeRequest);
      invalidDigestValues[2] = "invalid-digest";
      const nestedGateOneReached = await expectSqlState(
        client,
        GATE2_SPEND_AUTHORITY_SQL,
        invalidDigestValues,
        "22023"
      );
      return { gateOneDirect, nestedGateOneReached };
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
    authorizer.gateTwoDirect?.denied !== true ||
    gateTwoAuthorizer.gateOneDirect?.denied !== true ||
    gateTwoAuthorizer.nestedGateOneReached?.sqlstate !== "22023" ||
    authorizer.durableProof?.race_receipt_count !== "2" ||
    authorizer.durableProof?.resource_receipt_count !== "2" ||
    authorizer.durableProof?.reserved_count !== "1" ||
    authorizer.durableProof?.held_denial_count !== "1" ||
    authorizer.durableProof?.pending_count !== "0" ||
    authorizer.durableProof?.outbox_count !== "1" ||
    authorizer.durableProof?.protected_effect_count !== "0" ||
    sqlBindingNegatives.payloadSubstitutionOutcome !==
      "authorization_denied" ||
    sqlBindingNegatives.payloadSubstitutionReason !==
      "proposal_authorization_missing_or_stale" ||
    sqlBindingNegatives.proposalAliasOutcome !== "authorization_denied" ||
    sqlBindingNegatives.proposalAliasReason !==
      "proposal_authorization_missing_or_stale" ||
    sqlBindingNegatives.requestDigestRejected?.sqlstate !== "22023" ||
    sqlBindingNegatives.requestDigestRejected?.message !==
      "database-derived authority identity mismatch" ||
    sqlBindingNegatives.nullIntentNonceRejected?.sqlstate !== "22023" ||
    sqlBindingNegatives.nullIntentNonceRejected?.message !==
      "authority request identity binding mismatch" ||
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

  const recoverySource = await withClient(
    connectionStringForUser(
      adminConnectionString,
      "tp_recovery_source_user",
      passwords.tp_recovery_source_user
    ),
    async (client) => {
      const directRead = await expectPrivilegeDenied(
        client,
        "SELECT * FROM tp_ledger.g1_authority_receipts LIMIT 1"
      );
      const directTrustRootWrite =
        await assertRecoveryPublisherTrustRootWriteDeniedWithClient(client);
      const auditResolverDenied = await expectPrivilegeDenied(
        client,
        `
          SELECT *
          FROM tp_api.g1_resolve_recovery_publisher_trust_root_v1(
            'gate1-recovery-publisher-v1', $1, $2
          )
        `,
        [
          recoveryPublisherTrustRootCommitment,
          recoveryPublisherKeySetDigest
        ]
      );
      const legacySourceResolverDeniedOrAbsent =
        await expectPrivilegeDeniedOrUndefined(
          client,
          `
            SELECT *
            FROM tp_api.g1_resolve_recovery_source_receipt_v1(
              $1::UUID, $2::UUID, $3::UUID, $4::UUID,
              $5, $6::UUID, $7
            )
          `,
          [
            authorityFixture.tenantId,
            authorityFixture.runId,
            authorityFixture.incidentId,
            authorityFixture.evidenceId,
            authorityFixture.resourceId,
            normalizedCapabilityRequest.operationId,
            normalizedCapabilityRequest.requestDigest
          ]
        );
      const recoverySourceQuery = `
          SELECT *
          FROM tp_api.g1_resolve_recovery_source_receipt_v2(
            $1::UUID, $2::UUID, $3::UUID, $4::UUID,
            $5, $6::UUID, $7
          )
        `;
      const recoverySourceValues = Object.freeze([
        authorityFixture.tenantId,
        authorityFixture.runId,
        authorityFixture.incidentId,
        authorityFixture.evidenceId,
        authorityFixture.resourceId,
        normalizedCapabilityRequest.operationId,
        normalizedCapabilityRequest.requestDigest
      ]);
      let resolved;
      let resolvedAgain;
      let cursorCountAfterFirst;
      let cursorCountAfterSecond;
      await client.query("BEGIN");
      try {
        resolved = await client.query(
          recoverySourceQuery,
          recoverySourceValues
        );
        const cursorsAfterFirst = await client.query(
          "SELECT count(*)::INT8 AS cursor_count FROM pg_catalog.pg_cursors"
        );
        resolvedAgain = await client.query(
          recoverySourceQuery,
          recoverySourceValues
        );
        const cursorsAfterSecond = await client.query(
          "SELECT count(*)::INT8 AS cursor_count FROM pg_catalog.pg_cursors"
        );
        cursorCountAfterFirst = Number(
          cursorsAfterFirst.rows[0]?.cursor_count
        );
        cursorCountAfterSecond = Number(
          cursorsAfterSecond.rows[0]?.cursor_count
        );
        if (
          cursorsAfterFirst.rowCount !== 1 ||
          cursorsAfterSecond.rowCount !== 1 ||
          !Number.isSafeInteger(cursorCountAfterFirst) ||
          !Number.isSafeInteger(cursorCountAfterSecond) ||
          cursorCountAfterFirst !== 0 ||
          cursorCountAfterSecond !== 0
        ) {
          throw new Error("recovery source cursor was not closed exactly");
        }
        await client.query("COMMIT");
      } catch (error) {
        await client.query("ROLLBACK").catch(() => {});
        throw error;
      }
      const stableColumns = Object.keys(resolved.rows[0] ?? {})
        .filter((column) => column !== "database_now")
        .sort();
      if (
        resolved.rowCount !== 1 ||
        resolvedAgain.rowCount !== 1 ||
        resolved.rows[0]?.outcome !== "resource_reserved" ||
        resolved.rows[0]?.admissibility !== "admissible" ||
        resolved.rows[0]?.has_durable_intent !== true ||
        resolvedAgain.rows[0]?.outcome !== "resource_reserved" ||
        resolvedAgain.rows[0]?.admissibility !== "admissible" ||
        resolvedAgain.rows[0]?.has_durable_intent !== true ||
        JSON.stringify(stableColumns) !==
          JSON.stringify(RECOVERY_SOURCE_STABLE_COLUMNS) ||
        JSON.stringify(
          Object.keys(resolvedAgain.rows[0] ?? {})
            .filter((column) => column !== "database_now")
            .sort()
        ) !== JSON.stringify(RECOVERY_SOURCE_STABLE_COLUMNS) ||
        stableColumns.some(
          (column) =>
            !sameStableDatabaseValue(
              resolved.rows[0]?.[column],
              resolvedAgain.rows[0]?.[column]
            )
        )
      ) {
        throw new Error("recovery source receipt was not resolved exactly");
      }
      return {
        directRead,
        directTrustRootWrite,
        auditResolverDenied,
        legacySourceResolverDeniedOrAbsent,
        operationId: resolved.rows[0].operation_id,
        databaseNow: resolved.rows[0].database_now,
        cursorCountAfterFirst,
        cursorCountAfterSecond,
        resolverRepeatStable: true
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
      const directTrustRootWrite =
        await assertRecoveryPublisherTrustRootWriteDeniedWithClient(client);
      const sourceResolverDenied = await expectPrivilegeDenied(
        client,
        `
          SELECT *
          FROM tp_api.g1_resolve_recovery_source_receipt_v2(
            $1::UUID, $2::UUID, $3::UUID, $4::UUID,
            $5, $6::UUID, $7
          )
        `,
        [
          authorityFixture.tenantId,
          authorityFixture.runId,
          authorityFixture.incidentId,
          authorityFixture.evidenceId,
          authorityFixture.resourceId,
          normalizedCapabilityRequest.operationId,
          normalizedCapabilityRequest.requestDigest
        ]
      );
      const providerControlMutationDenials =
        await providerMutationDenials(client);
      const resolvedTrustRoot = await client.query(
        `
          SELECT *
          FROM tp_api.g1_resolve_recovery_publisher_trust_root_v1(
            'gate1-recovery-publisher-v1', $1, $2
          )
        `,
        [
          recoveryPublisherTrustRootCommitment,
          recoveryPublisherKeySetDigest
        ]
      );
      if (resolvedTrustRoot.rowCount !== 1) {
        throw new Error("committed recovery publisher trust root not resolved");
      }
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
        directTrustRootWrite,
        sourceResolverDenied,
        providerControlMutationDenials,
        publisherTrustRootCommittedAt:
          resolvedTrustRoot.rows[0].committed_at,
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

  const providerReconcile = await withClient(
    connectionStringForUser(
      adminConnectionString,
      "tp_provider_reconcile_user",
      passwords.tp_provider_reconcile_user
    ),
    async (client) => {
      const directRead = await expectPrivilegeDenied(
        client,
        "SELECT * FROM tp_ledger.g1_provider_dispatch_controls_v2 LIMIT 1"
      );
      const providerControlMutationDenials =
        await providerMutationDenials(client);
      const resolved = await client.query(
        `SELECT * FROM tp_api.g1_resolve_provider_dispatch_v2($1::UUID, $2)`,
        [PROVIDER_PROBE.authorizationId, PROVIDER_PROBE.bindingSha256]
      );
      const row = resolved.rows[0];
      if (
        resolved.rowCount !== 1 || row?.state !== "ABSENT" ||
        row?.transition_outcome !== "RESOLVED_ABSENT" ||
        Object.keys(row).some((name) =>
          /nonce|capability/u.test(name)
        )
      ) {
        throw new Error("provider reconcile capability invariant failed");
      }
      return {
        directRead,
        providerControlMutationDenials,
        resolveColumns: Object.keys(row).sort(),
        resolveState: row.state
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
        payloadCanonicalization,
        sqlBindingNegatives,
        gateTwoAuthorizer,
        dispatch,
        recoverySource,
        recoveryAudit,
        providerReconcile,
        audit,
        capabilityAuthority: {
          receiptCount: capabilitySnapshot.receipts.length,
          outboxCount: capabilitySnapshot.outbox.length,
          protectedEffectCount: capabilitySnapshot.effects.length,
          resourceFence: capabilitySnapshot.resource.current_fence
        },
        claimBoundary:
          "The signed-ingest, Gate One authority, and separate Gate Two authority identities can execute only their typed SECURITY DEFINER surfaces while direct base-table reads, writes, and cross-gate spend calls are denied. The 50-session capability race and deployed AWS IAM remain separate evidence gates."
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
