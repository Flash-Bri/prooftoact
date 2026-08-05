import { Client } from "pg";
import { createHash } from "node:crypto";
import { setTimeout as sleepTimer } from "node:timers/promises";
import { AuthorityStore, connectionStringForDatabase } from "./authority-store.js";
import { bootstrapDatabaseConfig } from "./database-runtime.js";
import {
  collectClusterManagedGrantPosture,
  collectDatabaseSecurityPosture,
  quoteIdentifier,
  validateDatabaseSecurityPosture
} from "./database-security-posture.js";
import { PRIMARY_MANAGED_BASE_TABLES } from "./recovery-security-contract.js";

const ROLE_BINDINGS = [
  ["tp_ingest_role", "tp_ingest_user"],
  ["tp_authorizer_role", "tp_authorizer_user"],
  ["tp_gate2_authorizer_role", "tp_gate2_authorizer_user"],
  ["tp_dispatch_role", "tp_dispatch_user"],
  ["tp_recovery_source_role", "tp_recovery_source_user"],
  ["tp_recovery_audit_role", "tp_recovery_audit_user"],
  ["tp_audit_role", "tp_audit_user"]
];

const RUNTIME_ROLES = ROLE_BINDINGS.map(([role]) => role);
const RUNTIME_USERS = ROLE_BINDINGS.map(([, user]) => user);
const CAPABILITY_ROLES = ["tp_owner", ...RUNTIME_ROLES];
const MANAGED_PRINCIPALS = [...CAPABILITY_ROLES, ...RUNTIME_USERS];
const RECOVERY_SIBLING_ROLES = [
  "tp_recovery_owner",
  "tp_recovery_publisher_role"
];
const RECOVERY_SIBLING_USERS = ["tp_recovery_publisher_user"];
const RECOVERY_SIBLING_BINDINGS = [[
  "tp_recovery_publisher_role",
  "tp_recovery_publisher_user"
]];
const CLUSTER_PRINCIPAL_DATABASES = Object.freeze(Object.fromEntries([
  ...MANAGED_PRINCIPALS.map((principal) => [principal, "tideproof"]),
  ...RECOVERY_SIBLING_ROLES.map((principal) => [
    principal,
    "tideproof_recovery"
  ]),
  ...RECOVERY_SIBLING_USERS.map((principal) => [
    principal,
    "tideproof_recovery"
  ])
]));
const LEGACY_RECOVERY_SOURCE_RESOLVER_SIGNATURE =
  "g1_resolve_recovery_source_receipt_v1(UUID, UUID, UUID, UUID, STRING, UUID, STRING)";
const CURRENT_RECOVERY_SOURCE_RESOLVER_SIGNATURE =
  "g1_resolve_recovery_source_receipt_v2(UUID, UUID, UUID, UUID, STRING, UUID, STRING)";
const PRIMARY_FUNCTION_SQL_BATCH_SCHEMA =
  "tideproof.primary-function-sql-batch.v1";
const PRIMARY_FUNCTION_SQL_STATEMENT_COUNT = 37;
const PRIMARY_FUNCTION_SQL_BATCH_SHA256 =
  "3756a7b2a67773eca795d00204ebe6fa13c695528215a01cc306a4f9ba8454f7";
const PRIMARY_ROLE_GRANT_POLICIES = Object.freeze({
  tp_ingest_role: Object.freeze({
    functions: Object.freeze([
      "g1_get_verification_key_v1(UUID, STRING)",
      "g1_append_verified_evidence_v2(UUID, UUID, UUID, STRING, STRING, STRING, STRING, STRING, STRING, STRING, STRING, STRING, STRING, TIMESTAMPTZ, TIMESTAMPTZ, TIMESTAMPTZ, STRING, STRING, STRING)",
      "g1_resolve_verified_evidence_v1(UUID, UUID, STRING, STRING)"
    ])
  }),
  tp_authorizer_role: Object.freeze({
    functions: Object.freeze([
      "g1_observe_admissibility_v1(UUID, UUID, UUID, STRING)",
      "g1_observe_admissibility_v2(UUID, UUID, UUID, STRING)",
      "g1_prepare_vector_set_v1(UUID, UUID, UUID, STRING, STRING, INT8)",
      "g1_observe_vector_exclusion_v1(UUID, UUID, UUID, UUID, STRING, STRING)",
      "g1_resolve_vector_set_v1(UUID, UUID, UUID, STRING, STRING, INT8)",
      "g1_rank_vector_set_v1(UUID, UUID, UUID, STRING, STRING, STRING, INT8)",
      "g1_commit_dvi_selection_v1(UUID, UUID, UUID, UUID, STRING, STRING, STRING, STRING, STRING, STRING, INT8, STRING)",
      "g1_delete_vector_set_v1(UUID, UUID)",
      "g1_purge_expired_vector_sets_v1(UUID, INT8)",
      "g1_spend_authority_v1(UUID, UUID, STRING, JSONB, STRING, STRING, STRING, UUID, UUID, STRING, STRING, STRING, UUID, UUID, JSONB, STRING, STRING, INT8)",
      "g1_resolve_request_v1(UUID, UUID, STRING, STRING)",
      "g1_observe_authority_race_v1(UUID, UUID, STRING, UUID, STRING, UUID, STRING)"
    ])
  }),
  tp_gate2_authorizer_role: Object.freeze({
    functions: Object.freeze([
      "g2_spend_authority_race_v1(UUID, UUID, STRING, JSONB, STRING, STRING, STRING, UUID, UUID, STRING, STRING, STRING, UUID, UUID, JSONB, STRING, STRING, INT8)",
      "g1_resolve_request_v1(UUID, UUID, STRING, STRING)",
      "g1_observe_authority_race_v1(UUID, UUID, STRING, UUID, STRING, UUID, STRING)"
    ])
  }),
  tp_dispatch_role: Object.freeze({
    functions: Object.freeze([
      "g1_record_protected_effect_v1(UUID, UUID, UUID, STRING, UUID, UUID, STRING, STRING, INT8, STRING)"
    ])
  }),
  tp_recovery_source_role: Object.freeze({
    functions: Object.freeze([
      CURRENT_RECOVERY_SOURCE_RESOLVER_SIGNATURE
    ])
  }),
  tp_recovery_audit_role: Object.freeze({
    functions: Object.freeze([
      "g1_append_recovery_audit_event_v3(UUID, UUID, UUID, UUID, STRING, STRING, STRING, UUID, STRING, STRING, STRING, STRING, TIMESTAMPTZ, STRING, STRING, STRING, TIMESTAMPTZ, TIMESTAMPTZ)",
      "g1_resolve_recovery_audit_event_v1(UUID, UUID, STRING)",
      "g1_resolve_recovery_publisher_trust_root_v1(STRING, STRING, STRING)"
    ])
  }),
  tp_audit_role: Object.freeze({
    relations: Object.freeze(["g1_receipt_audit_v1"])
  })
});
const PRIMARY_PREFLIGHT_ROLE_GRANT_POLICIES = Object.freeze({
  ...PRIMARY_ROLE_GRANT_POLICIES,
  tp_recovery_source_role: Object.freeze({
    functions: Object.freeze([
      LEGACY_RECOVERY_SOURCE_RESOLVER_SIGNATURE,
      CURRENT_RECOVERY_SOURCE_RESOLVER_SIGNATURE
    ])
  })
});
const PRIMARY_POSTURE_SPEC = Object.freeze({
  databaseName: "tideproof",
  managedSchemas: ["tp_private", "tp_ledger", "tp_api"],
  managedPrefixes: ["tp_"],
  apiSchema: "tp_api",
  ownerRoles: ["tp_owner"],
  roleGrantPolicies: PRIMARY_ROLE_GRANT_POLICIES,
  roles: CAPABILITY_ROLES,
  users: RUNTIME_USERS,
  bindings: ROLE_BINDINGS,
  optionalRoles: RECOVERY_SIBLING_ROLES,
  optionalUsers: RECOVERY_SIBLING_USERS,
  optionalBindings: RECOVERY_SIBLING_BINDINGS
});
const PRIMARY_PREFLIGHT_POSTURE_SPEC = Object.freeze({
  ...PRIMARY_POSTURE_SPEC,
  roleGrantPolicies: PRIMARY_PREFLIGHT_ROLE_GRANT_POLICIES
});

function requirePassword(passwords, user) {
  const value = passwords?.[user];
  if (typeof value !== "string" || value.length < 24) {
    throw new Error(`${user} requires a strong injected password`);
  }
  return value;
}

function validatedPasswords(passwords) {
  return Object.fromEntries(
    RUNTIME_USERS.map((user) => [user, requirePassword(passwords, user)])
  );
}

async function createPrincipalShells(client) {
  await client.query("CREATE ROLE IF NOT EXISTS tp_owner");
  for (const [role, user] of ROLE_BINDINGS) {
    await client.query(`CREATE ROLE IF NOT EXISTS ${role}`);
    await client.query(`CREATE USER IF NOT EXISTS ${user}`);
  }
}

async function lockInitialPublicCapability(client, bootstrapOwner) {
  await client.query("REVOKE ALL ON DATABASE tideproof FROM public");
  await client.query("REVOKE CREATE ON SCHEMA public FROM public");
  await lockPublicRoutineDefaults(client, [bootstrapOwner]);
}

async function lockPublicRoutineDefaults(client, principals, schemas = []) {
  const scopes = [
    "FOR ALL ROLES",
    ...principals.map((principal) =>
      `FOR ROLE ${quoteIdentifier(principal)}`
    )
  ];
  for (const scope of scopes) {
    await client.query(
      `ALTER DEFAULT PRIVILEGES ${scope} REVOKE EXECUTE ON FUNCTIONS FROM public`
    );
    for (const schema of schemas) {
      await client.query(
        `ALTER DEFAULT PRIVILEGES ${scope} IN SCHEMA ${quoteIdentifier(
          schema
        )} REVOKE EXECUTE ON FUNCTIONS FROM public`
      );
    }
  }
}

async function scrubManagedMemberships(client) {
  for (const role of RUNTIME_ROLES) {
    for (const principal of MANAGED_PRINCIPALS) {
      if (role !== principal) {
        await client.query(`REVOKE ${role} FROM ${principal}`);
      }
    }
  }
}

async function enforcePrincipalCredentials(client, passwords) {
  for (const role of CAPABILITY_ROLES) {
    await client.query(`ALTER ROLE ${role} WITH NOLOGIN`);
    await client.query(`ALTER ROLE ${role} WITH PASSWORD NULL`);
  }
  for (const user of RUNTIME_USERS) {
    await client.query(`ALTER USER ${user} WITH PASSWORD $1`, [passwords[user]]);
  }
}

async function grantExactMemberships(client) {
  for (const [role, user] of ROLE_BINDINGS) {
    await client.query(`GRANT ${role} TO ${user}`);
  }
}

async function scrubManagedPrivileges(client) {
  for (const principal of [...RUNTIME_ROLES, ...RUNTIME_USERS]) {
    await client.query(`REVOKE ALL ON DATABASE tideproof FROM ${principal}`);
    await client.query(
      `REVOKE ALL ON SCHEMA tp_private, tp_ledger, tp_api FROM ${principal}`
    );
    await client.query(
      `REVOKE ALL ON ALL TABLES IN SCHEMA tp_private, tp_ledger, tp_api FROM ${principal}`
    );
    await client.query(
      `REVOKE ALL ON ALL FUNCTIONS IN SCHEMA tp_private, tp_ledger, tp_api FROM ${principal}`
    );
  }
}

async function collectValidatedPosture(
  client,
  options,
  {
    attempts = 1,
    delayMs = 0,
    postureSpec = PRIMARY_POSTURE_SPEC
  } = {}
) {
  let lastError;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      const posture = await collectDatabaseSecurityPosture(client);
      const summary = validateDatabaseSecurityPosture(
        posture,
        postureSpec,
        options
      );
      return { posture, summary };
    } catch (error) {
      lastError = error;
      if (attempt + 1 < attempts) {
        await sleepTimer(delayMs);
      }
    }
  }
  throw lastError;
}

async function prepareOwnerPrivileges(client) {
  await client.query("GRANT ALL ON DATABASE tideproof TO tp_owner");
  await client.query(
    "GRANT ALL ON SCHEMA tp_private, tp_ledger, tp_api TO tp_owner"
  );
  await client.query(
    "GRANT ALL ON ALL TABLES IN SCHEMA tp_private, tp_ledger, tp_api TO tp_owner"
  );
  await client.query(
    "GRANT ALL ON ALL FUNCTIONS IN SCHEMA tp_api TO tp_owner"
  );
}

async function createAuditObjects(client, recoveryPublisherTrustRoot) {
  await client.query(`
    CREATE TABLE IF NOT EXISTS tp_ledger.g1_recovery_publisher_trust_roots (
      trust_root_id STRING NOT NULL,
      trust_root_commitment STRING(64) NOT NULL,
      publisher_key_set_digest STRING(64) NOT NULL,
      committed_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
      PRIMARY KEY (trust_root_id),
      CHECK (trust_root_id = 'gate1-recovery-publisher-v1'),
      CHECK (length(trust_root_commitment) = 64),
      CHECK (length(publisher_key_set_digest) = 64)
    )
  `);
  await client.query(
    `
      INSERT INTO tp_ledger.g1_recovery_publisher_trust_roots (
        trust_root_id,
        trust_root_commitment,
        publisher_key_set_digest
      ) VALUES ('gate1-recovery-publisher-v1', $1, $2)
      ON CONFLICT (trust_root_id) DO NOTHING
    `,
    [
      recoveryPublisherTrustRoot.trustRootCommitment,
      recoveryPublisherTrustRoot.publisherKeySetDigest
    ]
  );
  const committedTrustRoot = await client.query(`
    SELECT trust_root_commitment, publisher_key_set_digest
    FROM tp_ledger.g1_recovery_publisher_trust_roots
    WHERE trust_root_id = 'gate1-recovery-publisher-v1'
  `);
  if (
    committedTrustRoot.rowCount !== 1 ||
    committedTrustRoot.rows[0].trust_root_commitment !==
      recoveryPublisherTrustRoot.trustRootCommitment ||
    committedTrustRoot.rows[0].publisher_key_set_digest !==
      recoveryPublisherTrustRoot.publisherKeySetDigest
  ) {
    throw new Error("RECOVERY_PUBLISHER_TRUST_ROOT_ALREADY_COMMITTED");
  }

  await client.query(`
    CREATE TABLE IF NOT EXISTS tp_ledger.g1_recovery_audit_receipts (
      audit_id UUID NOT NULL,
      recovery_session_id UUID NOT NULL,
      caller_subject_hash STRING(64) NOT NULL,
      tool_name STRING NOT NULL,
      query_template_digest STRING(64) NOT NULL,
      bound_input_digest STRING(64) NOT NULL,
      result_digest STRING(64) NOT NULL,
      source_watermark TIMESTAMPTZ NOT NULL,
      outcome STRING NOT NULL,
      recorded_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
      PRIMARY KEY (audit_id),
      UNIQUE (
        recovery_session_id,
        query_template_digest,
        bound_input_digest,
        result_digest,
        outcome
      ),
      CHECK (length(caller_subject_hash) = 64),
      CHECK (tool_name = 'select_query'),
      CHECK (length(query_template_digest) = 64),
      CHECK (length(bound_input_digest) = 64),
      CHECK (length(result_digest) = 64),
      CHECK (
        outcome IN (
          'recovered_context_only',
          'unknown_do_not_act',
          'rejected'
        )
      )
    )
  `);

  await client.query(`
    CREATE TABLE IF NOT EXISTS tp_ledger.g1_recovery_audit_receipts_v2 (
      audit_id UUID NOT NULL,
      tenant_id UUID NOT NULL,
      recovery_session_id UUID NOT NULL,
      caller_subject_hash STRING(64) NOT NULL,
      tool_name STRING NOT NULL,
      recovery_cluster_id UUID NOT NULL,
      broker_config_digest STRING(64) NOT NULL,
      query_template_digest STRING(64) NOT NULL,
      bound_input_digest STRING(64) NOT NULL,
      result_digest STRING(64) NOT NULL,
      source_watermark TIMESTAMPTZ NOT NULL,
      started_at TIMESTAMPTZ NOT NULL,
      completed_at TIMESTAMPTZ NOT NULL,
      outcome STRING NOT NULL,
      error_code STRING NULL,
      recorded_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
      PRIMARY KEY (tenant_id, audit_id),
      CHECK (length(caller_subject_hash) = 64),
      CHECK (tool_name = 'select_query'),
      CHECK (length(broker_config_digest) = 64),
      CHECK (length(query_template_digest) = 64),
      CHECK (length(bound_input_digest) = 64),
      CHECK (length(result_digest) = 64),
      CHECK (completed_at >= started_at),
      CHECK (
        outcome IN (
          'recovered_context_only',
          'unknown_do_not_act',
          'rejected'
        )
      )
    )
  `);

  await client.query(`
    CREATE TABLE IF NOT EXISTS tp_ledger.g1_recovery_audit_events_v3 (
      tenant_id UUID NOT NULL,
      event_id UUID NOT NULL,
      interaction_id UUID NOT NULL,
      recovery_session_id UUID NOT NULL,
      caller_subject_hash STRING(64) NOT NULL,
      phase STRING NOT NULL,
      tool_name STRING NOT NULL,
      recovery_cluster_id UUID NOT NULL,
      broker_config_digest STRING(64) NOT NULL,
      query_template_digest STRING(64) NOT NULL,
      bound_input_digest STRING(64) NOT NULL,
      result_digest STRING(64) NULL,
      source_watermark TIMESTAMPTZ NULL,
      outcome STRING NOT NULL,
      error_code STRING NULL,
      event_digest STRING(64) NOT NULL,
      started_at TIMESTAMPTZ NOT NULL,
      completed_at TIMESTAMPTZ NOT NULL,
      recorded_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
      PRIMARY KEY (tenant_id, event_id),
      UNIQUE (tenant_id, interaction_id, phase),
      CHECK (length(caller_subject_hash) = 64),
      CHECK (phase IN ('pre_read', 'terminal')),
      CHECK (tool_name = 'select_query'),
      CHECK (length(broker_config_digest) = 64),
      CHECK (length(query_template_digest) = 64),
      CHECK (length(bound_input_digest) = 64),
      CHECK (result_digest IS NULL OR length(result_digest) = 64),
      CHECK (length(event_digest) = 64),
      CHECK (completed_at >= started_at),
      CHECK (
        (
          phase = 'pre_read'
          AND outcome = 'read_authorized'
          AND result_digest IS NULL
          AND source_watermark IS NULL
          AND error_code IS NULL
        )
        OR
        (
          phase = 'terminal'
          AND outcome IN (
            'recovered_context_only',
            'unknown_do_not_act',
            'rejected'
          )
          AND result_digest IS NOT NULL
          AND source_watermark IS NOT NULL
        )
      )
    )
  `);

  await client.query(`
    CREATE OR REPLACE VIEW tp_api.g1_receipt_audit_v1 AS
    SELECT
      tenant_id,
      operation_id,
      request_digest,
      proposal_digest,
      logical_action_digest,
      authorization_epoch,
      logical_authority_key_sha256,
      authorization_binding_sha256,
      run_id,
      incident_id,
      resource_id,
      agent_id,
      agency,
      evidence_digest,
      payload_digest,
      policy_version,
      outcome,
      reason,
      fencing_token,
      lease_expires_at,
      recorded_at
    FROM tp_ledger.g1_authority_receipts
  `);
}

function primaryFunctionSqlBatchSha256(statements) {
  return createHash("sha256")
    .update(JSON.stringify({
      schema: PRIMARY_FUNCTION_SQL_BATCH_SCHEMA,
      statements
    }))
    .digest("hex");
}

function validatePrimaryFunctionSqlStatements(statements) {
  if (
    !Array.isArray(statements) ||
    statements.length !== PRIMARY_FUNCTION_SQL_STATEMENT_COUNT ||
    statements.some(
      (statement) =>
        typeof statement !== "string" ||
        statement.length === 0 ||
        statement.includes("\u0000")
    ) ||
    primaryFunctionSqlBatchSha256(statements) !==
      PRIMARY_FUNCTION_SQL_BATCH_SHA256
  ) {
    throw new Error("PRIMARY_FUNCTION_SQL_BATCH_UNREVIEWED");
  }
  return Object.freeze({
    schema: PRIMARY_FUNCTION_SQL_BATCH_SCHEMA,
    statementCount: statements.length,
    sha256: PRIMARY_FUNCTION_SQL_BATCH_SHA256
  });
}

async function emitPrimaryFunctionSql(client) {
  await client.query(`
    CREATE OR REPLACE FUNCTION tp_api.g1_append_verified_evidence_v1(
      p_tenant_id UUID,
      p_evidence_id UUID,
      p_incident_id UUID,
      p_issuer STRING,
      p_agency_scope STRING,
      p_verification_key_id STRING,
      p_verifier_version STRING,
      p_signed_payload_digest STRING,
      p_evidence_digest STRING,
      p_observed_at TIMESTAMPTZ,
      p_valid_from TIMESTAMPTZ,
      p_valid_until TIMESTAMPTZ,
      p_conflict_status STRING,
      p_assertion STRING,
      p_embedding STRING
    )
    RETURNS UUID
    LANGUAGE SQL
    SECURITY DEFINER
    AS $$
      INSERT INTO tp_private.g1_evidence (
        tenant_id,
        evidence_id,
        incident_id,
        issuer,
        agency_scope,
        verification_key_id,
        verifier_version,
        signed_payload_digest,
        evidence_digest,
        observed_at,
        valid_from,
        valid_until,
        provenance_status,
        conflict_status,
        assertion,
        embedding
      )
      SELECT
        p_tenant_id,
        p_evidence_id,
        p_incident_id,
        p_issuer,
        p_agency_scope,
        p_verification_key_id,
        p_verifier_version,
        p_signed_payload_digest,
        p_evidence_digest,
        p_observed_at,
        p_valid_from,
        p_valid_until,
        'verified',
        p_conflict_status,
        p_assertion,
        p_embedding::VECTOR(3)
      WHERE session_user = 'tp_ingest_user'
      RETURNING evidence_id
    $$
  `);

  await client.query(`
    CREATE OR REPLACE FUNCTION tp_api.g1_get_verification_key_v1(
      p_tenant_id UUID,
      p_verification_key_id STRING
    )
    RETURNS TABLE(
      verification_key_id STRING,
      issuer STRING,
      algorithm STRING,
      public_key_spki_base64 STRING,
      public_key_digest STRING,
      status STRING,
      valid_from TIMESTAMPTZ,
      valid_until TIMESTAMPTZ
    )
    LANGUAGE SQL
    SECURITY DEFINER
    AS $$
      SELECT
        key.verification_key_id,
        key.issuer,
        key.algorithm,
        key.public_key_spki_base64,
        key.public_key_digest,
        key.status,
        key.valid_from,
        key.valid_until
      FROM tp_private.g1_verification_keys AS key
      WHERE key.tenant_id = p_tenant_id
        AND key.verification_key_id = p_verification_key_id
        AND session_user = 'tp_ingest_user'
    $$
  `);

  await client.query(`
    CREATE OR REPLACE FUNCTION tp_api.g1_append_verified_evidence_v2(
      p_tenant_id UUID,
      p_evidence_id UUID,
      p_incident_id UUID,
      p_issuer STRING,
      p_agency_scope STRING,
      p_claim_key STRING,
      p_claim_value STRING,
      p_verification_key_id STRING,
      p_verifier_version STRING,
      p_verification_request_digest STRING,
      p_signed_payload_digest STRING,
      p_signature_digest STRING,
      p_evidence_digest STRING,
      p_observed_at TIMESTAMPTZ,
      p_valid_from TIMESTAMPTZ,
      p_valid_until TIMESTAMPTZ,
      p_conflict_status STRING,
      p_assertion STRING,
      p_embedding STRING
    )
    RETURNS UUID
    LANGUAGE PLpgSQL
    SECURITY DEFINER
    AS $$
    DECLARE
      v_key_count INT8;
      v_public_key_digest STRING;
      v_existing_count INT8;
      v_existing_request_digest STRING;
      v_existing_outcome STRING;
      v_evidence_count INT8;
    BEGIN
      IF session_user <> 'tp_ingest_user' THEN
        RAISE EXCEPTION 'ingest database session required'
          USING ERRCODE = '42501';
      END IF;
      IF p_verifier_version <> 'gate1-ed25519-verifier-v1' THEN
        RAISE EXCEPTION 'unsupported verifier version'
          USING ERRCODE = '22023';
      END IF;
      IF length(p_verification_request_digest) <> 64
        OR length(p_signed_payload_digest) <> 64
        OR length(p_signature_digest) <> 64
        OR length(p_evidence_digest) <> 64 THEN
        RAISE EXCEPTION 'verification digest must be SHA-256 hex'
          USING ERRCODE = '22023';
      END IF;

      SELECT count(*)::INT8
      INTO v_key_count
      FROM tp_private.g1_verification_keys AS key
      WHERE key.tenant_id = p_tenant_id
        AND key.verification_key_id = p_verification_key_id
        AND key.issuer = p_issuer
        AND key.algorithm = 'ed25519'
        AND key.status = 'active'
        AND p_observed_at >= key.valid_from
        AND p_observed_at < key.valid_until;
      IF v_key_count <> 1 THEN
        RAISE EXCEPTION 'verification key is not admissible'
          USING ERRCODE = '42501';
      END IF;
      SELECT key.public_key_digest
      INTO v_public_key_digest
      FROM tp_private.g1_verification_keys AS key
      WHERE key.tenant_id = p_tenant_id
        AND key.verification_key_id = p_verification_key_id;

      SELECT count(*)::INT8
      INTO v_existing_count
      FROM tp_ledger.g1_evidence_verification_receipts AS verification
      WHERE verification.tenant_id = p_tenant_id
        AND verification.evidence_id = p_evidence_id;
      IF v_existing_count > 0 THEN
        SELECT
          verification.verification_request_digest,
          verification.outcome
        INTO v_existing_request_digest, v_existing_outcome
        FROM tp_ledger.g1_evidence_verification_receipts AS verification
        WHERE verification.tenant_id = p_tenant_id
          AND verification.evidence_id = p_evidence_id;
        IF v_existing_request_digest <> p_verification_request_digest
          OR v_existing_outcome <> 'verified' THEN
          RAISE EXCEPTION 'evidence verification mismatch'
            USING ERRCODE = '22000';
        END IF;
        SELECT count(*)::INT8
        INTO v_evidence_count
        FROM tp_private.g1_evidence AS evidence
        WHERE evidence.tenant_id = p_tenant_id
          AND evidence.evidence_id = p_evidence_id;
        IF v_evidence_count <> 1 THEN
          RAISE EXCEPTION 'verified receipt lacks evidence row'
            USING ERRCODE = 'XX000';
        END IF;
        RETURN p_evidence_id;
      END IF;

      INSERT INTO tp_ledger.g1_evidence_verification_receipts (
        tenant_id,
        evidence_id,
        verification_request_digest,
        incident_id,
        issuer,
        verification_key_id,
        verifier_version,
        signed_payload_digest,
        signature_digest,
        public_key_digest,
        outcome,
        reason
      )
      VALUES (
        p_tenant_id,
        p_evidence_id,
        p_verification_request_digest,
        p_incident_id,
        p_issuer,
        p_verification_key_id,
        p_verifier_version,
        p_signed_payload_digest,
        p_signature_digest,
        v_public_key_digest,
        'verified',
        NULL
      );

      INSERT INTO tp_private.g1_evidence (
        tenant_id,
        evidence_id,
        incident_id,
        issuer,
        agency_scope,
        claim_key,
        claim_value,
        verification_key_id,
        verifier_version,
        signed_payload_digest,
        signature_digest,
        evidence_digest,
        observed_at,
        valid_from,
        valid_until,
        provenance_status,
        conflict_status,
        assertion,
        embedding
      )
      VALUES (
        p_tenant_id,
        p_evidence_id,
        p_incident_id,
        p_issuer,
        p_agency_scope,
        p_claim_key,
        p_claim_value,
        p_verification_key_id,
        p_verifier_version,
        p_signed_payload_digest,
        p_signature_digest,
        p_evidence_digest,
        p_observed_at,
        p_valid_from,
        p_valid_until,
        'verified',
        p_conflict_status,
        p_assertion,
        p_embedding::VECTOR(3)
      );
      RETURN p_evidence_id;
    END
    $$
  `);

  await client.query(`
    CREATE OR REPLACE FUNCTION tp_api.g1_resolve_verified_evidence_v1(
      p_tenant_id UUID,
      p_evidence_id UUID,
      p_verification_request_digest STRING,
      p_evidence_digest STRING
    )
    RETURNS TABLE(
      evidence_id UUID,
      verification_request_digest STRING,
      evidence_digest STRING,
      outcome STRING,
      database_now TIMESTAMPTZ
    )
    LANGUAGE SQL
    SECURITY DEFINER
    AS $$
      SELECT
        evidence.evidence_id,
        verification.verification_request_digest,
        evidence.evidence_digest,
        'evidence_verified'::STRING,
        transaction_timestamp()
      FROM tp_ledger.g1_evidence_verification_receipts AS verification
      JOIN tp_private.g1_evidence AS evidence
        ON evidence.tenant_id = verification.tenant_id
       AND evidence.evidence_id = verification.evidence_id
      WHERE session_user = 'tp_ingest_user'
        AND verification.tenant_id = p_tenant_id
        AND verification.evidence_id = p_evidence_id
        AND verification.verification_request_digest =
          p_verification_request_digest
        AND verification.outcome = 'verified'
        AND evidence.evidence_digest = p_evidence_digest
    $$
  `);

  await client.query(`
    CREATE OR REPLACE FUNCTION tp_api.g1_observe_admissibility_v1(
      p_tenant_id UUID,
      p_evidence_id UUID,
      p_incident_id UUID,
      p_agency STRING
    )
    RETURNS TABLE(
      admissibility STRING,
      evidence_digest STRING,
      database_now TIMESTAMPTZ
    )
    LANGUAGE SQL
    SECURITY DEFINER
    AS $$
      SELECT
        CASE
          WHEN evidence.verification_key_id IS NULL
            OR evidence.verifier_version IS NULL
            OR evidence.signed_payload_digest IS NULL
            OR evidence.evidence_digest IS NULL
            THEN 'verification_receipt_missing'
          WHEN evidence.provenance_status <> 'verified'
            THEN 'provenance_not_verified'
          WHEN evidence.conflict_status = 'unresolved'
            THEN 'unresolved_conflict'
          WHEN evidence.observed_at >
            statement_timestamp() + INTERVAL '5 minutes'
            THEN 'future_observation'
          WHEN evidence.valid_from > statement_timestamp()
            THEN 'not_yet_valid'
          WHEN evidence.valid_until <= statement_timestamp()
            THEN 'expired'
          WHEN evidence.agency_scope NOT IN (p_agency, '*')
            THEN 'out_of_scope'
          ELSE 'admissible'
        END,
        evidence.evidence_digest,
        statement_timestamp()
      FROM tp_private.g1_evidence AS evidence
      WHERE evidence.tenant_id = p_tenant_id
        AND evidence.evidence_id = p_evidence_id
        AND evidence.incident_id = p_incident_id
        AND session_user = 'tp_authorizer_user'
    $$
  `);

  await client.query(`
    CREATE OR REPLACE FUNCTION tp_private.g1_list_admissibility_internal_v1(
      p_tenant_id UUID,
      p_incident_id UUID,
      p_agency STRING
    )
    RETURNS TABLE(
      evidence_id UUID,
      admissibility STRING,
      evidence_digest STRING,
      assertion STRING,
      embedding VECTOR(3),
      database_now TIMESTAMPTZ
    )
    LANGUAGE SQL
    SECURITY DEFINER
    AS $$
      SELECT
        evidence.evidence_id,
        CASE
          WHEN evidence.verification_key_id IS NULL
            OR evidence.verifier_version IS NULL
            OR evidence.signed_payload_digest IS NULL
            OR evidence.signature_digest IS NULL
            OR evidence.evidence_digest IS NULL
            THEN 'verification_receipt_missing'
          WHEN verification.evidence_id IS NULL
            THEN 'verification_receipt_missing'
          WHEN verification.outcome <> 'verified'
            THEN COALESCE(verification.reason, 'verification_rejected')
          WHEN verification.incident_id <> evidence.incident_id
            OR verification.issuer <> evidence.issuer
            OR verification.verification_key_id <>
              evidence.verification_key_id
            OR verification.verifier_version <> evidence.verifier_version
            OR verification.signed_payload_digest <>
              evidence.signed_payload_digest
            OR verification.signature_digest <> evidence.signature_digest
            THEN 'verification_binding_mismatch'
          WHEN verification_key.verification_key_id IS NULL
            THEN 'verification_key_unknown'
          WHEN verification_key.public_key_digest <>
            verification.public_key_digest
            THEN 'verification_key_digest_mismatch'
          WHEN verification_key.issuer <> evidence.issuer
            THEN 'verification_issuer_mismatch'
          WHEN verification_key.status <> 'active'
            THEN 'verification_key_revoked'
          WHEN evidence.observed_at < verification_key.valid_from
            OR evidence.observed_at >= verification_key.valid_until
            THEN 'verification_key_not_valid_at_observation'
          WHEN evidence.provenance_status <> 'verified'
            THEN 'provenance_not_verified'
          WHEN evidence.claim_key IS NULL OR evidence.claim_value IS NULL
            THEN 'claim_binding_missing'
          WHEN evidence.observed_at >
            statement_timestamp() + INTERVAL '5 minutes'
            THEN 'future_observation'
          WHEN evidence.valid_from > statement_timestamp()
            THEN 'not_yet_valid'
          WHEN evidence.valid_until <= statement_timestamp()
            THEN 'expired'
          WHEN evidence.agency_scope NOT IN (p_agency, '*')
            THEN 'out_of_scope'
          WHEN evidence.conflict_status = 'unresolved'
            THEN 'unresolved_conflict'
          WHEN EXISTS (
            SELECT 1
            FROM tp_private.g1_evidence AS other
            JOIN tp_ledger.g1_evidence_verification_receipts
              AS other_verification
              ON other_verification.tenant_id = other.tenant_id
             AND other_verification.evidence_id = other.evidence_id
            JOIN tp_private.g1_verification_keys AS other_key
              ON other_key.tenant_id = other.tenant_id
             AND other_key.verification_key_id = other.verification_key_id
            WHERE other.tenant_id = evidence.tenant_id
              AND other.incident_id = evidence.incident_id
              AND other.evidence_id <> evidence.evidence_id
              AND other.claim_key = evidence.claim_key
              AND other.claim_value <> evidence.claim_value
              AND other.provenance_status = 'verified'
              AND other_verification.outcome = 'verified'
              AND other_verification.incident_id = other.incident_id
              AND other_verification.issuer = other.issuer
              AND other_verification.verification_key_id =
                other.verification_key_id
              AND other_verification.verifier_version =
                other.verifier_version
              AND other_verification.signed_payload_digest =
                other.signed_payload_digest
              AND other_verification.signature_digest =
                other.signature_digest
              AND other_key.status = 'active'
              AND other_key.issuer = other.issuer
              AND other_key.public_key_digest =
                other_verification.public_key_digest
              AND other.observed_at >= other_key.valid_from
              AND other.observed_at < other_key.valid_until
              AND other.observed_at <=
                statement_timestamp() + INTERVAL '5 minutes'
              AND other.valid_from <= statement_timestamp()
              AND other.valid_until > statement_timestamp()
              AND other.agency_scope IN (p_agency, '*')
          )
            THEN 'unresolved_conflict'
          ELSE 'admissible'
        END,
        evidence.evidence_digest,
        evidence.assertion,
        evidence.embedding,
        statement_timestamp()
      FROM tp_private.g1_evidence AS evidence
      LEFT JOIN tp_ledger.g1_evidence_verification_receipts AS verification
        ON verification.tenant_id = evidence.tenant_id
       AND verification.evidence_id = evidence.evidence_id
      LEFT JOIN tp_private.g1_verification_keys AS verification_key
        ON verification_key.tenant_id = evidence.tenant_id
       AND verification_key.verification_key_id =
         evidence.verification_key_id
      WHERE evidence.tenant_id = p_tenant_id
        AND evidence.incident_id = p_incident_id
        AND session_user IN (
          'tp_authorizer_user',
          'tp_gate2_authorizer_user',
          'tp_recovery_source_user'
        )
    $$
  `);

  await client.query(`
    CREATE OR REPLACE FUNCTION tp_api.g1_observe_admissibility_v2(
      p_tenant_id UUID,
      p_evidence_id UUID,
      p_incident_id UUID,
      p_agency STRING
    )
    RETURNS TABLE(
      admissibility STRING,
      evidence_digest STRING,
      database_now TIMESTAMPTZ
    )
    LANGUAGE SQL
    SECURITY DEFINER
    AS $$
      SELECT
        listed.admissibility,
        listed.evidence_digest,
        listed.database_now
      FROM tp_private.g1_list_admissibility_internal_v1(
        p_tenant_id,
        p_incident_id,
        p_agency
      ) AS listed
      WHERE listed.evidence_id = p_evidence_id
        AND session_user IN (
          'tp_authorizer_user',
          'tp_gate2_authorizer_user'
        )
    $$
  `);

  await client.query(`
    CREATE OR REPLACE FUNCTION tp_api.g1_prepare_vector_set_v1(
      p_tenant_id UUID,
      p_retrieval_id UUID,
      p_incident_id UUID,
      p_agency STRING,
      p_policy_version STRING,
      p_ttl_ms INT8
    )
    RETURNS TABLE(
      retrieval_id UUID,
      candidate_count INT8,
      admitted_at TIMESTAMPTZ,
      expires_at TIMESTAMPTZ
    )
    LANGUAGE PLpgSQL
    SECURITY DEFINER
    AS $$
    DECLARE
      v_candidate_count INT8;
      v_exclusion_count INT8;
      v_admitted_at TIMESTAMPTZ;
      v_expires_at TIMESTAMPTZ;
    BEGIN
      IF session_user <> 'tp_authorizer_user' THEN
        RAISE EXCEPTION 'Gate One authorizer database session required'
          USING ERRCODE = '42501';
      END IF;
      IF p_policy_version <> 'g1-admissibility-v2' THEN
        RAISE EXCEPTION 'unsupported admissibility policy version'
          USING ERRCODE = '22023';
      END IF;
      IF length(p_agency) < 1 OR length(p_agency) > 128 THEN
        RAISE EXCEPTION 'agency outside policy'
          USING ERRCODE = '22023';
      END IF;
      IF p_ttl_ms < 1000 OR p_ttl_ms > 300000 THEN
        RAISE EXCEPTION 'retrieval TTL outside policy'
          USING ERRCODE = '22023';
      END IF;
      IF EXISTS (
        SELECT 1
        FROM tp_private.g1_vector_retrieval_sets AS retrieval
        WHERE retrieval.tenant_id = p_tenant_id
          AND retrieval.retrieval_id = p_retrieval_id
      ) OR EXISTS (
        SELECT 1
        FROM tp_private.g1_vector_candidates AS candidate
        WHERE candidate.tenant_id = p_tenant_id
          AND candidate.retrieval_id = p_retrieval_id
      ) OR EXISTS (
        SELECT 1
        FROM tp_private.g1_vector_exclusions AS exclusion
        WHERE exclusion.tenant_id = p_tenant_id
          AND exclusion.retrieval_id = p_retrieval_id
      ) THEN
        RAISE EXCEPTION 'retrieval identifier already used'
          USING ERRCODE = '23505';
      END IF;

      v_admitted_at := statement_timestamp();
      v_expires_at :=
        v_admitted_at + p_ttl_ms * INTERVAL '1 millisecond';

      SELECT count(*)::INT8
      INTO v_candidate_count
      FROM tp_private.g1_list_admissibility_internal_v1(
        p_tenant_id,
        p_incident_id,
        p_agency
      ) AS listed
      WHERE listed.admissibility = 'admissible';
      IF v_candidate_count > 10000 THEN
        RAISE EXCEPTION 'admissible candidate set exceeds policy cap'
          USING ERRCODE = '54000';
      END IF;
      SELECT count(*)::INT8
      INTO v_exclusion_count
      FROM tp_private.g1_list_admissibility_internal_v1(
        p_tenant_id,
        p_incident_id,
        p_agency
      ) AS listed
      WHERE listed.admissibility <> 'admissible';
      IF v_exclusion_count > 10000 THEN
        RAISE EXCEPTION 'inadmissible evidence set exceeds policy cap'
          USING ERRCODE = '54000';
      END IF;
      IF EXISTS (
        SELECT 1
        FROM tp_private.g1_list_admissibility_internal_v1(
          p_tenant_id,
          p_incident_id,
          p_agency
        ) AS listed
        WHERE listed.admissibility = 'admissible'
          AND octet_length(listed.assertion) NOT BETWEEN 1 AND 4096
      ) THEN
        RAISE EXCEPTION 'admissible assertion exceeds policy cap'
          USING ERRCODE = '54000';
      END IF;

      INSERT INTO tp_private.g1_vector_retrieval_sets (
        tenant_id,
        retrieval_id,
        incident_id,
        agency,
        policy_version,
        admitted_at,
        expires_at,
        candidate_count
      ) VALUES (
        p_tenant_id,
        p_retrieval_id,
        p_incident_id,
        p_agency,
        p_policy_version,
        v_admitted_at,
        v_expires_at,
        v_candidate_count
      );

      INSERT INTO tp_private.g1_vector_exclusions (
        tenant_id,
        retrieval_id,
        evidence_id,
        evidence_digest,
        admissibility,
        observed_at
      )
      SELECT
        p_tenant_id,
        p_retrieval_id,
        listed.evidence_id,
        listed.evidence_digest,
        listed.admissibility,
        v_admitted_at
      FROM tp_private.g1_list_admissibility_internal_v1(
        p_tenant_id,
        p_incident_id,
        p_agency
      ) AS listed
      WHERE listed.admissibility <> 'admissible';

      INSERT INTO tp_private.g1_vector_candidates (
        tenant_id,
        retrieval_id,
        evidence_id,
        evidence_digest,
        assertion,
        embedding
      )
      SELECT
        p_tenant_id,
        p_retrieval_id,
        listed.evidence_id,
        listed.evidence_digest,
        listed.assertion,
        listed.embedding
      FROM tp_private.g1_list_admissibility_internal_v1(
        p_tenant_id,
        p_incident_id,
        p_agency
      ) AS listed
      WHERE listed.admissibility = 'admissible';

      RETURN QUERY SELECT
        p_retrieval_id,
        v_candidate_count,
        v_admitted_at,
        v_expires_at;
    END
    $$
  `);

  await client.query(`
    CREATE OR REPLACE FUNCTION tp_api.g1_observe_vector_exclusion_v1(
      p_tenant_id UUID,
      p_retrieval_id UUID,
      p_evidence_id UUID,
      p_incident_id UUID,
      p_agency STRING,
      p_policy_version STRING
    )
    RETURNS TABLE(
      admissibility STRING,
      evidence_digest STRING,
      snapshot_admitted_at TIMESTAMPTZ
    )
    LANGUAGE PLpgSQL
    SECURITY DEFINER
    AS $$
    BEGIN
      IF session_user <> 'tp_authorizer_user' THEN
        RAISE EXCEPTION 'Gate One authorizer database session required'
          USING ERRCODE = '42501';
      END IF;
      RETURN QUERY
      SELECT
        exclusion.admissibility,
        exclusion.evidence_digest,
        retrieval.admitted_at
      FROM tp_private.g1_vector_retrieval_sets AS retrieval
      JOIN tp_private.g1_vector_exclusions AS exclusion
        ON exclusion.tenant_id = retrieval.tenant_id
       AND exclusion.retrieval_id = retrieval.retrieval_id
      WHERE retrieval.tenant_id = p_tenant_id
        AND retrieval.retrieval_id = p_retrieval_id
        AND retrieval.incident_id = p_incident_id
        AND retrieval.agency = p_agency
        AND retrieval.policy_version = p_policy_version
        AND exclusion.evidence_id = p_evidence_id
        AND exclusion.observed_at = retrieval.admitted_at;
    END
    $$
  `);

  await client.query(`
    CREATE OR REPLACE FUNCTION tp_api.g1_resolve_vector_set_v1(
      p_tenant_id UUID,
      p_retrieval_id UUID,
      p_incident_id UUID,
      p_agency STRING,
      p_policy_version STRING,
      p_ttl_ms INT8
    )
    RETURNS TABLE(
      retrieval_id UUID,
      candidate_count INT8,
      admitted_at TIMESTAMPTZ,
      expires_at TIMESTAMPTZ,
      database_now TIMESTAMPTZ
    )
    LANGUAGE SQL
    SECURITY DEFINER
    AS $$
      SELECT
        retrieval.retrieval_id,
        retrieval.candidate_count,
        retrieval.admitted_at,
        retrieval.expires_at,
        transaction_timestamp()
      FROM tp_private.g1_vector_retrieval_sets AS retrieval
      WHERE session_user = 'tp_authorizer_user'
        AND retrieval.tenant_id = p_tenant_id
        AND retrieval.retrieval_id = p_retrieval_id
        AND retrieval.incident_id = p_incident_id
        AND retrieval.agency = p_agency
        AND retrieval.policy_version = p_policy_version
        AND retrieval.expires_at = retrieval.admitted_at +
          (p_ttl_ms * INTERVAL '1 millisecond')
        AND retrieval.candidate_count = (
          SELECT count(*)::INT8
          FROM tp_private.g1_vector_candidates AS candidate
          WHERE candidate.tenant_id = retrieval.tenant_id
            AND candidate.retrieval_id = retrieval.retrieval_id
        )
    $$
  `);

  await client.query(`
    CREATE OR REPLACE FUNCTION tp_api.g1_rank_vector_set_v1(
      p_tenant_id UUID,
      p_retrieval_id UUID,
      p_incident_id UUID,
      p_agency STRING,
      p_policy_version STRING,
      p_query_embedding STRING,
      p_limit INT8
    )
    RETURNS TABLE(
      evidence_id UUID,
      evidence_digest STRING,
      assertion STRING,
      distance FLOAT8
    )
    LANGUAGE PLpgSQL
    SECURITY DEFINER
    AS $$
    DECLARE
      v_set_count INT8;
    BEGIN
      IF session_user <> 'tp_authorizer_user' THEN
        RAISE EXCEPTION 'Gate One authorizer database session required'
          USING ERRCODE = '42501';
      END IF;
      IF p_limit IS NULL OR p_limit < 1 OR p_limit > 100 THEN
        RAISE EXCEPTION 'vector result limit outside policy'
          USING ERRCODE = '22023';
      END IF;
      IF p_query_embedding IS NULL THEN
        RAISE EXCEPTION 'query embedding required'
          USING ERRCODE = '22023';
      END IF;
      SELECT count(*)::INT8
      INTO v_set_count
      FROM tp_private.g1_vector_retrieval_sets AS retrieval
      WHERE retrieval.tenant_id = p_tenant_id
        AND retrieval.retrieval_id = p_retrieval_id
        AND retrieval.incident_id = p_incident_id
        AND retrieval.agency = p_agency
        AND retrieval.policy_version = p_policy_version
        AND retrieval.cleaned_at IS NULL
        AND retrieval.expires_at > transaction_timestamp();
      IF v_set_count <> 1 THEN
        RAISE EXCEPTION 'retrieval set missing, mismatched, or expired'
          USING ERRCODE = '22023';
      END IF;

      RETURN QUERY
      SELECT
        candidate.evidence_id,
        candidate.evidence_digest,
        candidate.assertion,
        candidate.embedding <=> p_query_embedding::VECTOR(3)
      FROM tp_private.g1_vector_candidates AS candidate
      WHERE candidate.tenant_id = p_tenant_id
        AND candidate.retrieval_id = p_retrieval_id
      ORDER BY
        candidate.embedding <=> p_query_embedding::VECTOR(3),
        candidate.evidence_id
      LIMIT p_limit;
    END
    $$
  `);

  await client.query(`
    CREATE OR REPLACE FUNCTION tp_api.g1_delete_vector_set_v1(
      p_tenant_id UUID,
      p_retrieval_id UUID
    )
    RETURNS TABLE(deleted_candidates INT8, retired_sets INT8)
    LANGUAGE PLpgSQL
    SECURITY DEFINER
    AS $$
    DECLARE
      v_deleted_candidates INT8;
      v_retired_sets INT8;
    BEGIN
      IF session_user <> 'tp_authorizer_user' THEN
        RAISE EXCEPTION 'Gate One authorizer database session required'
          USING ERRCODE = '42501';
      END IF;
      SELECT count(*)::INT8
      INTO v_deleted_candidates
      FROM tp_private.g1_vector_candidates AS candidate
      WHERE candidate.tenant_id = p_tenant_id
        AND candidate.retrieval_id = p_retrieval_id;
      DELETE FROM tp_private.g1_vector_candidates AS candidate
      WHERE candidate.tenant_id = p_tenant_id
        AND candidate.retrieval_id = p_retrieval_id;
      DELETE FROM tp_private.g1_vector_exclusions AS exclusion
      WHERE exclusion.tenant_id = p_tenant_id
        AND exclusion.retrieval_id = p_retrieval_id;
      UPDATE tp_private.g1_vector_retrieval_sets AS retrieval
      SET cleaned_at = COALESCE(
        retrieval.cleaned_at,
        transaction_timestamp()
      )
      WHERE retrieval.tenant_id = p_tenant_id
        AND retrieval.retrieval_id = p_retrieval_id
      RETURNING 1::INT8 INTO v_retired_sets;
      v_retired_sets := COALESCE(v_retired_sets, 0);
      RETURN QUERY SELECT v_deleted_candidates, v_retired_sets;
    END
    $$
  `);

  await client.query(`
    CREATE OR REPLACE FUNCTION tp_api.g1_purge_expired_vector_sets_v1(
      p_tenant_id UUID,
      p_limit INT8
    )
    RETURNS TABLE(deleted_candidates INT8, retired_sets INT8)
    LANGUAGE PLpgSQL
    SECURITY DEFINER
    AS $$
    DECLARE
      v_retrieval_id UUID;
      v_deleted_candidates INT8 := 0;
      v_retired_sets INT8 := 0;
      v_row_count INT8;
    BEGIN
      IF session_user <> 'tp_authorizer_user' THEN
        RAISE EXCEPTION 'Gate One authorizer database session required'
          USING ERRCODE = '42501';
      END IF;
      IF p_limit IS NULL OR p_limit < 1 OR p_limit > 1000 THEN
        RAISE EXCEPTION 'vector purge limit outside policy'
          USING ERRCODE = '22023';
      END IF;

      FOR v_retrieval_id IN
        SELECT retrieval.retrieval_id
        FROM tp_private.g1_vector_retrieval_sets AS retrieval
        WHERE retrieval.tenant_id = p_tenant_id
          AND retrieval.cleaned_at IS NULL
          AND retrieval.expires_at <= transaction_timestamp()
        ORDER BY retrieval.expires_at, retrieval.retrieval_id
        LIMIT p_limit
      LOOP
        DELETE FROM tp_private.g1_vector_candidates AS candidate
        WHERE candidate.tenant_id = p_tenant_id
          AND candidate.retrieval_id = v_retrieval_id;
        GET DIAGNOSTICS v_row_count = ROW_COUNT;
        v_deleted_candidates := v_deleted_candidates + v_row_count;

        DELETE FROM tp_private.g1_vector_exclusions AS exclusion
        WHERE exclusion.tenant_id = p_tenant_id
          AND exclusion.retrieval_id = v_retrieval_id;

        UPDATE tp_private.g1_vector_retrieval_sets AS retrieval
        SET cleaned_at = transaction_timestamp()
        WHERE retrieval.tenant_id = p_tenant_id
          AND retrieval.retrieval_id = v_retrieval_id
          AND retrieval.cleaned_at IS NULL;
        GET DIAGNOSTICS v_row_count = ROW_COUNT;
        v_retired_sets := v_retired_sets + v_row_count;
      END LOOP;

      RETURN QUERY SELECT v_deleted_candidates, v_retired_sets;
    END
    $$
  `);

  await client.query(`
    DROP FUNCTION IF EXISTS tp_api.g1_commit_dvi_selection_v1(
      UUID, UUID, UUID, UUID, STRING, STRING, STRING, STRING, STRING,
      STRING, INT8, UUID, STRING, STRING
    )
  `);

  await client.query(`
    DROP FUNCTION IF EXISTS tp_api.g1_commit_dvi_selection_v1(
      UUID, UUID, UUID, UUID, STRING, STRING, STRING, STRING, STRING,
      STRING, INT8, STRING
    )
  `);

  await client.query(`
    CREATE OR REPLACE FUNCTION tp_api.g1_commit_dvi_selection_v1(
      p_tenant_id UUID,
      p_retrieval_id UUID,
      p_run_id UUID,
      p_incident_id UUID,
      p_agency STRING,
      p_policy_version STRING,
      p_source_commit STRING,
      p_tree_digest STRING,
      p_spec_sha256 STRING,
      p_query_embedding STRING,
      p_limit INT8,
      p_claimed_authority_evidence_binding_sha256 STRING
    )
    RETURNS TABLE(
      authority_evidence_binding_sha256 STRING,
      admitted_at TIMESTAMPTZ,
      expires_at TIMESTAMPTZ,
      ranked_sequence_sha256 STRING,
      query_embedding_sha256 STRING,
      result_limit INT8,
      selected_rank INT8,
      selected_evidence_id UUID,
      selected_evidence_digest STRING
    )
    LANGUAGE PLpgSQL
    SECURITY DEFINER
    AS $$
    DECLARE
      v_admitted_at TIMESTAMPTZ;
      v_expires_at TIMESTAMPTZ;
      v_observed_count INT8;
      v_ranked_sequence_sha256 STRING;
      v_query_embedding_sha256 STRING;
      v_selected_evidence_id UUID;
      v_selected_evidence_digest STRING;
      v_authority_evidence_binding_sha256 STRING;
      v_admitted_at_text STRING;
      v_expires_at_text STRING;
    BEGIN
      IF session_user <> 'tp_authorizer_user' THEN
        RAISE EXCEPTION 'Gate One authorizer database session required'
          USING ERRCODE = '42501';
      END IF;
      IF p_policy_version IS DISTINCT FROM 'g1-admissibility-v2'
        OR p_source_commit IS NULL
        OR p_source_commit !~ '^[0-9a-f]{40}$'
        OR p_tree_digest IS NULL
        OR p_tree_digest !~ '^[0-9a-f]{40}$'
        OR p_spec_sha256 IS NULL
        OR p_spec_sha256 !~ '^[0-9a-f]{64}$'
        OR p_query_embedding IS NULL
        OR p_claimed_authority_evidence_binding_sha256 IS NULL
        OR p_claimed_authority_evidence_binding_sha256 !~
          '^[0-9a-f]{64}$'
        OR p_limit IS NULL
        OR p_limit < 1
        OR p_limit > 100 THEN
        RAISE EXCEPTION 'DVI selection receipt identity outside policy'
          USING ERRCODE = '22023';
      END IF;

      SELECT retrieval.admitted_at, retrieval.expires_at
      INTO v_admitted_at, v_expires_at
      FROM tp_private.g1_vector_retrieval_sets AS retrieval
      WHERE retrieval.tenant_id = p_tenant_id
        AND retrieval.retrieval_id = p_retrieval_id
        AND retrieval.incident_id = p_incident_id
        AND retrieval.agency = p_agency
        AND retrieval.policy_version = p_policy_version
        AND retrieval.cleaned_at IS NULL
        AND retrieval.expires_at > transaction_timestamp();
      IF v_admitted_at IS NULL THEN
        RAISE EXCEPTION 'live DVI retrieval set required'
          USING ERRCODE = '22023';
      END IF;
      WITH ranked AS (
        SELECT
          candidate.evidence_id,
          candidate.evidence_digest,
          row_number() OVER (
            ORDER BY
              candidate.embedding <=> p_query_embedding::VECTOR(3),
              candidate.evidence_id
          ) AS rank
        FROM tp_private.g1_vector_candidates AS candidate
        WHERE candidate.tenant_id = p_tenant_id
          AND candidate.retrieval_id = p_retrieval_id
        ORDER BY
          candidate.embedding <=> p_query_embedding::VECTOR(3),
          candidate.evidence_id
        LIMIT p_limit
      )
      SELECT
        count(*)::INT8,
        encode(
          sha256((
            string_agg(
              ranked.evidence_id::STRING || ':' || ranked.evidence_digest,
              e'\n' ORDER BY ranked.rank
            ) || e'\n'
          )::BYTES),
          'hex'
        )
      INTO v_observed_count, v_ranked_sequence_sha256
      FROM ranked;
      IF v_observed_count <> p_limit THEN
        RAISE EXCEPTION 'ranked DVI result count outside policy'
          USING ERRCODE = '22023';
      END IF;
      SELECT candidate.evidence_id, candidate.evidence_digest
      INTO v_selected_evidence_id, v_selected_evidence_digest
      FROM tp_private.g1_vector_candidates AS candidate
      WHERE candidate.tenant_id = p_tenant_id
        AND candidate.retrieval_id = p_retrieval_id
      ORDER BY
        candidate.embedding <=> p_query_embedding::VECTOR(3),
        candidate.evidence_id
      LIMIT 1;
      IF v_selected_evidence_id IS NULL THEN
        RAISE EXCEPTION 'rank-1 DVI evidence missing'
          USING ERRCODE = '22023';
      END IF;

      v_query_embedding_sha256 := encode(
        sha256(p_query_embedding::BYTES),
        'hex'
      );
      v_admitted_at_text := to_char(
        v_admitted_at AT TIME ZONE 'UTC',
        'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
      );
      v_expires_at_text := to_char(
        v_expires_at AT TIME ZONE 'UTC',
        'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
      );
      v_authority_evidence_binding_sha256 := encode(
        sha256((
          '{"agency":' || to_json(p_agency)::STRING ||
          ',"incidentId":"' || p_incident_id::STRING ||
          '","policyVersion":' || to_json(p_policy_version)::STRING ||
          ',"queryEmbeddingSha256":"' || v_query_embedding_sha256 ||
          '","rankedSequenceSha256":"' || v_ranked_sequence_sha256 ||
          '","resultLimit":' || p_limit::STRING ||
          ',"retrievalId":"' || p_retrieval_id::STRING ||
          '","runId":"' || p_run_id::STRING ||
          '","schemaVersion":"tideproof.authority.dvi-selection-receipt.v2"' ||
          ',"selected":{"evidenceDigest":"' ||
          v_selected_evidence_digest || '","evidenceId":"' ||
          v_selected_evidence_id::STRING || '","rank":1}' ||
          ',"snapshot":{"admittedAt":"' || v_admitted_at_text ||
          '","expiresAt":"' || v_expires_at_text || '"}' ||
          ',"sourceCommit":"' || p_source_commit ||
          '","specSha256":"' || p_spec_sha256 ||
          '","tenantId":"' || p_tenant_id::STRING ||
          '","treeDigest":"' || p_tree_digest || '"}'
        )::BYTES),
        'hex'
      );
      IF v_authority_evidence_binding_sha256 IS DISTINCT FROM
        p_claimed_authority_evidence_binding_sha256 THEN
        RAISE EXCEPTION 'DVI selection binding mismatch'
          USING ERRCODE = '22023';
      END IF;

      INSERT INTO tp_ledger.g1_dvi_selection_receipts (
        tenant_id,
        retrieval_id,
        authority_evidence_binding_sha256,
        run_id,
        incident_id,
        agency,
        policy_version,
        source_commit,
        tree_digest,
        spec_sha256,
        admitted_at,
        expires_at,
        ranked_sequence_sha256,
        query_embedding_sha256,
        result_limit,
        selected_rank,
        selected_evidence_id,
        selected_evidence_digest
      ) VALUES (
        p_tenant_id,
        p_retrieval_id,
        v_authority_evidence_binding_sha256,
        p_run_id,
        p_incident_id,
        p_agency,
        p_policy_version,
        p_source_commit,
        p_tree_digest,
        p_spec_sha256,
        v_admitted_at,
        v_expires_at,
        v_ranked_sequence_sha256,
        v_query_embedding_sha256,
        p_limit,
        1,
        v_selected_evidence_id,
        v_selected_evidence_digest
      )
      ON CONFLICT DO NOTHING;

      SELECT count(*)::INT8
      INTO v_observed_count
      FROM tp_ledger.g1_dvi_selection_receipts AS receipt
      WHERE receipt.tenant_id = p_tenant_id
        AND receipt.retrieval_id = p_retrieval_id
        AND receipt.authority_evidence_binding_sha256 =
          v_authority_evidence_binding_sha256
        AND receipt.run_id = p_run_id
        AND receipt.incident_id = p_incident_id
        AND receipt.agency = p_agency
        AND receipt.policy_version = p_policy_version
        AND receipt.source_commit = p_source_commit
        AND receipt.tree_digest = p_tree_digest
        AND receipt.spec_sha256 = p_spec_sha256
        AND receipt.admitted_at = v_admitted_at
        AND receipt.expires_at = v_expires_at
        AND receipt.ranked_sequence_sha256 = v_ranked_sequence_sha256
        AND receipt.query_embedding_sha256 = v_query_embedding_sha256
        AND receipt.result_limit = p_limit
        AND receipt.selected_rank = 1
        AND receipt.selected_evidence_id = v_selected_evidence_id
        AND receipt.selected_evidence_digest = v_selected_evidence_digest;
      IF v_observed_count <> 1 THEN
        RAISE EXCEPTION 'DVI selection receipt conflict'
          USING ERRCODE = '22000';
      END IF;

      RETURN QUERY SELECT
        v_authority_evidence_binding_sha256,
        v_admitted_at,
        v_expires_at,
        v_ranked_sequence_sha256,
        v_query_embedding_sha256,
        p_limit,
        1::INT8,
        v_selected_evidence_id,
      v_selected_evidence_digest;
    END
    $$
  `);

  await client.query(`
    DROP FUNCTION IF EXISTS tp_api.g1_authorize_dvi_proposal_v1(
      UUID, UUID, UUID, UUID, UUID, STRING, STRING, STRING, STRING, JSONB
    )
  `);

  await client.query(`
    CREATE OR REPLACE FUNCTION tp_api.g1_authorize_dvi_proposal_v1(
      p_tenant_id UUID,
      p_retrieval_id UUID,
      p_expected_run_id UUID,
      p_expected_incident_id UUID,
      p_requested_selected_evidence_id UUID,
      p_requested_selected_evidence_digest STRING,
      p_resource_id STRING,
      p_agency STRING,
      p_action_kind STRING,
      p_payload JSONB
    )
    RETURNS TABLE(
      decision_outcome STRING,
      decision_reason STRING,
      decision_proposal_digest STRING,
      decision_logical_action_digest STRING,
      decision_authorization_epoch INT8,
      decision_logical_authority_key_sha256 STRING,
      decision_authorization_binding_sha256 STRING,
      decision_authority_evidence_binding_sha256 STRING,
      decision_run_id UUID,
      decision_incident_id UUID,
      decision_policy_version STRING,
      decision_selected_rank INT8,
      decision_selected_evidence_id UUID,
      decision_selected_evidence_digest STRING,
      decision_admitted_at TIMESTAMPTZ,
      decision_expires_at TIMESTAMPTZ,
      decision_payload_digest STRING,
      decision_authorized_at TIMESTAMPTZ,
      decision_authority_current BOOL,
      decision_database_now TIMESTAMPTZ
    )
    LANGUAGE PLpgSQL
    SECURITY DEFINER
    AS $$
    DECLARE
      v_database_now TIMESTAMPTZ := clock_timestamp();
      v_selection RECORD;
      v_evidence RECORD;
      v_existing RECORD;
      v_epoch RECORD;
      v_authorized_at TIMESTAMPTZ;
      v_payload_canonical STRING;
      v_payload_digest STRING;
      v_logical_action_digest STRING;
      v_proposal_digest STRING;
      v_logical_authority_key_sha256 STRING;
      v_authorization_binding_sha256 STRING;
      v_authorization_epoch INT8;
      v_admitted_at_text STRING;
      v_expires_at_text STRING;
      v_prior_spend_count INT8;
      v_authority_current BOOL;
    BEGIN
      IF session_user <> 'tp_authorizer_user' THEN
        RAISE EXCEPTION 'Gate One authorizer database session required'
          USING ERRCODE = '42501';
      END IF;
      IF p_tenant_id IS NULL
        OR p_retrieval_id IS NULL
        OR p_expected_run_id IS NULL
        OR p_expected_incident_id IS NULL
        OR p_requested_selected_evidence_id IS NULL
        OR p_requested_selected_evidence_digest IS NULL
        OR p_requested_selected_evidence_digest !~ '^[0-9a-f]{64}$'
        OR p_resource_id IS NULL
        OR length(p_resource_id) < 1
        OR length(p_resource_id) > 256
        OR btrim(p_resource_id) IS DISTINCT FROM p_resource_id
        OR p_agency IS NULL
        OR length(p_agency) < 1
        OR length(p_agency) > 128
        OR btrim(p_agency) IS DISTINCT FROM p_agency
        OR p_action_kind IS DISTINCT FROM 'dispatch_rescue_unit'
        OR p_payload IS NULL
        OR jsonb_typeof(p_payload) IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'DVI proposal authorization input outside policy'
          USING ERRCODE = '22023';
      END IF;

      SELECT selection.*
      INTO v_selection
      FROM tp_ledger.g1_dvi_selection_receipts AS selection
      WHERE selection.tenant_id = p_tenant_id
        AND selection.retrieval_id = p_retrieval_id;
      IF NOT FOUND THEN
        RETURN QUERY SELECT
          'proposal_authorization_denied'::STRING,
          'dvi_selection_receipt_missing'::STRING,
          NULL::STRING, NULL::STRING, NULL::INT8,
          NULL::STRING, NULL::STRING, NULL::STRING,
          NULL::UUID, NULL::UUID, NULL::STRING, NULL::INT8,
          NULL::UUID, NULL::STRING, NULL::TIMESTAMPTZ,
          NULL::TIMESTAMPTZ, NULL::STRING, NULL::TIMESTAMPTZ,
          false, v_database_now;
        RETURN;
      END IF;
      IF v_selection.run_id IS DISTINCT FROM p_expected_run_id
        OR v_selection.incident_id IS DISTINCT FROM p_expected_incident_id
        OR v_selection.agency IS DISTINCT FROM p_agency
        OR v_selection.selected_rank IS DISTINCT FROM 1
        OR v_selection.selected_evidence_id IS DISTINCT FROM
          p_requested_selected_evidence_id
        OR v_selection.selected_evidence_digest IS DISTINCT FROM
          p_requested_selected_evidence_digest THEN
        RETURN QUERY SELECT
          'proposal_authorization_denied'::STRING,
          'dvi_selection_request_mismatch'::STRING,
          NULL::STRING, NULL::STRING, NULL::INT8,
          NULL::STRING, NULL::STRING,
          v_selection.authority_evidence_binding_sha256,
          v_selection.run_id, v_selection.incident_id,
          v_selection.policy_version, v_selection.selected_rank,
          v_selection.selected_evidence_id,
          v_selection.selected_evidence_digest,
          v_selection.admitted_at, v_selection.expires_at,
          NULL::STRING, NULL::TIMESTAMPTZ, false, v_database_now;
        RETURN;
      END IF;
      IF v_selection.admitted_at > v_database_now
        OR v_selection.expires_at <= v_database_now THEN
        RETURN QUERY SELECT
          'proposal_authorization_denied'::STRING,
          'dvi_selection_receipt_expired'::STRING,
          NULL::STRING, NULL::STRING, NULL::INT8,
          NULL::STRING, NULL::STRING,
          v_selection.authority_evidence_binding_sha256,
          v_selection.run_id, v_selection.incident_id,
          v_selection.policy_version, v_selection.selected_rank,
          v_selection.selected_evidence_id,
          v_selection.selected_evidence_digest,
          v_selection.admitted_at, v_selection.expires_at,
          NULL::STRING, NULL::TIMESTAMPTZ, false, v_database_now;
        RETURN;
      END IF;

      SELECT listed.*
      INTO v_evidence
      FROM tp_private.g1_list_admissibility_internal_v1(
        p_tenant_id,
        v_selection.incident_id,
        p_agency
      ) AS listed
      WHERE listed.evidence_id = v_selection.selected_evidence_id;
      IF NOT FOUND
        OR v_evidence.admissibility IS DISTINCT FROM 'admissible'
        OR v_evidence.evidence_digest IS DISTINCT FROM
          v_selection.selected_evidence_digest THEN
        RETURN QUERY SELECT
          'proposal_authorization_denied'::STRING,
          CASE
            WHEN NOT FOUND THEN 'selected_evidence_missing'
            WHEN v_evidence.admissibility IS DISTINCT FROM 'admissible'
              THEN 'selected_evidence_not_admissible'
            ELSE 'selected_evidence_digest_mismatch'
          END::STRING,
          NULL::STRING, NULL::STRING, NULL::INT8,
          NULL::STRING, NULL::STRING,
          v_selection.authority_evidence_binding_sha256,
          v_selection.run_id, v_selection.incident_id,
          v_selection.policy_version, v_selection.selected_rank,
          v_selection.selected_evidence_id,
          v_selection.selected_evidence_digest,
          v_selection.admitted_at, v_selection.expires_at,
          NULL::STRING, NULL::TIMESTAMPTZ, false, v_database_now;
        RETURN;
      END IF;

      v_payload_canonical := p_payload::STRING;
      v_payload_digest := encode(
        sha256(v_payload_canonical::BYTES),
        'hex'
      );
      v_logical_action_digest := encode(
        sha256((
          '{"actionKind":' || to_json(p_action_kind)::STRING ||
          ',"agency":' || to_json(p_agency)::STRING ||
          ',"incidentId":"' || v_selection.incident_id::STRING ||
          '","payloadDigest":"' || v_payload_digest ||
          '","resourceId":' || to_json(p_resource_id)::STRING ||
          ',"schemaVersion":"tideproof.authority.logical-action.v1"' ||
          ',"tenantId":"' || p_tenant_id::STRING || '"}'
        )::BYTES),
        'hex'
      );
      v_admitted_at_text := to_char(
        v_selection.admitted_at AT TIME ZONE 'UTC',
        'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
      );
      v_expires_at_text := to_char(
        v_selection.expires_at AT TIME ZONE 'UTC',
        'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
      );
      v_proposal_digest := encode(
        sha256((
          '{"admittedAt":"' || v_admitted_at_text ||
          '","authorityEvidenceBindingSha256":"' ||
          v_selection.authority_evidence_binding_sha256 ||
          '","expiresAt":"' || v_expires_at_text ||
          '","incidentId":"' || v_selection.incident_id::STRING ||
          '","logicalActionDigest":"' || v_logical_action_digest ||
          '","policyVersion":' ||
          to_json(v_selection.policy_version)::STRING ||
          ',"retrievalId":"' || v_selection.retrieval_id::STRING ||
          '","runId":"' || v_selection.run_id::STRING ||
          '","schemaVersion":"tideproof.authority.dvi-proposal-identity.v1"' ||
          ',"selectedEvidenceDigest":"' ||
          v_selection.selected_evidence_digest ||
          '","selectedEvidenceId":"' ||
          v_selection.selected_evidence_id::STRING ||
          '","selectedRank":1' ||
          ',"tenantId":"' || p_tenant_id::STRING || '"}'
        )::BYTES),
        'hex'
      );

      SELECT proposal.*
      INTO v_existing
      FROM tp_ledger.g1_dvi_proposal_receipts AS proposal
      WHERE proposal.tenant_id = p_tenant_id
        AND proposal.proposal_digest = v_proposal_digest;
      IF FOUND THEN
        IF v_existing.logical_action_digest IS DISTINCT FROM
            v_logical_action_digest
          OR v_existing.resource_id IS DISTINCT FROM p_resource_id
          OR v_existing.agency IS DISTINCT FROM p_agency
          OR v_existing.action_kind IS DISTINCT FROM p_action_kind
          OR v_existing.payload_canonical IS DISTINCT FROM
            v_payload_canonical
          OR v_existing.payload_digest IS DISTINCT FROM v_payload_digest
          OR v_existing.retrieval_id IS DISTINCT FROM
            v_selection.retrieval_id
          OR v_existing.run_id IS DISTINCT FROM v_selection.run_id
          OR v_existing.incident_id IS DISTINCT FROM
            v_selection.incident_id
          OR v_existing.authority_evidence_binding_sha256 IS DISTINCT FROM
            v_selection.authority_evidence_binding_sha256
          OR v_existing.selected_evidence_id IS DISTINCT FROM
            v_selection.selected_evidence_id
          OR v_existing.selected_evidence_digest IS DISTINCT FROM
            v_selection.selected_evidence_digest THEN
          RAISE EXCEPTION 'proposal digest matched different durable state'
            USING ERRCODE = '22000';
        END IF;
        SELECT count(*)::INT8
        INTO v_prior_spend_count
        FROM tp_ledger.g1_authority_receipts AS receipt
        WHERE receipt.tenant_id = p_tenant_id
          AND receipt.logical_action_digest =
            v_existing.logical_action_digest
          AND receipt.outcome = 'resource_reserved';
        IF v_prior_spend_count > 0 THEN
          RETURN QUERY SELECT
            'proposal_authorization_denied'::STRING,
            'logical_authority_already_spent'::STRING,
            v_existing.proposal_digest,
            v_existing.logical_action_digest,
            NULL::INT8, NULL::STRING, NULL::STRING,
            v_existing.authority_evidence_binding_sha256,
            v_existing.run_id, v_existing.incident_id,
            v_existing.policy_version, v_existing.selected_rank,
            v_existing.selected_evidence_id,
            v_existing.selected_evidence_digest,
            v_existing.admitted_at, v_existing.expires_at,
            v_existing.payload_digest, NULL::TIMESTAMPTZ,
            false, v_database_now;
          RETURN;
        END IF;
        IF v_existing.expires_at <= v_database_now THEN
          RETURN QUERY SELECT
            'proposal_authorization_denied'::STRING,
            'explicit_new_authorization_required'::STRING,
            v_existing.proposal_digest,
            v_existing.logical_action_digest,
            NULL::INT8, NULL::STRING, NULL::STRING,
            v_existing.authority_evidence_binding_sha256,
            v_existing.run_id, v_existing.incident_id,
            v_existing.policy_version, v_existing.selected_rank,
            v_existing.selected_evidence_id,
            v_existing.selected_evidence_digest,
            v_existing.admitted_at, v_existing.expires_at,
            v_existing.payload_digest, NULL::TIMESTAMPTZ,
            false, v_database_now;
          RETURN;
        END IF;
        v_authority_current := true;
        RETURN QUERY SELECT
          'proposal_authorization_replay'::STRING,
          NULL::STRING,
          v_existing.proposal_digest,
          v_existing.logical_action_digest,
          v_existing.authorization_epoch,
          v_existing.logical_authority_key_sha256,
          v_existing.authorization_binding_sha256,
          v_existing.authority_evidence_binding_sha256,
          v_existing.run_id,
          v_existing.incident_id,
          v_existing.policy_version,
          v_existing.selected_rank,
          v_existing.selected_evidence_id,
          v_existing.selected_evidence_digest,
          v_existing.admitted_at,
          v_existing.expires_at,
          v_existing.payload_digest,
          v_existing.authorized_at,
          v_authority_current,
          v_database_now;
        RETURN;
      END IF;

      INSERT INTO tp_ledger.g1_logical_authority_epochs (
        tenant_id,
        logical_action_digest,
        current_epoch
      ) VALUES (
        p_tenant_id,
        v_logical_action_digest,
        0
      )
      ON CONFLICT DO NOTHING;
      SELECT epoch.*
      INTO v_epoch
      FROM tp_ledger.g1_logical_authority_epochs AS epoch
      WHERE epoch.tenant_id = p_tenant_id
        AND epoch.logical_action_digest = v_logical_action_digest
      FOR UPDATE;
      IF NOT FOUND THEN
        RAISE EXCEPTION 'logical authority epoch lock missing'
          USING ERRCODE = '22000';
      END IF;
      v_database_now := clock_timestamp();
      IF v_selection.expires_at <= v_database_now THEN
        RETURN QUERY SELECT
          'proposal_authorization_denied'::STRING,
          'dvi_selection_receipt_expired'::STRING,
          v_proposal_digest, v_logical_action_digest, NULL::INT8,
          NULL::STRING, NULL::STRING,
          v_selection.authority_evidence_binding_sha256,
          v_selection.run_id, v_selection.incident_id,
          v_selection.policy_version, v_selection.selected_rank,
          v_selection.selected_evidence_id,
          v_selection.selected_evidence_digest,
          v_selection.admitted_at, v_selection.expires_at,
          v_payload_digest, NULL::TIMESTAMPTZ, false, v_database_now;
        RETURN;
      END IF;

      SELECT proposal.*
      INTO v_existing
      FROM tp_ledger.g1_dvi_proposal_receipts AS proposal
      WHERE proposal.tenant_id = p_tenant_id
        AND proposal.proposal_digest = v_proposal_digest;
      IF FOUND THEN
        SELECT count(*)::INT8
        INTO v_prior_spend_count
        FROM tp_ledger.g1_authority_receipts AS receipt
        WHERE receipt.tenant_id = p_tenant_id
          AND receipt.logical_action_digest =
            v_existing.logical_action_digest
          AND receipt.outcome = 'resource_reserved';
        IF v_prior_spend_count > 0 THEN
          RETURN QUERY SELECT
            'proposal_authorization_denied'::STRING,
            'logical_authority_already_spent'::STRING,
            v_existing.proposal_digest,
            v_existing.logical_action_digest,
            NULL::INT8, NULL::STRING, NULL::STRING,
            v_existing.authority_evidence_binding_sha256,
            v_existing.run_id, v_existing.incident_id,
            v_existing.policy_version, v_existing.selected_rank,
            v_existing.selected_evidence_id,
            v_existing.selected_evidence_digest,
            v_existing.admitted_at, v_existing.expires_at,
            v_existing.payload_digest, NULL::TIMESTAMPTZ,
            false, v_database_now;
          RETURN;
        END IF;
        IF v_existing.expires_at <= v_database_now THEN
          RETURN QUERY SELECT
            'proposal_authorization_denied'::STRING,
            'explicit_new_authorization_required'::STRING,
            v_existing.proposal_digest,
            v_existing.logical_action_digest,
            NULL::INT8, NULL::STRING, NULL::STRING,
            v_existing.authority_evidence_binding_sha256,
            v_existing.run_id, v_existing.incident_id,
            v_existing.policy_version, v_existing.selected_rank,
            v_existing.selected_evidence_id,
            v_existing.selected_evidence_digest,
            v_existing.admitted_at, v_existing.expires_at,
            v_existing.payload_digest, NULL::TIMESTAMPTZ,
            false, v_database_now;
          RETURN;
        END IF;
        RETURN QUERY SELECT
          'proposal_authorization_replay'::STRING,
          NULL::STRING,
          v_existing.proposal_digest,
          v_existing.logical_action_digest,
          v_existing.authorization_epoch,
          v_existing.logical_authority_key_sha256,
          v_existing.authorization_binding_sha256,
          v_existing.authority_evidence_binding_sha256,
          v_existing.run_id,
          v_existing.incident_id,
          v_existing.policy_version,
          v_existing.selected_rank,
          v_existing.selected_evidence_id,
          v_existing.selected_evidence_digest,
          v_existing.admitted_at,
          v_existing.expires_at,
          v_existing.payload_digest,
          v_existing.authorized_at,
          true,
          v_database_now;
        RETURN;
      END IF;

      SELECT count(*)::INT8
      INTO v_prior_spend_count
      FROM tp_ledger.g1_authority_receipts AS receipt
      WHERE receipt.tenant_id = p_tenant_id
        AND receipt.logical_action_digest = v_logical_action_digest
        AND receipt.outcome = 'resource_reserved';
      IF v_prior_spend_count > 0 THEN
        RETURN QUERY SELECT
          'proposal_authorization_denied'::STRING,
          'logical_authority_already_spent'::STRING,
          v_proposal_digest, v_logical_action_digest, NULL::INT8,
          NULL::STRING, NULL::STRING,
          v_selection.authority_evidence_binding_sha256,
          v_selection.run_id, v_selection.incident_id,
          v_selection.policy_version, v_selection.selected_rank,
          v_selection.selected_evidence_id,
          v_selection.selected_evidence_digest,
          v_selection.admitted_at, v_selection.expires_at,
          v_payload_digest, NULL::TIMESTAMPTZ, false, v_database_now;
        RETURN;
      END IF;

      IF v_epoch.current_epoch = 1 THEN
        RETURN QUERY SELECT
          'proposal_authorization_denied'::STRING,
          'explicit_new_authorization_required'::STRING,
          v_proposal_digest, v_logical_action_digest, NULL::INT8,
          NULL::STRING, NULL::STRING,
          v_selection.authority_evidence_binding_sha256,
          v_selection.run_id, v_selection.incident_id,
          v_selection.policy_version, v_selection.selected_rank,
          v_selection.selected_evidence_id,
          v_selection.selected_evidence_digest,
          v_selection.admitted_at, v_selection.expires_at,
          v_payload_digest, NULL::TIMESTAMPTZ, false, v_database_now;
        RETURN;
      END IF;
      IF v_epoch.current_epoch <> 0 THEN
        RAISE EXCEPTION
          'authorization epoch advancement requires an explicit new-authorization receipt'
          USING ERRCODE = 'XX000';
      END IF;
      v_authorization_epoch := 1;
      UPDATE tp_ledger.g1_logical_authority_epochs AS epoch
      SET current_epoch = v_authorization_epoch,
          updated_at = v_database_now
      WHERE epoch.tenant_id = p_tenant_id
        AND epoch.logical_action_digest = v_logical_action_digest
        AND epoch.current_epoch = v_epoch.current_epoch;
      IF NOT FOUND THEN
        RAISE EXCEPTION 'logical authority epoch initialization failed'
          USING ERRCODE = '40001';
      END IF;

      v_logical_authority_key_sha256 := encode(
        sha256((
          '{"authorizationEpoch":' || v_authorization_epoch::STRING ||
          ',"logicalActionDigest":"' || v_logical_action_digest ||
          '","schemaVersion":"tideproof.authority.logical-authority-key.v1"}'
        )::BYTES),
        'hex'
      );
      v_authorization_binding_sha256 := encode(
        sha256((
          '{"authorizationEpoch":' || v_authorization_epoch::STRING ||
          ',"logicalActionDigest":"' || v_logical_action_digest ||
          '","logicalAuthorityKeySha256":"' ||
          v_logical_authority_key_sha256 ||
          '","proposalDigest":"' || v_proposal_digest ||
          '","schemaVersion":"tideproof.authority.authorization-binding.v1"}'
        )::BYTES),
        'hex'
      );
      INSERT INTO tp_ledger.g1_dvi_proposal_receipts (
        tenant_id,
        proposal_digest,
        logical_action_digest,
        resource_id,
        agency,
        action_kind,
        payload,
        payload_canonical,
        payload_digest,
        retrieval_id,
        run_id,
        incident_id,
        authority_evidence_binding_sha256,
        policy_version,
        selected_rank,
        selected_evidence_id,
        selected_evidence_digest,
        admitted_at,
        expires_at,
        authorization_epoch,
        logical_authority_key_sha256,
        authorization_binding_sha256
      ) VALUES (
        p_tenant_id,
        v_proposal_digest,
        v_logical_action_digest,
        p_resource_id,
        p_agency,
        p_action_kind,
        p_payload,
        v_payload_canonical,
        v_payload_digest,
        v_selection.retrieval_id,
        v_selection.run_id,
        v_selection.incident_id,
        v_selection.authority_evidence_binding_sha256,
        v_selection.policy_version,
        v_selection.selected_rank,
        v_selection.selected_evidence_id,
        v_selection.selected_evidence_digest,
        v_selection.admitted_at,
        v_selection.expires_at,
        v_authorization_epoch,
        v_logical_authority_key_sha256,
        v_authorization_binding_sha256
      )
      RETURNING authorized_at INTO v_authorized_at;
      IF NOT FOUND THEN
        RAISE EXCEPTION 'proposal authorization receipt insert failed'
          USING ERRCODE = '22000';
      END IF;

      RETURN QUERY SELECT
        'proposal_authorized'::STRING,
        NULL::STRING,
        v_proposal_digest,
        v_logical_action_digest,
        v_authorization_epoch,
        v_logical_authority_key_sha256,
        v_authorization_binding_sha256,
        v_selection.authority_evidence_binding_sha256,
        v_selection.run_id,
        v_selection.incident_id,
        v_selection.policy_version,
        v_selection.selected_rank,
        v_selection.selected_evidence_id,
        v_selection.selected_evidence_digest,
        v_selection.admitted_at,
        v_selection.expires_at,
        v_payload_digest,
        v_authorized_at,
        true,
        v_database_now;
    END
    $$
  `);

  await client.query(`
    CREATE OR REPLACE FUNCTION tp_private.g1_authority_receipt_current_v1(
      p_tenant_id UUID,
      p_operation_id UUID
    )
    RETURNS BOOL
    LANGUAGE PLpgSQL
    SECURITY DEFINER
    AS $$
    BEGIN
      IF session_user NOT IN (
        'tp_authorizer_user',
        'tp_gate2_authorizer_user'
      ) THEN
        RAISE EXCEPTION 'authorizer database session required'
          USING ERRCODE = '42501';
      END IF;
      RETURN COALESCE((
        SELECT
          receipt.outcome = 'resource_reserved'
          AND receipt.fencing_token = resource.current_fence
          AND receipt.run_id = resource.active_run_id
          AND receipt.operation_id = resource.holder_operation_id
          AND receipt.proposal_digest = resource.holder_proposal_digest
          AND receipt.logical_authority_key_sha256 =
            resource.holder_logical_authority_key_sha256
          AND outbox.request_digest = receipt.request_digest
          AND outbox.proposal_digest = receipt.proposal_digest
          AND outbox.logical_action_digest = receipt.logical_action_digest
          AND outbox.authorization_epoch = receipt.authorization_epoch
          AND outbox.logical_authority_key_sha256 =
            receipt.logical_authority_key_sha256
          AND outbox.authorization_binding_sha256 =
            receipt.authorization_binding_sha256
          AND outbox.run_id = receipt.run_id
          AND outbox.incident_id = receipt.incident_id
          AND outbox.resource_id = receipt.resource_id
          AND outbox.fencing_token = receipt.fencing_token
          AND outbox.effect_key = receipt.effect_key
          AND outbox.intent_kind = 'dispatch_rescue_unit'
          AND outbox.payload_digest = receipt.payload_digest
          AND proposal.payload = outbox.payload
          AND proposal.payload_digest = outbox.payload_digest
          AND encode(
            sha256(proposal.payload_canonical::BYTES),
            'hex'
          ) = outbox.payload_digest
          AND receipt.lease_expires_at > statement_timestamp()
          AND resource.lease_expires_at > statement_timestamp()
          AND proposal.expires_at > statement_timestamp()
        FROM tp_ledger.g1_authority_receipts AS receipt
        JOIN tp_private.g1_resources AS resource
          ON resource.tenant_id = receipt.tenant_id
         AND resource.resource_id = receipt.resource_id
        JOIN tp_ledger.g1_outbox_intents AS outbox
          ON outbox.tenant_id = receipt.tenant_id
         AND outbox.operation_id = receipt.operation_id
        JOIN tp_ledger.g1_dvi_proposal_receipts AS proposal
          ON proposal.tenant_id = receipt.tenant_id
         AND proposal.proposal_digest = receipt.proposal_digest
        WHERE receipt.tenant_id = p_tenant_id
          AND receipt.operation_id = p_operation_id
      ), false);
    END
    $$
  `);

  await client.query(`
    DROP FUNCTION IF EXISTS tp_api.g1_spend_authority_v1(
      UUID, UUID, STRING, JSONB, UUID, UUID, STRING, STRING, STRING,
      UUID, UUID, JSONB, STRING, STRING, INT8
    )
  `);

  await client.query(`
    DROP FUNCTION IF EXISTS tp_api.g1_spend_authority_v1(
      UUID, UUID, STRING, JSONB, STRING, STRING, STRING, UUID, UUID,
      STRING, STRING, STRING, UUID, UUID, JSONB, STRING, STRING, INT8
    )
  `);

  await client.query(`
    DROP FUNCTION IF EXISTS tp_api.g1_spend_authority_v1(
      UUID, UUID, STRING, JSONB, UUID, UUID, STRING, STRING, STRING, STRING,
      UUID, UUID, JSONB, STRING, STRING, INT8
    )
  `);

  await client.query(`
    CREATE OR REPLACE FUNCTION tp_api.g1_spend_authority_v1(
      p_tenant_id UUID,
      p_operation_id UUID,
      p_request_digest STRING,
      p_request_payload JSONB,
      p_proposal_digest STRING,
      p_logical_action_digest STRING,
      p_selected_evidence_digest STRING,
      p_run_id UUID,
      p_incident_id UUID,
      p_resource_id STRING,
      p_agent_id STRING,
      p_agency STRING,
      p_evidence_id UUID,
      p_effect_key UUID,
      p_payload JSONB,
      p_payload_digest STRING,
      p_policy_version STRING,
      p_lease_ms INT8
    )
    RETURNS TABLE(
      decision_outcome STRING,
      decision_reason STRING,
      decision_fencing_token INT8,
      decision_lease_expires_at TIMESTAMPTZ,
      decision_operation_id UUID,
      decision_request_digest STRING,
      decision_replay_kind STRING,
      decision_proposal_digest STRING,
      decision_logical_action_digest STRING,
      decision_authorization_epoch INT8,
      decision_logical_authority_key_sha256 STRING,
      decision_authorization_binding_sha256 STRING,
      decision_authority_current BOOL,
      decision_database_now TIMESTAMPTZ
    )
    LANGUAGE PLpgSQL
    SECURITY DEFINER
    AS $$
    DECLARE
      v_existing_digest STRING;
      v_existing_outcome STRING;
      v_existing_reason STRING;
      v_existing_fence INT8;
      v_existing_expiry TIMESTAMPTZ;
      v_existing_operation UUID;
      v_admissibility STRING;
      v_evidence_digest STRING;
      v_active_run UUID;
      v_current_fence INT8;
      v_holder_operation UUID;
      v_holder_expiry TIMESTAMPTZ;
      v_new_fence INT8;
      v_new_expiry TIMESTAMPTZ;
      v_inserted_operation UUID;
      v_existing_count INT8;
      v_replay_kind STRING;
      v_request_field_count INT8;
      v_authorization_epoch INT8;
      v_current_authorization_epoch INT8;
      v_logical_authority_key_sha256 STRING;
      v_authorization_binding_sha256 STRING;
      v_payload_canonical STRING;
      v_expected_payload_digest STRING;
      v_expected_logical_action_digest STRING;
      v_expected_request_digest STRING;
      v_existing_request_payload JSONB;
      v_existing_proposal_digest STRING;
      v_existing_logical_action_digest STRING;
      v_existing_authorization_epoch INT8;
      v_existing_logical_authority_key_sha256 STRING;
      v_existing_authorization_binding_sha256 STRING;
      v_proposal_expires_at TIMESTAMPTZ;
      v_database_now TIMESTAMPTZ := clock_timestamp();
    BEGIN
      IF session_user NOT IN (
        'tp_authorizer_user',
        'tp_gate2_authorizer_user'
      ) THEN
        RAISE EXCEPTION 'authorizer database session required'
          USING ERRCODE = '42501';
      END IF;
      IF p_request_digest IS NULL
        OR p_request_digest !~ '^[0-9a-f]{64}$'
        OR p_payload_digest IS NULL
        OR p_payload_digest !~ '^[0-9a-f]{64}$'
        OR p_proposal_digest IS NULL
        OR p_proposal_digest !~ '^[0-9a-f]{64}$'
        OR p_logical_action_digest IS NULL
        OR p_logical_action_digest !~ '^[0-9a-f]{64}$'
        OR p_selected_evidence_digest IS NULL
        OR p_selected_evidence_digest !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'digest must be SHA-256 hex'
          USING ERRCODE = '22023';
      END IF;
      IF p_lease_ms IS NULL OR p_lease_ms < 1000 OR p_lease_ms > 600000 THEN
        RAISE EXCEPTION 'lease duration outside policy'
          USING ERRCODE = '22023';
      END IF;
      IF p_request_payload IS NULL
        OR jsonb_typeof(p_request_payload) IS DISTINCT FROM 'object'
        OR p_payload IS NULL
        OR jsonb_typeof(p_payload) IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'authority request payload must be an object'
          USING ERRCODE = '22023';
      END IF;
      v_request_field_count := jsonb_object_length(p_request_payload)::INT8;
      IF v_request_field_count IS DISTINCT FROM 18
        OR p_request_payload->>'digestVersion' IS DISTINCT FROM '2'
        OR p_request_payload->>'tenantId' IS DISTINCT FROM p_tenant_id::STRING
        OR p_request_payload->>'runId' IS DISTINCT FROM p_run_id::STRING
        OR p_request_payload->>'incidentId' IS DISTINCT FROM p_incident_id::STRING
        OR p_request_payload->>'resourceId' IS DISTINCT FROM p_resource_id
        OR p_request_payload->>'agentId' IS DISTINCT FROM p_agent_id
        OR p_request_payload->>'agency' IS DISTINCT FROM p_agency
        OR p_request_payload->>'evidenceId' IS DISTINCT FROM p_evidence_id::STRING
        OR p_request_payload->>'effectKey' IS DISTINCT FROM p_effect_key::STRING
        OR p_request_payload->>'leaseMs' IS DISTINCT FROM p_lease_ms::STRING
        OR p_request_payload->>'policyVersion' IS DISTINCT FROM p_policy_version
        OR p_request_payload->>'actionKind' IS DISTINCT FROM 'dispatch_rescue_unit'
        OR p_request_payload->>'payloadDigest' IS DISTINCT FROM p_payload_digest
        OR p_request_payload->>'logicalActionDigest' IS DISTINCT FROM
          p_logical_action_digest
        OR p_request_payload->>'proposalDigest' IS DISTINCT FROM p_proposal_digest
        OR p_request_payload->>'selectedEvidenceId' IS DISTINCT FROM
          p_evidence_id::STRING
        OR p_request_payload->>'selectedEvidenceDigest' IS DISTINCT FROM
          p_selected_evidence_digest
        OR p_request_payload->>'intentNonce' IS NULL
        OR p_request_payload->>'intentNonce' !~
          '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
        OR p_payload->>'action' IS DISTINCT FROM 'dispatch_rescue_unit'
        OR p_policy_version IS DISTINCT FROM 'gate1-policy-v2' THEN
        RAISE EXCEPTION 'authority request identity binding mismatch'
          USING ERRCODE = '22023';
      END IF;

      v_authorization_epoch := NULL;
      SELECT
        proposal.authorization_epoch,
        proposal.logical_authority_key_sha256,
        proposal.authorization_binding_sha256,
        proposal.payload_canonical,
        proposal.expires_at
      INTO
        v_authorization_epoch,
        v_logical_authority_key_sha256,
        v_authorization_binding_sha256,
        v_payload_canonical,
        v_proposal_expires_at
      FROM tp_ledger.g1_dvi_proposal_receipts AS proposal
      WHERE proposal.tenant_id = p_tenant_id
        AND proposal.proposal_digest = p_proposal_digest
        AND proposal.logical_action_digest = p_logical_action_digest
        AND proposal.run_id = p_run_id
        AND proposal.incident_id = p_incident_id
        AND proposal.resource_id = p_resource_id
        AND proposal.agency = p_agency
        AND proposal.action_kind = 'dispatch_rescue_unit'
        AND proposal.payload = p_payload
        AND proposal.payload_digest = p_payload_digest
        AND proposal.selected_evidence_id = p_evidence_id
        AND proposal.selected_evidence_digest = p_selected_evidence_digest
        AND proposal.selected_rank = 1;
      IF v_authorization_epoch IS NULL THEN
        RETURN QUERY SELECT
          'authorization_denied'::STRING,
          'proposal_authorization_missing_or_stale'::STRING,
          NULL::INT8,
          NULL::TIMESTAMPTZ,
          p_operation_id,
          p_request_digest,
          NULL::STRING,
          p_proposal_digest,
          p_logical_action_digest,
          NULL::INT8,
          NULL::STRING,
          NULL::STRING,
          false,
          v_database_now;
        RETURN;
      END IF;

      v_expected_payload_digest := encode(
        sha256(v_payload_canonical::BYTES),
        'hex'
      );
      v_expected_logical_action_digest := encode(
        sha256((
          '{"actionKind":"dispatch_rescue_unit","agency":' ||
          to_json(p_agency)::STRING ||
          ',"incidentId":"' || p_incident_id::STRING ||
          '","payloadDigest":"' || v_expected_payload_digest ||
          '","resourceId":' || to_json(p_resource_id)::STRING ||
          ',"schemaVersion":"tideproof.authority.logical-action.v1"' ||
          ',"tenantId":"' || p_tenant_id::STRING || '"}'
        )::BYTES),
        'hex'
      );
      v_expected_request_digest := encode(
        sha256((
          '{"actionKind":"dispatch_rescue_unit","agency":' ||
          to_json(p_agency)::STRING ||
          ',"agentId":' || to_json(p_agent_id)::STRING ||
          ',"digestVersion":2' ||
          ',"effectKey":"' || p_effect_key::STRING ||
          '","evidenceId":"' || p_evidence_id::STRING ||
          '","incidentId":"' || p_incident_id::STRING ||
          '","intentNonce":' ||
          to_json(p_request_payload->>'intentNonce')::STRING ||
          ',"leaseMs":' || p_lease_ms::STRING ||
          ',"logicalActionDigest":"' ||
          v_expected_logical_action_digest ||
          '","payloadDigest":"' || v_expected_payload_digest ||
          '","policyVersion":' || to_json(p_policy_version)::STRING ||
          ',"proposalDigest":"' || p_proposal_digest ||
          '","resourceId":' || to_json(p_resource_id)::STRING ||
          ',"runId":"' || p_run_id::STRING ||
          '","selectedEvidenceDigest":"' ||
          p_selected_evidence_digest ||
          '","selectedEvidenceId":"' || p_evidence_id::STRING ||
          '","tenantId":"' || p_tenant_id::STRING || '"}'
        )::BYTES),
        'hex'
      );
      IF v_expected_payload_digest IS DISTINCT FROM p_payload_digest
        OR v_expected_logical_action_digest IS DISTINCT FROM
          p_logical_action_digest
        OR v_expected_request_digest IS DISTINCT FROM p_request_digest THEN
        RAISE EXCEPTION 'database-derived authority identity mismatch'
          USING ERRCODE = '22023';
      END IF;

      v_current_authorization_epoch := NULL;
      SELECT epoch.current_epoch
      INTO v_current_authorization_epoch
      FROM tp_ledger.g1_logical_authority_epochs AS epoch
      WHERE epoch.tenant_id = p_tenant_id
        AND epoch.logical_action_digest = p_logical_action_digest
      FOR UPDATE;
      IF v_current_authorization_epoch IS NULL THEN
        RAISE EXCEPTION 'logical authority epoch lock missing'
          USING ERRCODE = 'XX000';
      END IF;
      v_database_now := clock_timestamp();

      SELECT count(*)::INT8
      INTO v_existing_count
      FROM tp_ledger.g1_authority_receipts AS receipt
      WHERE receipt.tenant_id = p_tenant_id
        AND receipt.operation_id = p_operation_id;
      IF v_existing_count > 0 THEN
        SELECT
        receipt.request_digest,
        receipt.outcome,
        receipt.reason,
        receipt.fencing_token,
        receipt.lease_expires_at,
        receipt.operation_id,
        receipt.request_payload,
        receipt.proposal_digest,
        receipt.logical_action_digest,
        receipt.authorization_epoch,
        receipt.logical_authority_key_sha256,
        receipt.authorization_binding_sha256
      INTO
        v_existing_digest,
        v_existing_outcome,
        v_existing_reason,
        v_existing_fence,
        v_existing_expiry,
        v_existing_operation,
        v_existing_request_payload,
        v_existing_proposal_digest,
        v_existing_logical_action_digest,
        v_existing_authorization_epoch,
        v_existing_logical_authority_key_sha256,
        v_existing_authorization_binding_sha256
        FROM tp_ledger.g1_authority_receipts AS receipt
        WHERE receipt.tenant_id = p_tenant_id
          AND receipt.operation_id = p_operation_id;
        IF v_existing_digest <> p_request_digest
          OR v_existing_request_payload <> p_request_payload THEN
          RAISE EXCEPTION 'operation digest mismatch'
            USING ERRCODE = '22000';
        END IF;
        IF v_existing_outcome = 'pending' THEN
          RAISE EXCEPTION 'committed pending receipt invariant'
            USING ERRCODE = 'XX000';
        END IF;
        RETURN QUERY SELECT
          v_existing_outcome,
          v_existing_reason,
          v_existing_fence,
          v_existing_expiry,
          v_existing_operation,
          v_existing_digest,
          'operation_replay'::STRING,
          v_existing_proposal_digest,
          v_existing_logical_action_digest,
          v_existing_authorization_epoch,
          v_existing_logical_authority_key_sha256,
          v_existing_authorization_binding_sha256,
          tp_private.g1_authority_receipt_current_v1(
            p_tenant_id,
            v_existing_operation
          ),
          v_database_now;
        RETURN;
      END IF;

      SELECT count(*)::INT8
      INTO v_existing_count
      FROM tp_ledger.g1_authority_receipts AS receipt
      WHERE receipt.tenant_id = p_tenant_id
        AND receipt.logical_action_digest = p_logical_action_digest
        AND receipt.outcome = 'resource_reserved';
      IF v_existing_count > 0 THEN
        IF v_existing_count <> 1 THEN
          RAISE EXCEPTION 'logical authority spend was not singular'
            USING ERRCODE = 'XX000';
        END IF;
        SELECT
          receipt.request_digest,
          receipt.outcome,
          receipt.reason,
          receipt.fencing_token,
          receipt.lease_expires_at,
          receipt.operation_id,
          receipt.proposal_digest,
          receipt.logical_action_digest,
          receipt.authorization_epoch,
          receipt.logical_authority_key_sha256,
          receipt.authorization_binding_sha256
        INTO
          v_existing_digest,
          v_existing_outcome,
          v_existing_reason,
          v_existing_fence,
          v_existing_expiry,
          v_existing_operation,
          v_existing_proposal_digest,
          v_existing_logical_action_digest,
          v_existing_authorization_epoch,
          v_existing_logical_authority_key_sha256,
          v_existing_authorization_binding_sha256
        FROM tp_ledger.g1_authority_receipts AS receipt
        WHERE receipt.tenant_id = p_tenant_id
          AND receipt.logical_action_digest = p_logical_action_digest
          AND receipt.outcome = 'resource_reserved';
        IF v_existing_logical_action_digest <> p_logical_action_digest THEN
          RAISE EXCEPTION 'logical authority replay identity mismatch'
            USING ERRCODE = 'XX000';
        END IF;
        RETURN QUERY SELECT
          v_existing_outcome,
          v_existing_reason,
          v_existing_fence,
          v_existing_expiry,
          v_existing_operation,
          v_existing_digest,
          'logical_authority_replay'::STRING,
          v_existing_proposal_digest,
          v_existing_logical_action_digest,
          v_existing_authorization_epoch,
          v_existing_logical_authority_key_sha256,
          v_existing_authorization_binding_sha256,
          tp_private.g1_authority_receipt_current_v1(
            p_tenant_id,
            v_existing_operation
          ),
          v_database_now;
        RETURN;
      END IF;

      SELECT count(*)::INT8
      INTO v_existing_count
      FROM tp_ledger.g1_authority_receipts AS receipt
      WHERE receipt.tenant_id = p_tenant_id
        AND receipt.request_digest = p_request_digest;
      IF v_existing_count > 0 THEN
        SELECT
        receipt.request_digest,
        receipt.outcome,
        receipt.reason,
        receipt.fencing_token,
        receipt.lease_expires_at,
        receipt.operation_id,
        receipt.request_payload,
        receipt.proposal_digest,
        receipt.logical_action_digest,
        receipt.authorization_epoch,
        receipt.logical_authority_key_sha256,
        receipt.authorization_binding_sha256
      INTO
        v_existing_digest,
        v_existing_outcome,
        v_existing_reason,
        v_existing_fence,
        v_existing_expiry,
        v_existing_operation,
        v_existing_request_payload,
        v_existing_proposal_digest,
        v_existing_logical_action_digest,
        v_existing_authorization_epoch,
        v_existing_logical_authority_key_sha256,
        v_existing_authorization_binding_sha256
        FROM tp_ledger.g1_authority_receipts AS receipt
        WHERE receipt.tenant_id = p_tenant_id
          AND receipt.request_digest = p_request_digest;
        IF v_existing_request_payload <> p_request_payload THEN
          RAISE EXCEPTION 'semantic request payload mismatch'
            USING ERRCODE = '22000';
        END IF;
        IF v_existing_outcome = 'pending' THEN
          RAISE EXCEPTION 'committed pending receipt invariant'
            USING ERRCODE = 'XX000';
        END IF;
        RETURN QUERY SELECT
          v_existing_outcome,
          v_existing_reason,
          v_existing_fence,
          v_existing_expiry,
          v_existing_operation,
          v_existing_digest,
          'semantic_replay'::STRING,
          v_existing_proposal_digest,
          v_existing_logical_action_digest,
          v_existing_authorization_epoch,
          v_existing_logical_authority_key_sha256,
          v_existing_authorization_binding_sha256,
          tp_private.g1_authority_receipt_current_v1(
            p_tenant_id,
            v_existing_operation
          ),
          v_database_now;
        RETURN;
      END IF;

      IF v_current_authorization_epoch IS DISTINCT FROM
          v_authorization_epoch THEN
        RETURN QUERY SELECT
          'authorization_denied'::STRING,
          'proposal_authorization_superseded'::STRING,
          NULL::INT8,
          NULL::TIMESTAMPTZ,
          p_operation_id,
          p_request_digest,
          NULL::STRING,
          p_proposal_digest,
          p_logical_action_digest,
          v_authorization_epoch,
          v_logical_authority_key_sha256,
          v_authorization_binding_sha256,
          false,
          v_database_now;
        RETURN;
      END IF;

      IF v_proposal_expires_at <= v_database_now THEN
        RETURN QUERY SELECT
          'authorization_denied'::STRING,
          'proposal_authorization_expired'::STRING,
          NULL::INT8,
          NULL::TIMESTAMPTZ,
          p_operation_id,
          p_request_digest,
          NULL::STRING,
          p_proposal_digest,
          p_logical_action_digest,
          v_authorization_epoch,
          v_logical_authority_key_sha256,
          v_authorization_binding_sha256,
          false,
          v_database_now;
        RETURN;
      END IF;

      INSERT INTO tp_ledger.g1_authority_receipts (
        tenant_id,
        operation_id,
        request_digest,
        request_payload,
        proposal_digest,
        logical_action_digest,
        authorization_epoch,
        logical_authority_key_sha256,
        authorization_binding_sha256,
        run_id,
        incident_id,
        resource_id,
        agent_id,
        agency,
        evidence_id,
        effect_key,
        payload_digest,
        policy_version,
        outcome
      )
      VALUES (
        p_tenant_id,
        p_operation_id,
        p_request_digest,
        p_request_payload,
        p_proposal_digest,
        p_logical_action_digest,
        v_authorization_epoch,
        v_logical_authority_key_sha256,
        v_authorization_binding_sha256,
        p_run_id,
        p_incident_id,
        p_resource_id,
        p_agent_id,
        p_agency,
        p_evidence_id,
        p_effect_key,
        p_payload_digest,
        p_policy_version,
        'pending'
      )
      ON CONFLICT DO NOTHING
      RETURNING operation_id INTO v_inserted_operation;
      IF v_inserted_operation IS NULL THEN
        SELECT count(*)::INT8
        INTO v_existing_count
        FROM tp_ledger.g1_authority_receipts AS receipt
        WHERE receipt.tenant_id = p_tenant_id
          AND (
            receipt.operation_id = p_operation_id
            OR receipt.request_digest = p_request_digest
            OR (
              receipt.logical_action_digest = p_logical_action_digest
              AND receipt.outcome = 'resource_reserved'
            )
          );
        IF v_existing_count <> 1 THEN
          RAISE EXCEPTION 'receipt conflict was not singular'
            USING ERRCODE = 'XX000';
        END IF;
        SELECT
          receipt.outcome,
          receipt.reason,
          receipt.fencing_token,
          receipt.lease_expires_at,
          receipt.operation_id,
          receipt.request_digest,
          receipt.request_payload,
          receipt.proposal_digest,
          receipt.logical_action_digest,
          receipt.authorization_epoch,
          receipt.logical_authority_key_sha256,
          receipt.authorization_binding_sha256
        INTO
          v_existing_outcome,
          v_existing_reason,
          v_existing_fence,
          v_existing_expiry,
          v_existing_operation,
          v_existing_digest,
          v_existing_request_payload,
          v_existing_proposal_digest,
          v_existing_logical_action_digest,
          v_existing_authorization_epoch,
          v_existing_logical_authority_key_sha256,
          v_existing_authorization_binding_sha256
        FROM tp_ledger.g1_authority_receipts AS receipt
        WHERE receipt.tenant_id = p_tenant_id
          AND (
            receipt.operation_id = p_operation_id
            OR receipt.request_digest = p_request_digest
            OR (
              receipt.logical_action_digest = p_logical_action_digest
              AND receipt.outcome = 'resource_reserved'
            )
          )
        LIMIT 2;
        IF v_existing_outcome = 'pending' THEN
          RAISE EXCEPTION 'receipt conflict was not terminal'
            USING ERRCODE = 'XX000';
        END IF;
        IF v_existing_operation = p_operation_id THEN
          v_replay_kind := 'operation_replay';
        ELSIF v_existing_digest = p_request_digest THEN
          v_replay_kind := 'semantic_replay';
        ELSE
          v_replay_kind := 'logical_authority_replay';
        END IF;
        IF v_replay_kind IN ('operation_replay', 'semantic_replay')
          AND v_existing_request_payload <> p_request_payload THEN
          RAISE EXCEPTION 'receipt replay payload mismatch'
            USING ERRCODE = '22000';
        END IF;
        IF v_existing_logical_action_digest <> p_logical_action_digest
          OR (
            v_replay_kind <> 'logical_authority_replay'
            AND (
              v_existing_authorization_epoch <> v_authorization_epoch
              OR v_existing_logical_authority_key_sha256 <>
                v_logical_authority_key_sha256
            )
          ) THEN
          RAISE EXCEPTION 'receipt replay logical identity mismatch'
            USING ERRCODE = 'XX000';
        END IF;
        RETURN QUERY SELECT
          v_existing_outcome,
          v_existing_reason,
          v_existing_fence,
          v_existing_expiry,
          v_existing_operation,
          v_existing_digest,
          v_replay_kind,
          v_existing_proposal_digest,
          v_existing_logical_action_digest,
          v_existing_authorization_epoch,
          v_existing_logical_authority_key_sha256,
          v_existing_authorization_binding_sha256,
          tp_private.g1_authority_receipt_current_v1(
            p_tenant_id,
            v_existing_operation
          ),
          v_database_now;
        RETURN;
      END IF;

      v_admissibility := NULL;
      SELECT observed.admissibility, observed.evidence_digest
      INTO v_admissibility, v_evidence_digest
      FROM tp_api.g1_observe_admissibility_v2(
        p_tenant_id,
        p_evidence_id,
        p_incident_id,
        p_agency
      ) AS observed;
      IF v_admissibility IS NULL THEN
        v_admissibility := 'evidence_missing';
      END IF;
      IF v_admissibility <> 'admissible' THEN
        UPDATE tp_ledger.g1_authority_receipts AS receipt
        SET outcome = 'authorization_denied',
            reason = v_admissibility,
            evidence_digest = v_evidence_digest
        WHERE receipt.tenant_id = p_tenant_id
          AND receipt.operation_id = p_operation_id;
        RETURN QUERY SELECT
          'authorization_denied'::STRING,
          v_admissibility,
          NULL::INT8,
          NULL::TIMESTAMPTZ,
          p_operation_id,
          p_request_digest,
          NULL::STRING,
          p_proposal_digest,
          p_logical_action_digest,
          v_authorization_epoch,
          v_logical_authority_key_sha256,
          v_authorization_binding_sha256,
          false,
          v_database_now;
        RETURN;
      END IF;
      IF v_evidence_digest <> p_selected_evidence_digest THEN
        UPDATE tp_ledger.g1_authority_receipts AS receipt
        SET outcome = 'authorization_denied',
            reason = 'selected_evidence_digest_mismatch',
            evidence_digest = v_evidence_digest
        WHERE receipt.tenant_id = p_tenant_id
          AND receipt.operation_id = p_operation_id;
        RETURN QUERY SELECT
          'authorization_denied'::STRING,
          'selected_evidence_digest_mismatch'::STRING,
          NULL::INT8,
          NULL::TIMESTAMPTZ,
          p_operation_id,
          p_request_digest,
          NULL::STRING,
          p_proposal_digest,
          p_logical_action_digest,
          v_authorization_epoch,
          v_logical_authority_key_sha256,
          v_authorization_binding_sha256,
          false,
          v_database_now;
        RETURN;
      END IF;

      v_active_run := NULL;
      SELECT
        resource.active_run_id,
        resource.current_fence,
        resource.holder_operation_id,
        resource.lease_expires_at
      INTO
        v_active_run,
        v_current_fence,
        v_holder_operation,
        v_holder_expiry
      FROM tp_private.g1_resources AS resource
      WHERE resource.tenant_id = p_tenant_id
        AND resource.resource_id = p_resource_id
      FOR UPDATE;
      IF v_active_run IS NULL THEN
        UPDATE tp_ledger.g1_authority_receipts AS receipt
        SET outcome = 'authorization_denied',
            reason = 'resource_missing',
            evidence_digest = v_evidence_digest
        WHERE receipt.tenant_id = p_tenant_id
          AND receipt.operation_id = p_operation_id;
        RETURN QUERY SELECT
          'authorization_denied'::STRING,
          'resource_missing'::STRING,
          NULL::INT8,
          NULL::TIMESTAMPTZ,
          p_operation_id,
          p_request_digest,
          NULL::STRING,
          p_proposal_digest,
          p_logical_action_digest,
          v_authorization_epoch,
          v_logical_authority_key_sha256,
          v_authorization_binding_sha256,
          false,
          v_database_now;
        RETURN;
      END IF;
      v_database_now := clock_timestamp();
      IF v_active_run <> p_run_id THEN
        UPDATE tp_ledger.g1_authority_receipts AS receipt
        SET outcome = 'authorization_denied',
            reason = 'inactive_run',
            evidence_digest = v_evidence_digest
        WHERE receipt.tenant_id = p_tenant_id
          AND receipt.operation_id = p_operation_id;
        RETURN QUERY SELECT
          'authorization_denied'::STRING,
          'inactive_run'::STRING,
          NULL::INT8,
          NULL::TIMESTAMPTZ,
          p_operation_id,
          p_request_digest,
          NULL::STRING,
          p_proposal_digest,
          p_logical_action_digest,
          v_authorization_epoch,
          v_logical_authority_key_sha256,
          v_authorization_binding_sha256,
          false,
          v_database_now;
        RETURN;
      END IF;
      IF v_proposal_expires_at <= v_database_now THEN
        UPDATE tp_ledger.g1_authority_receipts AS receipt
        SET outcome = 'authorization_denied',
            reason = 'proposal_authorization_expired',
            evidence_digest = v_evidence_digest
        WHERE receipt.tenant_id = p_tenant_id
          AND receipt.operation_id = p_operation_id;
        RETURN QUERY SELECT
          'authorization_denied'::STRING,
          'proposal_authorization_expired'::STRING,
          NULL::INT8,
          NULL::TIMESTAMPTZ,
          p_operation_id,
          p_request_digest,
          NULL::STRING,
          p_proposal_digest,
          p_logical_action_digest,
          v_authorization_epoch,
          v_logical_authority_key_sha256,
          v_authorization_binding_sha256,
          false,
          v_database_now;
        RETURN;
      END IF;
      IF v_holder_operation IS NOT NULL
        AND v_holder_expiry > v_database_now THEN
        UPDATE tp_ledger.g1_authority_receipts AS receipt
        SET outcome = 'resource_held_denied',
            reason = 'active_holder',
            evidence_digest = v_evidence_digest,
            observed_holder_operation_id = v_holder_operation,
            observed_fence = v_current_fence
        WHERE receipt.tenant_id = p_tenant_id
          AND receipt.operation_id = p_operation_id;
        RETURN QUERY SELECT
          'resource_held_denied'::STRING,
          'active_holder'::STRING,
          NULL::INT8,
          NULL::TIMESTAMPTZ,
          p_operation_id,
          p_request_digest,
          NULL::STRING,
          p_proposal_digest,
          p_logical_action_digest,
          v_authorization_epoch,
          v_logical_authority_key_sha256,
          v_authorization_binding_sha256,
          false,
          v_database_now;
        RETURN;
      END IF;

      v_new_fence := NULL;
      UPDATE tp_private.g1_resources AS resource
      SET current_fence = resource.current_fence + 1,
          holder_incident_id = p_incident_id,
          holder_operation_id = p_operation_id,
          holder_agent_id = p_agent_id,
          holder_proposal_digest = p_proposal_digest,
          holder_logical_authority_key_sha256 =
            v_logical_authority_key_sha256,
          lease_expires_at =
            v_database_now +
            (p_lease_ms * INTERVAL '1 millisecond'),
          updated_at = v_database_now
      WHERE resource.tenant_id = p_tenant_id
        AND resource.resource_id = p_resource_id
        AND resource.active_run_id = p_run_id
        AND resource.current_fence < 9223372036854775807
        AND (
          resource.holder_operation_id IS NULL
          OR resource.lease_expires_at <= v_database_now
        )
        AND EXISTS (
          SELECT 1
          FROM tp_ledger.g1_dvi_proposal_receipts AS proposal
          WHERE proposal.tenant_id = p_tenant_id
            AND proposal.proposal_digest = p_proposal_digest
            AND proposal.logical_action_digest = p_logical_action_digest
            AND proposal.authorization_epoch = v_authorization_epoch
            AND proposal.logical_authority_key_sha256 =
              v_logical_authority_key_sha256
            AND proposal.authorization_binding_sha256 =
              v_authorization_binding_sha256
            AND proposal.expires_at > clock_timestamp()
        )
      RETURNING resource.current_fence, resource.lease_expires_at
      INTO v_new_fence, v_new_expiry;
      IF v_new_fence IS NULL THEN
        v_database_now := clock_timestamp();
        IF v_proposal_expires_at <= v_database_now THEN
          UPDATE tp_ledger.g1_authority_receipts AS receipt
          SET outcome = 'authorization_denied',
              reason = 'proposal_authorization_expired',
              evidence_digest = v_evidence_digest
          WHERE receipt.tenant_id = p_tenant_id
            AND receipt.operation_id = p_operation_id;
          RETURN QUERY SELECT
            'authorization_denied'::STRING,
            'proposal_authorization_expired'::STRING,
            NULL::INT8,
            NULL::TIMESTAMPTZ,
            p_operation_id,
            p_request_digest,
            NULL::STRING,
            p_proposal_digest,
            p_logical_action_digest,
            v_authorization_epoch,
            v_logical_authority_key_sha256,
            v_authorization_binding_sha256,
            false,
            v_database_now;
          RETURN;
        END IF;
        RAISE EXCEPTION 'resource acquisition invariant'
          USING ERRCODE = 'XX000';
      END IF;

      UPDATE tp_ledger.g1_authority_receipts AS receipt
      SET outcome = 'resource_reserved',
          evidence_digest = v_evidence_digest,
          fencing_token = v_new_fence,
          lease_expires_at = v_new_expiry
      WHERE receipt.tenant_id = p_tenant_id
        AND receipt.operation_id = p_operation_id;

      INSERT INTO tp_ledger.g1_outbox_intents (
        tenant_id,
        operation_id,
        request_digest,
        proposal_digest,
        logical_action_digest,
        authorization_epoch,
        logical_authority_key_sha256,
        authorization_binding_sha256,
        run_id,
        incident_id,
        resource_id,
        fencing_token,
        effect_key,
        intent_kind,
        payload,
        payload_digest
      )
      VALUES (
        p_tenant_id,
        p_operation_id,
        p_request_digest,
        p_proposal_digest,
        p_logical_action_digest,
        v_authorization_epoch,
        v_logical_authority_key_sha256,
        v_authorization_binding_sha256,
        p_run_id,
        p_incident_id,
        p_resource_id,
        v_new_fence,
        p_effect_key,
        'dispatch_rescue_unit',
        p_payload,
        p_payload_digest
      );

      RETURN QUERY SELECT
        'resource_reserved'::STRING,
        NULL::STRING,
        v_new_fence,
        v_new_expiry,
        p_operation_id,
        p_request_digest,
        NULL::STRING,
        p_proposal_digest,
        p_logical_action_digest,
        v_authorization_epoch,
        v_logical_authority_key_sha256,
        v_authorization_binding_sha256,
        true,
        v_database_now;
    END
    $$
  `);

  await client.query(`
    DROP FUNCTION IF EXISTS tp_api.g2_spend_authority_race_v1(
      UUID, UUID, STRING, JSONB, UUID, UUID, STRING, STRING, STRING,
      UUID, UUID, JSONB, STRING, STRING, INT8
    )
  `);

  await client.query(`
    DROP FUNCTION IF EXISTS tp_api.g2_spend_authority_race_v1(
      UUID, UUID, STRING, JSONB, STRING, STRING, STRING, UUID, UUID,
      STRING, STRING, STRING, UUID, UUID, JSONB, STRING, STRING, INT8
    )
  `);

  await client.query(`
    CREATE OR REPLACE FUNCTION tp_api.g2_spend_authority_race_v1(
      p_tenant_id UUID,
      p_operation_id UUID,
      p_request_digest STRING,
      p_request_payload JSONB,
      p_proposal_digest STRING,
      p_logical_action_digest STRING,
      p_selected_evidence_digest STRING,
      p_run_id UUID,
      p_incident_id UUID,
      p_resource_id STRING,
      p_agent_id STRING,
      p_agency STRING,
      p_evidence_id UUID,
      p_effect_key UUID,
      p_payload JSONB,
      p_payload_digest STRING,
      p_policy_version STRING,
      p_lease_ms INT8
    )
    RETURNS TABLE(
      decision_outcome STRING,
      decision_reason STRING,
      decision_fencing_token INT8,
      decision_lease_expires_at TIMESTAMPTZ,
      decision_operation_id UUID,
      decision_request_digest STRING,
      decision_replay_kind STRING,
      decision_proposal_digest STRING,
      decision_logical_action_digest STRING,
      decision_authorization_epoch INT8,
      decision_logical_authority_key_sha256 STRING,
      decision_authorization_binding_sha256 STRING,
      decision_authority_current BOOL,
      decision_database_now TIMESTAMPTZ,
      decision_durable_receipt BOOL,
      decision_authority_evidence_binding_sha256 STRING,
      decision_committed_evidence_id UUID,
      decision_committed_evidence_digest STRING
    )
    LANGUAGE PLpgSQL
    SECURITY DEFINER
    AS $$
    BEGIN
      IF session_user <> 'tp_gate2_authorizer_user' THEN
        RAISE EXCEPTION 'Gate Two authorizer database session required'
          USING ERRCODE = '42501';
      END IF;
      IF p_agent_id NOT IN ('aws-authority-alpha', 'aws-authority-bravo') THEN
        RAISE EXCEPTION 'Gate Two contender is not allowed'
          USING ERRCODE = '42501';
      END IF;
      RETURN QUERY
      WITH decision AS (
        SELECT *
        FROM tp_api.g1_spend_authority_v1(
          p_tenant_id,
          p_operation_id,
          p_request_digest,
          p_request_payload,
          p_proposal_digest,
          p_logical_action_digest,
          p_selected_evidence_digest,
          p_run_id,
          p_incident_id,
          p_resource_id,
          p_agent_id,
          p_agency,
          p_evidence_id,
          p_effect_key,
          p_payload,
          p_payload_digest,
          p_policy_version,
          p_lease_ms
        )
      )
      SELECT
        decision.*,
        receipt.operation_id IS NOT NULL,
        proposal.authority_evidence_binding_sha256,
        receipt.evidence_id,
        receipt.evidence_digest
      FROM decision
      LEFT JOIN tp_ledger.g1_authority_receipts AS receipt
        ON receipt.tenant_id = p_tenant_id
       AND receipt.operation_id = decision.decision_operation_id
      LEFT JOIN tp_ledger.g1_dvi_proposal_receipts AS proposal
        ON proposal.tenant_id = receipt.tenant_id
       AND proposal.proposal_digest = receipt.proposal_digest
       AND proposal.proposal_digest = decision.decision_proposal_digest;
    END
    $$
  `);

  await client.query(`
    DROP FUNCTION IF EXISTS tp_api.g1_resolve_request_v1(
      UUID, UUID, STRING
    )
  `);

  await client.query(`
    DROP FUNCTION IF EXISTS tp_api.g1_resolve_request_v1(
      UUID, UUID, STRING, STRING
    )
  `);

  await client.query(`
    CREATE OR REPLACE FUNCTION tp_api.g1_resolve_request_v1(
      p_tenant_id UUID,
      p_operation_id UUID,
      p_request_digest STRING,
      p_logical_action_digest STRING
    )
    RETURNS TABLE(
      operation_id UUID,
      request_digest STRING,
      request_payload JSONB,
      proposal_digest STRING,
      logical_action_digest STRING,
      authorization_epoch INT8,
      logical_authority_key_sha256 STRING,
      authorization_binding_sha256 STRING,
      run_id UUID,
      incident_id UUID,
      resource_id STRING,
      agent_id STRING,
      agency STRING,
      evidence_id UUID,
      evidence_digest STRING,
      effect_key UUID,
      payload_digest STRING,
      policy_version STRING,
      outcome STRING,
      reason STRING,
      fencing_token INT8,
      lease_expires_at TIMESTAMPTZ,
      observed_holder_operation_id UUID,
      observed_fence INT8,
      replay_kind STRING,
      outbox_intent_id UUID,
      outbox_operation_id UUID,
      outbox_request_digest STRING,
      outbox_proposal_digest STRING,
      outbox_logical_action_digest STRING,
      outbox_authorization_epoch INT8,
      outbox_logical_authority_key_sha256 STRING,
      outbox_authorization_binding_sha256 STRING,
      outbox_run_id UUID,
      outbox_incident_id UUID,
      outbox_resource_id STRING,
      outbox_fencing_token INT8,
      outbox_effect_key UUID,
      outbox_intent_kind STRING,
      outbox_payload JSONB,
      outbox_payload_digest STRING,
      current_fence INT8,
      active_run_id UUID,
      holder_operation_id UUID,
      holder_proposal_digest STRING,
      holder_logical_authority_key_sha256 STRING,
      resource_lease_expires_at TIMESTAMPTZ,
      receipt_proposal_tenant_id UUID,
      receipt_proposal_digest STRING,
      receipt_proposal_logical_action_digest STRING,
      receipt_proposal_resource_id STRING,
      receipt_proposal_agency STRING,
      receipt_proposal_action_kind STRING,
      receipt_proposal_payload JSONB,
      receipt_proposal_payload_canonical STRING,
      receipt_proposal_payload_digest STRING,
      receipt_proposal_retrieval_id UUID,
      receipt_proposal_run_id UUID,
      receipt_proposal_incident_id UUID,
      receipt_proposal_authority_evidence_binding_sha256 STRING,
      receipt_proposal_policy_version STRING,
      receipt_proposal_selected_rank INT8,
      receipt_proposal_selected_evidence_id UUID,
      receipt_proposal_selected_evidence_digest STRING,
      receipt_proposal_admitted_at TIMESTAMPTZ,
      receipt_proposal_expires_at TIMESTAMPTZ,
      receipt_proposal_authorization_epoch INT8,
      receipt_proposal_logical_authority_key_sha256 STRING,
      receipt_proposal_authorization_binding_sha256 STRING,
      authority_current BOOL,
      database_now TIMESTAMPTZ
    )
    LANGUAGE SQL
    SECURITY DEFINER
    AS $$
      WITH operation_candidate AS (
        SELECT receipt.*, 'operation_replay'::STRING AS replay_kind
        FROM tp_ledger.g1_authority_receipts AS receipt
        WHERE receipt.tenant_id = p_tenant_id
          AND receipt.operation_id = p_operation_id
        LIMIT 2
      ),
      logical_candidate AS (
        SELECT
          receipt.*,
          'logical_authority_replay'::STRING AS replay_kind
        FROM tp_ledger.g1_authority_receipts AS receipt
        WHERE receipt.tenant_id = p_tenant_id
          AND receipt.logical_action_digest = p_logical_action_digest
          AND receipt.outcome = 'resource_reserved'
          AND NOT EXISTS (SELECT 1 FROM operation_candidate)
        LIMIT 2
      ),
      semantic_candidate AS (
        SELECT receipt.*, 'semantic_replay'::STRING AS replay_kind
        FROM tp_ledger.g1_authority_receipts AS receipt
        WHERE receipt.tenant_id = p_tenant_id
          AND receipt.request_digest = p_request_digest
          AND NOT EXISTS (SELECT 1 FROM operation_candidate)
          AND NOT EXISTS (SELECT 1 FROM logical_candidate)
        LIMIT 2
      ),
      selected_receipt AS (
        SELECT * FROM operation_candidate
        UNION ALL
        SELECT * FROM logical_candidate
        UNION ALL
        SELECT * FROM semantic_candidate
      )
      SELECT
        receipt.operation_id,
        receipt.request_digest,
        receipt.request_payload,
        receipt.proposal_digest,
        receipt.logical_action_digest,
        receipt.authorization_epoch,
        receipt.logical_authority_key_sha256,
        receipt.authorization_binding_sha256,
        receipt.run_id,
        receipt.incident_id,
        receipt.resource_id,
        receipt.agent_id,
        receipt.agency,
        receipt.evidence_id,
        receipt.evidence_digest,
        receipt.effect_key,
        receipt.payload_digest,
        receipt.policy_version,
        receipt.outcome,
        receipt.reason,
        receipt.fencing_token,
        receipt.lease_expires_at,
        receipt.observed_holder_operation_id,
        receipt.observed_fence,
        receipt.replay_kind,
        outbox.intent_id,
        outbox.operation_id,
        outbox.request_digest,
        outbox.proposal_digest,
        outbox.logical_action_digest,
        outbox.authorization_epoch,
        outbox.logical_authority_key_sha256,
        outbox.authorization_binding_sha256,
        outbox.run_id,
        outbox.incident_id,
        outbox.resource_id,
        outbox.fencing_token,
        outbox.effect_key,
        outbox.intent_kind,
        outbox.payload,
        outbox.payload_digest,
        resource.current_fence,
        resource.active_run_id,
        resource.holder_operation_id,
        resource.holder_proposal_digest,
        resource.holder_logical_authority_key_sha256,
        resource.lease_expires_at,
        proposal.tenant_id,
        proposal.proposal_digest,
        proposal.logical_action_digest,
        proposal.resource_id,
        proposal.agency,
        proposal.action_kind,
        proposal.payload,
        proposal.payload_canonical,
        proposal.payload_digest,
        proposal.retrieval_id,
        proposal.run_id,
        proposal.incident_id,
        proposal.authority_evidence_binding_sha256,
        proposal.policy_version,
        proposal.selected_rank,
        proposal.selected_evidence_id,
        proposal.selected_evidence_digest,
        proposal.admitted_at,
        proposal.expires_at,
        proposal.authorization_epoch,
        proposal.logical_authority_key_sha256,
        proposal.authorization_binding_sha256,
        tp_private.g1_authority_receipt_current_v1(
          receipt.tenant_id,
          receipt.operation_id
        ),
        statement_timestamp()
      FROM selected_receipt AS receipt
      LEFT JOIN tp_ledger.g1_outbox_intents AS outbox
        ON outbox.tenant_id = receipt.tenant_id
       AND outbox.operation_id = receipt.operation_id
      LEFT JOIN tp_private.g1_resources AS resource
        ON resource.tenant_id = receipt.tenant_id
       AND resource.resource_id = receipt.resource_id
      LEFT JOIN tp_ledger.g1_dvi_proposal_receipts AS proposal
        ON proposal.tenant_id = receipt.tenant_id
       AND proposal.proposal_digest = receipt.proposal_digest
      WHERE session_user IN (
          'tp_authorizer_user',
          'tp_gate2_authorizer_user'
        )
      LIMIT 2
    $$
  `);

  await client.query(`
    CREATE OR REPLACE FUNCTION tp_api.g1_observe_authority_race_v1(
      p_tenant_id UUID,
      p_run_id UUID,
      p_resource_id STRING,
      p_alpha_operation_id UUID,
      p_alpha_request_digest STRING,
      p_bravo_operation_id UUID,
      p_bravo_request_digest STRING
    )
    RETURNS TABLE(
      active_run_id UUID,
      current_fence INT8,
      holder_operation_id UUID,
      race_receipt_count INT8,
      resource_receipt_count INT8,
      reserved_count INT8,
      held_denial_count INT8,
      pending_count INT8,
      outbox_count INT8,
      outbox_operation_id UUID,
      protected_effect_count INT8,
      alpha_outcome STRING,
      alpha_reason STRING,
      alpha_fencing_token INT8,
      alpha_observed_holder_operation_id UUID,
      alpha_observed_fence INT8,
      bravo_outcome STRING,
      bravo_reason STRING,
      bravo_fencing_token INT8,
      bravo_observed_holder_operation_id UUID,
      bravo_observed_fence INT8,
      observed_at TIMESTAMPTZ
    )
    LANGUAGE SQL
    SECURITY DEFINER
    AS $$
      SELECT
        resource.active_run_id,
        resource.current_fence,
        resource.holder_operation_id,
        (
          SELECT count(*)::INT8
          FROM tp_ledger.g1_authority_receipts AS receipt
          WHERE receipt.tenant_id = p_tenant_id
            AND receipt.run_id = p_run_id
            AND receipt.resource_id = p_resource_id
            AND (
              (
                receipt.operation_id = p_alpha_operation_id
                AND receipt.request_digest = p_alpha_request_digest
              )
              OR
              (
                receipt.operation_id = p_bravo_operation_id
                AND receipt.request_digest = p_bravo_request_digest
              )
            )
        ),
        (
          SELECT count(*)::INT8
          FROM tp_ledger.g1_authority_receipts AS receipt
          WHERE receipt.tenant_id = p_tenant_id
            AND receipt.run_id = p_run_id
            AND receipt.resource_id = p_resource_id
        ),
        (
          SELECT count(*)::INT8
          FROM tp_ledger.g1_authority_receipts AS receipt
          WHERE receipt.tenant_id = p_tenant_id
            AND receipt.run_id = p_run_id
            AND receipt.resource_id = p_resource_id
            AND receipt.outcome = 'resource_reserved'
        ),
        (
          SELECT count(*)::INT8
          FROM tp_ledger.g1_authority_receipts AS receipt
          WHERE receipt.tenant_id = p_tenant_id
            AND receipt.run_id = p_run_id
            AND receipt.resource_id = p_resource_id
            AND receipt.outcome = 'resource_held_denied'
        ),
        (
          SELECT count(*)::INT8
          FROM tp_ledger.g1_authority_receipts AS receipt
          WHERE receipt.tenant_id = p_tenant_id
            AND receipt.run_id = p_run_id
            AND receipt.resource_id = p_resource_id
            AND receipt.outcome = 'pending'
        ),
        (
          SELECT count(*)::INT8
          FROM tp_ledger.g1_outbox_intents AS outbox
          WHERE outbox.tenant_id = p_tenant_id
            AND outbox.run_id = p_run_id
            AND outbox.resource_id = p_resource_id
        ),
        (
          SELECT outbox.operation_id
          FROM tp_ledger.g1_outbox_intents AS outbox
          WHERE outbox.tenant_id = p_tenant_id
            AND outbox.run_id = p_run_id
            AND outbox.resource_id = p_resource_id
          ORDER BY outbox.operation_id
          LIMIT 1
        ),
        (
          SELECT count(*)::INT8
          FROM tp_ledger.g1_protected_effects AS effect
          WHERE effect.tenant_id = p_tenant_id
            AND effect.run_id = p_run_id
            AND effect.resource_id = p_resource_id
        ),
        (
          SELECT receipt.outcome
          FROM tp_ledger.g1_authority_receipts AS receipt
          WHERE receipt.tenant_id = p_tenant_id
            AND receipt.run_id = p_run_id
            AND receipt.resource_id = p_resource_id
            AND receipt.operation_id = p_alpha_operation_id
            AND receipt.request_digest = p_alpha_request_digest
          LIMIT 1
        ),
        (
          SELECT receipt.reason
          FROM tp_ledger.g1_authority_receipts AS receipt
          WHERE receipt.tenant_id = p_tenant_id
            AND receipt.run_id = p_run_id
            AND receipt.resource_id = p_resource_id
            AND receipt.operation_id = p_alpha_operation_id
            AND receipt.request_digest = p_alpha_request_digest
          LIMIT 1
        ),
        (
          SELECT receipt.fencing_token
          FROM tp_ledger.g1_authority_receipts AS receipt
          WHERE receipt.tenant_id = p_tenant_id
            AND receipt.run_id = p_run_id
            AND receipt.resource_id = p_resource_id
            AND receipt.operation_id = p_alpha_operation_id
            AND receipt.request_digest = p_alpha_request_digest
          LIMIT 1
        ),
        (
          SELECT receipt.observed_holder_operation_id
          FROM tp_ledger.g1_authority_receipts AS receipt
          WHERE receipt.tenant_id = p_tenant_id
            AND receipt.run_id = p_run_id
            AND receipt.resource_id = p_resource_id
            AND receipt.operation_id = p_alpha_operation_id
            AND receipt.request_digest = p_alpha_request_digest
          LIMIT 1
        ),
        (
          SELECT receipt.observed_fence
          FROM tp_ledger.g1_authority_receipts AS receipt
          WHERE receipt.tenant_id = p_tenant_id
            AND receipt.run_id = p_run_id
            AND receipt.resource_id = p_resource_id
            AND receipt.operation_id = p_alpha_operation_id
            AND receipt.request_digest = p_alpha_request_digest
          LIMIT 1
        ),
        (
          SELECT receipt.outcome
          FROM tp_ledger.g1_authority_receipts AS receipt
          WHERE receipt.tenant_id = p_tenant_id
            AND receipt.run_id = p_run_id
            AND receipt.resource_id = p_resource_id
            AND receipt.operation_id = p_bravo_operation_id
            AND receipt.request_digest = p_bravo_request_digest
          LIMIT 1
        ),
        (
          SELECT receipt.reason
          FROM tp_ledger.g1_authority_receipts AS receipt
          WHERE receipt.tenant_id = p_tenant_id
            AND receipt.run_id = p_run_id
            AND receipt.resource_id = p_resource_id
            AND receipt.operation_id = p_bravo_operation_id
            AND receipt.request_digest = p_bravo_request_digest
          LIMIT 1
        ),
        (
          SELECT receipt.fencing_token
          FROM tp_ledger.g1_authority_receipts AS receipt
          WHERE receipt.tenant_id = p_tenant_id
            AND receipt.run_id = p_run_id
            AND receipt.resource_id = p_resource_id
            AND receipt.operation_id = p_bravo_operation_id
            AND receipt.request_digest = p_bravo_request_digest
          LIMIT 1
        ),
        (
          SELECT receipt.observed_holder_operation_id
          FROM tp_ledger.g1_authority_receipts AS receipt
          WHERE receipt.tenant_id = p_tenant_id
            AND receipt.run_id = p_run_id
            AND receipt.resource_id = p_resource_id
            AND receipt.operation_id = p_bravo_operation_id
            AND receipt.request_digest = p_bravo_request_digest
          LIMIT 1
        ),
        (
          SELECT receipt.observed_fence
          FROM tp_ledger.g1_authority_receipts AS receipt
          WHERE receipt.tenant_id = p_tenant_id
            AND receipt.run_id = p_run_id
            AND receipt.resource_id = p_resource_id
            AND receipt.operation_id = p_bravo_operation_id
            AND receipt.request_digest = p_bravo_request_digest
          LIMIT 1
        ),
        statement_timestamp()
      FROM tp_private.g1_resources AS resource
      WHERE resource.tenant_id = p_tenant_id
        AND resource.resource_id = p_resource_id
        AND resource.active_run_id = p_run_id
        AND session_user IN (
          'tp_authorizer_user',
          'tp_gate2_authorizer_user'
        )
        AND EXISTS (
          SELECT 1
          FROM tp_ledger.g1_authority_receipts AS receipt
          WHERE receipt.tenant_id = p_tenant_id
            AND receipt.run_id = p_run_id
            AND receipt.resource_id = p_resource_id
            AND receipt.operation_id = p_alpha_operation_id
            AND receipt.request_digest = p_alpha_request_digest
        )
        AND EXISTS (
          SELECT 1
          FROM tp_ledger.g1_authority_receipts AS receipt
          WHERE receipt.tenant_id = p_tenant_id
            AND receipt.run_id = p_run_id
            AND receipt.resource_id = p_resource_id
            AND receipt.operation_id = p_bravo_operation_id
            AND receipt.request_digest = p_bravo_request_digest
        )
      LIMIT 1
    $$
  `);

  await client.query(`
    CREATE OR REPLACE FUNCTION tp_api.g1_append_recovery_audit_v1(
      p_audit_id UUID,
      p_recovery_session_id UUID,
      p_caller_subject_hash STRING,
      p_tool_name STRING,
      p_query_template_digest STRING,
      p_bound_input_digest STRING,
      p_result_digest STRING,
      p_source_watermark TIMESTAMPTZ,
      p_outcome STRING
    )
    RETURNS UUID
    LANGUAGE SQL
    SECURITY DEFINER
    AS $$
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
      SELECT
        p_audit_id,
        p_recovery_session_id,
        p_caller_subject_hash,
        p_tool_name,
        p_query_template_digest,
        p_bound_input_digest,
        p_result_digest,
        p_source_watermark,
        p_outcome
      WHERE session_user = 'tp_recovery_audit_user'
      ON CONFLICT (
        recovery_session_id,
        query_template_digest,
        bound_input_digest,
        result_digest,
        outcome
      )
      DO UPDATE SET audit_id = tp_ledger.g1_recovery_audit_receipts.audit_id
      RETURNING audit_id
    $$
  `);

  await client.query(`
    CREATE OR REPLACE FUNCTION tp_api.g1_append_recovery_audit_v2(
      p_audit_id UUID,
      p_tenant_id UUID,
      p_recovery_session_id UUID,
      p_caller_subject_hash STRING,
      p_tool_name STRING,
      p_recovery_cluster_id UUID,
      p_broker_config_digest STRING,
      p_query_template_digest STRING,
      p_bound_input_digest STRING,
      p_result_digest STRING,
      p_source_watermark TIMESTAMPTZ,
      p_started_at TIMESTAMPTZ,
      p_completed_at TIMESTAMPTZ,
      p_outcome STRING,
      p_error_code STRING
    )
    RETURNS UUID
    LANGUAGE SQL
    SECURITY DEFINER
    AS $$
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
        outcome,
        error_code
      )
      SELECT
        p_audit_id,
        p_tenant_id,
        p_recovery_session_id,
        p_caller_subject_hash,
        p_tool_name,
        p_recovery_cluster_id,
        p_broker_config_digest,
        p_query_template_digest,
        p_bound_input_digest,
        p_result_digest,
        p_source_watermark,
        p_started_at,
        p_completed_at,
        p_outcome,
        p_error_code
      WHERE session_user = 'tp_recovery_audit_user'
      ON CONFLICT (tenant_id, audit_id)
      DO UPDATE SET audit_id =
        tp_ledger.g1_recovery_audit_receipts_v2.audit_id
      RETURNING audit_id
    $$
  `);

  await client.query(`
    CREATE OR REPLACE FUNCTION tp_api.g1_append_recovery_audit_event_v3(
      p_event_id UUID,
      p_tenant_id UUID,
      p_interaction_id UUID,
      p_recovery_session_id UUID,
      p_caller_subject_hash STRING,
      p_phase STRING,
      p_tool_name STRING,
      p_recovery_cluster_id UUID,
      p_broker_config_digest STRING,
      p_query_template_digest STRING,
      p_bound_input_digest STRING,
      p_result_digest STRING,
      p_source_watermark TIMESTAMPTZ,
      p_outcome STRING,
      p_error_code STRING,
      p_event_digest STRING,
      p_started_at TIMESTAMPTZ,
      p_completed_at TIMESTAMPTZ
    )
    RETURNS UUID
    LANGUAGE PLpgSQL
    SECURITY DEFINER
    AS $$
    DECLARE
      v_existing_count INT8;
      v_exact_count INT8;
      v_pre_read_count INT8;
      v_existing_event_id STRING;
      v_inserted_event_id UUID;
    BEGIN
      IF session_user <> 'tp_recovery_audit_user' THEN
        RAISE EXCEPTION 'recovery audit database session required'
          USING ERRCODE = '42501';
      END IF;
      SELECT
        count(*),
        min(event_id::STRING)
      INTO
        v_existing_count,
        v_existing_event_id
      FROM tp_ledger.g1_recovery_audit_events_v3
      WHERE tenant_id = p_tenant_id
        AND (
          event_id = p_event_id
          OR (
            interaction_id = p_interaction_id
            AND phase = p_phase
          )
        );

      IF v_existing_count > 0 THEN
        SELECT count(*)
        INTO v_exact_count
        FROM tp_ledger.g1_recovery_audit_events_v3
        WHERE tenant_id = p_tenant_id
          AND event_id = p_event_id
          AND interaction_id = p_interaction_id
          AND recovery_session_id = p_recovery_session_id
          AND caller_subject_hash = p_caller_subject_hash
          AND phase = p_phase
          AND tool_name = p_tool_name
          AND recovery_cluster_id = p_recovery_cluster_id
          AND broker_config_digest = p_broker_config_digest
          AND query_template_digest = p_query_template_digest
          AND bound_input_digest = p_bound_input_digest
          AND result_digest IS NOT DISTINCT FROM p_result_digest
          AND source_watermark IS NOT DISTINCT FROM p_source_watermark
          AND outcome = p_outcome
          AND error_code IS NOT DISTINCT FROM p_error_code
          AND event_digest = p_event_digest
          AND started_at = p_started_at
          AND completed_at = p_completed_at;
        IF v_existing_count <> 1 OR v_exact_count <> 1 THEN
          RAISE EXCEPTION 'recovery audit event replay mismatch'
            USING ERRCODE = '22000';
        END IF;
        RETURN v_existing_event_id::UUID;
      END IF;

      IF p_phase = 'terminal' THEN
        SELECT count(*)
        INTO v_pre_read_count
        FROM tp_ledger.g1_recovery_audit_events_v3
        WHERE tenant_id = p_tenant_id
          AND interaction_id = p_interaction_id
          AND recovery_session_id = p_recovery_session_id
          AND caller_subject_hash = p_caller_subject_hash
          AND phase = 'pre_read'
          AND tool_name = p_tool_name
          AND recovery_cluster_id = p_recovery_cluster_id
          AND broker_config_digest = p_broker_config_digest
          AND query_template_digest = p_query_template_digest
          AND bound_input_digest = p_bound_input_digest
          AND started_at = p_started_at;
        IF v_pre_read_count <> 1 THEN
          RAISE EXCEPTION 'recovery terminal audit has no matching pre-read'
            USING ERRCODE = '22000';
        END IF;
      END IF;

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
        result_digest,
        source_watermark,
        outcome,
        error_code,
        event_digest,
        started_at,
        completed_at
      )
      VALUES (
        p_tenant_id,
        p_event_id,
        p_interaction_id,
        p_recovery_session_id,
        p_caller_subject_hash,
        p_phase,
        p_tool_name,
        p_recovery_cluster_id,
        p_broker_config_digest,
        p_query_template_digest,
        p_bound_input_digest,
        p_result_digest,
        p_source_watermark,
        p_outcome,
        p_error_code,
        p_event_digest,
        p_started_at,
        p_completed_at
      )
      RETURNING event_id INTO v_inserted_event_id;

      RETURN v_inserted_event_id;
    END
    $$
  `);

  await client.query(`
    CREATE OR REPLACE FUNCTION tp_api.g1_resolve_recovery_audit_event_v1(
      p_event_id UUID,
      p_tenant_id UUID,
      p_event_digest STRING
    )
    RETURNS TABLE(
      event_id UUID,
      tenant_id UUID,
      interaction_id UUID,
      recovery_session_id UUID,
      caller_subject_hash STRING,
      phase STRING,
      tool_name STRING,
      recovery_cluster_id UUID,
      broker_config_digest STRING,
      query_template_digest STRING,
      bound_input_digest STRING,
      result_digest STRING,
      source_watermark TIMESTAMPTZ,
      error_code STRING,
      event_digest STRING,
      outcome STRING,
      started_at TIMESTAMPTZ,
      completed_at TIMESTAMPTZ,
      recorded_at TIMESTAMPTZ,
      database_now TIMESTAMPTZ
    )
    LANGUAGE SQL
    SECURITY DEFINER
    AS $$
      SELECT
        event.event_id,
        event.tenant_id,
        event.interaction_id,
        event.recovery_session_id,
        event.caller_subject_hash,
        event.phase,
        event.tool_name,
        event.recovery_cluster_id,
        event.broker_config_digest,
        event.query_template_digest,
        event.bound_input_digest,
        event.result_digest,
        event.source_watermark,
        event.error_code,
        event.event_digest,
        event.outcome,
        event.started_at,
        event.completed_at,
        event.recorded_at,
        transaction_timestamp()
      FROM tp_ledger.g1_recovery_audit_events_v3 AS event
      WHERE session_user = 'tp_recovery_audit_user'
        AND event.tenant_id = p_tenant_id
        AND event.event_id = p_event_id
        AND event.event_digest = p_event_digest
    $$
  `);

  await client.query(`
    CREATE OR REPLACE FUNCTION tp_api.g1_resolve_recovery_source_receipt_v2(
      p_tenant_id UUID,
      p_run_id UUID,
      p_incident_id UUID,
      p_evidence_id UUID,
      p_resource_id STRING,
      p_operation_id UUID,
      p_request_digest STRING
    )
    RETURNS TABLE(
      tenant_id UUID,
      run_id UUID,
      incident_id UUID,
      evidence_id UUID,
      operation_id UUID,
      recorded_at TIMESTAMPTZ,
      request_digest STRING,
      proposal_digest STRING,
      logical_action_digest STRING,
      authorization_epoch INT8,
      logical_authority_key_sha256 STRING,
      authorization_binding_sha256 STRING,
      policy_version STRING,
      agent_id STRING,
      agency STRING,
      outcome STRING,
      reason STRING,
      evidence_digest STRING,
      authority_evidence_binding_sha256 STRING,
      resource_id STRING,
      has_durable_intent BOOL,
      admissibility STRING,
      database_now TIMESTAMPTZ
    )
    LANGUAGE SQL
    SECURITY DEFINER
    AS $$
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
        proposal.authority_evidence_binding_sha256,
        receipt.resource_id,
        true,
        observed.admissibility,
        statement_timestamp()
      FROM tp_ledger.g1_authority_receipts AS receipt
      JOIN tp_private.g1_resources AS resource
        ON resource.tenant_id = receipt.tenant_id
       AND resource.resource_id = receipt.resource_id
       AND resource.active_run_id = receipt.run_id
       AND resource.holder_incident_id = receipt.incident_id
       AND resource.holder_operation_id = receipt.operation_id
       AND resource.holder_agent_id = receipt.agent_id
       AND resource.holder_proposal_digest = receipt.proposal_digest
       AND resource.holder_logical_authority_key_sha256 =
         receipt.logical_authority_key_sha256
       AND resource.current_fence = receipt.fencing_token
      JOIN tp_private.g1_evidence AS evidence
        ON evidence.tenant_id = receipt.tenant_id
       AND evidence.evidence_id = receipt.evidence_id
      JOIN tp_ledger.g1_evidence_verification_receipts AS verification
        ON verification.tenant_id = evidence.tenant_id
       AND verification.evidence_id = evidence.evidence_id
      JOIN tp_ledger.g1_outbox_intents AS outbox
        ON outbox.tenant_id = receipt.tenant_id
       AND outbox.operation_id = receipt.operation_id
       AND outbox.request_digest = receipt.request_digest
       AND outbox.proposal_digest = receipt.proposal_digest
       AND outbox.logical_action_digest = receipt.logical_action_digest
       AND outbox.authorization_epoch = receipt.authorization_epoch
       AND outbox.logical_authority_key_sha256 =
         receipt.logical_authority_key_sha256
       AND outbox.authorization_binding_sha256 =
         receipt.authorization_binding_sha256
       AND outbox.run_id = receipt.run_id
       AND outbox.incident_id = receipt.incident_id
       AND outbox.resource_id = receipt.resource_id
       AND outbox.fencing_token = receipt.fencing_token
       AND outbox.effect_key = receipt.effect_key
       AND outbox.payload_digest = receipt.payload_digest
      JOIN tp_ledger.g1_dvi_proposal_receipts AS proposal
        ON proposal.tenant_id = receipt.tenant_id
       AND proposal.proposal_digest = receipt.proposal_digest
       AND proposal.logical_action_digest = receipt.logical_action_digest
       AND proposal.authorization_epoch = receipt.authorization_epoch
       AND proposal.logical_authority_key_sha256 =
         receipt.logical_authority_key_sha256
       AND proposal.authorization_binding_sha256 =
         receipt.authorization_binding_sha256
       AND proposal.run_id = receipt.run_id
       AND proposal.incident_id = receipt.incident_id
       AND proposal.resource_id = receipt.resource_id
       AND proposal.agency = receipt.agency
       AND proposal.policy_version = receipt.policy_version
       AND proposal.selected_evidence_id = receipt.evidence_id
       AND proposal.selected_evidence_digest = receipt.evidence_digest
       AND proposal.payload = outbox.payload
       AND proposal.payload_digest = receipt.payload_digest
      JOIN tp_private.g1_list_admissibility_internal_v1(
        receipt.tenant_id,
        receipt.incident_id,
        receipt.agency
      ) AS observed
        ON observed.evidence_id = receipt.evidence_id
      WHERE session_user = 'tp_recovery_source_user'
        AND receipt.tenant_id = p_tenant_id
        AND receipt.run_id = p_run_id
        AND receipt.incident_id = p_incident_id
        AND receipt.evidence_id = p_evidence_id
        AND receipt.resource_id = p_resource_id
        AND receipt.operation_id = p_operation_id
        AND receipt.request_digest = p_request_digest
        AND receipt.outcome = 'resource_reserved'
        AND receipt.recorded_at >
          statement_timestamp() - INTERVAL '50 minutes'
        AND receipt.lease_expires_at > statement_timestamp()
        AND resource.lease_expires_at > statement_timestamp()
        AND proposal.expires_at > statement_timestamp()
        AND verification.outcome = 'verified'
        AND verification.public_key_digest IS NOT NULL
        AND receipt.evidence_digest = evidence.evidence_digest
        AND encode(
          sha256(proposal.payload_canonical::BYTES),
          'hex'
        ) = outbox.payload_digest
        AND observed.admissibility = 'admissible'
    $$
  `);

  await client.query(`
    CREATE OR REPLACE FUNCTION tp_api.g1_resolve_recovery_publisher_trust_root_v1(
      p_trust_root_id STRING,
      p_trust_root_commitment STRING,
      p_publisher_key_set_digest STRING
    )
    RETURNS TABLE(
      trust_root_id STRING,
      trust_root_commitment STRING,
      publisher_key_set_digest STRING,
      committed_at TIMESTAMPTZ,
      database_now TIMESTAMPTZ
    )
    LANGUAGE SQL
    SECURITY DEFINER
    AS $$
      SELECT
        root.trust_root_id,
        root.trust_root_commitment,
        root.publisher_key_set_digest,
        root.committed_at,
        transaction_timestamp()
      FROM tp_ledger.g1_recovery_publisher_trust_roots AS root
      WHERE session_user = 'tp_recovery_audit_user'
        AND root.trust_root_id = p_trust_root_id
        AND root.trust_root_commitment = p_trust_root_commitment
        AND root.publisher_key_set_digest = p_publisher_key_set_digest
    $$
  `);

  await client.query(`
    CREATE OR REPLACE FUNCTION tp_api.g1_record_protected_effect_v1(
      p_tenant_id UUID,
      p_effect_key UUID,
      p_operation_id UUID,
      p_request_digest STRING,
      p_run_id UUID,
      p_incident_id UUID,
      p_resource_id STRING,
      p_agent_id STRING,
      p_fencing_token INT8,
      p_payload_digest STRING
    )
    RETURNS TABLE(effect_key UUID, operation_id UUID)
    LANGUAGE SQL
    SECURITY DEFINER
    AS $$
      INSERT INTO tp_ledger.g1_protected_effects (
        tenant_id,
        effect_key,
        operation_id,
        request_digest,
        proposal_digest,
        logical_action_digest,
        authorization_epoch,
        logical_authority_key_sha256,
        authorization_binding_sha256,
        run_id,
        incident_id,
        resource_id,
        agent_id,
        fencing_token,
        payload_digest
      )
      SELECT
        p_tenant_id,
        p_effect_key,
        p_operation_id,
        p_request_digest,
        outbox.proposal_digest,
        outbox.logical_action_digest,
        outbox.authorization_epoch,
        outbox.logical_authority_key_sha256,
        outbox.authorization_binding_sha256,
        p_run_id,
        p_incident_id,
        p_resource_id,
        p_agent_id,
        p_fencing_token,
        p_payload_digest
      FROM tp_private.g1_resources AS resource
      JOIN tp_ledger.g1_outbox_intents AS outbox
        ON outbox.tenant_id = resource.tenant_id
       AND outbox.operation_id = p_operation_id
       AND outbox.request_digest = p_request_digest
       AND outbox.run_id = p_run_id
       AND outbox.incident_id = p_incident_id
       AND outbox.resource_id = p_resource_id
       AND outbox.fencing_token = p_fencing_token
       AND outbox.effect_key = p_effect_key
       AND outbox.payload_digest = p_payload_digest
      JOIN tp_ledger.g1_authority_receipts AS receipt
       ON receipt.tenant_id = outbox.tenant_id
       AND receipt.operation_id = outbox.operation_id
       AND receipt.proposal_digest = outbox.proposal_digest
       AND receipt.logical_action_digest = outbox.logical_action_digest
       AND receipt.authorization_epoch = outbox.authorization_epoch
       AND receipt.logical_authority_key_sha256 =
         outbox.logical_authority_key_sha256
       AND receipt.authorization_binding_sha256 =
         outbox.authorization_binding_sha256
       AND receipt.agent_id = p_agent_id
       AND receipt.outcome = 'resource_reserved'
      JOIN tp_ledger.g1_dvi_proposal_receipts AS proposal
       ON proposal.tenant_id = outbox.tenant_id
       AND proposal.proposal_digest = outbox.proposal_digest
       AND proposal.logical_action_digest = outbox.logical_action_digest
       AND proposal.authorization_epoch = outbox.authorization_epoch
       AND proposal.logical_authority_key_sha256 =
         outbox.logical_authority_key_sha256
       AND proposal.authorization_binding_sha256 =
         outbox.authorization_binding_sha256
       AND proposal.run_id = outbox.run_id
       AND proposal.incident_id = outbox.incident_id
       AND proposal.resource_id = outbox.resource_id
       AND proposal.payload = outbox.payload
       AND proposal.payload_digest = outbox.payload_digest
      WHERE resource.tenant_id = p_tenant_id
        AND resource.resource_id = p_resource_id
        AND resource.active_run_id = p_run_id
        AND session_user = 'tp_dispatch_user'
        AND resource.holder_incident_id = p_incident_id
        AND resource.holder_operation_id = p_operation_id
        AND resource.holder_agent_id = p_agent_id
        AND resource.holder_proposal_digest = outbox.proposal_digest
        AND resource.holder_logical_authority_key_sha256 =
          outbox.logical_authority_key_sha256
        AND resource.current_fence = p_fencing_token
        AND encode(
          sha256(proposal.payload_canonical::BYTES),
          'hex'
        ) = outbox.payload_digest
        AND resource.lease_expires_at > statement_timestamp()
        AND proposal.expires_at > statement_timestamp()
      ON CONFLICT DO NOTHING
      RETURNING effect_key, operation_id
    $$
  `);
}

async function primaryFunctionSqlStatements() {
  const statements = [];
  await emitPrimaryFunctionSql({
    query(...args) {
      if (args.length !== 1 || typeof args[0] !== "string") {
        throw new Error("PRIMARY_FUNCTION_SQL_BATCH_UNREVIEWED");
      }
      statements.push(args[0]);
    }
  });
  return Object.freeze(statements);
}

async function executePrimaryFunctionSqlStatements(client, statements) {
  const receipt = validatePrimaryFunctionSqlStatements(statements);
  for (const statement of statements) {
    await client.query(statement);
  }
  return receipt;
}

async function createFunctions(client) {
  const statements = await primaryFunctionSqlStatements();
  return executePrimaryFunctionSqlStatements(client, statements);
}

async function transferOwnership(client) {
  for (const object of PRIMARY_MANAGED_BASE_TABLES) {
    await client.query(`ALTER TABLE ${object} OWNER TO tp_owner`);
  }
  for (const view of [
    "tp_api.g1_recovery_bundle_v1",
    "tp_api.g1_receipt_audit_v1"
  ]) {
    await client.query(`ALTER VIEW ${view} OWNER TO tp_owner`);
  }

  const functions = [
    "tp_api.g1_append_verified_evidence_v1(UUID, UUID, UUID, STRING, STRING, STRING, STRING, STRING, STRING, TIMESTAMPTZ, TIMESTAMPTZ, TIMESTAMPTZ, STRING, STRING, STRING)",
    "tp_api.g1_get_verification_key_v1(UUID, STRING)",
    "tp_api.g1_append_verified_evidence_v2(UUID, UUID, UUID, STRING, STRING, STRING, STRING, STRING, STRING, STRING, STRING, STRING, STRING, TIMESTAMPTZ, TIMESTAMPTZ, TIMESTAMPTZ, STRING, STRING, STRING)",
    "tp_api.g1_resolve_verified_evidence_v1(UUID, UUID, STRING, STRING)",
    "tp_private.g1_list_admissibility_internal_v1(UUID, UUID, STRING)",
    "tp_api.g1_observe_admissibility_v1(UUID, UUID, UUID, STRING)",
    "tp_api.g1_observe_admissibility_v2(UUID, UUID, UUID, STRING)",
    "tp_api.g1_prepare_vector_set_v1(UUID, UUID, UUID, STRING, STRING, INT8)",
    "tp_api.g1_observe_vector_exclusion_v1(UUID, UUID, UUID, UUID, STRING, STRING)",
    "tp_api.g1_resolve_vector_set_v1(UUID, UUID, UUID, STRING, STRING, INT8)",
    "tp_api.g1_rank_vector_set_v1(UUID, UUID, UUID, STRING, STRING, STRING, INT8)",
    "tp_api.g1_commit_dvi_selection_v1(UUID, UUID, UUID, UUID, STRING, STRING, STRING, STRING, STRING, STRING, INT8, STRING)",
    "tp_api.g1_authorize_dvi_proposal_v1(UUID, UUID, UUID, UUID, UUID, STRING, STRING, STRING, STRING, JSONB)",
    "tp_private.g1_authority_receipt_current_v1(UUID, UUID)",
    "tp_api.g1_delete_vector_set_v1(UUID, UUID)",
    "tp_api.g1_purge_expired_vector_sets_v1(UUID, INT8)",
    "tp_api.g1_spend_authority_v1(UUID, UUID, STRING, JSONB, STRING, STRING, STRING, UUID, UUID, STRING, STRING, STRING, UUID, UUID, JSONB, STRING, STRING, INT8)",
    "tp_api.g2_spend_authority_race_v1(UUID, UUID, STRING, JSONB, STRING, STRING, STRING, UUID, UUID, STRING, STRING, STRING, UUID, UUID, JSONB, STRING, STRING, INT8)",
    "tp_api.g1_resolve_request_v1(UUID, UUID, STRING, STRING)",
    "tp_api.g1_observe_authority_race_v1(UUID, UUID, STRING, UUID, STRING, UUID, STRING)",
    "tp_api.g1_append_recovery_audit_v1(UUID, UUID, STRING, STRING, STRING, STRING, STRING, TIMESTAMPTZ, STRING)",
    "tp_api.g1_append_recovery_audit_v2(UUID, UUID, UUID, STRING, STRING, UUID, STRING, STRING, STRING, STRING, TIMESTAMPTZ, TIMESTAMPTZ, TIMESTAMPTZ, STRING, STRING)",
    "tp_api.g1_append_recovery_audit_event_v3(UUID, UUID, UUID, UUID, STRING, STRING, STRING, UUID, STRING, STRING, STRING, STRING, TIMESTAMPTZ, STRING, STRING, STRING, TIMESTAMPTZ, TIMESTAMPTZ)",
    "tp_api.g1_resolve_recovery_audit_event_v1(UUID, UUID, STRING)",
    "tp_api.g1_resolve_recovery_source_receipt_v2(UUID, UUID, UUID, UUID, STRING, UUID, STRING)",
    "tp_api.g1_resolve_recovery_publisher_trust_root_v1(STRING, STRING, STRING)",
    "tp_api.g1_record_protected_effect_v1(UUID, UUID, UUID, STRING, UUID, UUID, STRING, STRING, INT8, STRING)"
  ];
  for (const functionSignature of functions) {
    await client.query(
      `ALTER FUNCTION ${functionSignature} OWNER TO tp_owner`
    );
    await client.query(
      `REVOKE ALL ON FUNCTION ${functionSignature} FROM public`
    );
  }
}

async function applyGrants(client, bootstrapOwner) {
  await client.query("REVOKE ALL ON DATABASE tideproof FROM public");
  await client.query("REVOKE CREATE ON SCHEMA public FROM public");
  await client.query(
    "REVOKE ALL ON SCHEMA tp_private, tp_ledger, tp_api FROM public"
  );
  await client.query(
    "REVOKE ALL ON ALL TABLES IN SCHEMA tp_private, tp_ledger, tp_api FROM public"
  );
  await client.query(
    "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA tp_private, tp_ledger, tp_api FROM public"
  );

  await scrubManagedPrivileges(client);
  for (const role of RUNTIME_ROLES) {
    await client.query(`GRANT CONNECT ON DATABASE tideproof TO ${role}`);
    await client.query(
      `GRANT USAGE ON SCHEMA tp_api TO ${role}`
    );
  }

  await client.query(`
    REVOKE EXECUTE ON FUNCTION
      tp_api.g1_append_verified_evidence_v1(
        UUID, UUID, UUID, STRING, STRING, STRING, STRING, STRING, STRING,
        TIMESTAMPTZ, TIMESTAMPTZ, TIMESTAMPTZ, STRING, STRING, STRING
      )
    FROM tp_ingest_role
  `);
  await client.query(`
    GRANT EXECUTE ON FUNCTION
      tp_api.g1_resolve_recovery_source_receipt_v2(
        UUID, UUID, UUID, UUID, STRING, UUID, STRING
      )
    TO tp_recovery_source_role
  `);

  await client.query(`
    GRANT EXECUTE ON FUNCTION
      tp_api.g1_get_verification_key_v1(UUID, STRING),
      tp_api.g1_append_verified_evidence_v2(
        UUID, UUID, UUID, STRING, STRING, STRING, STRING, STRING, STRING,
        STRING, STRING, STRING, STRING, TIMESTAMPTZ, TIMESTAMPTZ,
        TIMESTAMPTZ, STRING, STRING, STRING
      ),
      tp_api.g1_resolve_verified_evidence_v1(
        UUID, UUID, STRING, STRING
      )
    TO tp_ingest_role
  `);
  await client.query(`
    REVOKE EXECUTE ON FUNCTION
      tp_api.g2_spend_authority_race_v1(
        UUID, UUID, STRING, JSONB, STRING, STRING, STRING, UUID, UUID,
        STRING, STRING, STRING, UUID, UUID, JSONB, STRING, STRING, INT8
      )
    FROM tp_authorizer_role
  `);
  await client.query(`
    GRANT EXECUTE ON FUNCTION
      tp_api.g1_observe_admissibility_v1(UUID, UUID, UUID, STRING),
      tp_api.g1_observe_admissibility_v2(UUID, UUID, UUID, STRING),
      tp_api.g1_prepare_vector_set_v1(
        UUID, UUID, UUID, STRING, STRING, INT8
      ),
      tp_api.g1_observe_vector_exclusion_v1(
        UUID, UUID, UUID, UUID, STRING, STRING
      ),
      tp_api.g1_resolve_vector_set_v1(
        UUID, UUID, UUID, STRING, STRING, INT8
      ),
      tp_api.g1_rank_vector_set_v1(
        UUID, UUID, UUID, STRING, STRING, STRING, INT8
      ),
      tp_api.g1_commit_dvi_selection_v1(
        UUID, UUID, UUID, UUID, STRING, STRING, STRING, STRING, STRING,
        STRING, INT8, STRING
      ),
      tp_api.g1_authorize_dvi_proposal_v1(
        UUID, UUID, UUID, UUID, UUID, STRING, STRING, STRING, STRING, JSONB
      ),
      tp_api.g1_delete_vector_set_v1(UUID, UUID),
      tp_api.g1_purge_expired_vector_sets_v1(UUID, INT8),
      tp_api.g1_spend_authority_v1(
        UUID, UUID, STRING, JSONB, STRING, STRING, STRING, UUID, UUID,
        STRING, STRING, STRING, UUID, UUID, JSONB, STRING, STRING, INT8
      ),
      tp_api.g1_resolve_request_v1(UUID, UUID, STRING, STRING),
      tp_api.g1_observe_authority_race_v1(
        UUID, UUID, STRING, UUID, STRING, UUID, STRING
      )
    TO tp_authorizer_role
  `);
  await client.query(`
    REVOKE EXECUTE ON FUNCTION
      tp_api.g1_observe_admissibility_v1(UUID, UUID, UUID, STRING),
      tp_api.g1_observe_admissibility_v2(UUID, UUID, UUID, STRING),
      tp_api.g1_prepare_vector_set_v1(
        UUID, UUID, UUID, STRING, STRING, INT8
      ),
      tp_api.g1_observe_vector_exclusion_v1(
        UUID, UUID, UUID, UUID, STRING, STRING
      ),
      tp_api.g1_resolve_vector_set_v1(
        UUID, UUID, UUID, STRING, STRING, INT8
      ),
      tp_api.g1_rank_vector_set_v1(
        UUID, UUID, UUID, STRING, STRING, STRING, INT8
      ),
      tp_api.g1_commit_dvi_selection_v1(
        UUID, UUID, UUID, UUID, STRING, STRING, STRING, STRING, STRING,
        STRING, INT8, STRING
      ),
      tp_api.g1_authorize_dvi_proposal_v1(
        UUID, UUID, UUID, UUID, UUID, STRING, STRING, STRING, STRING, JSONB
      ),
      tp_api.g1_delete_vector_set_v1(UUID, UUID),
      tp_api.g1_purge_expired_vector_sets_v1(UUID, INT8),
      tp_api.g1_spend_authority_v1(
        UUID, UUID, STRING, JSONB, STRING, STRING, STRING, UUID, UUID,
        STRING, STRING, STRING, UUID, UUID, JSONB, STRING, STRING, INT8
      )
    FROM tp_gate2_authorizer_role
  `);
  await client.query(`
    GRANT EXECUTE ON FUNCTION
      tp_api.g2_spend_authority_race_v1(
        UUID, UUID, STRING, JSONB, STRING, STRING, STRING, UUID, UUID,
        STRING, STRING, STRING, UUID, UUID, JSONB, STRING, STRING, INT8
      ),
      tp_api.g1_resolve_request_v1(UUID, UUID, STRING, STRING),
      tp_api.g1_observe_authority_race_v1(
        UUID, UUID, STRING, UUID, STRING, UUID, STRING
      )
    TO tp_gate2_authorizer_role
  `);
  await client.query(`
    GRANT EXECUTE ON FUNCTION
      tp_api.g1_record_protected_effect_v1(
        UUID, UUID, UUID, STRING, UUID, UUID, STRING, STRING, INT8, STRING
      )
    TO tp_dispatch_role
  `);
  await client.query(`
    REVOKE EXECUTE ON FUNCTION
      tp_api.g1_append_recovery_audit_v1(
        UUID, UUID, STRING, STRING, STRING, STRING, STRING, TIMESTAMPTZ, STRING
      ),
      tp_api.g1_append_recovery_audit_v2(
        UUID, UUID, UUID, STRING, STRING, UUID, STRING, STRING, STRING, STRING,
        TIMESTAMPTZ, TIMESTAMPTZ, TIMESTAMPTZ, STRING, STRING
      )
    FROM tp_recovery_audit_role
  `);
  await client.query(`
    GRANT EXECUTE ON FUNCTION
      tp_api.g1_append_recovery_audit_event_v3(
        UUID, UUID, UUID, UUID, STRING, STRING, STRING, UUID, STRING, STRING,
        STRING, STRING, TIMESTAMPTZ, STRING, STRING, STRING, TIMESTAMPTZ,
        TIMESTAMPTZ
      ),
      tp_api.g1_resolve_recovery_audit_event_v1(
        UUID, UUID, STRING
      ),
      tp_api.g1_resolve_recovery_publisher_trust_root_v1(
        STRING, STRING, STRING
      )
    TO tp_recovery_audit_role
  `);
  await client.query(
    "GRANT SELECT ON tp_api.g1_receipt_audit_v1 TO tp_audit_role"
  );

  await lockPublicRoutineDefaults(
    client,
    [bootstrapOwner, ...MANAGED_PRINCIPALS],
    ["tp_private", "tp_ledger", "tp_api"]
  );
  for (const owner of [quoteIdentifier(bootstrapOwner), "tp_owner"]) {
    for (const schema of ["tp_private", "tp_ledger", "tp_api"]) {
      await client.query(
        `ALTER DEFAULT PRIVILEGES FOR ROLE ${owner} IN SCHEMA ${schema} REVOKE ALL ON TABLES FROM public`
      );
      await client.query(
        `ALTER DEFAULT PRIVILEGES FOR ROLE ${owner} IN SCHEMA ${schema} REVOKE EXECUTE ON FUNCTIONS FROM public`
      );
    }
  }
}

export function connectionStringForUser(
  adminConnectionString,
  user,
  password,
  databaseName = "tideproof"
) {
  const url = new URL(
    connectionStringForDatabase(adminConnectionString, databaseName)
  );
  url.username = user;
  url.password = password;
  return url.toString();
}

export async function bootstrapPrimarySecurity({
  adminConnectionString,
  passwords,
  recoveryPublisherTrustRootCommitment,
  recoveryPublisherKeySetDigest
}) {
  const acceptedPasswords = validatedPasswords(passwords);
  const recoveryPublisherTrustRoot = {
    trustRootCommitment: recoveryPublisherTrustRootCommitment,
    publisherKeySetDigest: recoveryPublisherKeySetDigest
  };
  for (const [name, value] of Object.entries(recoveryPublisherTrustRoot)) {
    if (typeof value !== "string" || !/^[a-f0-9]{64}$/u.test(value)) {
      throw new Error(`${name} must be a SHA-256 digest`);
    }
  }
  const client = new Client(bootstrapDatabaseConfig({
    connectionString: connectionStringForDatabase(
      adminConnectionString,
      "tideproof"
    ),
    max: 1,
    applicationName: "tideproof-primary-security"
  }));
  let store;
  try {
    await client.connect();
    const preflight = await collectValidatedPosture(
      client,
      {
        allowMissingPrincipals: true,
        allowMissingExpectedCapabilities: true,
        allowBootstrapDefaults: true
      },
      { postureSpec: PRIMARY_PREFLIGHT_POSTURE_SPEC }
    );
    const clusterPreflight = await collectClusterManagedGrantPosture({
      adminConnectionString,
      principalDatabases: CLUSTER_PRINCIPAL_DATABASES
    });
    const bootstrapOwner =
      preflight.posture.session[0].session_user_name;
    await lockInitialPublicCapability(client, bootstrapOwner);
    await createPrincipalShells(client);
    const existingOptionalPrincipals = preflight.posture.principals
      .map((row) => row.username)
      .filter((name) => [
        ...RECOVERY_SIBLING_ROLES,
        ...RECOVERY_SIBLING_USERS
      ].includes(name));
    await lockPublicRoutineDefaults(client, [
      ...MANAGED_PRINCIPALS,
      ...existingOptionalPrincipals
    ]);
    await collectValidatedPosture(
      client,
      {
        allowMissingPrincipals: false,
        allowMissingExpectedCapabilities: true,
        allowBootstrapDefaults: false
      },
      { postureSpec: PRIMARY_PREFLIGHT_POSTURE_SPEC }
    );

    store = new AuthorityStore({
      connectionString: adminConnectionString,
      databaseName: "tideproof",
      maxConnections: 2
    });
    await store.migrate();
    await store.close();
    store = undefined;
    await lockPublicRoutineDefaults(
      client,
      [bootstrapOwner, ...MANAGED_PRINCIPALS],
      ["tp_private", "tp_ledger", "tp_api"]
    );

    await scrubManagedPrivileges(client);
    await scrubManagedMemberships(client);
    await enforcePrincipalCredentials(client, acceptedPasswords);
    await prepareOwnerPrivileges(client);
    await createAuditObjects(client, recoveryPublisherTrustRoot);
    await createFunctions(client);
    await transferOwnership(client);
    await applyGrants(client, bootstrapOwner);
    await grantExactMemberships(client);

    const attested = await collectValidatedPosture(
      client,
      {
        allowMissingPrincipals: false,
        allowMissingExpectedCapabilities: false,
        allowBootstrapDefaults: false
      },
      { attempts: 30, delayMs: 2_000 }
    );
    const clusterAttested = await collectClusterManagedGrantPosture({
      adminConnectionString,
      principalDatabases: CLUSTER_PRINCIPAL_DATABASES
    });
    return {
      roles: attested.posture.principals.filter((row) =>
        MANAGED_PRINCIPALS.includes(row.username)
      ),
      preflightPostureDigest: preflight.summary.postureDigest,
      finalPostureDigest: attested.summary.postureDigest,
      clusterPreflightPostureDigest: clusterPreflight.postureDigest,
      clusterFinalPostureDigest: clusterAttested.postureDigest
    };
  } finally {
    if (store) {
      await store.close().catch(() => {});
    }
    await client.end().catch(() => {});
  }
}

export const __test = Object.freeze({
  PRIMARY_FUNCTION_SQL_BATCH_SCHEMA,
  PRIMARY_FUNCTION_SQL_BATCH_SHA256,
  PRIMARY_FUNCTION_SQL_STATEMENT_COUNT,
  executePrimaryFunctionSqlStatements,
  primaryFunctionSqlBatchSha256,
  primaryFunctionSqlStatements,
  primaryPostureSpec: PRIMARY_POSTURE_SPEC,
  primaryPreflightPostureSpec: PRIMARY_PREFLIGHT_POSTURE_SPEC,
  validatePrimaryFunctionSqlStatements
});
