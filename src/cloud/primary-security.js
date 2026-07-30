import { Client } from "pg";
import { AuthorityStore, connectionStringForDatabase } from "./authority-store.js";

const ROLE_BINDINGS = [
  ["tp_ingest_role", "tp_ingest_user"],
  ["tp_authorizer_role", "tp_authorizer_user"],
  ["tp_dispatch_role", "tp_dispatch_user"],
  ["tp_recovery_audit_role", "tp_recovery_audit_user"],
  ["tp_audit_role", "tp_audit_user"]
];

const RUNTIME_ROLES = ROLE_BINDINGS.map(([role]) => role);

function requirePassword(passwords, user) {
  const value = passwords?.[user];
  if (typeof value !== "string" || value.length < 24) {
    throw new Error(`${user} requires a strong injected password`);
  }
  return value;
}

async function createRolesAndUsers(client, passwords) {
  await client.query("CREATE ROLE IF NOT EXISTS tp_owner");
  for (const [role, user] of ROLE_BINDINGS) {
    await client.query(`CREATE ROLE IF NOT EXISTS ${role}`);
    await client.query(`CREATE USER IF NOT EXISTS ${user}`);
    await client.query(`ALTER USER ${user} WITH PASSWORD $1`, [
      requirePassword(passwords, user)
    ]);
    await client.query(`GRANT ${role} TO ${user}`);
  }
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

async function createAuditObjects(client) {
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

async function createFunctions(client) {
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
      VALUES (
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
      )
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
            transaction_timestamp() + INTERVAL '5 minutes'
            THEN 'future_observation'
          WHEN evidence.valid_from > transaction_timestamp()
            THEN 'not_yet_valid'
          WHEN evidence.valid_until <= transaction_timestamp()
            THEN 'expired'
          WHEN evidence.agency_scope NOT IN (p_agency, '*')
            THEN 'out_of_scope'
          ELSE 'admissible'
        END,
        evidence.evidence_digest,
        transaction_timestamp()
      FROM tp_private.g1_evidence AS evidence
      WHERE evidence.tenant_id = p_tenant_id
        AND evidence.evidence_id = p_evidence_id
        AND evidence.incident_id = p_incident_id
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
            transaction_timestamp() + INTERVAL '5 minutes'
            THEN 'future_observation'
          WHEN evidence.valid_from > transaction_timestamp()
            THEN 'not_yet_valid'
          WHEN evidence.valid_until <= transaction_timestamp()
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
                transaction_timestamp() + INTERVAL '5 minutes'
              AND other.valid_from <= transaction_timestamp()
              AND other.valid_until > transaction_timestamp()
              AND other.agency_scope IN (p_agency, '*')
          )
            THEN 'unresolved_conflict'
          ELSE 'admissible'
        END,
        evidence.evidence_digest,
        transaction_timestamp()
      FROM tp_private.g1_evidence AS evidence
      LEFT JOIN tp_ledger.g1_evidence_verification_receipts AS verification
        ON verification.tenant_id = evidence.tenant_id
       AND verification.evidence_id = evidence.evidence_id
      LEFT JOIN tp_private.g1_verification_keys AS verification_key
        ON verification_key.tenant_id = evidence.tenant_id
       AND verification_key.verification_key_id =
         evidence.verification_key_id
      WHERE evidence.tenant_id = p_tenant_id
        AND evidence.evidence_id = p_evidence_id
        AND evidence.incident_id = p_incident_id
    $$
  `);

  await client.query(`
    CREATE OR REPLACE FUNCTION tp_api.g1_spend_authority_v1(
      p_tenant_id UUID,
      p_operation_id UUID,
      p_request_digest STRING,
      p_request_payload JSONB,
      p_run_id UUID,
      p_incident_id UUID,
      p_resource_id STRING,
      p_agent_id STRING,
      p_authenticated_agent_id STRING,
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
      decision_replay_kind STRING
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
    BEGIN
      IF p_agent_id <> p_authenticated_agent_id THEN
        RAISE EXCEPTION 'authenticated actor mismatch'
          USING ERRCODE = '42501';
      END IF;
      IF length(p_request_digest) <> 64
        OR length(p_payload_digest) <> 64 THEN
        RAISE EXCEPTION 'digest must be SHA-256 hex'
          USING ERRCODE = '22023';
      END IF;
      IF p_lease_ms < 1000 OR p_lease_ms > 600000 THEN
        RAISE EXCEPTION 'lease duration outside policy'
          USING ERRCODE = '22023';
      END IF;

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
        receipt.operation_id
      INTO
        v_existing_digest,
        v_existing_outcome,
        v_existing_reason,
        v_existing_fence,
        v_existing_expiry,
        v_existing_operation
        FROM tp_ledger.g1_authority_receipts AS receipt
        WHERE receipt.tenant_id = p_tenant_id
          AND receipt.operation_id = p_operation_id;
        IF v_existing_digest <> p_request_digest THEN
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
          'operation_replay'::STRING;
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
        receipt.operation_id
      INTO
        v_existing_digest,
        v_existing_outcome,
        v_existing_reason,
        v_existing_fence,
        v_existing_expiry,
        v_existing_operation
        FROM tp_ledger.g1_authority_receipts AS receipt
        WHERE receipt.tenant_id = p_tenant_id
          AND receipt.request_digest = p_request_digest;
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
          'semantic_replay'::STRING;
        RETURN;
      END IF;

      INSERT INTO tp_ledger.g1_authority_receipts (
        tenant_id,
        operation_id,
        request_digest,
        request_payload,
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
          receipt.request_digest
        INTO
          v_existing_outcome,
          v_existing_reason,
          v_existing_fence,
          v_existing_expiry,
          v_existing_operation,
          v_existing_digest
        FROM tp_ledger.g1_authority_receipts AS receipt
        WHERE receipt.tenant_id = p_tenant_id
          AND (
            receipt.operation_id = p_operation_id
            OR receipt.request_digest = p_request_digest
          )
        LIMIT 2;
        IF v_existing_outcome = 'pending' THEN
          RAISE EXCEPTION 'receipt conflict was not terminal'
            USING ERRCODE = 'XX000';
        END IF;
        IF v_existing_operation = p_operation_id THEN
          v_replay_kind := 'operation_replay';
        ELSE
          v_replay_kind := 'semantic_replay';
        END IF;
        RETURN QUERY SELECT
          v_existing_outcome,
          v_existing_reason,
          v_existing_fence,
          v_existing_expiry,
          v_existing_operation,
          v_existing_digest,
          v_replay_kind;
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
          NULL::STRING;
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
          NULL::STRING;
        RETURN;
      END IF;
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
          NULL::STRING;
        RETURN;
      END IF;
      IF v_holder_operation IS NOT NULL
        AND v_holder_expiry > transaction_timestamp() THEN
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
          NULL::STRING;
        RETURN;
      END IF;

      v_new_fence := NULL;
      UPDATE tp_private.g1_resources AS resource
      SET current_fence = resource.current_fence + 1,
          holder_incident_id = p_incident_id,
          holder_operation_id = p_operation_id,
          holder_agent_id = p_agent_id,
          lease_expires_at =
            transaction_timestamp() +
            (p_lease_ms * INTERVAL '1 millisecond'),
          updated_at = transaction_timestamp()
      WHERE resource.tenant_id = p_tenant_id
        AND resource.resource_id = p_resource_id
        AND resource.active_run_id = p_run_id
        AND resource.current_fence < 9223372036854775807
        AND (
          resource.holder_operation_id IS NULL
          OR resource.lease_expires_at <= transaction_timestamp()
        )
      RETURNING resource.current_fence, resource.lease_expires_at
      INTO v_new_fence, v_new_expiry;
      IF v_new_fence IS NULL THEN
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
        NULL::STRING;
    END
    $$
  `);

  await client.query(`
    CREATE OR REPLACE FUNCTION tp_api.g1_resolve_request_v1(
      p_tenant_id UUID,
      p_operation_id UUID,
      p_request_digest STRING
    )
    RETURNS TABLE(
      operation_id UUID,
      request_digest STRING,
      outcome STRING,
      reason STRING,
      fencing_token INT8,
      lease_expires_at TIMESTAMPTZ,
      outbox_intent_id UUID,
      current_fence INT8,
      active_run_id UUID,
      holder_operation_id UUID
    )
    LANGUAGE SQL
    SECURITY DEFINER
    AS $$
      SELECT
        receipt.operation_id,
        receipt.request_digest,
        receipt.outcome,
        receipt.reason,
        receipt.fencing_token,
        receipt.lease_expires_at,
        outbox.intent_id,
        resource.current_fence,
        resource.active_run_id,
        resource.holder_operation_id
      FROM tp_ledger.g1_authority_receipts AS receipt
      LEFT JOIN tp_ledger.g1_outbox_intents AS outbox
        ON outbox.tenant_id = receipt.tenant_id
       AND outbox.operation_id = receipt.operation_id
      LEFT JOIN tp_private.g1_resources AS resource
        ON resource.tenant_id = receipt.tenant_id
       AND resource.resource_id = receipt.resource_id
      WHERE receipt.tenant_id = p_tenant_id
        AND (
          receipt.operation_id = p_operation_id
          OR receipt.request_digest = p_request_digest
        )
      LIMIT 2
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
      VALUES (
        p_audit_id,
        p_recovery_session_id,
        p_caller_subject_hash,
        p_tool_name,
        p_query_template_digest,
        p_bound_input_digest,
        p_result_digest,
        p_source_watermark,
        p_outcome
      )
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
      VALUES (
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
      )
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
       AND receipt.agent_id = p_agent_id
       AND receipt.outcome = 'resource_reserved'
      WHERE resource.tenant_id = p_tenant_id
        AND resource.resource_id = p_resource_id
        AND resource.active_run_id = p_run_id
        AND resource.holder_incident_id = p_incident_id
        AND resource.holder_operation_id = p_operation_id
        AND resource.holder_agent_id = p_agent_id
        AND resource.current_fence = p_fencing_token
        AND resource.lease_expires_at > transaction_timestamp()
      ON CONFLICT DO NOTHING
      RETURNING effect_key, operation_id
    $$
  `);
}

async function transferOwnership(client) {
  for (const object of [
    "tp_private.g1_evidence",
    "tp_private.g1_verification_keys",
    "tp_private.g1_resources",
    "tp_private.g1_retry_probes",
    "tp_ledger.g1_evidence_verification_receipts",
    "tp_ledger.g1_authority_receipts",
    "tp_ledger.g1_outbox_intents",
    "tp_ledger.g1_protected_effects",
    "tp_ledger.g1_recovery_audit_receipts",
    "tp_ledger.g1_recovery_audit_receipts_v2",
    "tp_ledger.g1_recovery_audit_events_v3"
  ]) {
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
    "tp_api.g1_observe_admissibility_v1(UUID, UUID, UUID, STRING)",
    "tp_api.g1_observe_admissibility_v2(UUID, UUID, UUID, STRING)",
    "tp_api.g1_spend_authority_v1(UUID, UUID, STRING, JSONB, UUID, UUID, STRING, STRING, STRING, STRING, UUID, UUID, JSONB, STRING, STRING, INT8)",
    "tp_api.g1_resolve_request_v1(UUID, UUID, STRING)",
    "tp_api.g1_append_recovery_audit_v1(UUID, UUID, STRING, STRING, STRING, STRING, STRING, TIMESTAMPTZ, STRING)",
    "tp_api.g1_append_recovery_audit_v2(UUID, UUID, UUID, STRING, STRING, UUID, STRING, STRING, STRING, STRING, TIMESTAMPTZ, TIMESTAMPTZ, TIMESTAMPTZ, STRING, STRING)",
    "tp_api.g1_append_recovery_audit_event_v3(UUID, UUID, UUID, UUID, STRING, STRING, STRING, UUID, STRING, STRING, STRING, STRING, TIMESTAMPTZ, STRING, STRING, STRING, TIMESTAMPTZ, TIMESTAMPTZ)",
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

async function applyGrants(client) {
  await client.query("REVOKE ALL ON DATABASE tideproof FROM public");
  await client.query("REVOKE CREATE ON SCHEMA public FROM public");
  await client.query(
    "REVOKE ALL ON SCHEMA tp_private, tp_ledger, tp_api FROM public"
  );
  await client.query(
    "REVOKE ALL ON ALL TABLES IN SCHEMA tp_private, tp_ledger, tp_api FROM public"
  );

  for (const role of RUNTIME_ROLES) {
    await client.query(`GRANT CONNECT ON DATABASE tideproof TO ${role}`);
    await client.query(
      `GRANT USAGE ON SCHEMA tp_private, tp_ledger, tp_api TO ${role}`
    );
    await client.query(
      `REVOKE ALL ON ALL TABLES IN SCHEMA tp_private, tp_ledger FROM ${role}`
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
      tp_api.g1_get_verification_key_v1(UUID, STRING),
      tp_api.g1_append_verified_evidence_v2(
        UUID, UUID, UUID, STRING, STRING, STRING, STRING, STRING, STRING,
        STRING, STRING, STRING, STRING, TIMESTAMPTZ, TIMESTAMPTZ,
        TIMESTAMPTZ, STRING, STRING, STRING
      )
    TO tp_ingest_role
  `);
  await client.query(`
    GRANT EXECUTE ON FUNCTION
      tp_api.g1_observe_admissibility_v1(UUID, UUID, UUID, STRING),
      tp_api.g1_observe_admissibility_v2(UUID, UUID, UUID, STRING),
      tp_api.g1_spend_authority_v1(
        UUID, UUID, STRING, JSONB, UUID, UUID, STRING, STRING, STRING, STRING,
        UUID, UUID, JSONB, STRING, STRING, INT8
      ),
      tp_api.g1_resolve_request_v1(UUID, UUID, STRING)
    TO tp_authorizer_role
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
      )
    TO tp_recovery_audit_role
  `);
  await client.query(
    "GRANT SELECT ON tp_api.g1_receipt_audit_v1 TO tp_audit_role"
  );

  for (const owner of ["bc", "tp_owner"]) {
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
  passwords
}) {
  const store = new AuthorityStore({
    connectionString: adminConnectionString,
    databaseName: "tideproof",
    maxConnections: 2
  });
  await store.migrate();
  await store.close();

  const client = new Client({
    connectionString: connectionStringForDatabase(
      adminConnectionString,
      "tideproof"
    )
  });
  try {
    await client.connect();
    await createRolesAndUsers(client, passwords);
    await prepareOwnerPrivileges(client);
    await createAuditObjects(client);
    await createFunctions(client);
    await transferOwnership(client);
    await applyGrants(client);

    const roles = await client.query(`
      SELECT username, options
      FROM [SHOW USERS]
      WHERE username IN (
        'tp_owner',
        'tp_ingest_role',
        'tp_ingest_user',
        'tp_authorizer_role',
        'tp_authorizer_user',
        'tp_dispatch_role',
        'tp_dispatch_user',
        'tp_recovery_audit_role',
        'tp_recovery_audit_user',
        'tp_audit_role',
        'tp_audit_user'
      )
      ORDER BY username
    `);
    return { roles: roles.rows };
  } finally {
    await client.end().catch(() => {});
  }
}
