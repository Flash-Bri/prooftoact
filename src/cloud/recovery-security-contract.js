const ZERO_DIGEST = "0".repeat(64);

export const PRIMARY_MANAGED_BASE_TABLES = Object.freeze([
  "tp_private.g1_evidence",
  "tp_private.g1_verification_keys",
  "tp_private.g1_vector_retrieval_sets",
  "tp_private.g1_vector_candidates",
  "tp_private.g1_vector_exclusions",
  "tp_private.g1_resources",
  "tp_private.g1_retry_probes",
  "tp_ledger.g1_evidence_verification_receipts",
  "tp_ledger.g1_logical_authority_epochs",
  "tp_ledger.g1_dvi_selection_receipts",
  "tp_ledger.g1_dvi_proposal_receipts",
  "tp_ledger.g1_authority_receipts",
  "tp_ledger.g1_outbox_intents",
  "tp_ledger.g1_protected_effects",
  "tp_ledger.g1_recovery_audit_receipts",
  "tp_ledger.g1_recovery_audit_receipts_v2",
  "tp_ledger.g1_recovery_audit_events_v3",
  "tp_ledger.g1_recovery_publisher_trust_roots"
]);

// Each statement is rollback-bounded by the caller and intentionally reads no
// table column. A write-only credential must therefore exercise its actual
// INSERT, column-specific UPDATE, or DELETE privilege instead of false-passing
// because SELECT privilege is absent.
export const RECOVERY_TRUST_ROOT_WRITE_PROBES = Object.freeze([
  `
    UPDATE tp_ledger.g1_recovery_publisher_trust_roots
    SET trust_root_id = 'gate1-recovery-publisher-v1'
  `,
  `
    UPDATE tp_ledger.g1_recovery_publisher_trust_roots
    SET trust_root_commitment = '${ZERO_DIGEST}'
  `,
  `
    UPDATE tp_ledger.g1_recovery_publisher_trust_roots
    SET publisher_key_set_digest = '${ZERO_DIGEST}'
  `,
  `
    UPDATE tp_ledger.g1_recovery_publisher_trust_roots
    SET committed_at = '1970-01-01T00:00:00.000Z'::TIMESTAMPTZ
  `,
  `DELETE FROM tp_ledger.g1_recovery_publisher_trust_roots`,
  `
    INSERT INTO tp_ledger.g1_recovery_publisher_trust_roots (
      trust_root_id,
      trust_root_commitment,
      publisher_key_set_digest
    ) VALUES (
      'gate1-recovery-publisher-v1',
      '${ZERO_DIGEST}',
      '${ZERO_DIGEST}'
    ) ON CONFLICT (trust_root_id) DO NOTHING
  `
]);
