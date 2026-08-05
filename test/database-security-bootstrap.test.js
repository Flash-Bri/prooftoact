import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const primaryUrl = new URL("../src/cloud/primary-security.js", import.meta.url);
const authorityStoreUrl = new URL(
  "../src/cloud/authority-store.js",
  import.meta.url
);
const recoveryUrl = new URL("../src/cloud/recovery-security.js", import.meta.url);
const recoveryStoreUrl = new URL("../src/cloud/recovery-store.js", import.meta.url);
const recoveryBrokerUrl = new URL("../src/cloud/recovery-broker.js", import.meta.url);
const signedIngestUrl = new URL("../src/cloud/signed-ingest.js", import.meta.url);
const admissibleVectorUrl = new URL(
  "../src/cloud/admissible-vector-retrieval.js",
  import.meta.url
);
const recoveryScriptUrls = [
  new URL("../scripts/gate1-recovery.js", import.meta.url),
  new URL("../scripts/gate1-recovery-broker.js", import.meta.url)
];
const gate1AuthorityUrl = new URL(
  "../scripts/gate1-authority.js",
  import.meta.url
);
const gate1SecurityUrl = new URL(
  "../scripts/gate1-security.js",
  import.meta.url
);
const fullDrillEvidenceUrl = new URL(
  "../docs/FULL_DRILL_EVIDENCE.md",
  import.meta.url
);

test("primary bootstrap audits posture before credentials, ownership, or grants", async () => {
  const source = await readFile(primaryUrl, "utf8");
  const bootstrap = source.slice(source.indexOf("export async function bootstrapPrimarySecurity"));
  const preflight = bootstrap.indexOf("collectValidatedPosture(");
  assert.ok(preflight >= 0);
  const clusterPreflight = bootstrap.indexOf(
    "collectClusterManagedGrantPosture({"
  );
  assert.ok(clusterPreflight > preflight);
  const initialLock = bootstrap.indexOf(
    "lockInitialPublicCapability(client, bootstrapOwner)"
  );
  assert.ok(initialLock > clusterPreflight);
  assert.ok(bootstrap.indexOf("createPrincipalShells(client)") > initialLock);
  assert.ok(
    bootstrap.indexOf("lockPublicRoutineDefaults(client, [") > initialLock
  );
  for (const later of [
    "createPrincipalShells(client)",
    "enforcePrincipalCredentials(client, acceptedPasswords)",
    "prepareOwnerPrivileges(client)",
    "transferOwnership(client)",
    "applyGrants("
  ]) {
    assert.ok(bootstrap.indexOf(later) > preflight, later);
  }
  assert.match(source, /REVOKE ALL ON ALL FUNCTIONS IN SCHEMA tp_private, tp_ledger, tp_api FROM \$\{principal\}/u);
  assert.doesNotMatch(source, /\["bc", "tp_owner"\]/u);
  assert.match(
    bootstrap.slice(0, bootstrap.indexOf("createPrincipalShells(client)")),
    /allowMissingPrincipals: true,[\s\S]*allowMissingExpectedCapabilities: true,[\s\S]*allowBootstrapDefaults: true/u
  );
  assert.match(
    source,
    /roleGrantPolicies: PRIMARY_ROLE_GRANT_POLICIES/u
  );
  assert.match(
    source,
    /roles: attested\.posture\.principals\.filter\(\(row\) =>[\s\S]*MANAGED_PRINCIPALS\.includes\(row\.username\)/u
  );
  const migration = bootstrap.indexOf("await store.migrate()");
  const schemaDefaultLock = bootstrap.indexOf(
    "await lockPublicRoutineDefaults(\n      client,",
    migration
  );
  assert.ok(schemaDefaultLock > migration);
  assert.ok(bootstrap.indexOf("await createFunctions(client)") > schemaDefaultLock);
});

test("snapshot exclusions are exact, bounded, and removed with the snapshot", async () => {
  const source = await readFile(primaryUrl, "utf8");
  const store = await readFile(authorityStoreUrl, "utf8");
  const tableDefinition = (name) => {
    const start = store.indexOf(`CREATE TABLE IF NOT EXISTS ${name}`);
    assert.notEqual(start, -1, `${name} definition missing`);
    const end = store.indexOf("    `);", start);
    assert.notEqual(end, -1, `${name} definition unterminated`);
    return store.slice(start, end);
  };
  const functionDefinition = (name) => {
    const start = source.indexOf(`CREATE OR REPLACE FUNCTION tp_api.${name}`);
    assert.notEqual(start, -1, `${name} definition missing`);
    const end = source.indexOf("  `);", start);
    assert.notEqual(end, -1, `${name} definition unterminated`);
    return source.slice(start, end);
  };
  const candidates = tableDefinition("tp_private.g1_vector_candidates");
  const exclusions = tableDefinition("tp_private.g1_vector_exclusions");
  assert.match(candidates, /evidence_digest STRING\(64\) NOT NULL/u);
  assert.match(exclusions, /evidence_digest STRING\(64\) NULL/u);
  assert.match(source, /v_exclusion_count > 10000/u);
  assert.match(
    functionDefinition("g1_observe_vector_exclusion_v1"),
    /retrieval\.tenant_id = p_tenant_id[\s\S]*retrieval\.retrieval_id = p_retrieval_id[\s\S]*retrieval\.incident_id = p_incident_id[\s\S]*retrieval\.agency = p_agency[\s\S]*retrieval\.policy_version = p_policy_version[\s\S]*exclusion\.evidence_id = p_evidence_id[\s\S]*exclusion\.observed_at = retrieval\.admitted_at/u
  );
  assert.match(
    functionDefinition("g1_delete_vector_set_v1"),
    /DELETE FROM tp_private\.g1_vector_candidates[\s\S]*DELETE FROM tp_private\.g1_vector_exclusions/u
  );
  assert.match(
    functionDefinition("g1_purge_expired_vector_sets_v1"),
    /DELETE FROM tp_private\.g1_vector_candidates[\s\S]*DELETE FROM tp_private\.g1_vector_exclusions/u
  );
});

test("recovery bootstrap audits first and grants no private-schema access", async () => {
  const source = await readFile(recoveryUrl, "utf8");
  const bootstrap = source.slice(source.indexOf("export async function bootstrapRecoverySecurity"));
  const preflight = bootstrap.indexOf("collectValidatedRecoveryPosture(");
  assert.ok(preflight >= 0);
  const clusterPreflight = bootstrap.indexOf(
    "collectClusterManagedGrantPosture({"
  );
  assert.ok(clusterPreflight > preflight);
  const initialLock = bootstrap.indexOf(
    "lockInitialRecoveryPublicCapability(client, bootstrapOwner)"
  );
  assert.ok(initialLock > clusterPreflight);
  assert.ok(
    bootstrap.indexOf("CREATE ROLE IF NOT EXISTS tp_recovery_owner") >
      initialLock
  );
  assert.ok(
    bootstrap.indexOf("lockRecoveryPublicRoutineDefaults(client, [") >
      initialLock
  );
  assert.ok(bootstrap.indexOf("ALTER USER ${RECOVERY_PUBLISHER_USER}") > preflight);
  assert.ok(bootstrap.indexOf("GRANT ALL ON DATABASE tideproof_recovery") > preflight);
  assert.match(
    source,
    /GRANT USAGE ON SCHEMA mcp_api TO \$\{RECOVERY_PUBLISHER_ROLE\}/u
  );
  assert.doesNotMatch(
    source,
    /GRANT USAGE ON SCHEMA mcp_api, mcp_private/u
  );
  assert.match(
    source,
    /REVOKE ALL ON ALL FUNCTIONS IN SCHEMA mcp_private, mcp_public, mcp_api FROM public/u
  );
  assert.doesNotMatch(source, /\["bc", "tp_recovery_owner"\]/u);
  assert.match(
    source,
    /roleGrantPolicies: Object\.freeze\([\s\S]*append_recovery_bundle_v2/u
  );
  assert.match(
    source,
    /roles: attested\.posture\.principals\.filter\(\(row\) =>/u
  );
  const migration = bootstrap.indexOf("await migrationStore.migrate()");
  const schemaDefaultLock = bootstrap.indexOf(
    "await lockRecoveryPublicRoutineDefaults(\n      client,",
    migration
  );
  assert.ok(schemaDefaultLock > migration);
  assert.ok(
    bootstrap.indexOf("CREATE OR REPLACE FUNCTION mcp_api", schemaDefaultLock) >
      schemaDefaultLock
  );
});

test("recovery publication rejects database-stale input before canonical occupancy", async () => {
  const source = await readFile(recoveryUrl, "utf8");
  const start = source.indexOf(
    "CREATE OR REPLACE FUNCTION mcp_api.append_recovery_bundle_v2"
  );
  assert.notEqual(start, -1);
  const end = source.indexOf("    `);", start);
  assert.notEqual(end, -1);
  const definition = source.slice(start, end);
  const canonicalLookup = definition.indexOf("SELECT count(*)::INT8");
  const canonicalInsert = definition.indexOf(
    "INSERT INTO mcp_private.recovery_bundles_v2"
  );
  assert.ok(canonicalLookup > 0);
  assert.ok(canonicalInsert > canonicalLookup);
  for (const predicate of [
    "p_source_commit_ts < statement_timestamp() - INTERVAL '1 hour'",
    "p_source_commit_ts > statement_timestamp() + INTERVAL '1 minute'",
    "p_expires_at <= statement_timestamp()",
    "p_expires_at > statement_timestamp() + INTERVAL '24 hours'"
  ]) {
    const position = definition.indexOf(predicate);
    assert.ok(position > 0, predicate);
    assert.ok(position < canonicalLookup, predicate);
    assert.ok(position < canonicalInsert, predicate);
  }
});

test("fixed and direct recovery reads share one database-time freshness filter", async () => {
  const source = await readFile(recoveryStoreUrl, "utf8");
  const declaration = source.indexOf(
    "const RECOVERY_DATABASE_FRESHNESS_SQL = `"
  );
  assert.notEqual(declaration, -1);
  const declarationEnd = source.indexOf("`.trim();", declaration);
  assert.notEqual(declarationEnd, -1);
  const freshnessSql = source.slice(declaration, declarationEnd);
  for (const predicate of [
    "source_commit_ts >= statement_timestamp() - INTERVAL '1 hour'",
    "source_commit_ts <= statement_timestamp() + INTERVAL '1 minute'",
    "expires_at > statement_timestamp()",
    "expires_at <= statement_timestamp() + INTERVAL '24 hours'"
  ]) {
    assert.equal(freshnessSql.includes(predicate), true, predicate);
  }
  assert.equal(
    source.match(/\$\{RECOVERY_DATABASE_FRESHNESS_SQL\}/gu)?.length,
    2
  );
});

test("every database SECURITY DEFINER body binds the exact session user", async () => {
  const sharedAuthorizerGuard =
    /session_user (?:IN|NOT IN) \(\s*'tp_authorizer_user',\s*'tp_gate2_authorizer_user'\s*\)/u;
  const internalAdmissibilityGuard =
    /session_user IN \(\s*'tp_authorizer_user',\s*'tp_gate2_authorizer_user',\s*'tp_recovery_source_user'\s*\)/u;
  const expectedPrimaryGuards = new Map([
    ["g1_append_verified_evidence_v1", /session_user = 'tp_ingest_user'/u],
    ["g1_get_verification_key_v1", /session_user = 'tp_ingest_user'/u],
    ["g1_append_verified_evidence_v2", /session_user <> 'tp_ingest_user'/u],
    ["g1_resolve_verified_evidence_v1", /session_user = 'tp_ingest_user'/u],
    ["g1_observe_admissibility_v1", /session_user = 'tp_authorizer_user'/u],
    ["g1_list_admissibility_internal_v1", internalAdmissibilityGuard],
    ["g1_observe_admissibility_v2", sharedAuthorizerGuard],
    ["g1_prepare_vector_set_v1", /session_user <> 'tp_authorizer_user'/u],
    ["g1_observe_vector_exclusion_v1", /session_user <> 'tp_authorizer_user'/u],
    ["g1_resolve_vector_set_v1", /session_user = 'tp_authorizer_user'/u],
    ["g1_rank_vector_set_v1", /session_user <> 'tp_authorizer_user'/u],
    ["g1_delete_vector_set_v1", /session_user <> 'tp_authorizer_user'/u],
    ["g1_purge_expired_vector_sets_v1", /session_user <> 'tp_authorizer_user'/u],
    ["g1_commit_dvi_selection_v1", /session_user <> 'tp_authorizer_user'/u],
    ["g1_authorize_dvi_proposal_v1", /session_user <> 'tp_authorizer_user'/u],
    ["g1_authority_receipt_current_v1", sharedAuthorizerGuard],
    ["g1_spend_authority_v1", sharedAuthorizerGuard],
    ["g2_spend_authority_race_v1", /session_user <> 'tp_gate2_authorizer_user'/u],
    ["g1_resolve_request_v1", sharedAuthorizerGuard],
    ["g1_observe_authority_race_v1", sharedAuthorizerGuard],
    ["g1_append_recovery_audit_v1", /session_user = 'tp_recovery_audit_user'/u],
    ["g1_append_recovery_audit_v2", /session_user = 'tp_recovery_audit_user'/u],
    ["g1_append_recovery_audit_event_v3", /session_user <> 'tp_recovery_audit_user'/u],
    ["g1_resolve_recovery_audit_event_v1", /session_user = 'tp_recovery_audit_user'/u],
    ["g1_resolve_recovery_source_receipt_v2", /session_user = 'tp_recovery_source_user'/u],
    ["g1_resolve_recovery_publisher_trust_root_v1", /session_user = 'tp_recovery_audit_user'/u],
    ["g1_record_protected_effect_v1", /session_user = 'tp_dispatch_user'/u]
  ]);
  for (const [url, expectedGuards] of [
    [primaryUrl, expectedPrimaryGuards],
    [recoveryUrl, new Map([
      [
        "append_recovery_bundle_v2",
        /session_user <> '\$\{RECOVERY_PUBLISHER_USER\}'/u
      ],
      [
        "resolve_recovery_bundle_v1",
        /session_user = '\$\{RECOVERY_PUBLISHER_USER\}'/u
      ]
    ])]
  ]) {
    const source = await readFile(url, "utf8");
    const definitions = [...source.matchAll(
      /CREATE OR REPLACE FUNCTION\s+[\w.]+\.([a-z0-9_]+)\([\s\S]*?AS \$\$([\s\S]*?)\$\$/g
    )];
    assert.equal(definitions.length, expectedGuards.size, url.pathname);
    for (const [definition, functionName, body] of definitions) {
      assert.match(definition, /\bSECURITY DEFINER\b/u, url.pathname);
      assert.equal(expectedGuards.has(functionName), true, functionName);
      assert.match(body, expectedGuards.get(functionName), functionName);
    }
  }
});

test("recovery evidence selects one exact upstream authority receipt", async () => {
  for (const url of recoveryScriptUrls) {
    const source = await readFile(url, "utf8");
    for (const field of [
      "RECOVERY_SOURCE_TENANT_ID",
      "RECOVERY_SOURCE_RUN_ID",
      "RECOVERY_SOURCE_INCIDENT_ID",
      "RECOVERY_SOURCE_EVIDENCE_ID",
      "RECOVERY_SOURCE_RESOURCE_ID",
      "RECOVERY_SOURCE_OPERATION_ID",
      "RECOVERY_SOURCE_REQUEST_DIGEST",
      "RECOVERY_SOURCE_AUTHORITY_EVIDENCE_BINDING_SHA256",
      "RECOVERY_SOURCE_SELECTED_EVIDENCE_BINDING_SHA256"
    ]) {
      assert.equal(source.includes(field), true, `${url.pathname}:${field}`);
    }
    assert.doesNotMatch(source, /ORDER BY receipt\.recorded_at DESC/u);
    assert.doesNotMatch(source, /latestSyntheticReceipt/u);
    assert.match(source, /loadCommittedRecoveryPublisherSigner\(\)/u);
    assert.match(source, /signer\.trustedPublisherKeys/u);
    assert.match(source, /resolveCommittedRecoveryPublisherTrustRoot\(/u);
    assert.match(source, /resolveCommittedRecoverySourceReceipt\(/u);
    assert.match(source, /assertRecoveryPublisherTrustRootWriteDenied\(/u);
    assert.match(source, /assertRecoveryRunnerBaseTableReadsDenied\(/u);
    assert.match(source, /PRIMARY_RECOVERY_SOURCE_DATABASE_URL/u);
    assert.match(source, /PRIMARY_AUDIT_DATABASE_URL/u);
    assert.doesNotMatch(source, /PRIMARY_DATABASE_URL/u);
    assert.match(source, /primaryAuditConnectionString: primaryAuditUrl/u);
    assert.match(source, /publisherTrustRootCommitment/u);
    assert.doesNotMatch(source, /createSyntheticRecoverySigner/u);
    const signerLoaded = source.indexOf("loadCommittedRecoveryPublisherSigner()");
    const trustResolved = source.indexOf(
      "await resolveCommittedRecoveryPublisherTrustRoot({"
    );
    const bundleSigned = source.indexOf("signer.sign({");
    assert.ok(trustResolved > signerLoaded, `${url.pathname}: trust resolution`);
    assert.ok(bundleSigned > trustResolved, `${url.pathname}: sign ordering`);
  }
});

test("recovery publisher trust root is immutable and runner-readable only", async () => {
  const source = await readFile(primaryUrl, "utf8");
  assert.match(
    source,
    /CREATE TABLE IF NOT EXISTS tp_ledger\.g1_recovery_publisher_trust_roots[\s\S]*PRIMARY KEY \(trust_root_id\)/u
  );
  assert.match(
    source,
    /INSERT INTO tp_ledger\.g1_recovery_publisher_trust_roots[\s\S]*ON CONFLICT \(trust_root_id\) DO NOTHING/u
  );
  assert.doesNotMatch(
    source,
    /GRANT (?:INSERT|UPDATE|DELETE)[\s\S]*g1_recovery_publisher_trust_roots[\s\S]*tp_recovery_audit_role/u
  );
  assert.match(
    source,
    /g1_resolve_recovery_publisher_trust_root_v1\(STRING, STRING, STRING\)/u
  );
  assert.match(
    source,
    /tp_recovery_source_role:[\s\S]*g1_resolve_recovery_source_receipt_v2\(UUID, UUID, UUID, UUID, STRING, UUID, STRING\)/u
  );
  assert.match(source, /\["tp_recovery_source_role", "tp_recovery_source_user"\]/u);
});

test("Gate One trust-root write probes use the shared rollback-bounded verifier", async () => {
  const source = await readFile(gate1SecurityUrl, "utf8");
  assert.match(
    source,
    /assertRecoveryPublisherTrustRootWriteDeniedWithClient/u
  );
  assert.match(
    source,
    /await assertRecoveryPublisherTrustRootWriteDeniedWithClient\(client\)/u
  );
  assert.doesNotMatch(
    source,
    /async function expectTrustRootWritesDenied\(client\)/u
  );
});

test("recovery source resolver binds the full receipt and outbox identity", async () => {
  const source = await readFile(primaryUrl, "utf8");
  const resolver = source.match(
    /CREATE OR REPLACE FUNCTION tp_api\.g1_resolve_recovery_source_receipt_v2\([\s\S]*?AS \$\$([\s\S]*?)\$\$/u
  )?.[1];
  assert.ok(resolver);
  for (const field of [
    "request_digest",
    "proposal_digest",
    "logical_action_digest",
    "authorization_epoch",
    "logical_authority_key_sha256",
    "authorization_binding_sha256",
    "run_id",
    "incident_id",
    "resource_id",
    "fencing_token",
    "effect_key",
    "payload_digest"
  ]) {
    assert.match(
      resolver,
      new RegExp(`outbox\\.${field}\\s*=\\s*receipt\\.${field}`, "u"),
      field
    );
  }
  for (const field of [
    "proposal_digest",
    "logical_action_digest",
    "authorization_epoch",
    "logical_authority_key_sha256",
    "authorization_binding_sha256",
    "run_id",
    "incident_id",
    "resource_id",
    "agency",
    "policy_version"
  ]) {
    assert.match(
      resolver,
      new RegExp(`proposal\\.${field}\\s*=\\s*receipt\\.${field}`, "u"),
      `proposal.${field}`
    );
  }
  assert.match(
    resolver,
    /proposal\.selected_evidence_id\s*=\s*receipt\.evidence_id/u
  );
  assert.match(
    resolver,
    /proposal\.selected_evidence_digest\s*=\s*receipt\.evidence_digest/u
  );
  assert.match(resolver, /proposal\.authority_evidence_binding_sha256/u);
});

test("recovery source resolver upgrades by version without destructive DDL", async () => {
  const source = await readFile(primaryUrl, "utf8");
  assert.doesNotMatch(
    source,
    /DROP FUNCTION(?: IF EXISTS)? tp_api\.g1_resolve_recovery_source_receipt_v[12]\(/u
  );
  assert.match(
    source,
    /CREATE OR REPLACE FUNCTION tp_api\.g1_resolve_recovery_source_receipt_v2\(/u
  );

  const recoveryBroker = await readFile(recoveryBrokerUrl, "utf8");
  const gate1Security = await readFile(gate1SecurityUrl, "utf8");
  for (const [label, runtimeSource] of [
    ["recovery broker", recoveryBroker],
    ["Gate One security probe", gate1Security]
  ]) {
    assert.match(
      runtimeSource,
      /tp_api\.g1_resolve_recovery_source_receipt_v2\(/u,
      label
    );
    assert.doesNotMatch(
      runtimeSource,
      /tp_api\.g1_resolve_recovery_source_receipt_v1\(/u,
      label
    );
  }
});

test("recovery storage enforces one row per exact broker lookup identity", async () => {
  const source = await readFile(recoveryStoreUrl, "utf8");
  assert.match(
    source,
    /CREATE UNIQUE INDEX IF NOT EXISTS g1_recovery_bundle_v2_broker_lookup_uidx[\s\S]*tenant_id,[\s\S]*recovery_session_id,[\s\S]*subject_binding_hash,[\s\S]*source_digest/u
  );
  const reconciliation = source.match(
    /SELECT \*[\s\S]*?FROM mcp_private\.recovery_bundles_v2([\s\S]*?)ORDER BY recorded_at/u
  )?.[1];
  assert.ok(reconciliation);
  assert.match(
    reconciliation,
    /tenant_id = \$1::UUID[\s\S]*recovery_session_id = \$2::UUID[\s\S]*subject_binding_hash = \$5[\s\S]*source_digest = \$6/u
  );
});

test("recovery operator contract enumerates every exact private input", async () => {
  const source = await readFile(fullDrillEvidenceUrl, "utf8");
  for (const input of [
    "PRIMARY_RECOVERY_SOURCE_DATABASE_URL",
    "PRIMARY_AUDIT_DATABASE_URL",
    "RECOVERY_SOURCE_TENANT_ID",
    "RECOVERY_SOURCE_RUN_ID",
    "RECOVERY_SOURCE_INCIDENT_ID",
    "RECOVERY_SOURCE_EVIDENCE_ID",
    "RECOVERY_SOURCE_RESOURCE_ID",
    "RECOVERY_SOURCE_OPERATION_ID",
    "RECOVERY_SOURCE_REQUEST_DIGEST",
    "RECOVERY_SOURCE_AUTHORITY_EVIDENCE_BINDING_SHA256",
    "RECOVERY_SOURCE_SELECTED_EVIDENCE_BINDING_SHA256",
    "PRIMARY_CLUSTER_ID",
    "RECOVERY_CLUSTER_ID",
    "EXPECTED_PRIMARY_HOSTNAME",
    "EXPECTED_RECOVERY_HOSTNAME",
    "TIDEPROOF_RECOVERY_PUBLISHER_TRUST_ROOT",
    "TIDEPROOF_RECOVERY_PUBLISHER_TRUST_ROOT_COMMITMENT",
    "TIDEPROOF_RECOVERY_PUBLISHER_KEY_SET_DIGEST",
    "RECOVERY_PUBLISHER_PRIVATE_KEY_PKCS8_BASE64",
    "RECOVERY_DATABASE_URL",
    "RECOVERY_PUBLISHER_PASSWORD",
    "RECOVERY_PUBLISHER_DATABASE_URL",
    "MCP_API_KEY",
    "SOURCE_BUILD_IDENTITY"
  ]) {
    assert.equal(source.includes(input), true, input);
  }
  assert.match(source, /winner\.operationId/u);
  assert.match(source, /winner\.requestDigest/u);
  assert.match(source, /race receipt `dvi\.authorityEvidenceBindingSha256`/u);
  assert.match(source, /race receipt `dvi\.selectedEvidenceBindingSha256`/u);
  assert.match(source, /The nine `RECOVERY_SOURCE_\*` values/u);
  assert.match(source, /all 18[\s\S]*managed base-table read probes/u);
  assert.match(source, /administrator URL/u);
});

test("recovery broker verifies audit events only through the narrow resolver", async () => {
  const [source, primarySource] = await Promise.all([
    readFile(recoveryScriptUrls[1], "utf8"),
    readFile(primaryUrl, "utf8")
  ]);
  assert.match(source, /resolveCommittedRecoveryAuditEvent/u);
  assert.doesNotMatch(
    source,
    /FROM tp_ledger\.g1_recovery_audit_events_v3/u
  );
  assert.match(
    primarySource,
    /g1_resolve_recovery_audit_event_v1[\s\S]*RETURNS TABLE\([\s\S]*event_id UUID,[\s\S]*tenant_id UUID,[\s\S]*interaction_id UUID,[\s\S]*recovery_session_id UUID,[\s\S]*caller_subject_hash STRING,[\s\S]*phase STRING,[\s\S]*tool_name STRING,[\s\S]*recovery_cluster_id UUID,[\s\S]*broker_config_digest STRING,[\s\S]*query_template_digest STRING,[\s\S]*bound_input_digest STRING,[\s\S]*result_digest STRING,[\s\S]*source_watermark TIMESTAMPTZ,[\s\S]*error_code STRING,[\s\S]*event_digest STRING,[\s\S]*outcome STRING,[\s\S]*started_at TIMESTAMPTZ,[\s\S]*completed_at TIMESTAMPTZ,[\s\S]*recorded_at TIMESTAMPTZ,[\s\S]*database_now TIMESTAMPTZ/u
  );
  assert.match(
    primarySource,
    /event\.event_id,[\s\S]*event\.tenant_id,[\s\S]*event\.interaction_id,[\s\S]*event\.recovery_session_id,[\s\S]*event\.caller_subject_hash,[\s\S]*event\.phase,[\s\S]*event\.tool_name,[\s\S]*event\.recovery_cluster_id,[\s\S]*event\.broker_config_digest,[\s\S]*event\.query_template_digest,[\s\S]*event\.bound_input_digest,[\s\S]*event\.result_digest,[\s\S]*event\.source_watermark,[\s\S]*event\.error_code,[\s\S]*event\.event_digest,[\s\S]*event\.outcome,[\s\S]*event\.started_at,[\s\S]*event\.completed_at,[\s\S]*event\.recorded_at,[\s\S]*transaction_timestamp\(\)/u
  );
});

test("logical-action spend is serialized and unique across authorization epochs", async () => {
  const [primarySource, authorityStoreSource, gate1AuthoritySource] = await Promise.all([
    readFile(primaryUrl, "utf8"),
    readFile(authorityStoreUrl, "utf8"),
    readFile(gate1AuthorityUrl, "utf8")
  ]);
  assert.match(
    authorityStoreSource,
    /CREATE UNIQUE INDEX IF NOT EXISTS g1_unique_logical_action_spend[\s\S]*tenant_id,[\s\S]*logical_action_digest[\s\S]*WHERE outcome = 'resource_reserved'/u
  );
  assert.match(
    authorityStoreSource,
    /CREATE UNIQUE INDEX IF NOT EXISTS g1_unique_logical_action_outbox[\s\S]*tenant_id,[\s\S]*logical_action_digest/u
  );
  assert.match(
    authorityStoreSource,
    /CREATE UNIQUE INDEX IF NOT EXISTS g1_unique_logical_action_effect[\s\S]*tenant_id,[\s\S]*logical_action_digest/u
  );
  assert.match(
    authorityStoreSource,
    /SELECT current_epoch[\s\S]*FROM tp_ledger\.g1_logical_authority_epochs[\s\S]*logical_action_digest = \$2[\s\S]*FOR UPDATE/u
  );
  assert.match(
    authorityStoreSource,
    /reason: "proposal_authorization_superseded"/u
  );
  const spendBody = primarySource.match(
    /CREATE OR REPLACE FUNCTION tp_api\.g1_spend_authority_v1\([\s\S]*?AS \$\$([\s\S]*?)\$\$/u
  )?.[1];
  assert.ok(spendBody);
  assert.match(
    spendBody,
    /FROM tp_ledger\.g1_logical_authority_epochs AS epoch[\s\S]*logical_action_digest = p_logical_action_digest[\s\S]*FOR UPDATE/u
  );
  assert.match(
    spendBody,
    /v_current_authorization_epoch IS DISTINCT FROM[\s\S]*v_authorization_epoch[\s\S]*'proposal_authorization_superseded'/u
  );
  assert.match(
    spendBody,
    /receipt\.logical_action_digest = p_logical_action_digest[\s\S]*receipt\.outcome = 'resource_reserved'/u
  );
  assert.match(
    gate1AuthoritySource,
    /runCrossEpochRaceProof[\s\S]*afterEpochLockObserver[\s\S]*logical_authority_already_spent[\s\S]*maximum_epoch/u
  );
});

test("expired unspent proposals cannot implicitly mint a replacement epoch", async () => {
  const [primarySource, authorityStoreSource, gate1AuthoritySource] = await Promise.all([
    readFile(primaryUrl, "utf8"),
    readFile(authorityStoreUrl, "utf8"),
    readFile(gate1AuthorityUrl, "utf8")
  ]);
  assert.match(
    authorityStoreSource,
    /authorizationEpoch === 1[\s\S]*outcome: "proposal_authorization_denied"[\s\S]*reason: "explicit_new_authorization_required"/u
  );
  const authorizeBody = primarySource.match(
    /CREATE OR REPLACE FUNCTION tp_api\.g1_authorize_dvi_proposal_v1\([\s\S]*?AS \$\$([\s\S]*?)\$\$/u
  )?.[1];
  assert.ok(authorizeBody);
  assert.match(
    authorizeBody,
    /v_epoch\.current_epoch = 1[\s\S]*'explicit_new_authorization_required'/u
  );
  assert.doesNotMatch(
    authorizeBody,
    /v_authorization_epoch := v_epoch\.current_epoch \+ 1/u
  );
  assert.match(
    gate1AuthoritySource,
    /runExpiredUnspentReplacementProof[\s\S]*expireProposalAtDatabaseNowForTest[\s\S]*explicit_new_authorization_required[\s\S]*proposal_receipt_count/u
  );
});

test("authority reconciliation binds the exact receipt, outbox, and current proposal", async () => {
  const [source, primarySource] = await Promise.all([
    readFile(authorityStoreUrl, "utf8"),
    readFile(primaryUrl, "utf8")
  ]);
  assert.match(
    source,
    /WITH operation_candidate AS[\s\S]*logical_candidate AS[\s\S]*'logical_authority_replay'[\s\S]*receipt\.logical_action_digest = \$4[\s\S]*semantic_candidate AS/u
  );
  assert.match(
    source,
    /const exactRequestReplay =[\s\S]*row\.request_digest !== request\.requestDigest[\s\S]*row\.operation_id !== request\.operationId[\s\S]*row\.outcome !== "resource_reserved"/u
  );
  assert.match(
    source,
    /const exactOutbox =[\s\S]*row\.outbox_operation_id === row\.operation_id[\s\S]*row\.outbox_request_digest === row\.request_digest[\s\S]*row\.outbox_authorization_binding_sha256 ===[\s\S]*row\.authorization_binding_sha256[\s\S]*row\.outbox_intent_kind === ACTION_KIND[\s\S]*row\.outbox_payload_digest === row\.payload_digest/u
  );
  assert.match(
    source,
    /canonicalJson\(row\.outbox_payload\)[\s\S]*canonicalJson\(row\.receipt_proposal_payload\)[\s\S]*sha256\(canonicalJson\(row\.outbox_payload\)\)[\s\S]*row\.outbox_payload_digest/u
  );
  assert.match(
    source,
    /proposalExpiresAt = new Date\(proposalInput\.expiresAt\)[\s\S]*leaseExpiresAt =[^;]*new Date\(row\.lease_expires_at\)[\s\S]*resourceLeaseExpiresAt =[^;]*new Date\(row\.resource_lease_expires_at\)[\s\S]*leaseExpiresAt > databaseNow[\s\S]*resourceLeaseExpiresAt > databaseNow[\s\S]*proposalExpiresAt > databaseNow/u
  );
  assert.match(source, /operationDigest: committedRequestDigest/u);
  assert.match(
    source,
    /reason: result\.reason \?\? result\.receipt\?\.reason \?\? null/u
  );
  assert.match(source, /status: commit\.status/u);
  const resolver = primarySource.match(
    /CREATE OR REPLACE FUNCTION tp_api\.g1_resolve_request_v1\([\s\S]*?AS \$\$([\s\S]*?)\$\$/u
  )?.[1];
  assert.ok(resolver);
  assert.match(
    primarySource,
    /g1_resolve_request_v1\([\s\S]*p_logical_action_digest STRING[\s\S]*RETURNS TABLE/u
  );
  assert.match(
    resolver,
    /logical_candidate AS[\s\S]*receipt\.logical_action_digest = p_logical_action_digest/u
  );
  assert.match(
    resolver,
    /outbox\.request_digest[\s\S]*outbox\.authorization_binding_sha256[\s\S]*outbox\.payload[\s\S]*outbox\.payload_digest[\s\S]*resource\.lease_expires_at[\s\S]*proposal\.payload[\s\S]*proposal\.expires_at/u
  );
});

test("direct authority replay currentness requires the exact outbox payload", async () => {
  const [primarySource, authorityStoreSource] = await Promise.all([
    readFile(primaryUrl, "utf8"),
    readFile(authorityStoreUrl, "utf8")
  ]);
  const currentBody = primarySource.match(
    /CREATE OR REPLACE FUNCTION tp_private\.g1_authority_receipt_current_v1\([\s\S]*?AS \$\$([\s\S]*?)\$\$/u
  )?.[1];
  assert.ok(currentBody);
  assert.match(
    currentBody,
    /outbox\.request_digest = receipt\.request_digest[\s\S]*outbox\.authorization_binding_sha256 =[\s\S]*receipt\.authorization_binding_sha256[\s\S]*proposal\.payload = outbox\.payload/u
  );
  assert.match(
    currentBody,
    /JOIN tp_ledger\.g1_outbox_intents AS outbox[\s\S]*outbox\.operation_id = receipt\.operation_id/u
  );
  assert.match(
    currentBody,
    /sha256\(proposal\.payload_canonical::BYTES\)[\s\S]*outbox\.payload_digest/u
  );
  assert.match(
    authorityStoreSource,
    /async #receiptAuthorityCurrent[\s\S]*JOIN tp_ledger\.g1_outbox_intents AS outbox[\s\S]*const exactOutbox =[\s\S]*canonicalJson\(state\.outbox_payload\)[\s\S]*sha256\(canonicalJson\(state\.outbox_payload\)\)/u
  );
});

test("post-COMMIT ambiguity cannot enter a rollback branch", async () => {
  const [
    authorityStore,
    admissibleVector,
    signedIngest,
    recoveryStore,
    recoveryAudit,
    recoveryPublisher
  ] =
    await Promise.all([
      readFile(authorityStoreUrl, "utf8"),
      readFile(admissibleVectorUrl, "utf8"),
      readFile(signedIngestUrl, "utf8"),
      readFile(recoveryStoreUrl, "utf8"),
      readFile(recoveryBrokerUrl, "utf8"),
      readFile(recoveryUrl, "utf8")
    ]);
  for (const [name, source] of [
    ["signed ingest", signedIngest],
    ["recovery store", recoveryStore],
    ["recovery audit", recoveryAudit]
  ]) {
    assert.match(
      source,
      /const commitDefinitivelyAborted =[\s\S]*commitDispatched && error\?\.code === "40001"/u,
      name
    );
    assert.match(
      source,
      /databaseClientMustBeDiscarded\(error\) \|\|[\s\S]*\(commitDispatched && !commitDefinitivelyAborted\)/u,
      name
    );
  }
  assert.match(
    recoveryPublisher,
    /commitDispatched &&[\s\S]*!commitDefinitivelyAborted[\s\S]*await beforeReconcile\(\)[\s\S]*await reconcile\(bundle\)/u
  );
  assert.match(
    recoveryPublisher,
    /\(!commitDispatched \|\| commitDefinitivelyAborted\)[\s\S]*!unsafeConnection/u
  );
  assert.match(
    authorityStore,
    /!commitDispatched &&[\s\S]*isRetryableTransactionError\(error\)[\s\S]*databaseFailureRequiresReconciliation\(error, \{[\s\S]*commitDispatched/u
  );
  assert.match(
    admissibleVector,
    /commitDispatched = true;[\s\S]*await client\.query\("COMMIT"\)[\s\S]*if \(!commitDispatched\) \{[\s\S]*rollbackQuietly\(client\)[\s\S]*throw preparationCommitUnknown\(error\)/u
  );
});

test("protected-effect SQL denies the exact proposal-expiry boundary", async () => {
  const source = await readFile(primaryUrl, "utf8");
  const body = source.match(
    /CREATE OR REPLACE FUNCTION tp_api\.g1_record_protected_effect_v1\([\s\S]*?AS \$\$([\s\S]*?)\$\$/u
  )?.[1];
  assert.ok(body);
  assert.match(
    body,
    /JOIN tp_ledger\.g1_dvi_proposal_receipts AS proposal[\s\S]*proposal\.proposal_digest = outbox\.proposal_digest[\s\S]*proposal\.authorization_epoch = outbox\.authorization_epoch/u
  );
  assert.match(body, /proposal\.expires_at > transaction_timestamp\(\)/u);
  assert.match(body, /proposal\.payload = outbox\.payload/u);
  assert.match(
    body,
    /sha256\(proposal\.payload_canonical::BYTES\)[\s\S]*outbox\.payload_digest/u
  );
  assert.doesNotMatch(body, /proposal\.expires_at >= transaction_timestamp\(\)/u);
});
