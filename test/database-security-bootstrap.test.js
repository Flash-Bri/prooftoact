import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { runInNewContext } from "node:vm";

import { __test as primarySecurityContract } from "../src/cloud/primary-security.js";
import { validateManagedObjectGrants } from "../src/cloud/database-security-posture.js";
import { dviSelectionBindingSha256For } from "../src/cloud/dvi-selection.js";
import { MANAGED_MCP_RECOVERY_FRESH_BOOTSTRAP_SQL } from
  "../src/cloud/recovery-security.js";
import { authorizeSyntheticProposal } from
  "../scripts/lib/synthetic-authority-proposal.js";

const primaryUrl = new URL("../src/cloud/primary-security.js", import.meta.url);
const authorityStoreUrl = new URL(
  "../src/cloud/authority-store.js",
  import.meta.url
);
const recoveryUrl = new URL("../src/cloud/recovery-security.js", import.meta.url);
const recoveryStoreUrl = new URL("../src/cloud/recovery-store.js", import.meta.url);
const recoveryContinuityIdentityUrl = new URL(
  "../src/cloud/recovery-continuity-identity.js",
  import.meta.url
);
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
const gate1CapabilityRaceUrl = new URL(
  "../scripts/gate1-capability-race.js",
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

const LOGIN_POSTURE_RUNTIME_USERS = [
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

function completeShowUsersPosture() {
  const databaseNow = "2026-08-19T08:00:14.000Z";
  return [
    { username: "admin", options: [], member_of: [], database_now: databaseNow },
    {
      username: "prooftoact_bootstrap_admin",
      options: [],
      member_of: ["admin"],
      database_now: databaseNow
    },
    {
      username: "root",
      options: ["NOLOGIN"],
      member_of: ["admin"],
      database_now: databaseNow
    },
    {
      username: "tp_owner",
      options: ["NOLOGIN"],
      member_of: [],
      database_now: databaseNow
    },
    ...LOGIN_POSTURE_RUNTIME_USERS.flatMap((username) => {
      const role = username.replace(/_user$/u, "_role");
      return [{
        username: role,
        options: ["NOLOGIN"],
        member_of: [],
        database_now: databaseNow
      }, {
        username,
        options: [],
        member_of: [role],
        database_now: databaseNow
      }];
    })
  ];
}

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

test("complete SHOW USERS posture proves root and capability NOLOGIN", async () => {
  const rows = completeShowUsersPosture();
  const client = {
    async query(sql) {
      assert.match(sql, /FROM \[SHOW USERS\]/u);
      return { rows, rowCount: rows.length };
    }
  };
  const posture = await primarySecurityContract.collectPrincipalLoginPosture(
    client,
    "prooftoact_bootstrap_admin"
  );
  assert.equal(posture.schemaVersion,
    "prooftoact.primary-principal-login-posture.v2");
  assert.equal(posture.status,
    "EXACT_COMPLETE_SHOW_USERS_LOGIN_POSTURE");
  assert.equal(posture.exactPrincipalCount, 32);
  assert.equal(posture.rootCanLogin, false);
  assert.deepEqual(posture.rootOptions, ["NOLOGIN"]);
  assert.equal(posture.capabilityNoLoginCount, 15);
  assert.equal(posture.runtimeLoginCount, 14);
  assert.equal(posture.immutableBuiltinAdminRoleExceptionPresent, true);
  assert.match(posture.fullPrincipalCensusSha256, /^[0-9a-f]{64}$/u);
});

test("complete SHOW USERS posture rejects root option drift and extra names", async () => {
  for (const rows of [
    completeShowUsersPosture().map((row) => row.username === "root"
      ? { ...row, options: [] }
      : row),
    [...completeShowUsersPosture(), {
      username: "unexpected_user",
      options: [],
      member_of: [],
      database_now: "2026-08-19T08:00:14.000Z"
    }]
  ]) {
    await assert.rejects(
      primarySecurityContract.collectPrincipalLoginPosture({
        async query() { return { rows, rowCount: rows.length }; }
      }, "prooftoact_bootstrap_admin"),
      /PRIMARY_LOGIN_POSTURE_MISMATCH/u
    );
  }
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

test("recovery bootstrap grants exact publisher and optional Managed MCP schema visibility without private relation capability", async () => {
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
    /GRANT USAGE ON SCHEMA mcp_api, mcp_private TO \$\{RECOVERY_PUBLISHER_ROLE\}/u
  );
  assert.match(
    source,
    /schemas: Object\.freeze\(\[\.\.\.publisherSchemas\]\)/u
  );
  assert.match(
    source,
    /REVOKE ALL ON ALL TABLES IN SCHEMA mcp_private, mcp_public FROM \$\{RECOVERY_PUBLISHER_ROLE\}/u
  );
  assert.match(
    source,
    /MANAGED_MCP_RECOVERY_FRESH_BOOTSTRAP_SQL = Object\.freeze\(\[[\s\S]*GRANT SELECT ON TABLE mcp_public\.recovery_bundle_v2[\s\S]*GRANT USAGE ON SCHEMA mcp_private[\s\S]*GRANT USAGE ON SCHEMA mcp_public/u
  );
  assert.match(
    bootstrap,
    /if \(managedMcpPrincipalPresent\) \{[\s\S]*for \(const statement of MANAGED_MCP_RECOVERY_FRESH_BOOTSTRAP_SQL\)/u
  );
  assert.doesNotMatch(
    MANAGED_MCP_RECOVERY_FRESH_BOOTSTRAP_SQL.join("\n"),
    /mcp_private\.[^\s]+|FUNCTION|EXECUTE|GRANT OPTION/u
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
  const identitySource = await readFile(recoveryContinuityIdentityUrl, "utf8");
  const storeSource = await readFile(recoveryStoreUrl, "utf8");
  const declaration = identitySource.indexOf(
    "export const RECOVERY_DATABASE_FRESHNESS_SQL = `"
  );
  assert.notEqual(declaration, -1);
  const declarationEnd = identitySource.indexOf("`.trim();", declaration);
  assert.notEqual(declarationEnd, -1);
  const freshnessSql = identitySource.slice(declaration, declarationEnd);
  for (const predicate of [
    "source_commit_ts >= statement_timestamp() - INTERVAL '1 hour'",
    "source_commit_ts <= statement_timestamp() + INTERVAL '1 minute'",
    "expires_at > statement_timestamp()",
    "expires_at <= statement_timestamp() + INTERVAL '24 hours'"
  ]) {
    assert.equal(freshnessSql.includes(predicate), true, predicate);
  }
  assert.equal(
    identitySource.match(/\$\{RECOVERY_DATABASE_FRESHNESS_SQL\}/gu)?.length,
    1
  );
  assert.equal(
    storeSource.match(/\$\{RECOVERY_DATABASE_FRESHNESS_SQL\}/gu)?.length,
    1
  );
  assert.match(
    storeSource,
    /import \{\s*RECOVERY_DATABASE_FRESHNESS_SQL,/u
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
    ["g1_authority_receipt_current_v2", sharedAuthorizerGuard],
    ["g1_spend_authority_v1", sharedAuthorizerGuard],
    ["g2_spend_authority_race_v1", /session_user <> 'tp_gate2_authorizer_user'/u],
    ["g1_resolve_request_v1", sharedAuthorizerGuard],
    ["g1_observe_authority_race_v1", sharedAuthorizerGuard],
    ["g1_claim_provider_dispatch_inner_v2", /session_user <> 'tp_provider_claim_user'/u],
    ["g1_begin_provider_dispatch_inner_v2", /session_user <> 'tp_provider_begin_user'/u],
    ["g1_redeem_provider_dispatch_inner_v2", /session_user <> 'tp_provider_redeem_user'/u],
    ["g1_activate_provider_dispatch_inner_v2", /session_user <> 'tp_provider_activate_user'/u],
    ["g1_complete_provider_dispatch_inner_v2", /session_user <> 'tp_provider_finalize_user'/u],
    ["g1_mark_provider_dispatch_unknown_inner_v2", /session_user <> 'tp_provider_finalize_user'/u],
    ["g1_terminalize_provider_dispatch_inner_v2", /session_user <> 'tp_provider_terminalize_user'/u],
    ["g1_resolve_provider_dispatch_inner_v2", /session_user <> 'tp_provider_reconcile_user'/u],
    ["g1_append_recovery_audit_v1", /session_user = 'tp_recovery_audit_user'/u],
    ["g1_append_recovery_audit_v2", /session_user = 'tp_recovery_audit_user'/u],
    ["g1_append_recovery_audit_event_v3", /session_user <> 'tp_recovery_audit_user'/u],
    ["g1_resolve_recovery_audit_event_v1", /session_user = 'tp_recovery_audit_user'/u],
    ["g1_resolve_recovery_source_snapshot_v1", /session_user = 'tp_recovery_source_user'/u],
    ["g1_resolve_recovery_source_receipt_v2", /session_user = 'tp_recovery_source_user'/u],
    ["g1_resolve_recovery_source_receipt_v3", /session_user = 'tp_recovery_source_user'/u],
    ["g1_resolve_recovery_publisher_trust_root_v1", /session_user = 'tp_recovery_audit_user'/u],
    ["g1_record_protected_effect_v1", /session_user <> 'tp_dispatch_user'/u]
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
  // The standalone recovery publisher remains the only source-receipt
  // constructor. The former direct provider broker entry now intentionally
  // fails closed behind the root-managed systemd boundary.
  for (const url of [recoveryScriptUrls[0]]) {
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

test("Gate One selection mismatch replay uses one immutable time window", async () => {
  const source = await readFile(gate1SecurityUrl, "utf8");
  assert.match(
    source,
    /const mismatchSelectionWindow = \{[\s\S]*retrievalId: randomUUID\(\),[\s\S]*admittedAt:[\s\S]*expiresAt:/u
  );
  assert.equal(
    source.match(/\.\.\.mismatchSelectionWindow/gu)?.length,
    3
  );
  assert.doesNotMatch(source, /retrievalId: mismatchRetrievalId/u);
});

test("DVI proposal payload identity uses one exact compact dispatch schema", async () => {
  const source = await readFile(primaryUrl, "utf8");
  const authorize = source.match(
    /CREATE OR REPLACE FUNCTION tp_api\.g1_authorize_dvi_proposal_v1\([\s\S]*?AS \$\$([\s\S]*?)\$\$/u
  )?.[1];
  assert.ok(authorize);
  assert.match(
    authorize,
    /FROM jsonb_object_keys\(p_payload\)[\s\S]*field\.key NOT IN \([\s\S]*'action'[\s\S]*'destination'[\s\S]*'logicalDispatch'[\s\S]*'scenario'[\s\S]*\)/u
  );
  assert.match(
    authorize,
    /jsonb_typeof\(p_payload->'scenario'\) IS DISTINCT FROM 'string'[\s\S]*octet_length\(p_payload->>'scenario'\) NOT BETWEEN 1 AND 128[\s\S]*p_payload->>'scenario' !~ '\^\[A-Za-z0-9\._:-\]\+\$'/u
  );
  assert.match(
    authorize,
    /v_payload_canonical :=[\s\S]*'\{"action":'[\s\S]*',"destination":'[\s\S]*',"logicalDispatch":'[\s\S]*',"scenario":'[\s\S]*v_payload_digest := sha256\(v_payload_canonical::BYTES\)/u
  );
  assert.doesNotMatch(authorize, /v_payload_canonical := p_payload::STRING/u);
});

test("bootstrap fails closed on legacy DVI payload identities before installing functions", async () => {
  const compatible = await primarySecurityContract
    .assertDviProposalPayloadCompatibility({
      responses: [
        { rowCount: 1, rows: [{ incompatible_count: "0" }] },
        { rowCount: 1, rows: [{ incompatible_count: "0" }] }
      ],
      async query() {
        return this.responses.shift();
      }
    });
  assert.deepEqual(compatible, {
    compatible: true,
    inspectedIncompatibleRows: 0
  });

  for (const responses of [
    [{ rowCount: 1, rows: [{ incompatible_count: "1" }] }],
    [
      { rowCount: 1, rows: [{ incompatible_count: "0" }] },
      { rowCount: 1, rows: [{ incompatible_count: "1" }] }
    ]
  ]) {
    await assert.rejects(
      primarySecurityContract.assertDviProposalPayloadCompatibility({
        responses: [...responses],
        async query() {
          return this.responses.shift();
        }
      }),
      /DVI_PROPOSAL_PAYLOAD_CANONICALIZATION_INCOMPATIBLE/u
    );
  }

  const source = await readFile(primaryUrl, "utf8");
  const scrub = source.indexOf("await scrubManagedPrivileges(client);");
  const compatibility = source.indexOf(
    "await assertDviProposalPayloadCompatibility(client);"
  );
  const install = source.indexOf("await createFunctions(client);");
  assert.ok(scrub !== -1 && scrub < compatibility && compatibility < install);
});

test("synthetic denial and authorization replay one durable DVI selection", async () => {
  const request = {
    tenantId: "00000000-0000-4000-8000-000000000011",
    runId: "00000000-0000-4000-8000-000000000012",
    incidentId: "00000000-0000-4000-8000-000000000013",
    resourceId: "synthetic-resource",
    evidenceId: "00000000-0000-4000-8000-000000000014",
    agency: "rescue",
    payload: {
      action: "dispatch_rescue_unit",
      scenario: "synthetic-highwater"
    }
  };
  const selectionWindow = {
    retrievalId: "00000000-0000-4000-8000-000000000015",
    admittedAt: "2026-08-13T20:00:00.000Z",
    expiresAt: "2026-08-13T20:05:00.000Z"
  };
  const durableSelections = new Map();
  const observedBindings = [];
  const durableStore = {
    async recordDviSelectionReceiptForTest(selection) {
      const key = `${selection.tenantId}:${selection.retrievalId}`;
      const binding = dviSelectionBindingSha256For(selection);
      observedBindings.push(binding);
      const existing = durableSelections.get(key);
      if (existing !== undefined && existing !== binding) {
        throw new Error(
          "synthetic DVI selection receipt conflicted with durable state"
        );
      }
      durableSelections.set(key, binding);
    }
  };
  const proposalAuthorizer = async ({ requestedSelectedEvidenceId }) =>
    requestedSelectedEvidenceId === request.evidenceId
      ? {
          outcome: "proposal_authorized",
          authorizationCurrent: true
        }
      : {
          outcome: "proposal_authorization_denied",
          reason: "dvi_selection_request_mismatch",
          authorizationCurrent: false
        };
  const sharedOptions = {
    ...selectionWindow,
    evidenceDigest: "a".repeat(64),
    proposalAuthorizer
  };

  const denied = await authorizeSyntheticProposal(
    durableStore,
    request,
    {
      ...sharedOptions,
      allowDenied: true,
      requestedSelectedEvidenceId:
        "00000000-0000-4000-8000-000000000016"
    }
  );
  assert.equal(denied.authorization.reason, "dvi_selection_request_mismatch");

  const authorized = await authorizeSyntheticProposal(
    durableStore,
    request,
    sharedOptions
  );
  assert.equal(authorized.authorization.outcome, "proposal_authorized");
  assert.equal(observedBindings[0], observedBindings[1]);
  assert.equal(durableSelections.size, 1);

  await assert.rejects(
    authorizeSyntheticProposal(durableStore, request, {
      ...sharedOptions,
      admittedAt: "2026-08-13T20:00:00.001Z"
    }),
    /synthetic DVI selection receipt conflicted with durable state/u
  );
});

test("Gate One SQL identity probes isolate one intended fault", async () => {
  const source = await readFile(gate1SecurityUrl, "utf8");
  assert.doesNotMatch(
    source,
    /(payloadSubstitution|proposalAlias|forgedRequestDigest|nullIntentNonce)\[13\] = randomUUID\(\)/u
  );
  assert.match(
    source,
    /function assertSqlProbeRequestBindings\(values\)[\s\S]*effectKey: values\[13\][\s\S]*requestPayload\[field\] !== expected[\s\S]*requestPayload\.actionKind !== payload\.action/u
  );
  assert.equal(
    source.match(/assertSqlProbeRequestBindings\(/gu)?.length,
    5,
    "the pre-query binding assertion must cover all four probes"
  );
  assert.match(
    source,
    /payloadSubstitutionReason:[\s\S]*proposal_authorization_missing_or_stale/u
  );
  assert.match(
    source,
    /forgedRequestDigest,[\s\S]*"22023",[\s\S]*"database-derived authority identity mismatch"/u
  );
  assert.match(
    source,
    /nullIntentNonce,[\s\S]*"22023",[\s\S]*"authority request identity binding mismatch"/u
  );
});

test("private recovery source snapshot binds identity while separating policy domains", async () => {
  const source = await readFile(primaryUrl, "utf8");
  const snapshot = source.match(
    /CREATE OR REPLACE FUNCTION tp_private\.g1_resolve_recovery_source_snapshot_v1\([\s\S]*?AS \$\$([\s\S]*?)\$\$/u
  )?.[1];
  assert.ok(snapshot);
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
      snapshot,
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
    "agency"
  ]) {
    assert.match(
      snapshot,
      new RegExp(`proposal\\.${field}\\s*=\\s*receipt\\.${field}`, "u"),
      `proposal.${field}`
    );
  }
  assert.match(
    snapshot,
    /proposal\.selected_evidence_id\s*=\s*receipt\.evidence_id/u
  );
  assert.match(
    snapshot,
    /proposal\.selected_evidence_digest\s*=\s*receipt\.evidence_digest/u
  );
  const statements = await primarySecurityContract.primaryFunctionSqlStatements();
  const emittedSnapshot = statements.find((statement) =>
    statement.includes("g1_resolve_recovery_source_snapshot_v1")
  );
  assert.ok(emittedSnapshot);
  assert.equal(
    emittedSnapshot.match(
      /proposal\.policy_version = 'g1-admissibility-v2'/gu
    )?.length,
    2
  );
  assert.equal(
    emittedSnapshot.match(/receipt\.policy_version = 'gate1-policy-v2'/gu)
      ?.length,
    2
  );
  assert.doesNotMatch(
    emittedSnapshot,
    /proposal\.policy_version\s*=\s*receipt\.policy_version/u
  );
  assert.match(snapshot, /proposal\.authority_evidence_binding_sha256/u);
});

test("recovery source resolves through a private scalar snapshot and inert public boundary", async () => {
  const source = await readFile(primaryUrl, "utf8");
  const snapshot = source.match(
    /CREATE OR REPLACE FUNCTION tp_private\.g1_resolve_recovery_source_snapshot_v1\([\s\S]*?AS \$\$([\s\S]*?)\$\$/u
  )?.[1];
  const wrapperMatch = source.match(
    /CREATE OR REPLACE FUNCTION tp_api\.g1_resolve_recovery_source_receipt_v3\([\s\S]*?RETURNS TABLE\(([\s\S]*?)\)\s*LANGUAGE PLpgSQL[\s\S]*?AS \$\$([\s\S]*?)\$\$/u
  );
  const returnSignature = wrapperMatch?.[1];
  const wrapper = wrapperMatch?.[2];
  assert.ok(snapshot);
  assert.ok(returnSignature);
  assert.ok(wrapper);
  assert.match(
    snapshot,
    /IF NOT \(session_user = 'tp_recovery_source_user'\) THEN[\s\S]*42501/u
  );
  assert.match(
    wrapper,
    /IF NOT \(session_user = 'tp_recovery_source_user'\) THEN[\s\S]*42501/u
  );
  assert.match(
    snapshot,
    /JOIN tp_private\.g1_resources AS resource\s+ON resource\.tenant_id = receipt\.tenant_id\s+AND resource\.resource_id = receipt\.resource_id/u
  );
  for (const [resourceField, receiptField] of [
    ["active_run_id", "run_id"],
    ["holder_incident_id", "incident_id"],
    ["holder_operation_id", "operation_id"],
    ["holder_agent_id", "agent_id"],
    ["holder_proposal_digest", "proposal_digest"],
    ["holder_logical_authority_key_sha256", "logical_authority_key_sha256"],
    ["current_fence", "fencing_token"]
  ]) {
    assert.match(
      snapshot,
      new RegExp(
        `resource\\.${resourceField}\\s*=\\s*receipt\\.${receiptField}`,
        "u"
      ),
      `${resourceField}=${receiptField}`
    );
  }
  assert.match(
    snapshot,
    /SELECT count\(\*\)::INT8[\s\S]*INTO v_candidate_count[\s\S]*SELECT 1[\s\S]*LIMIT 2[\s\S]*AS bounded_candidates;[\s\S]*COALESCE\(v_candidate_count, 0\) <> 1 THEN[\s\S]*RETURN NULL;/u
  );
  assert.match(
    snapshot,
    /receipt\.lease_expires_at AS receipt_lease_expires_at[\s\S]*resource\.lease_expires_at AS resource_lease_expires_at[\s\S]*proposal\.expires_at AS proposal_expires_at/u
  );
  assert.match(
    snapshot,
    /evidence\.observed_at AS evidence_observed_at[\s\S]*evidence\.valid_from AS evidence_valid_from[\s\S]*evidence\.valid_until AS evidence_valid_until[\s\S]*evidence\.conflict_status AS evidence_conflict_status[\s\S]*evidence\.claim_key AS evidence_claim_key[\s\S]*evidence\.claim_value AS evidence_claim_value/u
  );
  assert.match(
    snapshot,
    /OPEN v_candidate_conflict_cursor NO SCROLL FOR[\s\S]*other\.tenant_id = v_candidate_tenant_id[\s\S]*other\.incident_id = v_candidate_incident_id[\s\S]*other\.evidence_id <> v_candidate_evidence_id[\s\S]*other\.claim_key = v_candidate_evidence_claim_key[\s\S]*other\.claim_value <> v_candidate_evidence_claim_value[\s\S]*other_key\.status = 'active'[\s\S]*other\.agency_scope IN \(v_candidate_agency, '\*'\)[\s\S]*ORDER BY other\.evidence_id;[\s\S]*FETCH v_candidate_conflict_cursor INTO[\s\S]*v_candidate_conflict_count > 10000[\s\S]*CLOSE v_candidate_conflict_cursor;[\s\S]*IF NOT v_candidate_conflict_snapshot_valid THEN[\s\S]*RETURN NULL;/u
  );
  const freshClock = snapshot.indexOf("v_database_now := clock_timestamp();");
  const snapshotReturn = snapshot.indexOf("RETURN jsonb_build_object(", freshClock);
  assert.ok(freshClock > 0 && snapshotReturn > freshClock);
  const postClockDecision = snapshot.slice(freshClock, snapshotReturn);
  assert.match(
    postClockDecision,
    /v_candidate_evidence_observed_at >[\s\S]*v_database_now \+ INTERVAL '5 minutes'[\s\S]*v_candidate_evidence_valid_from > v_database_now[\s\S]*v_candidate_evidence_valid_until <= v_database_now[\s\S]*v_candidate_evidence_conflict_status = 'unresolved'[\s\S]*v_candidate_conflict_index := 0;[\s\S]*WHILE v_candidate_conflict_index <[\s\S]*jsonb_array_length\(v_candidate_conflict_windows\) LOOP[\s\S]*RETURN NULL;[\s\S]*END LOOP;/u
  );
  assert.equal(
    snapshot.match(/v_database_now := clock_timestamp\(\);/gu)?.length,
    1
  );
  assert.doesNotMatch(postClockDecision, /\btp_(?:api|private|ledger)\./u);
  const postClockWithoutIntervalExtract = postClockDecision.replace(
    /extract\(epoch FROM \(/u,
    "extract(epoch ("
  );
  assert.doesNotMatch(postClockWithoutIntervalExtract, /\b(?:SELECT|FROM)\b/u);
  assert.doesNotMatch(snapshot, /statement_timestamp\(\)|transaction_timestamp\(\)/u);
  assert.doesNotMatch(snapshot, /\bRETURN NEXT\b|\bRETURN QUERY\b/u);

  const snapshotKeys = Object.freeze([
    "snapshot_schema",
    "tenant_id",
    "run_id",
    "incident_id",
    "evidence_id",
    "operation_id",
    "recorded_at",
    "request_digest",
    "proposal_digest",
    "logical_action_digest",
    "authorization_epoch",
    "logical_authority_key_sha256",
    "authorization_binding_sha256",
    "policy_version",
    "agent_id",
    "agency",
    "outcome",
    "reason",
    "evidence_digest",
    "authority_evidence_binding_sha256",
    "resource_id",
    "has_durable_intent",
    "admissibility",
    "minimum_residual_ms",
    "database_now"
  ]);
  const normalizedSnapshot = snapshot.replace(/\s+/gu, " ");
  assert.match(
    normalizedSnapshot,
    /RETURN jsonb_build_object\( 'snapshot_schema', 'g1-recovery-source-snapshot-v1'/u
  );
  const snapshotPayload = normalizedSnapshot.slice(
    normalizedSnapshot.indexOf("RETURN jsonb_build_object(")
  );
  for (const key of snapshotKeys) {
    assert.equal(
      snapshotPayload.split(`'${key}'`).length - 1,
      1,
      key
    );
  }

  assert.match(
    wrapper,
    /v_snapshot := tp_private\.g1_resolve_recovery_source_snapshot_v1\([\s\S]*p_request_digest[\s\S]*\);/u
  );
  assert.match(
    wrapper,
    /v_snapshot IS DISTINCT FROM jsonb_build_object\([\s\S]*'snapshot_schema', v_snapshot->'snapshot_schema'[\s\S]*'database_now', v_snapshot->'database_now'[\s\S]*\)/u
  );
  assert.match(
    wrapper,
    /jsonb_typeof\(v_snapshot->'reason'\) IS DISTINCT FROM 'string'[\s\S]*jsonb_typeof\(v_snapshot->'reason'\) IS DISTINCT FROM 'null'/u
  );
  assert.doesNotMatch(
    wrapper,
    /\b(?:SELECT|OPEN|FETCH|CLOSE|RETURN QUERY|jsonb_object_keys|jsonb_array_elements|EXECUTE)\b/u
  );
  assert.doesNotMatch(
    wrapper,
    /\bFROM\s+(?:tp_|\()/u
  );
  for (const [key, value] of [
    ["tenant_id", "p_tenant_id::STRING"],
    ["run_id", "p_run_id::STRING"],
    ["incident_id", "p_incident_id::STRING"],
    ["evidence_id", "p_evidence_id::STRING"],
    ["operation_id", "p_operation_id::STRING"],
    ["resource_id", "p_resource_id"],
    ["request_digest", "p_request_digest"]
  ]) {
    assert.match(
      wrapper,
      new RegExp(
        `v_snapshot->>'${key}'\\s+IS DISTINCT FROM\\s+${value.replace(/[()]/gu, "\\$&")}`,
        "u"
      ),
      key
    );
  }
  assert.match(
    wrapper,
    /policy_version' IS DISTINCT FROM 'gate1-policy-v2'[\s\S]*outcome' IS DISTINCT FROM 'resource_reserved'[\s\S]*has_durable_intent' IS DISTINCT FROM 'true'[\s\S]*admissibility' IS DISTINCT FROM 'admissible'/u
  );

  const outputAssignments = Object.freeze([
    ["tenant_id", "(v_snapshot->>'tenant_id')::UUID"],
    ["run_id", "(v_snapshot->>'run_id')::UUID"],
    ["incident_id", "(v_snapshot->>'incident_id')::UUID"],
    ["evidence_id", "(v_snapshot->>'evidence_id')::UUID"],
    ["operation_id", "(v_snapshot->>'operation_id')::UUID"],
    ["recorded_at", "(v_snapshot->>'recorded_at')::TIMESTAMPTZ"],
    ["request_digest", "v_snapshot->>'request_digest'"],
    ["proposal_digest", "v_snapshot->>'proposal_digest'"],
    ["logical_action_digest", "v_snapshot->>'logical_action_digest'"],
    ["authorization_epoch", "(v_snapshot->>'authorization_epoch')::INT8"],
    ["logical_authority_key_sha256", "v_snapshot->>'logical_authority_key_sha256'"],
    ["authorization_binding_sha256", "v_snapshot->>'authorization_binding_sha256'"],
    ["policy_version", "v_snapshot->>'policy_version'"],
    ["agent_id", "v_snapshot->>'agent_id'"],
    ["agency", "v_snapshot->>'agency'"],
    ["outcome", "v_snapshot->>'outcome'"],
    ["reason", "v_snapshot->>'reason'"],
    ["evidence_digest", "v_snapshot->>'evidence_digest'"],
    [
      "authority_evidence_binding_sha256",
      "v_snapshot->>'authority_evidence_binding_sha256'"
    ],
    ["resource_id", "v_snapshot->>'resource_id'"],
    ["has_durable_intent", "(v_snapshot->>'has_durable_intent')::BOOL"],
    ["admissibility", "v_snapshot->>'admissibility'"],
    ["minimum_residual_ms", "(v_snapshot->>'minimum_residual_ms')::INT8"],
    ["database_now", "(v_snapshot->>'database_now')::TIMESTAMPTZ"]
  ]);
  const returnColumns = [...returnSignature.matchAll(
    /^\s*([a-z][a-z0-9_]*)\s+(?:UUID|STRING|INT8|TIMESTAMPTZ|BOOL),?\s*$/gmu
  )].map((match) => match[1]);
  assert.equal(outputAssignments.length, 24);
  assert.deepEqual(returnColumns, outputAssignments.map(([output]) => output));
  const normalizedWrapper = wrapper.replace(/\s+/gu, " ").trim();
  let previousAssignment = -1;
  for (const [output, sourceName] of outputAssignments) {
    const assignment = `${output} := ${sourceName};`;
    const assignmentIndex = normalizedWrapper.indexOf(assignment);
    assert.ok(assignmentIndex > previousAssignment, assignment);
    assert.equal(
      normalizedWrapper.split(assignment).length - 1,
      1,
      assignment
    );
    previousAssignment = assignmentIndex;
  }
  assert.match(
    normalizedWrapper,
    /minimum_residual_ms := \(v_snapshot->>'minimum_residual_ms'\)::INT8; database_now := \(v_snapshot->>'database_now'\)::TIMESTAMPTZ; RETURN NEXT; RETURN; END$/u
  );
  assert.equal(wrapper.match(/\bRETURN NEXT;/gu)?.length, 1);
  assert.doesNotMatch(wrapper, /\bRETURN QUERY\b/u);

  const statements = await primarySecurityContract.primaryFunctionSqlStatements();
  const emittedSnapshot = statements.filter((statement) =>
    statement.includes(
      "CREATE OR REPLACE FUNCTION tp_private.g1_resolve_recovery_source_snapshot_v1"
    )
  );
  const emittedWrapper = statements.filter((statement) =>
    statement.includes(
      "CREATE OR REPLACE FUNCTION tp_api.g1_resolve_recovery_source_receipt_v3"
    )
  );
  assert.equal(emittedSnapshot.length, 1);
  assert.equal(emittedWrapper.length, 1);
  assert.doesNotMatch(
    emittedWrapper[0],
    /\b(?:SELECT|OPEN|FETCH|CLOSE)\b/u
  );
  assert.doesNotMatch(emittedWrapper[0], /\bFROM\s+(?:tp_|\()/u);
  assert.match(
    source,
    /"tp_private\.g1_resolve_recovery_source_snapshot_v1\(UUID, UUID, UUID, UUID, STRING, UUID, STRING\)"/u
  );
  assert.match(
    source,
    /tp_recovery_source_role: ALL_RUNTIME_SCHEMAS,/u
  );

  const admissibility = source.match(
    /CREATE OR REPLACE FUNCTION tp_private\.g1_list_admissibility_internal_v1\([\s\S]*?AS \$\$([\s\S]*?)\$\$/u
  )?.[1];
  assert.ok(admissibility);
  assert.match(admissibility, /statement_timestamp\(\)/u);
  assert.doesNotMatch(admissibility, /transaction_timestamp\(\)/u);
});

test("shared admissibility consumers use fresh database clocks", async () => {
  const source = await readFile(primaryUrl, "utf8");
  const observe = source.match(
    /CREATE OR REPLACE FUNCTION tp_api\.g1_observe_admissibility_v1\([\s\S]*?AS \$\$([\s\S]*?)\$\$/u
  )?.[1];
  const prepare = source.match(
    /CREATE OR REPLACE FUNCTION tp_api\.g1_prepare_vector_set_v1\([\s\S]*?AS \$\$([\s\S]*?)\$\$/u
  )?.[1];
  const authorize = source.match(
    /CREATE OR REPLACE FUNCTION tp_api\.g1_authorize_dvi_proposal_v1\([\s\S]*?AS \$\$([\s\S]*?)\$\$/u
  )?.[1];
  assert.ok(observe);
  assert.ok(prepare);
  assert.ok(authorize);
  assert.doesNotMatch(observe, /transaction_timestamp\(\)/u);
  assert.match(
    prepare,
    /v_admitted_at\s*:=\s*statement_timestamp\(\)/u
  );
  assert.doesNotMatch(prepare, /v_admitted_at\s*:=\s*transaction_timestamp\(\)/u);
  assert.match(
    authorize,
    /v_database_now TIMESTAMPTZ\s*:=\s*clock_timestamp\(\)[\s\S]*FOR UPDATE;[\s\S]*v_database_now := clock_timestamp\(\)[\s\S]*dvi_selection_receipt_expired/u
  );
  assert.doesNotMatch(
    authorize,
    /v_database_now TIMESTAMPTZ\s*:=\s*transaction_timestamp\(\)/u
  );
});

test("recovery source resolver upgrades by version without destructive DDL", async () => {
  const source = await readFile(primaryUrl, "utf8");
  assert.match(
    source,
    /CREATE OR REPLACE FUNCTION tp_api\.g1_resolve_recovery_source_receipt_v2\(/u
  );

  const recoveryBroker = await readFile(recoveryBrokerUrl, "utf8");
  const gate1Security = await readFile(gate1SecurityUrl, "utf8");
  assert.match(
    recoveryBroker,
    /tp_api\.g1_resolve_recovery_source_receipt_v3\(/u
  );
  assert.match(
    gate1Security,
    /expectPrivilegeDeniedOrUndefined[\s\S]*g1_resolve_recovery_source_receipt_v1\(/u
  );
  assert.match(
    gate1Security,
    /privateSnapshotDenied[\s\S]*expectPrivilegeDenied\([\s\S]*tp_private\.g1_resolve_recovery_source_snapshot_v1\(/u
  );
  assert.match(
    gate1Security,
    /const directPrivateRead = await expectPrivilegeDenied\([\s\S]*SELECT \* FROM tp_private\.g1_resources LIMIT 1/u
  );
  assert.match(
    gate1Security,
    /error\.code === "42501" \|\| error\.code === "42883"/u
  );
  assert.match(
    gate1Security,
    /tp_api\.g1_resolve_recovery_source_receipt_v2\(/u
  );
  assert.match(
    gate1Security,
    /const recoverySourceQuery =[\s\S]*await client\.query\("BEGIN"\)[\s\S]*resolved = await client\.query\([\s\S]*pg_catalog\.pg_cursors[\s\S]*resolvedAgain = await client\.query\([\s\S]*pg_catalog\.pg_cursors[\s\S]*cursorCountAfterFirst !== 0[\s\S]*cursorCountAfterSecond !== 0[\s\S]*await client\.query\("COMMIT"\)[\s\S]*RECOVERY_SOURCE_STABLE_COLUMNS[\s\S]*stableColumns\.some\([\s\S]*directPrivateRead,[\s\S]*resolverRepeatStable: true/u
  );

  assert.match(source, /PRIMARY_PREFLIGHT_POSTURE_SPEC/u);
  assert.equal(
    source.match(/postureSpec: PRIMARY_PREFLIGHT_POSTURE_SPEC/gu)?.length,
    2
  );
  assert.match(
    source,
    /LEGACY_RECOVERY_SOURCE_RESOLVER_SIGNATURE[\s\S]*CURRENT_RECOVERY_SOURCE_RESOLVER_SIGNATURE/u
  );
});

test("Gate One repeat stability compares equal database timestamps by value", async () => {
  const source = await readFile(gate1SecurityUrl, "utf8");
  const stableColumnsSource = source.match(
    /const RECOVERY_SOURCE_STABLE_COLUMNS = Object\.freeze\((\[[\s\S]*?\])\);/u
  )?.[1];
  assert.ok(stableColumnsSource);
  const stableColumns = JSON.parse(stableColumnsSource);
  assert.equal(stableColumns.length, 22);
  assert.equal(new Set(stableColumns).size, 22);
  assert.deepEqual(stableColumns, [...stableColumns].sort());
  const helperSource = source.match(
    /function sameStableDatabaseValue\(left, right\) \{[\s\S]*?^\}/mu
  )?.[0];
  assert.ok(helperSource);
  const sameStableDatabaseValue = runInNewContext(
    `(${helperSource})`,
    { Date, Number }
  );
  const first = new Date("2026-08-13T23:59:59.123Z");
  const equalButDistinct = new Date("2026-08-13T23:59:59.123Z");
  const drifted = new Date("2026-08-13T23:59:59.124Z");

  assert.notStrictEqual(first, equalButDistinct);
  assert.equal(sameStableDatabaseValue(first, equalButDistinct), true);
  assert.equal(sameStableDatabaseValue(first, drifted), false);
  assert.equal(sameStableDatabaseValue(first, first.toISOString()), false);
  assert.throws(
    () => sameStableDatabaseValue(new Date(NaN), new Date(NaN)),
    /stable database timestamp invalid/u
  );
  assert.equal(sameStableDatabaseValue("stable", "stable"), true);
  assert.equal(sameStableDatabaseValue(null, null), true);
  assert.throws(
    () => sameStableDatabaseValue({}, {}),
    /stable database value invalid/u
  );
  assert.match(
    source,
    /const RECOVERY_SOURCE_STABLE_COLUMNS = Object\.freeze\(\[[\s\S]*"recorded_at"[\s\S]*"tenant_id"[\s\S]*JSON\.stringify\(stableColumns\) !==[\s\S]*JSON\.stringify\(RECOVERY_SOURCE_STABLE_COLUMNS\)/u
  );
  assert.match(
    source,
    /stableColumns\.some\([\s\S]*!sameStableDatabaseValue\([\s\S]*resolved\.rows\[0\]\?\.\[column\][\s\S]*resolvedAgain\.rows\[0\]\?\.\[column\]/u
  );
});

test("Gate One proves resolver cursor closure inside one transaction", async () => {
  const source = await readFile(gate1SecurityUrl, "utf8");
  const recoveryLane = source.slice(
    source.indexOf("const recoverySource = await withClient("),
    source.indexOf("const recoveryAudit = await withClient(")
  );
  assert.ok(recoveryLane.length > 0);
  assert.equal(recoveryLane.match(/await client\.query\("BEGIN"\)/gu)?.length, 1);
  assert.equal(recoveryLane.match(/pg_catalog\.pg_cursors/gu)?.length, 2);
  assert.equal(recoveryLane.match(/await client\.query\("COMMIT"\)/gu)?.length, 1);
  assert.equal(recoveryLane.match(/await client\.query\("ROLLBACK"\)/gu)?.length, 1);
  assert.match(
    recoveryLane,
    /cursorCountAfterFirst !== 0[\s\S]*cursorCountAfterSecond !== 0[\s\S]*cursorCountAfterFirst,[\s\S]*cursorCountAfterSecond,[\s\S]*resolverRepeatStable: true/u
  );
});

test("primary function SQL is digest-pinned before any database query", async () => {
  const statements = await primarySecurityContract.primaryFunctionSqlStatements();
  const receipt = primarySecurityContract.validatePrimaryFunctionSqlStatements(
    statements
  );
  assert.deepEqual(receipt, {
    schema: "tideproof.primary-function-sql-batch.v1",
    statementCount: 57,
    sha256: "82de099bcdf1fcf35a51486e6018213885625d11ae0e33de3a6d13ffd5ce8d9c"
  });
  const legacyProviderDrop = statements.find((statement) =>
    statement.includes("DROP FUNCTION IF EXISTS tp_api.g1_transition_provider_dispatch_v1")
  );
  assert.match(
    legacyProviderDrop,
    /DROP FUNCTION IF EXISTS tp_api\.g1_transition_provider_dispatch_v1/u
  );
  const providerClaim = statements.find((statement) =>
    statement.includes("g1_claim_provider_dispatch_inner_v2")
  );
  const providerBegin = statements.find((statement) =>
    statement.includes("g1_begin_provider_dispatch_inner_v2")
  );
  const providerRedeem = statements.find((statement) =>
    statement.includes("g1_redeem_provider_dispatch_inner_v2")
  );
  const providerComplete = statements.find((statement) =>
    statement.includes("g1_complete_provider_dispatch_inner_v2")
  );
  const providerUnknown = statements.find((statement) =>
    statement.includes("g1_mark_provider_dispatch_unknown_inner_v2")
  );
  const providerResolve = statements.find((statement) =>
    statement.includes("g1_resolve_provider_dispatch_inner_v2")
  );
  assert.match(providerClaim, /session_user <> 'tp_provider_claim_user'/u);
  assert.match(providerBegin, /session_user <> 'tp_provider_begin_user'/u);
  assert.match(providerRedeem, /session_user <> 'tp_provider_redeem_user'/u);
  assert.match(
    providerRedeem,
    /state = 'CREDENTIAL_REDEEMED'[\s\S]*completion_capability_sha256/u
  );
  assert.match(
    providerComplete,
    /session_user <> 'tp_provider_finalize_user'/u
  );
  assert.match(
    providerUnknown,
    /session_user <> 'tp_provider_finalize_user'/u
  );
  assert.match(
    providerResolve,
    /session_user <> 'tp_provider_reconcile_user'/u
  );
  assert.doesNotMatch(
    providerResolve,
    /execution_capability_sha256|owner_nonce|p_execution_capability/u
  );
  assert.equal(
    statements.some((statement) =>
      statement.includes(
        "CREATE OR REPLACE FUNCTION tp_api.g1_transition_provider_dispatch_v1"
      )
    ),
    false
  );
  assert.equal(
    statements.filter((statement) =>
      statement.includes("g1_resolve_recovery_source_receipt_v2")
    ).length,
    1
  );
  assert.equal(
    statements.some((statement) =>
      statement.includes("g1_resolve_recovery_source_receipt_v1")
    ),
    false
  );

  const executed = [];
  const executedReceipt =
    await primarySecurityContract.executePrimaryFunctionSqlStatements(
      {
        async query(statement) {
          executed.push(statement);
        }
      },
      statements
    );
  assert.deepEqual(executedReceipt, receipt);
  assert.deepEqual(executed, statements);
});

test("emitted-SQL pin rejects JavaScript spelling evasions before execution", async () => {
  const statements = await primarySecurityContract.primaryFunctionSqlStatements();
  const resolverIndex = statements.findIndex((statement) =>
    statement.includes("g1_resolve_recovery_source_receipt_v2")
  );
  assert.notEqual(resolverIndex, -1);
  const computedName = `g1_resolve_recovery_source_receipt_${1}`;
  const destructiveDdl = new Map([
    [
      "direct literal",
      "DROP FUNCTION IF EXISTS tp_api.g1_resolve_recovery_source_receipt_v1(UUID);"
    ],
    [
      "concatenation",
      "DROP " +
        "FUNCTION IF EXISTS tp_api.g1_resolve_recovery_source_receipt_v2(UUID);"
    ],
    [
      "Unicode escaped whitespace",
      "DROP\u0020FUNCTION IF EXISTS tp_api.g1_resolve_recovery_source_receipt_v1(UUID);"
    ],
    [
      "computed template name",
      `DROP FUNCTION IF EXISTS tp_api.${computedName}(UUID);`
    ],
    [
      "split identifier",
      "DROP FUNCTION IF EXISTS tp_api.g1_resolve_recovery_" +
        "source_receipt_v2(UUID);"
    ]
  ]);

  for (const [label, ddl] of destructiveDdl) {
    const changed = [...statements];
    changed[resolverIndex] = `${changed[resolverIndex]}\n${ddl}`;
    const executed = [];
    await assert.rejects(
      primarySecurityContract.executePrimaryFunctionSqlStatements(
        {
          async query(statement) {
            executed.push(statement);
          }
        },
        changed
      ),
      /PRIMARY_FUNCTION_SQL_BATCH_UNREVIEWED/u,
      label
    );
    assert.deepEqual(executed, [], label);
  }
});

test("emitted-SQL pin ignores benign JavaScript source decoys", async () => {
  const statements = await primarySecurityContract.primaryFunctionSqlStatements();
  const maintainerComment = "A maintainer's comment is not emitted SQL.";
  const sourceOnlyPattern = /DROP\s+FUNCTION/u;
  const sourceOnlyDollarQuote =
    "$$DROP FUNCTION tp_api.g1_resolve_recovery_source_receipt_v1(UUID)$$";
  assert.equal(sourceOnlyPattern.test(sourceOnlyDollarQuote), true);
  assert.equal(maintainerComment.endsWith("SQL."), true);

  const rebuiltFromFragments = statements.map((statement) =>
    [...statement].join("")
  );
  assert.deepEqual(
    primarySecurityContract.validatePrimaryFunctionSqlStatements(
      rebuiltFromFragments
    ),
    primarySecurityContract.validatePrimaryFunctionSqlStatements(statements)
  );
});

test("resolver upgrade preflight admits only the exact installed v1 capability", () => {
  const legacySignature =
    "g1_resolve_recovery_source_receipt_v1(UUID, UUID, UUID, UUID, STRING, UUID, STRING)";
  const currentSignature =
    "g1_resolve_recovery_source_receipt_v2(UUID, UUID, UUID, UUID, STRING, UUID, STRING)";
  const residualSignature =
    "g1_resolve_recovery_source_receipt_v3(UUID, UUID, UUID, UUID, STRING, UUID, STRING)";
  const finalPolicy =
    primarySecurityContract.primaryPostureSpec.roleGrantPolicies
      .tp_recovery_source_role.functions;
  const preflightPolicy =
    primarySecurityContract.primaryPreflightPostureSpec.roleGrantPolicies
      .tp_recovery_source_role.functions;
  assert.deepEqual(finalPolicy, [currentSignature, residualSignature]);
  assert.deepEqual(preflightPolicy, [
    legacySignature, currentSignature, residualSignature
  ]);
  assert.deepEqual(
    primarySecurityContract.primaryPostureSpec.roleGrantPolicies
      .tp_recovery_source_role.schemas,
    ["tp_api", "tp_private", "tp_ledger"]
  );
  assert.deepEqual(
    primarySecurityContract.primaryPreflightPostureSpec.roleGrantPolicies
      .tp_recovery_source_role.schemas,
    ["tp_api", "tp_private", "tp_ledger"]
  );

  const installedV1Grant = [{
    database_name: "tideproof",
    schema_name: "tp_api",
    object_name:
      "g1_resolve_recovery_source_receipt_v1(uuid,uuid,uuid,uuid,string,uuid,string)",
    object_type: "function",
    grantee: "tp_recovery_source_role",
    privilege_type: "EXECUTE",
    is_grantable: false
  }];
  const validateWith = (spec, grants = installedV1Grant) => validateManagedObjectGrants(
    grants,
    {
      databaseName: spec.databaseName,
      managedSchemas: spec.managedSchemas,
      managedPrefixes: spec.managedPrefixes,
      apiSchema: spec.apiSchema,
      ownerRoles: spec.ownerRoles,
      roleGrantPolicies: spec.roleGrantPolicies,
      runtimeUsers: spec.users,
      knownManagedPrincipals: [...spec.roles, ...spec.users],
      trustedPrincipals: ["cluster_admin"],
      allowMissingExpected: true
    }
  );

  assert.doesNotThrow(() => validateWith(
    primarySecurityContract.primaryPreflightPostureSpec
  ));
  assert.throws(
    () => validateWith(primarySecurityContract.primaryPostureSpec),
    /DATABASE_POSTURE_MANAGED_GRANT_UNEXPECTED/u
  );
  const privateSnapshotGrant = [{
    database_name: "tideproof",
    schema_name: "tp_private",
    object_name:
      "g1_resolve_recovery_source_snapshot_v1(uuid,uuid,uuid,uuid,string,uuid,string)",
    object_type: "function",
    grantee: "tp_recovery_source_role",
    privilege_type: "EXECUTE",
    is_grantable: false
  }];
  for (const spec of [
    primarySecurityContract.primaryPreflightPostureSpec,
    primarySecurityContract.primaryPostureSpec
  ]) {
    assert.throws(
      () => validateWith(spec, privateSnapshotGrant),
      /DATABASE_POSTURE_MANAGED_GRANT_UNEXPECTED/u
    );
  }
});

test("Cockroach schema closure preserves typed public surfaces and direct denials", async () => {
  const source = await readFile(primaryUrl, "utf8");
  const gate1Security = await readFile(gate1SecurityUrl, "utf8");
  const policies = primarySecurityContract.primaryPostureSpec.roleGrantPolicies;

  for (const role of [
    "tp_provider_activate_role",
    "tp_provider_terminalize_role",
    "tp_audit_role"
  ]) {
    assert.deepEqual(policies[role].schemas, ["tp_api", "tp_ledger"]);
  }
  assert.deepEqual(policies.tp_audit_role.relations, ["g1_receipt_audit_v1"]);
  assert.deepEqual(
    policies.tp_provider_activate_role.functions,
    ["g1_activate_provider_dispatch_v2(UUID, UUID, STRING, STRING)"]
  );
  assert.deepEqual(
    policies.tp_provider_terminalize_role.functions,
    ["g1_terminalize_provider_dispatch_v2(UUID, UUID, STRING, STRING)"]
  );
  assert.match(
    source,
    /tp_audit_role: Object\.freeze\(\["tp_api", "tp_ledger"\]\)/u
  );
  assert.match(
    gate1Security,
    /const PROVIDER_RUNTIME_CLOSURE_PROBES = Object\.freeze\(/u
  );
  assert.match(
    gate1Security,
    /async function assertProviderRuntimeClosure\([\s\S]*directLedgerRead[\s\S]*directPrivateFunction[\s\S]*publicControlAbsent/u
  );
  assert.match(
    gate1Security,
    /expectSqlState\([\s\S]*"provider dispatch control absent"/u
  );
  assert.match(
    gate1Security,
    /providerActivate,[\s\S]*providerTerminalize,[\s\S]*audit,/u
  );
});

test("authorizer posture admits the exact DVI proposal capability it grants", () => {
  const signature =
    "g1_authorize_dvi_proposal_v1(UUID, UUID, UUID, UUID, UUID, STRING, STRING, STRING, STRING, JSONB)";
  const finalPolicy =
    primarySecurityContract.primaryPostureSpec.roleGrantPolicies
      .tp_authorizer_role.functions;
  assert.ok(finalPolicy.includes(signature));
  assert.doesNotThrow(() => validateManagedObjectGrants([{
    database_name: "tideproof",
    schema_name: "tp_api",
    object_name:
      "g1_authorize_dvi_proposal_v1(uuid,uuid,uuid,uuid,uuid,string,string,string,string,jsonb)",
    object_type: "function",
    grantee: "tp_authorizer_role",
    privilege_type: "EXECUTE",
    is_grantable: false
  }], {
    databaseName: primarySecurityContract.primaryPostureSpec.databaseName,
    managedSchemas: primarySecurityContract.primaryPostureSpec.managedSchemas,
    managedPrefixes: primarySecurityContract.primaryPostureSpec.managedPrefixes,
    apiSchema: primarySecurityContract.primaryPostureSpec.apiSchema,
    ownerRoles: primarySecurityContract.primaryPostureSpec.ownerRoles,
    roleGrantPolicies:
      primarySecurityContract.primaryPostureSpec.roleGrantPolicies,
    runtimeUsers: primarySecurityContract.primaryPostureSpec.users,
    knownManagedPrincipals: [
      ...primarySecurityContract.primaryPostureSpec.roles,
      ...primarySecurityContract.primaryPostureSpec.users
    ],
    trustedPrincipals: ["cluster_admin"],
    allowMissingExpected: true
  }));
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
  const [source, recoveryRunner, brokerRunner] = await Promise.all([
    readFile(fullDrillEvidenceUrl, "utf8"),
    readFile(recoveryScriptUrls[0], "utf8"),
    readFile(recoveryScriptUrls[1], "utf8")
  ]);
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
    "SOURCE_BUILD_IDENTITY",
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_SPEC",
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_ROOT",
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_RECOVERY_BUNDLE_PATH",
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_FORBIDDEN_ROOT"
  ]) {
    assert.equal(source.includes(input), true, input);
  }
  assert.match(source, /winner\.operationId/u);
  assert.match(source, /winner\.requestDigest/u);
  assert.match(source, /race receipt `dvi\.authorityEvidenceBindingSha256`/u);
  assert.match(source, /race receipt `dvi\.selectedEvidenceBindingSha256`/u);
  assert.match(source, /The nine `RECOVERY_SOURCE_\*` values/u);
  assert.match(source, /all 22[\s\S]*managed base-table read probes/u);
  assert.match(source, /administrator URL/u);
  assert.match(source, /exact shared private inputs/u);
  assert.match(source, /broker is invoked by the integrated-live[\s\S]*it alone also requires/u);
  for (const input of [
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_SPEC",
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_ROOT",
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_RECOVERY_BUNDLE_PATH",
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_FORBIDDEN_ROOT"
  ]) {
    assert.equal(brokerRunner.includes(input), true, `broker:${input}`);
    assert.equal(recoveryRunner.includes(input), false, `recovery:${input}`);
  }
});

test("recovery broker verifies audit events only through the narrow resolver", async () => {
  const [source, primarySource] = await Promise.all([
    readFile(recoveryBrokerUrl, "utf8"),
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
    /runCrossEpochRaceProof[\s\S]*afterEpochLockObserver[\s\S]*proposal_authorization_expired[\s\S]*explicit_new_authorization_required[\s\S]*current_fence === "0"/u
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
    /v_epoch_current_epoch = 1[\s\S]*'explicit_new_authorization_required'/u
  );
  assert.doesNotMatch(
    authorizeBody,
    /v_authorization_epoch := v_epoch_current_epoch \+ 1/u
  );
  assert.match(
    gate1AuthoritySource,
    /runExpiredUnspentReplacementProof[\s\S]*expireProposalAtDatabaseNowForTest[\s\S]*store\.spendAuthority[\s\S]*proposal_authorization_expired[\s\S]*explicit_new_authorization_required[\s\S]*proposal_receipt_count/u
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
    /CREATE OR REPLACE FUNCTION tp_private\.g1_authority_receipt_current_v2\([\s\S]*?AS \$\$([\s\S]*?)\$\$/u
  )?.[1];
  const compatibilityBody = primarySource.match(
    /CREATE OR REPLACE FUNCTION tp_private\.g1_authority_receipt_current_v1\([\s\S]*?AS \$\$([\s\S]*?)\$\$/u
  )?.[1];
  assert.ok(currentBody);
  assert.ok(compatibilityBody);
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
    compatibilityBody,
    /SELECT currentness\.authority_current[\s\S]*FROM tp_private\.g1_authority_receipt_current_v2\(/u
  );
  assert.match(
    authorityStoreSource,
    /async #receiptAuthorityCurrent[\s\S]*JOIN tp_ledger\.g1_outbox_intents AS outbox[\s\S]*const exactOutbox =[\s\S]*canonicalJson\(state\.outbox_payload\)[\s\S]*sha256\(canonicalJson\(state\.outbox_payload\)\)/u
  );
});

test("authority spend, replay, and protected effects refresh database time", async () => {
  const [
    primarySource,
    authorityStoreSource,
    gate1AuthoritySource,
    gate1CapabilityRaceSource
  ] = await Promise.all([
    readFile(primaryUrl, "utf8"),
    readFile(authorityStoreUrl, "utf8"),
    readFile(gate1AuthorityUrl, "utf8"),
    readFile(gate1CapabilityRaceUrl, "utf8")
  ]);
  const currentBody = primarySource.match(
    /CREATE OR REPLACE FUNCTION tp_private\.g1_authority_receipt_current_v2\([\s\S]*?AS \$\$([\s\S]*?)\$\$/u
  )?.[1];
  const spendBody = primarySource.match(
    /CREATE OR REPLACE FUNCTION tp_api\.g1_spend_authority_v1\([\s\S]*?AS \$\$([\s\S]*?)\$\$/u
  )?.[1];
  const resolveBody = primarySource.match(
    /CREATE OR REPLACE FUNCTION tp_api\.g1_resolve_request_v1\([\s\S]*?AS \$\$([\s\S]*?)\$\$/u
  )?.[1];
  const effectBody = primarySource.match(
    /CREATE OR REPLACE FUNCTION tp_api\.g1_record_protected_effect_v1\([\s\S]*?AS \$\$([\s\S]*?)\$\$/u
  )?.[1];
  assert.ok(currentBody);
  assert.ok(spendBody);
  assert.ok(resolveBody);
  assert.ok(effectBody);

  assert.match(
    currentBody,
    /SELECT[\s\S]*INTO[\s\S]*v_structural_current[\s\S]*FROM tp_ledger\.g1_authority_receipts[\s\S]*v_database_now := clock_timestamp\(\);[\s\S]*RETURN QUERY SELECT[\s\S]*v_receipt_lease_expires_at > v_database_now[\s\S]*v_resource_lease_expires_at > v_database_now[\s\S]*v_proposal_expires_at > v_database_now[\s\S]*v_database_now/u
  );
  assert.equal(currentBody.match(/clock_timestamp\(\)/gu)?.length, 1);
  assert.match(
    spendBody,
    /v_database_now TIMESTAMPTZ\s*:=\s*clock_timestamp\(\)[\s\S]*FOR UPDATE;[\s\S]*v_database_now := clock_timestamp\(\)[\s\S]*FOR UPDATE;[\s\S]*v_database_now := clock_timestamp\(\)/u
  );
  assert.match(spendBody, /v_proposal_expires_at <= v_database_now/u);
  assert.match(spendBody, /v_holder_expiry > v_database_now/u);
  assert.match(
    spendBody,
    /IF p_lease_ms = 1800000 THEN\s*NULL;\s*ELSE\s*IF p_lease_ms IS NULL OR p_lease_ms < 1000 OR p_lease_ms > 600000 THEN/u
  );
  assert.match(
    spendBody,
    /IF p_lease_ms > 600000 AND NOT \(\s*p_lease_ms = 1800000\s*AND v_proposal_expires_at - v_proposal_admitted_at =\s*INTERVAL '30 minutes'\s*\) THEN/u
  );
  assert.match(
    spendBody,
    /lease_expires_at\s*=\s*v_database_now\s*\+\s*\(p_lease_ms \* INTERVAL '1 millisecond'\)/u
  );
  assert.match(
    spendBody,
    /resource\.lease_expires_at <= v_database_now/u
  );
  assert.match(
    spendBody,
    /UPDATE tp_private\.g1_resources[\s\S]*AND EXISTS \([\s\S]*proposal\.proposal_digest = p_proposal_digest[\s\S]*proposal\.authorization_binding_sha256 =[\s\S]*v_authorization_binding_sha256[\s\S]*proposal\.expires_at > clock_timestamp\(\)/u
  );
  assert.match(
    resolveBody,
    /currentness\.authority_current,\s*currentness\.database_now[\s\S]*CROSS JOIN tp_private\.g1_authority_receipt_current_v2\([\s\S]*\) AS currentness/u
  );
  assert.doesNotMatch(resolveBody, /statement_timestamp\(\)/u);
  assert.match(
    effectBody,
    /ON CONFLICT DO NOTHING[\s\S]*RETURNING 1::INT8 INTO v_inserted_count;[\s\S]*v_effect_key := p_effect_key;[\s\S]*v_operation_id := p_operation_id;[\s\S]*v_database_now := clock_timestamp\(\);[\s\S]*v_receipt_lease_expires_at <= v_database_now[\s\S]*v_resource_lease_expires_at <= v_database_now[\s\S]*v_proposal_expires_at <= v_database_now[\s\S]*DELETE FROM tp_ledger\.g1_protected_effects/u
  );
  assert.equal(
    spendBody.match(
      /SELECT currentness\.authority_current, currentness\.database_now\s*INTO v_existing_authority_current, v_database_now\s*FROM tp_private\.g1_authority_receipt_current_v2\([\s\S]*?\) AS currentness;\s*RETURN QUERY SELECT[\s\S]*?v_existing_authority_current,\s*v_database_now/gu
    )?.length,
    4
  );
  assert.doesNotMatch(
    spendBody,
    /g1_authority_receipt_current_v1|v_existing_authority_current :=/u
  );
  for (const [name, body] of [
    ["current receipt", currentBody],
    ["request resolution", resolveBody],
    ["protected effect", effectBody]
  ]) {
    assert.doesNotMatch(body, /transaction_timestamp\(\)/u, name);
  }
  assert.doesNotMatch(spendBody, /transaction_timestamp\(\)/u);
  assert.doesNotMatch(currentBody, /statement_timestamp\(\)/u);

  const directProposal = authorityStoreSource.match(
    /async #boundProposal\([\s\S]*?(?=\n  async #receiptAuthorityCurrent)/u
  )?.[0];
  const directCurrent = authorityStoreSource.match(
    /async #receiptAuthorityCurrent\([\s\S]*?(?=\n  async #existingReceipt)/u
  )?.[0];
  const directSpend = authorityStoreSource.match(
    /async spendAuthority\([\s\S]*?(?=\n  async proveSerializableRetry)/u
  )?.[0];
  const directReconcile = authorityStoreSource.match(
    /async reconcileRequest\([\s\S]*?(?=\n  async recordProtectedEffect)/u
  )?.[0];
  const directEffect = authorityStoreSource.match(
    /async recordProtectedEffect\([\s\S]*?(?=\n  async snapshot)/u
  )?.[0];
  assert.ok(directProposal);
  assert.ok(directCurrent);
  assert.ok(directSpend);
  assert.ok(directReconcile);
  assert.ok(directEffect);
  assert.match(
    directSpend,
    /proposal\.expires_at > statement_timestamp\(\)/u
  );
  assert.match(
    directEffect,
    /resource\.lease_expires_at > statement_timestamp\(\)[\s\S]*proposal\.expires_at > statement_timestamp\(\)/u
  );
  for (const [name, body] of [
    ["direct proposal", directProposal],
    ["direct current receipt", directCurrent],
    ["direct authority spend", directSpend],
    ["direct reconciliation", directReconcile],
    ["direct protected effect", directEffect]
  ]) {
    assert.match(body, /statement_timestamp\(\)/u, name);
    assert.doesNotMatch(body, /transaction_timestamp\(\)/u, name);
  }
  assert.match(
    gate1AuthoritySource,
    /runHeldTransactionExpiryProof[\s\S]*setProposalExpiryAfterMsForTest[\s\S]*waitForProposalExpiryForTest[\s\S]*proposal_authorization_expired[\s\S]*current_fence === "0"/u
  );
  assert.match(
    gate1CapabilityRaceSource,
    /runStoredFunctionHeldExpiryProof[\s\S]*FOR UPDATE[\s\S]*setProposalExpiryAfterMsForTest[\s\S]*waitForProposalExpiryForTest[\s\S]*proposal_authorization_expired[\s\S]*current_fence === "0"/u
  );
  assert.match(
    gate1CapabilityRaceSource,
    /runStoredReplayHeldExpiryProof[\s\S]*UPDATE tp_ledger\.g1_outbox_intents[\s\S]*SET payload = '\{"temporary-replay-lock-probe":true\}'::JSONB[\s\S]*await queryReady\.wait\(\)[\s\S]*stored replay currentness did not wait on the outbox intent[\s\S]*waitForProposalExpiryForTest[\s\S]*decision_replay_kind === "operation_replay"[\s\S]*decision_authority_current === false[\s\S]*replayDecisionTime - proposalExpiry <= 1_000[\s\S]*stored replay currentness and reported database time used different clocks/u
  );
  assert.match(
    gate1CapabilityRaceSource,
    /runReplayClockPairBoundaryControl[\s\S]*await client\.connect\(\);[\s\S]*setProposalExpiryAfterMsForTest[\s\S]*BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE[\s\S]*replayAtA\.decision_authority_current === true[\s\S]*decisionAtA < proposalExpiry[\s\S]*proposalExpiry <= databaseNowAtB[\s\S]*amplified old two-clock replay control did not cross proposal expiry[\s\S]*await client\.query\("ROLLBACK"\);[\s\S]*await client\.query\("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE"\);[\s\S]*atBoundaryEnd = await client\.query\(SPEND_SQL[\s\S]*replayAtC\.decision_authority_current === false[\s\S]*replayAtC\.decision_authority_current ===\s*\(decisionAtC < proposalExpiry\)/u
  );
  assert.doesNotMatch(
    gate1CapabilityRaceSource,
    /SET intent_kind = 'temporary-replay-lock-probe'/u
  );
  assert.match(
    gate1CapabilityRaceSource,
    /runStoredProtectedEffectHeldExpiryProof[\s\S]*INSERT INTO tp_ledger\.g1_protected_effects[\s\S]*protected effect did not wait on unique occupancy[\s\S]*waitForProposalExpiryForTest[\s\S]*effect\.rowCount === 0/u
  );
  assert.match(
    gate1CapabilityRaceSource,
    /runRecoveryResolverHeldExpiryProof[\s\S]*temporary-recovery-lock-probe[\s\S]*recovery resolver did not wait behind the receipt intent[\s\S]*waitForProposalExpiryForTest[\s\S]*resolution\.rowCount === 0/u
  );
  assert.match(
    gate1CapabilityRaceSource,
    /runRecoveryResolverEvidenceExpiryProof[\s\S]*temporary-recovery-evidence-expiry-lock-probe[\s\S]*recovery evidence expiry did not wait on the receipt intent[\s\S]*waitForDatabaseTime[\s\S]*timing\.evidence_expired === true[\s\S]*timing\.receipt_live === true[\s\S]*timing\.resource_live === true[\s\S]*timing\.proposal_live === true/u
  );
  assert.match(
    gate1CapabilityRaceSource,
    /runRecoveryResolverConflictActivationProof[\s\S]*claimValue: "unavailable"[\s\S]*temporary-recovery-conflict-activation-lock-probe[\s\S]*recovery conflict activation did not wait on the receipt intent[\s\S]*waitForDatabaseTime[\s\S]*timing\.conflict_active === true[\s\S]*timing\.evidence_expired === false/u
  );
  assert.match(
    gate1CapabilityRaceSource,
    /class QueryReadyBarrier[\s\S]*query-ready barrier timed out[\s\S]*queryReady\?\.reach\(\);[\s\S]*client\.query\(SPEND_SQL[\s\S]*queryReady\?\.reach\(\);[\s\S]*client\.query\(sql, values\)/u
  );
  assert.equal(
    gate1CapabilityRaceSource.match(
      /new QueryReadyBarrier\(/gu
    )?.length,
    6
  );
  assert.equal(
    gate1CapabilityRaceSource.match(/await queryReady\.wait\(\);/gu)?.length,
    6
  );
  assert.equal(
    gate1CapabilityRaceSource.match(
      /await pending(?:Decision|Replay|Effect|Resolution)\.catch\(\(\) => \{\}\);/gu
    )?.length,
    6
  );
  assert.match(
    authorityStoreSource,
    /async authorizeDviProposal[\s\S]*postLockClock[\s\S]*statement_timestamp\(\)[\s\S]*finalCurrent[\s\S]*authority_current[\s\S]*DELETE FROM tp_ledger\.g1_dvi_proposal_receipts[\s\S]*current_epoch = 0/u
  );
  assert.match(
    authorityStoreSource,
    /setProposalExpiryAfterMsForTest[\s\S]*LEAST\([\s\S]*expires_at > statement_timestamp\(\)/u
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
  const insertStart = body.indexOf(
    "INSERT INTO tp_ledger.g1_protected_effects AS inserted_effect"
  );
  const conflictEnd = body.indexOf("ON CONFLICT DO NOTHING", insertStart);
  assert.notEqual(insertStart, -1);
  assert.notEqual(conflictEnd, -1);
  const preInsert = body.slice(0, insertStart);
  const insertSource = body.slice(insertStart, conflictEnd);
  const postInsert = body.slice(conflictEnd);
  assert.match(
    preInsert,
    /SELECT\s+count\(\*\)::INT8,\s*min\(outbox\.proposal_digest\),\s*min\(outbox\.logical_action_digest\),\s*min\(outbox\.authorization_epoch\),\s*min\(outbox\.logical_authority_key_sha256\),\s*min\(outbox\.authorization_binding_sha256\),\s*min\(receipt\.lease_expires_at\),\s*min\(resource\.lease_expires_at\),\s*min\(proposal\.expires_at\)\s+INTO\s+v_authority_count,\s*v_proposal_digest,\s*v_logical_action_digest,\s*v_authorization_epoch,\s*v_logical_authority_key_sha256,\s*v_authorization_binding_sha256,\s*v_receipt_lease_expires_at,\s*v_resource_lease_expires_at,\s*v_proposal_expires_at/u
  );
  assert.match(
    preInsert,
    /v_database_now := clock_timestamp\(\);\s*IF v_authority_count <> 1[\s\S]*v_receipt_lease_expires_at <= v_database_now[\s\S]*v_resource_lease_expires_at <= v_database_now[\s\S]*v_proposal_expires_at <= v_database_now THEN\s*RETURN;/u
  );
  assert.match(
    insertSource,
    /VALUES \(\s*p_tenant_id,\s*p_effect_key,\s*p_operation_id,\s*p_request_digest,\s*v_proposal_digest,\s*v_logical_action_digest,\s*v_authorization_epoch,\s*v_logical_authority_key_sha256,\s*v_authorization_binding_sha256,\s*p_run_id,\s*p_incident_id,\s*p_resource_id,\s*p_agent_id,\s*p_fencing_token,\s*p_payload_digest\s*\)/u
  );
  assert.doesNotMatch(insertSource, /\)\s*SELECT\b/u);
  assert.match(
    postInsert,
    /SELECT\s+count\(\*\)::INT8,\s*min\(receipt\.lease_expires_at\),\s*min\(resource\.lease_expires_at\),\s*min\(proposal\.expires_at\)[\s\S]*v_database_now := clock_timestamp\(\);[\s\S]*IF v_authority_count <> 1[\s\S]*DELETE FROM tp_ledger\.g1_protected_effects/u
  );
  assert.match(
    body,
    /JOIN tp_ledger\.g1_dvi_proposal_receipts AS proposal[\s\S]*proposal\.proposal_digest = outbox\.proposal_digest[\s\S]*proposal\.authorization_epoch = outbox\.authorization_epoch/u
  );
  assert.match(body, /proposal\.expires_at > clock_timestamp\(\)/u);
  assert.match(body, /proposal\.payload = outbox\.payload/u);
  assert.match(
    body,
    /sha256\(proposal\.payload_canonical::BYTES\)[\s\S]*outbox\.payload_digest/u
  );
  assert.match(
    body,
    /v_database_now := clock_timestamp\(\);[\s\S]*v_proposal_expires_at <= v_database_now[\s\S]*DELETE FROM tp_ledger\.g1_protected_effects/u
  );
  assert.doesNotMatch(body, /proposal\.expires_at >= clock_timestamp\(\)/u);
});

test("protected-effect SQL snapshots one exact authority before a value-only insert", async () => {
  const source = await readFile(primaryUrl, "utf8");
  const body = source.match(
    /CREATE OR REPLACE FUNCTION tp_api\.g1_record_protected_effect_v1\([\s\S]*?AS \$\$([\s\S]*?)\$\$/u
  )?.[1];
  assert.ok(body);

  const normalizedBody = body.replace(/\s+/gu, " ").trim();
  const insertStart = normalizedBody.indexOf(
    "INSERT INTO tp_ledger.g1_protected_effects AS inserted_effect"
  );
  const conflictStart = normalizedBody.indexOf(
    "ON CONFLICT DO NOTHING",
    insertStart
  );
  const postInsertStart = normalizedBody.indexOf(
    "IF v_inserted_count IS NULL",
    conflictStart
  );
  assert.ok(
    insertStart > 0 &&
    conflictStart > insertStart &&
    postInsertStart > conflictStart
  );

  const preInsert = normalizedBody.slice(0, insertStart).trimEnd();
  const insertClause = normalizedBody.slice(insertStart, conflictStart);
  const postInsert = normalizedBody.slice(postInsertStart);

  const ledgerSnapshotProjection =
    "SELECT count(*)::INT8, " +
    "min(outbox.proposal_digest), " +
    "min(outbox.logical_action_digest), " +
    "min(outbox.authorization_epoch), " +
    "min(outbox.logical_authority_key_sha256), " +
    "min(outbox.authorization_binding_sha256), " +
    "min(receipt.lease_expires_at), " +
    "min(resource.lease_expires_at), " +
    "min(proposal.expires_at) " +
    "INTO v_authority_count, " +
    "v_proposal_digest, " +
    "v_logical_action_digest, " +
    "v_authorization_epoch, " +
    "v_logical_authority_key_sha256, " +
    "v_authorization_binding_sha256, " +
    "v_receipt_lease_expires_at, " +
    "v_resource_lease_expires_at, " +
    "v_proposal_expires_at " +
    "FROM tp_private.g1_resources AS resource " +
    "JOIN tp_ledger.g1_outbox_intents AS outbox";
  assert.ok(preInsert.includes(ledgerSnapshotProjection));

  const exactPreInsertGuard =
    "v_database_now := clock_timestamp(); " +
    "IF v_authority_count <> 1 " +
    "OR v_proposal_digest IS NULL " +
    "OR v_receipt_lease_expires_at <= v_database_now " +
    "OR v_resource_lease_expires_at <= v_database_now " +
    "OR v_proposal_expires_at <= v_database_now THEN " +
    "RETURN; END IF;";
  assert.ok(preInsert.endsWith(exactPreInsertGuard));

  const exactValues =
    "VALUES ( " +
    "p_tenant_id, p_effect_key, p_operation_id, p_request_digest, " +
    "v_proposal_digest, v_logical_action_digest, v_authorization_epoch, " +
    "v_logical_authority_key_sha256, v_authorization_binding_sha256, " +
    "p_run_id, p_incident_id, p_resource_id, p_agent_id, " +
    "p_fencing_token, p_payload_digest )";
  assert.ok(insertClause.includes(exactValues));
  assert.doesNotMatch(insertClause, /\bSELECT\b/u);
  assert.ok(normalizedBody.includes("v_inserted_count INT8;"));
  assert.ok(normalizedBody.includes(
    "ON CONFLICT DO NOTHING " +
    "RETURNING 1::INT8 INTO v_inserted_count; " +
    "IF v_inserted_count IS NULL THEN RETURN; END IF; " +
    "v_effect_key := p_effect_key; " +
    "v_operation_id := p_operation_id;"
  ));
  assert.doesNotMatch(
    normalizedBody,
    /RETURNING inserted_effect\.(?:effect_key|operation_id)/u
  );
  assert.equal(
    body.match(/v_database_now := clock_timestamp\(\);/gu)?.length,
    2
  );

  const postProjection =
    "SELECT count(*)::INT8, " +
    "min(receipt.lease_expires_at), " +
    "min(resource.lease_expires_at), " +
    "min(proposal.expires_at) " +
    "INTO v_authority_count, " +
    "v_receipt_lease_expires_at, " +
    "v_resource_lease_expires_at, " +
    "v_proposal_expires_at " +
    "FROM tp_private.g1_resources AS resource";
  assert.ok(postInsert.includes(postProjection));

  const retainedPostInsertClauses = Object.freeze([
    "receipt.proposal_digest = resource.holder_proposal_digest",
    "receipt.logical_authority_key_sha256 = resource.holder_logical_authority_key_sha256",
    "receipt.outcome = 'resource_reserved'",
    "outbox.request_digest = receipt.request_digest",
    "outbox.proposal_digest = receipt.proposal_digest",
    "outbox.logical_action_digest = receipt.logical_action_digest",
    "outbox.authorization_epoch = receipt.authorization_epoch",
    "outbox.logical_authority_key_sha256 = receipt.logical_authority_key_sha256",
    "outbox.authorization_binding_sha256 = receipt.authorization_binding_sha256",
    "proposal.proposal_digest = receipt.proposal_digest",
    "proposal.logical_action_digest = receipt.logical_action_digest",
    "proposal.authorization_epoch = receipt.authorization_epoch",
    "proposal.logical_authority_key_sha256 = receipt.logical_authority_key_sha256",
    "proposal.authorization_binding_sha256 = receipt.authorization_binding_sha256",
    "proposal.payload = outbox.payload",
    "proposal.payload_digest = outbox.payload_digest",
    "receipt.request_digest = p_request_digest",
    "receipt.effect_key = p_effect_key",
    "receipt.payload_digest = p_payload_digest",
    "sha256(proposal.payload_canonical::BYTES) = outbox.payload_digest"
  ]);
  for (const clause of retainedPostInsertClauses) {
    assert.ok(postInsert.includes(clause), clause);
  }

  const exactPostInsertGuard =
    "v_database_now := clock_timestamp(); " +
    "IF v_authority_count <> 1 " +
    "OR v_receipt_lease_expires_at <= v_database_now " +
    "OR v_resource_lease_expires_at <= v_database_now " +
    "OR v_proposal_expires_at <= v_database_now THEN " +
    "DELETE FROM tp_ledger.g1_protected_effects AS effect " +
    "WHERE effect.tenant_id = p_tenant_id " +
    "AND effect.effect_key = v_effect_key " +
    "AND effect.operation_id = v_operation_id; " +
    "RETURN; END IF; " +
    "RETURN QUERY SELECT v_effect_key, v_operation_id;";
  assert.ok(postInsert.includes(exactPostInsertGuard));
});

test("Gate One executes the protected-effect insert and replay routine", async () => {
  const source = await readFile(gate1SecurityUrl, "utf8");
  assert.match(
    source,
    /const PROTECTED_EFFECT_SQL = `[\s\S]*g1_record_protected_effect_v1/u
  );
  assert.match(
    source,
    /wrongDigestBeforeInsert = await client\.query\([\s\S]*inserted = await client\.query\([\s\S]*replay = await client\.query\([\s\S]*wrongDigestAfterReplay = await client\.query\(/u
  );
  assert.match(
    source,
    /wrongDigestBeforeInsert\.rowCount !== 0[\s\S]*inserted\.rowCount !== 1[\s\S]*replay\.rowCount !== 0[\s\S]*wrongDigestAfterReplay\.rowCount !== 0/u
  );
  assert.match(
    source,
    /currentAfterWrongDigest !== true[\s\S]*currentAfterInsert !== true[\s\S]*currentAfterReplay !== true[\s\S]*currentAfterWrongDigestReplay !== true/u
  );
  assert.match(
    source,
    /connectionStringForUser\(\s*adminConnectionString,\s*"tp_authorizer_user",\s*passwords\.tp_authorizer_user\s*\),\s*async \(authorizerClient\) => withClient\(/u
  );
  assert.match(
    source,
    /async function authorityCurrent\(client, request, authorityIdentity\)[\s\S]*client\.query\(\s*SPEND_AUTHORITY_SQL,\s*spendAuthorityValues\(request\)[\s\S]*decision_replay_kind !== "operation_replay"[\s\S]*authorityIdentity\.authorizationEpoch[\s\S]*authorityIdentity\.logicalAuthorityKeySha256[\s\S]*authorityIdentity\.authorizationBindingSha256[\s\S]*decision_authority_current/u
  );
  assert.doesNotMatch(
    source,
    /FROM tp_private\.g1_authority_receipt_current_v2/u
  );
  assert.doesNotMatch(source, /authorityCurrent\(\s*admin,/u);
  assert.match(
    source,
    /authorityIdentity: \{[\s\S]*authorizationEpoch: spent\.rows\[0\]\?\.decision_authorization_epoch[\s\S]*logicalAuthorityKeySha256:[\s\S]*decision_logical_authority_key_sha256[\s\S]*authorizationBindingSha256:[\s\S]*decision_authorization_binding_sha256/u
  );
  assert.doesNotMatch(
    source,
    /normalizedCapabilityRequest\.(?:authorizationEpoch|logicalAuthorityKeySha256|authorizationBindingSha256)/u
  );
  assert.match(
    source,
    /capabilitySnapshot\.effects\.length !== 1[\s\S]*protectedEffect\?\.effect_key !== normalizedCapabilityRequest\.effectKey[\s\S]*protectedEffect\?\.operation_id !== normalizedCapabilityRequest\.operationId/u
  );
});
