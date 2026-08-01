import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const primaryUrl = new URL("../src/cloud/primary-security.js", import.meta.url);
const authorityStoreUrl = new URL(
  "../src/cloud/authority-store.js",
  import.meta.url
);
const recoveryUrl = new URL("../src/cloud/recovery-security.js", import.meta.url);
const recoveryScriptUrls = [
  new URL("../scripts/gate1-recovery.js", import.meta.url),
  new URL("../scripts/gate1-recovery-broker.js", import.meta.url)
];
const gate1AuthorityUrl = new URL(
  "../scripts/gate1-authority.js",
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

test("every database SECURITY DEFINER body binds the exact session user", async () => {
  const sharedAuthorizerGuard =
    /session_user (?:IN|NOT IN) \(\s*'tp_authorizer_user',\s*'tp_gate2_authorizer_user'\s*\)/u;
  const expectedPrimaryGuards = new Map([
    ["g1_append_verified_evidence_v1", /session_user = 'tp_ingest_user'/u],
    ["g1_get_verification_key_v1", /session_user = 'tp_ingest_user'/u],
    ["g1_append_verified_evidence_v2", /session_user <> 'tp_ingest_user'/u],
    ["g1_observe_admissibility_v1", /session_user = 'tp_authorizer_user'/u],
    ["g1_list_admissibility_internal_v1", sharedAuthorizerGuard],
    ["g1_observe_admissibility_v2", sharedAuthorizerGuard],
    ["g1_prepare_vector_set_v1", /session_user <> 'tp_authorizer_user'/u],
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
    ["g1_record_protected_effect_v1", /session_user = 'tp_dispatch_user'/u]
  ]);
  for (const [url, expectedGuards] of [
    [primaryUrl, expectedPrimaryGuards],
    [recoveryUrl, new Map([[
      "append_recovery_bundle_v2",
      /session_user <> '\$\{RECOVERY_PUBLISHER_USER\}'/u
    ]])]
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
      "RECOVERY_SOURCE_REQUEST_DIGEST"
    ]) {
      assert.equal(source.includes(field), true, `${url.pathname}:${field}`);
    }
    assert.doesNotMatch(source, /ORDER BY receipt\.recorded_at DESC/u);
    assert.doesNotMatch(source, /latestSyntheticReceipt/u);
  }
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
  assert.doesNotMatch(body, /proposal\.expires_at >= transaction_timestamp\(\)/u);
});
