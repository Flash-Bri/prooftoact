import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

import {
  integratedLiveDrillCanonicalSha256,
  signIntegratedLiveDrillEvidence
} from "../src/cloud/integrated-live-drill-authorization.js";
import {
  __test as providerTest,
  INTEGRATED_LIVE_DRILL_PROVIDER_EXPIRY_BURN_SCHEMA,
  integratedLiveDrillProviderDispatchAuthorizationPayload,
  prepareIntegratedLiveDrillProviderRecoveryAuthorization,
  runIntegratedLiveDrillProviderRecovery,
  validateIntegratedLiveDrillManagedMcpSemanticRequestEvidence,
  validateIntegratedLiveDrillManagedMcpTransportEvidence,
  validateIntegratedLiveDrillProviderDispatchAuthorization
} from "../src/cloud/integrated-live-drill-provider-recovery.js";
import {
  __test as continuityTest,
  runIntegratedLiveDrillRecoveryContinuityW1,
  runIntegratedLiveDrillRecoveryContinuityW2
} from "../src/cloud/integrated-live-drill-recovery-continuity.js";
import { CockroachManagedMcpRecoveryClient } from
  "../src/cloud/managed-mcp-client.js";
import {
  DeterministicRecoveryBroker,
  principalBindingHash,
  recoveryAuditEventDigest
} from "../src/cloud/recovery-broker.js";
import { createRecoveryContinuityFixture } from
  "./helpers/integrated-live-drill-recovery-continuity-fixture.js";

const PRINCIPAL = "principal://synthetic-provider-continuity";

function consumedChildAuthorizationIssuedAt(context) {
  return context.preCallInputs.consumedChildAuthorization.attestation.payload
    .issuedAt;
}

function recoveryRow(bundle) {
  return Object.freeze({
    tenant_id: bundle.tenantId,
    recovery_session_id: bundle.recoverySessionId,
    subject_binding_hash: bundle.subjectBindingHash,
    schema_version: String(bundle.schemaVersion),
    snapshot_version: String(bundle.snapshotVersion),
    source_cluster_id: bundle.sourceClusterId,
    source_commit_ts: bundle.sourceCommitTs,
    source_digest: bundle.sourceDigest,
    bundle_digest: bundle.bundleDigest,
    policy_version: bundle.policyVersion,
    publisher_key_id: bundle.publisherKeyId,
    publisher_version: bundle.publisherVersion,
    signature_algorithm: bundle.signatureAlgorithm,
    source_signature_base64: bundle.sourceSignatureBase64,
    signature_digest: bundle.signatureDigest,
    checkpoint_summary: bundle.checkpointSummary,
    evidence_summary: bundle.evidenceSummary,
    conflict_summary: bundle.conflictSummary,
    receipt_summary: bundle.receiptSummary,
    authority_transferred: false,
    requires_fresh_authorization: true,
    expires_at: bundle.expiresAt
  });
}

function recoveryBundleWithExpiry(fixture, expiresAt) {
  const bundle = fixture.persistedBundle.bundle;
  return fixture.testOnly.recoverySigner.sign({
    tenantId: bundle.tenantId,
    recoverySessionId: bundle.recoverySessionId,
    subjectBindingHash: bundle.subjectBindingHash,
    schemaVersion: bundle.schemaVersion,
    snapshotVersion: bundle.snapshotVersion,
    sourceClusterId: bundle.sourceClusterId,
    sourceCommitTs: bundle.sourceCommitTs,
    sourceDigest: bundle.sourceDigest,
    policyVersion: bundle.policyVersion,
    checkpointSummary: bundle.checkpointSummary,
    evidenceSummary: bundle.evidenceSummary,
    conflictSummary: bundle.conflictSummary,
    receiptSummary: bundle.receiptSummary,
    expiresAt
  });
}

function normalizedAuditEvent(event) {
  return Object.freeze({
    ...event,
    startedAt: new Date(event.startedAt).toISOString(),
    completedAt: new Date(event.completedAt).toISOString(),
    sourceWatermark: event.sourceWatermark === null
      ? null
      : new Date(event.sourceWatermark).toISOString()
  });
}

function databaseAuditRow(event, eventDigest) {
  return Object.freeze({
    event_id: event.eventId,
    tenant_id: event.tenantId,
    interaction_id: event.interactionId,
    recovery_session_id: event.recoverySessionId,
    caller_subject_hash: event.callerSubjectHash,
    phase: event.phase,
    recovery_cluster_id: event.recoveryClusterId,
    broker_config_digest: event.brokerConfigDigest,
    query_template_digest: event.queryTemplateDigest,
    bound_input_digest: event.boundInputDigest,
    result_digest: event.resultDigest,
    source_watermark: event.sourceWatermark,
    outcome: event.outcome,
    error_code: event.errorCode,
    started_at: event.startedAt,
    completed_at: event.completedAt,
    event_digest: eventDigest
  });
}

function exactDispatchAuthorization(fixture, options = {}) {
  const payload = integratedLiveDrillProviderDispatchAuthorizationPayload({
    childAuthorizationIssuedAt:
      consumedChildAuthorizationIssuedAt(fixture.context),
    intent: fixture.context.preCallIntent,
    issuedAt: options.issuedAt ??
      consumedChildAuthorizationIssuedAt(fixture.context),
    expiresAt: options.expiresAt ??
      new Date(fixture.testOnly.now + 5 * 60_000).toISOString()
  });
  return signIntegratedLiveDrillEvidence(
    payload,
    fixture.testOnly.human.privateKeyPkcs8DerBase64,
    fixture.testOnly.human.publicKey
  );
}

function prepareDispatch(fixture, context = fixture.context, options = {}) {
  return prepareIntegratedLiveDrillProviderRecoveryAuthorization({
    context,
    issuedAt: options.issuedAt ??
      consumedChildAuthorizationIssuedAt(context),
    expiresAt: options.expiresAt ??
      new Date(fixture.testOnly.now + 5 * 60_000).toISOString()
  });
}

function signPreparedDispatch(fixture, preparation) {
  return signIntegratedLiveDrillEvidence(
    preparation.signingPayload,
    fixture.testOnly.human.privateKeyPkcs8DerBase64,
    fixture.testOnly.human.publicKey
  );
}

function serializedIncludes(value, needle) {
  return JSON.stringify(value).includes(needle);
}

function recomputeArtifactReceipt(value) {
  const changed = structuredClone(value);
  delete changed.receiptSha256;
  return {
    ...changed,
    receiptSha256: integratedLiveDrillCanonicalSha256(changed)
  };
}

function injectMutationAfterTargetRead(t, targetPath, mutate) {
  const target = fs.lstatSync(targetPath);
  const originalReadFileSync = fs.readFileSync.bind(fs);
  let injected = false;
  t.mock.method(fs, "readFileSync", (...args) => {
    const candidate = args[0];
    let matches = false;
    if (typeof candidate === "number") {
      const opened = fs.fstatSync(candidate);
      matches = opened.dev === target.dev && opened.ino === target.ino;
    } else if (typeof candidate === "string") {
      matches = path.resolve(candidate) === path.resolve(targetPath);
    }
    const bytes = originalReadFileSync(...args);
    if (matches && !injected) {
      injected = true;
      mutate();
    }
    return bytes;
  });
  return () => injected;
}

function providerHarness(fixture, {
  afterAuditAppend = null,
  afterAuditResolve = null,
  afterFetchRecorded = null,
  beforeAuditResolveDispatch = null,
  duringSessionResolve = null
} = {}) {
  const calls = [];
  const auditAppendAttempts = [];
  const auditResolveAttempts = [];
  const auditRows = new Map();
  const row = recoveryRow(fixture.persistedBundle.bundle);
  const sessionId = "synthetic-provider-session";
  const fetchImpl = async (url, options) => {
    const payload = options.body === undefined
      ? null
      : JSON.parse(options.body);
    calls.push(Object.freeze({ method: options.method, payload, url }));
    if (afterFetchRecorded !== null) {
      await afterFetchRecorded(Object.freeze({
        action: payload?.method ?? options.method,
        method: options.method,
        payload,
        url
      }));
    }
    if (options.method === "DELETE") {
      return new Response(null, {
        status: 200,
        headers: { "mcp-session-id": sessionId }
      });
    }
    if (payload.method === "initialize") {
      return new Response(JSON.stringify({
        jsonrpc: "2.0",
        id: payload.id,
        result: { protocolVersion: "2025-03-26", capabilities: {} }
      }), {
        status: 200,
        headers: {
          "content-type": "application/json",
          "mcp-session-id": sessionId
        }
      });
    }
    if (payload.method === "notifications/initialized") {
      return new Response(null, {
        status: 202,
        headers: { "mcp-session-id": sessionId }
      });
    }
    return new Response(JSON.stringify({
      jsonrpc: "2.0",
      id: payload.id,
      result: {
        content: [{
          type: "text",
          text: JSON.stringify({ rows: [row] })
        }]
      }
    }), {
      status: 200,
      headers: {
        "content-type": "application/json",
        "mcp-session-id": sessionId
      }
    });
  };
  const mcpClient = new CockroachManagedMcpRecoveryClient({
    apiKey: "synthetic-test-only-mcp-api-key-0001",
    clusterId: fixture.context.preCallIntent.recoveryClusterId,
    fetchImpl
  });
  const broker = new DeterministicRecoveryBroker({
    buildIdentity:
      fixture.context.trustedRunContext.spec.sourceBuildIdentity,
    recoveryClusterId: fixture.context.preCallIntent.recoveryClusterId,
    expectedSourceClusterId:
      fixture.context.preCallIntent.expectedSourceClusterId,
    trustedPublisherKeys: {
      [fixture.testOnly.recoverySigner.publisherKeyId]:
        fixture.testOnly.recoverySigner.publicKeySpkiBase64
    },
    mcpClient,
    sessionResolver: {
      async resolve({ authenticatedPrincipal }) {
        assert.equal(typeof authenticatedPrincipal, "string");
        if (duringSessionResolve !== null) {
          await duringSessionResolve();
        }
        return {
          tenantId: fixture.context.preCallIntent.tenantId,
          recoverySessionId:
            fixture.context.preCallIntent.recoverySessionId,
          subjectBindingHash:
            fixture.context.preCallIntent.subjectBindingSha256,
          sourceDigest: fixture.context.preCallIntent.sourceDigest
        };
      }
    },
    auditSink: {
      async append(event) {
        const normalized = normalizedAuditEvent(event);
        const eventDigest = recoveryAuditEventDigest(normalized);
        const row = databaseAuditRow(
          normalized,
          eventDigest
        );
        auditAppendAttempts.push(Object.freeze({
          event: normalized,
          eventDigest
        }));
        const existing = auditRows.get(normalized.eventId);
        if (existing !== undefined) {
          assert.deepEqual(row, existing);
        } else {
          auditRows.set(normalized.eventId, row);
        }
        if (afterAuditAppend !== null) {
          await afterAuditAppend(Object.freeze({
            event: normalized,
            eventDigest
          }));
        }
        return { eventDigest };
      },
      async resolve(event, { beforeExternalAction = null } = {}) {
        const normalized = normalizedAuditEvent(event);
        const eventDigest = recoveryAuditEventDigest(normalized);
        const eventId = normalized.eventId;
        const tenantId = normalized.tenantId;
        if (beforeAuditResolveDispatch !== null) {
          await beforeAuditResolveDispatch(Object.freeze({
            eventDigest,
            eventId,
            tenantId
          }));
        }
        if (beforeExternalAction !== null) {
          beforeExternalAction("AUDIT_RESOLVE_DISPATCH");
        }
        auditResolveAttempts.push(Object.freeze({
          eventDigest,
          eventId,
          tenantId
        }));
        const value = auditRows.get(eventId);
        assert.equal(value?.tenant_id, tenantId);
        assert.equal(value?.event_digest, eventDigest);
        if (afterAuditResolve !== null) {
          await afterAuditResolve(Object.freeze({
            eventDigest,
            eventId,
            tenantId
          }));
        }
        return value;
      }
    }
  });
  return {
    auditAppendAttempts,
    auditResolveAttempts,
    auditRows,
    broker,
    calls,
    mcpClient
  };
}

test("actual provider path cross-binds W1-W3, exact tools/call bytes, and private evidence", async (t) => {
  const subjectBindingSha256 = principalBindingHash(PRINCIPAL);
  const fixture = createRecoveryContinuityFixture(t, {
    prefix: "prooftoact-b2-provider-",
    subjectBindingSha256
  });
  const harness = providerHarness(fixture);
  const preparation = prepareDispatch(fixture);
  assert.equal(preparation.status, "AWAITING_AUTHORIZATION");
  assert.equal(preparation.providerBacked, false);
  assert.equal(preparation.accepted, false);
  assert.equal(preparation.finalReleaseReady, false);
  assert.equal(
    preparation.dedicatedCredentialFieldAcceptedOrPersisted,
    false
  );
  assert.equal(preparation.humanPrivateKeyRequired, false);
  assert.equal(
    preparation.humanSignatureProducedOutsidePreparationApi,
    true
  );
  assert.equal(preparation.preparationContextStrictlyAllowlisted, true);
  assert.equal(harness.calls.length, 0);
  assert.equal(
    serializedIncludes(
      preparation,
      fixture.testOnly.human.privateKeyPkcs8DerBase64
    ),
    false
  );
  const providerDispatchAuthorization = signPreparedDispatch(
    fixture,
    preparation
  );
  const context = Object.freeze({
    ...fixture.context,
    providerDispatchAuthorization
  });
  assert.equal(
    serializedIncludes(
      context,
      fixture.testOnly.human.privateKeyPkcs8DerBase64
    ),
    false
  );

  const result = await runIntegratedLiveDrillProviderRecovery({
    authenticatedPrincipal: PRINCIPAL,
    broker: harness.broker,
    context
  });

  assert.equal(result.recovery.status, "RECOVERED_CONTEXT_ONLY");
  assert.equal(result.providerContinuity.providerBacked, false);
  assert.equal(result.providerContinuity.accepted, false);
  assert.equal(result.providerContinuity.finalReleaseReady, false);
  assert.equal(result.providerContinuity.observedToolsCallCount, 1);
  assert.equal(result.providerContinuity.observedSessionCloseCount, 1);
  assert.equal(
    result.providerContinuity.logicalMcpRequestSha256,
    context.preCallIntent.logicalMcpRequestSha256
  );
  assert.deepEqual(
    harness.calls.map(({ payload, method }) => payload?.method ?? method),
    ["initialize", "notifications/initialized", "tools/call", "DELETE"]
  );
  const toolCall = harness.calls[2].payload;
  assert.equal(toolCall.params.name, "select_query");
  assert.equal(toolCall.params.arguments.database, "tideproof_recovery");
  const semantic = harness.mcpClient.semanticRequestEvidence();
  assert.equal(
    semantic.logicalMcpRequestSha256,
    context.preCallIntent.logicalMcpRequestSha256
  );
  validateIntegratedLiveDrillManagedMcpSemanticRequestEvidence(semantic, {
    intent: context.preCallIntent,
    transportEvidence: harness.mcpClient.transportEvidence()
  });
  validateIntegratedLiveDrillProviderDispatchAuthorization(
    providerDispatchAuthorization,
    {
      childAuthorizationIssuedAt:
        consumedChildAuthorizationIssuedAt(context),
      humanAuthorizationTrustRoot:
        context.trustedRunContext.humanAuthorizationTrustRoot,
      intent: context.preCallIntent
    }
  );
  const privateFiles = fs.readdirSync(context.recoveryEvidenceRootPath)
    .filter((name) => name.includes("provider-recovery-"));
  assert.equal(privateFiles.length, 6);
  for (const name of privateFiles) {
    assert.equal(
      fs.statSync(path.join(context.recoveryEvidenceRootPath, name)).mode & 0o777,
      0o600
    );
  }
  const preparationFile = privateFiles.find((name) =>
    name.endsWith("-dispatch-preparation.json")
  );
  const persistedPreparation = JSON.parse(fs.readFileSync(
    path.join(context.recoveryEvidenceRootPath, preparationFile),
    "utf8"
  ));
  assert.deepEqual(
    persistedPreparation.signingPayload,
    preparation.signingPayload
  );
  assert.deepEqual(
    persistedPreparation.preCallInputs,
    fixture.context.preCallInputs
  );
  assert.equal(
    serializedIncludes(
      persistedPreparation,
      fixture.testOnly.human.privateKeyPkcs8DerBase64
    ),
    false
  );
  const providerFile = privateFiles.find((name) => name.endsWith("-mcp.json"));
  const providerArtifact = JSON.parse(fs.readFileSync(
    path.join(context.recoveryEvidenceRootPath, providerFile),
    "utf8"
  ));
  const preReadPlanFile = privateFiles.find((name) =>
    name.endsWith("-pre-read-plan.json")
  );
  const preReadPlanArtifact = JSON.parse(fs.readFileSync(
    path.join(context.recoveryEvidenceRootPath, preReadPlanFile),
    "utf8"
  ));
  providerTest.validatePreReadPlanArtifact(
    preReadPlanArtifact,
    context.preCallIntent
  );
  const terminalPlanFile = privateFiles.find((name) =>
    name.endsWith("-terminal-plan.json")
  );
  const terminalPlanArtifact = JSON.parse(fs.readFileSync(
    path.join(context.recoveryEvidenceRootPath, terminalPlanFile),
    "utf8"
  ));
  providerTest.validateTerminalPlanArtifact(
    terminalPlanArtifact,
    context.preCallIntent,
    preReadPlanArtifact.prepared,
    providerArtifact
  );
  const transportMutations = [
    ["schema", (value) => { value.schemaVersion = "unexpected"; }],
    ["endpoint", (value) => { value.endpointSha256 = "0".repeat(64); }],
    ["authority", (value) => { value.endpointAuthority = "example.test"; }],
    ["cluster", (value) => { value.clusterIdSha256 = "not-a-digest"; }],
    ["protocol", (value) => { value.protocolVersion = "2099-01-01"; }],
    ["redirect", (value) => { value.redirectPolicy = "follow"; }],
    ["limit", (value) => { value.boundedResponseBytes += 1; }],
    ["session", (value) => { value.sessionIdSha256 = "0".repeat(64); }],
    ["rpc count", (value) => { value.rpcCalls.push(value.rpcCalls[1]); }],
    ["initialize method", (value) => {
      value.rpcCalls[0].method = "tools/call";
    }],
    ["initialize status", (value) => { value.rpcCalls[0].httpStatus = 201; }],
    ["initialize content", (value) => {
      value.rpcCalls[0].contentType = "application/json; charset=utf-8";
    }],
    ["initialize request bytes", (value) => {
      value.rpcCalls[0].requestBytes = 0;
    }],
    ["initialize response bytes", (value) => {
      value.rpcCalls[0].responseBytes = value.boundedResponseBytes + 1;
    }],
    ["initialize request id", (value) => {
      value.rpcCalls[0].requestIdSha256 = "invalid";
    }],
    ["initialize response id", (value) => {
      value.rpcCalls[0].responseIdSha256 = "0".repeat(64);
    }],
    ["initialize request digest", (value) => {
      value.rpcCalls[0].requestPayloadSha256 = "invalid";
    }],
    ["initialize response digest", (value) => {
      value.rpcCalls[0].responsePayloadSha256 = "invalid";
    }],
    ["initialize result digest", (value) => {
      value.rpcCalls[0].resultSha256 = "invalid";
    }],
    ["initialize correlated", (value) => {
      value.rpcCalls[0].responseCorrelated = false;
    }],
    ["initialize continuity", (value) => {
      value.rpcCalls[0].sessionContinuous = false;
    }],
    ["initialize outbound", (value) => {
      value.rpcCalls[0].outboundSessionIdSha256 = value.sessionIdSha256;
    }],
    ["initialize response session", (value) => {
      value.rpcCalls[0].responseSessionIdSha256 = null;
    }],
    ["initialize session", (value) => {
      value.rpcCalls[0].sessionIdSha256 = "0".repeat(64);
    }],
    ["tools method", (value) => { value.rpcCalls[1].method = "initialize"; }],
    ["tools status", (value) => { value.rpcCalls[1].httpStatus = 204; }],
    ["tools outbound", (value) => {
      value.rpcCalls[1].outboundSessionIdSha256 = null;
    }],
    ["tools response session", (value) => {
      value.rpcCalls[1].responseSessionIdSha256 = "0".repeat(64);
    }],
    ["notification count", (value) => { value.notifications.push({}); }],
    ["notification method", (value) => {
      value.notifications[0].method = "notification/other";
    }],
    ["notification status", (value) => {
      value.notifications[0].httpStatus = 201;
    }],
    ["notification bytes", (value) => {
      value.notifications[0].requestBytes += 1;
    }],
    ["notification digest", (value) => {
      value.notifications[0].requestPayloadSha256 = "invalid";
    }],
    ["notification continuity", (value) => {
      value.notifications[0].sessionContinuous = false;
    }],
    ["notification outbound", (value) => {
      value.notifications[0].outboundSessionIdSha256 = "0".repeat(64);
    }],
    ["notification response", (value) => {
      value.notifications[0].responseSessionIdSha256 = "0".repeat(64);
    }],
    ["close attempted", (value) => { value.close.attempted = false; }],
    ["close status", (value) => { value.close.httpStatus = 201; }],
    ["close continuity", (value) => { value.close.sessionContinuous = false; }],
    ["close outbound", (value) => {
      value.close.outboundSessionIdSha256 = "0".repeat(64);
    }],
    ["close response", (value) => {
      value.close.responseSessionIdSha256 = "0".repeat(64);
    }],
    ["rpc extra key", (value) => { value.rpcCalls[0].unexpected = true; }],
    ["extra key", (value) => { value.unexpected = true; }]
  ];
  for (const [name, mutate] of transportMutations) {
    const changed = structuredClone(providerArtifact.transportEvidence);
    mutate(changed);
    assert.throws(
      () => validateIntegratedLiveDrillManagedMcpTransportEvidence(changed),
      /INTEGRATED_LIVE_DRILL_PROVIDER_TRANSPORT_REJECTED/u,
      name
    );
  }
  for (const key of Object.keys(providerArtifact)) {
    const changed = structuredClone(providerArtifact);
    if (key === "receiptSha256") {
      changed[key] = "0".repeat(64);
    } else if (typeof changed[key] === "string") {
      changed[key] = `${changed[key]}-mutated`;
    } else if (changed[key] !== null && typeof changed[key] === "object") {
      changed[key].unexpectedOuterReceiptMutation = true;
    } else {
      changed[key] = !changed[key];
    }
    assert.throws(
      () => providerTest.validateProviderArtifact(
        changed,
        context.preCallIntent,
        context
      ),
      /INTEGRATED_LIVE_DRILL_PROVIDER_(?:EVIDENCE_BINDING|RECEIPT|TRANSPORT|SEMANTIC_REQUEST)_REJECTED/u,
      `outer receipt field ${key}`
    );
  }
  const changedResult = structuredClone(providerArtifact);
  changedResult.transportEvidence.rpcCalls[1].resultSha256 = "0".repeat(64);
  changedResult.observedTransportCounts =
    validateIntegratedLiveDrillManagedMcpTransportEvidence(
      changedResult.transportEvidence
    );
  changedResult.transportEvidenceSha256 =
    changedResult.observedTransportCounts.transportEvidenceSha256;
  const { receiptSha256: ignored, ...changedResultBody } = changedResult;
  void ignored;
  changedResult.receiptSha256 =
    integratedLiveDrillCanonicalSha256(changedResultBody);
  assert.throws(
    () => providerTest.validateProviderArtifact(
      changedResult,
      context.preCallIntent,
      context
    ),
    /INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_BINDING_REJECTED/u
  );

  const callCount = harness.calls.length;
  const resumed = await runIntegratedLiveDrillProviderRecovery({
    authenticatedPrincipal: PRINCIPAL,
    broker: harness.broker,
    context
  });
  assert.equal(resumed.recovery.status, "RECOVERED_CONTEXT_ONLY");
  assert.equal(harness.calls.length, callCount);
});

test("persisted provider recovery artifacts reject recomputed extra members and authority escalation", async (t) => {
  const fixture = createRecoveryContinuityFixture(t, {
    prefix: "prooftoact-b2-provider-exact-artifact-schema-",
    subjectBindingSha256: principalBindingHash(PRINCIPAL)
  });
  const preparation = prepareDispatch(fixture);
  const context = Object.freeze({
    ...fixture.context,
    providerDispatchAuthorization: signPreparedDispatch(fixture, preparation)
  });
  const harness = providerHarness(fixture);
  await runIntegratedLiveDrillProviderRecovery({
    authenticatedPrincipal: PRINCIPAL,
    broker: harness.broker,
    context
  });
  const readArtifact = (suffix) => {
    const name = fs.readdirSync(context.recoveryEvidenceRootPath)
      .find((candidate) => candidate.endsWith(
        `.provider-recovery-${suffix}.json`
      ));
    assert.equal(typeof name, "string");
    return JSON.parse(fs.readFileSync(
      path.join(context.recoveryEvidenceRootPath, name),
      "utf8"
    ));
  };
  const preReadPlan = readArtifact("pre-read-plan");
  const terminal = readArtifact("terminal");

  const extraPlanRoot = structuredClone(preReadPlan);
  extraPlanRoot.capability = "provider-dispatch";
  assert.throws(
    () => providerTest.validatePreReadPlanArtifact(
      recomputeArtifactReceipt(extraPlanRoot),
      context.preCallIntent
    ),
    /INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_BINDING_REJECTED/u
  );

  const extraPrepared = structuredClone(preReadPlan);
  extraPrepared.prepared.capability = "provider-dispatch";
  extraPrepared.preparedSha256 = integratedLiveDrillCanonicalSha256(
    extraPrepared.prepared
  );
  assert.throws(
    () => providerTest.validatePreReadPlanArtifact(
      recomputeArtifactReceipt(extraPrepared),
      context.preCallIntent
    ),
    /INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_BINDING_REJECTED/u
  );

  const extraAudit = structuredClone(preReadPlan);
  extraAudit.prepared.preReadAuditEvent.capability = "provider-dispatch";
  extraAudit.prepared.preReadAuditDigest = recoveryAuditEventDigest(
    extraAudit.prepared.preReadAuditEvent
  );
  extraAudit.preReadAuditDigest = extraAudit.prepared.preReadAuditDigest;
  extraAudit.preReadAuditEventSha256 = integratedLiveDrillCanonicalSha256(
    extraAudit.prepared.preReadAuditEvent
  );
  extraAudit.preparedSha256 = integratedLiveDrillCanonicalSha256(
    extraAudit.prepared
  );
  assert.throws(
    () => providerTest.validatePreReadPlanArtifact(
      recomputeArtifactReceipt(extraAudit),
      context.preCallIntent
    ),
    /INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_BINDING_REJECTED/u
  );

  const escalatedTerminal = structuredClone(terminal);
  escalatedTerminal.recovery.authorityTransferred = true;
  escalatedTerminal.recovery.requiresFreshAuthorization = false;
  escalatedTerminal.recovery.capability = "provider-dispatch";
  escalatedTerminal.recoverySha256 = integratedLiveDrillCanonicalSha256(
    escalatedTerminal.recovery
  );
  assert.throws(
    () => providerTest.validateTerminalArtifact(
      recomputeArtifactReceipt(escalatedTerminal),
      context.preCallIntent
    ),
    /INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_BINDING_REJECTED/u
  );

  const extraTerminalContext = structuredClone(terminal);
  extraTerminalContext.recovery.context.capability = "provider-dispatch";
  extraTerminalContext.recoverySha256 = integratedLiveDrillCanonicalSha256(
    extraTerminalContext.recovery
  );
  assert.throws(
    () => providerTest.validateTerminalArtifact(
      recomputeArtifactReceipt(extraTerminalContext),
      context.preCallIntent
    ),
    /INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_BINDING_REJECTED/u
  );

  for (const summary of ["evidence", "receipt"]) {
    const extraSummary = structuredClone(terminal);
    extraSummary.recovery.context[summary].capability = "provider-dispatch";
    extraSummary.recoverySha256 = integratedLiveDrillCanonicalSha256(
      extraSummary.recovery
    );
    assert.throws(
      () => providerTest.validateTerminalArtifact(
        recomputeArtifactReceipt(extraSummary),
        context.preCallIntent
      ),
      /INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_BINDING_REJECTED/u,
      summary
    );
  }
});

test("W1 and W3 audit-commit crashes resume exact persisted event plans without duplicate MCP fetches", async (t) => {
  const w1Fixture = createRecoveryContinuityFixture(t, {
    prefix: "prooftoact-b2-provider-w1-audit-crash-",
    subjectBindingSha256: principalBindingHash(PRINCIPAL)
  });
  const w1Harness = providerHarness(w1Fixture);
  const w1Preparation = prepareDispatch(w1Fixture);
  const w1Context = Object.freeze({
    ...w1Fixture.context,
    providerDispatchAuthorization: signPreparedDispatch(
      w1Fixture,
      w1Preparation
    )
  });
  const w1Args = Object.freeze({
    authenticatedPrincipal: PRINCIPAL,
    broker: w1Harness.broker,
    context: w1Context
  });
  await assert.rejects(
    () => providerTest.runProviderRecoveryWithInterruption(
      w1Args,
      "AFTER_PRE_READ_AUDIT_COMMIT"
    ),
    /INTEGRATED_LIVE_DRILL_PROVIDER_SYNTHETIC_CRASH_AFTER_PRE_READ_AUDIT_COMMIT/u
  );
  assert.equal(w1Harness.calls.length, 0);
  await assert.rejects(
    () => runIntegratedLiveDrillProviderRecovery({
      ...w1Args,
      authenticatedPrincipal: "principal://wrong-resume-identity"
    }),
    /RECOVERY_PREPARED_RESUME_BINDING_MISMATCH/u
  );
  assert.equal(w1Harness.calls.length, 0);
  const committedPreRead = w1Harness.auditRows.get(
    w1Context.preCallIntent.preReadAuditEventId
  );
  assert.ok(committedPreRead);
  const w1Result = await runIntegratedLiveDrillProviderRecovery(w1Args);
  assert.equal(w1Result.recovery.status, "RECOVERED_CONTEXT_ONLY");
  assert.deepEqual(
    w1Harness.calls.map(({ payload, method }) => payload?.method ?? method),
    ["initialize", "notifications/initialized", "tools/call", "DELETE"]
  );
  const preReadAttempts = w1Harness.auditAppendAttempts.filter(
    ({ event }) => event.eventId === w1Context.preCallIntent.preReadAuditEventId
  );
  assert.equal(preReadAttempts.length, 2);
  assert.deepEqual(preReadAttempts[0], preReadAttempts[1]);
  assert.deepEqual(
    w1Harness.auditRows.get(w1Context.preCallIntent.preReadAuditEventId),
    committedPreRead
  );

  const w3Fixture = createRecoveryContinuityFixture(t, {
    prefix: "prooftoact-b2-provider-w3-audit-crash-",
    subjectBindingSha256: principalBindingHash(PRINCIPAL)
  });
  const w3Harness = providerHarness(w3Fixture);
  const w3Preparation = prepareDispatch(w3Fixture);
  const w3Context = Object.freeze({
    ...w3Fixture.context,
    providerDispatchAuthorization: signPreparedDispatch(
      w3Fixture,
      w3Preparation
    )
  });
  const w3Args = Object.freeze({
    authenticatedPrincipal: PRINCIPAL,
    broker: w3Harness.broker,
    context: w3Context
  });
  await assert.rejects(
    () => providerTest.runProviderRecoveryWithInterruption(
      w3Args,
      "AFTER_TERMINAL_AUDIT_COMMIT"
    ),
    /INTEGRATED_LIVE_DRILL_PROVIDER_SYNTHETIC_CRASH_AFTER_TERMINAL_AUDIT_COMMIT/u
  );
  const providerCallCount = w3Harness.calls.length;
  assert.equal(providerCallCount, 4);
  const committedTerminal = w3Harness.auditRows.get(
    w3Context.preCallIntent.terminalAuditEventId
  );
  assert.ok(committedTerminal);
  const w3Result = await runIntegratedLiveDrillProviderRecovery(w3Args);
  assert.equal(w3Result.recovery.status, "RECOVERED_CONTEXT_ONLY");
  assert.equal(w3Harness.calls.length, providerCallCount);
  const terminalAttempts = w3Harness.auditAppendAttempts.filter(
    ({ event }) => event.eventId === w3Context.preCallIntent.terminalAuditEventId
  );
  assert.equal(terminalAttempts.length, 2);
  assert.deepEqual(terminalAttempts[0], terminalAttempts[1]);
  assert.deepEqual(
    w3Harness.auditRows.get(w3Context.preCallIntent.terminalAuditEventId),
    committedTerminal
  );

  for (const [context, suffixes] of [
    [w1Context, ["pre-read-plan", "pre-read", "terminal-plan", "terminal"]],
    [w3Context, ["pre-read-plan", "pre-read", "terminal-plan", "terminal"]]
  ]) {
    for (const suffix of suffixes) {
      const filePath = providerTest.artifactPath(
        {
          rootPath: context.recoveryEvidenceRootPath
        },
        context.preCallIntent.authorizationId,
        suffix
      );
      assert.equal(fs.statSync(filePath).mode & 0o777, 0o600);
    }
  }

  const expiryFixture = createRecoveryContinuityFixture(t, {
    prefix: "prooftoact-b2-provider-terminal-plan-expiry-",
    subjectBindingSha256: principalBindingHash(PRINCIPAL)
  });
  const expiryHarness = providerHarness(expiryFixture);
  const expiryPrepared = await expiryHarness.broker.planRecovery(
    { authenticatedPrincipal: PRINCIPAL },
    {
      auditIdentity: {
        interactionId: expiryFixture.context.preCallIntent.interactionId,
        preReadEventId: expiryFixture.context.preCallIntent.preReadAuditEventId,
        terminalEventId:
          expiryFixture.context.preCallIntent.terminalAuditEventId,
        startedAt: expiryFixture.context.preCallIntent.startedAt
      }
    }
  );
  const shortExpiry = new Date(Date.now() + 120).toISOString();
  const expiringRawResult = Object.freeze({
    content: [Object.freeze({
      type: "text",
      text: JSON.stringify({
        rows: [recoveryRow(recoveryBundleWithExpiry(
          expiryFixture,
          shortExpiry
        ))]
      })
    })]
  });
  const expiringPlan = expiryHarness.broker.planPreparedRecoveryCompletion(
    expiryPrepared,
    expiringRawResult
  );
  await new Promise((resolve) => setTimeout(resolve, 180));
  await assert.rejects(
    () => expiryHarness.broker.commitPreparedRecoveryCompletion(
      expiringPlan,
      expiryPrepared,
      expiringRawResult
    ),
    /RECOVERY_BUNDLE_EXPIRED/u
  );
  assert.equal(
    expiryHarness.auditRows.has(
      expiryFixture.context.preCallIntent.terminalAuditEventId
    ),
    false
  );
});

test("provider path rejects semantic or separately signed dispatch substitution", (t) => {
  const fixture = createRecoveryContinuityFixture(t, {
    prefix: "prooftoact-b2-provider-reject-",
    subjectBindingSha256: principalBindingHash(PRINCIPAL)
  });
  const authorization = exactDispatchAuthorization(fixture);
  const changed = structuredClone(authorization);
  changed.payload.logicalMcpRequestSha256 = "0".repeat(64);
  assert.throws(
    () => validateIntegratedLiveDrillProviderDispatchAuthorization(changed, {
      childAuthorizationIssuedAt:
        consumedChildAuthorizationIssuedAt(fixture.context),
      humanAuthorizationTrustRoot:
        fixture.context.trustedRunContext.humanAuthorizationTrustRoot,
      intent: fixture.context.preCallIntent
    }),
    /INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION_REJECTED/u
  );
  const payload = integratedLiveDrillProviderDispatchAuthorizationPayload({
    childAuthorizationIssuedAt:
      consumedChildAuthorizationIssuedAt(fixture.context),
    intent: fixture.context.preCallIntent,
    issuedAt: consumedChildAuthorizationIssuedAt(fixture.context),
    expiresAt: new Date(fixture.testOnly.now + 5 * 60_000).toISOString()
  });
  for (const changedPayload of [
    {
      ...payload,
      authorityStatement: "Authorize a vaguely described provider read."
    },
    { ...payload, requiredToolsCallCount: 2 },
    {
      ...payload,
      issuedAt: new Date(
        Date.parse(fixture.context.preCallIntent.startedAt) - 1
      ).toISOString()
    },
    {
      ...payload,
      expiresAt: new Date(
        Date.parse(payload.issuedAt) + 15 * 60_000 + 1
      ).toISOString()
    }
  ]) {
    const resigned = signIntegratedLiveDrillEvidence(
      changedPayload,
      fixture.testOnly.human.privateKeyPkcs8DerBase64,
      fixture.testOnly.human.publicKey
    );
    assert.throws(
      () => validateIntegratedLiveDrillProviderDispatchAuthorization(resigned, {
        childAuthorizationIssuedAt:
          consumedChildAuthorizationIssuedAt(fixture.context),
        humanAuthorizationTrustRoot:
          fixture.context.trustedRunContext.humanAuthorizationTrustRoot,
        intent: fixture.context.preCallIntent
      }),
      /INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION_REJECTED/u
    );
  }
});

test("preparation defaults to a bounded lifetime and rejects extra or credential-bearing context", (t) => {
  const defaultFixture = createRecoveryContinuityFixture(t, {
    prefix: "prooftoact-b2-provider-default-preparation-",
    subjectBindingSha256: principalBindingHash(PRINCIPAL)
  });
  const defaultPreparation =
    prepareIntegratedLiveDrillProviderRecoveryAuthorization({
      context: defaultFixture.context
    });
  const issuedAt = Date.parse(defaultPreparation.signingPayload.issuedAt);
  const expiresAt = Date.parse(defaultPreparation.signingPayload.expiresAt);
  assert.equal(
    expiresAt,
    Math.min(
      Date.parse(defaultFixture.context.preCallIntent.expiresAt),
      issuedAt + 15 * 60_000
    )
  );
  assert.equal(
    defaultPreparation.dedicatedCredentialFieldAcceptedOrPersisted,
    false
  );
  assert.equal(defaultPreparation.humanPrivateKeyRequired, false);
  assert.equal(
    defaultPreparation.humanSignatureProducedOutsidePreparationApi,
    true
  );
  assert.equal(defaultPreparation.preparationContextStrictlyAllowlisted, true);

  const rejectedFixture = createRecoveryContinuityFixture(t, {
    prefix: "prooftoact-b2-provider-secret-rejection-",
    subjectBindingSha256: principalBindingHash(PRINCIPAL)
  });
  const mutations = [
    (context) => { context.humanPrivateKey = "synthetic-secret"; },
    (context) => { context.preCallInputs.arbitraryExtra = true; },
    (context) => { context.preCallInputs.MCP_API_KEY = "synthetic-secret"; },
    (context) => {
      context.preCallInputs.recoverySourceReceipt.metadata = {
        clientSecret: "synthetic-secret"
      };
    },
    (context) => {
      context.preCallInputs.recoverySourceReceipt.password =
        "synthetic-secret";
    },
    (context) => {
      context.preCallInputs.recoverySourceReceipt.resource_id =
        "-----BEGIN PRIVATE KEY-----synthetic";
    },
    (context) => {
      context.preCallInputs.recoverySourceReceipt.resource_id =
        "Bearer synthetic-secret";
    },
    (context) => {
      context.preCallInputs.recoveryBinding.bearerToken =
        "synthetic-secret";
    },
    (context) => {
      context.preCallInputs.recoveryAppendReceipt.commit.authority.credential =
        "synthetic-secret";
    },
    (context) => {
      context.preCallInputs.recoveryReplayReceipt.commit.privateKeyPem =
        "-----BEGIN PRIVATE KEY-----synthetic";
    },
    (context) => {
      context.preCallInputs.signedBundlePersistenceReceipt.pem =
        "-----BEGIN PRIVATE KEY-----synthetic";
    },
    (context) => {
      context.preCallInputs.consumedChildAuthorization.jwk = {
        kty: "oct",
        k: "synthetic-secret"
      };
    },
    (context) => {
      context.preCallInputs.consumedChildAuthorization.attestation
        .privateKey = "synthetic-secret";
    },
    (context) => {
      context.preCallInputs.consumedChildAuthorization.attestation.payload
        .metadata = { clientSecret: "synthetic-secret" };
    },
    (context) => {
      context.preCallInputs.consumedChildAuthorization.attestation.payload
        .claim.credential = "synthetic-secret";
    },
    (context) => {
      context.preCallInputs.consumedChildAuthorization.attestation.signature
        .privateKey = "synthetic-secret";
    },
    (context) => {
      context.preCallInputs.managedMcpReservation.password =
        "synthetic-secret";
    },
    (context) => {
      context.preCallInputs.controlLedgerReceipt.bearerToken =
        "synthetic-secret";
    },
    (context) => {
      context.preCallInputs.consumedManagedMcpLaunch.private_key =
        "synthetic-secret";
    }
  ];
  for (const mutate of mutations) {
    const context = structuredClone(rejectedFixture.context);
    mutate(context);
    assert.throws(
      () => prepareIntegratedLiveDrillProviderRecoveryAuthorization({
        context
      }),
      /INTEGRATED_LIVE_DRILL_PROVIDER_(?:CONTEXT|CREDENTIAL_MATERIAL)_REJECTED/u
    );
    assert.equal(
      fs.readdirSync(context.recoveryEvidenceRootPath).some(
        (name) => name.endsWith("-dispatch-preparation.json")
      ),
      false
    );
  }
  assert.equal(
    fs.readdirSync(rejectedFixture.context.recoveryEvidenceRootPath).some(
      (name) => name.endsWith("-dispatch-preparation.json")
    ),
    false
  );
});

test("invalid exact dispatch authorization causes zero provider fetches", async (t) => {
  const fixture = createRecoveryContinuityFixture(t, {
    prefix: "prooftoact-b2-provider-invalid-authority-",
    subjectBindingSha256: principalBindingHash(PRINCIPAL)
  });
  const preparation = prepareDispatch(fixture);
  const providerDispatchAuthorization = structuredClone(
    signPreparedDispatch(fixture, preparation)
  );
  providerDispatchAuthorization.payload.logicalMcpRequestSha256 =
    "0".repeat(64);
  const context = Object.freeze({
    ...fixture.context,
    providerDispatchAuthorization
  });
  const harness = providerHarness(fixture);

  await assert.rejects(
    () => runIntegratedLiveDrillProviderRecovery({
      authenticatedPrincipal: PRINCIPAL,
      broker: harness.broker,
      context
    }),
    /INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION_REJECTED/u
  );
  assert.equal(harness.calls.length, 0);
  assert.equal(
    fs.existsSync(path.join(
      context.ledgerRootPath,
      continuityTest.unknownFileName(
        context.authorization.payload.authorizationId
      )
    )),
    false
  );
});

test("missing, substituted, or expired dispatch authority never fetches", async (t) => {
  const fixture = createRecoveryContinuityFixture(t, {
    prefix: "prooftoact-b2-provider-authority-boundary-",
    subjectBindingSha256: principalBindingHash(PRINCIPAL)
  });
  const preparation = prepareDispatch(fixture);
  const harness = providerHarness(fixture);
  const run = (providerDispatchAuthorization) =>
    runIntegratedLiveDrillProviderRecovery({
      authenticatedPrincipal: PRINCIPAL,
      broker: harness.broker,
      context: Object.freeze({
        ...fixture.context,
        ...(providerDispatchAuthorization === undefined
          ? {}
          : { providerDispatchAuthorization })
      })
    });

  await assert.rejects(
    () => run(undefined),
    /INTEGRATED_LIVE_DRILL_PROVIDER_RECOVERY_INPUT_REJECTED/u
  );
  const substitutedPayload = Object.freeze({
    ...preparation.signingPayload,
    logicalMcpRequestSha256: "0".repeat(64)
  });
  const substituted = signIntegratedLiveDrillEvidence(
    substitutedPayload,
    fixture.testOnly.human.privateKeyPkcs8DerBase64,
    fixture.testOnly.human.publicKey
  );
  await assert.rejects(
    () => run(substituted),
    /INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION_REJECTED/u
  );
  assert.equal(harness.calls.length, 0);

  const expiredFixture = createRecoveryContinuityFixture(t, {
    prefix: "prooftoact-b2-provider-expired-authority-",
    subjectBindingSha256: principalBindingHash(PRINCIPAL),
    auditStartOffsetMs: -2_000
  });
  const expiredPreparation = prepareDispatch(
    expiredFixture,
    expiredFixture.context,
    {
      issuedAt: consumedChildAuthorizationIssuedAt(expiredFixture.context),
      expiresAt: new Date(
        Date.parse(consumedChildAuthorizationIssuedAt(expiredFixture.context)) +
          1
      ).toISOString()
    }
  );
  const expiredHarness = providerHarness(expiredFixture);
  const expiredContext = Object.freeze({
    ...expiredFixture.context,
    providerDispatchAuthorization: signPreparedDispatch(
      expiredFixture,
      expiredPreparation
    )
  });
  await assert.rejects(
    () => providerTest.runProviderRecoveryWithTrustedClock(
      {
        authenticatedPrincipal: PRINCIPAL,
        broker: expiredHarness.broker,
        context: expiredContext
      },
      () => Date.parse(expiredPreparation.signingPayload.expiresAt)
    ),
    /INTEGRATED_LIVE_DRILL_PROVIDER_EXTERNAL_ACTION_AUTHORIZATION_REQUIRED/u
  );
  assert.equal(expiredHarness.calls.length, 0);
});

test("prepared resume rejects changed cluster, query, intent, ledger, or launch", async (t) => {
  const fixture = createRecoveryContinuityFixture(t, {
    prefix: "prooftoact-b2-provider-preparation-substitution-",
    subjectBindingSha256: principalBindingHash(PRINCIPAL)
  });
  const preparation = prepareDispatch(fixture);
  const providerDispatchAuthorization = signPreparedDispatch(
    fixture,
    preparation
  );
  const harness = providerHarness(fixture);
  const variants = [
    ["cluster", (context) => {
      context.preCallIntent.recoveryClusterId =
        "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
    }],
    ["query", (context) => {
      context.preCallIntent.renderedQuerySha256 = "0".repeat(64);
    }],
    ["intent", (context) => {
      context.preCallIntent.intentSha256 = "0".repeat(64);
    }],
    ["ledger", (context) => {
      context.controlLedgerReceipt.receiptSha256 = "0".repeat(64);
    }],
    ["launch", (context) => {
      context.preCallInputs.consumedManagedMcpLaunch.childLaunchSha256 =
        "0".repeat(64);
    }]
  ];
  for (const [name, mutate] of variants) {
    const context = structuredClone(fixture.context);
    mutate(context);
    context.providerDispatchAuthorization = providerDispatchAuthorization;
    await assert.rejects(
      () => runIntegratedLiveDrillProviderRecovery({
        authenticatedPrincipal: PRINCIPAL,
        broker: harness.broker,
        context
      }),
      /INTEGRATED_LIVE_DRILL_(?:CHILD_LAUNCH_RECEIPT|CONTROL_LEDGER_RECEIPT|PROVIDER_CONTEXT|PROVIDER_DISPATCH_PREPARATION|RECOVERY_CONTINUITY_BINDING)_REJECTED/u,
      name
    );
  }
  assert.equal(harness.calls.length, 0);
});

test("dispatch authorization is resampled immediately before selectQuery", async (t) => {
  const fixture = createRecoveryContinuityFixture(t, {
    prefix: "prooftoact-b2-dispatch-expiry-",
    subjectBindingSha256: principalBindingHash(PRINCIPAL)
  });
  const expiresAtMs = fixture.testOnly.now + 1_000;
  const preparation = prepareDispatch(fixture, fixture.context, {
    expiresAt: new Date(expiresAtMs).toISOString()
  });
  const providerDispatchAuthorization = signPreparedDispatch(
    fixture,
    preparation
  );
  const context = Object.freeze({
    ...fixture.context,
    providerDispatchAuthorization
  });
  validateIntegratedLiveDrillProviderDispatchAuthorization(
    providerDispatchAuthorization,
    {
      childAuthorizationIssuedAt:
        consumedChildAuthorizationIssuedAt(context),
      humanAuthorizationTrustRoot:
        context.trustedRunContext.humanAuthorizationTrustRoot,
      intent: context.preCallIntent,
      now: expiresAtMs - 1
    }
  );
  const harness = providerHarness(fixture);
  const prepared = await harness.broker.prepareRecovery(
    { authenticatedPrincipal: PRINCIPAL },
    {
      auditIdentity: {
        interactionId: context.preCallIntent.interactionId,
        preReadEventId: context.preCallIntent.preReadAuditEventId,
        terminalEventId: context.preCallIntent.terminalAuditEventId,
        startedAt: context.preCallIntent.startedAt
      }
    }
  );
  const guard = providerTest.providerDispatchGuard(
    context,
    context.preCallIntent,
    () => expiresAtMs
  );
  runIntegratedLiveDrillRecoveryContinuityW1(context);
  const w2 = await runIntegratedLiveDrillRecoveryContinuityW2(
    context,
    {
      mcpCall: async () => {
        try {
          return await harness.broker.executePreparedRecovery(
            prepared.prepared,
            { beforeProviderDispatch: guard }
          );
        } finally {
          await harness.mcpClient.close();
        }
      }
    }
  );
  assert.equal(w2.status, "UNKNOWN_DO_NOT_ACT");
  assert.equal(w2.retryPermitted, false);
  assert.deepEqual(
    harness.calls.map(({ payload, method }) => payload?.method ?? method),
    []
  );
  assert.equal(
    harness.calls.filter(({ payload }) => payload?.method === "tools/call").length,
    0
  );
  assert.equal(
    fs.existsSync(path.join(
      context.ledgerRootPath,
      continuityTest.unknownFileName(
        context.authorization.payload.authorizationId
      )
    )),
    true
  );
  let retryCalls = 0;
  const resumed = await runIntegratedLiveDrillRecoveryContinuityW2(
    context,
    {
      mcpCall: async () => {
        retryCalls += 1;
        throw new Error("permanent UNKNOWN must not retry");
      }
    }
  );
  assert.equal(resumed.status, "UNKNOWN_DO_NOT_ACT");
  assert.equal(resumed.retryPermitted, false);
  assert.equal(retryCalls, 0);
});

test("pre-W2 expiry is durably burned across clock rollback and repeated invocation", async (t) => {
  const fixture = createRecoveryContinuityFixture(t, {
    prefix: "prooftoact-b2-session-resolution-expiry-",
    subjectBindingSha256: principalBindingHash(PRINCIPAL)
  });
  const preparation = prepareDispatch(fixture);
  const context = Object.freeze({
    ...fixture.context,
    providerDispatchAuthorization: signPreparedDispatch(fixture, preparation)
  });
  let clockNow = Date.parse(consumedChildAuthorizationIssuedAt(context));
  let expireOnce = true;
  const harness = providerHarness(fixture, {
    async duringSessionResolve() {
      if (expireOnce) {
        expireOnce = false;
        clockNow = Date.parse(preparation.signingPayload.expiresAt);
      }
    }
  });
  const args = Object.freeze({
    authenticatedPrincipal: PRINCIPAL,
    broker: harness.broker,
    context
  });
  await assert.rejects(
    () => providerTest.runProviderRecoveryWithTrustedClock(
      args,
      () => clockNow
    ),
    /INTEGRATED_LIVE_DRILL_PROVIDER_EXTERNAL_ACTION_AUTHORIZATION_REQUIRED/u
  );
  assert.equal(harness.calls.length, 0);
  assert.equal(harness.auditAppendAttempts.length, 0);
  assert.equal(harness.auditResolveAttempts.length, 0);
  const burnPath = path.join(
    context.recoveryEvidenceRootPath,
    `${context.preCallIntent.authorizationId}` +
      ".provider-recovery-authority-expiry-burn.json"
  );
  assert.equal(fs.existsSync(burnPath), true);
  assert.equal(fs.statSync(burnPath).mode & 0o777, 0o600);
  const burn = JSON.parse(fs.readFileSync(burnPath, "utf8"));
  assert.equal(
    burn.schemaVersion,
    INTEGRATED_LIVE_DRILL_PROVIDER_EXPIRY_BURN_SCHEMA
  );
  assert.equal(burn.status, "BURNED_EXPIRED");
  assert.equal(burn.clockRollbackCanReactivateAfterDurableBurn, false);
  assert.equal(burn.failedBurnPersistenceRequiresRunAbandonment, true);
  assert.equal(burn.processRestartSafetyAfterFailedPersistenceProven, false);
  assert.equal(burn.processStickyBurnPrecedesPersistenceAttempt, true);
  assert.equal(burn.retryPermitted, false);

  clockNow = Date.parse(consumedChildAuthorizationIssuedAt(context));
  for (let attempt = 0; attempt < 2; attempt += 1) {
    await assert.rejects(
      () => providerTest.runProviderRecoveryWithTrustedClock(
        args,
        () => clockNow
      ),
      /INTEGRATED_LIVE_DRILL_PROVIDER_EXTERNAL_ACTION_AUTHORIZATION_REQUIRED/u
    );
    assert.equal(harness.calls.length, 0);
    assert.equal(harness.auditAppendAttempts.length, 0);
    assert.equal(harness.auditResolveAttempts.length, 0);
  }
});

test("signed child issuedAt gates dispatch before and at the exact boundary", (t) => {
  const fixture = createRecoveryContinuityFixture(t, {
    prefix: "prooftoact-b2-pre-issue-clock-",
    subjectBindingSha256: principalBindingHash(PRINCIPAL)
  });
  const preparation = prepareDispatch(fixture);
  const context = Object.freeze({
    ...fixture.context,
    providerDispatchAuthorization: signPreparedDispatch(fixture, preparation)
  });
  const childIssuedAt = Date.parse(
    consumedChildAuthorizationIssuedAt(context)
  );
  assert.equal(
    Date.parse(preparation.signingPayload.childAuthorizationIssuedAt),
    childIssuedAt
  );
  assert.equal(Date.parse(preparation.signingPayload.issuedAt), childIssuedAt);
  assert.throws(
    () => prepareIntegratedLiveDrillProviderRecoveryAuthorization({
      context: fixture.context,
      issuedAt: new Date(childIssuedAt - 1).toISOString(),
      expiresAt: preparation.signingPayload.expiresAt
    }),
    /INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION_REJECTED/u
  );
  let clockNow = childIssuedAt - 1;
  const guard = providerTest.providerDispatchGuard(
    context,
    context.preCallIntent,
    () => clockNow
  );
  assert.throws(
    () => guard("PRE_ISSUE_TEST"),
    /INTEGRATED_LIVE_DRILL_PROVIDER_EXTERNAL_ACTION_AUTHORIZATION_REQUIRED/u
  );
  const burnPath = path.join(
    context.recoveryEvidenceRootPath,
    `${context.preCallIntent.authorizationId}` +
      ".provider-recovery-authority-expiry-burn.json"
  );
  assert.equal(fs.existsSync(burnPath), false);

  clockNow = childIssuedAt;
  assert.equal(
    guard("CURRENT_TEST").attestationSha256,
    integratedLiveDrillCanonicalSha256(context.providerDispatchAuthorization)
  );
  assert.equal(fs.existsSync(burnPath), false);
});

test("failed expiry-burn persistence remains process-sticky after clock rollback", async (t) => {
  const fixture = createRecoveryContinuityFixture(t, {
    prefix: "prooftoact-b2-expiry-burn-enospc-",
    subjectBindingSha256: principalBindingHash(PRINCIPAL)
  });
  const preparation = prepareDispatch(fixture);
  const context = Object.freeze({
    ...fixture.context,
    providerDispatchAuthorization: signPreparedDispatch(fixture, preparation)
  });
  const harness = providerHarness(fixture);
  const args = Object.freeze({
    authenticatedPrincipal: PRINCIPAL,
    broker: harness.broker,
    context
  });
  const burnPath = path.join(
    context.recoveryEvidenceRootPath,
    `${context.preCallIntent.authorizationId}` +
      ".provider-recovery-authority-expiry-burn.json"
  );
  const originalOpenSync = fs.openSync.bind(fs);
  let injectedFailures = 0;
  t.mock.method(fs, "openSync", (...openArgs) => {
    const [candidate, flags] = openArgs;
    if (
      injectedFailures === 0 &&
      candidate === burnPath &&
      (flags & fs.constants.O_CREAT) !== 0
    ) {
      injectedFailures += 1;
      const cause = new Error("synthetic expiry-burn ENOSPC");
      cause.code = "ENOSPC";
      throw cause;
    }
    return originalOpenSync(...openArgs);
  });

  let clockNow = Date.parse(preparation.signingPayload.expiresAt);
  await assert.rejects(
    () => providerTest.runProviderRecoveryWithTrustedClock(
      args,
      () => clockNow
    ),
    /INTEGRATED_LIVE_DRILL_PROVIDER_EXTERNAL_ACTION_AUTHORIZATION_REQUIRED/u
  );
  assert.equal(injectedFailures, 1);
  assert.equal(fs.existsSync(burnPath), false);
  assert.equal(harness.calls.length, 0);
  assert.equal(harness.auditAppendAttempts.length, 0);
  assert.equal(harness.auditResolveAttempts.length, 0);

  clockNow = Date.parse(consumedChildAuthorizationIssuedAt(context));
  await assert.rejects(
    () => providerTest.runProviderRecoveryWithTrustedClock(
      args,
      () => clockNow
    ),
    /INTEGRATED_LIVE_DRILL_PROVIDER_EXTERNAL_ACTION_AUTHORIZATION_REQUIRED/u
  );
  assert.equal(fs.existsSync(burnPath), false);
  assert.equal(harness.calls.length, 0);
  assert.equal(harness.auditAppendAttempts.length, 0);
  assert.equal(harness.auditResolveAttempts.length, 0);
});

test("expiry inside audit resolver before actual dispatch stops with zero resolve or MCP action", async (t) => {
  const fixture = createRecoveryContinuityFixture(t, {
    prefix: "prooftoact-b2-audit-resolve-dispatch-expiry-",
    subjectBindingSha256: principalBindingHash(PRINCIPAL)
  });
  const preparation = prepareDispatch(fixture);
  const context = Object.freeze({
    ...fixture.context,
    providerDispatchAuthorization: signPreparedDispatch(fixture, preparation)
  });
  let clockNow = Date.parse(consumedChildAuthorizationIssuedAt(context));
  let expireOnce = true;
  const harness = providerHarness(fixture, {
    async beforeAuditResolveDispatch({ eventId }) {
      if (
        expireOnce &&
        eventId === context.preCallIntent.preReadAuditEventId
      ) {
        expireOnce = false;
        clockNow = Date.parse(preparation.signingPayload.expiresAt);
      }
    }
  });
  const args = Object.freeze({
    authenticatedPrincipal: PRINCIPAL,
    broker: harness.broker,
    context
  });
  await assert.rejects(
    () => providerTest.runProviderRecoveryWithTrustedClock(
      args,
      () => clockNow
    ),
    /INTEGRATED_LIVE_DRILL_PROVIDER_EXTERNAL_ACTION_AUTHORIZATION_REQUIRED/u
  );
  assert.equal(harness.auditAppendAttempts.length, 1);
  assert.equal(harness.auditResolveAttempts.length, 0);
  assert.equal(harness.calls.length, 0);
  assert.equal(
    harness.auditRows.has(context.preCallIntent.preReadAuditEventId),
    true
  );

  await assert.rejects(
    () => providerTest.runProviderRecoveryWithTrustedClock(
      args,
      () => clockNow
    ),
    /INTEGRATED_LIVE_DRILL_PROVIDER_EXTERNAL_ACTION_AUTHORIZATION_REQUIRED/u
  );
  assert.equal(harness.auditAppendAttempts.length, 1);
  assert.equal(harness.auditResolveAttempts.length, 0);
  assert.equal(harness.calls.length, 0);
});

test("expiry during initialize response burns W2 without notification, tool call, or retry", async (t) => {
  const fixture = createRecoveryContinuityFixture(t, {
    prefix: "prooftoact-b2-initialize-expiry-",
    subjectBindingSha256: principalBindingHash(PRINCIPAL)
  });
  const preparation = prepareDispatch(fixture);
  const context = Object.freeze({
    ...fixture.context,
    providerDispatchAuthorization: signPreparedDispatch(fixture, preparation)
  });
  let clockNow = Date.parse(consumedChildAuthorizationIssuedAt(context));
  let expireOnce = true;
  const harness = providerHarness(fixture, {
    async afterFetchRecorded({ action }) {
      if (expireOnce && action === "initialize") {
        expireOnce = false;
        clockNow = Date.parse(preparation.signingPayload.expiresAt);
      }
    }
  });
  const args = Object.freeze({
    authenticatedPrincipal: PRINCIPAL,
    broker: harness.broker,
    context
  });
  await assert.rejects(
    () => providerTest.runProviderRecoveryWithTrustedClock(
      args,
      () => clockNow
    ),
    /INTEGRATED_LIVE_DRILL_PROVIDER_RECOVERY_UNKNOWN_DO_NOT_ACT/u
  );
  assert.deepEqual(
    harness.calls.map(({ payload, method }) => payload?.method ?? method),
    ["initialize", "DELETE"]
  );
  assert.equal(
    harness.auditRows.has(context.preCallIntent.terminalAuditEventId),
    false
  );

  const callCount = harness.calls.length;
  await assert.rejects(
    () => providerTest.runProviderRecoveryWithTrustedClock(
      args,
      () => clockNow
    ),
    /INTEGRATED_LIVE_DRILL_PROVIDER_EXTERNAL_ACTION_AUTHORIZATION_REQUIRED/u
  );
  assert.equal(harness.calls.length, callCount);
});

test("post-W2 expiry reconciles locally and remains burned after clock rollback", async (t) => {
  const fixture = createRecoveryContinuityFixture(t, {
    prefix: "prooftoact-b2-tools-result-expiry-",
    subjectBindingSha256: principalBindingHash(PRINCIPAL)
  });
  const preparation = prepareDispatch(fixture);
  const context = Object.freeze({
    ...fixture.context,
    providerDispatchAuthorization: signPreparedDispatch(fixture, preparation)
  });
  let clockNow = Date.parse(consumedChildAuthorizationIssuedAt(context));
  let expireOnce = true;
  const harness = providerHarness(fixture, {
    async afterFetchRecorded({ action }) {
      if (expireOnce && action === "tools/call") {
        expireOnce = false;
        clockNow = Date.parse(preparation.signingPayload.expiresAt);
      }
    }
  });
  const args = Object.freeze({
    authenticatedPrincipal: PRINCIPAL,
    broker: harness.broker,
    context
  });
  await assert.rejects(
    () => providerTest.runProviderRecoveryWithTrustedClock(
      args,
      () => clockNow
    ),
    /INTEGRATED_LIVE_DRILL_PROVIDER_POST_EXPIRY_AUDIT_AUTHORIZATION_REQUIRED/u
  );
  assert.deepEqual(
    harness.calls.map(({ payload, method }) => payload?.method ?? method),
    ["initialize", "notifications/initialized", "tools/call", "DELETE"]
  );
  assert.equal(
    harness.auditRows.has(context.preCallIntent.terminalAuditEventId),
    false
  );

  const callCount = harness.calls.length;
  const appendCount = harness.auditAppendAttempts.length;
  const resolveCount = harness.auditResolveAttempts.length;
  const burnPath = path.join(
    context.recoveryEvidenceRootPath,
    `${context.preCallIntent.authorizationId}` +
      ".provider-recovery-authority-expiry-burn.json"
  );
  assert.equal(fs.existsSync(burnPath), true);

  clockNow = Date.parse(consumedChildAuthorizationIssuedAt(context));
  for (let attempt = 0; attempt < 2; attempt += 1) {
    await assert.rejects(
      () => providerTest.runProviderRecoveryWithTrustedClock(
        args,
        () => clockNow
      ),
      /INTEGRATED_LIVE_DRILL_PROVIDER_POST_EXPIRY_AUDIT_AUTHORIZATION_REQUIRED/u
    );
    assert.equal(harness.calls.length, callCount);
    assert.equal(harness.auditAppendAttempts.length, appendCount);
    assert.equal(harness.auditResolveAttempts.length, resolveCount);
  }
});

test("expiry after audit resolution preserves the exact event and remains non-accepting", async (t) => {
  for (const phase of ["pre-read", "terminal"]) {
    const fixture = createRecoveryContinuityFixture(t, {
      prefix: `prooftoact-b2-${phase}-resolve-expiry-`,
      subjectBindingSha256: principalBindingHash(PRINCIPAL)
    });
    const preparation = prepareDispatch(fixture);
    const context = Object.freeze({
      ...fixture.context,
      providerDispatchAuthorization: signPreparedDispatch(
        fixture,
        preparation
      )
    });
    const targetEventId = phase === "pre-read"
      ? context.preCallIntent.preReadAuditEventId
      : context.preCallIntent.terminalAuditEventId;
    let clockNow = Date.parse(consumedChildAuthorizationIssuedAt(context));
    let expireOnce = true;
    const harness = providerHarness(fixture, {
      async afterAuditResolve({ eventId }) {
        if (expireOnce && eventId === targetEventId) {
          expireOnce = false;
          clockNow = Date.parse(preparation.signingPayload.expiresAt);
        }
      }
    });
    const args = Object.freeze({
      authenticatedPrincipal: PRINCIPAL,
      broker: harness.broker,
      context
    });
    await assert.rejects(
      () => providerTest.runProviderRecoveryWithTrustedClock(
        args,
        () => clockNow
      ),
      phase === "pre-read"
        ? /INTEGRATED_LIVE_DRILL_PROVIDER_EXTERNAL_ACTION_AUTHORIZATION_REQUIRED/u
        : /INTEGRATED_LIVE_DRILL_PROVIDER_POST_EXPIRY_AUDIT_AUTHORIZATION_REQUIRED/u
    );
    const callsAfterExpiry = harness.calls.length;
    const appendCount = harness.auditAppendAttempts.length;
    const resolveCount = harness.auditResolveAttempts.length;
    assert.equal(harness.auditRows.has(targetEventId), true);

    await assert.rejects(
      () => providerTest.runProviderRecoveryWithTrustedClock(
        args,
        () => clockNow
      ),
      phase === "pre-read"
        ? /INTEGRATED_LIVE_DRILL_PROVIDER_EXTERNAL_ACTION_AUTHORIZATION_REQUIRED/u
        : /INTEGRATED_LIVE_DRILL_PROVIDER_POST_EXPIRY_AUDIT_AUTHORIZATION_REQUIRED/u
    );
    assert.equal(harness.calls.length, callsAfterExpiry);
    assert.equal(harness.auditAppendAttempts.length, appendCount);
    assert.equal(harness.auditResolveAttempts.length, resolveCount);
    const attempts = harness.auditAppendAttempts.filter(
      ({ event }) => event.eventId === targetEventId
    );
    assert.equal(attempts.length, 1);
  }
});

test("a durable private result reconciles the W2 journal without redispatch", async (t) => {
  const fixture = createRecoveryContinuityFixture(t, {
    prefix: "prooftoact-b2-result-reconcile-"
  });
  runIntegratedLiveDrillRecoveryContinuityW1(fixture.context);
  let calls = 0;
  const durable = Object.freeze({
    logicalMcpRequestSha256: fixture.logicalMcpRequestSha256,
    mcpResultSha256: "c".repeat(64),
    sessionCloseSha256: "d".repeat(64),
    sessionClosed: true
  });
  await assert.rejects(
    () => continuityTest.runW2WithPostCallInterruption(
      fixture.context,
      async () => {
        calls += 1;
        return durable;
      }
    ),
    /INTEGRATED_LIVE_DRILL_SYNTHETIC_CRASH_PROVIDER_RESULT_DURABLE_BEFORE_JOURNAL/u
  );
  const resumed = await continuityTest.runW2WithTrustedClock(
    fixture.context,
    {
      mcpCall: async () => {
        calls += 1;
        throw new Error("provider must not be called during reconciliation");
      },
      reconcileDurableResult: async () => durable
    },
    fixture.context.authorization.expiresAt + 1
  );
  assert.equal(resumed.reconciledFromDurableResult, true);
  assert.equal(resumed.retryPermitted, undefined);
  assert.equal(calls, 1);
});

test("post-expiry wrapper reconciles W2 locally then stops before any audit-provider action", async (t) => {
  const fixture = createRecoveryContinuityFixture(t, {
    prefix: "prooftoact-b2-provider-expired-wrapper-resume-",
    expiresAfterMs: 1_500,
    subjectBindingSha256: principalBindingHash(PRINCIPAL)
  });
  const harness = providerHarness(fixture);
  const preparation = prepareDispatch(fixture, fixture.context, {
    expiresAt: fixture.context.preCallIntent.expiresAt
  });
  const context = Object.freeze({
    ...fixture.context,
    providerDispatchAuthorization: signPreparedDispatch(fixture, preparation)
  });
  const args = Object.freeze({
    authenticatedPrincipal: PRINCIPAL,
    broker: harness.broker,
    context
  });
  await assert.rejects(
    () => providerTest.runProviderRecoveryWithInterruption(
      args,
      "AFTER_PROVIDER_EVIDENCE_DURABLE"
    ),
    /INTEGRATED_LIVE_DRILL_PROVIDER_SYNTHETIC_CRASH_AFTER_PROVIDER_EVIDENCE_DURABLE/u
  );
  const initialFetchCount = harness.calls.length;
  assert.equal(initialFetchCount, 4);
  assert.equal(
    harness.auditRows.has(context.preCallIntent.terminalAuditEventId),
    false
  );

  const journalPrefix = continuityTest.journalFilePrefix(
    context.preCallIntent.authorizationId
  );
  for (const name of fs.readdirSync(context.ledgerRootPath)) {
    if (!name.startsWith(journalPrefix)) continue;
    const sequence = Number(name.slice(
      journalPrefix.length,
      journalPrefix.length + 2
    ));
    if (sequence >= 8) {
      fs.unlinkSync(path.join(context.ledgerRootPath, name));
    }
  }
  const auditAppendCount = harness.auditAppendAttempts.length;
  const auditResolveCount = harness.auditResolveAttempts.length;
  const waitMs = Math.max(
    0,
    Date.parse(context.preCallIntent.expiresAt) - Date.now() + 30
  );
  await new Promise((resolve) => setTimeout(resolve, waitMs));
  assert.ok(Date.now() > context.authorization.expiresAt);
  assert.ok(Date.now() > Date.parse(
    context.preCallIntent.childAuthorizationExpiresAt
  ));

  await assert.rejects(
    () => runIntegratedLiveDrillProviderRecovery(args),
    /INTEGRATED_LIVE_DRILL_PROVIDER_POST_EXPIRY_AUDIT_AUTHORIZATION_REQUIRED/u
  );
  assert.equal(harness.calls.length, initialFetchCount);
  assert.equal(harness.auditAppendAttempts.length, auditAppendCount);
  assert.equal(harness.auditResolveAttempts.length, auditResolveCount);
  assert.equal(
    harness.auditRows.has(context.preCallIntent.terminalAuditEventId),
    false
  );
  const journalSequences = fs.readdirSync(context.ledgerRootPath)
    .filter((name) => name.startsWith(journalPrefix))
    .map((name) => Number(name.slice(
      journalPrefix.length,
      journalPrefix.length + 2
    )));
  assert.ok(journalSequences.includes(8));
  assert.ok(journalSequences.includes(9));
  assert.equal(
    fs.existsSync(providerTest.artifactPath(
      { rootPath: context.recoveryEvidenceRootPath },
      context.preCallIntent.authorizationId,
      "terminal"
    )),
    false
  );
});

test("provider artifact read rejects chmod and hardlink mutation after descriptor read", async (t) => {
  for (const mode of ["chmod", "hardlink"]) {
    await t.test(mode, (t) => {
      const fixture = createRecoveryContinuityFixture(t, {
        prefix: `prooftoact-b2-provider-read-${mode}-`
      });
      prepareDispatch(fixture);
      const authorizationId = fixture.context.preCallIntent.authorizationId;
      const artifact = path.join(
        fixture.context.recoveryEvidenceRootPath,
        `${authorizationId}.provider-recovery-dispatch-preparation.json`
      );
      const sibling = `${artifact}.hardlink`;
      const wasInjected = injectMutationAfterTargetRead(t, artifact, () => {
        if (mode === "chmod") {
          fs.chmodSync(artifact, 0o644);
        } else {
          fs.linkSync(artifact, sibling);
        }
      });
      try {
        assert.throws(
          () => prepareDispatch(fixture),
          /INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_AMBIGUOUS/u
        );
        assert.equal(wasInjected(), true);
      } finally {
        if (mode === "chmod" && fs.existsSync(artifact)) {
          fs.chmodSync(artifact, 0o600);
        }
        if (fs.existsSync(sibling)) {
          fs.unlinkSync(sibling);
        }
      }
    });
  }
});

test("continuity journal read rejects chmod and hardlink mutation after descriptor read", async (t) => {
  for (const mode of ["chmod", "hardlink"]) {
    await t.test(mode, (t) => {
      const fixture = createRecoveryContinuityFixture(t, {
        prefix: `prooftoact-b2-continuity-read-${mode}-`
      });
      runIntegratedLiveDrillRecoveryContinuityW1(fixture.context);
      const intent = path.join(
        fixture.context.ledgerRootPath,
        continuityTest.intentFileName(
          fixture.context.preCallIntent.authorizationId
        )
      );
      const sibling = `${intent}.hardlink`;
      const wasInjected = injectMutationAfterTargetRead(t, intent, () => {
        if (mode === "chmod") {
          fs.chmodSync(intent, 0o644);
        } else {
          fs.linkSync(intent, sibling);
        }
      });
      try {
        assert.throws(
          () => runIntegratedLiveDrillRecoveryContinuityW1(fixture.context),
          /INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_AMBIGUOUS/u
        );
        assert.equal(wasInjected(), true);
      } finally {
        if (mode === "chmod" && fs.existsSync(intent)) {
          fs.chmodSync(intent, 0o600);
        }
        if (fs.existsSync(sibling)) {
          fs.unlinkSync(sibling);
        }
      }
    });
  }
});
