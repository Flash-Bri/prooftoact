import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

import { canonicalJson } from "../src/cloud/canonical-json.js";

import {
  integratedLiveDrillCanonicalSha256,
  signIntegratedLiveDrillEvidence
} from "../src/cloud/integrated-live-drill-authorization.js";
import {
  __test as providerTestRaw,
  INTEGRATED_LIVE_DRILL_PROVIDER_EXPIRY_BURN_SCHEMA,
  integratedLiveDrillProviderDispatchAuthorizationPayload,
  prepareIntegratedLiveDrillProviderRecoveryAuthorization,
  runIntegratedLiveDrillProviderRecovery as
    runIntegratedLiveDrillProviderRecoveryRaw,
  validateIntegratedLiveDrillManagedMcpSemanticRequestEvidence,
  validateIntegratedLiveDrillManagedMcpTransportEvidence,
  validateIntegratedLiveDrillProviderDispatchAuthorization
} from "../src/cloud/integrated-live-drill-provider-recovery.js";
import {
  assertIntegratedLiveDrillProviderFinalizerEnvironment,
  finalizeIntegratedLiveDrillProviderRecovery,
  INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_INPUT_SCHEMA,
  integratedLiveDrillProviderFinalizerEnvironment,
  readIntegratedLiveDrillProviderFinalizationInput,
  validateIntegratedLiveDrillProviderFinalizationInput,
  validateIntegratedLiveDrillProviderRecoveryHandoff
} from "../src/cloud/integrated-live-drill-provider-finalization.js";
import {
  INTEGRATED_LIVE_DRILL_PRIVATE_ROOT_DESCRIPTOR_ENVIRONMENT,
  verifyIntegratedLiveDrillProviderEvidenceBundle
} from "../src/cloud/integrated-live-drill-provider-evidence.js";
import {
  __test as workerTest,
  assertIntegratedLiveDrillProviderWorkerEnvironment,
  INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_SCHEMA,
  integratedLiveDrillProviderWorkerEnvironment,
  readIntegratedLiveDrillProviderWorkerInput,
  validateIntegratedLiveDrillProviderWorkerInput
} from "../src/cloud/integrated-live-drill-provider-worker.js";
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
import {
  createRecoveryContinuityFixture
} from
  "./helpers/integrated-live-drill-recovery-continuity-fixture.js";

const PRINCIPAL = "principal://synthetic-provider-continuity";

function syntheticExecutionGrant(context, overrides = {}) {
  const body = Object.freeze({
    authorizationId: context.preCallIntent.authorizationId,
    controlBindingSha256: "a".repeat(64),
    executionCapabilitySha256: "b".repeat(64),
    grantId: "11111111-1111-5111-8111-111111111111",
    operationNonceSha256: "c".repeat(64),
    requestSha256: "d".repeat(64),
    schemaVersion: "tideproof.integrated-live-drill-execution-grant.v1",
    state: "EXECUTING",
    workerSpecSha256: "e".repeat(64),
    ...overrides
  });
  return Object.freeze({
    ...body,
    receiptSha256: integratedLiveDrillCanonicalSha256(body)
  });
}

function recoveryExecutionGrant(context, overrides = {}) {
  const full = syntheticExecutionGrant(context, overrides);
  return Object.freeze({
    executionCapabilitySha256: full.executionCapabilitySha256,
    grantId: full.grantId,
    operationNonceSha256: full.operationNonceSha256,
    workerSpecSha256: full.workerSpecSha256
  });
}

function withRecoveryExecutionGrant(args) {
  return Object.freeze({
    ...args,
    executionGrant: args.executionGrant ??
      recoveryExecutionGrant(args.context)
  });
}

function runIntegratedLiveDrillProviderRecovery(args) {
  return runIntegratedLiveDrillProviderRecoveryRaw(
    withRecoveryExecutionGrant(args)
  );
}

const providerTest = Object.freeze({
  ...providerTestRaw,
  runProviderRecoveryWithInterruption(args, ...rest) {
    return providerTestRaw.runProviderRecoveryWithInterruption(
      withRecoveryExecutionGrant(args),
      ...rest
    );
  },
  runProviderRecoveryWithInterruptionAndTrustedClock(args, ...rest) {
    return providerTestRaw.runProviderRecoveryWithInterruptionAndTrustedClock(
      withRecoveryExecutionGrant(args),
      ...rest
    );
  },
  runProviderRecoveryWithTrustedClock(args, ...rest) {
    return providerTestRaw.runProviderRecoveryWithTrustedClock(
      withRecoveryExecutionGrant(args),
      ...rest
    );
  }
});

test("provider worker input and environment contain no provider or database capability", async (t) => {
  const fixture = createRecoveryContinuityFixture(t, {
    prefix: "prooftoact-b2-worker-input-",
    subjectBindingSha256: principalBindingHash(PRINCIPAL)
  });
  const preparation = prepareDispatch(fixture);
  const context = Object.freeze({
    ...fixture.context,
    providerDispatchAuthorization: signPreparedDispatch(fixture, preparation)
  });
  const executionGrant = syntheticExecutionGrant(context);
  const input = Object.freeze({
    authenticatedPrincipal: PRINCIPAL,
    context,
    executionGrant,
    schemaVersion: INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_SCHEMA
  });
  const validatedWorkerInput =
    validateIntegratedLiveDrillProviderWorkerInput(input);
  assert.equal(validatedWorkerInput.authenticatedPrincipal, PRINCIPAL);
  assert.notEqual(validatedWorkerInput.context, context);
  assert.equal(Object.isFrozen(validatedWorkerInput.context), true);
  assert.equal(
    canonicalJson(validatedWorkerInput.context),
    canonicalJson(context)
  );
  assert.deepEqual(validatedWorkerInput.executionGrant, executionGrant);
  const inputPath = path.join(
    context.recoveryEvidenceRootPath,
    "provider-worker-input.json"
  );
  fs.writeFileSync(inputPath, `${canonicalJson(input)}\n`, { mode: 0o600 });
  assert.equal(
    readIntegratedLiveDrillProviderWorkerInput({
      forbiddenRootPath: context.forbiddenRootPath,
      inputPath,
      rootPath: context.recoveryEvidenceRootPath
    }).context.preCallIntent.intentSha256,
    context.preCallIntent.intentSha256
  );
  const credentialsDirectory = path.join(
    context.recoveryEvidenceRootPath,
    "synthetic-systemd-credentials"
  );
  fs.mkdirSync(credentialsDirectory, { mode: 0o700 });
  const isolated = integratedLiveDrillProviderWorkerEnvironment({
    ALL_PROXY: "http://unsafe.invalid",
    AWS_ACCESS_KEY_ID: "AKIAUNSAFEUNSAFE0000",
    AWS_PROFILE: "unsafe-profile",
    HOME: "/tmp/unsafe-home",
    MCP_API_KEY: "synthetic-test-only-mcp-api-key-0001",
    NODE_OPTIONS: "--inspect",
    PATH: process.env.PATH,
    PRIMARY_AUDIT_DATABASE_URL: "postgresql://audit.invalid/tideproof",
    PRIMARY_RECOVERY_SOURCE_DATABASE_URL:
      "postgresql://source.invalid/tideproof",
    RECOVERY_PUBLISHER_DATABASE_URL:
      "postgresql://publisher.invalid/tideproof"
  }, {
    credentialsDirectory,
    forbiddenRootPath: context.forbiddenRootPath,
    rootPath: context.recoveryEvidenceRootPath
  });
  assert.equal(isolated.CREDENTIALS_DIRECTORY, credentialsDirectory);
  assert.equal(
    isolated.TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_ROOT,
    context.recoveryEvidenceRootPath
  );
  assert.equal(Object.hasOwn(isolated, "MCP_API_KEY"), false);
  assert.equal(Object.hasOwn(isolated, "PRIMARY_AUDIT_DATABASE_URL"), false);
  const normalizedWorkerEnvironment =
    assertIntegratedLiveDrillProviderWorkerEnvironment(isolated, {
      forbiddenRootPath: context.forbiddenRootPath,
      rootPath: context.recoveryEvidenceRootPath
    });
  assert.notEqual(normalizedWorkerEnvironment, isolated);
  assert.deepEqual(normalizedWorkerEnvironment, isolated);
  assert.equal(Object.isFrozen(normalizedWorkerEnvironment), true);
  assert.throws(
    () => assertIntegratedLiveDrillProviderWorkerEnvironment({
      ...isolated,
      MCP_API_KEY: "synthetic-secret"
    }, {
      forbiddenRootPath: context.forbiddenRootPath,
      rootPath: context.recoveryEvidenceRootPath
    }),
    /INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_ENVIRONMENT_REJECTED/u
  );
  for (const name of [
    "ALL_PROXY",
    "AWS_ACCESS_KEY_ID",
    "AWS_CONFIG_FILE",
    "AWS_PROFILE",
    "AWS_SHARED_CREDENTIALS_FILE",
    "HOME",
    "MCP_API_KEY",
    "NODE_OPTIONS",
    "PRIMARY_AUDIT_DATABASE_URL",
    "PRIMARY_PROVIDER_FINALIZE_DATABASE_URL",
    "PRIMARY_RECOVERY_SOURCE_DATABASE_URL",
    "RECOVERY_PUBLISHER_DATABASE_URL"
  ]) {
    assert.equal(Object.hasOwn(isolated, name), false, name);
  }
  for (const name of [
    "ALL_PROXY",
    "AWS_PROFILE",
    "AWS_SHARED_CREDENTIALS_FILE",
    "NODE_OPTIONS",
    "RECOVERY_PUBLISHER_PRIVATE_KEY"
  ]) {
    assert.throws(
      () => assertIntegratedLiveDrillProviderWorkerEnvironment({
        ...isolated,
        [name]: "synthetic-forbidden"
      }, {
        forbiddenRootPath: context.forbiddenRootPath,
        rootPath: context.recoveryEvidenceRootPath
      }),
      /INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_ENVIRONMENT_REJECTED/u,
      name
    );
  }
  const workerEnvironmentDirectApiMutations = [
    ["enumerable symbol", (value) => {
      Object.defineProperty(value, Symbol("providerClient"), {
        enumerable: true,
        value: {}
      });
    }],
    ["non-enumerable extra", (value) => {
      Object.defineProperty(value, "providerClient", {
        enumerable: false,
        value: {}
      });
    }],
    ["custom prototype", (value) => {
      Object.setPrototypeOf(value, { providerClient: {} });
    }],
    ["getter", (value) => {
      Object.defineProperty(value, "MCP_API_KEY", {
        configurable: true,
        enumerable: true,
        get() {
          throw new Error("worker environment getter must never run");
        }
      });
    }]
  ];
  for (const [name, mutate] of workerEnvironmentDirectApiMutations) {
    const changedEnvironment = { ...isolated };
    mutate(changedEnvironment);
    assert.throws(
      () => assertIntegratedLiveDrillProviderWorkerEnvironment(
        changedEnvironment,
        {
          forbiddenRootPath: context.forbiddenRootPath,
          rootPath: context.recoveryEvidenceRootPath
        }
      ),
      /INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_ENVIRONMENT_REJECTED/u,
      name
    );
  }
  if (process.platform === "linux") {
    const workerEnvironmentProbe = spawnSync(
      process.execPath,
      [
        "--input-type=module",
        "--eval",
        `import { assertIntegratedLiveDrillProviderWorkerEnvironment as check } from ${JSON.stringify(new URL("../src/cloud/integrated-live-drill-provider-worker.js", import.meta.url).href)}; check(process.env, ${JSON.stringify({
          forbiddenRootPath: context.forbiddenRootPath,
          rootPath: context.recoveryEvidenceRootPath
        })});`
      ],
      { encoding: "utf8", env: isolated }
    );
    assert.equal(
      workerEnvironmentProbe.status,
      0,
      workerEnvironmentProbe.stderr
    );
  }
  const workerUnexpectedEnvironmentProbe = spawnSync(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      `import { assertIntegratedLiveDrillProviderWorkerEnvironment as check } from ${JSON.stringify(new URL("../src/cloud/integrated-live-drill-provider-worker.js", import.meta.url).href)}; check(process.env, ${JSON.stringify({
        forbiddenRootPath: context.forbiddenRootPath,
        rootPath: context.recoveryEvidenceRootPath
      })});`
    ],
    {
      encoding: "utf8",
      env: { ...isolated, FOO_UNEXPECTED: "present" }
    }
  );
  assert.notEqual(workerUnexpectedEnvironmentProbe.status, 0);
  assert.match(
    workerUnexpectedEnvironmentProbe.stderr,
    /INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_ENVIRONMENT_REJECTED/u
  );
  let fakeFetchCalls = 0;
  let fakeAuditFactoryCalls = 0;
  const workerInputDirectApiMutations = [
    ["enumerable symbol", (value) => {
      Object.defineProperty(value, Symbol("providerClient"), {
        enumerable: true,
        value: {}
      });
    }],
    ["non-enumerable extra", (value) => {
      Object.defineProperty(value, "providerClient", {
        enumerable: false,
        value: {}
      });
    }],
    ["custom prototype", (value) => {
      Object.setPrototypeOf(value, { providerClient: {} });
    }],
    ["getter", (value) => {
      Object.defineProperty(value, "context", {
        configurable: true,
        enumerable: true,
        get() {
          throw new Error("worker input getter must never run");
        }
      });
    }]
  ];
  for (const [name, mutate] of workerInputDirectApiMutations) {
    const changedInput = structuredClone(input);
    mutate(changedInput);
    await assert.rejects(
      () => workerTest.runWithLocalTransports({
        environment: isolated,
        input: changedInput
      }, {
        auditClientFactory: async () => {
          fakeAuditFactoryCalls += 1;
          throw new Error("fake audit factory must never run");
        },
        fetchImpl: null
      }),
      /INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_REJECTED/u,
      name
    );
  }
  assert.equal(fakeFetchCalls, 0);
  assert.equal(fakeAuditFactoryCalls, 0);
  const wrongPrincipal = structuredClone(input);
  wrongPrincipal.authenticatedPrincipal = "principal://wrong";
  assert.throws(
    () => validateIntegratedLiveDrillProviderWorkerInput(wrongPrincipal),
    /INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_PRINCIPAL_REJECTED/u
  );
  const symlinkPath = path.join(
    context.recoveryEvidenceRootPath,
    "provider-worker-input-link.json"
  );
  fs.symlinkSync(inputPath, symlinkPath);
  assert.throws(
    () => readIntegratedLiveDrillProviderWorkerInput({
      forbiddenRootPath: context.forbiddenRootPath,
      inputPath: symlinkPath,
      rootPath: context.recoveryEvidenceRootPath
    }),
    /(?:INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_REJECTED|RECOVERY_BUNDLE_PERSISTENCE_REJECTED)/u
  );
  const outsideRoot = fs.mkdtempSync(path.join(
    path.dirname(context.recoveryEvidenceRootPath),
    "provider-worker-outside-"
  ));
  fs.chmodSync(outsideRoot, 0o700);
  t.after(() => fs.rmSync(outsideRoot, { force: true, recursive: true }));
  const outsideInputPath = path.join(outsideRoot, "worker-input.json");
  fs.writeFileSync(outsideInputPath, `${canonicalJson(input)}\n`, {
    mode: 0o600
  });
  const intermediateLink = path.join(
    context.recoveryEvidenceRootPath,
    "provider-worker-outside-link"
  );
  fs.symlinkSync(outsideRoot, intermediateLink);
  assert.throws(
    () => readIntegratedLiveDrillProviderWorkerInput({
      forbiddenRootPath: context.forbiddenRootPath,
      inputPath: path.join(intermediateLink, "worker-input.json"),
      rootPath: context.recoveryEvidenceRootPath
    }),
    /(?:INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_REJECTED|RECOVERY_BUNDLE_PERSISTENCE_REJECTED)/u
  );
  const substitutedRootInput = structuredClone(input);
  substitutedRootInput.context.recoveryEvidenceRootPath = outsideRoot;
  const substitutedRootInputPath = path.join(
    context.recoveryEvidenceRootPath,
    "provider-worker-substituted-root.json"
  );
  fs.writeFileSync(
    substitutedRootInputPath,
    `${canonicalJson(substitutedRootInput)}\n`,
    { mode: 0o600 }
  );
  assert.throws(
    () => readIntegratedLiveDrillProviderWorkerInput({
      forbiddenRootPath: context.forbiddenRootPath,
      inputPath: substitutedRootInputPath,
      rootPath: context.recoveryEvidenceRootPath
    }),
    /(?:INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_REJECTED|RECOVERY_BUNDLE_PERSISTENCE_REJECTED)/u
  );
});

test("provider finalizer import surface is provider and credential free", () => {
  const finalizerSource = fs.readFileSync(
    new URL(
      "../src/cloud/integrated-live-drill-provider-finalization.js",
      import.meta.url
    ),
    "utf8"
  );
  const runnerSource = fs.readFileSync(
    new URL(
      "../scripts/gate2-integrated-live-drill-provider-finalizer.js",
      import.meta.url
    ),
    "utf8"
  );
  for (const source of [finalizerSource, runnerSource]) {
    for (const forbidden of [
      "managed-mcp-client",
      "recovery-broker",
      "MCP_API_KEY",
      "PRIMARY_AUDIT_DATABASE_URL",
      "PRIMARY_RECOVERY_SOURCE_DATABASE_URL",
      "RECOVERY_PUBLISHER_DATABASE_URL"
    ]) {
      assert.equal(source.includes(forbidden), false, forbidden);
    }
  }
  const rootPath = "/private/tmp/prooftoact-provider-finalizer";
  const rootBinding = Object.freeze({ synthetic: "root-binding" });
  const isolated = integratedLiveDrillProviderFinalizerEnvironment({
    ALL_PROXY: "http://unsafe.invalid",
    AWS_PROFILE: "unsafe-profile",
    HOME: "/tmp/unsafe-home",
    MCP_API_KEY: "synthetic-test-only-mcp-api-key-0001",
    NODE_OPTIONS: "--inspect",
    PATH: process.env.PATH,
    PRIMARY_AUDIT_DATABASE_URL: "postgresql://audit.invalid/tideproof",
    RECOVERY_PUBLISHER_PRIVATE_KEY: "synthetic-forbidden"
  }, {
    forbiddenRootPath: "/private/tmp/prooftoact-forbidden",
    inputPath: `${rootPath}/provider-finalization-input.json`,
    rootBinding,
    rootPath
  });
  assert.equal(
    isolated.TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_ROOT_BINDING,
    canonicalJson(rootBinding)
  );
  assert.equal(
    isolated[INTEGRATED_LIVE_DRILL_PRIVATE_ROOT_DESCRIPTOR_ENVIRONMENT],
    "3"
  );
  assert.throws(
    () => assertIntegratedLiveDrillProviderFinalizerEnvironment({
      ...isolated,
      [INTEGRATED_LIVE_DRILL_PRIVATE_ROOT_DESCRIPTOR_ENVIRONMENT]: "4"
    }),
    /INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_ENVIRONMENT_REJECTED/u
  );
  for (const name of [
    "ALL_PROXY",
    "AWS_PROFILE",
    "HOME",
    "MCP_API_KEY",
    "NODE_OPTIONS",
    "PRIMARY_AUDIT_DATABASE_URL",
    "RECOVERY_PUBLISHER_PRIVATE_KEY"
  ]) {
    assert.equal(Object.hasOwn(isolated, name), false, name);
    assert.throws(
      () => assertIntegratedLiveDrillProviderFinalizerEnvironment({
        ...isolated,
        [name]: "synthetic-forbidden"
      }),
      /INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_ENVIRONMENT_REJECTED/u,
      name
    );
  }
  const normalizedFinalizerEnvironment =
    assertIntegratedLiveDrillProviderFinalizerEnvironment(isolated);
  assert.notEqual(normalizedFinalizerEnvironment, isolated);
  assert.deepEqual(normalizedFinalizerEnvironment, isolated);
  assert.equal(Object.isFrozen(normalizedFinalizerEnvironment), true);
  const finalizerEnvironmentDirectApiMutations = [
    ["enumerable symbol", (value) => {
      Object.defineProperty(value, Symbol("providerClient"), {
        enumerable: true,
        value: {}
      });
    }],
    ["non-enumerable extra", (value) => {
      Object.defineProperty(value, "providerClient", {
        enumerable: false,
        value: {}
      });
    }],
    ["custom prototype", (value) => {
      Object.setPrototypeOf(value, { providerClient: {} });
    }],
    ["getter", (value) => {
      Object.defineProperty(
        value,
        "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_INPUT_PATH",
        {
          configurable: true,
          enumerable: true,
          get() {
            throw new Error("finalizer environment getter must never run");
          }
        }
      );
    }]
  ];
  for (const [name, mutate] of finalizerEnvironmentDirectApiMutations) {
    const changedEnvironment = { ...isolated };
    mutate(changedEnvironment);
    assert.throws(
      () => assertIntegratedLiveDrillProviderFinalizerEnvironment(
        changedEnvironment
      ),
      /INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_ENVIRONMENT_REJECTED/u,
      name
    );
  }
  const finalizerEnvironmentProbe = spawnSync(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      `import { assertIntegratedLiveDrillProviderFinalizerEnvironment as check } from ${JSON.stringify(new URL("../src/cloud/integrated-live-drill-provider-finalization.js", import.meta.url).href)}; check(process.env);`
    ],
    { encoding: "utf8", env: isolated }
  );
  assert.equal(
    finalizerEnvironmentProbe.status,
    0,
    finalizerEnvironmentProbe.stderr
  );
  const finalizerUnexpectedEnvironmentProbe = spawnSync(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      `import { assertIntegratedLiveDrillProviderFinalizerEnvironment as check } from ${JSON.stringify(new URL("../src/cloud/integrated-live-drill-provider-finalization.js", import.meta.url).href)}; check(process.env);`
    ],
    {
      encoding: "utf8",
      env: { ...isolated, FOO_UNEXPECTED: "present" }
    }
  );
  assert.notEqual(finalizerUnexpectedEnvironmentProbe.status, 0);
  assert.match(
    finalizerUnexpectedEnvironmentProbe.stderr,
    /INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_ENVIRONMENT_REJECTED/u
  );
});

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

function inMemoryProviderDispatchFinalizer() {
  let bindingSha256 = null;
  let state = null;
  let terminal = Object.freeze({
    mcpResultSha256: null,
    sessionCloseSha256: null
  });
  const result = (binding, transitionOutcome) => Object.freeze({
    authorizationId: binding.authorizationId,
    controlBindingSha256: binding.controlBindingSha256,
    databaseNow: binding.issuedAt,
    expiresAt: binding.expiresAt,
    ...terminal,
    grantId: "11111111-1111-5111-8111-111111111111",
    state,
    transitionOutcome
  });
  const assertBinding = (binding) => {
    if (bindingSha256 === null) {
      bindingSha256 = binding.controlBindingSha256;
    }
    assert.equal(binding.controlBindingSha256, bindingSha256);
  };
  return Object.freeze({
    complete(binding, grant, value) {
      assertBinding(binding);
      assert.equal(grant.grantId, "11111111-1111-5111-8111-111111111111");
      if (state === null) {
        terminal = Object.freeze({ ...value });
        state = "COMPLETED";
      }
      assert.equal(state, "COMPLETED");
      assert.deepEqual(terminal, value);
      return result(binding, "COMPLETED");
    },
    markUnknown(binding, grant) {
      assertBinding(binding);
      assert.equal(grant.grantId, "11111111-1111-5111-8111-111111111111");
      if (state === null) state = "UNKNOWN_DO_NOT_ACT";
      return result(binding, "UNKNOWN_RECORDED");
    }
  });
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
    auditTargetIdentity:
      fixture.context.trustedRunContext.recoveryBrokerConfiguration
        .auditTargetIdentity,
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
    providerDispatchFinalizer: inMemoryProviderDispatchFinalizer(),
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
    fetchImpl,
    mcpClient
  };
}

function auditDatabaseClientFactory() {
  const rows = new Map();
  const providerControls = new Map();
  return {
    clientFactory() {
      return {
        async connect() {},
        async end() {},
        async query(sql, params = []) {
          if (/^BEGIN|^COMMIT|^ROLLBACK/u.test(sql.trim())) {
            return { rowCount: 0, rows: [] };
          }
          if (sql.includes("transaction_timestamp()")) {
            return {
              rowCount: 1,
              rows: [{ database_now: new Date().toISOString() }]
            };
          }
          if (sql.includes("g1_append_recovery_audit_event_v3")) {
            const row = {
              event_id: params[0],
              tenant_id: params[1],
              interaction_id: params[2],
              recovery_session_id: params[3],
              caller_subject_hash: params[4],
              phase: params[5],
              tool_name: params[6],
              recovery_cluster_id: params[7],
              broker_config_digest: params[8],
              query_template_digest: params[9],
              bound_input_digest: params[10],
              result_digest: params[11],
              source_watermark: params[12],
              outcome: params[13],
              error_code: params[14],
              event_digest: params[15],
              started_at: params[16],
              completed_at: params[17],
              database_now: new Date().toISOString()
            };
            const existing = rows.get(row.event_id);
            if (existing !== undefined) assert.deepEqual(existing, row);
            rows.set(row.event_id, row);
            return { rowCount: 1, rows: [{ event_id: row.event_id }] };
          }
          if (sql.includes("g1_resolve_recovery_audit_event_v1")) {
            const row = rows.get(params[0]);
            assert.equal(row?.tenant_id, params[1]);
            assert.equal(row?.event_digest, params[2]);
            return row === undefined
              ? { rowCount: 0, rows: [] }
              : { rowCount: 1, rows: [row] };
          }
          if (sql.includes("g1_transition_provider_dispatch_v1")) {
            const [
              action,
              authorizationId,
              tenantId,
              runId,
              interactionId,
              ownerNonce,
              controlBindingSha256,
              logicalMcpRequestSha256,
              providerEffectKeySha256,
              providerDispatchAuthorizationSha256,
              sourceCommit,
              treeDigest,
              sourceBuildIdentity,
              issuedAt,
              expiresAt,
              mcpResultSha256,
              sessionCloseSha256
            ] = params;
            let control = providerControls.get(authorizationId);
            let transitionOutcome = "RESOLVED";
            if (control === undefined) {
              assert.equal(action, "CONSUME");
              control = {
                authorization_id: authorizationId,
                tenant_id: tenantId,
                run_id: runId,
                interaction_id: interactionId,
                owner_nonce: ownerNonce,
                control_binding_sha256: controlBindingSha256,
                logical_mcp_request_sha256: logicalMcpRequestSha256,
                provider_effect_key_sha256: providerEffectKeySha256,
                provider_dispatch_authorization_sha256:
                  providerDispatchAuthorizationSha256,
                source_commit: sourceCommit,
                tree_digest: treeDigest,
                source_build_identity: sourceBuildIdentity,
                issued_at: issuedAt,
                expires_at: expiresAt,
                database_now: issuedAt,
                state: "CONSUMED",
                mcp_result_sha256: null,
                session_close_sha256: null
              };
              providerControls.set(authorizationId, control);
              transitionOutcome = "DISPATCH_GRANTED";
            } else {
              assert.equal(
                control.control_binding_sha256,
                controlBindingSha256
              );
              if (action === "COMPLETE") {
                assert.equal(control.owner_nonce, ownerNonce);
                control.state = "COMPLETED";
                control.mcp_result_sha256 = mcpResultSha256;
                control.session_close_sha256 = sessionCloseSha256;
                transitionOutcome = "COMPLETED";
              } else if (action === "MARK_UNKNOWN") {
                if (control.state === "CONSUMED") {
                  control.state = "UNKNOWN_DO_NOT_ACT";
                }
                transitionOutcome = "UNKNOWN_RECORDED";
              } else if (action === "CONSUME") {
                transitionOutcome = "ALREADY_TERMINAL_OR_CONSUMED";
              }
            }
            return {
              rowCount: 1,
              rows: [{ ...control, transition_outcome: transitionOutcome }]
            };
          }
          throw new Error(`unexpected synthetic audit query: ${sql}`);
        }
      };
    },
    providerControls,
    rows
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
  const preReadFile = privateFiles.find((name) =>
    name.endsWith("-pre-read.json")
  );
  const terminalFile = privateFiles.find((name) =>
    name.endsWith("-terminal.json")
  );
  assert.equal(typeof preReadFile, "string");
  assert.equal(typeof providerFile, "string");
  assert.equal(typeof terminalFile, "string");
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

  for (const field of [
    "logicalMcpRequestSha256",
    "preCallIntentSha256",
    "preReadEvidenceReceiptSha256",
    "providerDispatchAuthorizationSha256",
    "providerEvidenceReceiptSha256",
    "terminalEvidenceReceiptSha256",
    "transportEvidenceSha256"
  ]) {
    const changed = structuredClone(result.providerContinuity);
    changed[field] = "0".repeat(64);
    const recomputed = recomputeArtifactReceipt(changed);
    assert.throws(
      () => finalizeIntegratedLiveDrillProviderRecovery({
        context,
        providerContinuity: recomputed
      }),
      /INTEGRATED_LIVE_DRILL_PROVIDER_(?:EVIDENCE_BINDING|FINALIZATION_INPUT|HANDOFF_BINDING|JOURNAL_BINDING)_REJECTED/u,
      field
    );
  }
  const tamperedDispatchContext = structuredClone(context);
  const dispatchSignature =
    tamperedDispatchContext.providerDispatchAuthorization.signature.value;
  tamperedDispatchContext.providerDispatchAuthorization.signature.value =
    `${dispatchSignature[0] === "A" ? "B" : "A"}${dispatchSignature.slice(1)}`;
  assert.throws(
    () => finalizeIntegratedLiveDrillProviderRecovery({
      context: tamperedDispatchContext,
      providerContinuity: result.providerContinuity
    }),
    /INTEGRATED_LIVE_DRILL_PROVIDER_(?:DISPATCH_AUTHORIZATION|FINALIZATION_INPUT)_REJECTED/u
  );

  const evidencePaths = [preReadFile, providerFile, terminalFile].map((name) =>
    path.join(context.recoveryEvidenceRootPath, name)
  );
  const evidenceBytes = evidencePaths.map((filePath) =>
    fs.readFileSync(filePath)
  );
  for (let index = 0; index < evidencePaths.length; index += 1) {
    const filePath = evidencePaths[index];
    const originalStat = fs.statSync(filePath);
    const missingPath = `${filePath}.missing`;
    fs.renameSync(filePath, missingPath);
    try {
      assert.throws(
        () => finalizeIntegratedLiveDrillProviderRecovery({
          context,
          providerContinuity: result.providerContinuity
        }),
        /INTEGRATED_LIVE_DRILL_PROVIDER_(?:EVIDENCE_AMBIGUOUS|EVIDENCE_BINDING_REJECTED)/u,
        `missing ${path.basename(filePath)}`
      );
    } finally {
      fs.renameSync(missingPath, filePath);
    }
    fs.writeFileSync(
      filePath,
      evidenceBytes[(index + 1) % evidenceBytes.length]
    );
    try {
      assert.throws(
        () => finalizeIntegratedLiveDrillProviderRecovery({
          context,
          providerContinuity: result.providerContinuity
        }),
        /INTEGRATED_LIVE_DRILL_PROVIDER_(?:EVIDENCE_BINDING|RECEIPT|TRANSPORT|SEMANTIC_REQUEST)_REJECTED/u,
        `substituted ${path.basename(filePath)}`
      );
    } finally {
      fs.writeFileSync(filePath, evidenceBytes[index]);
      fs.chmodSync(filePath, originalStat.mode & 0o777);
    }
  }

  const callCount = harness.calls.length;
  const resumed = await runIntegratedLiveDrillProviderRecovery({
    authenticatedPrincipal: PRINCIPAL,
    broker: harness.broker,
    context
  });
  assert.equal(resumed.recovery.status, "RECOVERED_CONTEXT_ONLY");
  assert.equal(harness.calls.length, callCount);

  const normalizedProviderContinuity =
    validateIntegratedLiveDrillProviderRecoveryHandoff(
      result.providerContinuity
    );
  assert.equal(
    normalizedProviderContinuity.receiptSha256,
    result.providerContinuity.receiptSha256
  );
  assert.notEqual(normalizedProviderContinuity, result.providerContinuity);
  assert.deepEqual(normalizedProviderContinuity, result.providerContinuity);
  assert.equal(Object.isFrozen(normalizedProviderContinuity), true);
  const componentReceiptName =
    `${context.preCallIntent.authorizationId}.provider-recovery-component.json`;
  const finalizationFilesBefore = fs.readdirSync(
    context.recoveryEvidenceRootPath
  ).sort();
  assert.equal(finalizationFilesBefore.includes(componentReceiptName), false);
  const finalizationInputFor = (changedContext) => ({
    context: changedContext,
    providerContinuity: result.providerContinuity,
    schemaVersion: INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_INPUT_SCHEMA
  });
  let nestedHandoffGetterCalls = 0;
  const handoffDirectApiMutations = [
    ["provider client", (value) => { value.providerClient = {}; }],
    ["raw provider result", (value) => { value.rawProviderResult = {}; }],
    ["retry authority", (value) => { value.retryAuthority = true; }],
    ["generic retry key", (value) => { value.retry = true; }],
    ["credential-like symbol", (value) => {
      Object.defineProperty(value, Symbol("MCP_API_KEY"), {
        enumerable: true,
        value: "synthetic-secret"
      });
    }],
    ["non-enumerable extra", (value) => {
      Object.defineProperty(value, "providerClient", {
        enumerable: false,
        value: {}
      });
    }],
    ["custom prototype", (value) => {
      Object.setPrototypeOf(value, { providerClient: {} });
    }],
    ["getter", (value) => {
      Object.defineProperty(value, "receiptSha256", {
        configurable: true,
        enumerable: true,
        get() {
          throw new Error("provider handoff getter must never run");
        }
      });
    }],
    ["nested getter", (value) => {
      const nestedCapability = {};
      Object.defineProperty(nestedCapability, "providerClient", {
        enumerable: true,
        get() {
          nestedHandoffGetterCalls += 1;
          throw new Error("nested handoff getter must never run");
        }
      });
      value.observedInitializeCount = nestedCapability;
    }],
    ["coercible digest object", (value) => {
      const coercibleDigest = Object.create(null);
      Object.defineProperty(coercibleDigest, Symbol.toPrimitive, {
        enumerable: false,
        value: () => "a".repeat(64)
      });
      value.preReadEvidenceReceiptSha256 = coercibleDigest;
      const { receiptSha256: _receiptSha256, ...body } = value;
      void _receiptSha256;
      value.receiptSha256 = integratedLiveDrillCanonicalSha256(body);
    }]
  ];
  for (const [name, mutate] of handoffDirectApiMutations) {
    const changedHandoff = structuredClone(result.providerContinuity);
    mutate(changedHandoff);
    assert.throws(
      () => validateIntegratedLiveDrillProviderRecoveryHandoff(
        changedHandoff
      ),
      /INTEGRATED_LIVE_DRILL_PROVIDER_HANDOFF_REJECTED/u,
      `${name} handoff validator`
    );
    assert.throws(
      () => finalizeIntegratedLiveDrillProviderRecovery({
        context,
        providerContinuity: changedHandoff
      }),
      /INTEGRATED_LIVE_DRILL_PROVIDER_HANDOFF_REJECTED/u,
      `${name} direct finalizer`
    );
    assert.deepEqual(
      fs.readdirSync(context.recoveryEvidenceRootPath).sort(),
      finalizationFilesBefore,
      `${name} created no W4, W5, or component artifact`
    );
  }
  assert.equal(nestedHandoffGetterCalls, 0);
  const rejectedContextMutations = [
    ["root MCP credential", (value) => {
      value.MCP_API_KEY = "synthetic-secret";
    }],
    ["root database credential", (value) => {
      value.PRIMARY_AUDIT_DATABASE_URL =
        "postgresql://synthetic.invalid/tideproof";
    }],
    ["root AWS profile", (value) => { value.AWS_PROFILE = "unsafe"; }],
    ["root proxy capability", (value) => {
      value.HTTPS_PROXY = "https://unsafe.invalid";
    }],
    ["root private key", (value) => {
      value.RECOVERY_PUBLISHER_PRIVATE_KEY = "synthetic-secret";
    }],
    ["root provider client", (value) => { value.providerClient = {}; }],
    ["root MCP client", (value) => { value.mcpClient = {}; }],
    ["root raw result", (value) => { value.rawProviderResult = {}; }],
    ["root transport evidence", (value) => {
      value.transportEvidence = {};
    }],
    ["root retry authority", (value) => {
      value.retryAuthority = true;
    }],
    ["root allow retry", (value) => { value.allowRetry = true; }],
    ["root arbitrary metadata", (value) => {
      value.unexpectedMetadata = "innocuous";
    }],
    ["nested pre-call metadata", (value) => {
      value.preCallInputs.unexpectedMetadata = "innocuous";
    }],
    ["nested audit retry", (value) => {
      value.preCallInputs.audit.retryPermitted = true;
    }],
    ["nested child payload secret", (value) => {
      value.preCallInputs.consumedChildAuthorization.attestation.payload
        .clientSecret = "synthetic-secret";
    }],
    ["nested child signature provider", (value) => {
      value.preCallInputs.consumedChildAuthorization.attestation.signature
        .providerClient = {};
    }],
    ["nested trusted provider", (value) => {
      value.trustedRunContext.providerClient = {};
    }],
    ["nested spec metadata", (value) => {
      value.trustedRunContext.spec.unexpectedMetadata = "innocuous";
    }],
    ["nested authorization raw result", (value) => {
      value.authorization.payload.rawResult = {};
    }],
    ["nested ledger retry authority", (value) => {
      value.controlLedgerReceipt.retryAfterMs = 1000;
    }],
    ["nested dispatch transport evidence", (value) => {
      value.providerDispatchAuthorization.payload.transportEvidence = {};
    }]
  ];
  for (const [name, mutate] of rejectedContextMutations) {
    const changedContext = structuredClone(context);
    mutate(changedContext);
    assert.throws(
      () => validateIntegratedLiveDrillProviderFinalizationInput(
        finalizationInputFor(changedContext)
      ),
      /INTEGRATED_LIVE_DRILL_(?:AUTHORIZATION|PROVIDER_(?:CONTEXT|CREDENTIAL_MATERIAL|FINALIZATION_INPUT))_REJECTED/u,
      `${name} validator`
    );
    assert.throws(
      () => finalizeIntegratedLiveDrillProviderRecovery({
        context: changedContext,
        providerContinuity: result.providerContinuity
      }),
      /INTEGRATED_LIVE_DRILL_(?:AUTHORIZATION|PROVIDER_(?:CONTEXT|CREDENTIAL_MATERIAL|FINALIZATION_INPUT))_REJECTED/u,
      `${name} direct finalizer`
    );
    assert.deepEqual(
      fs.readdirSync(context.recoveryEvidenceRootPath).sort(),
      finalizationFilesBefore,
      `${name} created no finalization artifact`
    );
  }
  const directApiMutations = [
    ["function", (value) => { value.providerClient = () => undefined; }],
    ["symbol", (value) => {
      Object.defineProperty(value, Symbol("providerClient"), {
        enumerable: true,
        value: {}
      });
    }],
    ["non-enumerable", (value) => {
      Object.defineProperty(value, "providerClient", {
        enumerable: false,
        value: {}
      });
    }],
    ["prototype", (value) => {
      Object.setPrototypeOf(value, { providerClient: {} });
    }],
    ["nested array prototype", (value) => {
      Object.setPrototypeOf(
        value.controlLedgerReceipt.childLaunchDigests,
        Object.create(Array.prototype, {
          providerClient: { enumerable: true, value: {} }
        })
      );
    }],
    ["getter", (value) => {
      Object.defineProperty(value, "providerClient", {
        enumerable: true,
        get() {
          throw new Error("getter must never run");
        }
      });
    }],
    ["nested array getter", (value) => {
      Object.defineProperty(
        value.controlLedgerReceipt.childLaunchDigests,
        "0",
        {
          configurable: true,
          enumerable: true,
          get() {
            throw new Error("nested getter must never run");
          }
        }
      );
    }]
  ];
  for (const [name, mutate] of directApiMutations) {
    const changedContext = structuredClone(context);
    mutate(changedContext);
    assert.throws(
      () => validateIntegratedLiveDrillProviderFinalizationInput(
        finalizationInputFor(changedContext)
      ),
      /INTEGRATED_LIVE_DRILL_PROVIDER_(?:CONTEXT|FINALIZATION_INPUT)_REJECTED/u,
      `${name} direct API value`
    );
    assert.throws(
      () => finalizeIntegratedLiveDrillProviderRecovery({
        context: changedContext,
        providerContinuity: result.providerContinuity
      }),
      /INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_INPUT_REJECTED/u,
      `${name} direct finalizer value`
    );
    assert.deepEqual(
      fs.readdirSync(context.recoveryEvidenceRootPath).sort(),
      finalizationFilesBefore,
      `${name} created no finalization artifact`
    );
  }
  const wrapperDirectApiMutations = [
    ["symbol", (value) => {
      Object.defineProperty(value, Symbol("providerClient"), {
        enumerable: true,
        value: {}
      });
    }],
    ["non-enumerable", (value) => {
      Object.defineProperty(value, "providerClient", {
        enumerable: false,
        value: {}
      });
    }],
    ["prototype", (value) => {
      Object.setPrototypeOf(value, { providerClient: {} });
    }],
    ["getter", (value) => {
      Object.defineProperty(value, "context", {
        configurable: true,
        enumerable: true,
        get() {
          throw new Error("wrapper getter must never run");
        }
      });
    }]
  ];
  for (const [name, mutate] of wrapperDirectApiMutations) {
    const changedInput = finalizationInputFor(context);
    mutate(changedInput);
    assert.throws(
      () => validateIntegratedLiveDrillProviderFinalizationInput(changedInput),
      /INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_INPUT_REJECTED/u,
      `${name} finalization-input wrapper`
    );
    const changedFinalizerArgs = {
      context,
      providerContinuity: result.providerContinuity
    };
    mutate(changedFinalizerArgs);
    assert.throws(
      () => finalizeIntegratedLiveDrillProviderRecovery(changedFinalizerArgs),
      /INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_INPUT_REJECTED/u,
      `${name} finalizer wrapper`
    );
    const changedEvidenceArgs = {
      context,
      providerContinuity: result.providerContinuity
    };
    mutate(changedEvidenceArgs);
    assert.throws(
      () => verifyIntegratedLiveDrillProviderEvidenceBundle(
        changedEvidenceArgs
      ),
      /INTEGRATED_LIVE_DRILL_PROVIDER_JOURNAL_BINDING_REJECTED/u,
      `${name} evidence wrapper`
    );
    assert.deepEqual(
      fs.readdirSync(context.recoveryEvidenceRootPath).sort(),
      finalizationFilesBefore,
      `${name} wrapper created no finalization artifact`
    );
  }
  const normalizedFinalizationInput =
    validateIntegratedLiveDrillProviderFinalizationInput(
      finalizationInputFor(context)
    );
  assert.notEqual(normalizedFinalizationInput.context, context);
  assert.notEqual(
    normalizedFinalizationInput.context.preCallInputs,
    context.preCallInputs
  );
  assert.notEqual(
    normalizedFinalizationInput.context.trustedRunContext,
    context.trustedRunContext
  );
  assert.equal(Object.isFrozen(normalizedFinalizationInput.context), true);
  assert.equal(
    Object.isFrozen(normalizedFinalizationInput.context.authorization),
    true
  );
  assert.equal(
    Object.isFrozen(normalizedFinalizationInput.context.preCallInputs),
    true
  );
  assert.equal(
    Object.isFrozen(normalizedFinalizationInput.context.trustedRunContext.spec),
    true
  );
  const finalized = finalizeIntegratedLiveDrillProviderRecovery({
    context,
    providerContinuity: result.providerContinuity
  });
  assert.equal(finalized.status, "LOCAL_FAKE_PRODUCTION_WIRING_VALIDATED");
  assert.equal(finalized.providerBacked, false);
  assert.equal(finalized.accepted, false);
  assert.equal(finalized.finalReleaseReady, false);
  assert.equal(finalized.providerCapabilityAccepted, false);
  assert.equal(finalized.credentialOptionAccepted, false);
  assert.equal(finalized.rawProviderResultAccepted, false);
  assert.equal(finalized.retryNamedKeyAccepted, false);
  assert.equal(finalized.contextCredentialMaterialAbsent, true);
  assert.equal(finalized.contextExactSchemaValidated, true);
  assert.equal(finalized.contextProviderCapabilityAbsent, true);
  assert.equal(finalized.contextRawProviderResultAbsent, true);
  assert.equal(finalized.contextRetryNamedKeyAbsent, true);
  assert.equal(finalized.observedToolsCallCount, 1);
  assert.equal(finalized.observedSessionCloseCount, 1);
  const normalizedComponentReceipt = JSON.parse(fs.readFileSync(
    path.join(context.recoveryEvidenceRootPath, componentReceiptName),
    "utf8"
  ));
  assert.equal(normalizedComponentReceipt.containsCredentialMaterial, false);
  assert.equal(normalizedComponentReceipt.containsRawProviderResult, false);
  assert.equal(normalizedComponentReceipt.contextCredentialMaterialAbsent, true);
  assert.equal(normalizedComponentReceipt.contextExactSchemaValidated, true);
  assert.equal(normalizedComponentReceipt.contextProviderCapabilityAbsent, true);
  assert.equal(normalizedComponentReceipt.contextRawProviderResultAbsent, true);
  assert.equal(normalizedComponentReceipt.contextRetryNamedKeyAbsent, true);
  assert.equal(
    finalizeIntegratedLiveDrillProviderRecovery({
      context,
      providerContinuity: result.providerContinuity
    }).receiptSha256,
    finalized.receiptSha256
  );
  const finalizationInput = Object.freeze({
    context,
    providerContinuity: result.providerContinuity,
    schemaVersion:
      INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_INPUT_SCHEMA
  });
  const finalizationInputPath = path.join(
    context.recoveryEvidenceRootPath,
    "provider-finalization-input.json"
  );
  fs.writeFileSync(
    finalizationInputPath,
    `${canonicalJson(finalizationInput)}\n`,
    { mode: 0o600 }
  );
  assert.equal(
    readIntegratedLiveDrillProviderFinalizationInput({
      forbiddenRootPath: context.forbiddenRootPath,
      inputPath: finalizationInputPath,
      rootPath: context.recoveryEvidenceRootPath
    }).providerContinuity.receiptSha256,
    result.providerContinuity.receiptSha256
  );
  const finalizerOutsideRoot = fs.mkdtempSync(path.join(
    path.dirname(context.recoveryEvidenceRootPath),
    "provider-finalizer-outside-"
  ));
  fs.chmodSync(finalizerOutsideRoot, 0o700);
  t.after(() => fs.rmSync(finalizerOutsideRoot, {
    force: true,
    recursive: true
  }));
  const finalizerOutsideInput = path.join(
    finalizerOutsideRoot,
    "provider-finalization-input.json"
  );
  fs.writeFileSync(
    finalizerOutsideInput,
    `${canonicalJson(finalizationInput)}\n`,
    { mode: 0o600 }
  );
  const finalizerIntermediateLink = path.join(
    context.recoveryEvidenceRootPath,
    "provider-finalizer-outside-link"
  );
  fs.symlinkSync(finalizerOutsideRoot, finalizerIntermediateLink);
  assert.throws(
    () => readIntegratedLiveDrillProviderFinalizationInput({
      forbiddenRootPath: context.forbiddenRootPath,
      inputPath: path.join(
        finalizerIntermediateLink,
        "provider-finalization-input.json"
      ),
      rootPath: context.recoveryEvidenceRootPath
    }),
    /INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_INPUT_REJECTED/u
  );
  const substitutedFinalizationInput = structuredClone(finalizationInput);
  substitutedFinalizationInput.context.recoveryEvidenceRootPath =
    finalizerOutsideRoot;
  const substitutedFinalizationInputPath = path.join(
    context.recoveryEvidenceRootPath,
    "provider-finalization-substituted-root.json"
  );
  fs.writeFileSync(
    substitutedFinalizationInputPath,
    `${canonicalJson(substitutedFinalizationInput)}\n`,
    { mode: 0o600 }
  );
  assert.throws(
    () => readIntegratedLiveDrillProviderFinalizationInput({
      forbiddenRootPath: context.forbiddenRootPath,
      inputPath: substitutedFinalizationInputPath,
      rootPath: context.recoveryEvidenceRootPath
    }),
    /INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_INPUT_REJECTED/u
  );
  const componentName = fs.readdirSync(context.recoveryEvidenceRootPath)
    .find((name) => name.endsWith(".provider-recovery-component.json"));
  assert.equal(typeof componentName, "string");
  assert.equal(
    fs.statSync(
      path.join(context.recoveryEvidenceRootPath, componentName)
    ).mode & 0o777,
    0o600
  );
  const componentReceipt = JSON.parse(fs.readFileSync(
    path.join(context.recoveryEvidenceRootPath, componentName),
    "utf8"
  ));
  assert.equal(componentReceipt.containsCredentialMaterial, false);
  assert.equal(componentReceipt.containsRawProviderResult, false);
  assert.equal(
    JSON.stringify(componentReceipt).includes("synthetic-api-key"),
    false
  );
  const fabricatedHandoff = structuredClone(result.providerContinuity);
  fabricatedHandoff.observedToolsCallCount = 2;
  const { receiptSha256: _fabricatedReceipt, ...fabricatedBody } =
    fabricatedHandoff;
  void _fabricatedReceipt;
  fabricatedHandoff.receiptSha256 =
    integratedLiveDrillCanonicalSha256(fabricatedBody);
  assert.throws(
    () => validateIntegratedLiveDrillProviderRecoveryHandoff(
      fabricatedHandoff
    ),
    /INTEGRATED_LIVE_DRILL_PROVIDER_HANDOFF_REJECTED/u
  );
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
  const expiryClock = Date.now();
  t.mock.timers.enable({ apis: ["Date"], now: expiryClock });
  const shortExpiry = new Date(expiryClock + 120).toISOString();
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
  t.mock.timers.setTime(expiryClock + 180);
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

test("a crash after the durable execution attempt resumes through the one-shot broker fence", async (t) => {
  const fixture = createRecoveryContinuityFixture(t, {
    prefix: "prooftoact-provider-attempt-crash-",
    subjectBindingSha256: principalBindingHash(PRINCIPAL)
  });
  const harness = providerHarness(fixture);
  const preparation = prepareDispatch(fixture);
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
      "AFTER_EXECUTION_ATTEMPT_DURABLE"
    ),
    /INTEGRATED_LIVE_DRILL_PROVIDER_SYNTHETIC_CRASH_AFTER_EXECUTION_ATTEMPT_DURABLE/u
  );
  assert.equal(harness.calls.length, 0);
  const attemptPath = path.join(
    context.recoveryEvidenceRootPath,
    "provider-execution-attempt.json"
  );
  assert.equal(fs.existsSync(attemptPath), true);
  assert.equal(fs.statSync(attemptPath).mode & 0o777, 0o600);

  const resumed = await runIntegratedLiveDrillProviderRecovery(args);
  assert.equal(resumed.recovery.status, "RECOVERED_CONTEXT_ONLY");
  assert.deepEqual(
    harness.calls.map(({ payload, method }) => payload?.method ?? method),
    ["initialize", "notifications/initialized", "tools/call", "DELETE"]
  );

  const providerCallCount = harness.calls.length;
  const repeated = await runIntegratedLiveDrillProviderRecovery(args);
  assert.equal(
    repeated.providerContinuity.receiptSha256,
    resumed.providerContinuity.receiptSha256
  );
  assert.equal(harness.calls.length, providerCallCount);
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
      path.dirname(candidate) === path.dirname(burnPath) &&
      path.basename(candidate).startsWith(
        `.${path.basename(burnPath)}.publish-`
      ) &&
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

test("post-W2 expiry reconciles audit-only without reactivating provider access", async (t) => {
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
  const first = await providerTest.runProviderRecoveryWithTrustedClock(
    args,
    () => clockNow
  );
  assert.equal(first.recovery.status, "RECOVERED_CONTEXT_ONLY");
  assert.deepEqual(
    harness.calls.map(({ payload, method }) => payload?.method ?? method),
    ["initialize", "notifications/initialized", "tools/call", "DELETE"]
  );
  assert.equal(
    harness.auditRows.has(context.preCallIntent.terminalAuditEventId),
    true
  );

  const callCount = harness.calls.length;
  const appendCount = harness.auditAppendAttempts.length;
  const resolveCount = harness.auditResolveAttempts.length;
  const burnPath = path.join(
    context.recoveryEvidenceRootPath,
    `${context.preCallIntent.authorizationId}` +
      ".provider-recovery-authority-expiry-burn.json"
  );
  assert.equal(fs.existsSync(burnPath), false);

  clockNow = Date.parse(consumedChildAuthorizationIssuedAt(context));
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const resumed = await providerTest.runProviderRecoveryWithTrustedClock(
      args,
      () => clockNow
    );
    assert.equal(resumed.providerContinuity.receiptSha256,
      first.providerContinuity.receiptSha256);
    assert.equal(harness.calls.length, callCount);
    assert.equal(harness.auditAppendAttempts.length, appendCount);
    assert.ok(harness.auditResolveAttempts.length >= resolveCount);
  }
});

test("expiry after audit resolution preserves the exact event and completes audit-only", async (t) => {
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
    if (phase === "pre-read") {
      await assert.rejects(
        () => providerTest.runProviderRecoveryWithTrustedClock(
          args,
          () => clockNow
        ),
        /INTEGRATED_LIVE_DRILL_PROVIDER_EXTERNAL_ACTION_AUTHORIZATION_REQUIRED/u
      );
    } else {
      const completed = await providerTest.runProviderRecoveryWithTrustedClock(
        args,
        () => clockNow
      );
      assert.equal(completed.recovery.status, "RECOVERED_CONTEXT_ONLY");
    }
    const callsAfterExpiry = harness.calls.length;
    const appendCount = harness.auditAppendAttempts.length;
    const resolveCount = harness.auditResolveAttempts.length;
    assert.equal(harness.auditRows.has(targetEventId), true);

    if (phase === "pre-read") {
      await assert.rejects(
        () => providerTest.runProviderRecoveryWithTrustedClock(
          args,
          () => clockNow
        ),
        /INTEGRATED_LIVE_DRILL_PROVIDER_EXTERNAL_ACTION_AUTHORIZATION_REQUIRED/u
      );
    } else {
      await providerTest.runProviderRecoveryWithTrustedClock(
        args,
        () => clockNow
      );
    }
    assert.equal(harness.calls.length, callsAfterExpiry);
    assert.equal(harness.auditAppendAttempts.length, appendCount);
    if (phase === "pre-read") {
      assert.equal(harness.auditResolveAttempts.length, resolveCount);
    } else {
      assert.ok(harness.auditResolveAttempts.length > resolveCount);
    }
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

test("post-expiry wrapper reconciles W2 and terminal audit without provider redispatch", async (t) => {
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
  const beforeExpiry = Math.max(
    Date.parse(context.preCallIntent.startedAt),
    context.authorization.issuedAt,
    Date.parse(
      context.preCallInputs.consumedChildAuthorization.attestation.payload
        .issuedAt
    ),
    Date.parse(context.providerDispatchAuthorization.payload.issuedAt)
  ) + 1;
  await assert.rejects(
    () => providerTest.runProviderRecoveryWithInterruptionAndTrustedClock(
      args,
      "AFTER_PROVIDER_EVIDENCE_DURABLE",
      () => beforeExpiry
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
  const afterExpiry = Math.max(
    context.authorization.expiresAt,
    Date.parse(context.preCallIntent.childAuthorizationExpiresAt),
    Date.parse(context.preCallIntent.expiresAt)
  ) + 1;

  const resumed = await providerTest.runProviderRecoveryWithTrustedClock(
    args,
    () => afterExpiry
  );
  assert.equal(resumed.recovery.status, "RECOVERED_CONTEXT_ONLY");
  assert.equal(harness.calls.length, initialFetchCount);
  assert.equal(harness.auditAppendAttempts.length, auditAppendCount + 1);
  assert.ok(harness.auditResolveAttempts.length > auditResolveCount);
  assert.equal(
    harness.auditRows.has(context.preCallIntent.terminalAuditEventId),
    true
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
    true
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
