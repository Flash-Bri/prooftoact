import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { canonicalJson } from "../src/cloud/canonical-json.js";
import {
  integratedLiveDrillCanonicalSha256,
  signIntegratedLiveDrillEvidence
} from "../src/cloud/integrated-live-drill-authorization.js";
import {
  INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORITY_STATEMENT,
  INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION_SCHEMA
} from "../src/cloud/integrated-live-drill-provider-evidence.js";
import {
  buildIntegratedLiveDrillProviderOrchestrationPreparation,
  INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_AMBIGUITY_BLOCKER,
  INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_HOLD,
  INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STATES,
  INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_PREPARATION_SCHEMA,
  persistIntegratedLiveDrillProviderOrchestrationPreparation,
  persistIntegratedLiveDrillProviderOrchestrationStop,
  readIntegratedLiveDrillProviderOrchestrationPreparation,
  readIntegratedLiveDrillProviderOrchestrationStop,
  sanitizedIntegratedLiveDrillProviderOrchestrationHold,
  validateIntegratedLiveDrillProviderSupervisorPreparation
} from "../src/cloud/integrated-live-drill-provider-orchestration.js";
import {
  INTEGRATED_LIVE_DRILL_SPEC_SCHEMA,
  integratedSourceBuildIdentity,
  selectedEvidenceBindingSha256
} from "../src/cloud/integrated-live-drill.js";
import {
  __test as supervisorTest,
  INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_INPUT_PATH_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_CONTEXT_PATH_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_PATH_ENVIRONMENT,
  persistIntegratedLiveDrillProviderSupervisorPreparation,
  prepareIntegratedLiveDrillProviderSupervisor,
  resumeIntegratedLiveDrillProviderSupervisor
} from "../scripts/gate1-integrated-live-drill-provider-supervisor.js";
import { principalBindingHash } from "../src/cloud/recovery-broker.js";
import { createRecoveryContinuityFixture } from
  "./helpers/integrated-live-drill-recovery-continuity-fixture.js";

const sha = (value) => createHash("sha256").update(value).digest("hex");
const sourceCommit = "a".repeat(40);
const treeDigest = "b".repeat(40);
const runId = "11111111-1111-4111-8111-111111111111";
const raceId = "22222222-2222-4222-8222-222222222222";
const evidenceId = "33333333-3333-4333-8333-333333333333";
const evidenceDigest = "d".repeat(64);
const authorityBinding = "e".repeat(64);
const operationId = "44444444-4444-4444-8444-444444444444";
const requestDigest = "f".repeat(64);
const functionArn = "arn:aws:lambda:us-east-1:111111111111:function:test:7";
const specWithoutIdentity = Object.freeze({
  schemaVersion: INTEGRATED_LIVE_DRILL_SPEC_SCHEMA,
  authorityArtifactDigest: "3".repeat(64),
  authoritySourceDigest: "2".repeat(64),
  configDigest: "0".repeat(64),
  functionArn,
  maximumAwsCostUsd: "0.02",
  packageLockDigest: "1".repeat(64),
  raceId,
  runId,
  sourceCommit,
  treeDigest
});
const spec = Object.freeze({
  ...specWithoutIdentity,
  sourceBuildIdentity: integratedSourceBuildIdentity(specWithoutIdentity)
});

function withReceipt(body) {
  return Object.freeze({
    ...body,
    receiptSha256: integratedLiveDrillCanonicalSha256(body)
  });
}

function components() {
  const selectedBinding = selectedEvidenceBindingSha256(
    evidenceId,
    evidenceDigest
  );
  const dvi = {
    schemaVersion: "tideproof.gate1.admissible-vector-proof.v2",
    status: "PASS",
    sourceCommit,
    treeDigest,
    drill: {
      runId,
      authorityEvidenceBindingSha256: authorityBinding,
      selectedEvidenceBindingSha256: selectedBinding,
      durableSelectionCommitted: true
    },
    fixture: {
      requiredExclusionsBoundToSnapshot: true,
      nearestExcludedCloserThanRanked: true
    },
    ranking: { vectorSearchUsed: true, exactPrefixSpansUsed: true },
    cleanup: {
      snapshotRetired: true,
      remainingCandidateCount: 0,
      remainingExclusionCount: 0
    }
  };
  const race = {
    schemaVersion: "tideproof.aws-authority-race-receipt.v7",
    status: "PASS",
    sourceCommit,
    treeDigest,
    packageLockDigest: spec.packageLockDigest,
    authoritySourceDigest: spec.authoritySourceDigest,
    authorityArtifactDigest: spec.authorityArtifactDigest,
    configDigest: spec.configDigest,
    raceId,
    runId,
    dvi: {
      authorityEvidenceBindingSha256: authorityBinding,
      selectedEvidenceBindingSha256: selectedBinding
    },
    functionArnDigest: sha(spec.functionArn),
    functionVersion: "7",
    callerBinding: {
      bindingDigest: "4".repeat(64),
      callerIdentityDigest: "5".repeat(64),
      contextDigest: "6".repeat(64),
      expectedIdentityDigest: "5".repeat(64),
      expectedPrincipalDigest: "7".repeat(64),
      principalIdDigest: "8".repeat(64),
      principalType: "assumed-role"
    },
    contenders: 2,
    serializableTransactions: true,
    overlappingDatabaseIntervals: true,
    distinctDatabaseSessions: true,
    distinctLogicalActions: true,
    distinctProposals: true,
    databaseInterval: {
      startedAt: "2026-08-06T12:00:00.000Z",
      completedAt: "2026-08-06T12:00:02.000Z"
    },
    invocationRequestDigests: {
      alpha: "4".repeat(64),
      bravo: "5".repeat(64),
      changedInput: "6".repeat(64),
      proof: "7".repeat(64),
      replay: "8".repeat(64)
    },
    awsInvokeRequestDigests: {
      alpha: "9".repeat(64),
      bravo: "a".repeat(64),
      changedInput: "b".repeat(64),
      proof: "c".repeat(64),
      replay: "d".repeat(64)
    },
    providerOperations: {
      cloudFormationDescribeStackResourceRequests: 1,
      lambdaInvokeRequests: 5,
      stsGetCallerIdentityRequests: 1
    },
    durableStateVerified: true,
    durableState: {
      receiptCount: 2,
      resourceReceiptCount: 2,
      outboxCount: 1,
      protectedEffectCount: 0,
      holderOperationId: operationId,
      outboxOperationId: operationId,
      denialObservedHolderOperationId: operationId,
      denialObservedFence: "1"
    },
    protectedEffectExecuted: false,
    authorityTransferredByModel: false,
    winner: {
      contender: "alpha",
      operationId,
      requestDigest,
      fencingToken: "1"
    },
    denial: {
      contender: "bravo",
      operationId: "77777777-7777-4777-8777-777777777777",
      requestDigest: "e".repeat(64),
      reason: "active_holder"
    },
    replay: {
      contender: "alpha",
      operationId,
      requestDigest,
      outcome: "resource_reserved",
      fencingToken: "1",
      replayKind: "operation_replay",
      exactDecisionReturned: true
    },
    changedInputDenial: {
      contender: "alpha",
      operationId,
      changedRequestDigest: "0".repeat(64),
      code: "OPERATION_DIGEST_MISMATCH",
      denied: true
    }
  };
  return { dvi, race };
}

function supervisorPreparation() {
  const authorizationId = "99999999-9999-4999-8999-999999999999";
  const issuedAt = "2026-08-10T16:00:00.000Z";
  const payload = Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION_SCHEMA,
    authorityStatement: INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORITY_STATEMENT,
    authorizationAttestationSha256: "1".repeat(64),
    authorizationId,
    childAuthorizationIssuedAt: "2026-08-10T15:59:00.000Z",
    expiresAt: "2026-08-10T16:05:00.000Z",
    issuedAt,
    logicalMcpRequestSha256: "2".repeat(64),
    maximumInitializeCount: 1,
    maximumInitializedNotificationCount: 1,
    maximumManagedMcpToolCallCount: 1,
    preCallIntentSha256: "3".repeat(64),
    recoveryBrokerConfigDigest: "4".repeat(64),
    requiredSessionCloseCount: 1,
    requiredToolsCallCount: 1,
    runId,
  });
  return withReceipt(Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_PREPARATION_SCHEMA,
    accepted: false,
    ambiguityBlocker:
      INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_AMBIGUITY_BLOCKER,
    authorizationId,
    authorizationAttestationSha256: payload.authorizationAttestationSha256,
    finalReleaseReady: false,
    logicalMcpRequestSha256: payload.logicalMcpRequestSha256,
    preCallIntentSha256: payload.preCallIntentSha256,
    preparationContextSha256: "5".repeat(64),
    preparationReceiptSha256: "6".repeat(64),
    providerBacked: false,
    recoveryBrokerConfigDigest: payload.recoveryBrokerConfigDigest,
    runId,
    signingPayload: payload,
    signingPayloadSha256: integratedLiveDrillCanonicalSha256(payload),
    stateHistory: [
      INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STATES
        .RECOVERY_PREPARED_AWAITING_EXACT_DISPATCH_AUTHORIZATION
    ],
    status: "AWAITING_AUTHORIZATION"
  }));
}

function preparationArgs() {
  return {
    authorityEvidenceId: evidenceId,
    authoritySelectedEvidenceDigest: evidenceDigest,
    ...components(),
    gate1Preparation: supervisorPreparation(),
    journalIntentBindingSha256: "7".repeat(64),
    journalPathSha256: "8".repeat(64),
    spec
  };
}

test("provider orchestration HOLD binds full legacy DVI/race invariants and exact signing payload", () => {
  const preparation = buildIntegratedLiveDrillProviderOrchestrationPreparation(
    preparationArgs()
  );
  assert.equal(preparation.status, INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_HOLD);
  assert.deepEqual(preparation.stateHistory, [
    "DVI_AND_RACE_DURABLE",
    "RECOVERY_PREPARED_AWAITING_EXACT_DISPATCH_AUTHORIZATION"
  ]);
  const hold = sanitizedIntegratedLiveDrillProviderOrchestrationHold(
    preparation,
    spec
  );
  assert.equal(hold.accepted, false);
  assert.equal(hold.providerBacked, false);
  assert.equal(hold.finalReleaseReady, false);
  assert.equal(hold.signingPayload.runId, runId);

  const badDvi = preparationArgs();
  badDvi.dvi.cleanup.snapshotRetired = false;
  assert.throws(
    () => buildIntegratedLiveDrillProviderOrchestrationPreparation(badDvi),
    /INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_COMPONENT_REJECTED/u
  );

  const substituted = structuredClone(supervisorPreparation());
  substituted.signingPayload.runId =
    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  substituted.signingPayloadSha256 = integratedLiveDrillCanonicalSha256(
    substituted.signingPayload
  );
  delete substituted.receiptSha256;
  substituted.receiptSha256 = integratedLiveDrillCanonicalSha256(substituted);
  assert.throws(
    () => validateIntegratedLiveDrillProviderSupervisorPreparation(substituted),
    /INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_PREPARATION_REJECTED/u
  );
});

test("orchestration boundaries reject accessors, exotic keys, prototypes, and coercible scalars before hashing", () => {
  let getterRuns = 0;
  const getterArgs = preparationArgs();
  Object.defineProperty(getterArgs.dvi.cleanup, "snapshotRetired", {
    enumerable: true,
    get() {
      getterRuns += 1;
      return true;
    }
  });
  assert.throws(
    () => buildIntegratedLiveDrillProviderOrchestrationPreparation(getterArgs),
    /INPUT_REJECTED/u
  );
  assert.equal(getterRuns, 0);

  for (const key of ["__proto__", "constructor", "prototype"]) {
    const changed = preparationArgs();
    Object.defineProperty(changed, key, {
      enumerable: true,
      value: "unexpected"
    });
    assert.throws(
      () => buildIntegratedLiveDrillProviderOrchestrationPreparation(changed),
      /INPUT_REJECTED/u,
      key
    );
  }
  const symbol = preparationArgs();
  symbol[Symbol("unexpected")] = true;
  assert.throws(
    () => buildIntegratedLiveDrillProviderOrchestrationPreparation(symbol),
    /INPUT_REJECTED/u
  );
  const hidden = preparationArgs();
  Object.defineProperty(hidden, "hidden", { value: true });
  assert.throws(
    () => buildIntegratedLiveDrillProviderOrchestrationPreparation(hidden),
    /INPUT_REJECTED/u
  );
  const custom = Object.create({ inherited: true });
  Object.assign(custom, preparationArgs());
  assert.throws(
    () => buildIntegratedLiveDrillProviderOrchestrationPreparation(custom),
    /INPUT_REJECTED/u
  );
  let coercionRuns = 0;
  const coercible = preparationArgs();
  coercible.authorityEvidenceId = {
    [Symbol.toPrimitive]() {
      coercionRuns += 1;
      return evidenceId;
    }
  };
  assert.throws(
    () => buildIntegratedLiveDrillProviderOrchestrationPreparation(coercible),
    /INPUT_REJECTED/u
  );
  assert.equal(coercionRuns, 0);
});

test("checkpoint sidecar binds canonical root and checkpoint file identity across resume", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "pta-orchestration-root-"));
  fs.chmodSync(root, 0o700);
  const moved = `${root}.original`;
  t.after(() => {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(moved, { recursive: true, force: true });
  });
  const checkpointPath = path.join(root, `${runId}.preparation.json`);
  const preparation = buildIntegratedLiveDrillProviderOrchestrationPreparation(
    preparationArgs()
  );
  persistIntegratedLiveDrillProviderOrchestrationPreparation({
    checkpointPath,
    forbiddenRootPath: fs.realpathSync(process.cwd()),
    preparation,
    rootPath: root,
    spec
  });
  const accepted = readIntegratedLiveDrillProviderOrchestrationPreparation({
    checkpointPath,
    forbiddenRootPath: fs.realpathSync(process.cwd()),
    rootPath: root,
    spec
  });
  assert.equal(accepted.preparation.receiptSha256, preparation.receiptSha256);
  assert.match(accepted.persistence.checkpointInode, /^[1-9][0-9]*$/u);
  assert.equal(fs.statSync(checkpointPath).mode & 0o777, 0o600);
  assert.equal(
    fs.statSync(`${checkpointPath}.persistence.json`).mode & 0o777,
    0o600
  );

  fs.renameSync(root, moved);
  fs.mkdirSync(root, { mode: 0o700 });
  fs.copyFileSync(
    path.join(moved, path.basename(checkpointPath)),
    checkpointPath
  );
  fs.copyFileSync(
    path.join(moved, `${path.basename(checkpointPath)}.persistence.json`),
    `${checkpointPath}.persistence.json`
  );
  fs.chmodSync(checkpointPath, 0o600);
  fs.chmodSync(`${checkpointPath}.persistence.json`, 0o600);
  assert.throws(
    () => readIntegratedLiveDrillProviderOrchestrationPreparation({
      checkpointPath,
      forbiddenRootPath: fs.realpathSync(process.cwd()),
      rootPath: root,
      spec
    }),
    /INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_CHECKPOINT_REJECTED/u
  );
  fs.rmSync(root, { recursive: true, force: true });
  fs.renameSync(moved, root);
});

test("UNKNOWN and expired orchestration stops are durable and permanently nonretryable", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "pta-orchestration-stop-"));
  fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const preparation = buildIntegratedLiveDrillProviderOrchestrationPreparation(
    preparationArgs()
  );
  for (const state of [
    INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STATES.UNKNOWN_DO_NOT_ACT,
    INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STATES
      .EXPIRED_FRESH_AUDIT_AUTHORITY_REQUIRED
  ]) {
    const stopPath = path.join(root, `${state}.json`);
    const stop = persistIntegratedLiveDrillProviderOrchestrationStop({
      causeCode: state === "UNKNOWN_DO_NOT_ACT"
        ? "INTEGRATED_LIVE_DRILL_PROVIDER_RECOVERY_UNKNOWN_DO_NOT_ACT"
        : "INTEGRATED_LIVE_DRILL_PROVIDER_POST_EXPIRY_AUDIT_AUTHORIZATION_REQUIRED",
      forbiddenRootPath: fs.realpathSync(process.cwd()),
      preparation,
      rootPath: root,
      state,
      stopPath
    });
    assert.equal(stop.state, state);
    assert.equal(stop.retryPermitted, false);
    assert.equal(stop.accepted, false);
    assert.deepEqual(
      readIntegratedLiveDrillProviderOrchestrationStop({
        forbiddenRootPath: fs.realpathSync(process.cwd()),
        rootPath: root,
        stopPath
      }),
      stop
    );
    assert.equal(canonicalJson(stop), canonicalJson(
      persistIntegratedLiveDrillProviderOrchestrationStop({
        causeCode: state === "UNKNOWN_DO_NOT_ACT"
          ? "INTEGRATED_LIVE_DRILL_PROVIDER_RECOVERY_UNKNOWN_DO_NOT_ACT"
          : "INTEGRATED_LIVE_DRILL_PROVIDER_POST_EXPIRY_AUDIT_AUTHORIZATION_REQUIRED",
        forbiddenRootPath: fs.realpathSync(process.cwd()),
        preparation,
        rootPath: root,
        state,
        stopPath
      })
    ));
  }
});

test("supervisor snapshots options and rejects accessor-bearing worker output before dereference", async (t) => {
  const fixture = createRecoveryContinuityFixture(t, {
    prefix: "pta-orchestration-supervisor-",
    subjectBindingSha256: principalBindingHash(
      "principal://tideproof-demo-successor"
    )
  });
  const contextPath = path.join(
    fixture.context.recoveryEvidenceRootPath,
    "provider-supervisor-context.json"
  );
  const issuedAt = fixture.context.preCallInputs.consumedChildAuthorization
    .attestation.payload.issuedAt;
  const preparation = persistIntegratedLiveDrillProviderSupervisorPreparation({
    context: fixture.context,
    contextPath,
    forbiddenRootPath: fixture.context.forbiddenRootPath,
    issuedAt,
    rootPath: fixture.context.recoveryEvidenceRootPath
  });
  const dispatch = signIntegratedLiveDrillEvidence(
    preparation.signingPayload,
    fixture.testOnly.human.privateKeyPkcs8DerBase64,
    fixture.testOnly.human.publicKey
  );
  const environment = {
    PATH: process.env.PATH,
    MCP_API_KEY: "synthetic-test-only-mcp-api-key-0001",
    PRIMARY_AUDIT_DATABASE_URL: "postgresql://audit.invalid/tideproof",
    TIDEPROOF_INTEGRATED_LIVE_DRILL_FORBIDDEN_ROOT:
      fixture.context.forbiddenRootPath,
    TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_ROOT:
      fixture.context.recoveryEvidenceRootPath,
    [INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_CONTEXT_PATH_ENVIRONMENT]:
      contextPath,
    [INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION_ENVIRONMENT]:
      canonicalJson(dispatch),
    [INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_PATH_ENVIRONMENT]: path.join(
      fixture.context.recoveryEvidenceRootPath,
      "provider-worker-input.json"
    ),
    [INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_INPUT_PATH_ENVIRONMENT]:
      path.join(
        fixture.context.recoveryEvidenceRootPath,
        "provider-finalization-input.json"
      )
  };
  let getterRuns = 0;
  let observedWorkerEnvironment;
  await assert.rejects(
    () => resumeIntegratedLiveDrillProviderSupervisor({
      environment,
      rootDir: fs.realpathSync(process.cwd()),
      runComponent: async (_script, childEnvironment) => {
        observedWorkerEnvironment = childEnvironment;
        const result = { recovery: {} };
        Object.defineProperty(result, "providerContinuity", {
          enumerable: true,
          get() {
            getterRuns += 1;
            return {};
          }
        });
        return result;
      }
    }),
    /INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_INPUT_REJECTED/u
  );
  assert.equal(getterRuns, 0);
  assert.deepEqual(
    Object.keys(observedWorkerEnvironment).sort(),
    [
      "MCP_API_KEY",
      "PATH",
      "PRIMARY_AUDIT_DATABASE_URL",
      "TIDEPROOF_INTEGRATED_LIVE_DRILL_FORBIDDEN_ROOT",
      "TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_ROOT",
      "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_PATH",
      "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_PRINCIPAL"
    ].sort()
  );
  for (const forbidden of [
    "AWS_ACCESS_KEY_ID",
    "HOME",
    "NODE_OPTIONS",
    "PRIMARY_RECOVERY_SOURCE_DATABASE_URL",
    "RECOVERY_PUBLISHER_DATABASE_URL",
    "RECOVERY_PUBLISHER_PRIVATE_KEY_PKCS8_BASE64"
  ]) {
    assert.equal(forbidden in observedWorkerEnvironment, false, forbidden);
  }

  let environmentGetterRuns = 0;
  const options = {};
  Object.defineProperty(options, "environment", {
    enumerable: true,
    get() {
      environmentGetterRuns += 1;
      return environment;
    }
  });
  await assert.rejects(
    () => prepareIntegratedLiveDrillProviderSupervisor(options),
    /INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_OPTIONS_REJECTED/u
  );
  assert.equal(environmentGetterRuns, 0);
});

test("supervisor preserves one exact bounded worker stop code", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "pta-supervisor-stop-"));
  fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const script = path.join(root, "fail-closed-worker.js");
  fs.writeFileSync(
    script,
    "process.stderr.write('INTEGRATED_LIVE_DRILL_PROVIDER_POST_EXPIRY_AUDIT_AUTHORIZATION_REQUIRED\\n'); process.exitCode = 1;\n",
    { mode: 0o600 }
  );
  assert.throws(
    () => supervisorTest.defaultRunComponent(script, {}, root),
    /INTEGRATED_LIVE_DRILL_PROVIDER_POST_EXPIRY_AUDIT_AUTHORIZATION_REQUIRED/u
  );
});
