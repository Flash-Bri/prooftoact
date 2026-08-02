import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  AUTHORITY_PROOF_RESPONSE_SCHEMA,
  AUTHORITY_RACE_RECEIPT_SCHEMA,
  AUTHORITY_REQUEST_SCHEMA,
  authorityProofEvent,
  authorityRaceEvent,
  parseAuthorityRaceArguments,
  runAuthorityRace,
  validateAuthorityRaceInvocations,
  validateAuthorityRaceProof
} from "../src/cloud/aws-authority-race.js";
import {
  authorityPrincipalFromStackResource,
  awsEvidenceClientOptions,
  safeAuthorityRaceFailureCode,
  validateAuthorityRaceExpectedPrincipal
} from "../scripts/gate2-authority-race.js";

const EXPECTED = Object.freeze({
  configDigest: "b".repeat(64),
  functionArn:
    "arn:aws:lambda:us-east-1:111111111111:function:tideproof-authority:7",
  raceId: "55555555-5555-4555-8555-555555555555",
  runId: "66666666-6666-4666-8666-666666666666",
  sourceCommit: "a".repeat(40)
});

const IDS = Object.freeze({
  alpha: "11111111-1111-5111-8111-111111111111",
  bravo: "22222222-2222-5222-8222-222222222222"
});

const CALLER_BINDING = Object.freeze({
  bindingDigest: "5".repeat(64),
  callerIdentityDigest: "6".repeat(64),
  contextDigest: "8".repeat(64),
  expectedIdentityDigest: "6".repeat(64),
  expectedPrincipalDigest: "7".repeat(64),
  principalType: "assumed-role"
});

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map(
      (key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`
    ).join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

function response(contender, options = {}) {
  const winner =
    options.outcome ??
    (contender === "alpha"
      ? "resource_reserved"
      : "resource_held_denied");
  const start =
    options.startedAt ??
    (contender === "alpha"
      ? "2026-08-01T12:00:00.000Z"
      : "2026-08-01T12:00:01.000Z");
  const completed =
    options.completedAt ??
    (contender === "alpha"
      ? "2026-08-01T12:00:02.000Z"
      : "2026-08-01T12:00:03.000Z");
  const proposalDigest =
    contender === "alpha" ? "8".repeat(64) : "a".repeat(64);
  const logicalActionDigest =
    contender === "alpha" ? "9".repeat(64) : "b".repeat(64);
  const logicalAuthorityKeySha256 = sha256({
    schemaVersion: "tideproof.authority.logical-authority-key.v1",
    logicalActionDigest,
    authorizationEpoch: 1
  });
  const authorizationBindingSha256 = sha256({
    schemaVersion: "tideproof.authority.authorization-binding.v1",
    logicalActionDigest,
    proposalDigest,
    authorizationEpoch: 1,
    logicalAuthorityKeySha256
  });
  const body = {
    schemaVersion: "tideproof.aws-authority-boundary.v2",
    status: "COMMITTED",
    raceId: EXPECTED.raceId,
    contender,
    operationId: IDS[contender],
    committedOperationId: IDS[contender],
    requestDigest:
      contender === "alpha" ? "1".repeat(64) : "2".repeat(64),
    committedRequestDigest:
      contender === "alpha" ? "1".repeat(64) : "2".repeat(64),
    proposalDigest,
    committedProposalDigest: proposalDigest,
    logicalActionDigest,
    selectedEvidenceDigest: "0".repeat(64),
    committedSelectedEvidenceId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    committedSelectedEvidenceDigest: "0".repeat(64),
    authorizationEpoch: 1,
    logicalAuthorityKeySha256,
    authorizationBindingSha256,
    outcome: winner,
    reason: winner === "resource_reserved" ? null : "active_holder",
    fencingToken: winner === "resource_reserved" ? "1" : null,
    leaseExpiresAt:
      winner === "resource_reserved"
        ? "2026-08-01T12:05:00.000Z"
        : null,
    replayKind: null,
    commit: {
      schemaVersion: "tideproof.database-commit-result.v1",
      status: "COMMITTED",
      operation: "authority",
      operationDigest:
        contender === "alpha" ? "1".repeat(64) : "2".repeat(64),
      observation: "direct_ack",
      databaseNow: start,
      outcome: winner,
      authority: {
        current: winner === "resource_reserved",
        requiresFreshAuthorization: winner !== "resource_reserved"
      },
      reason: winner === "resource_reserved" ? null : "active_holder"
    },
    transaction: {
      isolation: "serializable",
      attempts: 1,
      retryCodes: [],
      databaseStartedAt: start,
      databaseCompletedAt: completed,
      databaseSessionDigest:
        contender === "alpha" ? "3".repeat(64) : "4".repeat(64)
    },
    invocationRequestId:
      contender === "alpha"
        ? "33333333-3333-4333-8333-333333333333"
        : "44444444-4444-4444-8444-444444444444",
    functionVersion: "7",
    authorityTransferred: false,
    authorityCurrent: winner === "resource_reserved",
    requiresFreshAuthorization: winner !== "resource_reserved",
    modelAccess: false,
    sourceCommit: EXPECTED.sourceCommit,
    configDigest: EXPECTED.configDigest,
    treeDigest: "c".repeat(40),
    packageLockDigest: "d".repeat(64),
    authoritySourceDigest: "e".repeat(64),
    authorityArtifactDigest: "f".repeat(64),
    ...options.body
  };
  return {
    StatusCode: 200,
    ExecutedVersion: options.executedVersion ?? "7",
    Payload: Buffer.from(JSON.stringify(body)),
    $metadata: {
      requestId:
        contender === "alpha"
          ? "aws-invoke-request-alpha"
          : "aws-invoke-request-bravo"
    }
  };
}

function proofResponse(options = {}) {
  const state = {
    activeRunId: EXPECTED.runId,
    currentFence: "1",
    holderOperationId: IDS.alpha,
    outboxOperationId: IDS.alpha,
    observedAt: "2026-08-01T12:00:04.000Z",
    counts: {
      raceReceiptCount: "2",
      resourceReceiptCount: "2",
      reservedCount: "1",
      heldDenialCount: "1",
      pendingCount: "0",
      outboxCount: "1",
      protectedEffectCount: "0",
      ...options.counts
    },
    outcomes: {
      alpha: {
        operationId: IDS.alpha,
        requestDigest: "1".repeat(64),
        outcome: "resource_reserved",
        reason: null,
        fencingToken: "1",
        observedHolderOperationId: null,
        observedFence: null
      },
      bravo: {
        operationId: IDS.bravo,
        requestDigest: "2".repeat(64),
        outcome: "resource_held_denied",
        reason: "active_holder",
        fencingToken: null,
        observedHolderOperationId: IDS.alpha,
        observedFence: "1"
      },
      ...options.outcomes
    },
    ...options.state
  };
  const body = {
    schemaVersion: AUTHORITY_PROOF_RESPONSE_SCHEMA,
    status: "OBSERVED",
    raceId: EXPECTED.raceId,
    transaction: {
      isolation: "serializable",
      databaseObservedAt: "2026-08-01T12:00:04.000Z",
      databaseSessionDigest: "5".repeat(64),
      ...options.transaction
    },
    state,
    invocationRequestId:
      "77777777-7777-4777-8777-777777777777",
    functionVersion: "7",
    readOnly: true,
    authorityTransferred: false,
    requiresFreshAuthorization: true,
    modelAccess: false,
    sourceCommit: EXPECTED.sourceCommit,
    configDigest: EXPECTED.configDigest,
    treeDigest: "c".repeat(40),
    packageLockDigest: "d".repeat(64),
    authoritySourceDigest: "e".repeat(64),
    authorityArtifactDigest: "f".repeat(64),
    ...options.body
  };
  return {
    StatusCode: 200,
    ExecutedVersion: options.executedVersion ?? "7",
    Payload: Buffer.from(JSON.stringify(body)),
    $metadata: {
      requestId: "aws-invoke-request-proof"
    }
  };
}

test("authority race CLI accepts only an exact numeric proof target", () => {
  assert.deepEqual(
    parseAuthorityRaceArguments([
      "--function-arn",
      EXPECTED.functionArn,
      "--race-id",
      EXPECTED.raceId,
      "--run-id",
      EXPECTED.runId,
      "--source-commit",
      EXPECTED.sourceCommit,
      "--config-digest",
      EXPECTED.configDigest
    ]),
    EXPECTED
  );
  for (const argv of [
    [],
    [
      "--function-arn",
      EXPECTED.functionArn.replace(":7", ":proof"),
      "--race-id",
      EXPECTED.raceId,
      "--run-id",
      EXPECTED.runId,
      "--source-commit",
      EXPECTED.sourceCommit,
      "--config-digest",
      EXPECTED.configDigest
    ],
    [
      "--function-arn",
      EXPECTED.functionArn,
      "--race-id",
      EXPECTED.raceId,
      "--run-id",
      "not-a-run-id",
      "--source-commit",
      EXPECTED.sourceCommit,
      "--config-digest",
      EXPECTED.configDigest
    ],
    [
      "--function-arn",
      EXPECTED.functionArn,
      "--function-arn",
      EXPECTED.functionArn,
      "--source-commit",
      EXPECTED.sourceCommit,
      "--config-digest",
      EXPECTED.configDigest
    ]
  ]) {
    assert.throws(
      () => parseAuthorityRaceArguments(argv),
      /AUTHORITY_RACE_ARGUMENTS_REJECTED/
    );
  }
});

test("authority race checkout rejects Git object indirection and binds the tree", async () => {
  const source = await readFile(
    new URL("../scripts/gate2-authority-race.js", import.meta.url),
    "utf8"
  );
  for (const required of [
    'GIT_NO_REPLACE_OBJECTS: "1"',
    '"core.fsmonitor=false"',
    '["replace", "-l"]',
    '"info/grafts"',
    '"objects/info/alternates"',
    '"--is-shallow-repository"',
    'receipt.treeDigest !== checkout.treeDigest'
  ]) {
    assert.equal(source.includes(required), true, required);
  }
});

test("authority race accepts only the generated dedicated caller-role shape", () => {
  const accountId = "111111111111";
  const dedicated =
    `arn:aws:iam::${accountId}:role/` +
    "tideproof-gate2-AuthorityRaceCallerRole-A1B2C3D4";
  assert.equal(
    validateAuthorityRaceExpectedPrincipal(accountId, dedicated),
    dedicated
  );
  for (const untrusted of [
    `arn:aws:iam::${accountId}:role/Admin`,
    `arn:aws:iam::${accountId}:role/AuthorityRaceCallerRole`,
    `arn:aws:iam::222222222222:role/` +
      "tideproof-gate2-AuthorityRaceCallerRole-A1B2C3D4"
  ]) {
    assert.throws(
      () => validateAuthorityRaceExpectedPrincipal(accountId, untrusted),
      /AUTHORITY_RACE_EXPECTED_ROLE_REJECTED/
    );
  }
});

test("authority race derives its expected role from the exact stack resource", () => {
  const accountId = "111111111111";
  const physicalRoleName =
    "tideproof-gate2-AuthorityRaceCallerRole-A1B2C3D4";
  const response = {
    StackResourceDetail: {
      StackName: "tideproof-gate2",
      StackId:
        `arn:aws:cloudformation:us-east-1:${accountId}:stack/` +
        "tideproof-gate2/11111111-1111-4111-8111-111111111111",
      LogicalResourceId: "AuthorityRaceCallerRole",
      PhysicalResourceId: physicalRoleName,
      ResourceType: "AWS::IAM::Role",
      ResourceStatus: "CREATE_COMPLETE"
    }
  };
  assert.equal(
    authorityPrincipalFromStackResource(accountId, response),
    `arn:aws:iam::${accountId}:role/${physicalRoleName}`
  );
  for (const changed of [
    { ...response, StackResourceDetail: { ...response.StackResourceDetail, StackName: "other" } },
    { ...response, StackResourceDetail: { ...response.StackResourceDetail, LogicalResourceId: "Admin" } },
    { ...response, StackResourceDetail: { ...response.StackResourceDetail, PhysicalResourceId: "Admin" } }
  ]) {
    assert.throws(
      () => authorityPrincipalFromStackResource(accountId, changed),
      /AUTHORITY_RACE_STACK_ROLE_REJECTED/
    );
  }
});

test("STS and Lambda evidence clients share one explicit fail-fast option set", () => {
  const credentials = Object.freeze({
    accessKeyId: "ASIAEXAMPLE12345678",
    secretAccessKey: "secret-example-value",
    sessionToken: "session-example-value"
  });
  const requestHandler = Object.freeze({ kind: "bounded-handler" });
  const options = awsEvidenceClientOptions(credentials, requestHandler);
  assert.equal(options.credentials, credentials);
  assert.equal(options.requestHandler, requestHandler);
  assert.equal(options.region, "us-east-1");
  assert.equal(options.maxAttempts, 1);
  assert.equal(options.ignoreConfiguredEndpointUrls, true);
});

test("authority race errors never publish AWS identity or resource details", () => {
  assert.equal(
    safeAuthorityRaceFailureCode(
      new Error("AWS_EVIDENCE_CALLER_ACCOUNT")
    ),
    "AWS_EVIDENCE_CALLER_ACCOUNT"
  );
  assert.equal(
    safeAuthorityRaceFailureCode(
      new Error(
        "AccessDenied for arn:aws:sts::111111111111:assumed-role/Admin/session"
      )
    ),
    "AUTHORITY_RACE_UNKNOWN"
  );
});

test("authority race emits exact contender and proof events without authority fields", () => {
  assert.deepEqual(authorityRaceEvent(EXPECTED.raceId, "alpha"), {
    schemaVersion: AUTHORITY_REQUEST_SCHEMA,
    mode: "reserve",
    raceId: EXPECTED.raceId,
    contender: "alpha"
  });
  assert.throws(
    () => authorityRaceEvent(EXPECTED.raceId, "third"),
    /AUTHORITY_RACE_EVENT_REJECTED/
  );
  assert.deepEqual(authorityProofEvent(EXPECTED.raceId), {
    schemaVersion: AUTHORITY_REQUEST_SCHEMA,
    mode: "proof",
    raceId: EXPECTED.raceId
  });
});

test("authority race requires one overlapping winner and one durable denial", async () => {
  const invoked = [];
  const receipt = await runAuthorityRace({
    ...EXPECTED,
    callerBinding: CALLER_BINDING,
    invoke: async (functionArn, event) => {
      invoked.push({ functionArn, event });
      return event.mode === "proof"
        ? proofResponse()
        : response(event.contender);
    }
  });

  assert.equal(invoked.length, 3);
  assert.equal(
    invoked.every(
      ({ functionArn }) => functionArn === EXPECTED.functionArn
    ),
    true
  );
  assert.equal(receipt.schemaVersion, AUTHORITY_RACE_RECEIPT_SCHEMA);
  assert.equal(receipt.status, "PASS");
  assert.equal(receipt.runId, EXPECTED.runId);
  assert.equal(receipt.contenders, 2);
  assert.equal(receipt.overlappingDatabaseIntervals, true);
  assert.equal(receipt.distinctDatabaseSessions, true);
  assert.equal(receipt.distinctLogicalActions, true);
  assert.equal(receipt.distinctProposals, true);
  assert.equal(receipt.durableStateVerified, true);
  assert.equal(receipt.winner.contender, "alpha");
  assert.equal(receipt.denial.contender, "bravo");
  assert.equal(receipt.durableState.receiptCount, 2);
  assert.equal(receipt.durableState.outboxCount, 1);
  assert.equal(receipt.durableState.protectedEffectCount, 0);
  assert.equal(
    receipt.durableState.denialObservedHolderOperationId,
    receipt.winner.operationId
  );
  assert.equal(
    receipt.durableState.denialObservedFence,
    receipt.winner.fencingToken
  );
  assert.equal(receipt.protectedEffectExecuted, false);
  assert.equal(receipt.authorityTransferredByModel, false);
  assert.deepEqual(receipt.callerBinding, CALLER_BINDING);
  assert.equal("functionArn" in receipt, false);
});

test("authority race rejects non-overlap, numeric-version drift, and outcome drift", () => {
  assert.throws(
    () =>
      validateAuthorityRaceInvocations(
        {
          alpha: response("alpha", {
            completedAt: "2026-08-01T12:00:01.000Z"
          }),
          bravo: response("bravo", {
            startedAt: "2026-08-01T12:00:01.000Z"
          })
        },
        EXPECTED
      ),
    /AUTHORITY_RACE_NOT_OVERLAPPING/
  );
  assert.throws(
    () =>
      validateAuthorityRaceInvocations(
        {
          alpha: response("alpha", {
            completedAt: "2026-08-01T12:00:01.000Z"
          }),
          bravo: response("bravo", {
            startedAt: "2026-08-01T12:00:02.000Z"
          })
        },
        EXPECTED
      ),
    /AUTHORITY_RACE_NOT_OVERLAPPING/
  );
  assert.throws(
    () =>
      validateAuthorityRaceInvocations(
        {
          alpha: response("alpha", { executedVersion: "8" }),
          bravo: response("bravo")
        },
        EXPECTED
      ),
    /AUTHORITY_RACE_RESULT_REJECTED/
  );
  assert.throws(
    () =>
      validateAuthorityRaceInvocations(
        {
          alpha: response("alpha"),
          bravo: response("bravo", {
            outcome: "resource_reserved",
            body: {
              reason: null,
              fencingToken: "1",
              leaseExpiresAt: "2026-08-01T12:05:00.000Z"
            }
          })
        },
        EXPECTED
      ),
    /AUTHORITY_RACE_RESULT_REJECTED/
  );
});

test("authority race requires positive transaction duration, a fresh first fence, and a later canonical lease", () => {
  for (const changedAlpha of [
    response("alpha", {
      startedAt: "2026-08-01T12:00:02.000Z",
      completedAt: "2026-08-01T12:00:02.000Z"
    }),
    response("alpha", {
      body: { fencingToken: "2" }
    }),
    response("alpha", {
      body: { leaseExpiresAt: "not-a-timestamp" }
    }),
    response("alpha", {
      body: { leaseExpiresAt: "2026-08-01T12:00:02.000Z" }
    })
  ]) {
    assert.throws(
      () =>
        validateAuthorityRaceInvocations(
          {
            alpha: changedAlpha,
            bravo: response("bravo")
          },
          EXPECTED
        ),
      /AUTHORITY_RACE_RESPONSE_REJECTED/
    );
  }
});

test("authority race rejects response expansion and model authority", () => {
  assert.throws(
    () =>
      validateAuthorityRaceInvocations(
        {
          alpha: response("alpha", {
            body: { leakedSecret: true }
          }),
          bravo: response("bravo")
        },
        EXPECTED
      ),
    /AUTHORITY_RACE_RESPONSE_REJECTED/
  );
  assert.throws(
    () =>
      validateAuthorityRaceInvocations(
        {
          alpha: response("alpha", {
            body: { authorityTransferred: true }
          }),
          bravo: response("bravo")
        },
        EXPECTED
      ),
    /AUTHORITY_RACE_RESPONSE_REJECTED/
  );
});

test("authority race rejects durable proof drift, expansion, and stale observation", () => {
  const observation = validateAuthorityRaceInvocations(
    {
      alpha: response("alpha"),
      bravo: response("bravo")
    },
    EXPECTED
  );
  for (const proof of [
    proofResponse({ counts: { protectedEffectCount: "1" } }),
    proofResponse({ counts: { resourceReceiptCount: "3" } }),
    proofResponse({ state: { activeRunId: "not-a-run-id" } }),
    proofResponse({
      state: {
        activeRunId: "77777777-7777-4777-8777-777777777777"
      }
    }),
    proofResponse({ state: { outboxOperationId: IDS.bravo } }),
    proofResponse({
      outcomes: {
        alpha: {
          operationId: IDS.alpha,
          requestDigest: "1".repeat(64),
          outcome: "resource_reserved",
          reason: null,
          fencingToken: "2",
          observedHolderOperationId: null,
          observedFence: null
        }
      }
    }),
    proofResponse({
      outcomes: {
        bravo: {
          operationId: IDS.bravo,
          requestDigest: "2".repeat(64),
          outcome: "resource_held_denied",
          reason: "active_holder",
          fencingToken: null,
          observedHolderOperationId: IDS.bravo,
          observedFence: "1"
        }
      }
    }),
    proofResponse({
      state: { observedAt: "2026-08-01T12:00:02.000Z" },
      transaction: {
        databaseObservedAt: "2026-08-01T12:00:02.000Z"
      }
    }),
    proofResponse({ body: { leakedSecret: true } })
  ]) {
    assert.throws(
      () =>
        validateAuthorityRaceProof(
          proof,
          observation,
          EXPECTED,
          CALLER_BINDING
        ),
      /AUTHORITY_RACE_PROOF_REJECTED/
    );
  }
  const otherRunId = "77777777-7777-4777-8777-777777777777";
  assert.throws(
    () =>
      validateAuthorityRaceProof(
        proofResponse({ state: { activeRunId: otherRunId } }),
        observation,
        { ...EXPECTED, runId: otherRunId },
        CALLER_BINDING
      ),
    /AUTHORITY_RACE_PROOF_REJECTED/
  );
  assert.throws(
    () =>
      validateAuthorityRaceProof(
        proofResponse(),
        { ...observation, unexpected: true },
        EXPECTED,
        CALLER_BINDING
      ),
    /AUTHORITY_RACE_PROOF_REJECTED/
  );
  assert.throws(
    () =>
      validateAuthorityRaceProof(
        proofResponse(),
        { ...observation },
        EXPECTED,
        CALLER_BINDING
      ),
    /AUTHORITY_RACE_PROOF_REJECTED/
  );
  const expiringObservation = validateAuthorityRaceInvocations(
    {
      alpha: response("alpha", {
        body: { leaseExpiresAt: "2026-08-01T12:00:04.000Z" }
      }),
      bravo: response("bravo")
    },
    EXPECTED
  );
  assert.throws(
    () =>
      validateAuthorityRaceProof(
        proofResponse(),
        expiringObservation,
        EXPECTED,
        CALLER_BINDING
      ),
    /AUTHORITY_RACE_PROOF_REJECTED/
  );
});
