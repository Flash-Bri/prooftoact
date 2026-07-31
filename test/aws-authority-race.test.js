import assert from "node:assert/strict";
import test from "node:test";
import {
  AUTHORITY_RACE_RECEIPT_SCHEMA,
  AUTHORITY_REQUEST_SCHEMA,
  authorityRaceEvent,
  parseAuthorityRaceArguments,
  runAuthorityRace,
  validateAuthorityRaceInvocations
} from "../src/cloud/aws-authority-race.js";

const EXPECTED = Object.freeze({
  configDigest: "b".repeat(64),
  functionArn:
    "arn:aws:lambda:us-east-1:111111111111:function:tideproof-authority:proof",
  raceId: "55555555-5555-4555-8555-555555555555",
  sourceCommit: "a".repeat(40)
});

const IDS = Object.freeze({
  alpha: "11111111-1111-5111-8111-111111111111",
  bravo: "22222222-2222-5222-8222-222222222222"
});

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
  const body = {
    schemaVersion: "tideproof.aws-authority-boundary.v2",
    status: "COMMITTED",
    raceId: EXPECTED.raceId,
    contender,
    operationId: IDS[contender],
    requestDigest:
      contender === "alpha" ? "1".repeat(64) : "2".repeat(64),
    outcome: winner,
    reason: winner === "resource_reserved" ? null : "active_holder",
    fencingToken: winner === "resource_reserved" ? "1" : null,
    leaseExpiresAt:
      winner === "resource_reserved"
        ? "2026-08-01T12:05:00.000Z"
        : null,
    replayKind: null,
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
    requiresFreshAuthorization: false,
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

test("authority race CLI accepts only an exact aliased proof target", () => {
  assert.deepEqual(
    parseAuthorityRaceArguments([
      "--function-arn",
      EXPECTED.functionArn,
      "--race-id",
      EXPECTED.raceId,
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
      EXPECTED.functionArn.replace(":proof", ""),
      "--race-id",
      EXPECTED.raceId,
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

test("authority race emits exactly two non-authority-bearing events", () => {
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
});

test("authority race requires one overlapping winner and one durable denial", async () => {
  const invoked = [];
  const receipt = await runAuthorityRace({
    ...EXPECTED,
    invoke: async (functionArn, event) => {
      invoked.push({ functionArn, event });
      return response(event.contender);
    }
  });

  assert.equal(invoked.length, 2);
  assert.equal(
    invoked.every(
      ({ functionArn }) => functionArn === EXPECTED.functionArn
    ),
    true
  );
  assert.equal(receipt.schemaVersion, AUTHORITY_RACE_RECEIPT_SCHEMA);
  assert.equal(receipt.status, "PASS");
  assert.equal(receipt.contenders, 2);
  assert.equal(receipt.overlappingDatabaseIntervals, true);
  assert.equal(receipt.distinctDatabaseSessions, true);
  assert.equal(receipt.winner.contender, "alpha");
  assert.equal(receipt.denial.contender, "bravo");
  assert.equal(receipt.protectedEffectExecuted, false);
  assert.equal(receipt.authorityTransferredByModel, false);
  assert.equal("functionArn" in receipt, false);
});

test("authority race rejects non-overlap, alias drift, and outcome drift", () => {
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
              fencingToken: "2",
              leaseExpiresAt: "2026-08-01T12:05:00.000Z"
            }
          })
        },
        EXPECTED
      ),
    /AUTHORITY_RACE_RESULT_REJECTED/
  );
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
