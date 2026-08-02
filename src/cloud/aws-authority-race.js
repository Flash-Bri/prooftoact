import crypto from "node:crypto";

export const AUTHORITY_REQUEST_SCHEMA =
  "tideproof.aws-authority-request.v2";
export const AUTHORITY_RESPONSE_SCHEMA =
  "tideproof.aws-authority-boundary.v2";
export const AUTHORITY_PROOF_RESPONSE_SCHEMA =
  "tideproof.aws-authority-durable-proof.v1";
export const AUTHORITY_RACE_RECEIPT_SCHEMA =
  "tideproof.aws-authority-race-receipt.v5";
const AUTHORITY_RACE_OBSERVATION_SCHEMA =
  "tideproof.aws-authority-race-observation.v3";

const CONTENDERS = Object.freeze(["alpha", "bravo"]);
const INITIAL_FENCING_TOKEN = "1";
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const SHA1_PATTERN = /^[0-9a-f]{40}$/;
const validatedObservationBindings = new WeakMap();

function exactKeys(value, allowed) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join("\n") === [...allowed].sort().join("\n")
  );
}

function sha256Hex(value) {
  return crypto
    .createHash("sha256")
    .update(String(value))
    .digest("hex");
}

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function validatedCallerBinding(value) {
  if (
    !exactKeys(value, [
      "bindingDigest",
      "callerIdentityDigest",
      "contextDigest",
      "expectedIdentityDigest",
      "expectedPrincipalDigest",
      "principalType"
    ]) ||
    !SHA256_PATTERN.test(value.bindingDigest) ||
    !SHA256_PATTERN.test(value.callerIdentityDigest) ||
    !SHA256_PATTERN.test(value.contextDigest) ||
    value.expectedIdentityDigest !== value.callerIdentityDigest ||
    !SHA256_PATTERN.test(value.expectedPrincipalDigest) ||
    value.principalType !== "assumed-role"
  ) {
    throw new Error("AUTHORITY_RACE_CALLER_BINDING_REJECTED");
  }
  return Object.freeze({ ...value });
}

function parseIso(value, code) {
  if (
    typeof value !== "string" ||
    value.length > 40 ||
    !Number.isFinite(Date.parse(value)) ||
    new Date(value).toISOString() !== value
  ) {
    throw new Error(code);
  }
  return Date.parse(value);
}

export function parseAuthorityRaceArguments(argv) {
  const names = [
    "--config-digest",
    "--function-arn",
    "--race-id",
    "--run-id",
    "--source-commit"
  ];
  if (
    !Array.isArray(argv) ||
    argv.length !== names.length * 2 ||
    argv.some((value) => typeof value !== "string")
  ) {
    throw new Error("AUTHORITY_RACE_ARGUMENTS_REJECTED");
  }
  const parsed = {};
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!names.includes(name) || name in parsed || value.length === 0) {
      throw new Error("AUTHORITY_RACE_ARGUMENTS_REJECTED");
    }
    parsed[name] = value;
  }
  if (
    !SHA256_PATTERN.test(parsed["--config-digest"]) ||
    !SHA1_PATTERN.test(parsed["--source-commit"]) ||
    !UUID_PATTERN.test(parsed["--race-id"]) ||
    !UUID_PATTERN.test(parsed["--run-id"]) ||
    !/^arn:aws[a-zA-Z-]*:lambda:us-east-1:\d{12}:function:[A-Za-z0-9-_]{1,64}:proof$/.test(
      parsed["--function-arn"]
    )
  ) {
    throw new Error("AUTHORITY_RACE_ARGUMENTS_REJECTED");
  }
  return {
    configDigest: parsed["--config-digest"],
    functionArn: parsed["--function-arn"],
    raceId: parsed["--race-id"],
    runId: parsed["--run-id"],
    sourceCommit: parsed["--source-commit"]
  };
}

export function authorityRaceEvent(raceId, contender) {
  if (!UUID_PATTERN.test(raceId) || !CONTENDERS.includes(contender)) {
    throw new Error("AUTHORITY_RACE_EVENT_REJECTED");
  }
  return {
    schemaVersion: AUTHORITY_REQUEST_SCHEMA,
    mode: "reserve",
    raceId,
    contender
  };
}

export function authorityProofEvent(raceId) {
  if (!UUID_PATTERN.test(raceId)) {
    throw new Error("AUTHORITY_RACE_EVENT_REJECTED");
  }
  return {
    schemaVersion: AUTHORITY_REQUEST_SCHEMA,
    mode: "proof",
    raceId
  };
}

function invocationBody(value) {
  if (
    value?.FunctionError !== undefined ||
    value?.StatusCode !== 200 ||
    !value.Payload ||
    typeof value.ExecutedVersion !== "string" ||
    !/^[1-9][0-9]*$/.test(value.ExecutedVersion)
  ) {
    throw new Error("AUTHORITY_RACE_INVOCATION_REJECTED");
  }
  let parsed;
  try {
    parsed = JSON.parse(Buffer.from(value.Payload).toString("utf8"));
  } catch {
    throw new Error("AUTHORITY_RACE_INVOCATION_REJECTED");
  }
  const requestId = value?.$metadata?.requestId;
  if (
    typeof requestId !== "string" ||
    requestId.length < 8 ||
    requestId.length > 180
  ) {
    throw new Error("AUTHORITY_RACE_INVOCATION_REJECTED");
  }
  return {
    body: parsed,
    executedVersion: value.ExecutedVersion,
    invokeRequestDigest: sha256Hex(requestId)
  };
}

function validateCommittedResponse(
  value,
  contender,
  expected
) {
  const allowedKeys = [
    "authorityArtifactDigest",
    "authorityCurrent",
    "authoritySourceDigest",
    "authorityTransferred",
    "authorizationBindingSha256",
    "authorizationEpoch",
    "committedOperationId",
    "committedProposalDigest",
    "committedRequestDigest",
    "committedSelectedEvidenceDigest",
    "committedSelectedEvidenceId",
    "commit",
    "configDigest",
    "contender",
    "fencingToken",
    "functionVersion",
    "invocationRequestId",
    "leaseExpiresAt",
    "logicalActionDigest",
    "logicalAuthorityKeySha256",
    "modelAccess",
    "operationId",
    "outcome",
    "packageLockDigest",
    "proposalDigest",
    "raceId",
    "reason",
    "replayKind",
    "requestDigest",
    "requiresFreshAuthorization",
    "schemaVersion",
    "selectedEvidenceDigest",
    "sourceCommit",
    "status",
    "transaction",
    "treeDigest"
  ];
  if (
    !exactKeys(value, allowedKeys) ||
    value.schemaVersion !== AUTHORITY_RESPONSE_SCHEMA ||
    value.status !== "COMMITTED" ||
    value.raceId !== expected.raceId ||
    value.contender !== contender ||
    value.sourceCommit !== expected.sourceCommit ||
    value.configDigest !== expected.configDigest ||
    value.authorityTransferred !== false ||
    typeof value.authorityCurrent !== "boolean" ||
    value.requiresFreshAuthorization === value.authorityCurrent ||
    value.modelAccess !== false ||
    !UUID_PATTERN.test(value.operationId) ||
    value.committedOperationId !== value.operationId ||
    !SHA256_PATTERN.test(value.requestDigest) ||
    value.committedRequestDigest !== value.requestDigest ||
    !Number.isSafeInteger(value.authorizationEpoch) ||
    value.authorizationEpoch < 1 ||
    !SHA256_PATTERN.test(value.logicalAuthorityKeySha256) ||
    !SHA256_PATTERN.test(value.authorizationBindingSha256) ||
    !SHA256_PATTERN.test(value.proposalDigest) ||
    value.committedProposalDigest !== value.proposalDigest ||
    !SHA256_PATTERN.test(value.logicalActionDigest) ||
    !SHA256_PATTERN.test(value.selectedEvidenceDigest) ||
    value.committedSelectedEvidenceDigest !== value.selectedEvidenceDigest ||
    !UUID_PATTERN.test(value.committedSelectedEvidenceId) ||
    !SHA256_PATTERN.test(value.authorityArtifactDigest) ||
    !SHA256_PATTERN.test(value.authoritySourceDigest) ||
    !SHA256_PATTERN.test(value.packageLockDigest) ||
    !SHA1_PATTERN.test(value.treeDigest) ||
    typeof value.functionVersion !== "string" ||
    !/^[1-9][0-9]*$/.test(value.functionVersion) ||
    typeof value.invocationRequestId !== "string" ||
    value.invocationRequestId.length < 8 ||
    value.invocationRequestId.length > 160 ||
    !["resource_reserved", "resource_held_denied"].includes(
      value.outcome
    ) ||
    value.replayKind !== null
  ) {
    throw new Error("AUTHORITY_RACE_RESPONSE_REJECTED");
  }
  if (
    !exactKeys(value.commit, [
      "authority",
      "databaseNow",
      "observation",
      "operation",
      "operationDigest",
      "outcome",
      "reason",
      "schemaVersion",
      "status"
    ]) ||
    value.commit.schemaVersion !== "tideproof.database-commit-result.v1" ||
    value.commit.status !== "COMMITTED" ||
    value.commit.operation !== "authority" ||
    value.commit.operationDigest !== value.committedRequestDigest ||
    value.commit.observation !== "direct_ack" ||
    value.commit.outcome !== value.outcome ||
    value.commit.reason !== value.reason ||
    !exactKeys(value.commit.authority, [
      "current",
      "requiresFreshAuthorization"
    ]) ||
    value.commit.authority.current !== value.authorityCurrent ||
    value.commit.authority.requiresFreshAuthorization !==
      value.requiresFreshAuthorization
  ) {
    throw new Error("AUTHORITY_RACE_RESPONSE_REJECTED");
  }
  const commitDatabaseNow = parseIso(
    value.commit.databaseNow,
    "AUTHORITY_RACE_RESPONSE_REJECTED"
  );
  const expectedLogicalAuthorityKeySha256 = sha256Hex(canonicalJson({
    schemaVersion: "tideproof.authority.logical-authority-key.v1",
    logicalActionDigest: value.logicalActionDigest,
    authorizationEpoch: value.authorizationEpoch
  }));
  const expectedAuthorizationBindingSha256 = sha256Hex(canonicalJson({
    schemaVersion: "tideproof.authority.authorization-binding.v1",
    logicalActionDigest: value.logicalActionDigest,
    proposalDigest: value.committedProposalDigest,
    authorizationEpoch: value.authorizationEpoch,
    logicalAuthorityKeySha256: expectedLogicalAuthorityKeySha256
  }));
  if (
    value.logicalAuthorityKeySha256 !==
      expectedLogicalAuthorityKeySha256 ||
    value.authorizationBindingSha256 !==
      expectedAuthorizationBindingSha256
  ) {
    throw new Error("AUTHORITY_RACE_RESPONSE_REJECTED");
  }
  if (
    !exactKeys(value.transaction, [
      "attempts",
      "databaseCompletedAt",
      "databaseSessionDigest",
      "databaseStartedAt",
      "isolation",
      "retryCodes"
    ]) ||
    value.transaction.isolation !== "serializable" ||
    !Number.isSafeInteger(value.transaction.attempts) ||
    value.transaction.attempts < 1 ||
    value.transaction.attempts > 7 ||
    !Array.isArray(value.transaction.retryCodes) ||
    !value.transaction.retryCodes.every((code) => code === "40001") ||
    !SHA256_PATTERN.test(value.transaction.databaseSessionDigest)
  ) {
    throw new Error("AUTHORITY_RACE_RESPONSE_REJECTED");
  }
  const startedAt = parseIso(
    value.transaction.databaseStartedAt,
    "AUTHORITY_RACE_RESPONSE_REJECTED"
  );
  const completedAt = parseIso(
    value.transaction.databaseCompletedAt,
    "AUTHORITY_RACE_RESPONSE_REJECTED"
  );
  if (completedAt <= startedAt) {
    throw new Error("AUTHORITY_RACE_RESPONSE_REJECTED");
  }
  if (commitDatabaseNow > completedAt) {
    throw new Error("AUTHORITY_RACE_RESPONSE_REJECTED");
  }
  let leaseExpiresAt = null;
  if (value.outcome === "resource_reserved") {
    if (
      value.fencingToken !== INITIAL_FENCING_TOKEN ||
      value.authorityCurrent !== true
    ) {
      throw new Error("AUTHORITY_RACE_RESPONSE_REJECTED");
    }
    leaseExpiresAt = parseIso(
      value.leaseExpiresAt,
      "AUTHORITY_RACE_RESPONSE_REJECTED"
    );
    if (leaseExpiresAt <= completedAt) {
      throw new Error("AUTHORITY_RACE_RESPONSE_REJECTED");
    }
  }
  if (
    value.outcome === "resource_held_denied" &&
    (value.fencingToken !== null ||
      value.leaseExpiresAt !== null ||
      value.reason !== "active_holder" ||
      value.authorityCurrent !== false)
  ) {
    throw new Error("AUTHORITY_RACE_RESPONSE_REJECTED");
  }
  return {
    value,
    startedAt,
    completedAt,
    leaseExpiresAt
  };
}

export function validateAuthorityRaceInvocations(
  invocations,
  expected
) {
  if (
    !exactKeys(invocations, CONTENDERS) ||
    !exactKeys(expected, [
      "configDigest",
      "functionArn",
      "raceId",
      "runId",
      "sourceCommit"
    ])
  ) {
    throw new Error("AUTHORITY_RACE_RESULT_REJECTED");
  }
  const decoded = Object.fromEntries(
    CONTENDERS.map((contender) => [
      contender,
      invocationBody(invocations[contender])
    ])
  );
  const validated = Object.fromEntries(
    CONTENDERS.map((contender) => [
      contender,
      validateCommittedResponse(
        decoded[contender].body,
        contender,
        expected
      )
    ])
  );
  const values = CONTENDERS.map(
    (contender) => validated[contender].value
  );
  const winners = values.filter(
    ({ outcome }) => outcome === "resource_reserved"
  );
  const denials = values.filter(
    ({ outcome }) => outcome === "resource_held_denied"
  );
  if (
    winners.length !== 1 ||
    denials.length !== 1 ||
    CONTENDERS.some(
      (contender) =>
        decoded[contender].executedVersion !==
        validated[contender].value.functionVersion
    ) ||
    new Set(values.map(({ operationId }) => operationId)).size !== 2 ||
    new Set(values.map(({ requestDigest }) => requestDigest)).size !== 2 ||
    new Set(
      values.map(({ invocationRequestId }) => invocationRequestId)
    ).size !== 2 ||
    new Set(
      values.map(
        ({ transaction }) => transaction.databaseSessionDigest
      )
    ).size !== 2 ||
    new Set(values.map(({ functionVersion }) => functionVersion))
      .size !== 1 ||
    new Set(values.map(({ treeDigest }) => treeDigest)).size !== 1 ||
    new Set(values.map(({ packageLockDigest }) => packageLockDigest))
      .size !== 1 ||
    new Set(
      values.map(({ authoritySourceDigest }) => authoritySourceDigest)
    ).size !== 1 ||
    new Set(
      values.map(
        ({ authorityArtifactDigest }) => authorityArtifactDigest
      )
    ).size !== 1 ||
    new Set(values.map(({ proposalDigest }) => proposalDigest)).size !== 2 ||
    new Set(values.map(({ logicalActionDigest }) => logicalActionDigest))
      .size !== 2 ||
    new Set(values.map(({ authorizationEpoch }) => authorizationEpoch))
      .size !== 1 ||
    new Set(
      values.map(
        ({ logicalAuthorityKeySha256 }) => logicalAuthorityKeySha256
      )
    ).size !== 2 ||
    new Set(
      values.map(
        ({ authorizationBindingSha256 }) => authorizationBindingSha256
      )
    ).size !== 2
  ) {
    throw new Error("AUTHORITY_RACE_RESULT_REJECTED");
  }
  const overlapStarts = CONTENDERS.map(
    (contender) => validated[contender].startedAt
  );
  const overlapEnds = CONTENDERS.map(
    (contender) => validated[contender].completedAt
  );
  if (Math.max(...overlapStarts) >= Math.min(...overlapEnds)) {
    throw new Error("AUTHORITY_RACE_NOT_OVERLAPPING");
  }
  const winner = winners[0];
  const denial = denials[0];
  const observation = {
    schemaVersion: AUTHORITY_RACE_OBSERVATION_SCHEMA,
    status: "RACE_OBSERVED",
    sourceCommit: expected.sourceCommit,
    configDigest: expected.configDigest,
    treeDigest: winner.treeDigest,
    packageLockDigest: winner.packageLockDigest,
    authoritySourceDigest: winner.authoritySourceDigest,
    authorityArtifactDigest: winner.authorityArtifactDigest,
    raceId: expected.raceId,
    runId: expected.runId,
    functionArnDigest: sha256Hex(expected.functionArn),
    functionVersion: winner.functionVersion,
    contenders: 2,
    serializableTransactions: true,
    overlappingDatabaseIntervals: true,
    distinctDatabaseSessions: true,
    distinctLogicalActions: true,
    distinctProposals: true,
    winner: {
      contender: winner.contender,
      operationId: winner.operationId,
      requestDigest: winner.requestDigest,
      fencingToken: winner.fencingToken
    },
    denial: {
      contender: denial.contender,
      operationId: denial.operationId,
      requestDigest: denial.requestDigest,
      reason: denial.reason
    },
    databaseInterval: {
      startedAt: new Date(Math.min(...overlapStarts)).toISOString(),
      completedAt: new Date(Math.max(...overlapEnds)).toISOString()
    },
    invocationRequestDigests: Object.fromEntries(
      CONTENDERS.map((contender) => [
        contender,
        sha256Hex(decoded[contender].body.invocationRequestId)
      ])
    ),
    awsInvokeRequestDigests: Object.fromEntries(
      CONTENDERS.map((contender) => [
        contender,
        decoded[contender].invokeRequestDigest
      ])
    ),
    authorityTransferredByModel: false,
    durableStateVerified: false
  };
  validatedObservationBindings.set(observation, {
    digest: sha256Hex(JSON.stringify(observation)),
    leaseExpiresAt: validated[winner.contender].leaseExpiresAt
  });
  return observation;
}

export function validateAuthorityRaceProof(
  invocation,
  observation,
  expected,
  callerBinding
) {
  const acceptedCallerBinding = validatedCallerBinding(callerBinding);
  const observationBinding = validatedObservationBindings.get(observation);
  if (
    !observationBinding ||
    observationBinding.digest !== sha256Hex(JSON.stringify(observation)) ||
    !exactKeys(expected, [
      "configDigest",
      "functionArn",
      "raceId",
      "runId",
      "sourceCommit"
    ]) ||
    !exactKeys(observation, [
      "authorityArtifactDigest",
      "authoritySourceDigest",
      "authorityTransferredByModel",
      "awsInvokeRequestDigests",
      "configDigest",
      "contenders",
      "databaseInterval",
      "denial",
      "distinctDatabaseSessions",
      "distinctLogicalActions",
      "distinctProposals",
      "durableStateVerified",
      "functionArnDigest",
      "functionVersion",
      "invocationRequestDigests",
      "overlappingDatabaseIntervals",
      "packageLockDigest",
      "raceId",
      "runId",
      "schemaVersion",
      "serializableTransactions",
      "sourceCommit",
      "status",
      "treeDigest",
      "winner"
    ]) ||
    observation?.schemaVersion !==
      AUTHORITY_RACE_OBSERVATION_SCHEMA ||
    observation.status !== "RACE_OBSERVED" ||
    observation.sourceCommit !== expected.sourceCommit ||
    observation.configDigest !== expected.configDigest ||
    observation.raceId !== expected.raceId ||
    observation.runId !== expected.runId ||
    observation.functionArnDigest !== sha256Hex(expected.functionArn)
    || observation.distinctLogicalActions !== true
    || observation.distinctProposals !== true
  ) {
    throw new Error("AUTHORITY_RACE_PROOF_REJECTED");
  }
  const decoded = invocationBody(invocation);
  const value = decoded.body;
  if (
    !exactKeys(value, [
      "authorityArtifactDigest",
      "authoritySourceDigest",
      "authorityTransferred",
      "configDigest",
      "functionVersion",
      "invocationRequestId",
      "modelAccess",
      "packageLockDigest",
      "raceId",
      "readOnly",
      "requiresFreshAuthorization",
      "schemaVersion",
      "sourceCommit",
      "state",
      "status",
      "transaction",
      "treeDigest"
    ]) ||
    value.schemaVersion !== AUTHORITY_PROOF_RESPONSE_SCHEMA ||
    value.status !== "OBSERVED" ||
    value.raceId !== expected.raceId ||
    value.sourceCommit !== expected.sourceCommit ||
    value.configDigest !== expected.configDigest ||
    value.treeDigest !== observation.treeDigest ||
    value.packageLockDigest !== observation.packageLockDigest ||
    value.authoritySourceDigest !==
      observation.authoritySourceDigest ||
    value.authorityArtifactDigest !==
      observation.authorityArtifactDigest ||
    value.functionVersion !== observation.functionVersion ||
    value.functionVersion !== decoded.executedVersion ||
    value.readOnly !== true ||
    value.authorityTransferred !== false ||
    value.requiresFreshAuthorization !== true ||
    value.modelAccess !== false ||
    typeof value.invocationRequestId !== "string" ||
    value.invocationRequestId.length < 8 ||
    value.invocationRequestId.length > 160
  ) {
    throw new Error("AUTHORITY_RACE_PROOF_REJECTED");
  }
  const transaction = value.transaction;
  const state = value.state;
  const counts = state?.counts;
  const outcomes = state?.outcomes;
  if (
    !exactKeys(transaction, [
      "databaseObservedAt",
      "databaseSessionDigest",
      "isolation"
    ]) ||
    transaction.isolation !== "serializable" ||
    !SHA256_PATTERN.test(transaction.databaseSessionDigest) ||
    !exactKeys(state, [
      "activeRunId",
      "counts",
      "currentFence",
      "holderOperationId",
      "observedAt",
      "outboxOperationId",
      "outcomes"
    ]) ||
    !exactKeys(counts, [
      "heldDenialCount",
      "outboxCount",
      "pendingCount",
      "protectedEffectCount",
      "raceReceiptCount",
      "reservedCount",
      "resourceReceiptCount"
    ]) ||
    !exactKeys(outcomes, CONTENDERS) ||
    !CONTENDERS.every((contender) =>
      exactKeys(outcomes[contender], [
        "fencingToken",
        "observedFence",
        "observedHolderOperationId",
        "operationId",
        "outcome",
        "reason",
        "requestDigest"
      ])
    ) ||
    !UUID_PATTERN.test(state.activeRunId) ||
    state.activeRunId !== expected.runId ||
    !/^[1-9][0-9]*$/.test(state.currentFence) ||
    counts.raceReceiptCount !== "2" ||
    counts.resourceReceiptCount !== "2" ||
    counts.reservedCount !== "1" ||
    counts.heldDenialCount !== "1" ||
    counts.pendingCount !== "0" ||
    counts.outboxCount !== "1" ||
    counts.protectedEffectCount !== "0" ||
    state.currentFence !== observation.winner.fencingToken ||
    state.holderOperationId !== observation.winner.operationId ||
    state.outboxOperationId !== observation.winner.operationId ||
    outcomes[observation.winner.contender].operationId !==
      observation.winner.operationId ||
    outcomes[observation.winner.contender].requestDigest !==
      observation.winner.requestDigest ||
    outcomes[observation.winner.contender].outcome !==
      "resource_reserved" ||
    outcomes[observation.winner.contender].reason !== null ||
    outcomes[observation.winner.contender].fencingToken !==
      observation.winner.fencingToken ||
    outcomes[observation.winner.contender]
      .observedHolderOperationId !== null ||
    outcomes[observation.winner.contender].observedFence !== null ||
    outcomes[observation.denial.contender].operationId !==
      observation.denial.operationId ||
    outcomes[observation.denial.contender].requestDigest !==
      observation.denial.requestDigest ||
    outcomes[observation.denial.contender].outcome !==
      "resource_held_denied" ||
    outcomes[observation.denial.contender].reason !== "active_holder" ||
    outcomes[observation.denial.contender].fencingToken !== null ||
    outcomes[observation.denial.contender]
      .observedHolderOperationId !==
      observation.winner.operationId ||
    outcomes[observation.denial.contender].observedFence !==
      observation.winner.fencingToken
  ) {
    throw new Error("AUTHORITY_RACE_PROOF_REJECTED");
  }
  const stateObservedAt = parseIso(
    state.observedAt,
    "AUTHORITY_RACE_PROOF_REJECTED"
  );
  const transactionObservedAt = parseIso(
    transaction.databaseObservedAt,
    "AUTHORITY_RACE_PROOF_REJECTED"
  );
  if (
    stateObservedAt !== transactionObservedAt ||
    stateObservedAt < Date.parse(observation.databaseInterval.completedAt) ||
    stateObservedAt >= observationBinding.leaseExpiresAt
  ) {
    throw new Error("AUTHORITY_RACE_PROOF_REJECTED");
  }
  return {
    ...observation,
    schemaVersion: AUTHORITY_RACE_RECEIPT_SCHEMA,
    status: "PASS",
    callerBinding: acceptedCallerBinding,
    durableStateVerified: true,
    durableState: {
      observedAt: state.observedAt,
      currentFence: state.currentFence,
      holderOperationId: state.holderOperationId,
      receiptCount: 2,
      resourceReceiptCount: 2,
      outboxCount: 1,
      outboxOperationId: state.outboxOperationId,
      protectedEffectCount: 0,
      denialObservedHolderOperationId:
        outcomes[observation.denial.contender]
          .observedHolderOperationId,
      denialObservedFence:
        outcomes[observation.denial.contender].observedFence,
      databaseSessionDigest: transaction.databaseSessionDigest
    },
    protectedEffectExecuted: false,
    invocationRequestDigests: {
      ...observation.invocationRequestDigests,
      proof: sha256Hex(value.invocationRequestId)
    },
    awsInvokeRequestDigests: {
      ...observation.awsInvokeRequestDigests,
      proof: decoded.invokeRequestDigest
    }
  };
}

export async function runAuthorityRace({
  configDigest,
  functionArn,
  raceId,
  runId,
  sourceCommit,
  callerBinding,
  invoke
}) {
  if (typeof invoke !== "function") {
    throw new Error("AUTHORITY_RACE_INVOKER_REQUIRED");
  }
  const expected = {
    configDigest,
    functionArn,
    raceId,
    runId,
    sourceCommit
  };
  const acceptedCallerBinding = validatedCallerBinding(callerBinding);
  const responses = await Promise.all(
    CONTENDERS.map(async (contender) => [
      contender,
      await invoke(
        functionArn,
        authorityRaceEvent(raceId, contender)
      )
    ])
  );
  const observation = validateAuthorityRaceInvocations(
    Object.fromEntries(responses),
    expected
  );
  const proof = await invoke(
    functionArn,
    authorityProofEvent(raceId)
  );
  return validateAuthorityRaceProof(
    proof,
    observation,
    expected,
    acceptedCallerBinding
  );
}
