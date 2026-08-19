import crypto from "node:crypto";

const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const COCKROACH_SQL_CLUSTER_ID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const TABLE_ARN =
  /^arn:aws:dynamodb:us-east-1:[0-9]{12}:table\/prooftoact-release-controller$/u;
const COMMAND_SCHEMA = "prooftoact.fresh-primary-provider-command.v3";
const CONSUMPTION_SCHEMA =
  "prooftoact.fresh-primary-provider-consumption.v1";
const INTENT_SCHEMA = "prooftoact.fresh-primary-provider-intent.v3";
const TRANSITION_SCHEMA =
  "prooftoact.fresh-primary-provider-transition.v1";
const OUTCOME_SCHEMA = "prooftoact.fresh-primary-provider-outcome.v1";
const AUTHENTICATION_SCHEMA =
  "prooftoact.fresh-primary-provider-authentication.v3";
const TERMINAL_SCHEMA = "prooftoact.fresh-primary-provider-terminal.v1";
const AUTHENTICATION_MAX_AGE_MS = 5 * 60 * 1000;
const EXPECTED_BOOTSTRAP_PHASES = Object.freeze([
  "SIGNER_SECRET_DISPATCHING",
  "SIGNER_SECRET_SEALED",
  "PREFLIGHT_STARTED",
  "PREFLIGHT_ACCEPTED",
  "ADMIN_CREDENTIAL_DISCARDING",
  "ADMIN_CREDENTIAL_DISCARDED",
  "CREATE_DATABASE_DISPATCHING",
  "DATABASE_CREATED",
  "SECURITY_BOOTSTRAP_DISPATCHING",
  "SECURITY_BOOTSTRAPPED",
  "POSTFLIGHT_STARTED",
  "ACCEPTED"
]);
const EXPECTED_MUTATION_DISPATCH = Object.freeze([
  true, true, false, false, false, false, true, true, true, true, true, true
]);

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function plainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value, expected) {
  return plainObject(value) &&
    Object.keys(value).sort().join("\n") === [...expected].sort().join("\n");
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (plainObject(value)) {
    return `{${Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, nested]) => `${JSON.stringify(key)}:${canonicalJson(nested)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function canonicalBytes(value) {
  const bytes = Buffer.from(`${canonicalJson(value)}\n`, "utf8");
  requireCondition(
    bytes.length > 0 && bytes.length <= 128 * 1024,
    "FRESH_PRIMARY_PROVIDER_CANONICAL_RECORD_REJECTED"
  );
  return bytes;
}

function digest(value) {
  return crypto.createHash("sha256").update(canonicalBytes(value)).digest("hex");
}

function textDigest(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function iso(value, code) {
  requireCondition(Number.isFinite(value), code);
  return new Date(value).toISOString();
}

export function buildFreshPrimaryProviderCommand(value) {
  const code = "FRESH_PRIMARY_PROVIDER_COMMAND_REJECTED";
  requireCondition(exactKeys(value, [
    "adminSecretArnSha256",
    "adminSecretValueSha256",
    "adminSecretVersionIdSha256",
    "approvalId",
    "approvalSha256",
    "cloudApiSecretArnSha256",
    "cloudApiSecretValueSha256",
    "cloudApiSecretVersionIdSha256",
    "controllerTableArn",
    "credentialSecretArnSha256",
    "credentialSecretVersionIdSha256",
    "credentialBundleRawSha256",
    "credentialBundleSha256",
    "credentialSealReceiptSha256",
    "operationId",
    "providerClusterId",
    "recoveryPublisherKeySetDigest",
    "recoveryPublisherTrustRootCommitment",
    "recoverySecurityPostureReceiptSha256",
    "signerSecretArnSha256",
    "signerSecretValueSha256",
    "signerSecretVersionIdSha256",
    "sourceCommit",
    "sqlClusterId",
    "treeDigest",
    "trustRootJsonSha256"
  ]) &&
    UUID.test(value.approvalId ?? "") &&
    UUID.test(value.operationId ?? "") &&
    UUID.test(value.providerClusterId ?? "") &&
    COCKROACH_SQL_CLUSTER_ID.test(value.sqlClusterId ?? "") &&
    value.providerClusterId !== value.sqlClusterId &&
    HEX_40.test(value.sourceCommit ?? "") &&
    HEX_40.test(value.treeDigest ?? "") &&
    TABLE_ARN.test(value.controllerTableArn ?? "") &&
    [
      value.adminSecretArnSha256,
      value.adminSecretValueSha256,
      value.adminSecretVersionIdSha256,
      value.approvalSha256,
      value.cloudApiSecretArnSha256,
      value.cloudApiSecretValueSha256,
      value.cloudApiSecretVersionIdSha256,
      value.credentialBundleRawSha256,
      value.credentialBundleSha256,
      value.credentialSecretArnSha256,
      value.credentialSecretVersionIdSha256,
      value.credentialSealReceiptSha256,
      value.recoveryPublisherKeySetDigest,
      value.recoveryPublisherTrustRootCommitment,
      value.recoverySecurityPostureReceiptSha256,
      value.signerSecretArnSha256,
      value.signerSecretValueSha256,
      value.signerSecretVersionIdSha256,
      value.trustRootJsonSha256
    ].every((item) => HEX_64.test(item ?? "")), code);
  const command = {
    schemaVersion: COMMAND_SCHEMA,
    status: "AUTHORIZED_COORDINATES",
    action: "BOOTSTRAP_ONE_FRESH_PRIMARY",
    region: "us-east-1",
    cloud: "COCKROACHDB_CLOUD_ON_AWS",
    ...value
  };
  const effectIdentitySha256 = digest({
    action: command.action,
    cloud: command.cloud,
    providerClusterId: command.providerClusterId,
    region: command.region,
    sqlClusterId: command.sqlClusterId
  });
  const globalKeySha256 = crypto.createHash("sha256").update(Buffer.from(
    `prooftoact-fresh-primary-effect-v1\n${effectIdentitySha256}`,
    "utf8"
  )).digest("hex");
  return Object.freeze({
    ...command,
    effectIdentitySha256,
    globalKeySha256,
    commandSha256: digest({ ...command, effectIdentitySha256,
      globalKeySha256 })
  });
}

function validateCommand(command) {
  const code = "FRESH_PRIMARY_PROVIDER_COMMAND_REJECTED";
  requireCondition(exactKeys(command, [
    "action",
    "adminSecretArnSha256",
    "adminSecretValueSha256",
    "adminSecretVersionIdSha256",
    "approvalId",
    "approvalSha256",
    "cloud",
    "cloudApiSecretArnSha256",
    "cloudApiSecretValueSha256",
    "cloudApiSecretVersionIdSha256",
    "commandSha256",
    "controllerTableArn",
    "credentialSecretArnSha256",
    "credentialSecretVersionIdSha256",
    "credentialBundleRawSha256",
    "credentialBundleSha256",
    "credentialSealReceiptSha256",
    "effectIdentitySha256",
    "globalKeySha256",
    "operationId",
    "providerClusterId",
    "recoveryPublisherKeySetDigest",
    "recoveryPublisherTrustRootCommitment",
    "recoverySecurityPostureReceiptSha256",
    "region",
    "schemaVersion",
    "signerSecretArnSha256",
    "signerSecretValueSha256",
    "signerSecretVersionIdSha256",
    "sourceCommit",
    "sqlClusterId",
    "status",
    "treeDigest",
    "trustRootJsonSha256"
  ]) && command.schemaVersion === COMMAND_SCHEMA &&
    command.status === "AUTHORIZED_COORDINATES" &&
    command.action === "BOOTSTRAP_ONE_FRESH_PRIMARY" &&
    command.region === "us-east-1" &&
    command.cloud === "COCKROACHDB_CLOUD_ON_AWS", code);
  const unsigned = { ...command };
  delete unsigned.action;
  delete unsigned.cloud;
  delete unsigned.commandSha256;
  delete unsigned.effectIdentitySha256;
  delete unsigned.globalKeySha256;
  delete unsigned.region;
  delete unsigned.schemaVersion;
  delete unsigned.status;
  const rebuilt = buildFreshPrimaryProviderCommand(unsigned);
  requireCondition(
    canonicalJson(rebuilt) === canonicalJson(command),
    code
  );
  return command;
}

function validateConsumption(value, command) {
  const code = "FRESH_PRIMARY_PROVIDER_CONSUMPTION_REJECTED";
  requireCondition(exactKeys(value, [
    "approvalId",
    "commandSha256",
    "consumedAt",
    "durable",
    "globallyAuthoritative",
    "globalKeySha256",
    "namespaceArn",
    "oneShot",
    "operationId",
    "schemaVersion",
    "status",
    "version"
  ]) && value.schemaVersion === CONSUMPTION_SCHEMA &&
    value.status === "CONSUMED" && value.version === 1 &&
    value.approvalId === command.approvalId &&
    value.operationId === command.operationId &&
    value.globalKeySha256 === command.globalKeySha256 &&
    value.commandSha256 === command.commandSha256 &&
    value.namespaceArn === command.controllerTableArn &&
    value.durable === true && value.globallyAuthoritative === true &&
    value.oneShot === true && Number.isFinite(Date.parse(value.consumedAt)),
  code);
  return value;
}

function validateIntent(value, command, consumption, authentication) {
  const code = "FRESH_PRIMARY_PROVIDER_INTENT_REJECTED";
  requireCondition(exactKeys(value, [
    "commandSha256",
    "durable",
    "event",
    "globallyAuthoritative",
    "globalKeySha256",
    "namespaceArn",
    "operationId",
    "previousReceiptSha256",
    "providerAuthenticationReceiptSha256",
    "schemaVersion",
    "status",
    "version"
  ]) && value.schemaVersion === INTENT_SCHEMA &&
    value.status === "DURABLE" &&
    value.event === "BEFORE_SIGNER_OR_DATABASE_PROVIDER_DISPATCH" &&
    value.commandSha256 === command.commandSha256 &&
    value.operationId === command.operationId &&
    value.globalKeySha256 === command.globalKeySha256 &&
    value.namespaceArn === command.controllerTableArn &&
    value.previousReceiptSha256 === digest(consumption) &&
    value.providerAuthenticationReceiptSha256 === digest(authentication) &&
    value.durable === true && value.globallyAuthoritative === true &&
    value.version === 2, code);
  return value;
}

function validateTransition(value, command, previousReceiptSha256, sequence) {
  const code = "FRESH_PRIMARY_PROVIDER_TRANSITION_REJECTED";
  requireCondition(exactKeys(value, [
    "commandSha256",
    "durable",
    "globallyAuthoritative",
    "globalKeySha256",
    "mutationDispatched",
    "namespaceArn",
    "operationId",
    "payloadSha256",
    "phase",
    "previousReceiptSha256",
    "schemaVersion",
    "sequence",
    "status",
    "version"
  ]) && value.schemaVersion === TRANSITION_SCHEMA &&
    value.status === "DURABLE" &&
    value.commandSha256 === command.commandSha256 &&
    value.operationId === command.operationId &&
    value.globalKeySha256 === command.globalKeySha256 &&
    value.namespaceArn === command.controllerTableArn &&
    value.previousReceiptSha256 === previousReceiptSha256 &&
    value.sequence === sequence && value.version === sequence + 3 &&
    /^[A-Z][A-Z0-9_]{0,79}$/u.test(value.phase ?? "") &&
    typeof value.mutationDispatched === "boolean" &&
    HEX_64.test(value.payloadSha256 ?? "") && value.durable === true &&
    value.globallyAuthoritative === true, code);
  return value;
}

function validateSecretReadback(value, arnSha256, versionIdSha256,
  secretValueSha256) {
  return exactKeys(value, [
    "immutableVersion",
    "secretArnSha256",
    "secretValueSha256",
    "secretVersionIdSha256",
    "versionStage"
  ]) && value.immutableVersion === true &&
    value.secretArnSha256 === arnSha256 &&
    value.secretValueSha256 === secretValueSha256 &&
    value.secretVersionIdSha256 === versionIdSha256 &&
    value.versionStage === "AWSCURRENT";
}

function validateRecoverySignerReadback(value, command, recovery) {
  const absent = exactKeys(value, [
    "secretArnSha256", "targetVersionAbsent", "targetVersionIdSha256"
  ]) && value.secretArnSha256 === command.signerSecretArnSha256 &&
    value.targetVersionIdSha256 === command.signerSecretVersionIdSha256 &&
    value.targetVersionAbsent === true;
  if (!recovery) return absent;
  return absent || validateSecretReadback(
    value,
    command.signerSecretArnSha256,
    command.signerSecretVersionIdSha256,
    command.signerSecretValueSha256
  );
}

function validateAuthentication(value, command, observedNow, recovery = false) {
  const code = "FRESH_PRIMARY_PROVIDER_AUTHENTICATION_REJECTED";
  const observedAt = Date.parse(value?.observedAt);
  requireCondition(exactKeys(value, [
    "callerIdentitySha256",
    "cloud",
    "clusterInventorySha256",
    "namespaceArn",
    "observedAt",
    "providerBacked",
    "providerClusterId",
    "readOnly",
    "region",
    "schemaVersion",
    "secretReadbacks",
    "status",
    "stronglyConsistent"
  ]) && value.schemaVersion === AUTHENTICATION_SCHEMA &&
    value.status === "AUTHENTICATED_PROVIDER_READBACK" &&
    value.namespaceArn === command.controllerTableArn &&
    value.providerClusterId === command.providerClusterId &&
    value.region === command.region && value.cloud === command.cloud &&
    value.providerBacked === true && value.readOnly === true &&
    value.stronglyConsistent === true &&
    HEX_64.test(value.callerIdentitySha256 ?? "") &&
    HEX_64.test(value.clusterInventorySha256 ?? "") &&
    Number.isFinite(observedNow) && Number.isFinite(observedAt) &&
    value.observedAt === new Date(observedAt).toISOString() &&
    observedAt <= observedNow &&
    observedNow - observedAt <= AUTHENTICATION_MAX_AGE_MS &&
    exactKeys(value.secretReadbacks, [
      "admin", "cloudApi", "credential", "recoverySigner"
    ]) &&
    validateSecretReadback(value.secretReadbacks.admin,
      command.adminSecretArnSha256, command.adminSecretVersionIdSha256,
      command.adminSecretValueSha256) &&
    validateSecretReadback(value.secretReadbacks.cloudApi,
      command.cloudApiSecretArnSha256,
      command.cloudApiSecretVersionIdSha256,
      command.cloudApiSecretValueSha256) &&
    validateSecretReadback(value.secretReadbacks.credential,
      command.credentialSecretArnSha256,
      command.credentialSecretVersionIdSha256,
      command.credentialBundleRawSha256) &&
    validateRecoverySignerReadback(
      value.secretReadbacks.recoverySigner,
      command,
      recovery
    ), code);
  return value;
}

function requireProvider(provider) {
  requireCondition(provider && [
    "appendIntent",
    "appendTransition",
    "authenticate",
    "authenticateRecovery",
    "consumeOnce",
    "finalize",
    "readStrong"
  ].every((name) => typeof provider[name] === "function"),
  "FRESH_PRIMARY_PROVIDER_CAPABILITY_REJECTED");
}

function outcome({ command, observedAt, possibleMutation, receipt, status }) {
  const value = {
    schemaVersion: OUTCOME_SCHEMA,
    status,
    commandSha256: command.commandSha256,
    operationId: command.operationId,
    globalKeySha256: command.globalKeySha256,
    observedAt,
    possibleMutation,
    providerReceiptSha256: digest(receipt)
  };
  return Object.freeze(value);
}

function validateOutcome(value, command) {
  const code = "FRESH_PRIMARY_PROVIDER_OUTCOME_REJECTED";
  requireCondition(exactKeys(value, [
    "commandSha256",
    "globalKeySha256",
    "observedAt",
    "operationId",
    "possibleMutation",
    "providerReceiptSha256",
    "schemaVersion",
    "status"
  ]) && value.schemaVersion === OUTCOME_SCHEMA &&
    ["AMBIGUOUS", "CONFIRMED", "FAILED_TERMINAL"].includes(value.status) &&
    value.commandSha256 === command.commandSha256 &&
    value.operationId === command.operationId &&
    value.globalKeySha256 === command.globalKeySha256 &&
    HEX_64.test(value.providerReceiptSha256 ?? "") &&
    Number.isFinite(Date.parse(value.observedAt)) &&
    (value.status === "FAILED_TERMINAL"
      ? value.possibleMutation === false
      : value.possibleMutation === true), code);
  return value;
}

function validateTerminal(value, command, acceptedOutcome,
  previousReceiptSha256, transitionCount) {
  const code = "FRESH_PRIMARY_PROVIDER_TERMINAL_REJECTED";
  validateOutcome(acceptedOutcome, command);
  requireCondition(exactKeys(value, [
    "commandSha256",
    "durable",
    "globallyAuthoritative",
    "globalKeySha256",
    "namespaceArn",
    "operationId",
    "outcomeSha256",
    "previousReceiptSha256",
    "schemaVersion",
    "status",
    "transitionCount",
    "version"
  ]) && value.schemaVersion === TERMINAL_SCHEMA &&
    value.status === "TERMINAL" &&
    value.commandSha256 === command.commandSha256 &&
    value.operationId === command.operationId &&
    value.globalKeySha256 === command.globalKeySha256 &&
    value.namespaceArn === command.controllerTableArn &&
    value.outcomeSha256 === digest(acceptedOutcome) &&
    value.previousReceiptSha256 === previousReceiptSha256 &&
    value.transitionCount === transitionCount &&
    value.durable === true && value.globallyAuthoritative === true &&
    Number.isSafeInteger(transitionCount) && transitionCount >= 0 &&
    value.version === transitionCount + 3,
  code);
  return value;
}

function validateOccupiedRecord(value, command) {
  const code = "FRESH_PRIMARY_PROVIDER_OCCUPIED_RECORD_REJECTED";
  requireCondition(plainObject(value) && value.occupied === true &&
    canonicalJson(value.command) === canonicalJson(command) &&
    Number.isSafeInteger(value.transitionCount) &&
    value.transitionCount >= 0 &&
    value.transitionCount <= EXPECTED_BOOTSTRAP_PHASES.length &&
    Array.isArray(value.transitions) &&
    value.transitions.length === value.transitionCount &&
    value.version === value.transitionCount + (value.terminal ? 3 : 2), code);
  const consumption = validateConsumption(value.consumption, command);
  const intent = value.intent;
  requireCondition(exactKeys(intent, [
    "commandSha256",
    "durable",
    "event",
    "globallyAuthoritative",
    "globalKeySha256",
    "namespaceArn",
    "operationId",
    "previousReceiptSha256",
    "providerAuthenticationReceiptSha256",
    "schemaVersion",
    "status",
    "version"
  ]) && intent.schemaVersion === INTENT_SCHEMA &&
    intent.status === "DURABLE" &&
    intent.event === "BEFORE_SIGNER_OR_DATABASE_PROVIDER_DISPATCH" &&
    intent.commandSha256 === command.commandSha256 &&
    intent.operationId === command.operationId &&
    intent.globalKeySha256 === command.globalKeySha256 &&
    intent.namespaceArn === command.controllerTableArn &&
    intent.previousReceiptSha256 === digest(consumption) &&
    HEX_64.test(intent.providerAuthenticationReceiptSha256 ?? "") &&
    intent.durable === true && intent.globallyAuthoritative === true &&
    intent.version === 2, code);
  let previousReceiptSha256 = digest(intent);
  value.transitions.forEach((transition, sequence) => {
    validateTransition(
      transition,
      command,
      previousReceiptSha256,
      sequence
    );
    requireCondition(transition.phase === EXPECTED_BOOTSTRAP_PHASES[sequence] &&
      transition.mutationDispatched ===
        EXPECTED_MUTATION_DISPATCH[sequence], code);
    previousReceiptSha256 = digest(transition);
  });
  requireCondition(value.lastReceiptSha256 === (value.terminal
    ? digest(value.terminal)
    : previousReceiptSha256), code);
  if (value.terminal !== null) {
    validateTerminal(
      value.terminal,
      command,
      value.outcome,
      previousReceiptSha256,
      value.transitionCount
    );
  } else {
    requireCondition(value.outcome === null &&
      value.state === (value.transitionCount === 0 ? "INTENT" : "TRANSITION"),
    code);
  }
  return Object.freeze({
    ...value,
    lastTransitionReceiptSha256: previousReceiptSha256
  });
}

function validateDispatchReceipt(receipt, command, transitionCount) {
  const code = "FRESH_PRIMARY_PROVIDER_DISPATCH_RECEIPT_REJECTED";
  requireCondition(
    transitionCount === EXPECTED_BOOTSTRAP_PHASES.length &&
      plainObject(receipt) &&
      receipt.schemaVersion ===
        "prooftoact.fresh-primary-bootstrap-receipt.v3" &&
      receipt.status === "PASS" &&
      receipt.approvalId === command.approvalId &&
      receipt.operationId === command.operationId &&
      receipt.sourceCommit === command.sourceCommit &&
      receipt.treeDigest === command.treeDigest &&
      receipt.partialFailureDisposition ===
        "UNKNOWN_DO_NOT_RETRY_RECONCILE_OR_DISCARD" &&
      receipt.credentialLifecycle?.callerSuppliedSealReceiptSha256 ===
        command.credentialSealReceiptSha256 &&
      receipt.credentialLifecycle?.recoveryPublisher?.
        signerSecretArnSha256 === command.signerSecretArnSha256 &&
      receipt.credentialLifecycle?.recoveryPublisher?.
        signerSecretVersionIdSha256 ===
          command.signerSecretVersionIdSha256 &&
      receipt.credentialLifecycle?.recoveryPublisher?.
        signerSecretValueSha256 === command.signerSecretValueSha256 &&
      receipt.credentialLifecycle?.recoveryPublisher?.trustRootCommitment ===
        command.recoveryPublisherTrustRootCommitment &&
      receipt.credentialLifecycle?.recoveryPublisher?.publisherKeySetDigest ===
        command.recoveryPublisherKeySetDigest &&
      receipt.provider?.clusterIdSha256 === textDigest(command.sqlClusterId) &&
      receipt.postflight?.directPrivateTableAccessDenied === true &&
      receipt.postflight?.runtimeDatabase === "tideproof" &&
      receipt.postflight?.runtimeIdentity === "tp_gate2_authorizer_user",
    code
  );
  return receipt;
}

function controllerReceipt({
  authentication,
  command,
  receipt,
  recoveredOccupiedJournal,
  terminal,
  transitionCount
}) {
  return Object.freeze({
    schemaVersion: "prooftoact.fresh-primary-provider-controller-receipt.v3",
    status: "PASS",
    commandSha256: command.commandSha256,
    globalKeySha256: command.globalKeySha256,
    operationId: command.operationId,
    namespaceArn: command.controllerTableArn,
    providerClusterId: command.providerClusterId,
    recoverySecurityPostureReceiptSha256:
      command.recoverySecurityPostureReceiptSha256,
    sqlClusterId: command.sqlClusterId,
    bootstrapReceiptSha256: digest(receipt),
    providerAuthenticationReceiptSha256: digest(authentication),
    terminalReceiptSha256: digest(terminal),
    transitionCount,
    globallyAuthoritativeOneShot: true,
    recoveredOccupiedJournal,
    evidence: Object.freeze({
      providerAuthentication: authentication,
      bootstrapReceipt: receipt,
      terminalReceipt: terminal
    }),
    claimBoundary:
      "This receipt proves that the exact source/tree, separate Cockroach Cloud and SQL cluster identities, immutable secret-version digests, approval digest, credential-seal digest, and an independently controlled recovery-security posture receipt digest passed through one durable provider-global intent/transition/terminal controller. This fresh-primary run does not grant or mutate Managed MCP recovery access. The separate recovery receipt must prove only public recovery-view SELECT plus mcp_private and mcp_public schema USAGE, with no private relation, function, role, system, grant-option, login, or write capability. This receipt does not by itself prove those recovery grants, AWS application deployment, DVI execution, public availability, or an integrated live drill; those facts require separate bound provider receipts."
  });
}

export async function runFreshPrimaryProviderController({
  clock = Date.now,
  command,
  dispatch,
  provider
}) {
  validateCommand(command);
  requireProvider(provider);
  requireCondition(typeof clock === "function" && typeof dispatch === "function",
    "FRESH_PRIMARY_PROVIDER_CAPABILITY_REJECTED");

  const occupied = await provider.readStrong({
    commandSha256: command.commandSha256,
    globalKeySha256: command.globalKeySha256,
    namespaceArn: command.controllerTableArn,
    operationId: command.operationId,
    stronglyConsistent: true
  });
  const authenticationNow = clock();
  requireCondition(Number.isFinite(authenticationNow),
    "FRESH_PRIMARY_PROVIDER_CLOCK_REJECTED");
  const authentication = validateAuthentication(
    occupied === null
      ? await provider.authenticate(command)
      : await provider.authenticateRecovery(command),
    command,
    authenticationNow,
    occupied !== null
  );

  if (occupied !== null) {
    const acceptedOccupied = validateOccupiedRecord(occupied, command);
    if (acceptedOccupied.terminal !== null) {
      if (acceptedOccupied.outcome.status === "CONFIRMED") {
        const receipt = validateDispatchReceipt(
          acceptedOccupied.providerReceipt,
          command,
          acceptedOccupied.transitionCount
        );
        return controllerReceipt({
          authentication,
          command,
          receipt,
          recoveredOccupiedJournal: true,
          terminal: acceptedOccupied.terminal,
          transitionCount: acceptedOccupied.transitionCount
        });
      }
      reject("FRESH_PRIMARY_PROVIDER_UNKNOWN_DO_NOT_RETRY");
    }
    const failedReceipt = Object.freeze({
      causeCode: "FRESH_PRIMARY_PROCESS_INTERRUPTED_AFTER_DURABLE_INTENT",
      lastReceiptSha256: acceptedOccupied.lastTransitionReceiptSha256,
      transitionCount: acceptedOccupied.transitionCount
    });
    const failedOutcome = validateOutcome(outcome({
      command,
      observedAt: iso(clock(), "FRESH_PRIMARY_PROVIDER_CLOCK_REJECTED"),
      possibleMutation: true,
      receipt: failedReceipt,
      status: "AMBIGUOUS"
    }), command);
    const terminal = await provider.finalize({
      command,
      intent: acceptedOccupied.intent,
      outcome: failedOutcome,
      previousReceiptSha256:
        acceptedOccupied.lastTransitionReceiptSha256,
      providerReceipt: failedReceipt,
      transitionCount: acceptedOccupied.transitionCount
    });
    validateTerminal(
      terminal,
      command,
      failedOutcome,
      acceptedOccupied.lastTransitionReceiptSha256,
      acceptedOccupied.transitionCount
    );
    reject("FRESH_PRIMARY_PROVIDER_UNKNOWN_DO_NOT_RETRY");
  }

  const consumption = validateConsumption(
    await provider.consumeOnce(command),
    command
  );
  const intent = validateIntent(await provider.appendIntent({
    command,
    consumption,
    authentication
  }), command, consumption, authentication);
  let previousReceiptSha256 = digest(intent);
  let sequence = 0;
  let possibleMutation = false;

  const recordTransition = async (phase, payload) => {
    requireCondition(
      phase === EXPECTED_BOOTSTRAP_PHASES[sequence] &&
        plainObject(payload) &&
        payload.mutationDispatched === EXPECTED_MUTATION_DISPATCH[sequence],
      "FRESH_PRIMARY_PROVIDER_TRANSITION_REJECTED"
    );
    possibleMutation ||= payload.mutationDispatched;
    const transition = Object.freeze({
      schemaVersion: TRANSITION_SCHEMA,
      status: "DURABLE",
      commandSha256: command.commandSha256,
      globalKeySha256: command.globalKeySha256,
      operationId: command.operationId,
      namespaceArn: command.controllerTableArn,
      phase,
      payloadSha256: digest(payload),
      mutationDispatched: payload.mutationDispatched,
      previousReceiptSha256,
      sequence,
      version: sequence + 3,
      durable: true,
      globallyAuthoritative: true
    });
    const recorded = validateTransition(
      await provider.appendTransition({ command, intent, transition }),
      command,
      previousReceiptSha256,
      sequence
    );
    requireCondition(canonicalJson(recorded) === canonicalJson(transition),
      "FRESH_PRIMARY_PROVIDER_TRANSITION_CONFLICT");
    previousReceiptSha256 = digest(recorded);
    sequence += 1;
    return previousReceiptSha256;
  };

  let receipt;
  try {
    receipt = await dispatch(Object.freeze({ recordTransition }));
    validateDispatchReceipt(receipt, command, sequence);
  } catch (cause) {
    const failedReceipt = Object.freeze({
      causeCode: /^FRESH_PRIMARY_[A-Z0-9_]{1,100}$/u.test(
        String(cause?.message ?? "")
      ) ? cause.message : "FRESH_PRIMARY_UNKNOWN",
      lastReceiptSha256: previousReceiptSha256,
      transitionCount: sequence
    });
    const failedOutcome = validateOutcome(outcome({
      command,
      observedAt: iso(clock(), "FRESH_PRIMARY_PROVIDER_CLOCK_REJECTED"),
      possibleMutation,
      receipt: failedReceipt,
      status: possibleMutation ? "AMBIGUOUS" : "FAILED_TERMINAL"
    }), command);
    try {
      validateTerminal(
        await provider.finalize({
          command,
          intent,
          outcome: failedOutcome,
          previousReceiptSha256,
          providerReceipt: failedReceipt,
          transitionCount: sequence
        }),
        command,
        failedOutcome,
        previousReceiptSha256,
        sequence
      );
    } catch (finalizeCause) {
      reject("FRESH_PRIMARY_PROVIDER_FINALIZE_UNKNOWN", {
        cause,
        finalizeCause,
        failedOutcome
      });
    }
    if (possibleMutation) {
      reject("FRESH_PRIMARY_PROVIDER_UNKNOWN_DO_NOT_RETRY", cause);
    }
    throw cause;
  }

  const acceptedOutcome = validateOutcome(outcome({
    command,
    observedAt: iso(clock(), "FRESH_PRIMARY_PROVIDER_CLOCK_REJECTED"),
    possibleMutation: true,
    receipt,
    status: "CONFIRMED"
  }), command);
  const terminal = await provider.finalize({
    command,
    intent,
    outcome: acceptedOutcome,
    previousReceiptSha256,
    providerReceipt: receipt,
    transitionCount: sequence
  });
  validateTerminal(terminal, command, acceptedOutcome,
    previousReceiptSha256, sequence);

  return controllerReceipt({
    authentication,
    command,
    receipt,
    recoveredOccupiedJournal: false,
    terminal,
    transitionCount: sequence
  });
}

export const __test = Object.freeze({
  EXPECTED_BOOTSTRAP_PHASES,
  EXPECTED_MUTATION_DISPATCH,
  canonicalBytes,
  digest,
  validateAuthentication,
  validateCommand,
  validateConsumption,
  validateIntent,
  validateOutcome,
  validateTerminal,
  validateTransition
});
