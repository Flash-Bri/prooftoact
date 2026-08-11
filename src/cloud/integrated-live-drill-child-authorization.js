import { randomBytes, randomUUID } from "node:crypto";
import fs from "node:fs";

import { canonicalJson } from "./canonical-json.js";
import {
  INTEGRATED_LIVE_DRILL_SIGNED_EVIDENCE_SCHEMA,
  INTEGRATED_LIVE_DRILL_SPEND_SCOPES,
  INTEGRATED_LIVE_DRILL_COMMITTED_RECOVERY_TRUST_ROOT_SCHEMA,
  integratedLiveDrillAuthorizationAttestationDigest,
  integratedLiveDrillCanonicalSha256,
  integratedLiveDrillRunnerIdentityDigest,
  integratedLiveDrillSha256,
  signIntegratedLiveDrillEvidence,
  validateIntegratedLiveDrillRunAuthorization,
  verifyIntegratedLiveDrillEvidence
} from "./integrated-live-drill-authorization.js";
import {
  INTEGRATED_LIVE_DRILL_AUTHORIZATION_CLAIM_SCHEMA,
  INTEGRATED_LIVE_DRILL_SPEND_RESERVATION_SCHEMA,
  consumeIntegratedLiveDrillChildLaunch,
  validateIntegratedLiveDrillConsumedChildLaunch,
  validateIntegratedLiveDrillConsumedControlLedger
} from "./integrated-live-drill-control-ledger.js";
import { validateDeploymentExpectation } from
  "./aws-deployment-attestation.js";
import { trustedPublisherKeysDigest } from
  "./recovery-publisher-trust.js";

export const INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION_SCHEMA =
  "tideproof.highwater-drill-child-launch-token.v1";
export const INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION";
export const INTEGRATED_LIVE_DRILL_CHILD_COMMITTED_TRUST_ROOT_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_CHILD_COMMITTED_RECOVERY_TRUST_ROOT";

const HEX_64 = /^[0-9a-f]{64}$/u;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

function reject(code) {
  throw new Error(code);
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function exactKeys(value, keys) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join("\n") === [...keys].sort().join("\n")
  );
}

function exactIsoMilliseconds(value, code) {
  const milliseconds = typeof value === "string" ? Date.parse(value) : NaN;
  requireCondition(
    Number.isFinite(milliseconds) &&
      new Date(milliseconds).toISOString() === value,
    code
  );
  return milliseconds;
}

function requiredEnvironment(environment, name, maximum) {
  const value = environment?.[name];
  requireCondition(
    typeof value === "string" &&
      value.length > 0 &&
      value.length <= maximum &&
      !/[\0\r\n]/u.test(value),
    "INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION_REJECTED"
  );
  return value;
}

function parseCanonicalEnvironmentJson(environment, name, maximum) {
  const raw = requiredEnvironment(environment, name, maximum);
  let value;
  try {
    value = JSON.parse(raw);
  } catch {
    reject("INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION_REJECTED");
  }
  requireCondition(
    raw === canonicalJson(value),
    "INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION_REJECTED"
  );
  return value;
}

function exactClaim(value, authorizationId) {
  return (
    exactKeys(value, [
      "authorizationClaimSha256",
      "authorizationId",
      "fileByteLength",
      "fileNameSha256",
      "schemaVersion",
      "spendAuthorizationSha256"
    ]) &&
    value.schemaVersion === INTEGRATED_LIVE_DRILL_AUTHORIZATION_CLAIM_SCHEMA &&
    value.authorizationId === authorizationId &&
    Number.isSafeInteger(value.fileByteLength) &&
    value.fileByteLength > 0 &&
    [
      value.authorizationClaimSha256,
      value.fileNameSha256,
      value.spendAuthorizationSha256
    ].every((entry) => HEX_64.test(entry ?? ""))
  );
}

function exactReservation(value, authorizationId, scope) {
  return (
    exactKeys(value, [
      "authorizationId",
      "cumulativeAuthorizedExposureUsd",
      "fileByteLength",
      "fileNameSha256",
      "reservationSha256",
      "schemaVersion",
      "scopeId",
      "sequence"
    ]) &&
    value.schemaVersion === INTEGRATED_LIVE_DRILL_SPEND_RESERVATION_SCHEMA &&
    value.authorizationId === authorizationId &&
    value.scopeId === scope.scopeId &&
    value.sequence === scope.sequence &&
    /^0\.[0-9]{6}$/u.test(value.cumulativeAuthorizedExposureUsd ?? "") &&
    Number.isSafeInteger(value.fileByteLength) &&
    value.fileByteLength > 0 &&
    [value.fileNameSha256, value.reservationSha256].every((entry) =>
      HEX_64.test(entry ?? "")
    )
  );
}

function exactScope(value, expected) {
  return (
    exactKeys(value, [
      "component",
      "maximumExecutions",
      "maximumExposureUsd",
      "provider",
      "scopeId",
      "sequence"
    ]) &&
    value.component === expected?.component &&
    value.maximumExecutions === expected?.maximumExecutions &&
    /^0\.[0-9]{6}$/u.test(value.maximumExposureUsd ?? "") &&
    value.provider === expected?.provider &&
    value.scopeId === expected?.scopeId &&
    value.sequence === expected?.sequence
  );
}

export function integratedLiveDrillChildCommittedTrustRoot(value) {
  return Object.freeze({
    schemaVersion:
      INTEGRATED_LIVE_DRILL_COMMITTED_RECOVERY_TRUST_ROOT_SCHEMA,
    publisherKeySetDigest: value.publisherKeySetDigest,
    trustRootCommitment: value.trustRootCommitment,
    trustedPublisherKeys: value.trustedPublisherKeys
  });
}

function parseCommittedTrustRoot(value) {
  requireCondition(
    exactKeys(value, [
      "publisherKeySetDigest",
      "schemaVersion",
      "trustRootCommitment",
      "trustedPublisherKeys"
    ]) &&
      value.schemaVersion ===
        INTEGRATED_LIVE_DRILL_COMMITTED_RECOVERY_TRUST_ROOT_SCHEMA &&
      HEX_64.test(value.publisherKeySetDigest ?? "") &&
      HEX_64.test(value.trustRootCommitment ?? "") &&
      value.publisherKeySetDigest ===
        trustedPublisherKeysDigest(value.trustedPublisherKeys),
    "INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION_REJECTED"
  );
  return Object.freeze({
    schemaVersion:
      INTEGRATED_LIVE_DRILL_COMMITTED_RECOVERY_TRUST_ROOT_SCHEMA,
    publisherKeySetDigest: value.publisherKeySetDigest,
    trustRootCommitment: value.trustRootCommitment,
    trustedPublisherKeys: Object.freeze({ ...value.trustedPublisherKeys })
  });
}

export function integratedLiveDrillChildAuthorizationContext({
  authorization,
  claim,
  expectation,
  privateKeyPkcs8DerBase64,
  reservation,
  spec,
  now = Date.now(),
  nonceSha256 = integratedLiveDrillSha256(randomBytes(32)),
  tokenId = randomUUID()
}) {
  const scope = authorization?.payload?.spendAuthorization?.scopes?.find(
    ({ scopeId }) => scopeId === reservation?.scopeId
  );
  const issuedAt = Number.isSafeInteger(now)
    ? new Date(now).toISOString()
    : null;
  requireCondition(
    scope &&
      exactScope(scope, INTEGRATED_LIVE_DRILL_SPEND_SCOPES[scope.sequence - 1]) &&
      exactClaim(claim, authorization.payload.authorizationId) &&
      exactReservation(
        reservation,
        authorization.payload.authorizationId,
        scope
      ) &&
      HEX_64.test(nonceSha256 ?? "") &&
      UUID.test(tokenId ?? "") &&
      issuedAt !== null &&
      now >= authorization.issuedAt &&
      now <= authorization.expiresAt &&
      authorization.payload.specSha256 ===
        integratedLiveDrillCanonicalSha256(spec),
    "INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION_REJECTED"
  );
  const payload = Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION_SCHEMA,
    authorizationAttestationSha256:
      integratedLiveDrillAuthorizationAttestationDigest(
        authorization.attestation
      ),
    authorizationId: authorization.payload.authorizationId,
    claim: Object.freeze({ ...claim }),
    configDigest: authorization.payload.configDigest,
    expectationSha256: integratedLiveDrillCanonicalSha256(expectation),
    expiresAt: authorization.payload.expiresAt,
    issuedAt,
    nonceSha256,
    reservation: Object.freeze({ ...reservation }),
    runId: authorization.payload.runId,
    runnerIdentitySha256:
      authorization.payload.authorizationClaimAuthority.runnerIdentitySha256,
    scope: Object.freeze({ ...scope }),
    sourceCommit: authorization.payload.sourceCommit,
    specSha256: authorization.payload.specSha256,
    tokenId,
    treeDigest: authorization.payload.treeDigest
  });
  return signIntegratedLiveDrillEvidence(
    payload,
    privateKeyPkcs8DerBase64,
    authorization.payload.childLaunchPublicKey
  );
}

export function parseIntegratedLiveDrillChildAuthorization(
  environment,
  expectedScopeId,
  { now = Date.now() } = {}
) {
  const raw = requiredEnvironment(
    environment,
    INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION_ENVIRONMENT,
    32_768
  );
  let attestation;
  try {
    attestation = JSON.parse(raw);
  } catch {
    reject("INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION_REJECTED");
  }
  const value = attestation?.payload;
  const scope = INTEGRATED_LIVE_DRILL_SPEND_SCOPES.find(
    ({ scopeId }) => scopeId === expectedScopeId
  );
  const issuedAt = exactIsoMilliseconds(
    value?.issuedAt,
    "INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION_TIME_REJECTED"
  );
  const expiresAt = exactIsoMilliseconds(
    value?.expiresAt,
    "INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION_TIME_REJECTED"
  );
  requireCondition(
    scope &&
      exactKeys(attestation, ["payload", "schemaVersion", "signature"]) &&
      attestation.schemaVersion === INTEGRATED_LIVE_DRILL_SIGNED_EVIDENCE_SCHEMA &&
      exactKeys(attestation.signature, ["algorithm", "keyIdSha256", "value"]) &&
      exactKeys(value, [
        "authorizationAttestationSha256",
        "authorizationId",
        "claim",
        "configDigest",
        "expectationSha256",
        "expiresAt",
        "issuedAt",
        "nonceSha256",
        "reservation",
        "runId",
        "runnerIdentitySha256",
        "schemaVersion",
        "scope",
        "sourceCommit",
        "specSha256",
        "tokenId",
        "treeDigest"
      ]) &&
      value.schemaVersion === INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION_SCHEMA &&
      [
        value.authorizationAttestationSha256,
        value.configDigest,
        value.expectationSha256,
        value.nonceSha256,
        value.runnerIdentitySha256,
        value.specSha256
      ].every((entry) => HEX_64.test(entry ?? "")) &&
      UUID.test(value.authorizationId ?? "") &&
      UUID.test(value.runId ?? "") &&
      UUID.test(value.tokenId ?? "") &&
      exactScope(value.scope, scope) &&
      exactClaim(value.claim, value.authorizationId) &&
      exactReservation(value.reservation, value.authorizationId, scope) &&
      Number.isSafeInteger(now) &&
      now >= issuedAt &&
      now <= expiresAt &&
      issuedAt <= expiresAt,
    "INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION_REJECTED"
  );
  requireCondition(
    raw === canonicalJson(attestation),
    "INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION_REJECTED"
  );
  return Object.freeze({
    attestation: Object.freeze(attestation),
    expiresAt,
    issuedAt,
    value: Object.freeze(value)
  });
}

function validateIntegratedLiveDrillChildLaunchEnvironment(
  environment,
  expectedScopeId,
  {
    now = Date.now(),
    forbiddenRootPath = fs.realpathSync(process.cwd())
  } = {}
) {
  const context = parseIntegratedLiveDrillChildAuthorization(
    environment,
    expectedScopeId,
    { now }
  );
  const spec = parseCanonicalEnvironmentJson(
    environment,
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_SPEC",
    8192
  );
  const expectation = validateDeploymentExpectation(
    parseCanonicalEnvironmentJson(
      environment,
      "TIDEPROOF_GATE2_DEPLOYMENT_EXPECTATION",
      1024 * 1024
    )
  );
  const authorizationAttestation = parseCanonicalEnvironmentJson(
    environment,
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_RUN_AUTHORIZATION",
    1024 * 1024
  );
  const humanAuthorizationTrustRoot = parseCanonicalEnvironmentJson(
    environment,
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_HUMAN_AUTHORIZATION_TRUST_ROOT",
    16_384
  );
  const committedTrustRoot = parseCommittedTrustRoot(
    parseCanonicalEnvironmentJson(
      environment,
      INTEGRATED_LIVE_DRILL_CHILD_COMMITTED_TRUST_ROOT_ENVIRONMENT,
      16_384
    )
  );
  const ledgerRootPath = requiredEnvironment(
    environment,
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_AUTHORIZATION_LEDGER_ROOT",
    4096
  );
  const runnerIdentity = requiredEnvironment(
    environment,
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_RUNNER_IDENTITY",
    512
  );
  const authorization = validateIntegratedLiveDrillRunAuthorization(
    authorizationAttestation,
    {
      spec,
      expectation,
      committedTrustRoot,
      humanAuthorizationTrustRoot,
      authorizationLedgerRootPath: ledgerRootPath,
      now
    }
  );
  const payload = verifyIntegratedLiveDrillEvidence(
    context.attestation,
    authorization.payload.childLaunchPublicKey,
    INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION_SCHEMA,
    "INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION_SIGNATURE_REJECTED"
  );
  const scope = authorization.payload.spendAuthorization.scopes.find(
    ({ scopeId }) => scopeId === expectedScopeId
  );
  requireCondition(
    canonicalJson(payload) === canonicalJson(context.value) &&
      payload.authorizationAttestationSha256 ===
        integratedLiveDrillAuthorizationAttestationDigest(
          authorization.attestation
        ) &&
      payload.authorizationId === authorization.payload.authorizationId &&
      payload.runId === authorization.payload.runId &&
      payload.runnerIdentitySha256 ===
        authorization.payload.authorizationClaimAuthority
          .runnerIdentitySha256 &&
      payload.runnerIdentitySha256 ===
        integratedLiveDrillRunnerIdentityDigest(runnerIdentity) &&
      payload.sourceCommit === authorization.payload.sourceCommit &&
      payload.treeDigest === authorization.payload.treeDigest &&
      payload.configDigest === authorization.payload.configDigest &&
      payload.specSha256 === integratedLiveDrillCanonicalSha256(spec) &&
      payload.expectationSha256 ===
        integratedLiveDrillCanonicalSha256(expectation) &&
      payload.expiresAt === authorization.payload.expiresAt &&
      context.issuedAt >= authorization.issuedAt &&
      context.expiresAt === authorization.expiresAt &&
      canonicalJson(payload.scope) === canonicalJson(scope),
    "INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION_BINDING_REJECTED"
  );
  return Object.freeze({
    ...context,
    authorization,
    forbiddenRootPath,
    ledgerRootPath,
    payload
  });
}

export function authorizeIntegratedLiveDrillChildLaunch(
  environment,
  expectedScopeId,
  options = {}
) {
  const validated = validateIntegratedLiveDrillChildLaunchEnvironment(
    environment,
    expectedScopeId,
    options
  );
  const launchReceipt = consumeIntegratedLiveDrillChildLaunch({
    authorization: validated.authorization,
    claim: validated.payload.claim,
    reservation: validated.payload.reservation,
    tokenId: validated.payload.tokenId,
    ledgerRootPath: validated.ledgerRootPath,
    forbiddenRootPath: validated.forbiddenRootPath,
    now: options.now ?? Date.now()
  });
  const {
    forbiddenRootPath: _forbiddenRootPath,
    ledgerRootPath: _ledgerRootPath,
    payload: _payload,
    ...context
  } = validated;
  return Object.freeze({
    ...context,
    launchReceipt
  });
}

export function verifyIntegratedLiveDrillConsumedChildLaunch(
  environment,
  expectedScopeId,
  { launchReceipt, ...options } = {}
) {
  const validated = validateIntegratedLiveDrillChildLaunchEnvironment(
    environment,
    expectedScopeId,
    options
  );
  const resolvedLaunchReceipt = validateIntegratedLiveDrillConsumedChildLaunch({
    authorization: validated.authorization,
    claim: validated.payload.claim,
    reservation: validated.payload.reservation,
    tokenId: validated.payload.tokenId,
    launchReceipt,
    ledgerRootPath: validated.ledgerRootPath,
    forbiddenRootPath: validated.forbiddenRootPath
  });
  const ledger = validateIntegratedLiveDrillConsumedControlLedger({
    authorization: validated.authorization,
    claim: validated.payload.claim,
    ledgerRootPath: validated.ledgerRootPath,
    forbiddenRootPath: validated.forbiddenRootPath
  });
  const {
    forbiddenRootPath: _forbiddenRootPath,
    ledgerRootPath: _ledgerRootPath,
    payload: _payload,
    ...context
  } = validated;
  return Object.freeze({
    ...context,
    launchReceipt: resolvedLaunchReceipt,
    controlLedgerReceipt: ledger.controlLedgerReceipt,
    reservations: ledger.reservations
  });
}

export function authorizeOrVerifyIntegratedLiveDrillChildLaunch(
  environment,
  expectedScopeId,
  options = {}
) {
  let launchReceipt;
  let launchConsumedNow = false;
  try {
    launchReceipt = authorizeIntegratedLiveDrillChildLaunch(
      environment,
      expectedScopeId,
      options
    ).launchReceipt;
    launchConsumedNow = true;
  } catch (cause) {
    if (
      cause?.message !==
        "INTEGRATED_LIVE_DRILL_CHILD_LAUNCH_ALREADY_CONSUMED"
    ) {
      throw cause;
    }
  }
  const verified = verifyIntegratedLiveDrillConsumedChildLaunch(
    environment,
    expectedScopeId,
    {
      ...(launchReceipt === undefined ? {} : { launchReceipt }),
      ...options
    }
  );
  return Object.freeze({
    ...verified,
    launchConsumedNow
  });
}

export function assertIntegratedLiveDrillChildAuthorizationCurrent(
  context,
  { now = Date.now() } = {}
) {
  requireCondition(
    context &&
      Number.isSafeInteger(context.expiresAt) &&
      Number.isSafeInteger(now) &&
      now <= context.expiresAt,
    "INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION_TIME_REJECTED"
  );
  return context;
}
