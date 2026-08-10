import fs from "node:fs";
import path from "node:path";

import { canonicalJson } from "./canonical-json.js";
import {
  INTEGRATED_LIVE_DRILL_SPEND_SCOPES,
  integratedLiveDrillAuthorizationAttestationDigest,
  integratedLiveDrillCanonicalSha256,
  integratedLiveDrillSha256,
  validateIntegratedLiveDrillRunAuthorization,
  validateIntegratedLiveDrillSpendAuthorization
} from "./integrated-live-drill-authorization.js";

export const INTEGRATED_LIVE_DRILL_AUTHORIZATION_CLAIM_SCHEMA =
  "tideproof.highwater-drill-authorization-claim.v1";
export const INTEGRATED_LIVE_DRILL_SPEND_RESERVATION_SCHEMA =
  "tideproof.highwater-drill-spend-reservation.v1";
export const INTEGRATED_LIVE_DRILL_CONTROL_LEDGER_RECEIPT_SCHEMA =
  "tideproof.highwater-drill-control-ledger-receipt.v1";
export const INTEGRATED_LIVE_DRILL_CHILD_LAUNCH_SCHEMA =
  "tideproof.highwater-drill-child-launch-consumption.v1";

const MAX_LEDGER_FILE_BYTES = 64 * 1024;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(value, code) {
  if (!value) reject(code);
}

function exactKeys(value, keys) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join("\n") === [...keys].sort().join("\n")
  );
}

function pathIsWithin(candidate, root) {
  const relative = path.relative(root, candidate);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function secureLedgerRoot(ledgerRootPath, forbiddenRootPath) {
  requireCondition(
    typeof ledgerRootPath === "string" &&
      path.isAbsolute(ledgerRootPath) &&
      path.resolve(ledgerRootPath) === ledgerRootPath &&
      typeof forbiddenRootPath === "string" &&
      path.isAbsolute(forbiddenRootPath) &&
      path.resolve(forbiddenRootPath) === forbiddenRootPath,
    "INTEGRATED_LIVE_DRILL_CONTROL_LEDGER_ROOT_REJECTED"
  );
  let canonicalLedger;
  let canonicalForbidden;
  let stat;
  try {
    canonicalLedger = fs.realpathSync(ledgerRootPath);
    canonicalForbidden = fs.realpathSync(forbiddenRootPath);
    stat = fs.lstatSync(ledgerRootPath);
  } catch (cause) {
    reject("INTEGRATED_LIVE_DRILL_CONTROL_LEDGER_ROOT_REJECTED", cause);
  }
  const expectedUid = typeof process.getuid === "function"
    ? process.getuid()
    : stat.uid;
  requireCondition(
    canonicalLedger === ledgerRootPath &&
      stat.isDirectory() &&
      !stat.isSymbolicLink() &&
      stat.uid === expectedUid &&
      (stat.mode & 0o777) === 0o700 &&
      !pathIsWithin(canonicalLedger, canonicalForbidden),
    "INTEGRATED_LIVE_DRILL_CONTROL_LEDGER_ROOT_REJECTED"
  );
  return Object.freeze({
    expectedUid,
    ledgerRootPath,
    stat
  });
}

function assertSameRoot(secure) {
  let current;
  try {
    current = fs.lstatSync(secure.ledgerRootPath);
  } catch (cause) {
    reject("INTEGRATED_LIVE_DRILL_CONTROL_LEDGER_ROOT_DRIFT", cause);
  }
  requireCondition(
    current.isDirectory() &&
      !current.isSymbolicLink() &&
      current.dev === secure.stat.dev &&
      current.ino === secure.stat.ino &&
      current.uid === secure.expectedUid &&
      (current.mode & 0o777) === 0o700,
    "INTEGRATED_LIVE_DRILL_CONTROL_LEDGER_ROOT_DRIFT"
  );
}

function syncDirectory(secure) {
  let descriptor;
  try {
    assertSameRoot(secure);
    descriptor = fs.openSync(
      secure.ledgerRootPath,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW
    );
    const opened = fs.fstatSync(descriptor);
    requireCondition(
      opened.dev === secure.stat.dev &&
        opened.ino === secure.stat.ino &&
        opened.uid === secure.expectedUid &&
        (opened.mode & 0o777) === 0o700,
      "INTEGRATED_LIVE_DRILL_CONTROL_LEDGER_ROOT_DRIFT"
    );
    fs.fsyncSync(descriptor);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function readLedgerFile(filePath, secure, code) {
  let descriptor;
  try {
    assertSameRoot(secure);
    descriptor = fs.openSync(
      filePath,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW
    );
    const before = fs.fstatSync(descriptor);
    requireCondition(
      before.isFile() &&
        before.uid === secure.expectedUid &&
        before.nlink === 1 &&
        (before.mode & 0o777) === 0o600 &&
        before.size > 0 &&
        before.size <= MAX_LEDGER_FILE_BYTES,
      code
    );
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor);
    const named = fs.lstatSync(filePath);
    requireCondition(
      before.dev === after.dev &&
        before.ino === after.ino &&
        before.size === after.size &&
        named.dev === after.dev &&
        named.ino === after.ino &&
        !named.isSymbolicLink(),
      code
    );
    return bytes;
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function parseCanonicalLedgerRecord(bytes, code) {
  let parsed;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch (cause) {
    reject(code, cause);
  }
  requireCondition(
    bytes.equals(Buffer.from(`${canonicalJson(parsed)}\n`, "utf8")),
    code
  );
  return parsed;
}

function microsToUsd(value) {
  return `${value / 1_000_000n}.` +
    `${value % 1_000_000n}`.padStart(6, "0");
}

function scopeCumulativeMicros(scopes, throughIndex) {
  let cumulativeMicros = 0n;
  for (const scope of scopes.slice(0, throughIndex + 1)) {
    const [whole, fractional] = scope.maximumExposureUsd.split(".");
    cumulativeMicros += BigInt(whole) * 1_000_000n + BigInt(fractional);
  }
  return cumulativeMicros;
}

function readAndValidateReservationFile({
  authorization,
  claim,
  scope,
  scopeIndex,
  spend,
  secure
}) {
  const code = "INTEGRATED_LIVE_DRILL_SPEND_LEDGER_AMBIGUOUS";
  const fileName = reservationFileName(
    authorization.payload.authorizationId,
    scope
  );
  const bytes = readLedgerFile(
    path.join(secure.ledgerRootPath, fileName),
    secure,
    code
  );
  const body = parseCanonicalLedgerRecord(bytes, code);
  const reservedAt = Date.parse(body?.reservedAt);
  const expectedCumulative = microsToUsd(
    scopeCumulativeMicros(spend.scopes, scopeIndex)
  );
  requireCondition(
    exactKeys(body, [
      "authorizationClaimSha256",
      "authorizationId",
      "cumulativeAuthorizedExposureUsd",
      "reservedAt",
      "schemaVersion",
      "scope"
    ]) &&
      body.schemaVersion === INTEGRATED_LIVE_DRILL_SPEND_RESERVATION_SCHEMA &&
      body.authorizationClaimSha256 === claim.authorizationClaimSha256 &&
      body.authorizationId === authorization.payload.authorizationId &&
      body.cumulativeAuthorizedExposureUsd === expectedCumulative &&
      typeof body.reservedAt === "string" &&
      Number.isFinite(reservedAt) &&
      new Date(reservedAt).toISOString() === body.reservedAt &&
      reservedAt >= authorization.issuedAt &&
      reservedAt <= authorization.expiresAt &&
      canonicalJson(body.scope) === canonicalJson(scope),
    code
  );
  return Object.freeze({
    body: Object.freeze(body),
    bytes,
    digest: integratedLiveDrillCanonicalSha256(body),
    fileName,
    reservedAt
  });
}

function reservationReceiptFromValidated(authorization, scope, validated) {
  return Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_SPEND_RESERVATION_SCHEMA,
    authorizationId: authorization.payload.authorizationId,
    cumulativeAuthorizedExposureUsd:
      validated.body.cumulativeAuthorizedExposureUsd,
    fileByteLength: validated.bytes.length,
    fileNameSha256: integratedLiveDrillSha256(validated.fileName),
    reservationSha256: validated.digest,
    scopeId: scope.scopeId,
    sequence: scope.sequence
  });
}

function createDurableLedgerFile(filePath, body, secure, replayCode) {
  const serialized = Buffer.from(`${canonicalJson(body)}\n`, "utf8");
  requireCondition(
    serialized.length > 0 && serialized.length <= MAX_LEDGER_FILE_BYTES,
    "INTEGRATED_LIVE_DRILL_CONTROL_LEDGER_WRITE_REJECTED"
  );
  let descriptor;
  try {
    assertSameRoot(secure);
    descriptor = fs.openSync(
      filePath,
      fs.constants.O_WRONLY |
        fs.constants.O_CREAT |
        fs.constants.O_EXCL |
        fs.constants.O_NOFOLLOW,
      0o600
    );
    fs.writeFileSync(descriptor, serialized);
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = undefined;
    syncDirectory(secure);
    const reread = readLedgerFile(
      filePath,
      secure,
      "INTEGRATED_LIVE_DRILL_CONTROL_LEDGER_REREAD_REJECTED"
    );
    requireCondition(
      reread.equals(serialized),
      "INTEGRATED_LIVE_DRILL_CONTROL_LEDGER_REREAD_REJECTED"
    );
    return Object.freeze({ bytes: reread, byteLength: reread.length });
  } catch (cause) {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch { /* Preserve first error. */ }
    }
    if (cause?.code === "EEXIST") reject(replayCode, cause);
    if (cause?.message?.startsWith("INTEGRATED_LIVE_DRILL_")) throw cause;
    reject("INTEGRATED_LIVE_DRILL_CONTROL_LEDGER_WRITE_REJECTED", cause);
  }
}

function claimFileName(authorizationId) {
  requireCondition(
    UUID.test(authorizationId ?? ""),
    "INTEGRATED_LIVE_DRILL_AUTHORIZATION_CLAIM_REJECTED"
  );
  return `${authorizationId}.authorization-claim.json`;
}

function reservationFileName(authorizationId, scope) {
  return `${authorizationId}.${String(scope.sequence).padStart(2, "0")}.` +
    `${scope.scopeId.toLowerCase().replaceAll("_", "-")}.spend.json`;
}

function childLaunchFileName(authorizationId, scope) {
  return `${authorizationId}.${String(scope.sequence).padStart(2, "0")}.` +
    `${scope.scopeId.toLowerCase().replaceAll("_", "-")}.child-launch.json`;
}

function authorizationClaimBody(authorization, humanTrustRoot, claimedAt) {
  return Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_AUTHORIZATION_CLAIM_SCHEMA,
    authorizationAttestationSha256:
      integratedLiveDrillAuthorizationAttestationDigest(
        authorization.attestation
      ),
    authorizationId: authorization.payload.authorizationId,
    claimedAt,
    configDigest: authorization.payload.configDigest,
    humanAuthorizationKeyIdSha256: humanTrustRoot.keyIdSha256,
    humanAuthorizationTrustRootCommitment:
      authorization.payload.humanAuthorizationTrustRootCommitment,
    runId: authorization.payload.runId,
    sourceCommit: authorization.payload.sourceCommit,
    spendAuthorizationSha256: integratedLiveDrillCanonicalSha256(
      authorization.payload.spendAuthorization
    ),
    specSha256: authorization.payload.specSha256,
    treeDigest: authorization.payload.treeDigest
  });
}

export function consumeIntegratedLiveDrillRunAuthorization(
  attestation,
  {
    spec,
    expectation,
    committedTrustRoot,
    humanAuthorizationTrustRoot,
    ledgerRootPath,
    forbiddenRootPath,
    now = Date.now()
  }
) {
  const secure = secureLedgerRoot(ledgerRootPath, forbiddenRootPath);
  const authorization = validateIntegratedLiveDrillRunAuthorization(
    attestation,
    {
      spec,
      expectation,
      committedTrustRoot,
      humanAuthorizationTrustRoot,
      authorizationLedgerRootPath: ledgerRootPath,
      now
    }
  );
  const fileName = claimFileName(authorization.payload.authorizationId);
  const filePath = path.join(ledgerRootPath, fileName);
  // Any pre-existing pathname, including an empty/truncated/symlinked one, is
  // an ambiguous prior consume and therefore permanently denies reuse.
  if (fs.existsSync(filePath)) {
    reject("INTEGRATED_LIVE_DRILL_AUTHORIZATION_ALREADY_CONSUMED");
  }
  const claimedAt = new Date(now).toISOString();
  const body = authorizationClaimBody(
    authorization,
    humanAuthorizationTrustRoot,
    claimedAt
  );
  const persisted = createDurableLedgerFile(
    filePath,
    body,
    secure,
    "INTEGRATED_LIVE_DRILL_AUTHORIZATION_ALREADY_CONSUMED"
  );
  return Object.freeze({
    authorization,
    claim: Object.freeze({
      schemaVersion: INTEGRATED_LIVE_DRILL_AUTHORIZATION_CLAIM_SCHEMA,
      authorizationId: authorization.payload.authorizationId,
      authorizationClaimSha256: integratedLiveDrillCanonicalSha256(body),
      fileByteLength: persisted.byteLength,
      fileNameSha256: integratedLiveDrillSha256(fileName),
      spendAuthorizationSha256: body.spendAuthorizationSha256
    })
  });
}

function readAndValidateClaimFile(authorization, secure) {
  const fileName = claimFileName(authorization.payload.authorizationId);
  const bytes = readLedgerFile(
    path.join(secure.ledgerRootPath, fileName),
    secure,
    "INTEGRATED_LIVE_DRILL_AUTHORIZATION_CLAIM_AMBIGUOUS"
  );
  const parsed = parseCanonicalLedgerRecord(
    bytes,
    "INTEGRATED_LIVE_DRILL_AUTHORIZATION_CLAIM_AMBIGUOUS"
  );
  const claimedAt = Date.parse(parsed?.claimedAt);
  requireCondition(
    exactKeys(parsed, [
        "authorizationAttestationSha256",
        "authorizationId",
        "claimedAt",
        "configDigest",
        "humanAuthorizationKeyIdSha256",
        "humanAuthorizationTrustRootCommitment",
        "runId",
        "schemaVersion",
        "sourceCommit",
        "spendAuthorizationSha256",
        "specSha256",
        "treeDigest"
      ]) &&
      parsed.schemaVersion === INTEGRATED_LIVE_DRILL_AUTHORIZATION_CLAIM_SCHEMA &&
      parsed.authorizationAttestationSha256 ===
        integratedLiveDrillAuthorizationAttestationDigest(
          authorization.attestation
        ) &&
      parsed.authorizationId === authorization.payload.authorizationId &&
      typeof parsed.claimedAt === "string" &&
      Number.isFinite(claimedAt) &&
      new Date(claimedAt).toISOString() === parsed.claimedAt &&
      claimedAt >= authorization.issuedAt &&
      claimedAt <= authorization.expiresAt &&
      parsed.configDigest === authorization.payload.configDigest &&
      parsed.humanAuthorizationKeyIdSha256 ===
        authorization.humanAuthorizationKeyIdSha256 &&
      parsed.humanAuthorizationTrustRootCommitment ===
        authorization.payload.humanAuthorizationTrustRootCommitment &&
      parsed.runId === authorization.payload.runId &&
      parsed.sourceCommit === authorization.payload.sourceCommit &&
      parsed.spendAuthorizationSha256 === integratedLiveDrillCanonicalSha256(
        authorization.payload.spendAuthorization
      ) &&
      parsed.specSha256 === authorization.payload.specSha256 &&
      parsed.treeDigest === authorization.payload.treeDigest,
    "INTEGRATED_LIVE_DRILL_AUTHORIZATION_CLAIM_AMBIGUOUS"
  );
  return Object.freeze({
    body: Object.freeze(parsed),
    bytes,
    digest: integratedLiveDrillCanonicalSha256(parsed),
    fileName
  });
}

function claimReceiptFromValidated(authorization, validated) {
  return Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_AUTHORIZATION_CLAIM_SCHEMA,
    authorizationId: authorization.payload.authorizationId,
    authorizationClaimSha256: validated.digest,
    fileByteLength: validated.bytes.length,
    fileNameSha256: integratedLiveDrillSha256(validated.fileName),
    spendAuthorizationSha256:
      validated.body.spendAuthorizationSha256
  });
}

function validateClaimFile(authorization, claim, secure) {
  const validated = readAndValidateClaimFile(authorization, secure);
  const expected = claimReceiptFromValidated(authorization, validated);
  requireCondition(
    canonicalJson(claim) === canonicalJson(expected),
    "INTEGRATED_LIVE_DRILL_AUTHORIZATION_CLAIM_AMBIGUOUS"
  );
  return validated.body;
}

export function reserveIntegratedLiveDrillSpend({
  authorization,
  claim,
  scopeId,
  ledgerRootPath,
  forbiddenRootPath,
  now = Date.now()
}) {
  const secure = secureLedgerRoot(ledgerRootPath, forbiddenRootPath);
  requireCondition(
    Number.isSafeInteger(now) &&
      now >= authorization.issuedAt &&
      now <= authorization.expiresAt,
    "INTEGRATED_LIVE_DRILL_SPEND_RESERVATION_TIME_REJECTED"
  );
  validateClaimFile(authorization, claim, secure);
  const spend = validateIntegratedLiveDrillSpendAuthorization(
    authorization.payload.spendAuthorization,
    authorization.payload.maximumAwsCostUsd
  ).value;
  const scopeIndex = spend.scopes.findIndex((value) => value.scopeId === scopeId);
  requireCondition(
    scopeIndex >= 0,
    "INTEGRATED_LIVE_DRILL_SPEND_SCOPE_REJECTED"
  );
  for (let index = 0; index < scopeIndex; index += 1) {
    const prior = spend.scopes[index];
    const priorPath = path.join(
      ledgerRootPath,
      reservationFileName(authorization.payload.authorizationId, prior)
    );
    requireCondition(
      fs.existsSync(priorPath),
      "INTEGRATED_LIVE_DRILL_SPEND_RESERVATION_ORDER_REJECTED"
    );
    const validatedPrior = readAndValidateReservationFile({
      authorization,
      claim,
      scope: prior,
      scopeIndex: index,
      spend,
      secure
    });
    requireCondition(
      validatedPrior.reservedAt <= now,
      "INTEGRATED_LIVE_DRILL_SPEND_RESERVATION_ORDER_REJECTED"
    );
  }
  const cumulativeMicros = scopeCumulativeMicros(spend.scopes, scopeIndex);
  const maximumMicros = BigInt(
    spend.maximumCumulativeExposureUsd.replace(".", "")
  );
  requireCondition(
    cumulativeMicros <= maximumMicros,
    "INTEGRATED_LIVE_DRILL_SPEND_CAP_EXCEEDED"
  );
  const scope = spend.scopes[scopeIndex];
  const body = Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_SPEND_RESERVATION_SCHEMA,
    authorizationClaimSha256: claim.authorizationClaimSha256,
    authorizationId: authorization.payload.authorizationId,
    cumulativeAuthorizedExposureUsd: microsToUsd(cumulativeMicros),
    reservedAt: new Date(now).toISOString(),
    scope
  });
  const fileName = reservationFileName(
    authorization.payload.authorizationId,
    scope
  );
  const persisted = createDurableLedgerFile(
    path.join(ledgerRootPath, fileName),
    body,
    secure,
    "INTEGRATED_LIVE_DRILL_SPEND_SCOPE_ALREADY_RESERVED"
  );
  return Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_SPEND_RESERVATION_SCHEMA,
    authorizationId: authorization.payload.authorizationId,
    cumulativeAuthorizedExposureUsd: body.cumulativeAuthorizedExposureUsd,
    fileByteLength: persisted.byteLength,
    fileNameSha256: integratedLiveDrillSha256(fileName),
    reservationSha256: integratedLiveDrillCanonicalSha256(body),
    scopeId: scope.scopeId,
    sequence: scope.sequence
  });
}

function validateReservationReceipt({
  authorization,
  claim,
  receipt,
  scope,
  validated
}) {
  requireCondition(
    exactKeys(receipt, [
      "authorizationId",
      "cumulativeAuthorizedExposureUsd",
      "fileByteLength",
      "fileNameSha256",
      "reservationSha256",
      "schemaVersion",
      "scopeId",
      "sequence"
    ]) &&
      receipt.schemaVersion === INTEGRATED_LIVE_DRILL_SPEND_RESERVATION_SCHEMA &&
      receipt.authorizationId === authorization.payload.authorizationId &&
      receipt.scopeId === scope.scopeId &&
      receipt.sequence === scope.sequence &&
      receipt.cumulativeAuthorizedExposureUsd ===
        validated.body.cumulativeAuthorizedExposureUsd &&
      receipt.fileByteLength === validated.bytes.length &&
      receipt.fileNameSha256 === integratedLiveDrillSha256(
        validated.fileName
      ) &&
      receipt.reservationSha256 === validated.digest &&
      validated.body.authorizationClaimSha256 ===
        claim.authorizationClaimSha256,
    "INTEGRATED_LIVE_DRILL_SPEND_LEDGER_AMBIGUOUS"
  );
}

function readAndValidateChildLaunchFile({
  authorization,
  claim,
  reservationSha256,
  scope,
  secure
}) {
  const code = "INTEGRATED_LIVE_DRILL_CHILD_LAUNCH_AMBIGUOUS";
  const fileName = childLaunchFileName(
    authorization.payload.authorizationId,
    scope
  );
  const bytes = readLedgerFile(
    path.join(secure.ledgerRootPath, fileName),
    secure,
    code
  );
  const body = parseCanonicalLedgerRecord(bytes, code);
  const launchedAt = Date.parse(body?.launchedAt);
  requireCondition(
    exactKeys(body, [
      "authorizationClaimSha256",
      "authorizationId",
      "launchedAt",
      "reservationSha256",
      "schemaVersion",
      "scope",
      "tokenId"
    ]) &&
      body.schemaVersion === INTEGRATED_LIVE_DRILL_CHILD_LAUNCH_SCHEMA &&
      body.authorizationClaimSha256 === claim.authorizationClaimSha256 &&
      body.authorizationId === authorization.payload.authorizationId &&
      body.reservationSha256 === reservationSha256 &&
      UUID.test(body.tokenId ?? "") &&
      canonicalJson(body.scope) === canonicalJson(scope) &&
      typeof body.launchedAt === "string" &&
      Number.isFinite(launchedAt) &&
      new Date(launchedAt).toISOString() === body.launchedAt &&
      launchedAt >= authorization.issuedAt &&
      launchedAt <= authorization.expiresAt,
    code
  );
  return Object.freeze({
    body: Object.freeze(body),
    bytes,
    digest: integratedLiveDrillCanonicalSha256(body),
    fileName,
    launchedAt
  });
}

export function consumeIntegratedLiveDrillChildLaunch({
  authorization,
  claim,
  reservation,
  tokenId,
  ledgerRootPath,
  forbiddenRootPath,
  now = Date.now()
}) {
  const secure = secureLedgerRoot(ledgerRootPath, forbiddenRootPath);
  requireCondition(
    Number.isSafeInteger(now) &&
      now >= authorization.issuedAt &&
      now <= authorization.expiresAt &&
      UUID.test(tokenId ?? ""),
    "INTEGRATED_LIVE_DRILL_CHILD_LAUNCH_TIME_REJECTED"
  );
  validateClaimFile(authorization, claim, secure);
  const spend = validateIntegratedLiveDrillSpendAuthorization(
    authorization.payload.spendAuthorization,
    authorization.payload.maximumAwsCostUsd
  ).value;
  const scopeIndex = spend.scopes.findIndex(
    ({ scopeId }) => scopeId === reservation?.scopeId
  );
  requireCondition(
    scopeIndex >= 0,
    "INTEGRATED_LIVE_DRILL_CHILD_LAUNCH_REJECTED"
  );
  const scope = spend.scopes[scopeIndex];
  for (let index = 0; index < scopeIndex; index += 1) {
    const priorScope = spend.scopes[index];
    let priorReservation;
    try {
      priorReservation = readAndValidateReservationFile({
        authorization,
        claim,
        scope: priorScope,
        scopeIndex: index,
        spend,
        secure
      });
      const priorLaunch = readAndValidateChildLaunchFile({
        authorization,
        claim,
        reservationSha256: priorReservation.digest,
        scope: priorScope,
        secure
      });
      requireCondition(
        priorReservation.reservedAt <= priorLaunch.launchedAt &&
          priorLaunch.launchedAt <= now,
        "INTEGRATED_LIVE_DRILL_CHILD_LAUNCH_ORDER_REJECTED"
      );
    } catch (cause) {
      reject("INTEGRATED_LIVE_DRILL_CHILD_LAUNCH_ORDER_REJECTED", cause);
    }
  }
  const validated = readAndValidateReservationFile({
    authorization,
    claim,
    scope,
    scopeIndex,
    spend,
    secure
  });
  requireCondition(
    validated.reservedAt <= now,
    "INTEGRATED_LIVE_DRILL_CHILD_LAUNCH_ORDER_REJECTED"
  );
  validateReservationReceipt({
    authorization,
    claim,
    receipt: reservation,
    scope,
    validated
  });
  const body = Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_CHILD_LAUNCH_SCHEMA,
    authorizationClaimSha256: claim.authorizationClaimSha256,
    authorizationId: authorization.payload.authorizationId,
    launchedAt: new Date(now).toISOString(),
    reservationSha256: reservation.reservationSha256,
    scope,
    tokenId
  });
  const fileName = childLaunchFileName(
    authorization.payload.authorizationId,
    scope
  );
  const persisted = createDurableLedgerFile(
    path.join(ledgerRootPath, fileName),
    body,
    secure,
    "INTEGRATED_LIVE_DRILL_CHILD_LAUNCH_ALREADY_CONSUMED"
  );
  return Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_CHILD_LAUNCH_SCHEMA,
    authorizationId: authorization.payload.authorizationId,
    childLaunchSha256: integratedLiveDrillCanonicalSha256(body),
    fileByteLength: persisted.byteLength,
    fileNameSha256: integratedLiveDrillSha256(fileName),
    reservationSha256: reservation.reservationSha256,
    scopeId: scope.scopeId,
    sequence: scope.sequence,
    tokenId
  });
}

export function finalizeIntegratedLiveDrillControlLedger({
  authorization,
  claim,
  reservations,
  ledgerRootPath,
  forbiddenRootPath
}) {
  const secure = secureLedgerRoot(ledgerRootPath, forbiddenRootPath);
  validateClaimFile(authorization, claim, secure);
  requireCondition(
    Array.isArray(reservations) &&
      reservations.length === INTEGRATED_LIVE_DRILL_SPEND_SCOPES.length,
    "INTEGRATED_LIVE_DRILL_SPEND_LEDGER_INCOMPLETE"
  );
  const spend = validateIntegratedLiveDrillSpendAuthorization(
    authorization.payload.spendAuthorization,
    authorization.payload.maximumAwsCostUsd
  ).value;
  const reservationDigests = [];
  const childLaunchDigests = [];
  let previousReservedAt = authorization.issuedAt;
  let previousLaunchedAt = authorization.issuedAt;
  for (const [index, scope] of spend.scopes.entries()) {
    const receipt = reservations[index];
    const { body, bytes, digest, fileName } =
      readAndValidateReservationFile({
        authorization,
        claim,
        scope,
        scopeIndex: index,
        spend,
        secure
      });
    validateReservationReceipt({
      authorization,
      claim,
      receipt,
      scope,
      validated: { body, bytes, digest, fileName }
    });
    const reservedAt = Date.parse(body.reservedAt);
    requireCondition(
      reservedAt >= previousReservedAt,
      "INTEGRATED_LIVE_DRILL_SPEND_RESERVATION_ORDER_REJECTED"
    );
    previousReservedAt = reservedAt;
    reservationDigests.push(digest);
    const launch = readAndValidateChildLaunchFile({
      authorization,
      claim,
      reservationSha256: receipt.reservationSha256,
      scope,
      secure
    });
    requireCondition(
      launch.launchedAt >= reservedAt &&
        launch.launchedAt >= previousLaunchedAt,
      "INTEGRATED_LIVE_DRILL_CHILD_LAUNCH_ORDER_REJECTED"
    );
    previousLaunchedAt = launch.launchedAt;
    childLaunchDigests.push(launch.digest);
  }
  const receipt = Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_CONTROL_LEDGER_RECEIPT_SCHEMA,
    authorizationAttestationSha256:
      integratedLiveDrillAuthorizationAttestationDigest(
        authorization.attestation
      ),
    authorizationClaimSha256: claim.authorizationClaimSha256,
    authorizationId: authorization.payload.authorizationId,
    authorizedMaximumCumulativeExposureUsd:
      spend.maximumCumulativeExposureUsd,
    childLaunchDigests,
    exactChildLaunchCount: childLaunchDigests.length,
    exactScopeCount: spend.scopes.length,
    reservationDigests,
    reservedCumulativeExposureUsd:
      reservations.at(-1).cumulativeAuthorizedExposureUsd,
    runId: authorization.payload.runId,
    spendAuthorizationSha256: claim.spendAuthorizationSha256
  });
  return Object.freeze({
    ...receipt,
    receiptSha256: integratedLiveDrillCanonicalSha256(receipt)
  });
}

export function validateIntegratedLiveDrillConsumedControlLedger({
  authorization,
  claim = null,
  controlLedgerReceipt,
  ledgerRootPath,
  forbiddenRootPath
}) {
  const secure = secureLedgerRoot(ledgerRootPath, forbiddenRootPath);
  const validatedClaim = readAndValidateClaimFile(authorization, secure);
  const resolvedClaim = claimReceiptFromValidated(
    authorization,
    validatedClaim
  );
  if (claim !== null) {
    requireCondition(
      canonicalJson(claim) === canonicalJson(resolvedClaim),
      "INTEGRATED_LIVE_DRILL_AUTHORIZATION_CLAIM_AMBIGUOUS"
    );
  }
  const spend = validateIntegratedLiveDrillSpendAuthorization(
    authorization.payload.spendAuthorization,
    authorization.payload.maximumAwsCostUsd
  ).value;
  const reservations = spend.scopes.map((scope, scopeIndex) => {
    const validated = readAndValidateReservationFile({
      authorization,
      claim: resolvedClaim,
      scope,
      scopeIndex,
      spend,
      secure
    });
    return reservationReceiptFromValidated(authorization, scope, validated);
  });
  const validated = finalizeIntegratedLiveDrillControlLedger({
    authorization,
    claim: resolvedClaim,
    reservations,
    ledgerRootPath,
    forbiddenRootPath
  });
  if (controlLedgerReceipt !== undefined) {
    requireCondition(
      canonicalJson(controlLedgerReceipt) === canonicalJson(validated),
      "INTEGRATED_LIVE_DRILL_CONTROL_LEDGER_RECEIPT_REJECTED"
    );
  }
  return Object.freeze({
    authorization,
    claim: resolvedClaim,
    controlLedgerReceipt: validated,
    reservations: Object.freeze(reservations)
  });
}

export const __test = Object.freeze({
  childLaunchFileName,
  claimFileName,
  reservationFileName
});
