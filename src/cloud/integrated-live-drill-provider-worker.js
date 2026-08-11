import fs from "node:fs";
import path from "node:path";

import { isolatedEvidenceProcessEnvironment } from
  "./aws-evidence-identity.js";
import { canonicalJson } from "./canonical-json.js";
import {
  validateIntegratedLiveDrillRecoveryContinuityPreCallIntent
} from "./integrated-live-drill-recovery-continuity.js";
import { runIntegratedLiveDrillProviderRecovery } from
  "./integrated-live-drill-provider-recovery.js";
import { CockroachManagedMcpRecoveryClient } from
  "./managed-mcp-client.js";
import {
  DeterministicRecoveryBroker,
  principalBindingHash,
  RecoveryAuditSink
} from "./recovery-broker.js";

export const INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_SCHEMA =
  "tideproof.highwater-drill-provider-worker-input.v1";
export const INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_PATH_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_PATH";
export const INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_PRINCIPAL_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_PRINCIPAL";

const MAX_WORKER_INPUT_BYTES = 8 * 1024 * 1024;

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function exactKeys(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const ownKeys = Object.keys(value);
  return ownKeys.length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key));
}

function requiredText(value, code, maximum = 4096) {
  requireCondition(
    typeof value === "string" &&
      value.length > 0 &&
      value.length <= maximum &&
      !/[\0\r\n]/u.test(value),
    code
  );
  return value;
}

function pathIsWithin(candidate, root) {
  const relative = path.relative(root, candidate);
  return relative === "" || (
    !relative.startsWith("..") && !path.isAbsolute(relative)
  );
}

function secureWorkerInputPath(inputPath, rootPath, forbiddenRootPath) {
  const code = "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_REJECTED";
  requireCondition(
    [inputPath, rootPath, forbiddenRootPath].every(
      (value) =>
        typeof value === "string" &&
        path.isAbsolute(value) &&
        path.resolve(value) === value
    ),
    code
  );
  let canonicalRoot;
  let canonicalForbidden;
  let rootStat;
  try {
    canonicalRoot = fs.realpathSync(rootPath);
    canonicalForbidden = fs.realpathSync(forbiddenRootPath);
    rootStat = fs.lstatSync(rootPath);
  } catch (cause) {
    reject(code, cause);
  }
  const expectedUid = typeof process.getuid === "function"
    ? process.getuid()
    : rootStat.uid;
  requireCondition(
    canonicalRoot === rootPath &&
      rootStat.isDirectory() &&
      !rootStat.isSymbolicLink() &&
      rootStat.uid === expectedUid &&
      (rootStat.mode & 0o777) === 0o700 &&
      pathIsWithin(inputPath, canonicalRoot) &&
      !pathIsWithin(canonicalRoot, canonicalForbidden),
    code
  );
  return Object.freeze({
    expectedUid,
    inputPath,
    rootPath,
    rootStat
  });
}

function readWorkerInputFile(inputPath, secure) {
  const code = "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_REJECTED";
  let descriptor;
  try {
    const currentRoot = fs.lstatSync(secure.rootPath);
    requireCondition(
      currentRoot.dev === secure.rootStat.dev &&
        currentRoot.ino === secure.rootStat.ino &&
        currentRoot.uid === secure.expectedUid &&
        currentRoot.isDirectory() &&
        !currentRoot.isSymbolicLink() &&
        (currentRoot.mode & 0o777) === 0o700,
      code
    );
    descriptor = fs.openSync(
      inputPath,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW
    );
    const before = fs.fstatSync(descriptor);
    requireCondition(
      before.isFile() &&
        before.uid === secure.expectedUid &&
        before.nlink === 1 &&
        (before.mode & 0o777) === 0o600 &&
        before.size > 0 &&
        before.size <= MAX_WORKER_INPUT_BYTES,
      code
    );
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor);
    const named = fs.lstatSync(inputPath);
    requireCondition(
      before.dev === after.dev &&
        before.ino === after.ino &&
        before.size === after.size &&
        after.uid === secure.expectedUid &&
        after.nlink === 1 &&
        (after.mode & 0o777) === 0o600 &&
        named.dev === after.dev &&
        named.ino === after.ino &&
        named.uid === after.uid &&
        named.nlink === 1 &&
        (named.mode & 0o777) === 0o600 &&
        !named.isSymbolicLink() &&
        bytes.length === after.size,
      code
    );
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
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

export function validateIntegratedLiveDrillProviderWorkerInput(value) {
  requireCondition(
    exactKeys(value, [
      "authenticatedPrincipal",
      "context",
      "schemaVersion"
    ]) &&
      value.schemaVersion ===
        INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_SCHEMA,
    "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_REJECTED"
  );
  const authenticatedPrincipal = requiredText(
    value.authenticatedPrincipal,
    "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_PRINCIPAL_REJECTED",
    512
  );
  const intent = validateIntegratedLiveDrillRecoveryContinuityPreCallIntent(
    value.context?.preCallIntent,
    {
      authorization: value.context?.authorization,
      controlLedgerReceipt: value.context?.controlLedgerReceipt
    }
  );
  requireCondition(
    principalBindingHash(authenticatedPrincipal) ===
      intent.subjectBindingSha256,
    "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_PRINCIPAL_REJECTED"
  );
  return Object.freeze({
    authenticatedPrincipal,
    context: value.context,
    schemaVersion: value.schemaVersion
  });
}

export function readIntegratedLiveDrillProviderWorkerInput({
  forbiddenRootPath,
  inputPath,
  rootPath
}) {
  const secure = secureWorkerInputPath(
    inputPath,
    rootPath,
    forbiddenRootPath
  );
  return validateIntegratedLiveDrillProviderWorkerInput(
    readWorkerInputFile(inputPath, secure)
  );
}

export function integratedLiveDrillProviderWorkerEnvironment(
  sourceEnvironment,
  { inputPath, authenticatedPrincipal }
) {
  const apiKey = requiredText(
    sourceEnvironment?.MCP_API_KEY,
    "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_CREDENTIAL_REJECTED",
    8192
  );
  requireCondition(
    apiKey.length >= 24,
    "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_CREDENTIAL_REJECTED"
  );
  const auditDatabaseUrl = requiredText(
    sourceEnvironment?.PRIMARY_AUDIT_DATABASE_URL,
    "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_AUDIT_DATABASE_REJECTED",
    8192
  );
  const value = {
    ...isolatedEvidenceProcessEnvironment(sourceEnvironment),
    MCP_API_KEY: apiKey,
    PRIMARY_AUDIT_DATABASE_URL: auditDatabaseUrl,
    [INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_PATH_ENVIRONMENT]:
      requiredText(
        inputPath,
        "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_REJECTED"
      ),
    [INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_PRINCIPAL_ENVIRONMENT]:
      requiredText(
        authenticatedPrincipal,
        "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_PRINCIPAL_REJECTED",
        512
      )
  };
  return Object.freeze(value);
}

async function runIntegratedLiveDrillProviderWorkerInternal({
  input,
  environment
}, {
  fetchImpl,
  auditClientFactory
}) {
  const validated = validateIntegratedLiveDrillProviderWorkerInput(input);
  const intent = validated.context.preCallIntent;
  const apiKey = requiredText(
    environment?.MCP_API_KEY,
    "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_CREDENTIAL_REJECTED",
    8192
  );
  requireCondition(
    apiKey.length >= 24 && typeof fetchImpl === "function",
    "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_CREDENTIAL_REJECTED"
  );
  const auditDatabaseUrl = requiredText(
    environment?.PRIMARY_AUDIT_DATABASE_URL,
    "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_AUDIT_DATABASE_REJECTED",
    8192
  );
  const trustedRunContext = validated.context.trustedRunContext;
  const client = new CockroachManagedMcpRecoveryClient({
    apiKey,
    clusterId: intent.recoveryClusterId,
    fetchImpl
  });
  const broker = new DeterministicRecoveryBroker({
    auditSink: new RecoveryAuditSink({
      connectionString: auditDatabaseUrl,
      clientFactory: auditClientFactory
    }),
    buildIdentity: trustedRunContext.spec.sourceBuildIdentity,
    expectedSourceClusterId:
      trustedRunContext.recoveryBrokerConfiguration.expectedSourceClusterId,
    mcpClient: client,
    recoveryClusterId: intent.recoveryClusterId,
    sessionResolver: Object.freeze({
      async resolve({ authenticatedPrincipal }) {
        requireCondition(
          authenticatedPrincipal === validated.authenticatedPrincipal &&
            principalBindingHash(authenticatedPrincipal) ===
              intent.subjectBindingSha256,
          "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_PRINCIPAL_REJECTED"
        );
        return Object.freeze({
          recoverySessionId: intent.recoverySessionId,
          sourceDigest: intent.sourceDigest,
          subjectBindingHash: intent.subjectBindingSha256,
          tenantId: intent.tenantId
        });
      }
    }),
    trustedPublisherKeys:
      trustedRunContext.committedTrustRoot.trustedPublisherKeys
  });
  try {
    const result = await runIntegratedLiveDrillProviderRecovery({
      authenticatedPrincipal: validated.authenticatedPrincipal,
      broker,
      context: validated.context
    });
    requireCondition(
      !JSON.stringify(result).includes(apiKey),
      "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_CREDENTIAL_LEAK_REJECTED"
    );
    return result;
  } finally {
    await client.close();
  }
}

export async function runIntegratedLiveDrillProviderWorker(args) {
  return runIntegratedLiveDrillProviderWorkerInternal(args, {
    auditClientFactory: null,
    fetchImpl: globalThis.fetch
  });
}

export const __test = Object.freeze({
  runWithLocalTransports(args, { auditClientFactory, fetchImpl }) {
    requireCondition(
      typeof auditClientFactory === "function" &&
        typeof fetchImpl === "function",
      "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_TEST_TRANSPORT_REJECTED"
    );
    return runIntegratedLiveDrillProviderWorkerInternal(args, {
      auditClientFactory,
      fetchImpl
    });
  }
});
