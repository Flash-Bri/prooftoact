import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { publishOrReadExactOwnedFile } from "./atomic-create-only-file.js";
import { canonicalJson } from "./canonical-json.js";
import {
  buildIntegratedLiveDrillProviderResult,
  buildIntegratedLiveDrillProviderReady,
  validateIntegratedLiveDrillProviderExchangeInput
} from "./integrated-live-drill-provider-activation.js";
import {
  CockroachManagedMcpRecoveryClient,
  managedMcpLogicalRequest
} from "./managed-mcp-client.js";

const CONSUMPTION_FENCE = "provider-exchange-consumption-fence.json";
const MAX_FENCE_BYTES = 64 * 1024;
const RESULT_NAME = "provider-exchange-result.json";
const MAX_RESULT_BYTES = 2 * 1024 * 1024;
export const PROVIDER_ACTIVATION_MAX_AGE_MILLISECONDS = 30_000;
export const PROVIDER_ACTIVATION_CLOCK_SKEW_MILLISECONDS = 5_000;

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function secureRoot(rootPath) {
  const code = "INTEGRATED_LIVE_DRILL_PROVIDER_EXCHANGE_ROOT_REJECTED";
  requireCondition(
    typeof rootPath === "string" && path.isAbsolute(rootPath) &&
      path.resolve(rootPath) === rootPath && fs.realpathSync(rootPath) === rootPath,
    code
  );
  const stat = fs.lstatSync(rootPath);
  const uid = typeof process.getuid === "function" ? process.getuid() : stat.uid;
  requireCondition(
    stat.isDirectory() && !stat.isSymbolicLink() && stat.uid === uid &&
      (stat.mode & 0o777) === 0o700,
    code
  );
  return Object.freeze({ rootPath, uid });
}

export async function runIntegratedLiveDrillProviderExchange({
  apiKey,
  exchangeInput,
  fetchImpl = globalThis.fetch,
  now = () => Date.now(),
  proceed,
  rootPath
}) {
  requireCondition(
    typeof apiKey === "string" && apiKey.length >= 24 &&
      typeof fetchImpl === "function" && typeof now === "function" &&
      typeof proceed === "function",
    "INTEGRATED_LIVE_DRILL_PROVIDER_EXCHANGE_INPUT_REJECTED"
  );
  const accepted = validateIntegratedLiveDrillProviderExchangeInput(
    exchangeInput
  );
  const current = now();
  const databaseNow = Date.parse(accepted.activationReceipt.activatedAt);
  requireCondition(
    Number.isFinite(current) &&
      current >= databaseNow - PROVIDER_ACTIVATION_CLOCK_SKEW_MILLISECONDS &&
      current <= databaseNow + PROVIDER_ACTIVATION_MAX_AGE_MILLISECONDS &&
      current < Date.parse(accepted.activationReceipt.expiresAt),
    "INTEGRATED_LIVE_DRILL_PROVIDER_EXCHANGE_ACTIVATION_EXPIRED"
  );
  const payload = accepted.providerRequest.payload;
  requireCondition(
    sha256(canonicalJson(managedMcpLogicalRequest({
      clusterId: payload.clusterId,
      query: payload.query
    }))) === accepted.providerRequest.binding.logicalMcpRequestSha256,
    "INTEGRATED_LIVE_DRILL_PROVIDER_EXCHANGE_REQUEST_REJECTED"
  );
  const proceedReceipt = await proceed(buildIntegratedLiveDrillProviderReady(
    accepted.activationReceipt
  ));
  requireCondition(
    proceedReceipt?.activationReceiptSha256 ===
      accepted.activationReceipt.receiptSha256 &&
      proceedReceipt?.disposition === "PROCEED_ONCE",
    "INTEGRATED_LIVE_DRILL_PROVIDER_EXCHANGE_PROCEED_REJECTED"
  );
  const proceedCurrent = now();
  requireCondition(
    Number.isFinite(proceedCurrent) &&
      proceedCurrent >=
        databaseNow - PROVIDER_ACTIVATION_CLOCK_SKEW_MILLISECONDS &&
      proceedCurrent <=
        databaseNow + PROVIDER_ACTIVATION_MAX_AGE_MILLISECONDS &&
      proceedCurrent < Date.parse(accepted.activationReceipt.expiresAt),
    "INTEGRATED_LIVE_DRILL_PROVIDER_EXCHANGE_ACTIVATION_EXPIRED"
  );
  const root = secureRoot(rootPath);
  const fenceBody = Object.freeze({
    activationReceiptSha256: accepted.activationReceipt.receiptSha256,
    activationRequestSha256:
      accepted.activationReceipt.activationRequestSha256,
    schemaVersion: "tideproof.provider-exchange-consumption-fence.v1"
  });
  const fenceBytes = Buffer.from(`${canonicalJson(Object.freeze({
    ...fenceBody,
    receiptSha256: sha256(canonicalJson(fenceBody))
  }))}\n`, "utf8");
  const publication = publishOrReadExactOwnedFile({
    assertRoot: () => secureRoot(rootPath),
    bytes: fenceBytes,
    code: "INTEGRATED_LIVE_DRILL_PROVIDER_EXCHANGE_ALREADY_CONSUMED",
    filePath: path.join(rootPath, CONSUMPTION_FENCE),
    maximumBytes: MAX_FENCE_BYTES,
    mode: 0o600,
    rootPath,
    uid: root.uid
  });
  requireCondition(
    publication.created === true,
    "INTEGRATED_LIVE_DRILL_PROVIDER_EXCHANGE_ALREADY_CONSUMED"
  );
  const client = new CockroachManagedMcpRecoveryClient({
    apiKey,
    clusterId: payload.clusterId,
    fetchImpl
  });
  try {
    const rawResult = await client.selectQuery(payload);
    await client.close();
    const result = buildIntegratedLiveDrillProviderResult({
      activationReceipt: accepted.activationReceipt,
      result: Object.freeze({
        rawResult,
        semanticRequestEvidence: client.semanticRequestEvidence(),
        transportEvidence: client.transportEvidence()
      })
    });
    const bytes = Buffer.from(`${canonicalJson(result)}\n`, "utf8");
    requireCondition(
      bytes.length <= MAX_RESULT_BYTES,
      "INTEGRATED_LIVE_DRILL_PROVIDER_EXCHANGE_RESULT_REJECTED"
    );
    const published = publishOrReadExactOwnedFile({
      assertRoot: () => secureRoot(rootPath),
      bytes,
      code: "INTEGRATED_LIVE_DRILL_PROVIDER_EXCHANGE_RESULT_REJECTED",
      filePath: path.join(rootPath, RESULT_NAME),
      maximumBytes: MAX_RESULT_BYTES,
      mode: 0o600,
      rootPath,
      uid: root.uid
    });
    requireCondition(
      published.created === true,
      "INTEGRATED_LIVE_DRILL_PROVIDER_EXCHANGE_RESULT_REJECTED"
    );
    return result;
  } catch (cause) {
    await client.close().catch(() => {});
    reject("INTEGRATED_LIVE_DRILL_PROVIDER_EXCHANGE_UNKNOWN_DO_NOT_RETRY", cause);
  }
}

export const __test = Object.freeze({ CONSUMPTION_FENCE, RESULT_NAME });
