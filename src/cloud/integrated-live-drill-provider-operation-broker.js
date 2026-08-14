import { createHash, createHmac } from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { publishOrReadExactOwnedFile } from "./atomic-create-only-file.js";

import { canonicalJson } from "./canonical-json.js";
import {
  __test as clientContract
} from "./brokered-provider-operation-client.js";
import {
  INTEGRATED_LIVE_DRILL_PROVIDER_ACTIVATION_REQUEST_SCHEMA,
  INTEGRATED_LIVE_DRILL_PROVIDER_READY_SCHEMA,
  INTEGRATED_LIVE_DRILL_PROVIDER_RESULT_SCHEMA,
  validateIntegratedLiveDrillProviderActivationReceipt,
  validateIntegratedLiveDrillProviderExecutionGrant,
  validateIntegratedLiveDrillProviderReady,
  validateIntegratedLiveDrillProviderResult
} from "./integrated-live-drill-provider-activation.js";
import {
  PROVIDER_DISPATCH_CONTROL_STATES,
  PROVIDER_DISPATCH_HEX_64,
  validateProviderDispatchControlBinding
} from "./provider-dispatch-binding.js";
import {
  recoveryQueryBindingsFor,
  recoveryQueryTemplateDigest
} from "./recovery-continuity-identity.js";

const TRANSCRIPT_SCHEMA = "tideproof.provider-operation-broker-transcript.v1";
const TRANSCRIPT_NAME = "provider-operation-transcript.json";
const MAX_TRANSCRIPT_BYTES = 2 * 1024 * 1024;

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function exactRecord(value, keys) {
  return value && typeof value === "object" && !Array.isArray(value) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value)) &&
    Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key));
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

// Keep logical-request binding validation in the provider-key-isolated broker
// without importing any MCP transport/client implementation into its graph.
function providerLogicalRequest({ clusterId, query }) {
  const bindings = recoveryQueryBindingsFor(query);
  return Object.freeze({
    schemaVersion: "tideproof.highwater-drill-logical-managed-mcp-request.v1",
    boundInputSha256: sha256(canonicalJson({
      tenantId: bindings.tenantId,
      recoverySessionId: bindings.recoverySessionId,
      subjectBindingHash: bindings.subjectBindingHash,
      sourceDigest: bindings.sourceDigest
    })),
    databaseNameSha256: sha256("tideproof_recovery"),
    queryTemplateSha256: recoveryQueryTemplateDigest(),
    recoveryClusterId: clusterId,
    recoverySessionId: bindings.recoverySessionId,
    renderedQuerySha256: sha256(query),
    sourceDigest: bindings.sourceDigest,
    subjectBindingSha256: bindings.subjectBindingHash,
    tenantId: bindings.tenantId,
    toolNameSha256: sha256("select_query")
  });
}

function derive(executionCapability, grantId, purpose) {
  return createHmac("sha256", executionCapability)
    .update(canonicalJson({ grantId, purpose }))
    .digest("hex");
}

function receipt(body) {
  return Object.freeze({
    ...body,
    receiptSha256: sha256(canonicalJson(body))
  });
}

function secureRoot(rootPath) {
  const code = "INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_ROOT_REJECTED";
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

function readTranscript(root) {
  const filePath = path.join(root.rootPath, TRANSCRIPT_NAME);
  let descriptor;
  try {
    descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const before = fs.fstatSync(descriptor);
    requireCondition(
      before.isFile() && before.uid === root.uid && before.nlink === 1 &&
        (before.mode & 0o777) === 0o600 && before.size > 0 &&
        before.size <= MAX_TRANSCRIPT_BYTES,
      "INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_TRANSCRIPT_REJECTED"
    );
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor);
    requireCondition(
      before.dev === after.dev && before.ino === after.ino &&
        before.size === after.size,
      "INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_TRANSCRIPT_REJECTED"
    );
    const value = JSON.parse(bytes.toString("utf8"));
    requireCondition(
      bytes.equals(Buffer.from(`${canonicalJson(value)}\n`, "utf8")),
      "INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_TRANSCRIPT_REJECTED"
    );
    return value;
  } catch (cause) {
    if (cause?.code === "ENOENT") return null;
    if (cause?.message ===
      "INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_TRANSCRIPT_REJECTED") throw cause;
    reject("INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_TRANSCRIPT_REJECTED", cause);
  } finally {
    if (Number.isSafeInteger(descriptor)) fs.closeSync(descriptor);
  }
}

function persistTranscript(root, value) {
  const filePath = path.join(root.rootPath, TRANSCRIPT_NAME);
  const bytes = Buffer.from(`${canonicalJson(value)}\n`, "utf8");
  requireCondition(
    bytes.length > 0 && bytes.length <= MAX_TRANSCRIPT_BYTES,
    "INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_TRANSCRIPT_REJECTED"
  );
  publishOrReadExactOwnedFile({
    assertRoot: () => secureRoot(root.rootPath),
    bytes,
    code: "INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_TRANSCRIPT_REJECTED",
    filePath,
    maximumBytes: MAX_TRANSCRIPT_BYTES,
    mode: 0o600,
    rootPath: root.rootPath,
    uid: root.uid
  });
  const reread = readTranscript(root);
  requireCondition(
    canonicalJson(reread) === canonicalJson(value),
    "INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_TRANSCRIPT_REJECTED"
  );
  return reread;
}

function validateRequest(value, secrets) {
  const code = "INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_REQUEST_REJECTED";
  requireCondition(
    exactRecord(value, [
      "action",
      "binding",
      "executionGrant",
      "operationNonce",
      "payload",
      "schemaVersion"
    ]) && value.schemaVersion === clientContract.REQUEST_SCHEMA &&
      ["COMPLETE", "EXECUTE", "MARK_UNKNOWN"].includes(value.action),
    code
  );
  const binding = validateProviderDispatchControlBinding(value.binding);
  const grant = validateIntegratedLiveDrillProviderExecutionGrant(
    value.executionGrant
  );
  requireCondition(
    grant.authorizationId === binding.authorizationId &&
      grant.controlBindingSha256 === binding.controlBindingSha256 &&
      grant.grantId === secrets.grantId &&
      sha256(secrets.executionCapability) === grant.executionCapabilitySha256 &&
      sha256(value.operationNonce ?? "") === grant.operationNonceSha256 &&
      value.operationNonce === secrets.operationNonce,
    code
  );
  return Object.freeze({
    action: value.action,
    binding,
    executionGrant: grant,
    payload: value.payload
  });
}

function transcriptResult(value, accepted) {
  const { receiptSha256, ...body } = value ?? {};
  requireCondition(
    exactRecord(value, [
      "authorizationId",
      "controlBindingSha256",
      "grantId",
      "rawResult",
      "receiptSha256",
      "schemaVersion",
      "semanticRequestEvidence",
      "transportEvidence",
      "workerSpecSha256"
    ]) && body.schemaVersion === TRANSCRIPT_SCHEMA &&
      receiptSha256 === sha256(canonicalJson(body)) &&
      body.authorizationId === accepted.binding.authorizationId &&
      body.controlBindingSha256 === accepted.binding.controlBindingSha256 &&
      body.grantId === accepted.executionGrant.grantId &&
      body.workerSpecSha256 === accepted.executionGrant.workerSpecSha256,
    "INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_TRANSCRIPT_REJECTED"
  );
  return Object.freeze({
    rawResult: body.rawResult,
    semanticRequestEvidence: body.semanticRequestEvidence,
    transportEvidence: body.transportEvidence
  });
}

export async function runIntegratedLiveDrillProviderOperationBroker({
  activateExchange,
  executionCapability,
  finalizeControl,
  grantId,
  packageLockDigest,
  request,
  rootPath,
  redeemControl
}) {
  requireCondition(
    typeof activateExchange === "function" &&
      PROVIDER_DISPATCH_HEX_64.test(executionCapability ?? "") &&
      typeof redeemControl?.redeem === "function" &&
      typeof finalizeControl?.complete === "function" &&
      typeof finalizeControl?.markUnknown === "function",
    "INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_INPUT_REJECTED"
  );
  const secrets = Object.freeze({
    executionCapability,
    grantId,
    operationNonce: derive(
      executionCapability,
      grantId,
      "tideproof-provider-operation-nonce-v1"
    )
  });
  const accepted = validateRequest(request, secrets);
  const root = secureRoot(rootPath);
  const completionCapability = derive(
    executionCapability,
    grantId,
    "tideproof-provider-completion-capability-v1"
  );
  const completionGrant = Object.freeze({ completionCapability, grantId });
  if (accepted.action === "EXECUTE") {
    const payload = accepted.payload;
    requireCondition(
      exactRecord(payload, ["clusterId", "database", "query"]) &&
        payload.database === "tideproof_recovery" &&
        typeof payload.query === "string" && payload.query.length > 0 &&
        payload.query.length <= 1024 * 1024 &&
        sha256(canonicalJson(providerLogicalRequest({
          clusterId: payload.clusterId,
          query: payload.query
        }))) === accepted.binding.logicalMcpRequestSha256,
      "INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_REQUEST_REJECTED"
    );
    const existing = readTranscript(root);
    if (existing !== null) return transcriptResult(existing, accepted);
    const redeemed = await redeemControl.redeem(accepted.binding, {
      completionCapabilitySha256: sha256(completionCapability),
      executionCapability,
      grantId,
      workerSpecSha256: accepted.executionGrant.workerSpecSha256
    });
    if (
      redeemed.state !== PROVIDER_DISPATCH_CONTROL_STATES.CREDENTIAL_REDEEMED ||
      redeemed.transitionOutcome !== "CREDENTIAL_REDEEMED"
    ) {
      // A duplicate/replay may observe the original execution's redemption.
      // It must never terminalize beneath an already-issued activation receipt.
      // Only the database-time terminalizer may converge this state at expiry.
      reject("INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_ALREADY_REDEEMED");
    }
    requireCondition(
      PROVIDER_DISPATCH_HEX_64.test(packageLockDigest ?? ""),
      "INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_INPUT_REJECTED"
    );
    try {
      const providerResult = await activateExchange(Object.freeze({
        packageLockDigest,
        request: Object.freeze({
          action: request.action,
          binding: accepted.binding,
          executionGrant: accepted.executionGrant,
          operationNonce: request.operationNonce,
          payload: Object.freeze({ ...payload }),
          schemaVersion: request.schemaVersion
        }),
        schemaVersion: INTEGRATED_LIVE_DRILL_PROVIDER_ACTIVATION_REQUEST_SCHEMA
      }));
      const result = providerResult.result;
      const body = Object.freeze({
        schemaVersion: TRANSCRIPT_SCHEMA,
        authorizationId: accepted.binding.authorizationId,
        controlBindingSha256: accepted.binding.controlBindingSha256,
        grantId,
        rawResult: result.rawResult,
        semanticRequestEvidence: result.semanticRequestEvidence,
        transportEvidence: result.transportEvidence,
        workerSpecSha256: accepted.executionGrant.workerSpecSha256
      });
      return transcriptResult(
        persistTranscript(root, receipt(body)),
        accepted
      );
    } catch (cause) {
      // Activation has its own database one-shot and the provider must obtain
      // a broker PROCEED_ONCE handshake before any external call. Never
      // terminalize here: after PROCEED the effect may be in flight. The
      // separate database-time terminalizer owns expiry/unknown resolution.
      reject("INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_UNKNOWN_DO_NOT_ACT", cause);
    }
  }
  const existing = readTranscript(root);
  requireCondition(
    existing !== null,
    "INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_TRANSCRIPT_REQUIRED"
  );
  const result = transcriptResult(existing, accepted);
  if (accepted.action === "MARK_UNKNOWN") {
    reject(
      "INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_TERMINALIZER_REQUIRED"
    );
  }
  requireCondition(
    exactRecord(accepted.payload, ["mcpResultSha256", "sessionCloseSha256"]) &&
      PROVIDER_DISPATCH_HEX_64.test(accepted.payload.mcpResultSha256 ?? "") &&
      PROVIDER_DISPATCH_HEX_64.test(accepted.payload.sessionCloseSha256 ?? "") &&
      accepted.payload.mcpResultSha256 === sha256(canonicalJson(result.rawResult)) &&
      accepted.payload.sessionCloseSha256 ===
        sha256(canonicalJson(result.transportEvidence.close)),
    "INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_COMPLETION_REJECTED"
  );
  return finalizeControl.complete(
    accepted.binding,
    completionGrant,
    accepted.payload
  );
}

export function serveIntegratedLiveDrillProviderOperationBroker({
  listen,
  operation,
  providerReady = null,
  providerResult = null
}) {
  requireCondition(
    typeof operation === "function" &&
      (providerResult === null || typeof providerResult === "function") &&
      (providerReady === null || typeof providerReady === "function") &&
      listen && typeof listen === "object" &&
      (Number.isSafeInteger(listen.fd) || typeof listen.path === "string"),
    "INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_SERVER_REJECTED"
  );
  let queue = Promise.resolve();
  const server = net.createServer({ allowHalfOpen: true }, (socket) => {
    socket.setEncoding("utf8");
    socket.setTimeout(120_000, () => socket.destroy());
    socket.on("error", () => socket.destroy());
    let requestText = "";
    let bytes = 0;
    socket.on("data", (chunk) => {
      bytes += Buffer.byteLength(chunk);
      if (bytes > clientContract.MAX_MESSAGE_BYTES) {
        socket.destroy();
        return;
      }
      requestText += chunk;
    });
    socket.on("end", () => {
      const respond = async () => {
        let response;
        try {
          requireCondition(
            requestText.endsWith("\n") &&
              !requestText.slice(0, -1).includes("\n"),
            "INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_REQUEST_REJECTED"
          );
          const parsed = JSON.parse(requestText);
          const result = parsed?.schemaVersion ===
              INTEGRATED_LIVE_DRILL_PROVIDER_RESULT_SCHEMA
            ? await providerResult(parsed)
            : parsed?.schemaVersion === INTEGRATED_LIVE_DRILL_PROVIDER_READY_SCHEMA
              ? await providerReady(parsed)
              : await operation(parsed);
          response = Object.freeze({
            errorCode: null,
            result,
            schemaVersion: clientContract.RESPONSE_SCHEMA,
            status: "OK"
          });
        } catch (cause) {
          const errorCode = /^INTEGRATED_LIVE_DRILL_[A-Z0-9_]{1,160}$/u.test(
            String(cause?.message ?? "")
          ) ? cause.message : "INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_REJECTED";
          response = Object.freeze({
            errorCode,
            result: null,
            schemaVersion: clientContract.RESPONSE_SCHEMA,
            status: "ERROR"
          });
        }
        if (!socket.destroyed) socket.end(`${canonicalJson(response)}\n`);
      };
      let parsed;
      try { parsed = JSON.parse(requestText); } catch {}
      if (
        (providerResult !== null && parsed?.schemaVersion ===
          INTEGRATED_LIVE_DRILL_PROVIDER_RESULT_SCHEMA) ||
        (providerReady !== null && parsed?.schemaVersion ===
          INTEGRATED_LIVE_DRILL_PROVIDER_READY_SCHEMA)
      ) {
        void respond();
      } else {
        queue = queue.then(respond, respond);
      }
    });
  });
  server.listen(listen);
  return server;
}

export function createIntegratedLiveDrillProviderActivationCoordinator({
  activationRpc,
  activationTimeoutMilliseconds = 30_000,
  timeoutMilliseconds = 90_000
}) {
  requireCondition(
    typeof activationRpc === "function" &&
      Number.isSafeInteger(activationTimeoutMilliseconds) &&
      activationTimeoutMilliseconds >= 1 &&
      activationTimeoutMilliseconds <= 60_000 &&
      Number.isSafeInteger(timeoutMilliseconds) &&
      timeoutMilliseconds >= 1 && timeoutMilliseconds <= 300_000,
    "INTEGRATED_LIVE_DRILL_PROVIDER_ACTIVATION_COORDINATOR_REJECTED"
  );
  const pending = new Map();
  async function activateExchange(envelope) {
    const requestKey = sha256(canonicalJson(envelope));
    requireCondition(
      !pending.has(requestKey),
      "INTEGRATED_LIVE_DRILL_PROVIDER_ACTIVATION_REPLAY_REJECTED"
    );
    let resolveResult;
    let rejectResult;
    const resultPromise = new Promise((resolve, rejectPromise) => {
      resolveResult = resolve;
      rejectResult = rejectPromise;
    });
    pending.set(requestKey, {
      activationReceipt: null,
      envelope,
      phase: "ACTIVATING",
      reject: rejectResult,
      resolve: resolveResult,
      result: null,
      ready: null,
      timer: null
    });
    let response;
    try {
      response = await Promise.race([
        activationRpc(envelope),
        new Promise((_, rejectPromise) => setTimeout(
          () => rejectPromise(new Error(
            "INTEGRATED_LIVE_DRILL_PROVIDER_ACTIVATION_ACK_TIMEOUT"
          )),
          activationTimeoutMilliseconds
        ))
      ]);
    } catch (cause) {
      pending.get(requestKey)?.ready?.reject(new Error(
        "INTEGRATED_LIVE_DRILL_PROVIDER_ACTIVATION_ACK_REQUIRED"
      ));
      pending.delete(requestKey);
      throw cause;
    }
    let activationReceipt;
    try {
      activationReceipt = validateIntegratedLiveDrillProviderActivationReceipt(
        response?.activationReceipt
      );
      requireCondition(
        canonicalJson(response) === canonicalJson({ activationReceipt }),
        "INTEGRATED_LIVE_DRILL_PROVIDER_ACTIVATION_RESPONSE_REJECTED"
      );
      requireCondition(
        activationReceipt.activationRequestSha256 === requestKey,
        "INTEGRATED_LIVE_DRILL_PROVIDER_ACTIVATION_RESPONSE_REJECTED"
      );
    } catch (cause) {
      pending.get(requestKey)?.ready?.reject(new Error(
        "INTEGRATED_LIVE_DRILL_PROVIDER_ACTIVATION_ACK_REQUIRED"
      ));
      pending.delete(requestKey);
      throw cause;
    }
    const waiting = pending.get(requestKey);
    requireCondition(
      waiting !== undefined,
      "INTEGRATED_LIVE_DRILL_PROVIDER_ACTIVATION_RESPONSE_REJECTED"
    );
    waiting.activationReceipt = activationReceipt;
    waiting.phase = "ACTIVATION_ACKNOWLEDGED";
    if (waiting.ready !== null) {
      if (canonicalJson(waiting.ready.activationReceipt) !==
          canonicalJson(activationReceipt)) {
        waiting.ready.reject(new Error(
          "INTEGRATED_LIVE_DRILL_PROVIDER_READY_REJECTED"
        ));
        pending.delete(requestKey);
        waiting.reject(new Error(
          "INTEGRATED_LIVE_DRILL_PROVIDER_READY_REJECTED"
        ));
        return resultPromise;
      }
      waiting.ready.resolve(Object.freeze({
        activationReceiptSha256: activationReceipt.receiptSha256,
        disposition: "PROCEED_ONCE"
      }));
      waiting.ready = null;
      waiting.phase = "PROCEED_GRANTED";
    }
    if (waiting.result !== null) {
      const accepted = validateIntegratedLiveDrillProviderResult(
        waiting.result,
        { activationReceipt }
      );
      pending.delete(requestKey);
      waiting.resolve(accepted);
      return resultPromise;
    }
    waiting.timer = setTimeout(() => {
      pending.delete(requestKey);
      if (waiting.ready !== null) {
        waiting.ready.reject(new Error(
          "INTEGRATED_LIVE_DRILL_PROVIDER_RESULT_TIMEOUT_DO_NOT_RETRY"
        ));
        waiting.ready = null;
      }
      waiting.timer = null;
      waiting.phase = "TIMED_OUT_BLOCKED";
      waiting.reject(new Error(
        "INTEGRATED_LIVE_DRILL_PROVIDER_RESULT_TIMEOUT_DO_NOT_RETRY"
      ));
    }, timeoutMilliseconds);
    return resultPromise;
  }
  async function providerReady(value) {
    const accepted = validateIntegratedLiveDrillProviderReady(value);
    const waiting = pending.get(accepted.activationRequestSha256);
    requireCondition(
      waiting !== undefined &&
        ["ACTIVATING", "ACTIVATION_ACKNOWLEDGED"].includes(waiting.phase) &&
        waiting.ready === null,
      "INTEGRATED_LIVE_DRILL_PROVIDER_READY_UNSOLICITED"
    );
    if (waiting.activationReceipt !== null) {
      requireCondition(
        canonicalJson(accepted.activationReceipt) ===
          canonicalJson(waiting.activationReceipt),
        "INTEGRATED_LIVE_DRILL_PROVIDER_READY_REJECTED"
      );
      waiting.phase = "PROCEED_GRANTED";
      return Object.freeze({
        activationReceiptSha256: accepted.activationReceipt.receiptSha256,
        disposition: "PROCEED_ONCE"
      });
    }
    return new Promise((resolve, rejectPromise) => {
      waiting.ready = Object.freeze({
        activationReceipt: accepted.activationReceipt,
        reject: rejectPromise,
        resolve
      });
    });
  }
  async function providerResult(value) {
    const requestKey = value?.activationRequestSha256;
    const waiting = pending.get(requestKey);
    requireCondition(
      waiting !== undefined && waiting.phase === "PROCEED_GRANTED",
      "INTEGRATED_LIVE_DRILL_PROVIDER_RESULT_UNSOLICITED"
    );
    if (waiting.activationReceipt === null) {
      waiting.result = value;
      return Object.freeze({ accepted: true });
    }
    const accepted = validateIntegratedLiveDrillProviderResult(value, {
      activationReceipt: waiting.activationReceipt
    });
    clearTimeout(waiting.timer);
    pending.delete(requestKey);
    waiting.resolve(accepted);
    return Object.freeze({ accepted: true });
  }
  return Object.freeze({ activateExchange, providerReady, providerResult });
}

export const __test = Object.freeze({
  TRANSCRIPT_NAME,
  TRANSCRIPT_SCHEMA,
  derive,
  validateRequest
});
