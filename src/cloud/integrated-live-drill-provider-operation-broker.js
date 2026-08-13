import { createHash, createHmac } from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";

import { canonicalJson } from "./canonical-json.js";
import {
  __test as clientContract
} from "./brokered-provider-operation-client.js";
import {
  validateIntegratedLiveDrillExecutionGrant
} from "./integrated-live-drill-dispatch-broker.js";
import {
  CockroachManagedMcpRecoveryClient,
  managedMcpLogicalRequest
} from "./managed-mcp-client.js";
import {
  PROVIDER_DISPATCH_CONTROL_STATES,
  PROVIDER_DISPATCH_HEX_64,
  validateProviderDispatchControlBinding
} from "./provider-dispatch-binding.js";

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
  let descriptor;
  try {
    descriptor = fs.openSync(
      filePath,
      fs.constants.O_WRONLY | fs.constants.O_CREAT |
        fs.constants.O_EXCL | fs.constants.O_NOFOLLOW,
      0o600
    );
    fs.writeFileSync(descriptor, bytes);
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = undefined;
    const directory = fs.openSync(
      root.rootPath,
      fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW
    );
    try { fs.fsyncSync(directory); } finally { fs.closeSync(directory); }
  } catch (cause) {
    if (Number.isSafeInteger(descriptor)) fs.closeSync(descriptor);
    if (cause?.code !== "EEXIST") {
      reject("INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_TRANSCRIPT_REJECTED", cause);
    }
  }
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
  const grant = validateIntegratedLiveDrillExecutionGrant(value.executionGrant);
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
  apiKey,
  executionCapability,
  fetchImpl,
  finalizeControl,
  grantId,
  request,
  rootPath,
  redeemControl
}) {
  requireCondition(
    typeof apiKey === "string" && apiKey.length >= 24 &&
      PROVIDER_DISPATCH_HEX_64.test(executionCapability ?? "") &&
      typeof fetchImpl === "function" &&
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
        sha256(canonicalJson(managedMcpLogicalRequest({
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
      await finalizeControl.markUnknown(accepted.binding, completionGrant)
        .catch(() => {});
      reject("INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_ALREADY_REDEEMED");
    }
    const client = new CockroachManagedMcpRecoveryClient({
      apiKey,
      clusterId: payload.clusterId,
      fetchImpl
    });
    try {
      const rawResult = await client.selectQuery(payload);
      await client.close();
      const body = Object.freeze({
        schemaVersion: TRANSCRIPT_SCHEMA,
        authorizationId: accepted.binding.authorizationId,
        controlBindingSha256: accepted.binding.controlBindingSha256,
        grantId,
        rawResult,
        semanticRequestEvidence: client.semanticRequestEvidence(),
        transportEvidence: client.transportEvidence(),
        workerSpecSha256: accepted.executionGrant.workerSpecSha256
      });
      return transcriptResult(
        persistTranscript(root, receipt(body)),
        accepted
      );
    } catch (cause) {
      await client.close().catch(() => {});
      await finalizeControl.markUnknown(accepted.binding, completionGrant)
        .catch(() => {});
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
    return finalizeControl.markUnknown(accepted.binding, completionGrant);
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
  operation
}) {
  requireCondition(
    typeof operation === "function" &&
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
          const result = await operation(JSON.parse(requestText));
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
      queue = queue.then(respond, respond);
    });
  });
  server.listen(listen);
  return server;
}

export const __test = Object.freeze({
  TRANSCRIPT_NAME,
  TRANSCRIPT_SCHEMA,
  derive
});
