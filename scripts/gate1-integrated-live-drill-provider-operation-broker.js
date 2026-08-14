import net from "node:net";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { canonicalJson } from "../src/cloud/canonical-json.js";
import {
  createIntegratedLiveDrillProviderActivationCoordinator,
  runIntegratedLiveDrillProviderOperationBroker,
  serveIntegratedLiveDrillProviderOperationBroker
} from "../src/cloud/integrated-live-drill-provider-operation-broker.js";
import { assertIntegratedLiveDrillRuntime } from
  "../src/cloud/integrated-live-drill-runtime.js";
import {
  integratedLiveDrillProviderAuthorityTimes,
  validateProviderExecutionAttempt
} from "../src/cloud/integrated-live-drill-provider-recovery.js";
import { validateIntegratedLiveDrillProviderWorkerInput } from
  "../src/cloud/integrated-live-drill-provider-worker.js";
import { validateIntegratedLiveDrillProviderDispatchAuthorizationPure } from
  "../src/cloud/integrated-live-drill-provider-evidence.js";
import { buildProviderDispatchControlBinding } from
  "../src/cloud/provider-dispatch-binding.js";
import { ProviderDispatchFinalizeControl } from
  "../src/cloud/provider-dispatch-finalize-control.js";
import { validateProviderDispatchReconciliationInput } from
  "../src/cloud/provider-dispatch-reconciliation-input.js";
import { ProviderDispatchRedeemControl } from
  "../src/cloud/provider-dispatch-redeem-control.js";
import {
  readSystemdCredential,
  readSystemdCredentialText
} from "../src/cloud/systemd-credential.js";

const MAX = 2 * 1024 * 1024;

function absoluteEnvironment(name) {
  const value = process.env[name];
  if (typeof value !== "string" || !path.isAbsolute(value) ||
    path.resolve(value) !== value || value.length > 4096) {
    throw new Error("INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_ENVIRONMENT_REJECTED");
  }
  return value;
}

function activationRpc(socketPath, envelope) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ path: socketPath });
    let text = "";
    let bytes = 0;
    const fail = (cause) => { socket.destroy(); reject(cause); };
    socket.setTimeout(30_000, () => fail(new Error(
      "INTEGRATED_LIVE_DRILL_PROVIDER_ACTIVATION_ACK_TIMEOUT"
    )));
    socket.on("error", reject);
    socket.setEncoding("utf8");
    socket.on("connect", () => socket.end(`${canonicalJson(envelope)}\n`));
    socket.on("data", (chunk) => {
      bytes += Buffer.byteLength(chunk);
      if (bytes > MAX) fail(new Error(
        "INTEGRATED_LIVE_DRILL_PROVIDER_ACTIVATION_RESPONSE_REJECTED"
      ));
      else text += chunk;
    });
    socket.on("end", () => {
      try {
        if (!text.endsWith("\n") || text.slice(0, -1).includes("\n")) {
          throw new Error("INTEGRATED_LIVE_DRILL_PROVIDER_ACTIVATION_RESPONSE_REJECTED");
        }
        resolve(JSON.parse(text));
      } catch (cause) { reject(cause); }
    });
  });
}

export async function main({ clientFactory = null } = {}) {
  const credentialsDirectory = absoluteEnvironment("CREDENTIALS_DIRECTORY");
  const workerInput = validateIntegratedLiveDrillProviderWorkerInput(JSON.parse(
    readSystemdCredential({
      credentialsDirectory,
      maximumBytes: 8 * 1024 * 1024,
      name: "provider-worker-input"
    }).toString("utf8")
  ));
  const reconciliation = validateProviderDispatchReconciliationInput(JSON.parse(
    readSystemdCredential({
      credentialsDirectory,
      maximumBytes: 64 * 1024,
      name: "provider-reconciliation-input"
    }).toString("utf8")
  ));
  const intent = workerInput.context.preCallIntent;
  const dispatch = validateIntegratedLiveDrillProviderDispatchAuthorizationPure(
    workerInput.context.providerDispatchAuthorization,
    {
      childAuthorizationIssuedAt:
        workerInput.context.preCallInputs.consumedChildAuthorization.attestation
          .payload.issuedAt,
      humanAuthorizationTrustRoot:
        workerInput.context.trustedRunContext.humanAuthorizationTrustRoot,
      intent,
      requireCurrent: false
    }
  );
  const authorityTimes = integratedLiveDrillProviderAuthorityTimes(
    workerInput.context,
    intent,
    dispatch,
    Date.parse(
      workerInput.context.preCallInputs.consumedChildAuthorization.attestation
        .payload.issuedAt
    )
  );
  const binding = buildProviderDispatchControlBinding({
    context: workerInput.context,
    dispatchAuthorizationSha256: dispatch.attestationSha256,
    earliestControllingExpiry: authorityTimes.earliestControllingExpiry,
    latestControllingIssuedAt: authorityTimes.latestControllingIssuedAt
  });
  if (
    binding.controlBindingSha256 !== reconciliation.binding.controlBindingSha256 ||
    binding.controlBindingSha256 !==
      workerInput.executionGrant.controlBindingSha256
  ) throw new Error("INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_BINDING_REJECTED");
  validateProviderExecutionAttempt(JSON.parse(readSystemdCredential({
    credentialsDirectory,
    maximumBytes: 64 * 1024,
    name: "provider-execution-attempt"
  }).toString("utf8")), {
    executionGrant: workerInput.executionGrant,
    intent,
    providerControlBinding: binding
  });
  const secret = JSON.parse(readSystemdCredential({
    credentialsDirectory,
    maximumBytes: 256,
    name: "execution-capability"
  }).toString("utf8"));
  if (
    secret?.grantId !== workerInput.executionGrant.grantId ||
    typeof secret.executionCapability !== "string"
  ) throw new Error("INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_BINDING_REJECTED");
  assertIntegratedLiveDrillRuntime({
    environment: process.env,
    expectedComponent: "provider-operation",
    spec: Object.freeze({
      packageLockDigest: reconciliation.packageLockDigest,
      runtimeBundleManifestSha256:
        process.env.TIDEPROOF_INTEGRATED_LIVE_DRILL_RUNTIME_MANIFEST_SHA256,
      sourceCommit: binding.sourceCommit,
      treeDigest: binding.treeDigest
    })
  });
  const coordinator = createIntegratedLiveDrillProviderActivationCoordinator({
    activationRpc: (envelope) => activationRpc(
      absoluteEnvironment(
        "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_ACTIVATION_SOCKET"
      ),
      envelope
    )
  });
  const finalizeControl = new ProviderDispatchFinalizeControl({
    clientFactory,
    connectionString: readSystemdCredentialText({
      credentialsDirectory,
      name: "provider-finalize-database-url"
    })
  });
  const redeemControl = new ProviderDispatchRedeemControl({
    clientFactory,
    connectionString: readSystemdCredentialText({
      credentialsDirectory,
      name: "provider-redeem-database-url"
    })
  });
  const operation = (request) => runIntegratedLiveDrillProviderOperationBroker({
    activateExchange: coordinator.activateExchange,
    apiKey: undefined,
    executionCapability: secret.executionCapability,
    finalizeControl,
    grantId: secret.grantId,
    packageLockDigest: reconciliation.packageLockDigest,
    request,
    rootPath: absoluteEnvironment(
      "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_ROOT"
    ),
    redeemControl
  });
  const descriptorNames = String(process.env.LISTEN_FDNAMES ?? "")
    .split(":");
  if (
    Number(process.env.LISTEN_PID) !== process.pid ||
    Number(process.env.LISTEN_FDS) !== 2 ||
    descriptorNames.length !== 2 ||
    new Set(descriptorNames).size !== 2 ||
    !descriptorNames.includes("worker") ||
    !descriptorNames.includes("provider-callback")
  ) throw new Error("INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_SOCKET_REJECTED");
  const descriptor = (name) => 3 + descriptorNames.indexOf(name);
  const workerServer = serveIntegratedLiveDrillProviderOperationBroker({
    listen: { fd: descriptor("worker") },
    operation
  });
  const callbackServer = serveIntegratedLiveDrillProviderOperationBroker({
    listen: { fd: descriptor("provider-callback") },
    operation: async () => {
      throw new Error("INTEGRATED_LIVE_DRILL_PROVIDER_CALLBACK_PROTOCOL_REJECTED");
    },
    providerReady: coordinator.providerReady,
    providerResult: coordinator.providerResult
  });
  return Object.freeze({ callbackServer, workerServer });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`${String(error?.message ?? "INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_UNKNOWN")}\n`);
    process.exitCode = 1;
  });
}
