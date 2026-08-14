import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { publishOrReadExactOwnedFile } from
  "../src/cloud/atomic-create-only-file.js";
import { canonicalJson } from "../src/cloud/canonical-json.js";
import {
  providerExchangeInputBytes,
  runIntegratedLiveDrillProviderActivation,
  validateIntegratedLiveDrillProviderActivationEnvelope
} from "../src/cloud/integrated-live-drill-provider-activation.js";
import { assertIntegratedLiveDrillRuntime } from
  "../src/cloud/integrated-live-drill-runtime.js";
import { ProviderDispatchActivateControl } from
  "../src/cloud/provider-dispatch-activate-control.js";
import { validateProviderDispatchReconciliationInput } from
  "../src/cloud/provider-dispatch-reconciliation-input.js";
import { readSystemdCredential, readSystemdCredentialText } from
  "../src/cloud/systemd-credential.js";

const MAX = 2 * 1024 * 1024;

function absoluteEnvironment(name) {
  const value = process.env[name];
  if (typeof value !== "string" || !path.isAbsolute(value) ||
    path.resolve(value) !== value || value.length > 4096) {
    throw new Error("INTEGRATED_LIVE_DRILL_PROVIDER_ACTIVATION_ENVIRONMENT_REJECTED");
  }
  return value;
}

function secureRoot(rootPath) {
  const stat = fs.lstatSync(rootPath);
  if (fs.realpathSync(rootPath) !== rootPath || !stat.isDirectory() ||
    stat.isSymbolicLink() || stat.uid !== process.getuid() ||
    (stat.mode & 0o777) !== 0o700) {
    throw new Error("INTEGRATED_LIVE_DRILL_PROVIDER_ACTIVATION_ROOT_REJECTED");
  }
  return stat.uid;
}

function publish(rootPath, name, bytes) {
  const uid = secureRoot(rootPath);
  return publishOrReadExactOwnedFile({
    assertRoot: () => secureRoot(rootPath),
    bytes,
    code: "INTEGRATED_LIVE_DRILL_PROVIDER_ACTIVATION_PUBLICATION_REJECTED",
    filePath: path.join(rootPath, name),
    maximumBytes: MAX,
    mode: 0o600,
    rootPath,
    uid
  });
}

function readOneFromSocket(activate) {
  return new Promise((resolve, reject) => {
    const server = net.createServer({ allowHalfOpen: true }, (socket) => {
      let text = "";
      let bytes = 0;
      socket.setEncoding("utf8");
      socket.setTimeout(30_000, () => socket.destroy());
      socket.on("data", (chunk) => {
        bytes += Buffer.byteLength(chunk);
        if (bytes > MAX) socket.destroy();
        else text += chunk;
      });
      socket.on("end", async () => {
        try {
          if (!text.endsWith("\n") || text.slice(0, -1).includes("\n")) {
            throw new Error("INTEGRATED_LIVE_DRILL_PROVIDER_ACTIVATION_REQUEST_REJECTED");
          }
          const result = await activate(JSON.parse(text));
          // The publication that systemd OnSuccess consumes is durable before
          // the broker receives an acknowledgement.  ACK loss therefore
          // leaves the broker in ACTIVATING, and READY cannot obtain PROCEED.
          socket.end(`${canonicalJson({
            activationReceipt: result.activationReceipt
          })}\n`);
          server.close(() => resolve(result));
        } catch (cause) {
          socket.destroy();
          server.close(() => reject(cause));
        }
      });
    });
    server.on("error", reject);
    server.listen({ fd: 3 });
  });
}

export async function main({ clientFactory = null } = {}) {
  if (
    process.env.LISTEN_PID !== String(process.pid) ||
    process.env.LISTEN_FDS !== "1" ||
    process.env.LISTEN_FDNAMES !== "activation"
  ) {
    throw new Error("INTEGRATED_LIVE_DRILL_PROVIDER_ACTIVATION_SOCKET_REJECTED");
  }
  const credentialsDirectory = absoluteEnvironment("CREDENTIALS_DIRECTORY");
  const rootPath = absoluteEnvironment(
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_ACTIVATION_ROOT"
  );
  const reconciliation = validateProviderDispatchReconciliationInput(JSON.parse(
    readSystemdCredential({
      credentialsDirectory,
      maximumBytes: 64 * 1024,
      name: "provider-reconciliation-input"
    }).toString("utf8")
  ));
  const runtime = assertIntegratedLiveDrillRuntime({
    environment: process.env,
    expectedComponent: "provider-activation",
    spec: Object.freeze({
      packageLockDigest: reconciliation.packageLockDigest,
      runtimeBundleManifestSha256:
        process.env.TIDEPROOF_INTEGRATED_LIVE_DRILL_RUNTIME_MANIFEST_SHA256,
      sourceCommit: reconciliation.binding.sourceCommit,
      treeDigest: reconciliation.binding.treeDigest
    })
  });
  void runtime;
  const activateControl = new ProviderDispatchActivateControl({
    clientFactory,
    connectionString: readSystemdCredentialText({
      credentialsDirectory,
      name: "provider-activate-database-url"
    })
  });
  const result = await readOneFromSocket(async (envelopeInput) => {
    const envelope = validateIntegratedLiveDrillProviderActivationEnvelope(
      envelopeInput
    );
    if (
      envelope.packageLockDigest !== reconciliation.packageLockDigest ||
      envelope.request.binding.controlBindingSha256 !==
        reconciliation.binding.controlBindingSha256 ||
      envelope.request.executionGrant.grantId !==
        reconciliation.admission.grantId ||
      envelope.request.executionGrant.workerSpecSha256 !==
        reconciliation.admission.workerSpecSha256
    ) throw new Error("INTEGRATED_LIVE_DRILL_PROVIDER_ACTIVATION_BINDING_REJECTED");
    const activated = await runIntegratedLiveDrillProviderActivation({
      activateControl,
      envelope
    });
    const exchange = providerExchangeInputBytes(activated.exchangeInput);
    publish(rootPath, "provider-exchange-input.json", exchange);
    publish(
      rootPath,
      "provider-activation-receipt.json",
      Buffer.from(`${canonicalJson(activated.activationReceipt)}\n`, "utf8")
    );
    return activated;
  });
  void result;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`${String(error?.message ?? "INTEGRATED_LIVE_DRILL_PROVIDER_ACTIVATION_UNKNOWN")}\n`);
    process.exitCode = 1;
  });
}
