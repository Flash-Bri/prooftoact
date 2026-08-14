import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { canonicalJson } from "../src/cloud/canonical-json.js";
import { runIntegratedLiveDrillProviderExchange } from
  "../src/cloud/integrated-live-drill-provider-exchange.js";
import { assertIntegratedLiveDrillRuntime } from
  "../src/cloud/integrated-live-drill-runtime.js";
import {
  readSystemdCredential,
  readSystemdCredentialText
} from "../src/cloud/systemd-credential.js";

const MAX = 2 * 1024 * 1024;

function absoluteEnvironment(name) {
  const value = process.env[name];
  if (typeof value !== "string" || !path.isAbsolute(value) ||
    path.resolve(value) !== value || value.length > 4096) {
    throw new Error("INTEGRATED_LIVE_DRILL_PROVIDER_EXCHANGE_ENVIRONMENT_REJECTED");
  }
  return value;
}

function rpc(socketPath, request) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ path: socketPath });
    let text = "";
    let bytes = 0;
    socket.setTimeout(30_000, () => socket.destroy(
      new Error("INTEGRATED_LIVE_DRILL_PROVIDER_EXCHANGE_CALLBACK_TIMEOUT")
    ));
    socket.on("error", reject);
    socket.setEncoding("utf8");
    socket.on("connect", () => socket.end(`${canonicalJson(request)}\n`));
    socket.on("data", (chunk) => {
      bytes += Buffer.byteLength(chunk);
      if (bytes > MAX) socket.destroy();
      else text += chunk;
    });
    socket.on("end", () => {
      try {
        if (!text.endsWith("\n") || text.slice(0, -1).includes("\n")) {
          throw new Error("INTEGRATED_LIVE_DRILL_PROVIDER_EXCHANGE_CALLBACK_REJECTED");
        }
        const response = JSON.parse(text);
        if (response.status !== "OK") throw new Error(response.errorCode);
        resolve(response.result);
      } catch (cause) { reject(cause); }
    });
  });
}

export async function main({ fetchImpl = globalThis.fetch } = {}) {
  const credentialsDirectory = absoluteEnvironment("CREDENTIALS_DIRECTORY");
  const input = JSON.parse(readSystemdCredential({
    credentialsDirectory,
    maximumBytes: MAX,
    name: "provider-exchange-input"
  }).toString("utf8"));
  assertIntegratedLiveDrillRuntime({
    environment: process.env,
    expectedComponent: "provider-exchange",
    spec: Object.freeze({
      packageLockDigest: input.providerRequest.packageLockDigest,
      runtimeBundleManifestSha256:
        process.env.TIDEPROOF_INTEGRATED_LIVE_DRILL_RUNTIME_MANIFEST_SHA256,
      sourceCommit: input.providerRequest.binding.sourceCommit,
      treeDigest: input.providerRequest.binding.treeDigest
    })
  });
  const callbackPath = absoluteEnvironment(
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_CALLBACK_SOCKET"
  );
  const result = await runIntegratedLiveDrillProviderExchange({
    apiKey: readSystemdCredentialText({
      credentialsDirectory,
      maximumBytes: 8192,
      name: "mcp-api-key"
    }),
    exchangeInput: input,
    fetchImpl,
    proceed: (ready) => rpc(callbackPath, ready),
    rootPath: absoluteEnvironment(
      "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_EXCHANGE_ROOT"
    )
  });
  await rpc(callbackPath, result);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`${String(error?.message ?? "INTEGRATED_LIVE_DRILL_PROVIDER_EXCHANGE_UNKNOWN")}\n`);
    process.exitCode = 1;
  });
}
