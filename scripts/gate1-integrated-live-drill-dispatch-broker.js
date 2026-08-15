import path from "node:path";
import { pathToFileURL } from "node:url";

import {
  dispatchBrokerRequestFromOrchestrationRequest,
  runIntegratedLiveDrillDispatchBroker
} from "../src/cloud/integrated-live-drill-dispatch-broker.js";
import { ProviderDispatchBeginControl } from
  "../src/cloud/provider-dispatch-begin-control.js";
import { ProviderDispatchClaimControl } from
  "../src/cloud/provider-dispatch-claim-control.js";
import { assertIntegratedLiveDrillRuntime } from
  "../src/cloud/integrated-live-drill-runtime.js";
import {
  readSystemdCredential,
  readSystemdCredentialText
} from "../src/cloud/systemd-credential.js";

const REQUEST_CREDENTIAL = "dispatch-request";
const CLAIM_DATABASE_CREDENTIAL = "provider-claim-database-url";
const BEGIN_DATABASE_CREDENTIAL = "provider-begin-database-url";

function required(name, maximum = 8192) {
  const value = process.env[name];
  if (
    typeof value !== "string" || value.length === 0 ||
    value.length > maximum || /[\0\r\n]/u.test(value)
  ) {
    throw new Error("INTEGRATED_LIVE_DRILL_DISPATCH_BROKER_ENVIRONMENT_REJECTED");
  }
  return value;
}

function exactAbsolute(name) {
  const value = required(name);
  if (!path.isAbsolute(value) || path.resolve(value) !== value) {
    throw new Error("INTEGRATED_LIVE_DRILL_DISPATCH_BROKER_ENVIRONMENT_REJECTED");
  }
  return value;
}

export async function main({ clientFactory = null } = {}) {
  if (
    Object.hasOwn(process.env, "MCP_API_KEY") ||
    Object.hasOwn(process.env, "PRIMARY_AUDIT_DATABASE_URL")
  ) {
    throw new Error("INTEGRATED_LIVE_DRILL_DISPATCH_BROKER_CAPABILITY_REJECTED");
  }
  const credentialsDirectory = exactAbsolute("CREDENTIALS_DIRECTORY");
  let request;
  try {
    request = dispatchBrokerRequestFromOrchestrationRequest(JSON.parse(
      readSystemdCredential({
        credentialsDirectory,
        maximumBytes: 8 * 1024 * 1024,
        name: REQUEST_CREDENTIAL
      }).toString("utf8")
    ));
  } catch (cause) {
    throw new Error("INTEGRATED_LIVE_DRILL_DISPATCH_BROKER_REQUEST_REJECTED", {
      cause
    });
  }
  const manifestSha256 = required(
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_RUNTIME_MANIFEST_SHA256",
    64
  );
  assertIntegratedLiveDrillRuntime({
    environment: process.env,
    expectedComponent: "dispatch-broker",
    spec: Object.freeze({
      packageLockDigest: request.packageLockDigest,
      runtimeBundleManifestSha256: manifestSha256,
      sourceCommit: request.binding.sourceCommit,
      treeDigest: request.binding.treeDigest
    })
  });
  const claimControl = new ProviderDispatchClaimControl({
    clientFactory,
    connectionString: readSystemdCredentialText({
      credentialsDirectory,
      name: CLAIM_DATABASE_CREDENTIAL
    })
  });
  const beginControl = new ProviderDispatchBeginControl({
    clientFactory,
    connectionString: readSystemdCredentialText({
      credentialsDirectory,
      name: BEGIN_DATABASE_CREDENTIAL
    })
  });
  const executionGrantRootPath = exactAbsolute(
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_EXECUTION_GRANT_ROOT"
  );
  const reconciliationInputRootPath = exactAbsolute(
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_RECONCILIATION_INPUT_ROOT"
  );
  const result = await runIntegratedLiveDrillDispatchBroker({
    beginControl,
    brokerRootPath: exactAbsolute(
      "TIDEPROOF_INTEGRATED_LIVE_DRILL_DISPATCH_BROKER_PRIVATE_ROOT"
    ),
    claimControl,
    executionGrantPath: path.join(
      executionGrantRootPath,
      "execution-grant.json"
    ),
    executionGrantRootPath,
    providerReconciliationInputPath: path.join(
      reconciliationInputRootPath,
      "provider-reconciliation-input.json"
    ),
    reconciliationInputRootPath,
    request
  });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}

const startedDirectly = process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href;
if (startedDirectly) {
  main().catch((error) => {
    const code = /^INTEGRATED_LIVE_DRILL_[A-Z0-9_]{1,140}$/u.test(
      String(error?.message ?? "")
    ) ? error.message : "INTEGRATED_LIVE_DRILL_DISPATCH_BROKER_UNKNOWN";
    process.stderr.write(`${code}\n`);
    process.exitCode = 1;
  });
}
