import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { __test as providerLoaderContract } from
  "../release-provider/src/release-provider-runtime-loader.js";
import {
  dispatchReservedProviderOneShotIntent,
  finalizeProviderOneShotIntent,
  reserveProviderOneShotIntent
} from "./release-provider-one-shot-broker.js";
import {
  assertExecuteDiagnosticCredentialAbsence,
  validateExecuteWorkflowContext
} from "./run-release-execute-common.js";

function requireCondition(condition, code) {
  if (!condition) throw new Error(code);
}

export function validateExecuteDiagnostic(environment = process.env,
  platform = process.platform) {
  const context = validateExecuteWorkflowContext(
    environment,
    "diagnostic",
    platform
  );
  assertExecuteDiagnosticCredentialAbsence(environment);
  requireCondition([
    reserveProviderOneShotIntent,
    dispatchReservedProviderOneShotIntent,
    finalizeProviderOneShotIntent
  ].every((value) => typeof value === "function"),
  "RELEASE_EXECUTE_DIAGNOSTIC_BROKER_INTERFACE_REJECTED");
  const capabilities = providerLoaderContract.CAPABILITIES;
  requireCondition(capabilities.EXECUTE_PERMIT_READER?.includes(
    "createExecutePermitReader") &&
    capabilities.EXECUTE_DISPATCHER?.includes("createExecuteDispatcher") &&
    capabilities.EXECUTE_READBACK?.includes("createExecuteReadback"),
  "RELEASE_EXECUTE_DIAGNOSTIC_PROVIDER_INTERFACE_REJECTED");
  for (const relative of [
    "release-control/src/release-control-runtime-loader.js",
    "release-provider/src/release-provider-runtime-loader.js",
    "scripts/release-provider-one-shot-broker.js",
    "scripts/run-release-execute-common.js",
    "scripts/run-release-execute-phase.js",
    "scripts/run-release-execute-preflight.js",
    "test/release-execute-runner.test.js"
  ]) {
    const candidate = path.join(context.controlRoot, relative);
    const stat = fs.lstatSync(candidate);
    requireCondition(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1,
      "RELEASE_EXECUTE_DIAGNOSTIC_FILE_REJECTED");
  }
  return Object.freeze({
    providerExecutionEnabled: false,
    status: "LOCAL_EXECUTE_CONTRACT_VERIFIED_PROVIDER_DISABLED"
  });
}

export async function main(args = process.argv.slice(2),
  environment = process.env) {
  requireCondition(args.length === 0,
    "RELEASE_EXECUTE_DIAGNOSTIC_ARGUMENT_REJECTED");
  const result = validateExecuteDiagnostic(environment);
  process.stdout.write(`PROOFTOACT_EXECUTE_DIAGNOSTIC_PASS:${result.status}\n`);
}

if (process.argv[1] && import.meta.url ===
  pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch((cause) => {
    const message = String(cause?.message ?? "");
    const code = /^RELEASE_EXECUTE_[A-Z0-9_]{1,100}$/u.test(message)
      ? message : "RELEASE_EXECUTE_DIAGNOSTIC_UNKNOWN";
    process.stderr.write(`HOLD:${code}\n`);
    process.exitCode = 1;
  });
}
