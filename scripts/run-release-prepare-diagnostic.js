import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { __test as providerLoaderContract } from
  "../release-provider/src/release-provider-runtime-loader.js";
import {
  assertDiagnosticCredentialAbsence,
  validatePrepareWorkflowContext
} from "./run-release-prepare-common.js";
import {
  dispatchReservedProviderOneShotIntent,
  finalizeProviderOneShotIntent,
  reserveProviderOneShotIntent
} from "./release-provider-one-shot-broker.js";

function requireCondition(condition, code) {
  if (!condition) throw new Error(code);
}

export function validatePrepareDiagnostic(environment = process.env,
  platform = process.platform) {
  const context = validatePrepareWorkflowContext(
    environment,
    "diagnostic",
    platform
  );
  assertDiagnosticCredentialAbsence(environment);
  requireCondition([
    reserveProviderOneShotIntent,
    dispatchReservedProviderOneShotIntent,
    finalizeProviderOneShotIntent
  ].every((value) => typeof value === "function"),
  "RELEASE_PREPARE_DIAGNOSTIC_BROKER_INTERFACE_REJECTED");
  const permitExports = providerLoaderContract.CAPABILITIES.PERMIT_READER;
  requireCondition(Array.isArray(permitExports) &&
    permitExports.includes("createAwsPreparePermitTransport") &&
    permitExports.includes("createPreparePermitReader"),
  "RELEASE_PREPARE_DIAGNOSTIC_PROVIDER_INTERFACE_REJECTED");
  for (const relative of [
    "release-control/src/release-control-runtime-loader.js",
    "release-provider/src/release-provider-runtime-loader.js",
    "scripts/release-provider-one-shot-broker.js",
    "scripts/run-release-prepare-common.js",
    "scripts/run-release-prepare-phase.js",
    "scripts/run-release-prepare-preflight.js",
    "test/release-prepare-runner.test.js"
  ]) {
    const candidate = path.join(context.controlRoot, relative);
    const stat = fs.lstatSync(candidate);
    requireCondition(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1,
      "RELEASE_PREPARE_DIAGNOSTIC_FILE_REJECTED");
  }
  return Object.freeze({
    providerExecutionEnabled: false,
    status: "LOCAL_CONTRACT_VERIFIED_PROVIDER_DISABLED"
  });
}

export async function main(args = process.argv.slice(2),
  environment = process.env) {
  requireCondition(args.length === 0,
    "RELEASE_PREPARE_DIAGNOSTIC_ARGUMENT_REJECTED");
  const result = validatePrepareDiagnostic(environment);
  process.stdout.write(`PROOFTOACT_PREPARE_DIAGNOSTIC_PASS:${result.status}\n`);
}

if (process.argv[1] && import.meta.url ===
  pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch((cause) => {
    const message = String(cause?.message ?? "");
    const code = /^RELEASE_PREPARE_[A-Z0-9_]{1,100}$/u.test(message)
      ? message
      : "RELEASE_PREPARE_DIAGNOSTIC_UNKNOWN";
    process.stderr.write(`HOLD:${code}\n`);
    process.exitCode = 1;
  });
}
