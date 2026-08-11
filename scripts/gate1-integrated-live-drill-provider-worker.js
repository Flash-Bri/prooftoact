import { pathToFileURL } from "node:url";

import {
  INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_PATH_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_PRINCIPAL_ENVIRONMENT,
  readIntegratedLiveDrillProviderWorkerInput,
  runIntegratedLiveDrillProviderWorker
} from "../src/cloud/integrated-live-drill-provider-worker.js";

function requiredEnvironment(name) {
  const value = process.env[name];
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 8192 ||
    /[\0\r\n]/u.test(value)
  ) {
    throw new Error("INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_REJECTED");
  }
  return value;
}

export async function main() {
  const input = readIntegratedLiveDrillProviderWorkerInput({
    forbiddenRootPath: requiredEnvironment(
      "TIDEPROOF_INTEGRATED_LIVE_DRILL_FORBIDDEN_ROOT"
    ),
    inputPath: requiredEnvironment(
      INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_PATH_ENVIRONMENT
    ),
    rootPath: requiredEnvironment(
      "TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_ROOT"
    )
  });
  if (
    input.authenticatedPrincipal !== requiredEnvironment(
      INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_PRINCIPAL_ENVIRONMENT
    )
  ) {
    throw new Error(
      "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_PRINCIPAL_REJECTED"
    );
  }
  const result = await runIntegratedLiveDrillProviderWorker({
    environment: process.env,
    input
  });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}

const startedDirectly =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (startedDirectly) {
  main().catch((error) => {
    const code = /^INTEGRATED_LIVE_DRILL_[A-Z0-9_]{1,120}$/u.test(
      String(error?.message ?? "")
    )
      ? error.message
      : "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_UNKNOWN";
    process.stderr.write(`${code}\n`);
    process.exitCode = 1;
  });
}
