import { pathToFileURL } from "node:url";

import {
  assertIntegratedLiveDrillProviderWorkerEnvironment,
  INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_FORBIDDEN_ROOT_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_PATH_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_PRINCIPAL_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_ROOT_ENVIRONMENT,
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
  const authenticatedPrincipal = requiredEnvironment(
    INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_PRINCIPAL_ENVIRONMENT
  );
  const forbiddenRootPath = requiredEnvironment(
    INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_FORBIDDEN_ROOT_ENVIRONMENT
  );
  const rootPath = requiredEnvironment(
    INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_ROOT_ENVIRONMENT
  );
  const environment = assertIntegratedLiveDrillProviderWorkerEnvironment(
    process.env,
    { authenticatedPrincipal, forbiddenRootPath, rootPath }
  );
  const input = readIntegratedLiveDrillProviderWorkerInput({
    forbiddenRootPath,
    inputPath: requiredEnvironment(
      INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_PATH_ENVIRONMENT
    ),
    rootPath
  });
  if (
    input.authenticatedPrincipal !== authenticatedPrincipal
  ) {
    throw new Error(
      "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_PRINCIPAL_REJECTED"
    );
  }
  const result = await runIntegratedLiveDrillProviderWorker({
    environment,
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
