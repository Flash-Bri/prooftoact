import { pathToFileURL } from "node:url";

import {
  acquireIntegratedLiveDrillPrivateRootLease,
  INTEGRATED_LIVE_DRILL_PRIVATE_ROOT_DESCRIPTOR_ENVIRONMENT
} from "../src/cloud/integrated-live-drill-provider-evidence.js";
import {
  INTEGRATED_LIVE_DRILL_PROVIDER_DECISION_ROOT_DESCRIPTOR_ENVIRONMENT
} from "../src/cloud/integrated-live-drill-provider-orchestration.js";

import {
  assertIntegratedLiveDrillProviderWorkerEnvironment,
  INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_FORBIDDEN_ROOT_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_PATH_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_PRINCIPAL_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_ROOT_BINDING_ENVIRONMENT,
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
  let rootBinding;
  try {
    rootBinding = JSON.parse(requiredEnvironment(
      INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_ROOT_BINDING_ENVIRONMENT
    ));
  } catch (cause) {
    throw new Error(
      "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_REJECTED",
      { cause }
    );
  }
  const rootLease = acquireIntegratedLiveDrillPrivateRootLease({
    binding: rootBinding,
    code: "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_ROOT_REJECTED",
    descriptor: Number(requiredEnvironment(
      INTEGRATED_LIVE_DRILL_PRIVATE_ROOT_DESCRIPTOR_ENVIRONMENT
    )),
    forbiddenRootPath,
    rootPath
  });
  const decisionRootDescriptor = Number(requiredEnvironment(
    INTEGRATED_LIVE_DRILL_PROVIDER_DECISION_ROOT_DESCRIPTOR_ENVIRONMENT
  ));
  if (decisionRootDescriptor !== 4) {
    throw new Error(
      "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_ADMISSION_REJECTED"
    );
  }
  try {
  const environment = assertIntegratedLiveDrillProviderWorkerEnvironment(
    process.env,
    { authenticatedPrincipal, forbiddenRootPath, rootBinding, rootPath }
  );
  const inputObservation = rootLease.beginOperation();
  const input = readIntegratedLiveDrillProviderWorkerInput({
    forbiddenRootPath,
    inputPath: requiredEnvironment(
      INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_PATH_ENVIRONMENT
    ),
    rootPath
  });
  rootLease.assertOperation(inputObservation);
  if (
    input.authenticatedPrincipal !== authenticatedPrincipal
  ) {
    throw new Error(
      "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_PRINCIPAL_REJECTED"
    );
  }
  await rootLease.assertSettled();
  const result = await runIntegratedLiveDrillProviderWorker({
    decisionRootDescriptor,
    evidenceRootDescriptor: rootLease.descriptor,
    environment,
    input
  });
  await rootLease.assertSettled();
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } finally {
    rootLease.release();
  }
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
