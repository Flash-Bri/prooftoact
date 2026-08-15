import { pathToFileURL } from "node:url";

import {
  acquireIntegratedLiveDrillPrivateRootLease
} from "../src/cloud/integrated-live-drill-provider-evidence.js";
import { assertIntegratedLiveDrillRuntime } from
  "../src/cloud/integrated-live-drill-runtime.js";

import {
  assertIntegratedLiveDrillProviderWorkerEnvironment,
  INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_ROOT_ENVIRONMENT,
  runIntegratedLiveDrillProviderWorker,
  validateIntegratedLiveDrillProviderWorkerInput
} from "../src/cloud/integrated-live-drill-provider-worker.js";
import {
  readSystemdCredential
} from "../src/cloud/systemd-credential.js";

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
  const rootPath = requiredEnvironment(
    INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_ROOT_ENVIRONMENT
  );
  const credentialsDirectory = requiredEnvironment("CREDENTIALS_DIRECTORY");
  let input;
  try {
    input = JSON.parse(readSystemdCredential({
      credentialsDirectory,
      maximumBytes: 8 * 1024 * 1024,
      name: "provider-worker-input"
    }).toString("utf8"));
  } catch (cause) {
    throw new Error(
      "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_REJECTED",
      { cause }
    );
  }
  input = validateIntegratedLiveDrillProviderWorkerInput(input);
  const forbiddenRootPath = input.context.forbiddenRootPath;
  const rootLease = acquireIntegratedLiveDrillPrivateRootLease({
    binding: input.context.evidenceRootBinding,
    code: "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_ROOT_REJECTED",
    forbiddenRootPath,
    rootPath
  });
  try {
    const environment = assertIntegratedLiveDrillProviderWorkerEnvironment(
      process.env,
      { forbiddenRootPath, rootPath }
    );
    assertIntegratedLiveDrillRuntime({
      environment: process.env,
      expectedComponent: "worker",
      spec: input.context.trustedRunContext.spec
    });
    if (
      input.context.recoveryEvidenceRootPath !== rootPath
    ) {
      throw new Error(
        "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_ROOT_REJECTED"
      );
    }
    await rootLease.assertSettled();
    const result = await runIntegratedLiveDrillProviderWorker({
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
