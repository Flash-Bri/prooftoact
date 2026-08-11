import { pathToFileURL } from "node:url";

import {
  acquireIntegratedLiveDrillPrivateRootLease,
  INTEGRATED_LIVE_DRILL_PRIVATE_ROOT_DESCRIPTOR_ENVIRONMENT
} from "../src/cloud/integrated-live-drill-provider-evidence.js";

import {
  assertIntegratedLiveDrillProviderFinalizerEnvironment,
  finalizeIntegratedLiveDrillProviderRecovery,
  INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_FORBIDDEN_ROOT_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_INPUT_PATH_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_ROOT_BINDING_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_ROOT_ENVIRONMENT,
  readIntegratedLiveDrillProviderFinalizationInput
} from "../src/cloud/integrated-live-drill-provider-finalization.js";

export async function main() {
  const environment = assertIntegratedLiveDrillProviderFinalizerEnvironment(
    process.env
  );
  let rootBinding;
  try {
    rootBinding = JSON.parse(
      environment[
        INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_ROOT_BINDING_ENVIRONMENT
      ]
    );
  } catch (cause) {
    throw new Error(
      "INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_ROOT_REJECTED",
      { cause }
    );
  }
  const rootLease = acquireIntegratedLiveDrillPrivateRootLease({
    binding: rootBinding,
    code: "INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_ROOT_REJECTED",
    descriptor: Number(
      environment[INTEGRATED_LIVE_DRILL_PRIVATE_ROOT_DESCRIPTOR_ENVIRONMENT]
    ),
    forbiddenRootPath: environment[
      INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_FORBIDDEN_ROOT_ENVIRONMENT
    ],
    rootPath: environment[
      INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_ROOT_ENVIRONMENT
    ]
  });
  try {
  await rootLease.assertSettled();
  const input = readIntegratedLiveDrillProviderFinalizationInput({
    forbiddenRootPath: environment[
      INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_FORBIDDEN_ROOT_ENVIRONMENT
    ],
    inputPath: environment[
      INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_INPUT_PATH_ENVIRONMENT
    ],
    rootPath: environment[
      INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_ROOT_ENVIRONMENT
    ]
  });
  await rootLease.assertSettled();
  const receipt = finalizeIntegratedLiveDrillProviderRecovery({
    context: input.context,
    providerContinuity: input.providerContinuity
  });
  await rootLease.assertSettled();
  process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
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
      : "INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_UNKNOWN";
    process.stderr.write(`${code}\n`);
    process.exitCode = 1;
  });
}
