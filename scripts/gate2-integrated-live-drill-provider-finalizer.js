import { pathToFileURL } from "node:url";

import {
  assertIntegratedLiveDrillProviderFinalizerEnvironment,
  finalizeIntegratedLiveDrillProviderRecovery,
  INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_FORBIDDEN_ROOT_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_INPUT_PATH_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_ROOT_ENVIRONMENT,
  readIntegratedLiveDrillProviderFinalizationInput
} from "../src/cloud/integrated-live-drill-provider-finalization.js";

export function main() {
  const environment = assertIntegratedLiveDrillProviderFinalizerEnvironment(
    process.env
  );
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
  const receipt = finalizeIntegratedLiveDrillProviderRecovery({
    context: input.context,
    providerContinuity: input.providerContinuity
  });
  process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
}

const startedDirectly =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (startedDirectly) {
  try {
    main();
  } catch (error) {
    const code = /^INTEGRATED_LIVE_DRILL_[A-Z0-9_]{1,120}$/u.test(
      String(error?.message ?? "")
    )
      ? error.message
      : "INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_UNKNOWN";
    process.stderr.write(`${code}\n`);
    process.exitCode = 1;
  }
}
