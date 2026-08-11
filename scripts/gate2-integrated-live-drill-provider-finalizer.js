import { pathToFileURL } from "node:url";

import {
  finalizeIntegratedLiveDrillProviderRecovery,
  readIntegratedLiveDrillProviderFinalizationInput
} from "../src/cloud/integrated-live-drill-provider-finalization.js";

function requiredEnvironment(name) {
  const value = process.env[name];
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 8192 ||
    /[\0\r\n]/u.test(value)
  ) {
    throw new Error(
      "INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_INPUT_REJECTED"
    );
  }
  return value;
}

export function main() {
  const input = readIntegratedLiveDrillProviderFinalizationInput({
    forbiddenRootPath: requiredEnvironment(
      "TIDEPROOF_INTEGRATED_LIVE_DRILL_FORBIDDEN_ROOT"
    ),
    inputPath: requiredEnvironment(
      "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_INPUT_PATH"
    ),
    rootPath: requiredEnvironment(
      "TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_ROOT"
    )
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
