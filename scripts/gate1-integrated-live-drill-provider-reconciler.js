import { pathToFileURL } from "node:url";

import {
  INTEGRATED_LIVE_DRILL_PRIVATE_ROOT_DESCRIPTOR_ENVIRONMENT
} from "../src/cloud/integrated-live-drill-provider-evidence.js";
import {
  INTEGRATED_LIVE_DRILL_PROVIDER_DECISION_ROOT_DESCRIPTOR_ENVIRONMENT
} from "../src/cloud/integrated-live-drill-provider-orchestration.js";
import {
  readIntegratedLiveDrillProviderReconciliationInput,
  runIntegratedLiveDrillProviderReconciliation
} from "../src/cloud/integrated-live-drill-provider-reconciliation.js";
import { assertIntegratedLiveDrillRuntime } from
  "../src/cloud/integrated-live-drill-runtime.js";
import { parseIntegratedLiveDrillSpec } from
  "../src/cloud/integrated-live-drill.js";

export async function main() {
  const spec = parseIntegratedLiveDrillSpec(JSON.parse(
    process.env.TIDEPROOF_INTEGRATED_LIVE_DRILL_SPEC
  ));
  assertIntegratedLiveDrillRuntime({
    environment: process.env,
    expectedComponent: "reconciler",
    spec
  });
  const input = readIntegratedLiveDrillProviderReconciliationInput(process.env);
  const result = await runIntegratedLiveDrillProviderReconciliation({
    decisionRootDescriptor: Number(
      process.env[
        INTEGRATED_LIVE_DRILL_PROVIDER_DECISION_ROOT_DESCRIPTOR_ENVIRONMENT
      ]
    ),
    environment: process.env,
    evidenceRootDescriptor: Number(
      process.env[INTEGRATED_LIVE_DRILL_PRIVATE_ROOT_DESCRIPTOR_ENVIRONMENT]
    ),
    input
  });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}

const startedDirectly = process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href;
if (startedDirectly) {
  main().catch((error) => {
    const code = /^INTEGRATED_LIVE_DRILL_[A-Z0-9_]{1,140}$/u.test(
      String(error?.message ?? "")
    )
      ? error.message
      : "INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_UNKNOWN_DO_NOT_ACT";
    process.stderr.write(`${code}\n`);
    process.exitCode = 1;
  });
}
