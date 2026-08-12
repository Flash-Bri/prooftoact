import {
  GATE2_BUILD_CONTROL_INPUT_COUNT,
  GATE2_BUILD_OUTPUT_COUNT,
  GATE2_BUILD_SCHEMA
} from "../../src/cloud/release-build-receipt-contract.js";

export {
  GATE2_BUILD_CONTROL_INPUT_COUNT,
  GATE2_BUILD_OUTPUT_COUNT,
  GATE2_BUILD_SCHEMA
};

export const GATE2_LIVE_RUNTIME_COMPONENTS = Object.freeze([
  "authority-race",
  "dvi",
  "finalizer",
  "orchestrator",
  "recovery",
  "supervisor",
  "worker"
]);

export const GATE2_BUILD_CONTROL_PATHS = Object.freeze([
  "infra/aws/lambda/agent.cjs",
  "scripts/build-gate2-exact.js",
  "scripts/build-gate2-template.js",
  "scripts/lib/aws-provider-bundle-entry.js",
  "scripts/lib/aws-provider-runtime.js",
  "scripts/lib/aws-provider-runtime-loader.js",
  "scripts/lib/bundled-third-party-notices.js",
  "scripts/lib/dependency-snapshot.js",
  "scripts/lib/deterministic-zip.js",
  "scripts/lib/exact-build-reproduction.js",
  "scripts/lib/exact-git-source.js",
  "scripts/lib/gate2-build-contract.js",
  "scripts/lib/official-node-runtime.js",
  "scripts/lib/pg-native-unavailable.cjs",
  "scripts/lib/raw-text-plugin.js",
  "scripts/lib/verified-node-bundle-launcher.pl",
  "scripts/runtime-entries/integrated-live-drill-authority-race.js",
  "scripts/runtime-entries/integrated-live-drill-dvi.js",
  "scripts/runtime-entries/integrated-live-drill-finalizer.js",
  "scripts/runtime-entries/integrated-live-drill-orchestrator.js",
  "scripts/runtime-entries/integrated-live-drill-recovery.js",
  "scripts/runtime-entries/integrated-live-drill-supervisor.js",
  "scripts/runtime-entries/integrated-live-drill-worker.js",
  "scripts/verify-bundled-third-party-notices.js",
  "scripts/verify-release-privacy.js",
  "RELEASE_PRIVACY_MANIFEST.json",
  "src/cloud/aws-gate2-template.js",
  "src/cloud/integrated-live-drill-runtime-spawn.js",
  "src/cloud/integrated-live-drill-runtime.js",
  "src/cloud/official-node-runtime-contract.js",
  "src/cloud/public-demo.js",
  "src/cloud/release-build-receipt-contract.js"
]);

if (GATE2_BUILD_CONTROL_PATHS.length !== GATE2_BUILD_CONTROL_INPUT_COUNT) {
  throw new Error("GATE2_BUILD_CONTROL_INPUT_COUNT_DRIFT");
}
