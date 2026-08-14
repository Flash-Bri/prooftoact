import path from "node:path";
import { pathToFileURL } from "node:url";

import {
  runIntegratedLiveDrillProviderReconciliation,
  validateIntegratedLiveDrillProviderReconciliationInput
} from "../src/cloud/integrated-live-drill-provider-reconciliation.js";
import { providerDispatchReconciliationInputBytes } from
  "../src/cloud/provider-dispatch-reconciliation-input.js";
import { assertIntegratedLiveDrillRuntime } from
  "../src/cloud/integrated-live-drill-runtime.js";
import {
  readSystemdCredential,
  readSystemdCredentialText
} from "../src/cloud/systemd-credential.js";

function requiredAbsoluteEnvironment(name) {
  const value = process.env[name];
  if (
    typeof value !== "string" || !path.isAbsolute(value) ||
    path.resolve(value) !== value || value.length > 4096
  ) {
    throw new Error(
      "INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_ENVIRONMENT_REJECTED"
    );
  }
  return value;
}

export async function main({ clientFactory = null } = {}) {
  const credentialsDirectory = requiredAbsoluteEnvironment(
    "CREDENTIALS_DIRECTORY"
  );
  let input;
  let inputBytes;
  try {
    inputBytes = readSystemdCredential({
        credentialsDirectory,
        maximumBytes: 64 * 1024,
        name: "provider-reconciliation-input"
      });
    input = validateIntegratedLiveDrillProviderReconciliationInput(JSON.parse(
      inputBytes.toString("utf8")
    ));
    if (!providerDispatchReconciliationInputBytes(input).equals(inputBytes)) {
      throw new Error("noncanonical reconciliation input");
    }
  } catch (cause) {
    throw new Error(
      "INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_INPUT_REJECTED",
      { cause }
    );
  }
  const environment = Object.freeze({
    ...Object.fromEntries([
      "LANG", "LC_ALL", "LC_CTYPE", "NO_COLOR", "PATH", "TMPDIR",
      "TIDEPROOF_INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT",
      "TIDEPROOF_INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_SHA256",
      "TIDEPROOF_INTEGRATED_LIVE_DRILL_RUNTIME_MANIFEST_SHA256",
      "TIDEPROOF_INTEGRATED_LIVE_DRILL_RUNTIME_STAGE_ROOT"
    ].filter((name) => typeof process.env[name] === "string")
      .map((name) => [name, process.env[name]])),
    PRIMARY_PROVIDER_RECONCILE_DATABASE_URL: readSystemdCredentialText({
      credentialsDirectory,
      name: "provider-reconcile-database-url"
    })
  });
  assertIntegratedLiveDrillRuntime({
    environment,
    expectedComponent: "reconciler",
    spec: Object.freeze({
      packageLockDigest: input.packageLockDigest,
      runtimeBundleManifestSha256:
        environment.TIDEPROOF_INTEGRATED_LIVE_DRILL_RUNTIME_MANIFEST_SHA256,
      sourceCommit: input.binding.sourceCommit,
      treeDigest: input.binding.treeDigest
    })
  });
  const result = await runIntegratedLiveDrillProviderReconciliation({
    auditClientFactory: clientFactory,
    environment,
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
