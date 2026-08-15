import path from "node:path";
import { pathToFileURL } from "node:url";

import { terminalizeIntegratedLiveDrillProviderDispatch } from
  "../src/cloud/integrated-live-drill-provider-terminalization.js";
import { assertIntegratedLiveDrillRuntime } from
  "../src/cloud/integrated-live-drill-runtime.js";
import { validateProviderDispatchReconciliationInput } from
  "../src/cloud/provider-dispatch-reconciliation-input.js";
import { ProviderDispatchTerminalizeControl } from
  "../src/cloud/provider-dispatch-terminalize-control.js";
import {
  readSystemdCredential,
  readSystemdCredentialText
} from "../src/cloud/systemd-credential.js";

function credentialsDirectory() {
  const value = process.env.CREDENTIALS_DIRECTORY;
  if (typeof value !== "string" || !path.isAbsolute(value) ||
    path.resolve(value) !== value) {
    throw new Error("INTEGRATED_LIVE_DRILL_PROVIDER_TERMINALIZATION_ENVIRONMENT_REJECTED");
  }
  return value;
}

export async function main({ clientFactory = null } = {}) {
  const directory = credentialsDirectory();
  const reconciliation = validateProviderDispatchReconciliationInput(JSON.parse(
    readSystemdCredential({
      credentialsDirectory: directory,
      maximumBytes: 64 * 1024,
      name: "provider-reconciliation-input"
    }).toString("utf8")
  ));
  assertIntegratedLiveDrillRuntime({
    environment: process.env,
    expectedComponent: "provider-terminalizer",
    spec: Object.freeze({
      packageLockDigest: reconciliation.packageLockDigest,
      runtimeBundleManifestSha256:
        process.env.TIDEPROOF_INTEGRATED_LIVE_DRILL_RUNTIME_MANIFEST_SHA256,
      sourceCommit: reconciliation.binding.sourceCommit,
      treeDigest: reconciliation.binding.treeDigest
    })
  });
  const result = await terminalizeIntegratedLiveDrillProviderDispatch({
    input: Object.freeze({
      binding: reconciliation.binding,
      grantId: reconciliation.admission.grantId,
      workerSpecSha256: reconciliation.admission.workerSpecSha256
    }),
    terminalizeControl: new ProviderDispatchTerminalizeControl({
      clientFactory,
      connectionString: readSystemdCredentialText({
        credentialsDirectory: directory,
        name: "provider-terminalize-database-url"
      })
    })
  });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`${String(error?.message ?? "INTEGRATED_LIVE_DRILL_PROVIDER_TERMINALIZATION_UNKNOWN")}\n`);
    process.exitCode = 1;
  });
}
