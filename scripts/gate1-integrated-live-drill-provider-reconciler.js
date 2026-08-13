import { pathToFileURL } from "node:url";

import {
  acquireIntegratedLiveDrillPrivateRootLease
} from "../src/cloud/integrated-live-drill-provider-evidence.js";
import {
  runIntegratedLiveDrillProviderReconciliation
} from "../src/cloud/integrated-live-drill-provider-reconciliation.js";
import { assertIntegratedLiveDrillRuntime } from
  "../src/cloud/integrated-live-drill-runtime.js";
import { parseIntegratedLiveDrillSpec } from
  "../src/cloud/integrated-live-drill.js";
import {
  readSystemdCredential,
  readSystemdCredentialText
} from "../src/cloud/systemd-credential.js";

export async function main() {
  const credentialsDirectory = process.env.CREDENTIALS_DIRECTORY;
  const input = JSON.parse(readSystemdCredential({
    credentialsDirectory,
    maximumBytes: 8 * 1024 * 1024,
    name: "provider-reconciliation-input"
  }).toString("utf8"));
  const spec = parseIntegratedLiveDrillSpec(input.context.trustedRunContext.spec);
  const rootPath = input.context.recoveryEvidenceRootPath;
  const forbiddenRootPath = input.context.forbiddenRootPath;
  const rootLease = acquireIntegratedLiveDrillPrivateRootLease({
    binding: input.context.evidenceRootBinding,
    code: "INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_ROOT_REJECTED",
    forbiddenRootPath,
    rootPath
  });
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
    }),
    TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_ROOT: rootPath,
    TIDEPROOF_INTEGRATED_LIVE_DRILL_FORBIDDEN_ROOT: forbiddenRootPath
  });
  assertIntegratedLiveDrillRuntime({
    environment,
    expectedComponent: "reconciler",
    spec
  });
  try {
    await rootLease.assertSettled();
    const result = await runIntegratedLiveDrillProviderReconciliation({
      environment,
      input
    });
    await rootLease.assertSettled();
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } finally {
    rootLease.release();
  }
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
