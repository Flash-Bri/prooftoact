import { spawnSync } from "node:child_process";
import path from "node:path";
import { pathToFileURL } from "node:url";
import {
  buildIntegratedLiveDrillReceipt,
  parseIntegratedLiveDrillSpec
} from "../src/cloud/integrated-live-drill.js";

function requiredEnvironment(environment, name, maximum = 4096) {
  const value = environment[name];
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maximum ||
    /[\0\r\n]/.test(value)
  ) {
    throw new Error("INTEGRATED_LIVE_DRILL_ENVIRONMENT_REJECTED");
  }
  return value;
}

function parseJson(value, code) {
  try {
    return JSON.parse(value);
  } catch {
    throw new Error(code);
  }
}

function defaultRunComponent(script, args, environment) {
  const result = spawnSync(process.execPath, [script, ...args], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: environment,
    maxBuffer: 8 * 1024 * 1024,
    timeout: 10 * 60 * 1000,
    stdio: ["ignore", "pipe", "pipe"]
  });
  if (
    result.error ||
    result.status !== 0 ||
    typeof result.stdout !== "string" ||
    result.stdout.length === 0 ||
    result.stdout.length > 8 * 1024 * 1024
  ) {
    throw new Error("INTEGRATED_LIVE_DRILL_COMPONENT_FAILED");
  }
  return parseJson(
    result.stdout,
    "INTEGRATED_LIVE_DRILL_COMPONENT_OUTPUT_REJECTED"
  );
}

export function safeIntegratedLiveDrillFailureCode(error) {
  const value = String(error?.message ?? "");
  return /^INTEGRATED_LIVE_DRILL_[A-Z0-9_]{1,100}$/.test(value)
    ? value
    : "INTEGRATED_LIVE_DRILL_UNKNOWN";
}

export async function runIntegratedLiveDrill({
  environment = process.env,
  rootDir = process.cwd(),
  runComponent = defaultRunComponent
} = {}) {
  const spec = parseIntegratedLiveDrillSpec(
    parseJson(
      requiredEnvironment(
        environment,
        "TIDEPROOF_INTEGRATED_LIVE_DRILL_SPEC",
        8192
      ),
      "INTEGRATED_LIVE_DRILL_SPEC_REJECTED"
    )
  );
  const authorityEvidenceId = requiredEnvironment(
    environment,
    "AUTHORITY_EVIDENCE_ID",
    64
  );
  const authoritySelectedEvidenceDigest = requiredEnvironment(
    environment,
    "AUTHORITY_SELECTED_EVIDENCE_DIGEST",
    64
  );
  if (
    environment.AUTHORITY_RUN_ID !== spec.runId ||
    environment.AUTHORITY_RACE_ID !== spec.raceId ||
    environment.SOURCE_COMMIT !== spec.sourceCommit ||
    environment.CONFIG_DIGEST !== spec.configDigest
  ) {
    throw new Error("INTEGRATED_LIVE_DRILL_ENVIRONMENT_REJECTED");
  }
  const dvi = await runComponent(
    path.join(rootDir, "scripts/gate1-admissible-vector.js"),
    ["--proof"],
    environment
  );
  const race = await runComponent(
    path.join(rootDir, "scripts/gate2-authority-race.js"),
    [
      "--config-digest",
      spec.configDigest,
      "--function-arn",
      spec.functionArn,
      "--race-id",
      spec.raceId,
      "--run-id",
      spec.runId,
      "--source-commit",
      spec.sourceCommit
    ],
    environment
  );
  const recoveryEnvironment = {
    ...environment,
    RECOVERY_SOURCE_TENANT_ID: requiredEnvironment(
      environment,
      "AUTHORITY_TENANT_ID",
      64
    ),
    RECOVERY_SOURCE_RUN_ID: spec.runId,
    RECOVERY_SOURCE_INCIDENT_ID: requiredEnvironment(
      environment,
      "AUTHORITY_INCIDENT_ID",
      64
    ),
    RECOVERY_SOURCE_EVIDENCE_ID: authorityEvidenceId,
    RECOVERY_SOURCE_RESOURCE_ID: requiredEnvironment(
      environment,
      "AUTHORITY_RESOURCE_ID",
      160
    ),
    RECOVERY_SOURCE_OPERATION_ID: race.winner?.operationId,
    RECOVERY_SOURCE_REQUEST_DIGEST: race.winner?.requestDigest,
    RECOVERY_SOURCE_AUTHORITY_EVIDENCE_BINDING_SHA256:
      race.dvi?.authorityEvidenceBindingSha256,
    RECOVERY_SOURCE_SELECTED_EVIDENCE_BINDING_SHA256:
      race.dvi?.selectedEvidenceBindingSha256,
    SOURCE_BUILD_IDENTITY: spec.sourceBuildIdentity
  };
  const recovery = await runComponent(
    path.join(rootDir, "scripts/gate1-recovery-broker.js"),
    [],
    recoveryEnvironment
  );
  return buildIntegratedLiveDrillReceipt({
    spec,
    dvi,
    race,
    recovery,
    authorityEvidenceId,
    authoritySelectedEvidenceDigest
  });
}

export async function main() {
  const receipt = await runIntegratedLiveDrill();
  process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
}

const startedDirectly =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (startedDirectly) {
  main().catch((error) => {
    process.stderr.write(
      `${safeIntegratedLiveDrillFailureCode(error)}\n`
    );
    process.exitCode = 1;
  });
}
