import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

import {
  consumePrivatePrepareConfiguration,
  consumeBoundedSignedApproval,
  readTrackedOperatorPublicKey,
  validatePrepareWorkflowContext,
  validateProtectedBootstrapGate
} from "./run-release-prepare-common.js";
import { buildPrepareExecutableSet } from "./run-release-prepare-phase.js";

function requireCondition(condition, code) {
  if (!condition) throw new Error(code);
}

function exactRunnerTemp(environment) {
  const code = "RELEASE_PREPARE_PREFLIGHT_TEMP_REJECTED";
  const candidate = environment.RUNNER_TEMP;
  requireCondition(typeof candidate === "string" && path.isAbsolute(candidate),
  code);
  const real = fs.realpathSync(candidate);
  const stat = fs.lstatSync(real);
  requireCondition(real === path.resolve(candidate) && stat.isDirectory() &&
    !stat.isSymbolicLink(), code);
  return real;
}

function assertBeforeCredentialConfiguration(environment) {
  const code = "RELEASE_PREPARE_PREFLIGHT_CREDENTIAL_REJECTED";
  requireCondition([
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_WEB_IDENTITY_TOKEN_FILE"
  ].every((name) => environment[name] === undefined ||
    environment[name] === ""), code);
}

export async function runPreparePreflight(phaseName, {
  clock = Date.now,
  environment = process.env,
} = {}) {
  requireCondition(["reserve", "dispatch", "finalize"].includes(phaseName),
    "RELEASE_PREPARE_PREFLIGHT_PHASE_REJECTED");
  assertBeforeCredentialConfiguration(environment);
  const context = validatePrepareWorkflowContext(environment, phaseName);
  const publicKey = readTrackedOperatorPublicKey(context.controlRoot);
  const approvalEnvironment = { ...environment };
  const accepted = consumeBoundedSignedApproval({
    clock,
    environment: approvalEnvironment,
    phaseName,
    trustedOperatorPublicKey: publicKey
  });
  requireCondition(accepted.approval.claims.controlPlane.commit ===
    environment.GITHUB_SHA,
  "RELEASE_PREPARE_PREFLIGHT_CONTROL_PLANE_REJECTED");
  validateProtectedBootstrapGate({
    approval: accepted.approval,
    controlRoot: context.controlRoot,
    environment,
    phaseName
  });
  if (phaseName === "dispatch" || phaseName === "finalize") {
    consumePrivatePrepareConfiguration(approvalEnvironment,
      accepted.approval.providerAccountId);
  }
  const executable = await buildPrepareExecutableSet({
    approval: accepted.approval,
    context,
    operatorPublicKey: publicKey,
    runnerTemp: exactRunnerTemp(environment)
  });
  try {
    accepted.boundary();
    return Object.freeze({
      buildSha256: executable.identity.buildSha256,
      providerExecutionEnabled: false,
      status: "EXACT_EXECUTABLE_MANIFEST_VERIFIED_BEFORE_OIDC"
    });
  } finally {
    executable.cleanup();
  }
}

export async function main(args = process.argv.slice(2),
  environment = process.env) {
  requireCondition(args.length === 1,
    "RELEASE_PREPARE_PREFLIGHT_ARGUMENT_REJECTED");
  const result = await runPreparePreflight(args[0], { environment });
  process.stdout.write(`PROOFTOACT_PREPARE_PREFLIGHT_PASS:${result.status}:` +
    `${result.buildSha256}\n`);
}

if (process.argv[1] && import.meta.url ===
  pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch((cause) => {
    const message = String(cause?.message ?? "");
    const code = /^RELEASE_PREPARE_[A-Z0-9_]{1,100}$/u.test(message)
      ? message
      : "RELEASE_PREPARE_PREFLIGHT_UNKNOWN_HOLD";
    process.stderr.write(`HOLD:${code}\n`);
    process.exitCode = 1;
  });
}

export const __test = Object.freeze({ assertBeforeCredentialConfiguration });
