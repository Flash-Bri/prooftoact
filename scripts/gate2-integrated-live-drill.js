import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import {
  buildIntegratedLiveDrillCandidateReceipt,
  parseIntegratedLiveDrillSpec,
  persistIntegratedLiveDrillPrivateEvidence
} from "../src/cloud/integrated-live-drill.js";
import { parseAuthorityDrillBinding } from
  "../src/cloud/aws-authority-race.js";
import { isolatedEvidenceProcessEnvironment } from
  "../src/cloud/aws-evidence-identity.js";
import {
  assertExactCleanCheckout,
  createAuthorityRaceGitRunner,
  fetchOfficialMain
} from "./gate2-authority-race.js";
import { runReleaseProvenance } from "./verify-release-provenance.js";

const DVI_ENVIRONMENT = Object.freeze([
  "DATABASE_URL",
  "TIDEPROOF_ADMISSIBLE_VECTOR_PROOF_SPEC",
  "TIDEPROOF_AUDITOR_DATABASE_URL"
]);
const AUTHORITY_ENVIRONMENT = Object.freeze([
  "AWS_ACCESS_KEY_ID",
  "AWS_EVIDENCE_EXPECTED_ACCOUNT_ID",
  "AWS_EVIDENCE_EXPECTED_AUTHORITY_CALLER_ARN",
  "AWS_EVIDENCE_EXPECTED_AUTHORITY_CALLER_USER_ID",
  "AWS_SECRET_ACCESS_KEY",
  "AWS_SESSION_TOKEN"
]);
const RECOVERY_ENVIRONMENT = Object.freeze([
  "EXPECTED_PRIMARY_HOSTNAME",
  "EXPECTED_RECOVERY_HOSTNAME",
  "MCP_API_KEY",
  "PRIMARY_AUDIT_DATABASE_URL",
  "PRIMARY_CLUSTER_ID",
  "PRIMARY_RECOVERY_SOURCE_DATABASE_URL",
  "RECOVERY_CLUSTER_ID",
  "RECOVERY_PUBLISHER_DATABASE_URL",
  "RECOVERY_PUBLISHER_PRIVATE_KEY_PKCS8_BASE64",
  "TIDEPROOF_RECOVERY_PUBLISHER_TRUST_ROOT",
  "TIDEPROOF_RECOVERY_PUBLISHER_TRUST_ROOT_COMMITMENT"
]);

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

function isolatedComponentEnvironment(environment, names, additions = {}) {
  const selected = Object.fromEntries(
    names.map((name) => [name, requiredEnvironment(environment, name, 16_384)])
  );
  return Object.freeze({
    ...isolatedEvidenceProcessEnvironment(environment),
    ...selected,
    ...additions
  });
}

export function dviComponentEnvironment(environment) {
  return isolatedComponentEnvironment(environment, DVI_ENVIRONMENT);
}

export function authorityComponentEnvironment(environment, drill) {
  return isolatedComponentEnvironment(
    environment,
    AUTHORITY_ENVIRONMENT,
    {
      TIDEPROOF_AUTHORITY_DRILL_BINDING: JSON.stringify(
        parseAuthorityDrillBinding(drill)
      )
    }
  );
}

export function recoveryComponentEnvironment(environment, additions) {
  return isolatedComponentEnvironment(
    environment,
    RECOVERY_ENVIRONMENT,
    additions
  );
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

export async function verifyIntegratedRelease(spec, rootDir) {
  const readGit = createAuthorityRaceGitRunner({ rootDir });
  fetchOfficialMain(readGit, { rootDir });
  const checkout = assertExactCleanCheckout(spec.sourceCommit, {
    rootDir,
    readGit
  });
  const provenance = await runReleaseProvenance({ projectRoot: rootDir });
  if (
    checkout.treeDigest !== spec.treeDigest ||
    provenance.source.commit !== spec.sourceCommit ||
    provenance.source.tree !== spec.treeDigest ||
    provenance.dependencies.installedTree.packageLockSha256 !==
      spec.packageLockDigest
  ) {
    throw new Error("INTEGRATED_LIVE_DRILL_RELEASE_REJECTED");
  }
  return Object.freeze({
    sourceCommit: spec.sourceCommit,
    treeDigest: spec.treeDigest,
    packageLockDigest: spec.packageLockDigest
  });
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
  runComponent = defaultRunComponent,
  verifyRelease = verifyIntegratedRelease
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
    environment.SOURCE_COMMIT !== spec.sourceCommit ||
    environment.CONFIG_DIGEST !== spec.configDigest
  ) {
    throw new Error("INTEGRATED_LIVE_DRILL_ENVIRONMENT_REJECTED");
  }
  const preRelease = await verifyRelease(spec, rootDir);
  const dvi = await runComponent(
    path.join(rootDir, "scripts/gate1-admissible-vector.js"),
    ["--proof"],
    dviComponentEnvironment(environment)
  );
  const drill = parseAuthorityDrillBinding({
    runId: spec.runId,
    authorityEvidenceBindingSha256:
      dvi?.drill?.authorityEvidenceBindingSha256,
    selectedEvidenceId: authorityEvidenceId,
    selectedEvidenceDigest: authoritySelectedEvidenceDigest,
    alphaProposalDigest: requiredEnvironment(
      environment,
      "AUTHORITY_ALPHA_PROPOSAL_DIGEST",
      64
    ),
    bravoProposalDigest: requiredEnvironment(
      environment,
      "AUTHORITY_BRAVO_PROPOSAL_DIGEST",
      64
    ),
    alphaLogicalActionDigest: requiredEnvironment(
      environment,
      "AUTHORITY_ALPHA_LOGICAL_ACTION_DIGEST",
      64
    ),
    bravoLogicalActionDigest: requiredEnvironment(
      environment,
      "AUTHORITY_BRAVO_LOGICAL_ACTION_DIGEST",
      64
    )
  });
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
    authorityComponentEnvironment(environment, drill)
  );
  const recoveryEnvironment = recoveryComponentEnvironment(environment, {
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
  });
  const recovery = await runComponent(
    path.join(rootDir, "scripts/gate1-recovery-broker.js"),
    [],
    recoveryEnvironment
  );
  const privateEvidencePath = requiredEnvironment(
    environment,
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_PATH",
    4096
  );
  const privateEvidenceRootPath = requiredEnvironment(
    environment,
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_ROOT",
    4096
  );
  const forbiddenPrivateEvidenceRootPath = fs.realpathSync(rootDir);
  const privateEvidenceReceipt =
    persistIntegratedLiveDrillPrivateEvidence({
      destinationPath: privateEvidencePath,
      evidenceRootPath: privateEvidenceRootPath,
      forbiddenRootPath: forbiddenPrivateEvidenceRootPath,
      spec,
      dvi,
      race,
      recovery,
      authorityEvidenceId,
      authoritySelectedEvidenceDigest
    });
  const candidate = buildIntegratedLiveDrillCandidateReceipt({
    spec,
    dvi,
    race,
    recovery,
    privateEvidencePath,
    privateEvidenceRootPath,
    forbiddenPrivateEvidenceRootPath,
    privateEvidenceReceipt,
    authorityEvidenceId,
    authoritySelectedEvidenceDigest
  });
  const postRelease = await verifyRelease(spec, rootDir);
  if (JSON.stringify(postRelease) !== JSON.stringify(preRelease)) {
    throw new Error("INTEGRATED_LIVE_DRILL_RELEASE_DRIFT");
  }
  return candidate;
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
