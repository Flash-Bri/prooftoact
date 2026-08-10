import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  appendIntegratedLiveDrillJournal,
  buildIntegratedLiveDrillCandidateReceipt,
  parseIntegratedLiveDrillSpec,
  persistIntegratedLiveDrillPrivateEvidence,
  startIntegratedLiveDrillJournal
} from "../src/cloud/integrated-live-drill.js";
import { canonicalJson } from "../src/cloud/canonical-json.js";
import {
  integratedLiveDrillAuthorizationAttestationDigest,
  integratedLiveDrillRunnerIdentityDigest,
  validateIntegratedLiveDrillPreAuthorizationBinding,
  validateIntegratedLiveDrillRunAuthorization
} from "../src/cloud/integrated-live-drill-authorization.js";
import {
  consumeIntegratedLiveDrillRunAuthorization,
  finalizeIntegratedLiveDrillControlLedger,
  reserveIntegratedLiveDrillSpend
} from "../src/cloud/integrated-live-drill-control-ledger.js";
import {
  INTEGRATED_LIVE_DRILL_CHILD_COMMITTED_TRUST_ROOT_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION_ENVIRONMENT,
  integratedLiveDrillChildCommittedTrustRoot,
  integratedLiveDrillChildAuthorizationContext
} from "../src/cloud/integrated-live-drill-child-authorization.js";
import {
  validateDeploymentExpectation,
  validateSignedPreDeploymentAttestation
} from "../src/cloud/aws-deployment-attestation.js";
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
import { loadCommittedRecoveryPublisherTrustRoot } from
  "./lib/recovery-publisher-key.js";

const MODULE_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  ".."
);

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

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
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

export function dviComponentEnvironment(environment, additions = {}) {
  return isolatedComponentEnvironment(
    environment,
    DVI_ENVIRONMENT,
    additions
  );
}

export function authorityComponentEnvironment(
  environment,
  drill,
  additions = {}
) {
  return isolatedComponentEnvironment(
    environment,
    AUTHORITY_ENVIRONMENT,
    {
      TIDEPROOF_AUTHORITY_DRILL_BINDING: JSON.stringify(
        parseAuthorityDrillBinding(drill)
      ),
      ...additions
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

function defaultRunComponent(script, args, environment, rootDir) {
  const result = spawnSync(process.execPath, [script, ...args], {
    cwd: rootDir,
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
  clock = Date.now,
  environment = process.env,
  rootDir = MODULE_ROOT,
  runComponent = defaultRunComponent,
  verifyRelease = verifyIntegratedRelease
} = {}) {
  const verifiedRootDir = fs.realpathSync(rootDir);
  if (verifiedRootDir !== rootDir) {
    throw new Error("INTEGRATED_LIVE_DRILL_RELEASE_REJECTED");
  }
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
  const expectation = validateDeploymentExpectation(parseJson(
    requiredEnvironment(
      environment,
      "TIDEPROOF_GATE2_DEPLOYMENT_EXPECTATION",
      1024 * 1024
    ),
    "INTEGRATED_LIVE_DRILL_AUTHORIZATION_REJECTED"
  ));
  const preAttestation = parseJson(
    requiredEnvironment(
      environment,
      "TIDEPROOF_GATE2_PRE_DEPLOYMENT_ATTESTATION",
      8 * 1024 * 1024
    ),
    "INTEGRATED_LIVE_DRILL_AUTHORIZATION_REJECTED"
  );
  const authorizationAttestation = parseJson(
    requiredEnvironment(
      environment,
      "TIDEPROOF_INTEGRATED_LIVE_DRILL_RUN_AUTHORIZATION",
      1024 * 1024
    ),
    "INTEGRATED_LIVE_DRILL_AUTHORIZATION_REJECTED"
  );
  const humanAuthorizationTrustRoot = parseJson(
    requiredEnvironment(
      environment,
      "TIDEPROOF_INTEGRATED_LIVE_DRILL_HUMAN_AUTHORIZATION_TRUST_ROOT",
      16_384
    ),
    "INTEGRATED_LIVE_DRILL_HUMAN_TRUST_ROOT_REJECTED"
  );
  const authorizationLedgerRootPath = requiredEnvironment(
    environment,
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_AUTHORIZATION_LEDGER_ROOT",
    4096
  );
  const runnerIdentity = requiredEnvironment(
    environment,
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_RUNNER_IDENTITY",
    512
  );
  const committedTrustRoot = integratedLiveDrillChildCommittedTrustRoot(
    loadCommittedRecoveryPublisherTrustRoot(environment)
  );
  const childLaunchPrivateKeyPkcs8DerBase64 = requiredEnvironment(
    environment,
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_CHILD_LAUNCH_PRIVATE_KEY_PKCS8_BASE64",
    1024
  );
  const validatedPreAttestation = validateSignedPreDeploymentAttestation(
    preAttestation,
    expectation
  );
  if (typeof clock !== "function") {
    throw new Error("INTEGRATED_LIVE_DRILL_AUTHORIZATION_TIME_REJECTED");
  }
  const validateCurrentLaunchAuthorization = (checkedAt = clock()) => {
    const currentAuthorization = validateIntegratedLiveDrillRunAuthorization(
      authorizationAttestation,
      {
        spec,
        expectation,
        committedTrustRoot,
        humanAuthorizationTrustRoot,
        authorizationLedgerRootPath,
        now: checkedAt
      }
    );
    validateIntegratedLiveDrillPreAuthorizationBinding(
      currentAuthorization,
      validatedPreAttestation,
      { now: checkedAt }
    );
    return currentAuthorization;
  };
  const authorization = validateCurrentLaunchAuthorization();
  if (
    authorization.payload.authorizationClaimAuthority.runnerIdentitySha256 !==
      integratedLiveDrillRunnerIdentityDigest(runnerIdentity)
  ) {
    throw new Error("INTEGRATED_LIVE_DRILL_RUNNER_IDENTITY_REJECTED");
  }
  const preRelease = await verifyRelease(spec, verifiedRootDir);
  const privateEvidenceRootPath = requiredEnvironment(
    environment,
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_ROOT",
    4096
  );
  const journalPath = requiredEnvironment(
    environment,
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_JOURNAL_PATH",
    4096
  );
  const forbiddenPrivateEvidenceRootPath = verifiedRootDir;
  const consumedAuthorization = consumeIntegratedLiveDrillRunAuthorization(
    authorizationAttestation,
    {
      spec,
      expectation,
      committedTrustRoot,
      humanAuthorizationTrustRoot,
      ledgerRootPath: authorizationLedgerRootPath,
      forbiddenRootPath: forbiddenPrivateEvidenceRootPath,
      now: clock()
    }
  );
  validateIntegratedLiveDrillPreAuthorizationBinding(
    consumedAuthorization.authorization,
    validatedPreAttestation,
    { now: clock() }
  );
  const authorizationClaim = consumedAuthorization.claim;
  const spendReservations = [];
  const childLaunchEnvironment = (
    reservation,
    launchAuthorization,
    checkedAt
  ) => {
    const launchToken = integratedLiveDrillChildAuthorizationContext({
      authorization: launchAuthorization,
      claim: authorizationClaim,
      expectation,
      privateKeyPkcs8DerBase64: childLaunchPrivateKeyPkcs8DerBase64,
      reservation,
      spec,
      now: checkedAt
    });
    return Object.freeze({
      TIDEPROOF_INTEGRATED_LIVE_DRILL_SPEC: canonicalJson(spec),
      TIDEPROOF_GATE2_DEPLOYMENT_EXPECTATION: canonicalJson(expectation),
      TIDEPROOF_INTEGRATED_LIVE_DRILL_RUN_AUTHORIZATION: canonicalJson(
        authorizationAttestation
      ),
      TIDEPROOF_INTEGRATED_LIVE_DRILL_HUMAN_AUTHORIZATION_TRUST_ROOT:
        canonicalJson(humanAuthorizationTrustRoot),
      TIDEPROOF_INTEGRATED_LIVE_DRILL_AUTHORIZATION_LEDGER_ROOT:
        authorizationLedgerRootPath,
      TIDEPROOF_INTEGRATED_LIVE_DRILL_RUNNER_IDENTITY: runnerIdentity,
      [INTEGRATED_LIVE_DRILL_CHILD_COMMITTED_TRUST_ROOT_ENVIRONMENT]:
        canonicalJson(
          integratedLiveDrillChildCommittedTrustRoot(committedTrustRoot)
        ),
      [INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION_ENVIRONMENT]:
        canonicalJson(launchToken)
    });
  };
  const authorityAlphaProposalDigest = requiredEnvironment(
    environment,
    "AUTHORITY_ALPHA_PROPOSAL_DIGEST",
    64
  );
  const authorityBravoProposalDigest = requiredEnvironment(
    environment,
    "AUTHORITY_BRAVO_PROPOSAL_DIGEST",
    64
  );
  const authorityAlphaLogicalActionDigest = requiredEnvironment(
    environment,
    "AUTHORITY_ALPHA_LOGICAL_ACTION_DIGEST",
    64
  );
  const authorityBravoLogicalActionDigest = requiredEnvironment(
    environment,
    "AUTHORITY_BRAVO_LOGICAL_ACTION_DIGEST",
    64
  );
  const authorityTenantId = requiredEnvironment(
    environment,
    "AUTHORITY_TENANT_ID",
    64
  );
  const authorityIncidentId = requiredEnvironment(
    environment,
    "AUTHORITY_INCIDENT_ID",
    64
  );
  const authorityResourceId = requiredEnvironment(
    environment,
    "AUTHORITY_RESOURCE_ID",
    160
  );
  const journalIntentBindingSha256 = sha256(canonicalJson({
    schemaVersion: "tideproof.highwater-drill-live-journal-intent.v1",
    spec,
    authorityEvidenceId,
    authoritySelectedEvidenceDigest,
    authorityAlphaProposalDigest,
    authorityBravoProposalDigest,
    authorityAlphaLogicalActionDigest,
    authorityBravoLogicalActionDigest,
    authorityTenantId,
    authorityIncidentId,
    authorityResourceId,
    dviProofSpecSha256: sha256(requiredEnvironment(
      environment,
      "TIDEPROOF_ADMISSIBLE_VECTOR_PROOF_SPEC",
      16_384
    )),
    primaryClusterId: requiredEnvironment(
      environment,
      "PRIMARY_CLUSTER_ID",
      16_384
    ),
    recoveryClusterId: requiredEnvironment(
      environment,
      "RECOVERY_CLUSTER_ID",
      16_384
    ),
    recoveryPublisherTrustRootCommitment: requiredEnvironment(
      environment,
      "TIDEPROOF_RECOVERY_PUBLISHER_TRUST_ROOT_COMMITMENT",
      16_384
    ),
    recoveryPublisherKeySetDigest: committedTrustRoot.publisherKeySetDigest,
    runAuthorizationAttestationSha256:
      integratedLiveDrillAuthorizationAttestationDigest(
        authorizationAttestation
      ),
    authorizationClaimSha256:
      authorizationClaim.authorizationClaimSha256,
    spendAuthorizationSha256:
      authorizationClaim.spendAuthorizationSha256,
    preDeploymentAttestationSha256: sha256(
      canonicalJson(validatedPreAttestation)
    )
  }));
  startIntegratedLiveDrillJournal({
    journalPath,
    evidenceRootPath: privateEvidenceRootPath,
    forbiddenRootPath: forbiddenPrivateEvidenceRootPath,
    spec,
    intentBindingSha256: journalIntentBindingSha256
  });
  const dviCheckedAt = clock();
  const dviAuthorization = validateCurrentLaunchAuthorization(dviCheckedAt);
  const dviSpendReservation = reserveIntegratedLiveDrillSpend({
    authorization: dviAuthorization,
    claim: authorizationClaim,
    scopeId: "DVI_PROOF",
    ledgerRootPath: authorizationLedgerRootPath,
    forbiddenRootPath: forbiddenPrivateEvidenceRootPath,
    now: dviCheckedAt
  });
  spendReservations.push(dviSpendReservation);
  const dvi = await runComponent(
    path.join(rootDir, "scripts/gate1-admissible-vector.js"),
    ["--proof"],
    dviComponentEnvironment(environment, {
      ...childLaunchEnvironment(
        dviSpendReservation,
        dviAuthorization,
        dviCheckedAt
      )
    }),
    verifiedRootDir
  );
  validateCurrentLaunchAuthorization();
  appendIntegratedLiveDrillJournal({
    journalPath,
    evidenceRootPath: privateEvidenceRootPath,
    forbiddenRootPath: forbiddenPrivateEvidenceRootPath,
    spec,
    phase: "DVI_RESULT",
    payload: dvi
  });
  const drill = parseAuthorityDrillBinding({
    runId: spec.runId,
    authorityEvidenceBindingSha256:
      dvi?.drill?.authorityEvidenceBindingSha256,
    selectedEvidenceId: authorityEvidenceId,
    selectedEvidenceDigest: authoritySelectedEvidenceDigest,
    alphaProposalDigest: authorityAlphaProposalDigest,
    bravoProposalDigest: authorityBravoProposalDigest,
    alphaLogicalActionDigest: authorityAlphaLogicalActionDigest,
    bravoLogicalActionDigest: authorityBravoLogicalActionDigest
  });
  const authorityCheckedAt = clock();
  const authorityAuthorization = validateCurrentLaunchAuthorization(
    authorityCheckedAt
  );
  const authoritySpendReservation = reserveIntegratedLiveDrillSpend({
    authorization: authorityAuthorization,
    claim: authorizationClaim,
    scopeId: "AWS_AUTHORITY_RACE",
    ledgerRootPath: authorizationLedgerRootPath,
    forbiddenRootPath: forbiddenPrivateEvidenceRootPath,
    now: authorityCheckedAt
  });
  spendReservations.push(authoritySpendReservation);
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
    authorityComponentEnvironment(environment, drill, {
      ...childLaunchEnvironment(
        authoritySpendReservation,
        authorityAuthorization,
        authorityCheckedAt
      )
    }),
    verifiedRootDir
  );
  validateCurrentLaunchAuthorization();
  appendIntegratedLiveDrillJournal({
    journalPath,
    evidenceRootPath: privateEvidenceRootPath,
    forbiddenRootPath: forbiddenPrivateEvidenceRootPath,
    spec,
    phase: "AUTHORITY_RACE_RESULT",
    payload: race
  });
  const recoveryCheckedAt = clock();
  const recoveryAuthorization = validateCurrentLaunchAuthorization(
    recoveryCheckedAt
  );
  const recoverySpendReservation = reserveIntegratedLiveDrillSpend({
    authorization: recoveryAuthorization,
    claim: authorizationClaim,
    scopeId: "MANAGED_MCP_RECOVERY",
    ledgerRootPath: authorizationLedgerRootPath,
    forbiddenRootPath: forbiddenPrivateEvidenceRootPath,
    now: recoveryCheckedAt
  });
  spendReservations.push(recoverySpendReservation);
  const recoveryEnvironment = recoveryComponentEnvironment(environment, {
    RECOVERY_SOURCE_TENANT_ID: authorityTenantId,
    RECOVERY_SOURCE_RUN_ID: spec.runId,
    RECOVERY_SOURCE_INCIDENT_ID: authorityIncidentId,
    RECOVERY_SOURCE_EVIDENCE_ID: authorityEvidenceId,
    RECOVERY_SOURCE_RESOURCE_ID: authorityResourceId,
    RECOVERY_SOURCE_OPERATION_ID: race.winner?.operationId,
    RECOVERY_SOURCE_REQUEST_DIGEST: race.winner?.requestDigest,
    RECOVERY_SOURCE_AUTHORITY_EVIDENCE_BINDING_SHA256:
      race.dvi?.authorityEvidenceBindingSha256,
    RECOVERY_SOURCE_SELECTED_EVIDENCE_BINDING_SHA256:
      race.dvi?.selectedEvidenceBindingSha256,
    SOURCE_BUILD_IDENTITY: spec.sourceBuildIdentity,
    TIDEPROOF_INTEGRATED_LIVE_DRILL_FORBIDDEN_ROOT:
      forbiddenPrivateEvidenceRootPath,
    TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_ROOT:
      privateEvidenceRootPath,
    TIDEPROOF_INTEGRATED_LIVE_DRILL_RECOVERY_BUNDLE_PATH: path.join(
      privateEvidenceRootPath,
      `${spec.runId}.signed-recovery-bundle.json`
    ),
    TIDEPROOF_INTEGRATED_LIVE_DRILL_SPEC: canonicalJson(spec),
    ...childLaunchEnvironment(
      recoverySpendReservation,
      recoveryAuthorization,
      recoveryCheckedAt
    )
  });
  const recovery = await runComponent(
    path.join(rootDir, "scripts/gate1-recovery-broker.js"),
    [],
    recoveryEnvironment,
    verifiedRootDir
  );
  validateCurrentLaunchAuthorization();
  appendIntegratedLiveDrillJournal({
    journalPath,
    evidenceRootPath: privateEvidenceRootPath,
    forbiddenRootPath: forbiddenPrivateEvidenceRootPath,
    spec,
    phase: "RECOVERY_RESULT",
    payload: recovery
  });
  const privateEvidencePath = requiredEnvironment(
    environment,
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_PATH",
    4096
  );
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
  appendIntegratedLiveDrillJournal({
    journalPath,
    evidenceRootPath: privateEvidenceRootPath,
    forbiddenRootPath: forbiddenPrivateEvidenceRootPath,
    spec,
    phase: "PRIVATE_EVIDENCE_RESULT",
    payload: privateEvidenceReceipt
  });
  const postRelease = await verifyRelease(spec, verifiedRootDir);
  if (JSON.stringify(postRelease) !== JSON.stringify(preRelease)) {
    throw new Error("INTEGRATED_LIVE_DRILL_RELEASE_DRIFT");
  }
  const journalReceipt = appendIntegratedLiveDrillJournal({
    journalPath,
    evidenceRootPath: privateEvidenceRootPath,
    forbiddenRootPath: forbiddenPrivateEvidenceRootPath,
    spec,
    phase: "POST_RELEASE_VERIFICATION",
    payload: postRelease
  });
  const controlLedgerReceipt = finalizeIntegratedLiveDrillControlLedger({
    authorization,
    claim: authorizationClaim,
    reservations: spendReservations,
    ledgerRootPath: authorizationLedgerRootPath,
    forbiddenRootPath: forbiddenPrivateEvidenceRootPath
  });
  return buildIntegratedLiveDrillCandidateReceipt({
    spec,
    dvi,
    race,
    recovery,
    journalPath,
    journalRootPath: privateEvidenceRootPath,
    journalReceipt,
    journalIntentBindingSha256,
    postRelease,
    privateEvidencePath,
    privateEvidenceRootPath,
    forbiddenPrivateEvidenceRootPath,
    privateEvidenceReceipt,
    controlLedgerReceipt,
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
