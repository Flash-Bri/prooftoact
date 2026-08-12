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
import {
  buildIntegratedLiveDrillProviderOrchestrationCompletion,
  buildIntegratedLiveDrillProviderOrchestrationPreparation,
  claimIntegratedLiveDrillProviderOrchestrationAdmission,
  INTEGRATED_LIVE_DRILL_PROVIDER_DECISION_ROOT_DESCRIPTOR_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STATES,
  persistIntegratedLiveDrillProviderOrchestrationStop,
  persistIntegratedLiveDrillProviderOrchestrationPreparation,
  persistIntegratedLiveDrillExactPrivateJson,
  readIntegratedLiveDrillOrchestrationPrivateJson,
  readIntegratedLiveDrillProviderOrchestrationDecisionIfPresent,
  readIntegratedLiveDrillProviderOrchestrationPreparation,
  sanitizedIntegratedLiveDrillProviderOrchestrationHold,
  validateIntegratedLiveDrillProviderOrchestrationCompletion,
  validateIntegratedLiveDrillProviderSupervisorCompletion,
  validateIntegratedLiveDrillProviderSupervisorPreparation
} from "../src/cloud/integrated-live-drill-provider-orchestration.js";
import { canonicalJson } from "../src/cloud/canonical-json.js";
import {
  integratedLiveDrillAuthorizationAttestationDigest,
  integratedLiveDrillCanonicalSha256,
  integratedLiveDrillRunnerIdentityDigest,
  validateIntegratedLiveDrillPreAuthorizationBinding,
  validateIntegratedLiveDrillRunAuthorization
} from "../src/cloud/integrated-live-drill-authorization.js";
import {
  acquireIntegratedLiveDrillPrivateRootLease,
  normalizeIntegratedLiveDrillProviderContext,
  INTEGRATED_LIVE_DRILL_PRIVATE_ROOT_DESCRIPTOR_ENVIRONMENT,
  validateIntegratedLiveDrillProviderDispatchAuthorizationPure
} from "../src/cloud/integrated-live-drill-provider-evidence.js";
import {
  readIntegratedLiveDrillProviderRecoveryAuthorizationPreparation
} from "../src/cloud/integrated-live-drill-provider-recovery.js";
import {
  consumeIntegratedLiveDrillRunAuthorization,
  finalizeIntegratedLiveDrillControlLedger,
  reserveIntegratedLiveDrillSpend
} from "../src/cloud/integrated-live-drill-control-ledger.js";
import {
  assertIntegratedLiveDrillRuntime
} from "../src/cloud/integrated-live-drill-runtime.js";
import { spawnIntegratedLiveDrillRuntimeComponent } from
  "../src/cloud/integrated-live-drill-runtime-spawn.js";
import {
  integratedLiveDrillProviderReconciliationEnvironment,
  INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_INPUT_PATH_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_INPUT_SCHEMA,
  validateIntegratedLiveDrillProviderReconciliationReceipt
} from "../src/cloud/integrated-live-drill-provider-reconciliation.js";
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
const PROVIDER_PREPARATION_ENVIRONMENT = Object.freeze(
  RECOVERY_ENVIRONMENT.filter((name) => name !== "MCP_API_KEY")
);
const PROVIDER_RESUME_ENVIRONMENT = Object.freeze([
  "MCP_API_KEY",
  "PRIMARY_AUDIT_DATABASE_URL"
]);
const PROVIDER_ORCHESTRATION_MODE_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_MODE";
const PROVIDER_SUPERVISOR_MODE_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_MODE";
const PROVIDER_SUPERVISOR_CONTEXT_PATH_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_CONTEXT_PATH";
const PROVIDER_DISPATCH_AUTHORIZATION_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION";
const PROVIDER_WORKER_INPUT_PATH_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_WORKER_INPUT_PATH";
const PROVIDER_FINALIZATION_INPUT_PATH_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_FINALIZATION_INPUT_PATH";
const PROVIDER_ROOT_BINDING_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_ROOT_BINDING";
const PROVIDER_EXPECTED_PREPARATION_CONTEXT_SHA256_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_EXPECTED_PREPARATION_CONTEXT_SHA256";
const PROVIDER_EXPECTED_PREPARATION_RECEIPT_SHA256_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_EXPECTED_PREPARATION_RECEIPT_SHA256";
const PROVIDER_EXPECTED_SIGNING_PAYLOAD_SHA256_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_EXPECTED_SIGNING_PAYLOAD_SHA256";
const PROVIDER_ADMISSION_RECEIPT_SHA256_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_ADMISSION_RECEIPT_SHA256";

function boundaryRecord(value, allowedKeys, code) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))
  ) {
    throw new Error(code);
  }
  const ownKeys = Reflect.ownKeys(value);
  if (!ownKeys.every((key) => {
    const descriptor = typeof key === "string"
      ? Object.getOwnPropertyDescriptor(value, key)
      : null;
    return typeof key === "string" &&
      allowedKeys.includes(key) &&
      descriptor !== null &&
      descriptor !== undefined &&
      Object.hasOwn(descriptor, "value") &&
      descriptor.enumerable === true;
  })) {
    throw new Error(code);
  }
  return Object.freeze(Object.fromEntries(ownKeys.map((key) => [
    key,
    Object.getOwnPropertyDescriptor(value, key).value
  ])));
}

function normalizedOrchestratorEnvironment(environment) {
  const code = "INTEGRATED_LIVE_DRILL_ENVIRONMENT_REJECTED";
  const realProcessEnvironment = environment === process.env;
  if (
    !environment ||
    typeof environment !== "object" ||
    Array.isArray(environment) ||
    (
      !realProcessEnvironment &&
      ![Object.prototype, null].includes(Object.getPrototypeOf(environment))
    )
  ) {
    throw new Error(code);
  }
  const ownKeys = Reflect.ownKeys(environment);
  if (!ownKeys.every((key) => {
    const descriptor = typeof key === "string"
      ? Object.getOwnPropertyDescriptor(environment, key)
      : null;
    return typeof key === "string" &&
      descriptor !== null &&
      descriptor !== undefined &&
      Object.hasOwn(descriptor, "value") &&
      descriptor.enumerable === true &&
      typeof descriptor.value === "string";
  })) {
    throw new Error(code);
  }
  return Object.freeze(Object.fromEntries(ownKeys.map((key) => [
    key,
    Object.getOwnPropertyDescriptor(environment, key).value
  ])));
}

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

function strictPathEntryPresent(filePath, code) {
  try {
    fs.lstatSync(filePath);
    return true;
  } catch (cause) {
    if (cause?.code === "ENOENT") return false;
    throw new Error(code, { cause });
  }
}

function pathIsWithin(candidate, root) {
  const relative = path.relative(root, candidate);
  return relative === "" || (
    !relative.startsWith("..") && !path.isAbsolute(relative)
  );
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

export function providerPreparationComponentEnvironment(
  environment,
  additions
) {
  return isolatedComponentEnvironment(
    environment,
    PROVIDER_PREPARATION_ENVIRONMENT,
    additions
  );
}

export function providerResumeComponentEnvironment(environment, additions) {
  return isolatedComponentEnvironment(
    environment,
    PROVIDER_RESUME_ENVIRONMENT,
    additions
  );
}

function defaultRunComponent(
  script,
  args,
  environment,
  rootDir,
  { capabilityRootPath, decisionRootDescriptor, rootDescriptor, spec } = {}
) {
  const stdio = Number.isSafeInteger(rootDescriptor)
    ? Number.isSafeInteger(decisionRootDescriptor)
      ? ["ignore", "pipe", "pipe", rootDescriptor, decisionRootDescriptor]
      : ["ignore", "pipe", "pipe", rootDescriptor]
    : ["ignore", "pipe", "pipe"];
  const result = spawnIntegratedLiveDrillRuntimeComponent({
    args,
    childEnvironment: environment,
    cwd: Number.isSafeInteger(rootDescriptor)
      ? capabilityRootPath
      : rootDir,
    parentComponent: "orchestrator",
    parentEnvironment: process.env,
    script,
    spec,
    stdio
  });
  if (
    result.error ||
    result.status !== 0 ||
    typeof result.stdout !== "string" ||
    result.stdout.length === 0 ||
    result.stdout.length > 8 * 1024 * 1024
  ) {
    const childCode = typeof result.stderr === "string"
      ? result.stderr.trim()
      : "";
    throw new Error(
      /^INTEGRATED_LIVE_DRILL_[A-Z0-9_]{1,140}$/u.test(childCode)
        ? childCode
        : "INTEGRATED_LIVE_DRILL_COMPONENT_FAILED"
    );
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
  const packageLockPath = path.join(rootDir, "package-lock.json");
  const packageLockStat = fs.lstatSync(packageLockPath);
  if (
    !packageLockStat.isFile() ||
    packageLockStat.isSymbolicLink() ||
    packageLockStat.nlink !== 1
  ) {
    throw new Error("INTEGRATED_LIVE_DRILL_RELEASE_REJECTED");
  }
  const packageLockDigest = createHash("sha256")
    .update(fs.readFileSync(packageLockPath))
    .digest("hex");
  if (
    checkout.treeDigest !== spec.treeDigest ||
    packageLockDigest !== spec.packageLockDigest
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

function providerOrchestrationMode(environment) {
  const value = environment?.[PROVIDER_ORCHESTRATION_MODE_ENVIRONMENT];
  const dispatchPresent =
    environment?.[PROVIDER_DISPATCH_AUTHORIZATION_ENVIRONMENT] !== undefined;
  if (value === undefined) {
    if (dispatchPresent) {
      throw new Error(
        "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_PARTIAL_CONFIG_REJECTED"
      );
    }
    return null;
  }
  if (!['PREPARE', 'RESUME'].includes(value)) {
    throw new Error("INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_MODE_REJECTED");
  }
  if (value === "PREPARE" && dispatchPresent) {
    throw new Error(
      "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_PARTIAL_CONFIG_REJECTED"
    );
  }
  return value;
}

function providerOrchestrationPaths(privateEvidenceRootPath, spec) {
  return Object.freeze({
    checkpointPath: path.join(
      privateEvidenceRootPath,
      `${spec.runId}.provider-orchestration-preparation.json`
    ),
    completionPath: path.join(
      privateEvidenceRootPath,
      `${spec.runId}.provider-orchestration-completion.json`
    ),
    contextPath: path.join(
      privateEvidenceRootPath,
      `${spec.runId}.provider-supervisor-context.json`
    ),
    finalizationInputPath: path.join(
      privateEvidenceRootPath,
      `${spec.runId}.provider-finalization-input.json`
    ),
    reconciliationInputPath: path.join(
      privateEvidenceRootPath,
      `${spec.runId}.provider-reconciliation-input.json`
    ),
    workerInputPath: path.join(
      privateEvidenceRootPath,
      `${spec.runId}.provider-worker-input.json`
    )
  });
}

export function verifyIntegratedLiveDrillProviderPreparationEvidence({
  forbiddenRootPath,
  gate1Preparation,
  paths,
  rootBinding,
  rootPath
}) {
  const context = normalizeIntegratedLiveDrillProviderContext(
    readIntegratedLiveDrillOrchestrationPrivateJson({
      code: "INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_CONTEXT_REJECTED",
      filePath: paths.contextPath,
      forbiddenRootPath,
      rootPath
    }),
    { requireDispatchAuthorization: false }
  );
  if (canonicalJson(context.evidenceRootBinding) !== canonicalJson(rootBinding)) {
    throw new Error(
      "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_ROOT_BINDING_REJECTED"
    );
  }
  const dispatchPreparation =
    readIntegratedLiveDrillProviderRecoveryAuthorizationPreparation(context);
  const supervisorEvidence = Object.freeze({ context, dispatchPreparation });
  return Object.freeze({
    gate1Preparation: validateIntegratedLiveDrillProviderSupervisorPreparation(
      gate1Preparation,
      supervisorEvidence
    ),
    supervisorEvidence
  });
}

export function verifyIntegratedLiveDrillProviderDispatchAdmission({
  dispatchAuthorization,
  now,
  requireCurrent,
  supervisorEvidence
}) {
  if (
    !supervisorEvidence ||
    typeof supervisorEvidence !== "object" ||
    !supervisorEvidence.context
  ) {
    throw new Error(
      "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_PREPARATION_REJECTED"
    );
  }
  const context = normalizeIntegratedLiveDrillProviderContext(
    supervisorEvidence.context,
    { requireDispatchAuthorization: false }
  );
  return validateIntegratedLiveDrillProviderDispatchAuthorizationPure(
    dispatchAuthorization,
    {
      childAuthorizationIssuedAt:
        context.preCallInputs.consumedChildAuthorization.attestation.payload
          .issuedAt,
      humanAuthorizationTrustRoot:
        context.trustedRunContext.humanAuthorizationTrustRoot,
      intent: context.preCallIntent,
      now,
      requireCurrent
    }
  );
}

async function resumeIntegratedLiveDrillProviderOrchestration({
  clock,
  environment,
  rootDir,
  runComponent,
  spec,
  verifiedRootDir,
  verifyProviderDispatchAuthorization,
  verifyProviderPreparationEvidence,
  verifyRelease
}) {
  const privateEvidenceRootPath = requiredEnvironment(
    environment,
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_ROOT",
    4096
  );
  const forbiddenRootPath = verifiedRootDir;
  const requestedDecisionRootPath = requiredEnvironment(
    environment,
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_AUTHORIZATION_LEDGER_ROOT",
    4096
  );
  if (
    pathIsWithin(requestedDecisionRootPath, privateEvidenceRootPath) ||
    pathIsWithin(privateEvidenceRootPath, requestedDecisionRootPath)
  ) {
    throw new Error(
      "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_ROOT_SEPARATION_REJECTED"
    );
  }
  const paths = providerOrchestrationPaths(privateEvidenceRootPath, spec);
  let completionPresent = false;
  let decision = null;
  let decisionPath = null;
  let decisionRootBound = false;
  let decisionRootLease;
  let decisionRootPath = null;
  let preparation = null;
  let providerAdmissionClaimedHere = false;
  let assertAdmissionMatches = null;
  const rootLease = acquireIntegratedLiveDrillPrivateRootLease({
    code: "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_ROOT_BINDING_REJECTED",
    forbiddenRootPath,
    rootPath: privateEvidenceRootPath
  });
  try {
    const completionObservation = rootLease.beginOperation();
    completionPresent = strictPathEntryPresent(
      paths.completionPath,
      "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_COMPLETION_REJECTED"
    );
    rootLease.assertOperation(completionObservation);
    const checkpointObservation = rootLease.beginOperation();
    const checkpoint = readIntegratedLiveDrillProviderOrchestrationPreparation({
      checkpointPath: paths.checkpointPath,
      forbiddenRootPath,
      rootPath: privateEvidenceRootPath,
      spec
    });
    rootLease.assertOperation(checkpointObservation);
    ({ preparation } = checkpoint);
    const { persistence } = checkpoint;
    if (
      canonicalJson(preparation.evidenceRootBinding) !==
        canonicalJson(rootLease.binding)
    ) {
      throw new Error(
        "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_ROOT_BINDING_REJECTED"
      );
    }
    rootLease.assertCurrent();
    const assertCheckpointCurrent = async () => {
      const observation = rootLease.beginOperation();
      const current = readIntegratedLiveDrillProviderOrchestrationPreparation({
        checkpointPath: paths.checkpointPath,
        forbiddenRootPath,
        rootPath: privateEvidenceRootPath,
        spec
      });
      rootLease.assertOperation(observation);
      if (
        canonicalJson(current.persistence) !== canonicalJson(persistence) ||
        canonicalJson(current.preparation) !== canonicalJson(preparation)
      ) {
        throw new Error(
          "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_UNKNOWN_DO_NOT_ACT"
        );
      }
      await rootLease.assertSettled();
    };
    await assertCheckpointCurrent();
    await rootLease.assertSettled();
    decisionRootPath = requestedDecisionRootPath;
    decisionPath = path.join(
      decisionRootPath,
      `${spec.runId}.provider-orchestration-decision.json`
    );
    if (
      integratedLiveDrillCanonicalSha256(decisionRootPath) !==
        preparation.decisionRootPathSha256 ||
      integratedLiveDrillCanonicalSha256(decisionPath) !==
        preparation.decisionPathSha256
    ) {
      throw new Error(
        "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_DECISION_ROOT_REJECTED"
      );
    }
    decisionRootLease = acquireIntegratedLiveDrillPrivateRootLease({
      binding: preparation.decisionRootBinding,
      code:
        "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_DECISION_ROOT_REJECTED",
      forbiddenRootPath,
      rootPath: decisionRootPath
    });
    await decisionRootLease.assertSettled();
    decisionRootBound = true;
    decision = readIntegratedLiveDrillProviderOrchestrationDecisionIfPresent({
      decisionPath,
      forbiddenRootPath,
      rootPath: decisionRootPath
    });
    if (
      decision?.decision ===
        INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STATES
          .STOPPED_BEFORE_PROVIDER_ADMISSION
    ) {
      return decision;
    }
    assertAdmissionMatches = (observed, dispatchSha256 = null) => {
      if (
        observed?.decision !==
          INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STATES
            .PROVIDER_ADMITTED ||
        observed.authorizationId !== preparation.authorizationId ||
        observed.runId !== preparation.runId ||
        observed.preparationReceiptSha256 !== preparation.receiptSha256 ||
        observed.preparationContextSha256 !==
          preparation.gate1Preparation.preparationContextSha256 ||
        observed.signingPayloadSha256 !==
          preparation.gate1Preparation.signingPayloadSha256 ||
        observed.checkpointPersistenceReceiptSha256 !==
          persistence.receiptSha256 ||
        observed.decisionPathSha256 !== preparation.decisionPathSha256 ||
        observed.decisionRootBindingReceiptSha256 !==
          preparation.decisionRootBinding.receiptSha256 ||
        observed.decisionRootPathSha256 !==
          preparation.decisionRootPathSha256 ||
        observed.evidenceRootBindingReceiptSha256 !==
          preparation.evidenceRootBinding.receiptSha256 ||
        observed.sourceCommit !== preparation.sourceCommit ||
        observed.treeDigest !== preparation.treeDigest ||
        (
          dispatchSha256 !== null &&
          observed.dispatchAuthorizationSha256 !== dispatchSha256
        )
      ) {
        throw new Error(
          "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STATE_CONFLICT"
        );
      }
      return observed;
    };
    const rebound = await verifyProviderPreparationEvidence({
      decisionRootPath,
      forbiddenRootPath,
      gate1Preparation: preparation.gate1Preparation,
      paths,
      rootBinding: rootLease.binding,
      rootPath: privateEvidenceRootPath
    });
    if (
      canonicalJson(rebound?.gate1Preparation) !==
        canonicalJson(preparation.gate1Preparation)
    ) {
      throw new Error(
        "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_PREPARATION_REJECTED"
      );
    }
    const reboundContext = rebound?.supervisorEvidence?.context;
    if (
      reboundContext?.ledgerRootPath !== decisionRootPath
    ) {
      throw new Error(
        "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_DECISION_ROOT_REJECTED"
      );
    }
    if (
      completionPresent &&
      decision?.decision !==
        INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STATES.PROVIDER_ADMITTED
    ) {
      throw new Error(
        "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STATE_CONFLICT"
      );
    }
    if (completionPresent) {
      assertAdmissionMatches(decision);
      const completionReadObservation = rootLease.beginOperation();
      const existingCompletion =
        validateIntegratedLiveDrillProviderOrchestrationCompletion(
          readIntegratedLiveDrillOrchestrationPrivateJson({
            code:
              "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_COMPLETION_REJECTED",
            filePath: paths.completionPath,
            forbiddenRootPath,
            rootPath: privateEvidenceRootPath
          }),
          preparation,
          spec
        );
      rootLease.assertOperation(completionReadObservation);
      await assertCheckpointCurrent();
      await rootLease.assertSettled();
      await decisionRootLease.assertSettled();
      return existingCompletion;
    }
    await assertCheckpointCurrent();
    const preRelease = await verifyRelease(spec, verifiedRootDir);
    const dispatchAuthorizationText = requiredEnvironment(
      environment,
      PROVIDER_DISPATCH_AUTHORIZATION_ENVIRONMENT,
      1024 * 1024
    );
    const dispatchAuthorization = parseJson(
      dispatchAuthorizationText,
      "INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION_REJECTED"
    );
    const dispatchEvidence = await verifyProviderDispatchAuthorization({
      dispatchAuthorization,
      now: clock(),
      requireCurrent: decision === null,
      supervisorEvidence: rebound?.supervisorEvidence ?? null
    });
    if (!/^[0-9a-f]{64}$/u.test(dispatchEvidence?.attestationSha256 ?? "")) {
      throw new Error(
        "INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION_REJECTED"
      );
    }
    if (decision === null) {
      const admissionClaim =
        claimIntegratedLiveDrillProviderOrchestrationAdmission({
          decisionPath,
          dispatchAuthorizationSha256: dispatchEvidence.attestationSha256,
          forbiddenRootPath,
          persistence,
          preparation,
          rootPath: decisionRootPath
        });
      decision = admissionClaim.decision;
      providerAdmissionClaimedHere = admissionClaim.claimed;
      if (
        decision.decision ===
            INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STATES
              .STOPPED_BEFORE_PROVIDER_ADMISSION
      ) {
        return decision;
      }
      if (!admissionClaim.claimed) {
        assertAdmissionMatches(decision, dispatchEvidence.attestationSha256);
      }
    }
    assertAdmissionMatches(decision, dispatchEvidence.attestationSha256);
    const currentDecision =
      readIntegratedLiveDrillProviderOrchestrationDecisionIfPresent({
        decisionPath,
        forbiddenRootPath,
        rootPath: decisionRootPath
      });
    assertAdmissionMatches(
      currentDecision,
      dispatchEvidence.attestationSha256
    );
    if (canonicalJson(currentDecision) !== canonicalJson(decision)) {
      throw new Error(
        "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STATE_CONFLICT"
      );
    }
    await rootLease.assertSettled();
    await decisionRootLease.assertSettled();
    if (!providerAdmissionClaimedHere) {
      const reconciliationInput = Object.freeze({
        schemaVersion:
          INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_INPUT_SCHEMA,
        context: Object.freeze({
          ...rebound.supervisorEvidence.context,
          providerDispatchAuthorization: dispatchAuthorization
        }),
        providerAdmissionReceiptSha256: decision.receiptSha256
      });
      const inputWriteObservation = rootLease.beginOperation();
      persistIntegratedLiveDrillExactPrivateJson({
        code: "INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_INPUT_REJECTED",
        filePath: paths.reconciliationInputPath,
        forbiddenRootPath,
        rootPath: privateEvidenceRootPath,
        value: reconciliationInput
      });
      rootLease.assertOperation(inputWriteObservation);
      const rawReconciliation = await runComponent(
        path.join(
          rootDir,
          "scripts/gate1-integrated-live-drill-provider-reconciler.js"
        ),
        [],
        integratedLiveDrillProviderReconciliationEnvironment(environment, {
          [INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_INPUT_PATH_ENVIRONMENT]:
            paths.reconciliationInputPath,
          TIDEPROOF_INTEGRATED_LIVE_DRILL_FORBIDDEN_ROOT: forbiddenRootPath,
          TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_ROOT:
            privateEvidenceRootPath,
          TIDEPROOF_INTEGRATED_LIVE_DRILL_SPEC: canonicalJson(spec),
          [INTEGRATED_LIVE_DRILL_PRIVATE_ROOT_DESCRIPTOR_ENVIRONMENT]: "3",
          [INTEGRATED_LIVE_DRILL_PROVIDER_DECISION_ROOT_DESCRIPTOR_ENVIRONMENT]:
            "4"
        }),
        verifiedRootDir,
        {
          capabilityRootPath: privateEvidenceRootPath,
          decisionRootDescriptor: decisionRootLease.descriptor,
          rootDescriptor: rootLease.descriptor,
          spec
        }
      );
      const reconciliation =
        validateIntegratedLiveDrillProviderReconciliationReceipt(
        rawReconciliation,
        {
          authorizationId: preparation.authorizationId,
          runId: preparation.runId
        }
      );
      if (reconciliation.providerCompletion === null) {
        return reconciliation;
      }
      const completion = validateIntegratedLiveDrillProviderSupervisorCompletion(
        reconciliation.providerCompletion
      );
      assertAdmissionMatches(
        readIntegratedLiveDrillProviderOrchestrationDecisionIfPresent({
          decisionPath,
          forbiddenRootPath,
          rootPath: decisionRootPath
        }),
        dispatchEvidence.attestationSha256
      );
      await assertCheckpointCurrent();
      const postRelease = await verifyRelease(spec, verifiedRootDir);
      if (canonicalJson(preRelease) !== canonicalJson(postRelease)) {
        throw new Error("INTEGRATED_LIVE_DRILL_RELEASE_DRIFT");
      }
      const receipt = buildIntegratedLiveDrillProviderOrchestrationCompletion({
        completion,
        preparation,
        spec
      });
      const completionWriteObservation = rootLease.beginOperation();
      const persistedCompletion = persistIntegratedLiveDrillExactPrivateJson({
        code:
          "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_COMPLETION_REJECTED",
        filePath: paths.completionPath,
        forbiddenRootPath,
        rootPath: privateEvidenceRootPath,
        value: receipt
      });
      rootLease.assertOperation(completionWriteObservation);
      await assertCheckpointCurrent();
      return validateIntegratedLiveDrillProviderOrchestrationCompletion(
        persistedCompletion,
        preparation,
        spec
      );
    }
    const componentObservation = runComponent === defaultRunComponent
      ? null
      : rootLease.beginOperation();
    const rawCompletion = await runComponent(
        path.join(
          rootDir,
          "scripts/gate1-integrated-live-drill-provider-supervisor.js"
        ),
        [],
        providerResumeComponentEnvironment(environment, {
          [PROVIDER_SUPERVISOR_MODE_ENVIRONMENT]: "RESUME",
          [PROVIDER_SUPERVISOR_CONTEXT_PATH_ENVIRONMENT]: paths.contextPath,
          [PROVIDER_DISPATCH_AUTHORIZATION_ENVIRONMENT]:
            dispatchAuthorizationText,
          [PROVIDER_EXPECTED_PREPARATION_CONTEXT_SHA256_ENVIRONMENT]:
            preparation.gate1Preparation.preparationContextSha256,
          [PROVIDER_EXPECTED_PREPARATION_RECEIPT_SHA256_ENVIRONMENT]:
            preparation.gate1Preparation.preparationReceiptSha256,
          [PROVIDER_EXPECTED_SIGNING_PAYLOAD_SHA256_ENVIRONMENT]:
            preparation.gate1Preparation.signingPayloadSha256,
          [PROVIDER_ADMISSION_RECEIPT_SHA256_ENVIRONMENT]:
            decision.receiptSha256,
          [PROVIDER_WORKER_INPUT_PATH_ENVIRONMENT]: paths.workerInputPath,
          [PROVIDER_FINALIZATION_INPUT_PATH_ENVIRONMENT]:
            paths.finalizationInputPath,
          TIDEPROOF_INTEGRATED_LIVE_DRILL_FORBIDDEN_ROOT: forbiddenRootPath,
          TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_ROOT:
            privateEvidenceRootPath,
          [PROVIDER_ROOT_BINDING_ENVIRONMENT]: canonicalJson(
            rootLease.binding
          ),
          [INTEGRATED_LIVE_DRILL_PRIVATE_ROOT_DESCRIPTOR_ENVIRONMENT]: "3",
          [INTEGRATED_LIVE_DRILL_PROVIDER_DECISION_ROOT_DESCRIPTOR_ENVIRONMENT]:
            "4"
        }),
        verifiedRootDir,
        {
          capabilityRootPath: privateEvidenceRootPath,
          decisionRootDescriptor: decisionRootLease.descriptor,
          rootDescriptor: rootLease.descriptor,
          spec
        }
      );
    if (componentObservation === null) {
      await rootLease.assertSettled();
      await decisionRootLease.assertSettled();
    } else {
      rootLease.assertOperation(componentObservation);
      decisionRootLease.assertCurrent();
    }
    const completion = validateIntegratedLiveDrillProviderSupervisorCompletion(
      rawCompletion
    );
    assertAdmissionMatches(
      readIntegratedLiveDrillProviderOrchestrationDecisionIfPresent({
        decisionPath,
        forbiddenRootPath,
        rootPath: decisionRootPath
      }),
      dispatchEvidence.attestationSha256
    );
    await assertCheckpointCurrent();
    const postRelease = await verifyRelease(spec, verifiedRootDir);
    if (canonicalJson(preRelease) !== canonicalJson(postRelease)) {
      throw new Error("INTEGRATED_LIVE_DRILL_RELEASE_DRIFT");
    }
    const receipt = buildIntegratedLiveDrillProviderOrchestrationCompletion({
      completion,
      preparation,
      spec
    });
    const completionWriteObservation = rootLease.beginOperation();
    const persistedCompletion = persistIntegratedLiveDrillExactPrivateJson({
      code: "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_COMPLETION_REJECTED",
      filePath: paths.completionPath,
      forbiddenRootPath,
      rootPath: privateEvidenceRootPath,
      value: receipt
    });
    rootLease.assertOperation(completionWriteObservation);
    await assertCheckpointCurrent();
    return validateIntegratedLiveDrillProviderOrchestrationCompletion(
      persistedCompletion,
      preparation,
      spec
    );
  } catch (error) {
    if (!decisionRootBound || preparation === null || completionPresent) {
      throw error;
    }
    const causeCode = /^INTEGRATED_LIVE_DRILL_[A-Z0-9_]{1,140}$/u.test(
      String(error?.message ?? "")
    )
      ? error.message
      : "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_UNKNOWN_DO_NOT_ACT";
    if (
      causeCode.startsWith(
        "INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_"
      )
    ) {
      throw error;
    }
    if (
      environment.NODE_ENV === "test" &&
      /SYNTHETIC_CRASH_AFTER_(?:PRE_READ_AUDIT_COMMIT|PROVIDER_EVIDENCE_DURABLE|TERMINAL_AUDIT_COMMIT)$/u.test(
        causeCode
      )
    ) {
      throw error;
    }
    decision = readIntegratedLiveDrillProviderOrchestrationDecisionIfPresent({
      decisionPath,
      forbiddenRootPath,
      rootPath: decisionRootPath
    });
    if (
      decision?.decision ===
        INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STATES.PROVIDER_ADMITTED
    ) {
      if (assertAdmissionMatches === null) throw error;
      return assertAdmissionMatches(decision);
    }
    const state = [
      "INTEGRATED_LIVE_DRILL_PROVIDER_POST_EXPIRY_AUDIT_AUTHORIZATION_REQUIRED",
      "INTEGRATED_LIVE_DRILL_PROVIDER_RECOVERY_AUTHORIZATION_EXPIRED"
    ].includes(causeCode)
      ? INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STATES
          .EXPIRED_FRESH_AUDIT_AUTHORITY_REQUIRED
      : INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STATES.UNKNOWN_DO_NOT_ACT;
    return persistIntegratedLiveDrillProviderOrchestrationStop({
      causeCode,
      forbiddenRootPath,
      preparation,
      rootPath: decisionRootPath,
      state,
      stopPath: decisionPath
    });
  } finally {
    decisionRootLease?.release();
    rootLease.release();
  }
}

export async function runIntegratedLiveDrill(args = {}) {
  const options = boundaryRecord(
    args,
    [
      "clock",
      "environment",
      "rootDir",
      "runComponent",
      "verifyProviderDispatchAuthorization",
      "verifyProviderPreparationEvidence",
      "verifyRelease"
    ],
    "INTEGRATED_LIVE_DRILL_OPTIONS_REJECTED"
  );
  const clock = options.clock ?? Date.now;
  const sourceEnvironment = options.environment ?? process.env;
  const environment = normalizedOrchestratorEnvironment(sourceEnvironment);
  const rootDir = options.rootDir ?? MODULE_ROOT;
  const runComponent = options.runComponent ?? defaultRunComponent;
  const verifyRelease = options.verifyRelease ?? verifyIntegratedRelease;
  const verifyProviderPreparationEvidence =
    options.verifyProviderPreparationEvidence ??
      verifyIntegratedLiveDrillProviderPreparationEvidence;
  const verifyProviderDispatchAuthorization =
    options.verifyProviderDispatchAuthorization ??
      verifyIntegratedLiveDrillProviderDispatchAdmission;
  if (
    typeof clock !== "function" ||
    typeof rootDir !== "string" ||
      typeof runComponent !== "function" ||
      typeof verifyProviderDispatchAuthorization !== "function" ||
      typeof verifyProviderPreparationEvidence !== "function" ||
    typeof verifyRelease !== "function"
  ) {
    throw new Error("INTEGRATED_LIVE_DRILL_OPTIONS_REJECTED");
  }
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
  if (runComponent === defaultRunComponent) {
    if (sourceEnvironment !== process.env) {
      throw new Error("INTEGRATED_LIVE_DRILL_RUNTIME_REJECTED");
    }
    assertIntegratedLiveDrillRuntime({
      environment: process.env,
      expectedComponent: "orchestrator",
      spec
    });
  }
  const orchestrationMode = providerOrchestrationMode(environment);
  if (orchestrationMode === "RESUME") {
    return resumeIntegratedLiveDrillProviderOrchestration({
      clock,
      environment,
      rootDir,
      runComponent,
      spec,
      verifiedRootDir,
      verifyProviderDispatchAuthorization,
      verifyProviderPreparationEvidence,
      verifyRelease
    });
  }
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
  if (
    orchestrationMode !== null &&
    (
      pathIsWithin(authorizationLedgerRootPath, privateEvidenceRootPath) ||
      pathIsWithin(privateEvidenceRootPath, authorizationLedgerRootPath)
    )
  ) {
    throw new Error(
      "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_ROOT_SEPARATION_REJECTED"
    );
  }
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
    verifiedRootDir,
    { spec }
  );
  const postDviRelease = orchestrationMode === "PREPARE"
    ? await verifyRelease(spec, verifiedRootDir)
    : preRelease;
  if (canonicalJson(postDviRelease) !== canonicalJson(preRelease)) {
    throw new Error("INTEGRATED_LIVE_DRILL_RELEASE_DRIFT");
  }
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
    verifiedRootDir,
    { spec }
  );
  const postRaceRelease = orchestrationMode === "PREPARE"
    ? await verifyRelease(spec, verifiedRootDir)
    : preRelease;
  if (
    canonicalJson(postRaceRelease) !== canonicalJson(preRelease) ||
    canonicalJson(postRaceRelease) !== canonicalJson(postDviRelease)
  ) {
    throw new Error("INTEGRATED_LIVE_DRILL_RELEASE_DRIFT");
  }
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
  const recoveryAdditions = {
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
  };
  if (orchestrationMode === "PREPARE") {
    const paths = providerOrchestrationPaths(privateEvidenceRootPath, spec);
    const rootLease = acquireIntegratedLiveDrillPrivateRootLease({
      code: "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_ROOT_BINDING_REJECTED",
      forbiddenRootPath: forbiddenPrivateEvidenceRootPath,
      rootPath: privateEvidenceRootPath
    });
    let decisionRootLease;
    try {
      decisionRootLease = acquireIntegratedLiveDrillPrivateRootLease({
        code:
          "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_DECISION_ROOT_REJECTED",
        forbiddenRootPath: forbiddenPrivateEvidenceRootPath,
        rootPath: authorizationLedgerRootPath
      });
      await rootLease.assertSettled();
      await decisionRootLease.assertSettled();
      const componentObservation = runComponent === defaultRunComponent
        ? null
        : rootLease.beginOperation();
      const rawGate1Preparation = await runComponent(
          path.join(
            rootDir,
            "scripts/gate1-integrated-live-drill-provider-supervisor.js"
          ),
          [],
          providerPreparationComponentEnvironment(environment, {
            ...recoveryAdditions,
            [PROVIDER_SUPERVISOR_MODE_ENVIRONMENT]: "PREPARE",
            [PROVIDER_SUPERVISOR_CONTEXT_PATH_ENVIRONMENT]: paths.contextPath,
            [PROVIDER_ROOT_BINDING_ENVIRONMENT]: canonicalJson(
              rootLease.binding
            ),
            [INTEGRATED_LIVE_DRILL_PRIVATE_ROOT_DESCRIPTOR_ENVIRONMENT]: "3"
          }),
          verifiedRootDir,
          {
            capabilityRootPath: privateEvidenceRootPath,
            rootDescriptor: rootLease.descriptor,
            spec
          }
        );
      if (componentObservation === null) {
        await rootLease.assertSettled();
      } else {
        rootLease.assertOperation(componentObservation);
      }
      const preparationEvidenceObservation = rootLease.beginOperation();
      const verifiedPreparationEvidence =
        verifyProviderPreparationEvidence({
          forbiddenRootPath: forbiddenPrivateEvidenceRootPath,
          gate1Preparation: rawGate1Preparation,
          paths,
          rootBinding: rootLease.binding,
          rootPath: privateEvidenceRootPath
        });
      rootLease.assertOperation(preparationEvidenceObservation);
      const gate1Preparation =
        verifiedPreparationEvidence.gate1Preparation;
      const decisionPath = path.join(
        authorizationLedgerRootPath,
        `${spec.runId}.provider-orchestration-decision.json`
      );
      if (
        decisionRootLease.binding.rootPathSha256 !==
          integratedLiveDrillCanonicalSha256(authorizationLedgerRootPath)
      ) {
        throw new Error(
          "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_DECISION_ROOT_REJECTED"
        );
      }
      const postSupervisorRelease = await verifyRelease(
        spec,
        verifiedRootDir
      );
      if (
        canonicalJson(postSupervisorRelease) !== canonicalJson(preRelease) ||
        canonicalJson(postSupervisorRelease) !== canonicalJson(postRaceRelease)
      ) {
        throw new Error("INTEGRATED_LIVE_DRILL_RELEASE_DRIFT");
      }
      const preparation =
        buildIntegratedLiveDrillProviderOrchestrationPreparation({
        authorityEvidenceId,
        authoritySelectedEvidenceDigest,
        decisionPathSha256: integratedLiveDrillCanonicalSha256(decisionPath),
        decisionRootBinding: decisionRootLease.binding,
        decisionRootPathSha256: integratedLiveDrillCanonicalSha256(
          authorizationLedgerRootPath
        ),
        dvi,
        evidenceRootBinding: rootLease.binding,
        gate1Preparation,
        journalIntentBindingSha256,
        journalPathSha256: sha256(journalPath),
        race,
        spec
      });
      const checkpointWriteObservation = rootLease.beginOperation();
      const persisted =
        persistIntegratedLiveDrillProviderOrchestrationPreparation({
        checkpointPath: paths.checkpointPath,
        forbiddenRootPath: forbiddenPrivateEvidenceRootPath,
        preparation,
        rootPath: privateEvidenceRootPath,
          spec
        });
      rootLease.assertOperation(checkpointWriteObservation);
      const preHoldRelease = await verifyRelease(spec, verifiedRootDir);
      if (
        canonicalJson(preHoldRelease) !== canonicalJson(preRelease) ||
        canonicalJson(preHoldRelease) !== canonicalJson(postDviRelease) ||
        canonicalJson(preHoldRelease) !== canonicalJson(postRaceRelease) ||
        canonicalJson(preHoldRelease) !== canonicalJson(postSupervisorRelease)
      ) {
        throw new Error("INTEGRATED_LIVE_DRILL_RELEASE_DRIFT");
      }
      await rootLease.assertSettled();
      await decisionRootLease.assertSettled();
      return sanitizedIntegratedLiveDrillProviderOrchestrationHold(
        persisted,
        spec
      );
    } finally {
      decisionRootLease?.release();
      rootLease.release();
    }
  }
  const recoveryEnvironment = recoveryComponentEnvironment(
    environment,
    recoveryAdditions
  );
  const recovery = await runComponent(
    path.join(rootDir, "scripts/gate1-recovery-broker.js"),
    [],
    recoveryEnvironment,
    verifiedRootDir,
    { spec }
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
  const exitCode = integratedLiveDrillCliExitCode(receipt);
  if (exitCode !== 0) {
    process.stderr.write(
      "INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_REQUIRED\n"
    );
    process.exitCode = exitCode;
  }
}

export function integratedLiveDrillCliExitCode(receipt) {
  return (
    receipt?.decision ===
        INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STATES.PROVIDER_ADMITTED &&
      receipt?.status ===
        INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STATES.PROVIDER_ADMITTED
  ) || receipt?.status ===
      "AUDIT_ONLY_PROVIDER_RECONCILIATION_NOT_RELEASED"
    ? 3
    : 0;
}

export const __test = Object.freeze({
  defaultRunComponent,
  integratedLiveDrillCliExitCode
});

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
