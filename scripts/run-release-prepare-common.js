import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

import {
  brokerCanonicalBytes,
  brokerPublicKeyFingerprint,
  brokerSha256,
  providerBrokerConstants,
  validateProviderBrokerApproval
} from "./release-provider-one-shot-broker.js";
import {
  APP_SOURCE,
  ARTIFACT_NAMES,
  PARAMETER_KEYS,
  base64Sha256,
  canonicalDigest,
  canonicalJson,
  sha256
} from "../release-provider/src/release-provider-common.js";
import {
  gitEnvironment,
  gitInvariantArguments,
  trustedGitExecutable
} from "./lib/exact-git-source.js";

const WORKFLOW = "ProofToAct Release Candidate";
const WORKFLOW_REF =
  "Flash-Bri/prooftoact/.github/workflows/" +
  "prooftoact-release-candidate.yml@refs/heads/main";
const OFFICIAL_REPOSITORY = "Flash-Bri/prooftoact";
const OFFICIAL_REPOSITORY_ID = "1317716765";
const OFFICIAL_OWNER_ID = "252500266";
const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;
const CONTROL_PLANE_MANIFEST_SCHEMA =
  "prooftoact.control-plane-executable-manifest.v1";
const MINIMUM_APPROVAL_REMAINING_MS = Object.freeze({
  dispatch: 10 * 60 * 1000,
  finalize: 5 * 60 * 1000,
  reserve: 5 * 60 * 1000
});
const OFFICIAL_ORIGIN = new Set([
  "https://github.com/Flash-Bri/prooftoact",
  "https://github.com/Flash-Bri/prooftoact.git"
]);
const TRACKED_EXECUTABLE_PATHS = Object.freeze([
  ".github/workflows/prooftoact-release-candidate.yml",
  "config/prooftoact-release-operator-public.pub",
  "infra/aws/release-deployment-roles-template.json",
  "release-control/build-release-control-runtime.js",
  "release-provider/build-release-provider-runtimes.js",
  "scripts/normalize-release-control-checkouts.js",
  "scripts/release-provider-one-shot-broker.js",
  "scripts/run-release-prepare-common.js",
  "scripts/run-release-prepare-phase.js",
  "scripts/run-release-prepare-preflight.js"
]);
const PHASES = Object.freeze({
  diagnostic: Object.freeze({
    environment: "DIAGNOSTIC_NO_PROVIDER",
    job: "prepare-diagnostic",
    phase: null,
    role: null
  }),
  reserve: Object.freeze({
    environment: "aws-release-coordination",
    job: "coordinator-reserve",
    phase: "COORDINATOR_RESERVE",
    role: "ProofToActReleaseCoordinator"
  }),
  dispatch: Object.freeze({
    environment: "aws-release-deployment",
    job: "provider-dispatch",
    phase: "PROVIDER_DISPATCH",
    role: "ProofToActReleaseDeployment"
  }),
  finalize: Object.freeze({
    environment: "aws-release-coordination",
    job: "coordinator-finalize",
    phase: "COORDINATOR_FINALIZE",
    role: "ProofToActReleaseCoordinator"
  })
});
const PRIVATE_CONFIGURATION_KEYS = Object.freeze([
  "artifactBucket",
  "authorityDatabaseHost",
  "authorityDatabasePort",
  "authorityDatabaseSecretArn",
  "authorityDatabaseSecretVersionId",
  "authorityIncidentId",
  "authorityResourceId",
  "authorityTenantId",
  "bedrockModelId",
  "configDigest",
  "schemaVersion"
]);
const LOOKUP_KEYS = Object.freeze([
  "approvalSha256",
  "commandSha256",
  "globalKeySha256",
  "intentSha256",
  "lookupSha256",
  "namespaceArnSha256",
  "schemaVersion",
  "tableIdentitySha256"
]);

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function plainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value, expected) {
  return plainObject(value) && Object.keys(value).sort().join("\n") ===
    [...expected].sort().join("\n");
}

function digest(value) {
  return brokerSha256(brokerCanonicalBytes(value));
}

function exactFileSha256(root, relativePath, code) {
  const candidate = path.resolve(root, relativePath);
  requireCondition(path.relative(root, candidate) ===
    relativePath.split("/").join(path.sep), code);
  let descriptor;
  try {
    requireCondition(fs.realpathSync(candidate) === candidate, code);
    descriptor = fs.openSync(candidate,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const stat = fs.fstatSync(descriptor);
    requireCondition(stat.isFile() && stat.nlink === 1 && stat.size > 0 &&
      stat.size <= 8 * 1024 * 1024, code);
    return crypto.createHash("sha256").update(fs.readFileSync(descriptor))
      .digest("hex");
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  } finally {
    if (Number.isSafeInteger(descriptor)) fs.closeSync(descriptor);
  }
}

function gitText(root, args, code) {
  const result = spawnSync(trustedGitExecutable(),
    [...gitInvariantArguments(), ...args], {
      cwd: root,
      encoding: "utf8",
      env: { ...gitEnvironment(), GIT_OPTIONAL_LOCKS: "0" },
      maxBuffer: 8 * 1024 * 1024,
      stdio: ["ignore", "pipe", "ignore"]
    });
  requireCondition(!result.error && result.status === 0 &&
    typeof result.stdout === "string", code);
  return result.stdout.trim();
}

export function verifyLiveControlCheckout({
  controlRoot,
  expectedCommit,
  expectedTree
}) {
  const code = "RELEASE_PREPARE_LIVE_CONTROL_CHECKOUT_REJECTED";
  requireCondition(HEX_40.test(expectedCommit ?? "") &&
    HEX_40.test(expectedTree ?? ""), code);
  const root = exactDirectory(controlRoot, code);
  const gitDirectory = path.join(root, ".git");
  let gitStat;
  try {
    gitStat = fs.lstatSync(gitDirectory);
  } catch (cause) {
    reject(code, cause);
  }
  requireCondition(gitStat.isDirectory() && !gitStat.isSymbolicLink() &&
    fs.realpathSync(gitDirectory) === gitDirectory &&
    gitText(root, ["rev-parse", "--show-toplevel"], code) === root &&
    gitText(root, ["rev-parse", "HEAD"], code) === expectedCommit &&
    gitText(root, ["rev-parse", "HEAD^{tree}"], code) === expectedTree &&
    ["HEAD", "main"].includes(gitText(root,
      ["rev-parse", "--abbrev-ref", "HEAD"], code)) &&
    OFFICIAL_ORIGIN.has(gitText(root,
      ["config", "--local", "--get", "remote.origin.url"], code)) &&
    gitText(root, ["status", "--porcelain=v1", "--untracked-files=all"],
      code) === "", code);
  for (const relativePath of TRACKED_EXECUTABLE_PATHS) {
    requireCondition(gitText(root,
      ["ls-files", "--error-unmatch", "--", relativePath], code) ===
      relativePath, code);
  }
  return Object.freeze({ commit: expectedCommit, root, tree: expectedTree });
}

export function createControlPlaneExecutableManifest({
  controlPlane,
  controlReceipt,
  controlRoot,
  operatorPublicKey,
  providerReceipt
}) {
  const code = "RELEASE_PREPARE_CONTROL_PLANE_BUILD_REJECTED";
  requireCondition(controlPlane && controlReceipt && providerReceipt &&
    controlReceipt.controlPlaneCommit === controlPlane.commit &&
    controlReceipt.controlPlaneTree === controlPlane.tree &&
    providerReceipt.controlPlaneCommit === controlPlane.commit &&
    providerReceipt.controlPlaneTree === controlPlane.tree &&
    HEX_64.test(controlReceipt.sha256 ?? "") &&
    HEX_64.test(controlReceipt.provenanceSha256 ?? "") &&
    HEX_64.test(providerReceipt.runtimeSetSha256 ?? "") &&
    HEX_64.test(providerReceipt.provenanceSha256 ?? ""), code);
  const manifest = Object.freeze({
    schemaVersion: CONTROL_PLANE_MANIFEST_SCHEMA,
    brokerSha256: exactFileSha256(controlRoot,
      "scripts/release-provider-one-shot-broker.js", code),
    commit: controlPlane.commit,
    controlRuntimeProvenanceSha256: controlReceipt.provenanceSha256,
    controlRuntimeSha256: controlReceipt.sha256,
    iamBootstrapTemplateSha256: exactFileSha256(controlRoot,
      "infra/aws/release-deployment-roles-template.json", code),
    normalizerSha256: exactFileSha256(controlRoot,
      "scripts/normalize-release-control-checkouts.js", code),
    operatorPublicKeyFingerprint:
      brokerPublicKeyFingerprint(operatorPublicKey),
    prepareCommonSha256: exactFileSha256(controlRoot,
      "scripts/run-release-prepare-common.js", code),
    preparePhaseSha256: exactFileSha256(controlRoot,
      "scripts/run-release-prepare-phase.js", code),
    preparePreflightSha256: exactFileSha256(controlRoot,
      "scripts/run-release-prepare-preflight.js", code),
    providerRuntimeProvenanceSha256: providerReceipt.provenanceSha256,
    providerRuntimeSetSha256: providerReceipt.runtimeSetSha256,
    tree: controlPlane.tree,
    workflowSha256: exactFileSha256(controlRoot,
      ".github/workflows/prooftoact-release-candidate.yml", code)
  });
  const buildSha256 = canonicalDigest(manifest);
  const identitySha256 = canonicalDigest({
    brokerArtifactSha256: manifest.brokerSha256,
    buildSha256,
    commit: controlPlane.commit,
    separation: "SEPARATE_CONTROL_PLANE_FROM_FROZEN_APPLICATION",
    tree: controlPlane.tree
  });
  return Object.freeze({ buildSha256, identitySha256, manifest });
}

export function verifyControlPlaneExecutableManifest(options) {
  const code = "RELEASE_PREPARE_CONTROL_PLANE_BUILD_REJECTED";
  const controlPlane = options.approval?.claims?.controlPlane;
  const identity = createControlPlaneExecutableManifest({
    ...options,
    controlPlane
  });
  requireCondition(identity.manifest.brokerSha256 ===
    controlPlane.brokerArtifactSha256 &&
    identity.buildSha256 === controlPlane.buildSha256 &&
    identity.identitySha256 === controlPlane.identitySha256, code);
  return identity;
}

function decodeBase64Json(value, maximumBytes, code) {
  requireCondition(typeof value === "string" && value.length > 0 &&
    value.length <= Math.ceil(maximumBytes / 3) * 4 &&
    value.length % 4 === 0 && BASE64.test(value), code);
  let bytes;
  let parsed;
  try {
    bytes = Buffer.from(value, "base64");
    requireCondition(bytes.length > 0 && bytes.length <= maximumBytes &&
      bytes.toString("base64") === value, code);
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  }
  return parsed;
}

function exactDirectory(candidate, code) {
  try {
    requireCondition(typeof candidate === "string" && path.isAbsolute(candidate) &&
      path.resolve(candidate) === candidate && fs.realpathSync(candidate) === candidate,
    code);
    const stat = fs.lstatSync(candidate);
    requireCondition(stat.isDirectory() && !stat.isSymbolicLink(), code);
    return candidate;
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  }
}

export function validatePrepareWorkflowContext(
  environment,
  phaseName,
  platform = process.platform
) {
  const code = "RELEASE_PREPARE_WORKFLOW_CONTEXT_REJECTED";
  const contract = PHASES[phaseName];
  requireCondition(contract && plainObject(environment) && platform === "linux" &&
    environment.CI === "true" && environment.GITHUB_ACTIONS === "true" &&
    environment.RUNNER_OS === "Linux" &&
    environment.RUNNER_ENVIRONMENT === "github-hosted" &&
    environment.GITHUB_EVENT_NAME === "workflow_dispatch" &&
    environment.GITHUB_REF === "refs/heads/main" &&
    environment.GITHUB_REF_NAME === "main" &&
    environment.GITHUB_REF_TYPE === "branch" &&
    environment.GITHUB_SERVER_URL === "https://github.com" &&
    environment.GITHUB_API_URL === "https://api.github.com" &&
    environment.GITHUB_GRAPHQL_URL === "https://api.github.com/graphql" &&
    environment.GITHUB_REPOSITORY === OFFICIAL_REPOSITORY &&
    environment.GITHUB_REPOSITORY_ID === OFFICIAL_REPOSITORY_ID &&
    environment.GITHUB_REPOSITORY_OWNER_ID === OFFICIAL_OWNER_ID &&
    environment.GITHUB_WORKFLOW === WORKFLOW &&
    environment.GITHUB_WORKFLOW_REF === WORKFLOW_REF &&
    environment.GITHUB_JOB === contract.job &&
    environment.PROOFTOACT_RELEASE_PHASE_ENVIRONMENT ===
      contract.environment &&
    HEX_40.test(environment.GITHUB_SHA ?? "") &&
    environment.GITHUB_WORKFLOW_SHA === environment.GITHUB_SHA &&
    environment.EXPECTED_OFFICIAL_MAIN_COMMIT === environment.GITHUB_SHA &&
    /^[1-9][0-9]{0,19}$/u.test(environment.GITHUB_RUN_ID ?? "") &&
    environment.GITHUB_RUN_ATTEMPT === "1", code);
  const workspace = exactDirectory(environment.GITHUB_WORKSPACE, code);
  const controlRoot = exactDirectory(path.join(workspace, "control-plane"), code);
  const applicationRoot = exactDirectory(
    path.join(workspace, "frozen-application"),
    code
  );
  const control = fs.lstatSync(controlRoot);
  const application = fs.lstatSync(applicationRoot);
  requireCondition(controlRoot !== applicationRoot &&
    (control.dev !== application.dev || control.ino !== application.ino), code);
  return Object.freeze({ applicationRoot, contract, controlRoot, workspace });
}

export function assertDiagnosticCredentialAbsence(environment) {
  const names = Object.keys(environment);
  requireCondition(!names.some((name) =>
    name === "ACTIONS_ID_TOKEN_REQUEST_TOKEN" ||
    name === "ACTIONS_ID_TOKEN_REQUEST_URL" ||
    /^AWS_(?:ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN|WEB_IDENTITY_TOKEN_FILE)$/u
      .test(name) ||
    name === "PROOFTOACT_RELEASE_PREPARE_APPROVAL_B64" ||
    name === "PROOFTOACT_RELEASE_PREPARE_PRIVATE_CONFIG_B64"),
  "RELEASE_PREPARE_DIAGNOSTIC_CREDENTIAL_REJECTED");
  return true;
}

export function consumeExplicitTemporaryCredentials(environment) {
  const code = "RELEASE_PREPARE_EXPLICIT_CREDENTIALS_REJECTED";
  const credentials = {
    accessKeyId: environment.AWS_ACCESS_KEY_ID,
    secretAccessKey: environment.AWS_SECRET_ACCESS_KEY,
    sessionToken: environment.AWS_SESSION_TOKEN
  };
  requireCondition(/^ASIA[A-Z0-9]{16}$/u.test(credentials.accessKeyId ?? "") &&
    typeof credentials.secretAccessKey === "string" &&
    credentials.secretAccessKey.length === 40 &&
    typeof credentials.sessionToken === "string" &&
    credentials.sessionToken.length >= 16 &&
    credentials.sessionToken.length <= 4096 &&
    environment.AWS_REGION === "us-east-1" &&
    environment.AWS_DEFAULT_REGION === "us-east-1", code);
  const allowedAws = new Set([
    "AWS_ACCESS_KEY_ID",
    "AWS_DEFAULT_REGION",
    "AWS_REGION",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN"
  ]);
  requireCondition(Object.keys(environment).filter((name) =>
    name.startsWith("AWS_")).every((name) => allowedAws.has(name)), code);
  for (const name of allowedAws) delete environment[name];
  delete environment.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  delete environment.ACTIONS_ID_TOKEN_REQUEST_URL;
  return Object.freeze(credentials);
}

export function sanitizedBrokerEnvironment(environment) {
  const code = "RELEASE_PREPARE_HOSTILE_ENVIRONMENT_REJECTED";
  const forbidden = Object.keys(environment).filter((name) =>
    environment[name] !== undefined && environment[name] !== "" && (
    /^(?:ALL|HTTP|HTTPS|NO)_PROXY$/u.test(name) ||
    /^(?:DYLD_.+|LD_PRELOAD|NODE_COMPILE_CACHE|NODE_EXTRA_CA_CERTS|NODE_OPTIONS|NODE_PATH|NODE_REPL_EXTERNAL_MODULE|NODE_V8_COVERAGE)$/u.test(name) ||
    /^AWS_/u.test(name) ||
    /OPENAI|OPENCLAW.*OAUTH|(?:npm_config_)?(?:https?_proxy|no_proxy)/iu.test(name)));
  requireCondition(forbidden.length === 0, code);
  return Object.freeze({});
}

export function consumeSignedApproval(environment, trustedOperatorPublicKey,
  now = Date.now()) {
  const encoded = environment.PROOFTOACT_RELEASE_PREPARE_APPROVAL_B64;
  delete environment.PROOFTOACT_RELEASE_PREPARE_APPROVAL_B64;
  const envelope = decodeBase64Json(encoded, 512 * 1024,
    "RELEASE_PREPARE_APPROVAL_SECRET_REJECTED");
  const approval = validateProviderBrokerApproval(
    envelope,
    trustedOperatorPublicKey,
    now
  );
  requireCondition(approval.claims.lane === "PREPARE",
    "RELEASE_PREPARE_APPROVAL_LANE_REJECTED");
  return Object.freeze({ approval, envelope });
}

export function consumeBoundedSignedApproval({
  clock = Date.now,
  environment,
  phaseName,
  trustedOperatorPublicKey
}) {
  const code = "RELEASE_PREPARE_APPROVAL_WINDOW_REJECTED";
  const minimumRemaining = MINIMUM_APPROVAL_REMAINING_MS[phaseName];
  requireCondition(typeof clock === "function" &&
    Number.isSafeInteger(minimumRemaining), code);
  const initialNow = clock();
  validateApprovalWindow({ expiresAt: Number.MAX_SAFE_INTEGER,
    now: initialNow, phaseName, priorNow: 0 });
  const accepted = consumeSignedApproval(environment, trustedOperatorPublicKey,
    initialNow);
  validateApprovalWindow({ expiresAt: accepted.approval.expiresAt,
    now: initialNow, phaseName, priorNow: initialNow });
  let priorNow = initialNow;
  function boundary() {
    const now = clock();
    validateApprovalWindow({ expiresAt: accepted.approval.expiresAt,
      now, phaseName, priorNow });
    const approval = validateProviderBrokerApproval(
      accepted.envelope,
      trustedOperatorPublicKey,
      now
    );
    requireCondition(approval.approvalSha256 ===
      accepted.approval.approvalSha256 &&
      approval.expiresAt - now >= minimumRemaining, code);
    priorNow = now;
    return Object.freeze({ approval, now, remainingMs: approval.expiresAt - now });
  }
  return Object.freeze({ ...accepted, boundary, initialNow,
    minimumRemainingMs: minimumRemaining });
}

function validateApprovalWindow({ expiresAt, now, phaseName, priorNow }) {
  const code = "RELEASE_PREPARE_APPROVAL_WINDOW_REJECTED";
  const minimumRemaining = MINIMUM_APPROVAL_REMAINING_MS[phaseName];
  requireCondition(Number.isSafeInteger(minimumRemaining) &&
    Number.isSafeInteger(now) && now >= 0 &&
    Number.isSafeInteger(priorNow) && now >= priorNow &&
    Number.isSafeInteger(expiresAt) && expiresAt - now >= minimumRemaining,
  code);
  return Object.freeze({ now, remainingMs: expiresAt - now });
}

export function consumePrivatePrepareConfiguration(environment, accountId) {
  const encoded = environment.PROOFTOACT_RELEASE_PREPARE_PRIVATE_CONFIG_B64;
  delete environment.PROOFTOACT_RELEASE_PREPARE_PRIVATE_CONFIG_B64;
  const value = decodeBase64Json(encoded, 64 * 1024,
    "RELEASE_PREPARE_PRIVATE_CONFIG_REJECTED");
  const code = "RELEASE_PREPARE_PRIVATE_CONFIG_REJECTED";
  requireCondition(exactKeys(value, PRIVATE_CONFIGURATION_KEYS) &&
    value.schemaVersion === "prooftoact.prepare-private-configuration.v1" &&
    /^(?!xn--)(?!.*\.\.)(?!\d{1,3}(?:\.\d{1,3}){3}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])$/u
      .test(value.artifactBucket ?? "") &&
    /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+cockroachlabs\.cloud$/u
      .test(value.authorityDatabaseHost ?? "") &&
    /^[1-9][0-9]{0,4}$/u.test(value.authorityDatabasePort ?? "") &&
    Number(value.authorityDatabasePort) <= 65535 &&
    new RegExp(`^arn:aws:secretsmanager:us-east-1:${accountId}:secret:` +
      "[A-Za-z0-9/_+=.@-]+$", "u")
      .test(value.authorityDatabaseSecretArn ?? "") &&
    /^[A-Za-z0-9-]{32,64}$/u.test(
      value.authorityDatabaseSecretVersionId ?? "") &&
    UUID.test(value.authorityIncidentId ?? "") &&
    UUID.test(value.authorityTenantId ?? "") &&
    /^[A-Za-z0-9._:-]{1,160}$/u.test(value.authorityResourceId ?? "") &&
    value.bedrockModelId === "amazon.nova-micro-v1:0" &&
    HEX_64.test(value.configDigest ?? ""), code);
  return Object.freeze({ ...value });
}

export function validateProtectedBootstrapGate({
  approval,
  controlRoot,
  environment,
  phaseName
}) {
  const code = "RELEASE_PREPARE_PROTECTED_BOOTSTRAP_GATE_REJECTED";
  const contract = PHASES[phaseName];
  const bootstrapTemplateSha256 = exactFileSha256(controlRoot,
    "infra/aws/release-deployment-roles-template.json", code);
  requireCondition(contract?.phase && approval?.claims?.globalStore &&
    environment.PROOFTOACT_RELEASE_BOOTSTRAP_STATUS ===
      "EXACT_BOOTSTRAP_PROVIDER_READBACK_ACCEPTED" &&
    HEX_64.test(environment
      .PROOFTOACT_RELEASE_BOOTSTRAP_RECEIPT_SHA256 ?? "") &&
    HEX_64.test(environment
      .PROOFTOACT_RELEASE_BOOTSTRAP_STACK_ID_SHA256 ?? "") &&
    environment.PROOFTOACT_RELEASE_BOOTSTRAP_TEMPLATE_SHA256 ===
      bootstrapTemplateSha256 &&
    environment.PROOFTOACT_RELEASE_CONTROL_TABLE_ID ===
      approval.claims.globalStore.tableId &&
    environment.PROOFTOACT_RELEASE_ROLE_ARN ===
      `arn:aws:iam::${approval.providerAccountId}:role/${contract.role}`,
  code);
  if (phaseName === "dispatch" || phaseName === "finalize") {
    requireCondition(typeof environment
      .PROOFTOACT_RELEASE_PREPARE_PRIVATE_CONFIG_B64 === "string" &&
      environment.PROOFTOACT_RELEASE_PREPARE_PRIVATE_CONFIG_B64.length > 0,
    code);
  }
  return Object.freeze({
    bootstrapReceiptSha256:
      environment.PROOFTOACT_RELEASE_BOOTSTRAP_RECEIPT_SHA256,
    bootstrapStackIdSha256:
      environment.PROOFTOACT_RELEASE_BOOTSTRAP_STACK_ID_SHA256,
    bootstrapTemplateSha256,
    tableId: environment.PROOFTOACT_RELEASE_CONTROL_TABLE_ID
  });
}

export function decodePhaseLookup(value) {
  const lookup = decodeBase64Json(value, 16 * 1024,
    "RELEASE_PREPARE_LOOKUP_REJECTED");
  requireCondition(exactKeys(lookup, LOOKUP_KEYS) &&
    lookup.schemaVersion === "prooftoact.provider-broker-phase-lookup.v1" &&
    [lookup.approvalSha256, lookup.commandSha256, lookup.globalKeySha256,
      lookup.intentSha256, lookup.lookupSha256, lookup.namespaceArnSha256,
      lookup.tableIdentitySha256].every((item) => HEX_64.test(item ?? "")),
  "RELEASE_PREPARE_LOOKUP_REJECTED");
  return Object.freeze({ ...lookup });
}

export function encodePhaseLookup(lookup) {
  requireCondition(exactKeys(lookup, LOOKUP_KEYS) &&
    lookup.schemaVersion === "prooftoact.provider-broker-phase-lookup.v1",
  "RELEASE_PREPARE_LOOKUP_REJECTED");
  return Buffer.from(`${JSON.stringify(lookup)}\n`, "utf8").toString("base64");
}

function artifactDescriptor(name, artifact, body, bucket) {
  requireCondition(body.length === artifact.artifactBytes &&
    sha256(body) === artifact.artifactDigest &&
    base64Sha256(body) === artifact.artifactCodeSha256,
  "RELEASE_PREPARE_ARTIFACT_REJECTED");
  return Object.freeze({
    body,
    descriptor: Object.freeze({
      bytes: body.length,
      checksumSha256: base64Sha256(body),
      codeSha256: artifact.artifactCodeSha256,
      contentType: "application/zip",
      kind: "LAMBDA_ZIP",
      name,
      s3Bucket: bucket,
      s3Key: artifact.suggestedS3Key,
      sha256: artifact.artifactDigest,
      sourceSha256: artifact.sourceDigest
    })
  });
}

function createResourceInventory(template) {
  return Object.freeze(Object.entries(template.Resources)
    .filter(([, resource]) => resource.Condition !== "ShouldDeployProbes")
    .map(([logicalId, resource]) => Object.freeze({
      logicalId,
      type: resource.Type
    }))
    .sort((left, right) => left.logicalId.localeCompare(right.logicalId)));
}

function parameterBindings({ accountId, artifacts, configuration,
  packageLockDigest }) {
  const values = {
    ArtifactBucket: configuration.artifactBucket,
    AuthorityDatabaseHost: configuration.authorityDatabaseHost,
    AuthorityDatabasePort: configuration.authorityDatabasePort,
    AuthorityDatabaseSecretArn: configuration.authorityDatabaseSecretArn,
    AuthorityDatabaseSecretVersionId:
      configuration.authorityDatabaseSecretVersionId,
    AuthorityIncidentId: configuration.authorityIncidentId,
    AuthorityResourceId: configuration.authorityResourceId,
    AuthorityTenantId: configuration.authorityTenantId,
    BedrockModelId: configuration.bedrockModelId,
    ConfigDigest: configuration.configDigest,
    EnableProbeFunctions: "false",
    EvidenceOperatorPrincipalArn:
      `arn:aws:iam::${accountId}:role/ProofToActLiveDrillOperator`,
    PackageLockDigest: packageLockDigest,
    SourceCommit: APP_SOURCE.commit,
    TreeDigest: APP_SOURCE.tree
  };
  for (const artifact of artifacts) {
    const prefix = artifact.descriptor.name[0].toUpperCase() +
      artifact.descriptor.name.slice(1);
    values[`${prefix}ArtifactCodeSha256`] =
      artifact.descriptor.codeSha256;
    values[`${prefix}ArtifactDigest`] = artifact.descriptor.sha256;
    values[`${prefix}ArtifactKey`] = artifact.descriptor.s3Key;
    values[`${prefix}SourceDigest`] = artifact.descriptor.sourceSha256;
  }
  const bindings = PARAMETER_KEYS.map((ParameterKey) => {
    if (ParameterKey.endsWith("ArtifactVersion")) {
      const prefix = ParameterKey.slice(0, -"ArtifactVersion".length);
      return Object.freeze({
        ParameterKey,
        Source: "OBJECT_VERSION",
        Value: prefix.toLowerCase()
      });
    }
    requireCondition(typeof values[ParameterKey] === "string" &&
      values[ParameterKey].length > 0,
    "RELEASE_PREPARE_PARAMETER_REJECTED");
    return Object.freeze({
      ParameterKey,
      Source: "LITERAL",
      Value: values[ParameterKey]
    });
  });
  return Object.freeze(bindings);
}

export function buildPrepareProviderRequest({
  accountId,
  applicationRoot,
  approvalClaims,
  buildReceiptBytes,
  configuration,
  intentId,
  validatedBuild
}) {
  const code = "RELEASE_PREPARE_REQUEST_BINDING_REJECTED";
  requireCondition(/^[0-9]{12}$/u.test(accountId ?? "") &&
    approvalClaims?.lane === "PREPARE" && UUID.test(intentId ?? "") &&
    exactKeys(validatedBuild.artifacts, ARTIFACT_NAMES) &&
    Buffer.isBuffer(buildReceiptBytes), code);
  const artifacts = ARTIFACT_NAMES.map((name) => {
    const artifact = validatedBuild.artifacts[name];
    const body = fs.readFileSync(path.join(applicationRoot,
      artifact.artifactPath));
    return artifactDescriptor(name, artifact, body,
      configuration.artifactBucket);
  });
  const templateBody = fs.readFileSync(path.join(applicationRoot,
    "infra/aws/gate2-template.json"));
  const templateSha256 = sha256(templateBody);
  const template = Object.freeze({
    body: templateBody,
    descriptor: Object.freeze({
      bytes: templateBody.length,
      checksumSha256: base64Sha256(templateBody),
      contentType: "application/json",
      kind: "CLOUDFORMATION_TEMPLATE",
      name: "gate2-template",
      s3Bucket: configuration.artifactBucket,
      s3Key: `gate2/${APP_SOURCE.commit}/gate2-template-${templateSha256}.json`,
      sha256: templateSha256
    })
  });
  const gate2 = JSON.parse(templateBody.toString("utf8"));
  const inventory = createResourceInventory(gate2);
  const parameters = parameterBindings({
    accountId,
    artifacts,
    configuration,
    packageLockDigest: validatedBuild.packageLockDigest
  });
  const release = approvalClaims.release;
  requireCondition(sha256(buildReceiptBytes) === release.buildReceiptSha256 &&
    canonicalDigest({
      artifactBucket: configuration.artifactBucket,
      artifacts: artifacts.map(({ descriptor }) => descriptor)
    }) === release.artifactManifestSha256 &&
    canonicalDigest(parameters) === release.parameterManifestSha256 &&
    canonicalDigest(inventory) === release.resourceInventorySha256 &&
    templateSha256 === release.templateSha256,
  code);
  return Object.freeze({
    schemaVersion: "prooftoact.prepare-provider-request.v1",
    accountId,
    artifactBucket: configuration.artifactBucket,
    artifacts,
    capabilities: Object.freeze(["CAPABILITY_NAMED_IAM"]),
    changeSetName: release.changeSetName,
    changeSetType: "CREATE",
    cloudFormationRoleArn:
      `arn:aws:iam::${accountId}:role/ProofToActGate2CloudFormation`,
    commandSha256: null,
    createResourceInventory: inventory,
    intentId,
    parameterBindings: parameters,
    region: "us-east-1",
    stackName: "prooftoact-gate2",
    template
  });
}

export function bindPrepareRequestToCommand(request, command) {
  requireCondition(request.commandSha256 === null &&
    request.changeSetName === command.changeSetName &&
    request.intentId && command.commandSha256,
  "RELEASE_PREPARE_REQUEST_COMMAND_REJECTED");
  return Object.freeze({ ...request, commandSha256: command.commandSha256 });
}

export function phaseRuntimeIdentity(runtime) {
  const identity = {
    environment: runtime.environment,
    jobName: runtime.jobName,
    lane: runtime.lane,
    phase: runtime.phase,
    principalArn: runtime.principalArn,
    providerAccountId: runtime.providerAccountId,
    repositoryId: runtime.repositoryId,
    repositoryOwnerId: runtime.repositoryOwnerId,
    runAttempt: runtime.runAttempt,
    runId: runtime.runId,
    workflow: runtime.workflow,
    workflowRef: runtime.workflowRef,
    workflowSha: runtime.workflowSha
  };
  return Object.freeze({ ...identity,
    phaseRuntimeIdentitySha256: digest(identity) });
}

export function buildPhaseRuntime({ actualControlPlaneBuildSha256, approval,
  brokerArtifactSha256, context, callerIdentity, phaseName,
  now = Date.now() }) {
  const contract = PHASES[phaseName];
  const env = context.environment;
  const code = "RELEASE_PREPARE_PHASE_RUNTIME_REJECTED";
  const expectedSession = `pta-${env.GITHUB_RUN_ID}-1-${contract.job}`;
  requireCondition(contract?.phase && callerIdentity.accountId ===
    approval.providerAccountId && callerIdentity.roleName === contract.role &&
    callerIdentity.sessionName === expectedSession &&
    callerIdentity.assumedRoleArn ===
      `arn:aws:sts::${approval.providerAccountId}:assumed-role/` +
      `${contract.role}/${expectedSession}` &&
    actualControlPlaneBuildSha256 === approval.claims.controlPlane.buildSha256 &&
    brokerArtifactSha256 === approval.claims.controlPlane.brokerArtifactSha256,
  code);
  const runtime = {
    schemaVersion: providerBrokerConstants.PHASE_RUNTIME_SCHEMA,
    adminDatabaseCredentialPresent: false,
    appSource: APP_SOURCE,
    artifactManifestSha256: approval.claims.release.artifactManifestSha256,
    authorityReceipts: null,
    brokerArtifactSha256,
    buildReceiptSha256: approval.claims.release.buildReceiptSha256,
    controlPlaneBuildSha256: actualControlPlaneBuildSha256,
    controlPlaneCommit: approval.claims.controlPlane.commit,
    controlPlaneIdentitySha256: approval.claims.controlPlane.identitySha256,
    controlPlaneTree: approval.claims.controlPlane.tree,
    credentialSource: "GITHUB_OIDC_SHORT_LIVED",
    environment: contract.environment,
    jobName: contract.job,
    lane: "PREPARE",
    openClawOauthPresent: false,
    phase: contract.phase,
    principalArn: callerIdentity.assumedRoleArn,
    providerAccountId: approval.providerAccountId,
    region: "us-east-1",
    releaseReadbackSha256: digest(approval.claims.release),
    repositoryId: OFFICIAL_REPOSITORY_ID,
    repositoryOwnerId: OFFICIAL_OWNER_ID,
    rootOrAdministratorPrincipal: false,
    runAttempt: 1,
    runId: env.GITHUB_RUN_ID,
    staticProviderCredentialsPresent: false,
    workflow: WORKFLOW,
    workflowRef: WORKFLOW_REF,
    workflowSha: env.GITHUB_SHA,
    workspaceRoot: context.controlRoot
  };
  const identity = phaseRuntimeIdentity(runtime);
  const expiresAt = Math.min(Date.parse(context.approvalEnvelope.expiresAt),
    now + 10 * 60 * 1000);
  requireCondition(expiresAt > now, code);
  runtime.authorityReceipts = Object.freeze({
    schemaVersion: providerBrokerConstants.PHASE_AUTHORITY_SCHEMA,
    status: "EXACT_PHASE_RUNTIME_AUTHORITY_CONFIRMED",
    artifactReadbackSha256: approval.claims.release.artifactManifestSha256,
    buildReadbackSha256: approval.claims.release.buildReceiptSha256,
    controlPlaneSha256: approval.claims.controlPlane.identitySha256,
    costCensusSha256: approval.claims.budget.censusReceiptSha256,
    expiresAt: new Date(expiresAt).toISOString(),
    freshDatabaseSha256:
      approval.claims.database.freshPrimaryReceiptSha256,
    globalStoreSha256: approval.claims.globalStore.tableIdentitySha256,
    iamSeparationSha256: digest(approval.claims.authoritySeparation),
    observedAt: new Date(now).toISOString(),
    providerBacked: true,
    providerIdentitySha256: digest({
      accountId: runtime.providerAccountId,
      principalArn: runtime.principalArn,
      region: runtime.region
    }),
    releaseReadbackSha256: digest(approval.claims.release),
    sourceCheckoutSha256: digest(APP_SOURCE),
    strongRead: true,
    teardownContractSha256: digest(approval.claims.teardown),
    workflowIdentitySha256: identity.phaseRuntimeIdentitySha256
  });
  return Object.freeze({ ...runtime });
}

export function brokerFileSha256(controlRoot) {
  return crypto.createHash("sha256").update(fs.readFileSync(path.join(
    controlRoot,
    "scripts/release-provider-one-shot-broker.js"
  ))).digest("hex");
}

export function readTrackedOperatorPublicKey(controlRoot) {
  const file = path.join(controlRoot,
    "config/prooftoact-release-operator-public.pub");
  const descriptor = fs.openSync(file,
    fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const stat = fs.fstatSync(descriptor);
    requireCondition(stat.isFile() && stat.nlink === 1 &&
      stat.size > 0 && stat.size <= 16 * 1024,
    "RELEASE_PREPARE_OPERATOR_KEY_REJECTED");
    return fs.readFileSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}

export const releasePrepareConstants = Object.freeze({
  CONTROL_PLANE_MANIFEST_SCHEMA,
  MINIMUM_APPROVAL_REMAINING_MS,
  LOOKUP_KEYS,
  PHASES,
  PRIVATE_CONFIGURATION_KEYS,
  TRACKED_EXECUTABLE_PATHS,
  WORKFLOW,
  WORKFLOW_REF
});

export const __test = Object.freeze({
  decodeBase64Json,
  digest,
  exactKeys,
  parameterBindings,
  validateApprovalWindow
});
