import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");
const OFFICIAL_REMOTE =
  "https://github.com/Flash-Bri/tideproof.git";
const EXPECTED_BRANCH = "main";
const EXPECTED_REGION = "us-east-1";
const ARTIFACT_NAMES = Object.freeze([
  "agent",
  "authority",
  "boundary",
  "demo",
  "probe",
  "signer"
]);
const HEX_40 = /^[0-9a-f]{40}$/;
const HEX_64 = /^[0-9a-f]{64}$/;
const SECRET_ENVIRONMENT_NAME =
  /(TOKEN|SECRET|PASSWORD|API_KEY|PRIVATE_KEY|CREDENTIAL)/i;
const APPLICATION_ENVIRONMENT_NAME = new RegExp(
  [
    "^(",
    "DATABASE_URL",
    "|PG(HOST|PORT|DATABASE|USER|PASSWORD|SERVICE|SERVICEFILE|PASSFILE)",
    "|COCKROACH_.+",
    "|CRDB_.+",
    "|OPENAI_.+",
    "|ANTHROPIC_.+",
    "|GOOGLE_.+",
    "|OPENCLAW_.+",
    "|CODEX_.+",
    "|GH_TOKEN",
    "|GITHUB_TOKEN",
    ")$"
  ].join(""),
  "i"
);

function requireCondition(condition, code) {
  if (!condition) {
    throw new Error(code);
  }
}

function exactKeys(value, keys) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join("\n") ===
      [...keys].sort().join("\n")
  );
}

function sha256(value, encoding = "hex") {
  return crypto.createHash("sha256").update(value).digest(encoding);
}

function sha256File(filePath, encoding = "hex") {
  return sha256(fs.readFileSync(filePath), encoding);
}

function resolvedFile(projectRoot, relativePath, code) {
  requireCondition(
    typeof relativePath === "string" &&
      relativePath.length > 0 &&
      !path.isAbsolute(relativePath),
    code
  );
  const resolved = path.resolve(projectRoot, relativePath);
  const relative = path.relative(projectRoot, resolved);
  requireCondition(
    relative.length > 0 &&
      !relative.startsWith(`..${path.sep}`) &&
      relative !== ".." &&
      !path.isAbsolute(relative),
    code
  );
  const stat = fs.lstatSync(resolved);
  requireCondition(stat.isFile() && !stat.isSymbolicLink(), code);
  return { resolved, stat };
}

function validateStoredSingleFileZip(buffer) {
  requireCondition(
    Buffer.isBuffer(buffer) && buffer.length >= 52,
    "AWS_READINESS_ZIP"
  );
  requireCondition(
    buffer.readUInt32LE(0) === 0x04034b50,
    "AWS_READINESS_ZIP_LOCAL_HEADER"
  );
  const localFlags = buffer.readUInt16LE(6);
  const localMethod = buffer.readUInt16LE(8);
  const compressedBytes = buffer.readUInt32LE(18);
  const uncompressedBytes = buffer.readUInt32LE(22);
  const localNameBytes = buffer.readUInt16LE(26);
  const localExtraBytes = buffer.readUInt16LE(28);
  const localNameEnd = 30 + localNameBytes;
  const dataOffset = localNameEnd + localExtraBytes;
  const centralOffset = dataOffset + compressedBytes;
  requireCondition(
    localFlags === 0 &&
      localMethod === 0 &&
      compressedBytes > 0 &&
      compressedBytes === uncompressedBytes &&
      localNameEnd <= buffer.length &&
      centralOffset + 46 <= buffer.length &&
      buffer.subarray(30, localNameEnd).toString("utf8") ===
        "index.js" &&
      buffer.readUInt32LE(centralOffset) === 0x02014b50,
    "AWS_READINESS_ZIP_LOCAL_ENTRY"
  );

  const centralFlags = buffer.readUInt16LE(centralOffset + 8);
  const centralMethod = buffer.readUInt16LE(centralOffset + 10);
  const centralCompressedBytes =
    buffer.readUInt32LE(centralOffset + 20);
  const centralUncompressedBytes =
    buffer.readUInt32LE(centralOffset + 24);
  const centralNameBytes =
    buffer.readUInt16LE(centralOffset + 28);
  const centralExtraBytes =
    buffer.readUInt16LE(centralOffset + 30);
  const centralCommentBytes =
    buffer.readUInt16LE(centralOffset + 32);
  const localHeaderOffset =
    buffer.readUInt32LE(centralOffset + 42);
  const centralNameEnd = centralOffset + 46 + centralNameBytes;
  const endOffset =
    centralNameEnd + centralExtraBytes + centralCommentBytes;
  requireCondition(
    centralFlags === 0 &&
      centralMethod === 0 &&
      centralCompressedBytes === compressedBytes &&
      centralUncompressedBytes === uncompressedBytes &&
      localHeaderOffset === 0 &&
      centralNameEnd <= buffer.length &&
      buffer
        .subarray(centralOffset + 46, centralNameEnd)
        .toString("utf8") === "index.js" &&
      endOffset + 22 === buffer.length &&
      buffer.readUInt32LE(endOffset) === 0x06054b50 &&
      buffer.readUInt16LE(endOffset + 4) === 0 &&
      buffer.readUInt16LE(endOffset + 6) === 0 &&
      buffer.readUInt16LE(endOffset + 8) === 1 &&
      buffer.readUInt16LE(endOffset + 10) === 1 &&
      buffer.readUInt32LE(endOffset + 12) ===
        endOffset - centralOffset &&
      buffer.readUInt32LE(endOffset + 16) === centralOffset &&
      buffer.readUInt16LE(endOffset + 20) === 0,
    "AWS_READINESS_ZIP_CENTRAL_ENTRY"
  );
}

function validateTemplateReceipt(
  projectRoot,
  receipt,
  expectedPath,
  code
) {
  requireCondition(
    receipt?.path === expectedPath &&
      HEX_64.test(receipt.templateDigest) &&
      HEX_64.test(receipt.canonicalDigest) &&
      Number.isSafeInteger(receipt.bytes) &&
      receipt.bytes > 0,
    code
  );
  const file = resolvedFile(projectRoot, expectedPath, code);
  requireCondition(
    file.stat.size === receipt.bytes &&
      sha256File(file.resolved) === receipt.templateDigest,
    code
  );
  return {
    path: expectedPath,
    templateDigest: receipt.templateDigest,
    canonicalDigest: receipt.canonicalDigest,
    bytes: receipt.bytes
  };
}

export function validateBuildReceipt(
  receipt,
  {
    projectRoot = root,
    sourceCommit,
    treeDigest
  }
) {
  requireCondition(
    receipt?.schemaVersion === "tideproof.gate2-build.v2" &&
      receipt.mode === "CLEAN_ARTIFACT_BUILD" &&
      receipt.sourceCommit === sourceCommit &&
      receipt.treeDigest === treeDigest &&
      receipt.workingTreeClean === true &&
      receipt.workingTreeCleanBeforeGeneration === true &&
      receipt.archiveFormat === "ZIP_STORED_SINGLE_FILE_V1" &&
      HEX_64.test(receipt.packageLockDigest),
    "AWS_READINESS_BUILD_RECEIPT"
  );
  const packageLock = resolvedFile(
    projectRoot,
    "package-lock.json",
    "AWS_READINESS_PACKAGE_LOCK"
  );
  requireCondition(
    sha256File(packageLock.resolved) ===
      receipt.packageLockDigest,
    "AWS_READINESS_PACKAGE_LOCK"
  );

  const artifacts = Array.isArray(receipt.artifacts)
    ? receipt.artifacts
    : [];
  requireCondition(
    artifacts.length === ARTIFACT_NAMES.length &&
      artifacts
        .map((artifact) => artifact?.name)
        .sort()
        .join("\n") === [...ARTIFACT_NAMES].sort().join("\n"),
    "AWS_READINESS_ARTIFACT_SET"
  );

  const acceptedArtifacts = {};
  for (const name of ARTIFACT_NAMES) {
    const artifact = artifacts.find(
      (candidate) => candidate?.name === name
    );
    const expectedSourcePath =
      `infra/aws/lambda/${name}.${name === "demo" ? "js" : "cjs"}`;
    requireCondition(
      artifact?.sourcePath === expectedSourcePath &&
        HEX_64.test(artifact.sourceDigest) &&
        HEX_64.test(artifact.artifactDigest) &&
        typeof artifact.artifactCodeSha256 === "string" &&
        Number.isSafeInteger(artifact.artifactBytes) &&
        artifact.artifactBytes > 0,
      "AWS_READINESS_ARTIFACT_RECEIPT"
    );
    const expectedArtifactFile =
      `${name}-${artifact.artifactDigest}.zip`;
    const expectedArtifactPath =
      `dist/aws/${expectedArtifactFile}`;
    requireCondition(
      artifact.artifactFile === expectedArtifactFile &&
        artifact.artifactPath === expectedArtifactPath &&
        artifact.suggestedS3Key ===
          `gate2/${sourceCommit}/${expectedArtifactFile}`,
      "AWS_READINESS_ARTIFACT_PATH"
    );

    const source = resolvedFile(
      projectRoot,
      expectedSourcePath,
      "AWS_READINESS_ARTIFACT_SOURCE"
    );
    const archive = resolvedFile(
      projectRoot,
      expectedArtifactPath,
      "AWS_READINESS_ARTIFACT_FILE"
    );
    const archiveBuffer = fs.readFileSync(archive.resolved);
    requireCondition(
      sha256File(source.resolved) === artifact.sourceDigest &&
        archive.stat.size === artifact.artifactBytes &&
        sha256(archiveBuffer) === artifact.artifactDigest &&
        sha256(archiveBuffer, "base64") ===
          artifact.artifactCodeSha256,
      "AWS_READINESS_ARTIFACT_DIGEST"
    );
    validateStoredSingleFileZip(archiveBuffer);
    acceptedArtifacts[name] = {
      sourceDigest: artifact.sourceDigest,
      artifactDigest: artifact.artifactDigest,
      artifactCodeSha256: artifact.artifactCodeSha256,
      artifactBytes: artifact.artifactBytes,
      artifactPath: expectedArtifactPath,
      suggestedS3Key: artifact.suggestedS3Key
    };
  }

  return {
    schemaVersion: receipt.schemaVersion,
    mode: receipt.mode,
    packageLockDigest: receipt.packageLockDigest,
    bootstrapTemplate: validateTemplateReceipt(
      projectRoot,
      receipt.bootstrapTemplate,
      "infra/aws/bootstrap-template.json",
      "AWS_READINESS_BOOTSTRAP_TEMPLATE"
    ),
    gate2Template: validateTemplateReceipt(
      projectRoot,
      receipt.gate2Template,
      "infra/aws/gate2-template.json",
      "AWS_READINESS_GATE2_TEMPLATE"
    ),
    artifacts: acceptedArtifacts
  };
}

export function validateAuditReport(report) {
  const vulnerabilities = report?.metadata?.vulnerabilities;
  const expectedKeys = [
    "critical",
    "high",
    "info",
    "low",
    "moderate",
    "total"
  ];
  requireCondition(
    vulnerabilities &&
      typeof vulnerabilities === "object" &&
      !Array.isArray(vulnerabilities) &&
      expectedKeys.every(
        (key) =>
          Number.isSafeInteger(vulnerabilities[key]) &&
          vulnerabilities[key] === 0
      ),
    "AWS_READINESS_AUDIT"
  );
  return {
    status: "PASS",
    knownVulnerabilities: 0
  };
}

export function validatePreflightReceipt(
  receipt,
  { sourceCommit, treeDigest }
) {
  const controls = receipt?.controls;
  const budget = controls?.budget;
  const currentCost = controls?.currentCost;
  const projectExposure = controls?.projectExposure;
  const artifactBucket = controls?.artifactBucket;
  const bedrock = controls?.bedrock;
  const notificationSet = Array.isArray(budget?.notifications)
    ? budget.notifications
        .map(
          (notification) =>
            `${notification?.metric}:${notification?.thresholdUsd}`
        )
        .sort()
        .join("\n")
    : "";
  requireCondition(
    exactKeys(receipt, [
      "claimBoundary",
      "controls",
      "observedAt",
      "privacy",
      "region",
      "schemaVersion",
      "sourceCommit",
      "status",
      "treeDigest"
    ]) &&
      exactKeys(controls, [
        "artifactBucket",
        "authenticatedAwsCaller",
        "bedrock",
        "bootstrapStack",
        "budget",
        "currentCost",
        "mainGateTwoStack",
        "projectExposure"
      ]) &&
      exactKeys(controls?.bootstrapStack, ["name", "status"]) &&
      exactKeys(budget, [
        "budgetReportedActualUsd",
        "conservativeObservedActualUsd",
        "costBasis",
        "coverageEnd",
        "coverageStart",
        "defaultCostTypes",
        "fixedLimit",
        "limitUsd",
        "name",
        "notifications",
        "scope",
        "timeUnit",
        "type"
      ]) &&
      exactKeys(currentCost, [
        "amountUsd",
        "estimated",
        "periodEndExclusive",
        "periodStart",
        "scope"
      ]) &&
      exactKeys(projectExposure, [
        "autoRenewReportedEnabled",
        "awsCostWindowStart",
        "ceilingUsd",
        "conservativeObservedTotalExposureUsd",
        "effectiveAwsSpendCeilingUsd",
        "recordedNonAwsSpendUsd",
        "recordedSpendBasis",
        "registrarReceiptVerified",
        "remainingExposureUsd",
        "scope"
      ]) &&
      exactKeys(artifactBucket, [
        "aes256AtRest",
        "bucketOwnerEnforced",
        "publicAccessBlocked",
        "tlsOnlyPolicy",
        "versioningEnabled"
      ]) &&
      exactKeys(controls?.mainGateTwoStack, ["name", "state"]) &&
      exactKeys(bedrock, [
        "catalogStatus",
        "modelId",
        "onDemandListed",
        "textInput",
        "textOutput"
      ]) &&
      receipt?.schemaVersion ===
      "tideproof.gate2.aws-preflight.v3" &&
      receipt.status === "PASS" &&
      receipt.sourceCommit === sourceCommit &&
      receipt.treeDigest === treeDigest &&
      receipt.region === EXPECTED_REGION &&
      Number.isFinite(Date.parse(receipt.observedAt)) &&
      typeof receipt.privacy === "string" &&
      receipt.privacy.length > 0 &&
      typeof receipt.claimBoundary === "string" &&
      receipt.claimBoundary.length > 0 &&
      controls?.authenticatedAwsCaller === true &&
      controls.bootstrapStack.name ===
        "tideproof-gate2-artifacts" &&
      ["CREATE_COMPLETE", "UPDATE_COMPLETE"].includes(
        controls.bootstrapStack.status
      ) &&
      controls?.mainGateTwoStack?.state === "ABSENT" &&
      controls?.bedrock?.catalogStatus === "ACTIVE" &&
      controls?.artifactBucket?.versioningEnabled === true &&
      controls?.artifactBucket?.aes256AtRest === true &&
      controls?.artifactBucket?.publicAccessBlocked === true &&
      controls?.artifactBucket?.bucketOwnerEnforced === true &&
      controls?.artifactBucket?.tlsOnlyPolicy === true &&
      Array.isArray(budget.notifications) &&
      budget.notifications.length === 4 &&
      notificationSet ===
        [
          "ACTUAL:1",
          "ACTUAL:5",
          "ACTUAL:10",
          "FORECASTED:15"
        ]
          .sort()
          .join("\n") &&
      budget.notifications.every((notification) =>
        exactKeys(notification, [
          "comparison",
          "emailRecipientCount",
          "metric",
          "thresholdType",
          "thresholdUsd"
        ]) &&
        notification.comparison === "GREATER_THAN" &&
        notification.thresholdType === "ABSOLUTE_VALUE" &&
        Number.isSafeInteger(notification.emailRecipientCount) &&
        notification.emailRecipientCount >= 1
      ) &&
      budget.name ===
        "tideproof-gate2-artifacts-account-safety" &&
      budget.scope === "ACCOUNT_WIDE" &&
      budget.type === "COST" &&
      budget.timeUnit === "MONTHLY" &&
      budget.costBasis === "UnblendedCost" &&
      budget.defaultCostTypes === true &&
      budget.fixedLimit === true &&
      Number(budget.limitUsd) === 15 &&
      currentCost.scope ===
        "ACCOUNT_WIDE_PROJECT_WINDOW_TO_DATE" &&
      Number.isFinite(Number(currentCost.amountUsd)) &&
      Number(currentCost.amountUsd) >= 0 &&
      Number(currentCost.amountUsd) < 13.14 &&
      projectExposure.scope ===
        "TIDEPROOF_TOTAL_APPROVED_EXPOSURE" &&
      Number(
        projectExposure.ceilingUsd
      ) === 25 &&
      Number(
        projectExposure.recordedNonAwsSpendUsd
      ) === 11.86 &&
      Number(
        projectExposure.effectiveAwsSpendCeilingUsd
      ) === 13.14 &&
      Number(
        projectExposure.conservativeObservedTotalExposureUsd
      ) < 25 &&
      projectExposure.registrarReceiptVerified === false &&
      projectExposure.autoRenewReportedEnabled === false &&
      controls.mainGateTwoStack.name === "tideproof-gate2" &&
      bedrock.modelId === "amazon.nova-micro-v1:0" &&
      bedrock.textInput === true &&
      bedrock.textOutput === true &&
      bedrock.onDemandListed === true,
    "AWS_READINESS_PREFLIGHT"
  );
  return receipt;
}

export function parseArguments(args) {
  if (args.length === 0) {
    return { localOnly: false };
  }
  if (args.length === 1 && args[0] === "--local-only") {
    return { localOnly: true };
  }
  throw new Error("AWS_READINESS_ARGUMENT");
}

function childEnvironment(
  sourceEnvironment,
  { awsAuthenticated = false } = {}
) {
  const environment = {};
  for (const [name, value] of Object.entries(sourceEnvironment)) {
    if (
      (name.startsWith("AWS_") && !awsAuthenticated) ||
      (!name.startsWith("AWS_") &&
        (SECRET_ENVIRONMENT_NAME.test(name) ||
          APPLICATION_ENVIRONMENT_NAME.test(name)))
    ) {
      continue;
    }
    environment[name] = value;
  }
  environment.AWS_EC2_METADATA_DISABLED = "true";
  environment.AWS_PAGER = "";
  environment.GIT_CONFIG_GLOBAL = "/dev/null";
  environment.GIT_CONFIG_NOSYSTEM = "1";
  environment.GIT_TERMINAL_PROMPT = "0";
  environment.npm_config_always_auth = "false";
  environment.npm_config_registry = "https://registry.npmjs.org/";
  environment.npm_config_update_notifier = "false";
  environment.npm_config_userconfig = "/dev/null";
  if (!awsAuthenticated) {
    environment.AWS_CONFIG_FILE = "/dev/null";
    environment.AWS_SHARED_CREDENTIALS_FILE = "/dev/null";
  }
  return environment;
}

function defaultRunner(projectRoot) {
  return (command, args, options) =>
    spawnSync(command, args, {
      cwd: projectRoot,
      encoding: "utf8",
      env: childEnvironment(process.env, options),
      maxBuffer: 32 * 1024 * 1024
    });
}

function checkedCommand(
  run,
  command,
  args,
  code,
  options = {}
) {
  const result = run(command, args, options);
  requireCondition(
    result &&
      !result.error &&
      result.status === 0 &&
      typeof result.stdout === "string",
    code
  );
  return result.stdout;
}

function textCommand(run, command, args, code) {
  return checkedCommand(run, command, args, code).trim();
}

function jsonCommand(
  run,
  command,
  args,
  code,
  options = {}
) {
  const output = checkedCommand(
    run,
    command,
    args,
    code,
    options
  );
  try {
    return JSON.parse(output);
  } catch {
    throw new Error(`${code}_JSON`);
  }
}

function fetchOfficialMain(run) {
  checkedCommand(
    run,
    "git",
    [
      "-c",
      "http.https://github.com/.extraheader=",
      "fetch",
      "--quiet",
      "--no-tags",
      "origin",
      "refs/heads/main:refs/remotes/origin/main"
    ],
    "AWS_READINESS_GIT_FETCH"
  );
}

function isOfficialRemote(value) {
  return (
    value === OFFICIAL_REMOTE ||
    value === OFFICIAL_REMOTE.slice(0, -4)
  );
}

function assertCheckout(run) {
  const remote = textCommand(
    run,
    "git",
    ["remote", "get-url", "origin"],
    "AWS_READINESS_GIT_REMOTE"
  );
  const branch = textCommand(
    run,
    "git",
    ["symbolic-ref", "--short", "HEAD"],
    "AWS_READINESS_GIT_BRANCH"
  );
  const status = textCommand(
    run,
    "git",
    ["status", "--short"],
    "AWS_READINESS_GIT_STATUS"
  );
  requireCondition(
    isOfficialRemote(remote) &&
      branch === EXPECTED_BRANCH &&
      status.length === 0,
    "AWS_READINESS_CHECKOUT"
  );
  fetchOfficialMain(run);
  const sourceCommit = textCommand(
    run,
    "git",
    ["rev-parse", "HEAD"],
    "AWS_READINESS_GIT_HEAD"
  );
  const originMain = textCommand(
    run,
    "git",
    ["rev-parse", "refs/remotes/origin/main"],
    "AWS_READINESS_GIT_ORIGIN_MAIN"
  );
  const treeDigest = textCommand(
    run,
    "git",
    ["rev-parse", "HEAD^{tree}"],
    "AWS_READINESS_GIT_TREE"
  );
  requireCondition(
    HEX_40.test(sourceCommit) &&
      HEX_40.test(originMain) &&
      HEX_40.test(treeDigest) &&
      sourceCommit === originMain,
    "AWS_READINESS_UPSTREAM"
  );
  return {
    sourceCommit,
    treeDigest,
    originMain
  };
}

function assertCheckoutUnchanged(run, initial) {
  fetchOfficialMain(run);
  const current = {
    sourceCommit: textCommand(
      run,
      "git",
      ["rev-parse", "HEAD"],
      "AWS_READINESS_FINAL_HEAD"
    ),
    originMain: textCommand(
      run,
      "git",
      ["rev-parse", "refs/remotes/origin/main"],
      "AWS_READINESS_FINAL_ORIGIN_MAIN"
    ),
    treeDigest: textCommand(
      run,
      "git",
      ["rev-parse", "HEAD^{tree}"],
      "AWS_READINESS_FINAL_TREE"
    ),
    status: textCommand(
      run,
      "git",
      ["status", "--short"],
      "AWS_READINESS_FINAL_STATUS"
    )
  };
  requireCondition(
    current.status.length === 0 &&
      current.sourceCommit === initial.sourceCommit &&
      current.originMain === initial.originMain &&
      current.treeDigest === initial.treeDigest,
    "AWS_READINESS_CHECKOUT_CHANGED"
  );
}

export async function runAwsReadiness({
  projectRoot = root,
  localOnly = false,
  now = () => new Date(),
  run = defaultRunner(projectRoot)
} = {}) {
  const checkout = assertCheckout(run);
  checkedCommand(
    run,
    "npm",
    [
      "ci",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund"
    ],
    "AWS_READINESS_NPM_CI"
  );
  checkedCommand(
    run,
    "npm",
    ["test"],
    "AWS_READINESS_TESTS"
  );
  const audit = validateAuditReport(
    jsonCommand(
      run,
      "npm",
      ["audit", "--json", "--audit-level=low"],
      "AWS_READINESS_NPM_AUDIT"
    )
  );
  const build = validateBuildReceipt(
    jsonCommand(
      run,
      "npm",
      ["run", "--silent", "build:gate2"],
      "AWS_READINESS_BUILD"
    ),
    {
      projectRoot,
      sourceCommit: checkout.sourceCommit,
      treeDigest: checkout.treeDigest
    }
  );
  const preflight = localOnly
    ? null
    : validatePreflightReceipt(
        jsonCommand(
          run,
          "npm",
          ["run", "--silent", "gate2:aws-preflight"],
          "AWS_READINESS_AWS_PREFLIGHT",
          { awsAuthenticated: true }
        ),
        checkout
      );
  assertCheckoutUnchanged(run, checkout);

  const observedAt = preflight?.observedAt ?? now().toISOString();
  requireCondition(
    Number.isFinite(Date.parse(observedAt)),
    "AWS_READINESS_OBSERVED_AT"
  );
  return {
    schemaVersion: "tideproof.gate2.aws-readiness.v1",
    status: localOnly ? "LOCAL_ONLY_PASS" : "PASS",
    mode: localOnly
      ? "LOCAL_VALIDATION_NO_AWS"
      : "READ_ONLY_AWS_RELEASE_GATE",
    observedAt,
    source: {
      commit: checkout.sourceCommit,
      tree: checkout.treeDigest,
      branch: EXPECTED_BRANCH,
      originMain: checkout.originMain,
      officialRemote: OFFICIAL_REMOTE
    },
    checks: {
      officialCheckout: true,
      cleanBeforeAndAfter: true,
      lockedInstall: true,
      dependencyLifecycleScripts: false,
      testsPassed: true,
      dependencyAudit: audit,
      exactHeadBuild: true,
      artifactSet: ARTIFACT_NAMES,
      artifactIntegrity: true,
      awsPreflight: preflight ? "PASS" : "NOT_RUN"
    },
    build,
    awsPreflight: preflight,
    claimBoundary: localOnly
      ? "Local-only validation passed. AWS was not queried or mutated, and this is not authorization to upload or deploy."
      : "The exact official checkout, local suite, dependency audit, reproducible artifacts, and read-only AWS preflight passed. No AWS resource was mutated; upload and deployment remain separate reviewed actions."
  };
}

async function main() {
  const { localOnly } = parseArguments(process.argv.slice(2));
  const receipt = await runAwsReadiness({ localOnly });
  process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
}

const invokedPath = process.argv[1]
  ? path.resolve(process.argv[1])
  : "";
if (invokedPath === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    const message = String(error?.message ?? "");
    const code = /^AWS_READINESS_[A-Z0-9_]{1,120}$/.test(message)
      ? message
      : "AWS_READINESS_UNKNOWN";
    process.stderr.write(
      `TIDEPROOF_GATE2_AWS_READINESS_FAILED:${code}\n`
    );
    process.exitCode = 1;
  });
}

export const __test = Object.freeze({
  ARTIFACT_NAMES,
  EXPECTED_BRANCH,
  EXPECTED_REGION,
  OFFICIAL_REMOTE,
  childEnvironment,
  isOfficialRemote,
  validateStoredSingleFileZip
});
