import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

import {
  canonicalProvenanceJson,
  generateControlPlaneProvenanceEvidence,
  validateControlPlaneProvenanceEvidence
} from "./control-plane-provenance.js";
import { validateBuildReceipt } from "../scripts/gate2-aws-readiness.js";
import {
  createControlPlaneExecutableManifest,
  readTrackedOperatorPublicKey
} from "../scripts/run-release-prepare-common.js";
import { PARAMETER_KEYS } from
  "../release-provider/src/release-provider-common.js";
import { publishOrReadExactOwnedFile } from
  "../src/cloud/atomic-create-only-file.js";

const SCHEMA = "prooftoact.hosted-dual-root-verification.v1";
const WORKFLOW = "ProofToAct Hosted Dual Root Verification";
const WORKFLOW_FILE = "prooftoact-hosted-dual-root-verification.yml";
const WORKFLOW_REF =
  `Flash-Bri/prooftoact/.github/workflows/${WORKFLOW_FILE}@refs/heads/main`;
const OFFICIAL_REPOSITORY = "Flash-Bri/prooftoact";
const OFFICIAL_REPOSITORY_ID = "1317716765";
const OFFICIAL_OWNER_ID = "252500266";
const FROZEN_APPLICATION = Object.freeze({
  commit: "963937a9873f0199b91897fe88da1b91bc84b5e3",
  tree: "a330e0d57328e63a568be73c523b2cae6338f26c"
});
const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const MAXIMUM_LOG_BYTES = 96 * 1024 * 1024;
const LOG_SEPARATOR = Buffer.from("\n---STDERR---\n", "utf8");

const SAFETY_TEST_FILES = Object.freeze([
  "test/authority-store.test.js",
  "test/database-commit-result.test.js",
  "test/integrated-live-drill-control-ledger.test.js",
  "test/integrated-live-drill-dispatch-broker.test.js",
  "test/integrated-live-drill-provider-execution-fence.test.js",
  "test/integrated-live-drill-provider-orchestration.test.js",
  "test/integrated-live-drill-provider-reconciliation.test.js",
  "test/integrated-live-drill-provider-recovery.test.js",
  "test/integrated-live-drill-recovery-continuity.test.js",
  "test/integrated-live-drill-stress.test.js",
  "test/provider-dispatch-activation-terminalization.test.js",
  "test/provider-dispatch-control.test.js",
  "test/provider-operation-broker.test.js",
  "test/recovery-bundle-persistence.test.js",
  "test/recovery-store.test.js",
  "test/release-control-dynamodb-store.test.js",
  "test/release-cost.test.js",
  "test/release-deployment-plan.test.js",
  "test/release-provider-controller.test.js",
  "test/release-provider-one-shot-broker.test.js"
]);

const SOURCE_SECURITY_TEST_FILES = Object.freeze([
  "test/aws-gate2-template-security.test.js",
  "test/database-security-bootstrap.test.js",
  "test/database-security-posture.test.js",
  "test/recovery-security.test.js",
  "test/release-security.test.js"
]);

const PRIVATE_PARAMETER_KEYS = Object.freeze([
  "ArtifactBucket",
  "AuthorityDatabaseHost",
  "AuthorityDatabasePort",
  "AuthorityDatabaseSecretArn",
  "AuthorityDatabaseSecretVersionId",
  "AuthorityIncidentId",
  "AuthorityResourceId",
  "AuthorityTenantId",
  "BedrockModelId",
  "ConfigDigest",
  "EvidenceOperatorPrincipalArn",
  ...PARAMETER_KEYS.filter((name) => name.endsWith("ArtifactVersion"))
].sort());

function invariant(condition, code) {
  if (!condition) throw new Error(code);
}

function plainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value, keys) {
  return plainObject(value) &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort());
}

export function canonicalHostedJson(value) {
  return canonicalProvenanceJson(value);
}

export function hostedSha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function canonicalDigest(value) {
  return hostedSha256(Buffer.from(canonicalHostedJson(value), "utf8"));
}

function exactOwnedDirectory(candidate, code, exactMode = null) {
  invariant(typeof candidate === "string" && path.isAbsolute(candidate), code);
  const resolved = path.resolve(candidate);
  const stat = fs.lstatSync(resolved);
  const expectedUid = typeof process.getuid === "function" ? process.getuid() :
    stat.uid;
  const mode = stat.mode & 0o777;
  invariant(fs.realpathSync(resolved) === resolved && stat.isDirectory() &&
    !stat.isSymbolicLink() && stat.uid === expectedUid &&
    (exactMode === null
      ? (mode & 0o700) === 0o700 && (mode & 0o022) === 0
      : mode === exactMode), code);
  return resolved;
}

function rootsAreSeparate(left, right) {
  const relation = path.relative(left, right);
  const reverse = path.relative(right, left);
  return relation !== "" && (relation === ".." ||
    relation.startsWith(`..${path.sep}`)) && (reverse === ".." ||
    reverse.startsWith(`..${path.sep}`));
}

function forbiddenCredentialName(name) {
  return name === "ACTIONS_ID_TOKEN_REQUEST_TOKEN" ||
    name === "ACTIONS_ID_TOKEN_REQUEST_URL" ||
    /^(?:AWS_(?:ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN|WEB_IDENTITY_TOKEN_FILE|PROFILE|DEFAULT_PROFILE|ROLE_ARN|ROLE_SESSION_NAME|CONTAINER_CREDENTIALS_FULL_URI|CONTAINER_CREDENTIALS_RELATIVE_URI)|GOOGLE_APPLICATION_CREDENTIALS)$/u
      .test(name) ||
    /^(?:PGHOST|PGHOSTADDR|PGPASSWORD|PGPASSFILE|PGSERVICE|PGSERVICEFILE|PGUSER)$/u
      .test(name) ||
    /(?:COCKROACH|CRDB|DATABASE_URL|OPENAI_API_KEY|OPENCLAW.*OAUTH)/iu
      .test(name) ||
    /^(?:GH_TOKEN|GITHUB_TOKEN|NODE_AUTH_TOKEN|NPM_TOKEN)$/u.test(name) ||
    /^PROOFTOACT_.+(?:APPROVAL|PRIVATE|SECRET|TOKEN|CREDENTIAL)/u
      .test(name);
}

export function validateHostedWorkflowContext(environment,
  platform = process.platform) {
  const code = "HOSTED_DUAL_ROOT_CONTEXT_REJECTED";
  invariant(plainObject(environment) || environment === process.env, code);
  invariant(platform === "linux" && environment.CI === "true" &&
    environment.GITHUB_ACTIONS === "true" &&
    environment.RUNNER_OS === "Linux" &&
    environment.RUNNER_ENVIRONMENT === "github-hosted" &&
    environment.GITHUB_EVENT_NAME === "workflow_dispatch" &&
    environment.GITHUB_REF === "refs/heads/main" &&
    environment.GITHUB_REF_NAME === "main" &&
    environment.GITHUB_REF_TYPE === "branch" &&
    environment.GITHUB_REPOSITORY === OFFICIAL_REPOSITORY &&
    environment.GITHUB_REPOSITORY_ID === OFFICIAL_REPOSITORY_ID &&
    environment.GITHUB_REPOSITORY_OWNER_ID === OFFICIAL_OWNER_ID &&
    environment.GITHUB_WORKFLOW === WORKFLOW &&
    environment.GITHUB_WORKFLOW_REF === WORKFLOW_REF &&
    environment.GITHUB_JOB === "verify-dual-root" &&
    HEX_40.test(environment.GITHUB_SHA ?? "") &&
    environment.GITHUB_WORKFLOW_SHA === environment.GITHUB_SHA &&
    environment.EXPECTED_OFFICIAL_MAIN_COMMIT === environment.GITHUB_SHA &&
    /^[1-9][0-9]{0,19}$/u.test(environment.GITHUB_RUN_ID ?? "") &&
    environment.GITHUB_RUN_ATTEMPT === "1" &&
    !Object.keys(environment).some((name) =>
      environment[name] !== undefined && environment[name] !== "" &&
      forbiddenCredentialName(name)), code);
  return Object.freeze({
    commit: environment.GITHUB_SHA,
    runAttempt: 1,
    runId: environment.GITHUB_RUN_ID,
    workflow: WORKFLOW,
    workflowRef: WORKFLOW_REF
  });
}

export function parseRequiredTap(bytes, code =
  "HOSTED_DUAL_ROOT_TAP_REJECTED") {
  invariant(Buffer.isBuffer(bytes) && bytes.length > 0, code);
  const text = bytes.toString("utf8");
  const count = (label) => {
    const matches = [...text.matchAll(new RegExp(
      `^# ${label} ([0-9]+)$`, "gmu"))];
    invariant(matches.length > 0, code);
    return Number(matches.at(-1)[1]);
  };
  const result = Object.freeze({
    cancelled: count("cancelled"),
    failed: count("fail"),
    passed: count("pass"),
    skipped: count("skipped"),
    tests: count("tests"),
    todo: count("todo")
  });
  invariant(result.tests > 0 && result.passed === result.tests &&
    result.failed === 0 && result.cancelled === 0 && result.skipped === 0 &&
    result.todo === 0, code);
  return result;
}

function assertNonsecretBytes(bytes, code) {
  invariant(Buffer.isBuffer(bytes) && bytes.length > 0 &&
    bytes.length <= MAXIMUM_LOG_BYTES, code);
  const text = bytes.toString("utf8");
  invariant(!/-----BEGIN (?:EC |RSA |OPENSSH )?PRIVATE KEY-----/u.test(text) &&
    !/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/u.test(text) &&
    !/\bgh[pousr]_[A-Za-z0-9]{20,}\b/u.test(text) &&
    !/\bsk-[A-Za-z0-9_-]{20,}\b/u.test(text) &&
    !/postgres(?:ql)?:\/\/[^\s:@/]+:[^\s@/]+@/iu.test(text), code);
  return bytes;
}

function childEnvironment(temporaryRoot, npmCli) {
  const globalConfig = path.join(temporaryRoot, "npm-global-config");
  const userConfig = path.join(temporaryRoot, "npm-user-config");
  for (const filePath of [globalConfig, userConfig]) {
    fs.writeFileSync(filePath, Buffer.alloc(0), { flag: "wx", mode: 0o600 });
  }
  return Object.freeze({
    AWS_CONFIG_FILE: "/dev/null",
    AWS_EC2_METADATA_DISABLED: "true",
    AWS_SHARED_CREDENTIALS_FILE: "/dev/null",
    GIT_ATTR_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_NO_LAZY_FETCH: "1",
    GIT_NO_REPLACE_OBJECTS: "1",
    GIT_TERMINAL_PROMPT: "0",
    LANG: "C",
    LC_ALL: "C",
    NO_COLOR: "1",
    PATH: `${path.dirname(fs.realpathSync(process.execPath))}:/usr/bin:/bin`,
    TEMP: temporaryRoot,
    TMP: temporaryRoot,
    TMPDIR: temporaryRoot,
    npm_config_audit: "false",
    npm_config_cache: path.join(temporaryRoot, "npm-cache"),
    npm_config_fund: "false",
    npm_config_globalconfig: globalConfig,
    npm_config_ignore_scripts: "true",
    npm_config_registry: "https://registry.npmjs.org/",
    npm_config_update_notifier: "false",
    npm_config_userconfig: userConfig,
    npm_execpath: npmCli,
    npm_node_execpath: process.execPath
  });
}

function checkedSpawn(executable, args, { code, cwd, env }) {
  const result = spawnSync(executable, args, {
    cwd,
    encoding: null,
    env,
    maxBuffer: MAXIMUM_LOG_BYTES,
    stdio: ["ignore", "pipe", "pipe"]
  });
  invariant(result && !result.error && result.status === 0 &&
    Buffer.isBuffer(result.stdout) && Buffer.isBuffer(result.stderr), code);
  return Object.freeze({
    argumentsSha256: canonicalDigest(args),
    executableSha256: hostedSha256(fs.readFileSync(
      fs.realpathSync(executable))),
    stderr: result.stderr,
    stdout: result.stdout
  });
}

function assertPublicationRoot(root) {
  return exactOwnedDirectory(root,
    "HOSTED_DUAL_ROOT_PUBLICATION_ROOT_REJECTED", 0o700);
}

function ensurePublicationDirectory(root, relativeDirectory) {
  const target = path.join(root, relativeDirectory);
  if (!fs.existsSync(target)) fs.mkdirSync(target, { mode: 0o700 });
  return exactOwnedDirectory(target,
    "HOSTED_DUAL_ROOT_PUBLICATION_ROOT_REJECTED", 0o700);
}

function publishFile(outputRoot, relativePath, bytes) {
  const code = "HOSTED_DUAL_ROOT_PUBLICATION_REJECTED";
  invariant(typeof relativePath === "string" && relativePath.length > 0 &&
    !path.isAbsolute(relativePath) &&
    !relativePath.split("/").includes(".."), code);
  assertNonsecretBytes(bytes, code);
  const parentRelative = path.posix.dirname(relativePath);
  const parent = parentRelative === "." ? outputRoot :
    ensurePublicationDirectory(outputRoot, parentRelative);
  const filePath = path.join(outputRoot, relativePath);
  invariant(path.dirname(filePath) === parent, code);
  publishOrReadExactOwnedFile({
    assertRoot: () => exactOwnedDirectory(parent,
      "HOSTED_DUAL_ROOT_PUBLICATION_ROOT_REJECTED", 0o700),
    bytes,
    code,
    filePath,
    maximumBytes: MAXIMUM_LOG_BYTES,
    mode: 0o600,
    rootPath: parent
  });
  return Object.freeze({
    bytes: bytes.length,
    path: relativePath,
    sha256: hostedSha256(bytes)
  });
}

function combinedLog(result) {
  return Buffer.concat([result.stdout, LOG_SEPARATOR, result.stderr]);
}

function splitCombinedLog(bytes, code) {
  invariant(Buffer.isBuffer(bytes), code);
  const separator = bytes.indexOf(LOG_SEPARATOR);
  invariant(separator > 0 && separator === bytes.lastIndexOf(LOG_SEPARATOR),
    code);
  return Object.freeze({
    stderr: bytes.subarray(separator + LOG_SEPARATOR.length),
    stdout: bytes.subarray(0, separator)
  });
}

function fileDescriptorMatches(descriptor, relativePath, bytes) {
  return exactKeys(descriptor, ["bytes", "path", "sha256"]) &&
    descriptor.path === relativePath && descriptor.bytes === bytes.length &&
    descriptor.sha256 === hostedSha256(bytes);
}

function runAndPublish({ args, code, cwd, env, executable = process.execPath,
  outputRoot, relativePath, tap = false }) {
  const result = checkedSpawn(executable, args, { code, cwd, env });
  const log = publishFile(outputRoot, relativePath, combinedLog(result));
  return Object.freeze({
    argumentsSha256: result.argumentsSha256,
    executableSha256: result.executableSha256,
    log,
    status: "PASS",
    ...(tap ? { summary: parseRequiredTap(result.stdout, code) } : {})
  });
}

function materializeProvenanceLogs(provenance, outputRoot) {
  const result = {};
  for (const kind of ["installations", "tests", "audits"]) {
    result[kind] = provenance.body.executions[kind].map((record) => {
      const stdout = Buffer.from(record.stdoutBase64, "base64");
      const stderr = Buffer.from(record.stderrBase64, "base64");
      invariant(stdout.toString("base64") === record.stdoutBase64 &&
        stderr.toString("base64") === record.stderrBase64,
      "HOSTED_DUAL_ROOT_PROVENANCE_LOG_REJECTED");
      const bytes = Buffer.concat([stdout, LOG_SEPARATOR, stderr]);
      invariant(hostedSha256(bytes) === record.outputSha256,
        "HOSTED_DUAL_ROOT_PROVENANCE_LOG_REJECTED");
      const log = publishFile(outputRoot,
        `logs/provenance-${kind}-${record.command}.log`, bytes);
      if (kind === "tests") parseRequiredTap(stdout,
        "HOSTED_DUAL_ROOT_REQUIRED_TEST_SKIPPED");
      return Object.freeze({
        command: record.command,
        log,
        semantic: record.semantic,
        status: "PASS"
      });
    });
  }
  return Object.freeze(result);
}

function templateParameterContract(applicationRoot, receipt) {
  const code = "HOSTED_DUAL_ROOT_PARAMETER_CONTRACT_REJECTED";
  const templatePath = path.join(applicationRoot,
    receipt.gate2Template.path);
  let template;
  try {
    template = JSON.parse(fs.readFileSync(templatePath, "utf8"));
  } catch (cause) {
    throw new Error(code, { cause });
  }
  const names = Object.keys(template.Parameters ?? {}).sort();
  invariant(canonicalHostedJson(names) ===
    canonicalHostedJson([...PARAMETER_KEYS].sort()), code);
  const schema = PARAMETER_KEYS.map((name) => Object.freeze({
    name,
    schema: template.Parameters[name]
  }));
  const artifactInputs = [...receipt.artifacts]
    .sort((left, right) => left.name.localeCompare(right.name))
    .map((artifact) => Object.freeze({
      artifactCodeSha256: artifact.artifactCodeSha256,
      artifactDigest: artifact.artifactDigest,
      artifactPath: artifact.artifactPath,
      name: artifact.name,
      sourceDigest: artifact.sourceDigest,
      suggestedS3Key: artifact.suggestedS3Key
    }));
  const buildDerived = Object.freeze({
    artifactInputs,
    enableProbeFunctions: "false",
    packageLockDigest: receipt.packageLockDigest,
    sourceCommit: receipt.sourceCommit,
    treeDigest: receipt.treeDigest
  });
  return Object.freeze({
    buildDerivedParameterInputsSha256: canonicalDigest(buildDerived),
    keyCount: names.length,
    liveParameterValuesObserved: false,
    parameterSchemaSha256: canonicalDigest(schema),
    privateOrProviderResolvedKeys: PRIVATE_PARAMETER_KEYS,
    status: "SOURCE_CONTRACT_ONLY_NO_PROVIDER_CONFIGURATION"
  });
}

function summarizeApplicationBuild(receipt, bytes, applicationRoot) {
  const code = "HOSTED_DUAL_ROOT_APPLICATION_BUILD_REJECTED";
  const accepted = validateBuildReceipt(receipt, {
    projectRoot: applicationRoot,
    sourceCommit: FROZEN_APPLICATION.commit,
    treeDigest: FROZEN_APPLICATION.tree
  });
  invariant(bytes.equals(Buffer.from(`${JSON.stringify(receipt, null, 2)}\n`,
    "utf8")), code);
  const outputs = accepted.outputPrivacy.outputs.map((item) =>
    Object.freeze({ ...item }));
  invariant(outputs.length > 0 && outputs.every((item) =>
    HEX_64.test(item.sha256 ?? "")), code);
  return Object.freeze({
    buildReceiptSha256: hostedSha256(bytes),
    deployOutputInventorySha256: canonicalDigest(outputs),
    outputs,
    parameterContract: templateParameterContract(applicationRoot, receipt),
    templates: Object.freeze({
      bootstrap: accepted.bootstrapTemplate,
      gate2: accepted.gate2Template
    })
  });
}

function parseExactJsonBytes(bytes, suffix, code) {
  let value;
  try { value = JSON.parse(bytes.toString("utf8")); } catch (cause) {
    throw new Error(code, { cause });
  }
  invariant(Buffer.from(`${suffix(value)}\n`, "utf8").equals(bytes), code);
  return value;
}

function runtimeBuildSummary({ controlReceipt, executable,
  executableBytes, providerReceipt }) {
  return Object.freeze({
    buildSha256: executable.buildSha256,
    controlRuntimeProvenanceSha256: controlReceipt.provenanceSha256,
    controlRuntimeSha256: controlReceipt.sha256,
    executableManifestSha256: hostedSha256(executableBytes),
    identitySha256: executable.identitySha256,
    providerRuntimeProvenanceSha256: providerReceipt.provenanceSha256,
    providerRuntimeSetSha256: providerReceipt.runtimeSetSha256
  });
}

async function buildApplicationTwice({ applicationRoot, env, outputRoot,
  npmCli, runner = checkedSpawn }) {
  const summaries = [];
  for (let attempt = 1; attempt <= 2; attempt += 1) {
    const result = runner(process.execPath,
      [npmCli, "--silent", "run", "build:gate2"], {
        code: "HOSTED_DUAL_ROOT_APPLICATION_BUILD_FAILED",
        cwd: applicationRoot,
        env
      });
    let receipt;
    try {
      receipt = JSON.parse(result.stdout.toString("utf8"));
    } catch (cause) {
      throw new Error("HOSTED_DUAL_ROOT_APPLICATION_BUILD_JSON_REJECTED",
        { cause });
    }
    const log = publishFile(outputRoot,
      `builds/application-build-${attempt}.log`, combinedLog(result));
    summaries.push(Object.freeze({
      log,
      summary: summarizeApplicationBuild(receipt, result.stdout,
        applicationRoot)
    }));
  }
  invariant(canonicalHostedJson(summaries[0].summary) ===
    canonicalHostedJson(summaries[1].summary),
  "HOSTED_DUAL_ROOT_APPLICATION_BUILD_NOT_REPRODUCIBLE");
  return Object.freeze({
    attempts: summaries,
    reproducible: true,
    summary: summaries[0].summary
  });
}

async function buildExecutablesTwice({ controlIdentity, controlRoot,
  outputRoot, temporaryRoot }) {
  const [{ buildReleaseControlRuntime },
    { buildReleaseProviderRuntimes }] = await Promise.all([
    import("../release-control/build-release-control-runtime.js"),
    import("../release-provider/build-release-provider-runtimes.js")
  ]);
  const operatorPublicKey = readTrackedOperatorPublicKey(controlRoot);
  const attempts = [];
  for (let attempt = 1; attempt <= 2; attempt += 1) {
    const attemptRoot = path.join(temporaryRoot, `executable-${attempt}`);
    fs.mkdirSync(attemptRoot, { mode: 0o700 });
    const controlReceipt = await buildReleaseControlRuntime({
      controlPlaneCommit: controlIdentity.commit,
      controlPlaneTree: controlIdentity.tree,
      outputRoot: path.join(attemptRoot, "release-control"),
      projectRoot: path.join(controlRoot, "release-control")
    });
    const providerReceipt = await buildReleaseProviderRuntimes({
      controlPlaneCommit: controlIdentity.commit,
      controlPlaneTree: controlIdentity.tree,
      outputRoot: path.join(attemptRoot, "release-provider"),
      projectRoot: path.join(controlRoot, "release-provider")
    });
    const executable = createControlPlaneExecutableManifest({
      controlPlane: controlIdentity,
      controlReceipt,
      controlRoot,
      operatorPublicKey,
      providerReceipt
    });
    const controlBytes = Buffer.from(`${JSON.stringify(controlReceipt)}\n`,
      "utf8");
    const providerBytes = Buffer.from(`${JSON.stringify(providerReceipt)}\n`,
      "utf8");
    const executableBytes = Buffer.from(
      `${canonicalHostedJson(executable)}\n`, "utf8");
    const files = Object.freeze({
      control: publishFile(outputRoot,
        `builds/release-control-${attempt}.json`, controlBytes),
      executable: publishFile(outputRoot,
        `builds/executable-manifest-${attempt}.json`, executableBytes),
      provider: publishFile(outputRoot,
        `builds/release-provider-${attempt}.json`, providerBytes)
    });
    attempts.push(Object.freeze({
      files,
      summary: runtimeBuildSummary({ controlReceipt, executable,
        executableBytes, providerReceipt })
    }));
  }
  invariant(canonicalHostedJson(attempts[0].summary) ===
    canonicalHostedJson(attempts[1].summary),
  "HOSTED_DUAL_ROOT_EXECUTABLE_BUILD_NOT_REPRODUCIBLE");
  return Object.freeze({
    attempts,
    reproducible: true,
    summary: attempts[0].summary
  });
}

function parseSecurityReceipt(bytes) {
  let receipt;
  try {
    receipt = JSON.parse(bytes.toString("utf8"));
  } catch (cause) {
    throw new Error("HOSTED_DUAL_ROOT_SECURITY_RECEIPT_REJECTED", { cause });
  }
  invariant(receipt?.status === "CURRENT_SOURCE_SECURITY_PASS" &&
    receipt.finalReleaseReady === false &&
    HEX_64.test(receipt.manifestSha256 ?? ""),
  "HOSTED_DUAL_ROOT_SECURITY_RECEIPT_REJECTED");
  return Object.freeze({
    finalReleaseReady: false,
    manifestSha256: receipt.manifestSha256,
    status: receipt.status
  });
}

function parseProcessBoundaryReceipts(bytes) {
  const lines = bytes.toString("utf8").trim().split("\n");
  invariant(lines.length === 2,
    "HOSTED_DUAL_ROOT_PROCESS_BOUNDARY_REJECTED");
  let receipts;
  try { receipts = lines.map((line) => JSON.parse(line)); } catch (cause) {
    throw new Error("HOSTED_DUAL_ROOT_PROCESS_BOUNDARY_REJECTED", { cause });
  }
  invariant(receipts.every((receipt) => receipt?.status === "PASS"),
    "HOSTED_DUAL_ROOT_PROCESS_BOUNDARY_REJECTED");
  return Object.freeze(receipts.map((receipt) => Object.freeze({
    schemaVersion: receipt.schemaVersion,
    status: receipt.status
  })));
}

function runRequiredSuites({ controlRoot, env, npmCli, outputRoot,
  runner = checkedSpawn }) {
  const safety = runAndPublish({
    args: ["--test", ...SAFETY_TEST_FILES],
    code: "HOSTED_DUAL_ROOT_SAFETY_TEST_FAILED",
    cwd: controlRoot,
    env,
    outputRoot,
    relativePath: "logs/safety.tap",
    tap: true
  });
  const sourceSecurityTests = runAndPublish({
    args: ["--test", ...SOURCE_SECURITY_TEST_FILES],
    code: "HOSTED_DUAL_ROOT_SOURCE_SECURITY_TEST_FAILED",
    cwd: controlRoot,
    env,
    outputRoot,
    relativePath: "logs/source-security-tests.tap",
    tap: true
  });
  const securityResult = checkedSpawn(process.execPath,
    ["scripts/verify-release-security.js"], {
      code: "HOSTED_DUAL_ROOT_SOURCE_SECURITY_VERIFIER_FAILED",
      cwd: controlRoot,
      env
    });
  const sourceSecurityVerifier = Object.freeze({
    argumentsSha256: securityResult.argumentsSha256,
    executableSha256: securityResult.executableSha256,
    log: publishFile(outputRoot, "logs/source-security-verifier.json",
      combinedLog(securityResult)),
    receipt: parseSecurityReceipt(securityResult.stdout),
    status: "PASS"
  });
  const processResult = checkedSpawn(process.execPath,
    [npmCli, "--silent", "run", "process-boundaries:verify"], {
      code: "HOSTED_DUAL_ROOT_PROCESS_BOUNDARY_FAILED",
      cwd: controlRoot,
      env
    });
  const processBoundaries = Object.freeze({
    argumentsSha256: processResult.argumentsSha256,
    executableSha256: processResult.executableSha256,
    log: publishFile(outputRoot, "logs/process-boundaries.log",
      combinedLog(processResult)),
    receipts: parseProcessBoundaryReceipts(processResult.stdout),
    status: "PASS"
  });
  const sudo = "/usr/bin/sudo";
  const exactNode = fs.realpathSync(process.execPath);
  const sudoArgs = ["--non-interactive", "/usr/bin/env", "-i",
    `PATH=${path.dirname(exactNode)}:/usr/bin:/bin`, "LANG=C", "LC_ALL=C",
    exactNode, "--test", "test/root/integrated-live-drill-stage-root.test.js"];
  const privileged = runAndPublish({
    args: sudoArgs,
    code: "HOSTED_DUAL_ROOT_PRIVILEGED_STAGE_FAILED",
    cwd: controlRoot,
    env,
    executable: sudo,
    outputRoot,
    relativePath: "logs/privileged-root-stage.tap",
    tap: true
  });
  return Object.freeze({
    processBoundaries,
    privileged,
    safety,
    sourceSecurityTests,
    sourceSecurityVerifier
  });
}

function readArtifactFile(root, relativePath, code) {
  invariant(typeof relativePath === "string" && relativePath.length > 0 &&
    !path.isAbsolute(relativePath) &&
    !relativePath.split("/").includes(".."), code);
  const filePath = path.join(root, relativePath);
  const stat = fs.lstatSync(filePath);
  const expectedUid = typeof process.getuid === "function" ? process.getuid() :
    stat.uid;
  invariant(fs.realpathSync(filePath) === filePath && stat.isFile() &&
    !stat.isSymbolicLink() && stat.nlink === 1 && stat.uid === expectedUid &&
    (stat.mode & 0o777) === 0o600 && stat.size > 0 &&
    stat.size <= MAXIMUM_LOG_BYTES, code);
  return Object.freeze({ bytes: fs.readFileSync(filePath), stat });
}

function inventoryArtifactFiles(outputRoot) {
  const paths = [];
  const pending = [""];
  while (pending.length > 0) {
    const relativeDirectory = pending.pop();
    const directory = path.join(outputRoot, relativeDirectory);
    for (const name of fs.readdirSync(directory).sort().reverse()) {
      const relative = relativeDirectory.length === 0 ? name :
        `${relativeDirectory}/${name}`;
      if (relative === "manifest.json") continue;
      const target = path.join(outputRoot, relative);
      const stat = fs.lstatSync(target);
      invariant(!stat.isSymbolicLink(),
        "HOSTED_DUAL_ROOT_ARTIFACT_INVENTORY_REJECTED");
      if (stat.isDirectory()) {
        invariant((stat.mode & 0o777) === 0o700,
          "HOSTED_DUAL_ROOT_ARTIFACT_INVENTORY_REJECTED");
        pending.push(relative);
      } else {
        invariant(stat.isFile(),
          "HOSTED_DUAL_ROOT_ARTIFACT_INVENTORY_REJECTED");
        paths.push(relative);
      }
    }
  }
  return paths.sort().map((relativePath) => {
    const opened = readArtifactFile(outputRoot, relativePath,
      "HOSTED_DUAL_ROOT_ARTIFACT_INVENTORY_REJECTED");
    assertNonsecretBytes(opened.bytes,
      "HOSTED_DUAL_ROOT_ARTIFACT_INVENTORY_REJECTED");
    return Object.freeze({
      bytes: opened.bytes.length,
      path: relativePath,
      sha256: hostedSha256(opened.bytes)
    });
  });
}

function semanticProvenanceTests(provenance) {
  const names = ["control-plane-root", "release-control", "release-provider",
    "frozen-application"];
  invariant(canonicalHostedJson(provenance.body.executions.tests.map(
    ({ command }) => command)) === canonicalHostedJson(names) &&
    provenance.body.executions.tests.every(({ semantic }) =>
      semantic.failed === 0 && semantic.cancelled === 0 &&
      semantic.skipped === 0 && semantic.todo === 0 && semantic.tests > 0 &&
      semantic.passed === semantic.tests),
  "HOSTED_DUAL_ROOT_REQUIRED_TEST_SKIPPED");
  return Object.freeze(provenance.body.executions.tests.map((record) =>
    Object.freeze({ command: record.command, ...record.semantic })));
}

export async function generateHostedDualRootVerification({
  applicationRoot,
  controlRoot,
  environment = process.env,
  npmCli,
  outputRoot
}) {
  const context = validateHostedWorkflowContext(environment);
  const control = exactOwnedDirectory(controlRoot,
    "HOSTED_DUAL_ROOT_CONTROL_ROOT_REJECTED");
  const application = exactOwnedDirectory(applicationRoot,
    "HOSTED_DUAL_ROOT_APPLICATION_ROOT_REJECTED");
  const output = assertPublicationRoot(outputRoot);
  invariant(rootsAreSeparate(control, application) &&
    rootsAreSeparate(control, output) && rootsAreSeparate(application, output) &&
    fs.readdirSync(output).length === 0,
  "HOSTED_DUAL_ROOT_ROOT_SEPARATION_REJECTED");
  invariant(typeof npmCli === "string" && path.isAbsolute(npmCli),
    "HOSTED_DUAL_ROOT_NPM_CLI_REJECTED");

  const provenance = generateControlPlaneProvenanceEvidence({
    controlPlaneRoot: control,
    frozenApplicationRoot: application,
    npmCli
  });
  validateControlPlaneProvenanceEvidence(provenance);
  invariant(provenance.body.git.controlPlane.commit === context.commit &&
    provenance.body.git.frozenApplication.commit === FROZEN_APPLICATION.commit &&
    provenance.body.git.frozenApplication.tree === FROZEN_APPLICATION.tree,
  "HOSTED_DUAL_ROOT_PROVENANCE_IDENTITY_REJECTED");
  const baseTests = semanticProvenanceTests(provenance);
  const provenanceFile = publishFile(output,
    "control-plane-provenance.json",
    Buffer.from(`${canonicalHostedJson(provenance)}\n`, "utf8"));
  const provenanceLogs = materializeProvenanceLogs(provenance, output);

  const temporaryRoot = fs.mkdtempSync(
    path.join(output, ".hosted-dual-root-temporary-"));
  fs.chmodSync(temporaryRoot, 0o700);
  try {
    const env = childEnvironment(temporaryRoot, npmCli);
    const applicationBuild = await buildApplicationTwice({
      applicationRoot: application,
      env,
      npmCli,
      outputRoot: output
    });
    const executableBuild = await buildExecutablesTwice({
      controlIdentity: {
        commit: provenance.body.git.controlPlane.commit,
        tree: provenance.body.git.controlPlane.tree
      },
      controlRoot: control,
      outputRoot: output,
      temporaryRoot
    });
    const requiredSuites = runRequiredSuites({
      controlRoot: control,
      env,
      npmCli,
      outputRoot: output
    });
    fs.rmSync(temporaryRoot, { force: true, recursive: true });
    const files = inventoryArtifactFiles(output);
    const body = Object.freeze({
      schemaVersion: SCHEMA,
      applicationBuild,
      artifactPublication: Object.freeze({
        artifactUploadObserved: false,
        requestedRetentionDays: 90,
        status: "LOCAL_ARTIFACT_SET_COMPLETE_UPLOAD_NEXT"
      }),
      claimBoundary: Object.freeze({
        applicationDeploymentObserved: false,
        cockroachDbAccessPerformed: false,
        liveParameterValuesObserved: false,
        oidcRequested: false,
        privilegedRootStageObserved: true,
        providerActionsPerformed: false,
        providerCredentialsPresent: false,
        providerExecutionAuthorized: false,
        sourceAndHostedExecutionEvidenceOnly: true
      }),
      decision: Object.freeze({
        nextGate: "INDEPENDENT_REVIEW_THEN_SEPARATE_GOVERNED_PROVIDER_AUTHORITY",
        providerExecutionAuthorized: false,
        status: "HOSTED_DUAL_ROOT_SOURCE_VERIFIED"
      }),
      executableBuild,
      files,
      provenance: Object.freeze({
        bodySha256: provenance.bodySha256,
        file: provenanceFile,
        logs: provenanceLogs
      }),
      roots: provenance.body.git,
      tests: Object.freeze({
        base: baseTests,
        requiredSuites
      }),
      toolchain: provenance.body.executions.toolchain,
      workflow: context
    });
    const manifest = Object.freeze({
      ...body,
      manifestSha256: canonicalDigest(body)
    });
    publishFile(output, "manifest.json",
      Buffer.from(`${canonicalHostedJson(manifest)}\n`, "utf8"));
    return manifest;
  } catch (cause) {
    try { fs.rmSync(temporaryRoot, { force: true, recursive: true }); } catch {}
    throw cause;
  }
}

function requiredArtifactPaths() {
  const provenanceLogs = ["installations", "tests", "audits"].flatMap((kind) =>
    ["control-plane-root", "release-control", "release-provider",
      "frozen-application"].map((name) =>
      `logs/provenance-${kind}-${name}.log`));
  return Object.freeze([
    "builds/application-build-1.log",
    "builds/application-build-2.log",
    "builds/executable-manifest-1.json",
    "builds/executable-manifest-2.json",
    "builds/release-control-1.json",
    "builds/release-control-2.json",
    "builds/release-provider-1.json",
    "builds/release-provider-2.json",
    "control-plane-provenance.json",
    "logs/privileged-root-stage.tap",
    "logs/process-boundaries.log",
    "logs/safety.tap",
    "logs/source-security-tests.tap",
    "logs/source-security-verifier.json",
    ...provenanceLogs
  ].sort());
}

function requireExactArtifactPaths(paths, code =
  "HOSTED_DUAL_ROOT_ARTIFACT_SET_REJECTED") {
  invariant(Array.isArray(paths) && paths.every((item) =>
    typeof item === "string") && new Set(paths).size === paths.length &&
    canonicalHostedJson([...paths].sort()) ===
      canonicalHostedJson(requiredArtifactPaths()), code);
  return true;
}

function reopenApplicationBuildEvidence({ applicationRoot, manifest,
  outputRoot }) {
  const code = "HOSTED_DUAL_ROOT_APPLICATION_BUILD_EVIDENCE_REJECTED";
  const build = manifest.applicationBuild;
  invariant(exactKeys(build, ["attempts", "reproducible", "summary"]) &&
    build.reproducible === true && Array.isArray(build.attempts) &&
    build.attempts.length === 2, code);
  const summaries = build.attempts.map((attempt, index) => {
    invariant(exactKeys(attempt, ["log", "summary"]), code);
    const relativePath = `builds/application-build-${index + 1}.log`;
    const opened = readArtifactFile(outputRoot, relativePath, code);
    invariant(fileDescriptorMatches(attempt.log, relativePath, opened.bytes),
      code);
    const { stdout } = splitCombinedLog(opened.bytes, code);
    const receipt = parseExactJsonBytes(stdout,
      (value) => JSON.stringify(value, null, 2), code);
    const summary = summarizeApplicationBuild(receipt, stdout,
      applicationRoot);
    invariant(canonicalHostedJson(summary) ===
      canonicalHostedJson(attempt.summary), code);
    return summary;
  });
  invariant(canonicalHostedJson(summaries[0]) ===
    canonicalHostedJson(summaries[1]) && canonicalHostedJson(summaries[0]) ===
    canonicalHostedJson(build.summary), code);
  return summaries[0];
}

function reopenExecutableBuildEvidence({ controlRoot, manifest, outputRoot }) {
  const code = "HOSTED_DUAL_ROOT_EXECUTABLE_BUILD_EVIDENCE_REJECTED";
  const build = manifest.executableBuild;
  invariant(exactKeys(build, ["attempts", "reproducible", "summary"]) &&
    build.reproducible === true && Array.isArray(build.attempts) &&
    build.attempts.length === 2, code);
  const controlPlane = Object.freeze({
    commit: manifest.roots.controlPlane.commit,
    tree: manifest.roots.controlPlane.tree
  });
  const operatorPublicKey = readTrackedOperatorPublicKey(controlRoot);
  const summaries = build.attempts.map((attempt, index) => {
    invariant(exactKeys(attempt, ["files", "summary"]) &&
      exactKeys(attempt.files, ["control", "executable", "provider"]), code);
    const number = index + 1;
    const paths = Object.freeze({
      control: `builds/release-control-${number}.json`,
      executable: `builds/executable-manifest-${number}.json`,
      provider: `builds/release-provider-${number}.json`
    });
    const opened = Object.fromEntries(Object.entries(paths).map(
      ([name, relativePath]) => [name,
        readArtifactFile(outputRoot, relativePath, code)]));
    for (const [name, relativePath] of Object.entries(paths)) {
      invariant(fileDescriptorMatches(attempt.files[name], relativePath,
        opened[name].bytes), code);
    }
    const controlReceipt = parseExactJsonBytes(opened.control.bytes,
      JSON.stringify, code);
    const providerReceipt = parseExactJsonBytes(opened.provider.bytes,
      JSON.stringify, code);
    const executable = createControlPlaneExecutableManifest({
      controlPlane,
      controlReceipt,
      controlRoot,
      operatorPublicKey,
      providerReceipt
    });
    const expectedExecutableBytes = Buffer.from(
      `${canonicalHostedJson(executable)}\n`, "utf8");
    invariant(expectedExecutableBytes.equals(opened.executable.bytes), code);
    const publishedExecutable = parseExactJsonBytes(opened.executable.bytes,
      canonicalHostedJson, code);
    invariant(canonicalHostedJson(publishedExecutable) ===
      canonicalHostedJson(executable), code);
    const summary = runtimeBuildSummary({ controlReceipt, executable,
      executableBytes: expectedExecutableBytes, providerReceipt });
    invariant(canonicalHostedJson(summary) ===
      canonicalHostedJson(attempt.summary), code);
    return summary;
  });
  invariant(canonicalHostedJson(summaries[0]) ===
    canonicalHostedJson(summaries[1]) && canonicalHostedJson(summaries[0]) ===
    canonicalHostedJson(build.summary), code);
  return summaries[0];
}

export function verifyHostedDualRootArtifact({
  applicationRoot,
  controlRoot,
  environment = process.env,
  outputRoot,
  requireHostedContext = true
}) {
  const context = requireHostedContext
    ? validateHostedWorkflowContext(environment) : null;
  const control = exactOwnedDirectory(controlRoot,
    "HOSTED_DUAL_ROOT_CONTROL_ROOT_REJECTED");
  const application = exactOwnedDirectory(applicationRoot,
    "HOSTED_DUAL_ROOT_APPLICATION_ROOT_REJECTED");
  const output = assertPublicationRoot(outputRoot);
  invariant(rootsAreSeparate(control, application) &&
    rootsAreSeparate(control, output) && rootsAreSeparate(application, output),
  "HOSTED_DUAL_ROOT_ROOT_SEPARATION_REJECTED");
  const manifestFile = readArtifactFile(output, "manifest.json",
    "HOSTED_DUAL_ROOT_MANIFEST_REJECTED");
  let manifest;
  try { manifest = JSON.parse(manifestFile.bytes.toString("utf8")); } catch (cause) {
    throw new Error("HOSTED_DUAL_ROOT_MANIFEST_REJECTED", { cause });
  }
  invariant(exactKeys(manifest, [
    "applicationBuild", "artifactPublication", "claimBoundary", "decision",
    "executableBuild", "files", "manifestSha256", "provenance", "roots",
    "schemaVersion", "tests", "toolchain", "workflow"
  ]) && manifest.schemaVersion === SCHEMA &&
    HEX_64.test(manifest.manifestSha256 ?? ""),
  "HOSTED_DUAL_ROOT_MANIFEST_REJECTED");
  const unsigned = { ...manifest };
  delete unsigned.manifestSha256;
  invariant(manifest.manifestSha256 === canonicalDigest(unsigned) &&
    manifest.decision.status === "HOSTED_DUAL_ROOT_SOURCE_VERIFIED" &&
    manifest.decision.providerExecutionAuthorized === false &&
    manifest.claimBoundary.oidcRequested === false &&
    manifest.claimBoundary.providerActionsPerformed === false &&
    manifest.claimBoundary.providerCredentialsPresent === false &&
    manifest.claimBoundary.cockroachDbAccessPerformed === false &&
    manifest.claimBoundary.liveParameterValuesObserved === false &&
    manifest.applicationBuild.reproducible === true &&
    manifest.executableBuild.reproducible === true &&
    manifest.applicationBuild.summary.parameterContract
      .liveParameterValuesObserved === false,
  "HOSTED_DUAL_ROOT_MANIFEST_REJECTED");
  invariant(exactKeys(manifest.workflow, ["commit", "runAttempt", "runId",
    "workflow", "workflowRef"]) &&
    manifest.workflow.commit === manifest.roots.controlPlane.commit &&
    (!context || canonicalHostedJson(manifest.workflow) ===
      canonicalHostedJson(context)),
  "HOSTED_DUAL_ROOT_MANIFEST_WORKFLOW_REJECTED");
  const controlStat = fs.lstatSync(control);
  const applicationStat = fs.lstatSync(application);
  invariant(manifest.roots.frozenApplication.commit ===
    FROZEN_APPLICATION.commit && manifest.roots.frozenApplication.tree ===
    FROZEN_APPLICATION.tree &&
    manifest.roots.frozenApplication.rootDevice === applicationStat.dev &&
    manifest.roots.frozenApplication.rootInode === applicationStat.ino &&
    manifest.roots.controlPlane.rootDevice === controlStat.dev &&
    manifest.roots.controlPlane.rootInode === controlStat.ino && HEX_40.test(
      manifest.roots.controlPlane.commit ?? "") && HEX_40.test(
      manifest.roots.controlPlane.tree ?? "") &&
    manifest.roots.controlPlane.commit !== FROZEN_APPLICATION.commit,
  "HOSTED_DUAL_ROOT_MANIFEST_ROOT_REJECTED");
  invariant(Array.isArray(manifest.files) &&
    requireExactArtifactPaths(manifest.files.map(({ path: item }) => item)),
  "HOSTED_DUAL_ROOT_ARTIFACT_SET_REJECTED");
  for (const record of manifest.files) {
    invariant(exactKeys(record, ["bytes", "path", "sha256"]) &&
      Number.isSafeInteger(record.bytes) && record.bytes > 0 &&
      HEX_64.test(record.sha256 ?? ""),
    "HOSTED_DUAL_ROOT_ARTIFACT_SET_REJECTED");
    const opened = readArtifactFile(output, record.path,
      "HOSTED_DUAL_ROOT_ARTIFACT_SET_REJECTED");
    invariant(opened.bytes.length === record.bytes &&
      hostedSha256(opened.bytes) === record.sha256,
    "HOSTED_DUAL_ROOT_ARTIFACT_SET_REJECTED");
    assertNonsecretBytes(opened.bytes,
      "HOSTED_DUAL_ROOT_ARTIFACT_SET_REJECTED");
  }
  const actual = inventoryArtifactFiles(output).map(({ path: item }) => item);
  requireExactArtifactPaths(actual);
  const tapPaths = [
    "logs/privileged-root-stage.tap",
    "logs/safety.tap",
    "logs/source-security-tests.tap",
    ...["control-plane-root", "release-control", "release-provider",
      "frozen-application"].map((name) => `logs/provenance-tests-${name}.log`)
  ];
  for (const relativePath of tapPaths) {
    const bytes = readArtifactFile(output, relativePath,
      "HOSTED_DUAL_ROOT_REQUIRED_TEST_SKIPPED").bytes;
    const separator = bytes.indexOf(LOG_SEPARATOR);
    invariant(separator >= 0,
      "HOSTED_DUAL_ROOT_REQUIRED_TEST_SKIPPED");
    parseRequiredTap(bytes.subarray(0, separator),
      "HOSTED_DUAL_ROOT_REQUIRED_TEST_SKIPPED");
  }
  const provenanceFile = readArtifactFile(output,
    "control-plane-provenance.json",
    "HOSTED_DUAL_ROOT_PROVENANCE_REJECTED");
  let provenance;
  try { provenance = JSON.parse(provenanceFile.bytes.toString("utf8")); }
  catch (cause) {
    throw new Error("HOSTED_DUAL_ROOT_PROVENANCE_REJECTED", { cause });
  }
  validateControlPlaneProvenanceEvidence(provenance);
  semanticProvenanceTests(provenance);
  invariant(fileDescriptorMatches(manifest.provenance.file,
    "control-plane-provenance.json", provenanceFile.bytes) &&
    provenance.bodySha256 === manifest.provenance.bodySha256 &&
    canonicalHostedJson(provenance.body.git) ===
      canonicalHostedJson(manifest.roots) &&
    canonicalHostedJson(provenance.body.executions.toolchain) ===
      canonicalHostedJson(manifest.toolchain) &&
    manifest.artifactPublication.requestedRetentionDays >= 30 &&
    manifest.artifactPublication.artifactUploadObserved === false,
  "HOSTED_DUAL_ROOT_PROVENANCE_REJECTED");
  reopenApplicationBuildEvidence({ applicationRoot: application, manifest,
    outputRoot: output });
  reopenExecutableBuildEvidence({ controlRoot: control, manifest,
    outputRoot: output });
  return Object.freeze({
    artifactFileCount: manifest.files.length + 1,
    controlPlaneCommit: manifest.roots.controlPlane.commit,
    frozenApplicationCommit: FROZEN_APPLICATION.commit,
    manifestSha256: manifest.manifestSha256,
    providerExecutionAuthorized: false,
    status: "HOSTED_DUAL_ROOT_ARTIFACT_VERIFIED"
  });
}

export const HOSTED_DUAL_ROOT_CONSTANTS = Object.freeze({
  FROZEN_APPLICATION,
  PRIVATE_PARAMETER_KEYS,
  REQUIRED_ARTIFACT_PATHS: requiredArtifactPaths(),
  SAFETY_TEST_FILES,
  SCHEMA,
  SOURCE_SECURITY_TEST_FILES,
  WORKFLOW,
  WORKFLOW_FILE,
  WORKFLOW_REF
});

export const __test = Object.freeze({
  assertNonsecretBytes,
  canonicalDigest,
  parseProcessBoundaryReceipts,
  parseSecurityReceipt,
  requireExactArtifactPaths,
  requiredArtifactPaths,
  rootsAreSeparate,
  semanticProvenanceTests,
  templateParameterContract
});
