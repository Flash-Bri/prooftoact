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
  validateReleaseSecurityReceipt,
  verifyReleaseSecurity
} from "../scripts/verify-release-security.js";
import { verifyIntegratedLiveDrillProcessBoundaries } from
  "../scripts/verify-integrated-live-drill-process-boundaries.js";
import { verifyIntegratedLiveDrillSystemdBoundary } from
  "../scripts/verify-integrated-live-drill-systemd-boundary.js";
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

const PROCESS_BOUNDARY_BASE_SOURCE_FILES = Object.freeze([
  "package-lock.json",
  "package.json",
  "scripts/verify-integrated-live-drill-process-boundaries.js",
  "scripts/verify-integrated-live-drill-systemd-boundary.js"
]);
const PRIVILEGED_SOURCE_FILES = Object.freeze([
  "test/root/integrated-live-drill-stage-root.test.js"
]);
const SECURITY_VERIFIER_BASE_SOURCE_FILES = Object.freeze([
  "RELEASE_SECURITY_MANIFEST.json",
  "scripts/verify-release-security.js"
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
const PARAMETER_STATUS = Object.freeze({
  notObserved: "NOT_OBSERVED_NO_PROVIDER_CONFIGURATION",
  observed: "OBSERVED_BUILD_DERIVED_VALUE"
});

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
  const resolvedExecutable = fs.realpathSync(executable);
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
    executable: resolvedExecutable,
    executableSha256: hostedSha256(fs.readFileSync(resolvedExecutable)),
    stderr: result.stderr,
    stdout: result.stdout
  });
}

function sourceRecords(root, rootRole, relativePaths, code) {
  invariant(typeof rootRole === "string" && rootRole.length > 0 &&
    Array.isArray(relativePaths) && relativePaths.length > 0 &&
    new Set(relativePaths).size === relativePaths.length, code);
  return Object.freeze([...relativePaths].sort().map((relativePath) => {
    invariant(typeof relativePath === "string" && relativePath.length > 0 &&
      !path.isAbsolute(relativePath) &&
      !relativePath.split("/").includes(".."), code);
    const filePath = path.resolve(root, relativePath);
    invariant(path.relative(root, filePath) ===
      relativePath.split("/").join(path.sep), code);
    const stat = fs.lstatSync(filePath);
    invariant(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1 &&
      stat.size > 0 && stat.size <= 8 * 1024 * 1024 &&
      fs.realpathSync(filePath) === filePath, code);
    const bytes = fs.readFileSync(filePath);
    return Object.freeze({
      bytes: bytes.length,
      path: relativePath,
      rootRole,
      sha256: hostedSha256(bytes)
    });
  }));
}

function createCommandBinding({ args, executable, sourcePaths, sourceRole,
  sourceRoot }, code = "HOSTED_DUAL_ROOT_COMMAND_BINDING_REJECTED") {
  invariant(Array.isArray(args) && args.every((item) =>
    typeof item === "string") && typeof executable === "string" &&
    path.isAbsolute(executable), code);
  const resolvedExecutable = fs.realpathSync(executable);
  const stat = fs.lstatSync(resolvedExecutable);
  invariant(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1 &&
    (stat.mode & 0o022) === 0, code);
  const sources = sourceRecords(sourceRoot, sourceRole, sourcePaths, code);
  return Object.freeze({
    arguments: Object.freeze([...args]),
    argumentsSha256: canonicalDigest(args),
    executable: resolvedExecutable,
    executableSha256: hostedSha256(fs.readFileSync(resolvedExecutable)),
    sourceFiles: sources,
    sourceSetSha256: canonicalDigest(sources)
  });
}

function verifyCommandBinding(binding, expected, code =
  "HOSTED_DUAL_ROOT_COMMAND_BINDING_REJECTED") {
  const rebuilt = createCommandBinding(expected, code);
  invariant(canonicalHostedJson(binding) === canonicalHostedJson(rebuilt), code);
  return rebuilt;
}

function securityVerifierSourceFiles(controlRoot) {
  const code = "HOSTED_DUAL_ROOT_SECURITY_SOURCE_SET_REJECTED";
  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(path.join(controlRoot,
      "RELEASE_SECURITY_MANIFEST.json"), "utf8"));
  } catch (cause) {
    throw new Error(code, { cause });
  }
  invariant(Array.isArray(manifest?.surfaces) && manifest.surfaces.length > 0 &&
    manifest.surfaces.every(({ path: item }) =>
      typeof item === "string" && item.length > 0), code);
  return Object.freeze([...new Set([
    ...SECURITY_VERIFIER_BASE_SOURCE_FILES,
    ...manifest.surfaces.map(({ path: item }) => item)
  ])].sort());
}

function processBoundarySourceFiles(receipts) {
  const code = "HOSTED_DUAL_ROOT_PROCESS_SOURCE_SET_REJECTED";
  invariant(Array.isArray(receipts) && receipts.length === 2, code);
  const paths = new Set(PROCESS_BOUNDARY_BASE_SOURCE_FILES);
  const collect = (value, parent = null) => {
    if (typeof value === "string") {
      if (/^(?:infra|scripts|src|test)\//u.test(value)) paths.add(value);
      if (parent === "directImports" && /^(?:\.\.\/|\.\/)/u.test(value)) {
        const resolved = path.posix.normalize(path.posix.join("scripts", value));
        invariant(/^(?:scripts|src)\//u.test(resolved), code);
        paths.add(resolved);
      }
      return;
    }
    if (Array.isArray(value)) {
      for (const item of value) collect(item, parent);
      return;
    }
    if (plainObject(value)) {
      for (const [name, item] of Object.entries(value)) collect(item, name);
    }
  };
  collect(receipts);
  return Object.freeze([...paths].sort());
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
  outputRoot, relativePath, sourcePaths, sourceRole = "control-plane",
  sourceRoot = cwd, tap = false }) {
  const command = createCommandBinding({ args, executable, sourcePaths,
    sourceRole, sourceRoot }, code);
  const result = checkedSpawn(executable, args, { code, cwd, env });
  invariant(result.argumentsSha256 === command.argumentsSha256 &&
    result.executable === command.executable &&
    result.executableSha256 === command.executableSha256, code);
  const log = publishFile(outputRoot, relativePath, combinedLog(result));
  return Object.freeze({
    command,
    log,
    status: "PASS",
    ...(tap ? { summary: parseRequiredTap(result.stdout, code) } : {})
  });
}

function provenanceLaneSource(lane, controlRoot, applicationRoot) {
  if (lane === "frozen-application") {
    return Object.freeze({
      paths: Object.freeze(["package-lock.json", "package.json"]),
      role: "frozen-application",
      root: applicationRoot
    });
  }
  const prefix = lane === "control-plane-root" ? "" : `${lane}/`;
  return Object.freeze({
    paths: Object.freeze([
      `${prefix}package-lock.json`, `${prefix}package.json`
    ]),
    role: "control-plane",
    root: controlRoot
  });
}

function provenanceArguments(kind, npmCli) {
  if (kind === "installations") {
    return Object.freeze([npmCli, "ci", "--ignore-scripts", "--no-audit",
      "--no-fund"]);
  }
  if (kind === "tests") return Object.freeze([npmCli, "--silent", "test"]);
  invariant(kind === "audits",
    "HOSTED_DUAL_ROOT_PROVENANCE_COMMAND_REJECTED");
  return Object.freeze([npmCli, "audit", "--omit=dev", "--json"]);
}

function materializeProvenanceLogs(provenance, outputRoot, {
  applicationRoot, controlRoot, npmCli
}) {
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
      const source = provenanceLaneSource(record.command, controlRoot,
        applicationRoot);
      const args = provenanceArguments(kind, npmCli);
      const command = createCommandBinding({
        args,
        executable: process.execPath,
        sourcePaths: source.paths,
        sourceRole: source.role,
        sourceRoot: source.root
      }, "HOSTED_DUAL_ROOT_PROVENANCE_COMMAND_REJECTED");
      invariant(command.argumentsSha256 === record.argumentsSha256,
        "HOSTED_DUAL_ROOT_PROVENANCE_COMMAND_REJECTED");
      return Object.freeze({
        command,
        lane: record.command,
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
  const values = {
    EnableProbeFunctions: "false",
    PackageLockDigest: receipt.packageLockDigest,
    SourceCommit: receipt.sourceCommit,
    TreeDigest: receipt.treeDigest
  };
  for (const artifact of receipt.artifacts) {
    const prefix = artifact.name[0].toUpperCase() + artifact.name.slice(1);
    values[`${prefix}ArtifactCodeSha256`] = artifact.artifactCodeSha256;
    values[`${prefix}ArtifactDigest`] = artifact.artifactDigest;
    values[`${prefix}ArtifactKey`] = artifact.suggestedS3Key;
    values[`${prefix}SourceDigest`] = artifact.sourceDigest;
  }
  const privateKeys = new Set(PRIVATE_PARAMETER_KEYS);
  const observedNames = PARAMETER_KEYS.filter((name) => !privateKeys.has(name));
  invariant(Object.keys(values).sort().join("\n") ===
    [...observedNames].sort().join("\n") && Object.values(values).every(
      (value) => typeof value === "string" && value.length > 0), code);
  const parameterDispositions = Object.freeze(Object.fromEntries(
    PARAMETER_KEYS.map((name) => {
      if (privateKeys.has(name)) {
        return [name, Object.freeze({
          evidence: "NONE",
          status: PARAMETER_STATUS.notObserved,
          valueObserved: false,
          valueSha256: null
        })];
      }
      return [name, Object.freeze({
        evidence: name === "EnableProbeFunctions"
          ? "SOURCE_POLICY" : "FROZEN_APPLICATION_BUILD_RECEIPT",
        status: PARAMETER_STATUS.observed,
        valueObserved: true,
        valueSha256: hostedSha256(Buffer.from(values[name], "utf8"))
      })];
    })
  ));
  return Object.freeze({
    buildDerivedParameterInputsSha256: canonicalDigest(buildDerived),
    keyCount: names.length,
    liveParameterValuesObserved: false,
    notObservedValueCount: PRIVATE_PARAMETER_KEYS.length,
    observedValueCount: observedNames.length,
    parameterDispositionSha256: canonicalDigest(parameterDispositions),
    parameterDispositions,
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
    const args = [npmCli, "--silent", "run", "build:gate2"];
    const result = runner(process.execPath, args, {
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
    const sourcePaths = [...new Set([
      "package-lock.json",
      "package.json",
      ...receipt.buildControlInputs.map(({ path: item }) => item)
    ])].sort();
    const command = createCommandBinding({
      args,
      executable: process.execPath,
      sourcePaths,
      sourceRole: "frozen-application",
      sourceRoot: applicationRoot
    }, "HOSTED_DUAL_ROOT_APPLICATION_BUILD_FAILED");
    invariant(result.argumentsSha256 === command.argumentsSha256 &&
      result.executableSha256 === command.executableSha256,
    "HOSTED_DUAL_ROOT_APPLICATION_BUILD_FAILED");
    summaries.push(Object.freeze({
      command,
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
  env, outputRoot, temporaryRoot, runner = checkedSpawn }) {
  const operatorPublicKey = readTrackedOperatorPublicKey(controlRoot);
  const attempts = [];
  for (let attempt = 1; attempt <= 2; attempt += 1) {
    const attemptRoot = path.join(temporaryRoot, `executable-${attempt}`);
    fs.mkdirSync(attemptRoot, { mode: 0o700 });
    const controlOutput = path.join(attemptRoot, "release-control");
    const providerOutput = path.join(attemptRoot, "release-provider");
    const controlArgs = ["release-control/build-release-control-runtime.js",
      controlOutput, controlIdentity.commit, controlIdentity.tree];
    const providerArgs = ["release-provider/build-release-provider-runtimes.js",
      providerOutput, controlIdentity.commit, controlIdentity.tree];
    const controlResult = runner(process.execPath, controlArgs, {
      code: "HOSTED_DUAL_ROOT_CONTROL_RUNTIME_BUILD_FAILED",
      cwd: controlRoot,
      env
    });
    const providerResult = runner(process.execPath, providerArgs, {
      code: "HOSTED_DUAL_ROOT_PROVIDER_RUNTIME_BUILD_FAILED",
      cwd: controlRoot,
      env
    });
    const controlReceipt = parseExactJsonBytes(controlResult.stdout,
      JSON.stringify, "HOSTED_DUAL_ROOT_CONTROL_RUNTIME_BUILD_FAILED");
    const providerReceipt = parseExactJsonBytes(providerResult.stdout,
      JSON.stringify, "HOSTED_DUAL_ROOT_PROVIDER_RUNTIME_BUILD_FAILED");
    const controlCommand = createCommandBinding({
      args: controlArgs,
      executable: process.execPath,
      sourcePaths: [...new Set([
        "release-control/build-release-control-runtime.js",
        "release-control/package-lock.json",
        "release-control/package.json",
        ...controlReceipt.sourceInventory.map(({ path: item }) => item)
      ])].sort(),
      sourceRole: "control-plane",
      sourceRoot: controlRoot
    }, "HOSTED_DUAL_ROOT_CONTROL_RUNTIME_BUILD_FAILED");
    const providerCommand = createCommandBinding({
      args: providerArgs,
      executable: process.execPath,
      sourcePaths: [...new Set([
        "release-provider/build-release-provider-runtimes.js",
        "release-provider/package-lock.json",
        "release-provider/package.json",
        ...providerReceipt.sourceInventory.map(({ path: item }) => item)
      ])].sort(),
      sourceRole: "control-plane",
      sourceRoot: controlRoot
    }, "HOSTED_DUAL_ROOT_PROVIDER_RUNTIME_BUILD_FAILED");
    invariant(controlResult.argumentsSha256 ===
      controlCommand.argumentsSha256 && controlResult.executableSha256 ===
      controlCommand.executableSha256 && providerResult.argumentsSha256 ===
      providerCommand.argumentsSha256 && providerResult.executableSha256 ===
      providerCommand.executableSha256,
    "HOSTED_DUAL_ROOT_EXECUTABLE_BUILD_COMMAND_REJECTED");
    const executable = createControlPlaneExecutableManifest({
      controlPlane: controlIdentity,
      controlReceipt,
      controlRoot,
      operatorPublicKey,
      providerReceipt
    });
    const controlBytes = controlResult.stdout;
    const providerBytes = providerResult.stdout;
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
      commands: Object.freeze({
        control: controlCommand,
        provider: providerCommand
      }),
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
    validateReleaseSecurityReceipt(receipt);
  } catch (cause) {
    throw new Error("HOSTED_DUAL_ROOT_SECURITY_RECEIPT_REJECTED", { cause });
  }
  invariant(Buffer.from(`${JSON.stringify(receipt, null, 2)}\n`, "utf8")
    .equals(bytes),
  "HOSTED_DUAL_ROOT_SECURITY_RECEIPT_REJECTED");
  return Object.freeze(receipt);
}

function parseProcessBoundaryReceipts(bytes) {
  const lines = bytes.toString("utf8").trim().split("\n");
  invariant(lines.length === 2,
    "HOSTED_DUAL_ROOT_PROCESS_BOUNDARY_REJECTED");
  let receipts;
  try { receipts = lines.map((line) => JSON.parse(line)); } catch (cause) {
    throw new Error("HOSTED_DUAL_ROOT_PROCESS_BOUNDARY_REJECTED", { cause });
  }
  invariant(receipts[0]?.schemaVersion ===
    "tideproof.highwater-drill-process-boundary-verification.v5" &&
    receipts[1]?.schemaVersion ===
      "tideproof.integrated-live-drill-systemd-boundary.v1" &&
    receipts.every((receipt) => receipt.status === "PASS") &&
    Buffer.from(`${receipts.map((receipt) => JSON.stringify(receipt))
      .join("\n")}\n`, "utf8").equals(bytes),
    "HOSTED_DUAL_ROOT_PROCESS_BOUNDARY_REJECTED");
  return Object.freeze(receipts.map((receipt) => Object.freeze(receipt)));
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
    sourcePaths: SAFETY_TEST_FILES,
    tap: true
  });
  const sourceSecurityTests = runAndPublish({
    args: ["--test", ...SOURCE_SECURITY_TEST_FILES],
    code: "HOSTED_DUAL_ROOT_SOURCE_SECURITY_TEST_FAILED",
    cwd: controlRoot,
    env,
    outputRoot,
    relativePath: "logs/source-security-tests.tap",
    sourcePaths: SOURCE_SECURITY_TEST_FILES,
    tap: true
  });
  const securityArgs = ["scripts/verify-release-security.js"];
  const securityResult = checkedSpawn(process.execPath,
    securityArgs, {
      code: "HOSTED_DUAL_ROOT_SOURCE_SECURITY_VERIFIER_FAILED",
      cwd: controlRoot,
      env
    });
  const securityReceipt = parseSecurityReceipt(securityResult.stdout);
  invariant(canonicalHostedJson(securityReceipt) === canonicalHostedJson(
    verifyReleaseSecurity({ rootDir: controlRoot })),
  "HOSTED_DUAL_ROOT_SOURCE_SECURITY_VERIFIER_FAILED");
  const securityCommand = createCommandBinding({
    args: securityArgs,
    executable: process.execPath,
    sourcePaths: securityVerifierSourceFiles(controlRoot),
    sourceRole: "control-plane",
    sourceRoot: controlRoot
  }, "HOSTED_DUAL_ROOT_SOURCE_SECURITY_VERIFIER_FAILED");
  invariant(securityResult.argumentsSha256 ===
    securityCommand.argumentsSha256 && securityResult.executableSha256 ===
    securityCommand.executableSha256,
  "HOSTED_DUAL_ROOT_SOURCE_SECURITY_VERIFIER_FAILED");
  const sourceSecurityVerifier = Object.freeze({
    command: securityCommand,
    log: publishFile(outputRoot, "logs/source-security-verifier.json",
      combinedLog(securityResult)),
    receipt: securityReceipt,
    status: "PASS"
  });
  const processArgs = [npmCli, "--silent", "run",
    "process-boundaries:verify"];
  const processResult = checkedSpawn(process.execPath,
    processArgs, {
      code: "HOSTED_DUAL_ROOT_PROCESS_BOUNDARY_FAILED",
      cwd: controlRoot,
      env
    });
  const processReceipts = parseProcessBoundaryReceipts(processResult.stdout);
  const expectedProcessReceipts = Object.freeze([
    verifyIntegratedLiveDrillProcessBoundaries(),
    verifyIntegratedLiveDrillSystemdBoundary()
  ]);
  invariant(canonicalHostedJson(processReceipts) ===
    canonicalHostedJson(expectedProcessReceipts),
  "HOSTED_DUAL_ROOT_PROCESS_BOUNDARY_FAILED");
  const processCommand = createCommandBinding({
    args: processArgs,
    executable: process.execPath,
    sourcePaths: processBoundarySourceFiles(processReceipts),
    sourceRole: "control-plane",
    sourceRoot: controlRoot
  }, "HOSTED_DUAL_ROOT_PROCESS_BOUNDARY_FAILED");
  invariant(processResult.argumentsSha256 === processCommand.argumentsSha256 &&
    processResult.executableSha256 === processCommand.executableSha256,
  "HOSTED_DUAL_ROOT_PROCESS_BOUNDARY_FAILED");
  const processBoundaries = Object.freeze({
    command: processCommand,
    log: publishFile(outputRoot, "logs/process-boundaries.log",
      combinedLog(processResult)),
    receipts: processReceipts,
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
    sourcePaths: PRIVILEGED_SOURCE_FILES,
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
  invariant(fs.existsSync(filePath), code);
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
  invariant(typeof npmCli === "string" && path.isAbsolute(npmCli),
    "HOSTED_DUAL_ROOT_NPM_CLI_REJECTED");
  const exactNpmCli = fs.realpathSync(npmCli);
  const output = assertPublicationRoot(outputRoot);
  invariant(rootsAreSeparate(control, application) &&
    rootsAreSeparate(control, output) && rootsAreSeparate(application, output) &&
    fs.readdirSync(output).length === 0,
  "HOSTED_DUAL_ROOT_ROOT_SEPARATION_REJECTED");

  const provenance = generateControlPlaneProvenanceEvidence({
    controlPlaneRoot: control,
    frozenApplicationRoot: application,
    npmCli: exactNpmCli
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
  const provenanceLogs = materializeProvenanceLogs(provenance, output, {
    applicationRoot: application,
    controlRoot: control,
    npmCli: exactNpmCli
  });

  const temporaryRoot = fs.mkdtempSync(
    path.join(output, ".hosted-dual-root-temporary-"));
  fs.chmodSync(temporaryRoot, 0o700);
  try {
    const env = childEnvironment(temporaryRoot, exactNpmCli);
    const applicationBuild = await buildApplicationTwice({
      applicationRoot: application,
      env,
      npmCli: exactNpmCli,
      outputRoot: output
    });
    const executableBuild = await buildExecutablesTwice({
      controlIdentity: {
        commit: provenance.body.git.controlPlane.commit,
        tree: provenance.body.git.controlPlane.tree
      },
      controlRoot: control,
      env,
      outputRoot: output,
      temporaryRoot
    });
    const requiredSuites = runRequiredSuites({
      controlRoot: control,
      env,
      npmCli: exactNpmCli,
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
  npmCli, outputRoot }) {
  const code = "HOSTED_DUAL_ROOT_APPLICATION_BUILD_EVIDENCE_REJECTED";
  const build = manifest.applicationBuild;
  invariant(exactKeys(build, ["attempts", "reproducible", "summary"]) &&
    build.reproducible === true && Array.isArray(build.attempts) &&
    build.attempts.length === 2, code);
  const summaries = build.attempts.map((attempt, index) => {
    invariant(exactKeys(attempt, ["command", "log", "summary"]), code);
    const relativePath = `builds/application-build-${index + 1}.log`;
    const opened = readArtifactFile(outputRoot, relativePath, code);
    invariant(fileDescriptorMatches(attempt.log, relativePath, opened.bytes),
      code);
    const { stdout } = splitCombinedLog(opened.bytes, code);
    const receipt = parseExactJsonBytes(stdout,
      (value) => JSON.stringify(value, null, 2), code);
    const sourcePaths = [...new Set([
      "package-lock.json", "package.json",
      ...receipt.buildControlInputs.map(({ path: item }) => item)
    ])].sort();
    verifyCommandBinding(attempt.command, {
      args: [npmCli, "--silent", "run", "build:gate2"],
      executable: process.execPath,
      sourcePaths,
      sourceRole: "frozen-application",
      sourceRoot: applicationRoot
    }, code);
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
    invariant(exactKeys(attempt, ["commands", "files", "summary"]) &&
      exactKeys(attempt.commands, ["control", "provider"]) &&
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
    const runtimeOutput = (command, suffix) => {
      invariant(plainObject(command) && Array.isArray(command.arguments) &&
        command.arguments.length === 4, code);
      const candidate = command.arguments[1];
      invariant(typeof candidate === "string" && path.isAbsolute(candidate) &&
        path.relative(outputRoot, candidate).split(path.sep).join("/")
          .match(new RegExp(
            `^\\.hosted-dual-root-temporary-[A-Za-z0-9._-]+/` +
            `executable-${number}/${suffix}$`, "u")), code);
      return candidate;
    };
    const controlOutput = runtimeOutput(attempt.commands.control,
      "release-control");
    const providerOutput = runtimeOutput(attempt.commands.provider,
      "release-provider");
    verifyCommandBinding(attempt.commands.control, {
      args: ["release-control/build-release-control-runtime.js",
        controlOutput, controlPlane.commit, controlPlane.tree],
      executable: process.execPath,
      sourcePaths: [...new Set([
        "release-control/build-release-control-runtime.js",
        "release-control/package-lock.json", "release-control/package.json",
        ...controlReceipt.sourceInventory.map(({ path: item }) => item)
      ])].sort(),
      sourceRole: "control-plane",
      sourceRoot: controlRoot
    }, code);
    verifyCommandBinding(attempt.commands.provider, {
      args: ["release-provider/build-release-provider-runtimes.js",
        providerOutput, controlPlane.commit, controlPlane.tree],
      executable: process.execPath,
      sourcePaths: [...new Set([
        "release-provider/build-release-provider-runtimes.js",
        "release-provider/package-lock.json", "release-provider/package.json",
        ...providerReceipt.sourceInventory.map(({ path: item }) => item)
      ])].sort(),
      sourceRole: "control-plane",
      sourceRoot: controlRoot
    }, code);
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

function reopenTapEvidence({ expected, outputRoot, record, relativePath }) {
  const code = "HOSTED_DUAL_ROOT_REQUIRED_SUITE_EVIDENCE_REJECTED";
  invariant(exactKeys(record, ["command", "log", "status", "summary"]) &&
    record.status === "PASS", code);
  const opened = readArtifactFile(outputRoot, relativePath, code);
  invariant(fileDescriptorMatches(record.log, relativePath, opened.bytes),
    code);
  const { stdout } = splitCombinedLog(opened.bytes, code);
  const summary = parseRequiredTap(stdout, code);
  invariant(canonicalHostedJson(summary) ===
    canonicalHostedJson(record.summary), code);
  verifyCommandBinding(record.command, expected, code);
  return summary;
}

function reopenRequiredSuiteEvidence({ controlRoot, manifest, npmCli,
  outputRoot }) {
  const code = "HOSTED_DUAL_ROOT_REQUIRED_SUITE_EVIDENCE_REJECTED";
  const suites = manifest.tests?.requiredSuites;
  invariant(exactKeys(suites, ["privileged", "processBoundaries", "safety",
    "sourceSecurityTests", "sourceSecurityVerifier"]), code);
  reopenTapEvidence({
    expected: {
      args: ["--test", ...SAFETY_TEST_FILES],
      executable: process.execPath,
      sourcePaths: SAFETY_TEST_FILES,
      sourceRole: "control-plane",
      sourceRoot: controlRoot
    },
    outputRoot,
    record: suites.safety,
    relativePath: "logs/safety.tap"
  });
  reopenTapEvidence({
    expected: {
      args: ["--test", ...SOURCE_SECURITY_TEST_FILES],
      executable: process.execPath,
      sourcePaths: SOURCE_SECURITY_TEST_FILES,
      sourceRole: "control-plane",
      sourceRoot: controlRoot
    },
    outputRoot,
    record: suites.sourceSecurityTests,
    relativePath: "logs/source-security-tests.tap"
  });
  const exactNode = fs.realpathSync(process.execPath);
  reopenTapEvidence({
    expected: {
      args: ["--non-interactive", "/usr/bin/env", "-i",
        `PATH=${path.dirname(exactNode)}:/usr/bin:/bin`, "LANG=C", "LC_ALL=C",
        exactNode, "--test",
        "test/root/integrated-live-drill-stage-root.test.js"],
      executable: "/usr/bin/sudo",
      sourcePaths: PRIVILEGED_SOURCE_FILES,
      sourceRole: "control-plane",
      sourceRoot: controlRoot
    },
    outputRoot,
    record: suites.privileged,
    relativePath: "logs/privileged-root-stage.tap"
  });

  invariant(exactKeys(suites.sourceSecurityVerifier,
    ["command", "log", "receipt", "status"]) &&
    suites.sourceSecurityVerifier.status === "PASS", code);
  const securityPath = "logs/source-security-verifier.json";
  const securityLog = readArtifactFile(outputRoot, securityPath, code);
  invariant(fileDescriptorMatches(suites.sourceSecurityVerifier.log,
    securityPath, securityLog.bytes), code);
  const securityOutput = splitCombinedLog(securityLog.bytes, code).stdout;
  const securityReceipt = parseSecurityReceipt(securityOutput);
  invariant(canonicalHostedJson(securityReceipt) === canonicalHostedJson(
    suites.sourceSecurityVerifier.receipt) &&
    canonicalHostedJson(securityReceipt) === canonicalHostedJson(
      verifyReleaseSecurity({ rootDir: controlRoot })), code);
  verifyCommandBinding(suites.sourceSecurityVerifier.command, {
    args: ["scripts/verify-release-security.js"],
    executable: process.execPath,
    sourcePaths: securityVerifierSourceFiles(controlRoot),
    sourceRole: "control-plane",
    sourceRoot: controlRoot
  }, code);

  invariant(exactKeys(suites.processBoundaries,
    ["command", "log", "receipts", "status"]) &&
    suites.processBoundaries.status === "PASS", code);
  const processPath = "logs/process-boundaries.log";
  const processLog = readArtifactFile(outputRoot, processPath, code);
  invariant(fileDescriptorMatches(suites.processBoundaries.log, processPath,
    processLog.bytes), code);
  const processOutput = splitCombinedLog(processLog.bytes, code).stdout;
  const processReceipts = parseProcessBoundaryReceipts(processOutput);
  invariant(canonicalHostedJson(processReceipts) === canonicalHostedJson(
    suites.processBoundaries.receipts) &&
    canonicalHostedJson(processReceipts) === canonicalHostedJson([
      verifyIntegratedLiveDrillProcessBoundaries(),
      verifyIntegratedLiveDrillSystemdBoundary()
    ]), code);
  verifyCommandBinding(suites.processBoundaries.command, {
    args: [npmCli, "--silent", "run", "process-boundaries:verify"],
    executable: process.execPath,
    sourcePaths: processBoundarySourceFiles(processReceipts),
    sourceRole: "control-plane",
    sourceRoot: controlRoot
  }, code);
  return true;
}

function parseZeroAudit(bytes, code) {
  let receipt;
  try { receipt = JSON.parse(bytes.toString("utf8")); } catch (cause) {
    throw new Error(code, { cause });
  }
  const vulnerabilities = receipt?.metadata?.vulnerabilities;
  invariant(plainObject(vulnerabilities) &&
    ["critical", "high", "info", "low", "moderate", "total"].every(
      (name) => Number.isSafeInteger(vulnerabilities[name]) &&
        vulnerabilities[name] === 0), code);
  return true;
}

function reopenProvenanceLogEvidence({ applicationRoot, controlRoot, manifest,
  npmCli, outputRoot, provenance }) {
  const code = "HOSTED_DUAL_ROOT_PROVENANCE_LOG_EVIDENCE_REJECTED";
  const logs = manifest.provenance?.logs;
  invariant(exactKeys(logs, ["audits", "installations", "tests"]), code);
  for (const kind of ["installations", "tests", "audits"]) {
    const originals = provenance.body.executions[kind];
    invariant(Array.isArray(logs[kind]) && logs[kind].length === 4 &&
      logs[kind].length === originals.length, code);
    logs[kind].forEach((record, index) => {
      const original = originals[index];
      invariant(exactKeys(record,
        ["command", "lane", "log", "semantic", "status"]) &&
        record.lane === original.command && record.status === "PASS" &&
        canonicalHostedJson(record.semantic) ===
          canonicalHostedJson(original.semantic), code);
      const relativePath =
        `logs/provenance-${kind}-${record.lane}.log`;
      const opened = readArtifactFile(outputRoot, relativePath, code);
      invariant(fileDescriptorMatches(record.log, relativePath, opened.bytes) &&
        hostedSha256(opened.bytes) === original.outputSha256, code);
      const split = splitCombinedLog(opened.bytes, code);
      if (kind === "tests") {
        const summary = parseRequiredTap(split.stdout, code);
        for (const [name, value] of Object.entries(summary)) {
          invariant(original.semantic[name] === value, code);
        }
      } else if (kind === "audits") {
        parseZeroAudit(split.stdout, code);
      }
      const source = provenanceLaneSource(record.lane, controlRoot,
        applicationRoot);
      verifyCommandBinding(record.command, {
        args: provenanceArguments(kind, npmCli),
        executable: process.execPath,
        sourcePaths: source.paths,
        sourceRole: source.role,
        sourceRoot: source.root
      }, code);
      invariant(record.command.argumentsSha256 === original.argumentsSha256,
        code);
    });
  }
  return true;
}

export function verifyHostedDualRootArtifact({
  applicationRoot,
  controlRoot,
  environment = process.env,
  npmCli,
  outputRoot,
  requireHostedContext = true
}) {
  const context = requireHostedContext
    ? validateHostedWorkflowContext(environment) : null;
  const control = exactOwnedDirectory(controlRoot,
    "HOSTED_DUAL_ROOT_CONTROL_ROOT_REJECTED");
  const application = exactOwnedDirectory(applicationRoot,
    "HOSTED_DUAL_ROOT_APPLICATION_ROOT_REJECTED");
  invariant(typeof npmCli === "string" && path.isAbsolute(npmCli),
    "HOSTED_DUAL_ROOT_NPM_CLI_REJECTED");
  const exactNpmCli = fs.realpathSync(npmCli);
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
  const baseTests = semanticProvenanceTests(provenance);
  invariant(fileDescriptorMatches(manifest.provenance.file,
    "control-plane-provenance.json", provenanceFile.bytes) &&
    provenance.bodySha256 === manifest.provenance.bodySha256 &&
    canonicalHostedJson(baseTests) ===
      canonicalHostedJson(manifest.tests.base) &&
    canonicalHostedJson(provenance.body.git) ===
      canonicalHostedJson(manifest.roots) &&
    canonicalHostedJson(provenance.body.executions.toolchain) ===
      canonicalHostedJson(manifest.toolchain) &&
    manifest.artifactPublication.requestedRetentionDays >= 30 &&
    manifest.artifactPublication.artifactUploadObserved === false,
  "HOSTED_DUAL_ROOT_PROVENANCE_REJECTED");
  reopenApplicationBuildEvidence({ applicationRoot: application, manifest,
    npmCli: exactNpmCli, outputRoot: output });
  reopenExecutableBuildEvidence({ controlRoot: control, manifest,
    outputRoot: output });
  reopenRequiredSuiteEvidence({ controlRoot: control, manifest,
    npmCli: exactNpmCli, outputRoot: output });
  reopenProvenanceLogEvidence({ applicationRoot: application,
    controlRoot: control, manifest, npmCli: exactNpmCli, outputRoot: output,
    provenance });
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
  PARAMETER_STATUS,
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
  createCommandBinding,
  parseProcessBoundaryReceipts,
  parseSecurityReceipt,
  processBoundarySourceFiles,
  requireExactArtifactPaths,
  requiredArtifactPaths,
  rootsAreSeparate,
  securityVerifierSourceFiles,
  semanticProvenanceTests,
  templateParameterContract,
  verifyCommandBinding
});
