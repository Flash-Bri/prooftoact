import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const CURRENT_FILE = fileURLToPath(import.meta.url);
const OFFICIAL_ORIGIN = "https://github.com/Flash-Bri/prooftoact.git";
const REGION = "us-east-1";
const ROLE_PATH = "/prooftoact/bootstrap/";
const SESSION_DURATION_SECONDS = 900;
const MAX_PLAN_WINDOW_MS = 60 * 60 * 1000;
const MAX_CLEANUP_WINDOW_MS = 24 * 60 * 60 * 1000;
const INLINE_POLICY_MAX_NON_WHITESPACE_BYTES = 10_240;
const PLANNER_PATH = "scripts/prepare-one-time-bootstrap-authority.js";
const ROOT_ASSUME_RUNTIME_PATH =
  "scripts/assume-one-time-bootstrap-root-session.js";
const CEREMONY_LAUNCHER_PATH = "scripts/launch-one-time-bootstrap-ceremony.js";
const CEREMONY_RUNNER_PATH = "scripts/run-one-time-bootstrap-ceremony.js";
const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const ACCOUNT_ID = /^[0-9]{12}$/u;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const BUCKET_NAME =
  /^(?!xn--)(?!.*\.\.)(?!.*\.-)(?!.*-\.)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])$/u;
const PROFILE_NAME = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/u;
const EXACT_MONTHLY_AUTHORIZATION_USD_CENTS = 350;
const EXACT_ONE_TIME_AUTHORIZATION_USD_CENTS = 500;
const COST_RECONCILIATION_MAXIMUM_AGE_MS = 7 * 24 * 60 * 60 * 1000;
const COST_RECONCILIATION_LINE_ITEMS = Object.freeze([
  Object.freeze({
    monthlyUsdCents: 320,
    resourceClass: "AWS_SECRETS_MANAGER_EIGHT_RETAINED_SECRETS"
  }),
  Object.freeze({
    monthlyUsdCents: 30,
    resourceClass: "AWS_VARIABLE_SERVICES_EXPLICIT_HEADROOM"
  }),
  Object.freeze({
    monthlyUsdCents: 150,
    resourceClass: "COCKROACH_BASIC_PAID_WORST_CASE"
  })
]);
const PRIVATE_RECOVERY_WORKFLOW_DEFINITIONS = Object.freeze({
  deployment: Object.freeze({
    parameterName: "DeploymentWorkflowCommit",
    path: ".github/workflows/prooftoact-sealed-private-recovery-deploy.yml"
  }),
  secretSeal: Object.freeze({
    parameterName: "SecretSealWorkflowCommit",
    path:
      ".github/workflows/prooftoact-sealed-private-recovery-secret-seal.yml"
  })
});
const PRIVATE_RECOVERY_WORKFLOW_KEYS = Object.freeze(
  Object.keys(PRIVATE_RECOVERY_WORKFLOW_DEFINITIONS)
);
const A1_INTEGRATION_RUNTIME_PATHS = Object.freeze([
  "scripts/bootstrap-fresh-primary.js",
  "scripts/fresh-primary-bootstrap-role-readback.js",
  "scripts/fresh-primary-credential-custody-readback.js",
  "scripts/fresh-primary-credential-sealer.js",
  "scripts/lib/fresh-bootstrap-collector-binding.js",
  "scripts/prepare-fresh-primary-bootstrap-role.js",
  "scripts/prepare-fresh-primary-credential-custody.js"
]);
const RUNTIME_DEPENDENCY_PATHS = Object.freeze([
  "package-lock.json",
  "package.json",
  ...A1_INTEGRATION_RUNTIME_PATHS,
  ...Object.values(PRIVATE_RECOVERY_WORKFLOW_DEFINITIONS)
    .map(({ path: workflowPath }) => workflowPath)
]);

function runtimeTree(rootPath, code, { skipRootBin = false } = {}) {
  let root;
  let rootStat;
  try {
    root = fs.realpathSync(rootPath);
    rootStat = fs.lstatSync(rootPath);
  } catch (cause) {
    reject(code, cause);
  }
  requireCondition(root === path.resolve(rootPath) && rootStat.isDirectory() &&
    !rootStat.isSymbolicLink(), code);
  const records = [];
  let totalBytes = 0;
  function visit(directory, relativeDirectory = "") {
    for (const name of fs.readdirSync(directory).sort()) {
      if (skipRootBin && relativeDirectory === "" && name === ".bin") {
        continue;
      }
      requireCondition(name !== "" && name !== "." && name !== ".." &&
        !name.includes("\0"), code);
      const relativePath = relativeDirectory ?
        `${relativeDirectory}/${name}` : name;
      const absolutePath = path.join(directory, name);
      const stat = fs.lstatSync(absolutePath);
      if (stat.isDirectory()) {
        records.push({ mode: stat.mode & 0o777, path: `${relativePath}/`,
          size: 0, type: "directory", valueSha256: sha256("") });
        visit(absolutePath, relativePath);
        continue;
      }
      if (stat.isSymbolicLink()) {
        const target = fs.readlinkSync(absolutePath);
        const bytes = Buffer.from(target, "utf8");
        totalBytes += bytes.length;
        records.push({ mode: stat.mode & 0o777, path: relativePath,
          size: bytes.length, type: "symlink", valueSha256: sha256(bytes) });
        continue;
      }
      requireCondition(stat.isFile(), code);
      const bytes = fs.readFileSync(absolutePath);
      requireCondition(bytes.length === stat.size, code);
      totalBytes += bytes.length;
      records.push({ mode: stat.mode & 0o777, path: relativePath,
        size: bytes.length, type: "file", valueSha256: sha256(bytes) });
    }
  }
  visit(root);
  return Object.freeze({
    fileCount: records.filter(({ type }) => type !== "directory").length,
    recordCount: records.length,
    totalBytes,
    treeDigest: sha256(Buffer.from(records.map((record) =>
      `${record.path}\0${record.type}\0${record.mode}\0${record.size}\0` +
      `${record.valueSha256}\n`).join(""), "utf8"))
  });
}

function awsCliRuntimeBinding(awsCliPath) {
  const code = "ONE_TIME_BOOTSTRAP_AWS_CLI_RUNTIME_REJECTED";
  requireCondition(typeof awsCliPath === "string" &&
    path.isAbsolute(awsCliPath), code);
  let realPath;
  let requestedStat;
  let realStat;
  try {
    realPath = fs.realpathSync(awsCliPath);
    requestedStat = fs.lstatSync(awsCliPath);
    realStat = fs.lstatSync(realPath);
  } catch (cause) {
    reject(code, cause);
  }
  requireCondition((requestedStat.isFile() || requestedStat.isSymbolicLink()) &&
    realStat.isFile() && !realStat.isSymbolicLink() &&
    (realStat.mode & 0o111) !== 0, code);
  const parent = path.dirname(realPath);
  const runtimeRoot = path.basename(parent) === "bin" ?
    path.dirname(parent) : parent;
  const tree = runtimeTree(runtimeRoot, code);
  return Object.freeze({
    entrySha256: sha256(fs.readFileSync(realPath)),
    requestedPath: awsCliPath,
    realPath,
    runtimeRoot,
    ...tree
  });
}

function runtimeExecutionBinding(sourceRoot, awsCliPath, homeDirectory) {
  const code = "ONE_TIME_BOOTSTRAP_RUNTIME_EXECUTION_REJECTED";
  const nodeRealPath = fs.realpathSync(process.execPath);
  const nodeStat = fs.lstatSync(nodeRealPath);
  requireCondition(nodeStat.isFile() && !nodeStat.isSymbolicLink() &&
    (nodeStat.mode & 0o111) !== 0, code);
  const dependencies = runtimeTree(path.join(sourceRoot, "node_modules"),
    code, { skipRootBin: true });
  requireCondition(path.isAbsolute(homeDirectory ?? "") &&
    fs.realpathSync(homeDirectory) === homeDirectory &&
    fs.lstatSync(homeDirectory).isDirectory() &&
    fs.lstatSync(homeDirectory).uid === process.getuid(), code);
  return Object.freeze({
    schemaVersion: "prooftoact.one-time-bootstrap-runtime-execution.v1",
    awsCli: awsCliRuntimeBinding(awsCliPath),
    dependencies,
    homeDirectory,
    node: Object.freeze({
      architecture: process.arch,
      executableSha256: sha256(fs.readFileSync(nodeRealPath)),
      platform: process.platform,
      realPath: nodeRealPath,
      version: process.version
    })
  });
}

const TARGET_DEFINITIONS = Object.freeze({
  freshPrimaryBootstrapRole: Object.freeze({
    path: "infra/aws/fresh-primary-bootstrap-role-stack.json",
    stackName: "prooftoact-fresh-primary-bootstrap-role",
    purpose: "FreshPrimaryBootstrapRole",
    stackTagKeys: Object.freeze(["Project"]),
    parameterNames: Object.freeze(["GitHubOidcProviderArn"]),
    resources: Object.freeze({
      FreshPrimaryBootstrapRole: Object.freeze({
        type: "AWS::IAM::Role",
        physicalName: "ProofToActFreshPrimaryBootstrap"
      })
    })
  }),
  freshPrimaryCredentialCustody: Object.freeze({
    path: "infra/aws/fresh-primary-credential-custody-stack.json",
    stackNamePrefix: "prooftoact-fresh-primary-credential-custody-",
    purpose: "FreshPrimaryCredentialCustody",
    stackTagKeys: Object.freeze(["OperationId", "Project"]),
    parameterNames: Object.freeze([
      "BootstrapCreatorRoleArn",
      "CredentialSealExternalId",
      "OperationId",
      "OperationToken",
      "OperatorAuthorizationSha256",
      "SourceCommit",
      "TemplateSha256",
      "TreeDigest"
    ]),
    resources: Object.freeze({
      FreshClusterAuditorSecret: Object.freeze({
        type: "AWS::SecretsManager::Secret",
        secretName: "prooftoact/fresh-cluster/auditor"
      }),
      FreshPrimaryCloudApiSecret: Object.freeze({
        type: "AWS::SecretsManager::Secret",
        secretName: "prooftoact/fresh-primary/cloud-api"
      }),
      FreshPrimaryRuntimeCredentialsSecret: Object.freeze({
        type: "AWS::SecretsManager::Secret",
        secretName: "prooftoact/fresh-primary/runtime-credentials"
      }),
      ManagedMcpSecret: Object.freeze({
        type: "AWS::SecretsManager::Secret",
        secretName: "prooftoact/gate2/managed-mcp"
      }),
      RecoveryPublisherSecret: Object.freeze({
        type: "AWS::SecretsManager::Secret",
        secretName: "prooftoact/gate2/recovery-publisher"
      }),
      FreshPrimaryAdminSecret: Object.freeze({
        type: "AWS::SecretsManager::Secret",
        secretNamePrefix: "prooftoact/fresh-primary/admin-"
      }),
      FreshPrimaryRecoverySignerSecret: Object.freeze({
        type: "AWS::SecretsManager::Secret",
        secretNamePrefix: "prooftoact/fresh-primary/recovery-signer-"
      }),
      FreshPrimaryCredentialWriterRole: Object.freeze({
        type: "AWS::IAM::Role",
        physicalNamePrefix: "ProofToActFreshCredentialWriter-",
        path: ROLE_PATH
      })
    })
  }),
  privateRecoveryQueryBootstrap: Object.freeze({
    path: "infra/aws/private-recovery-query-bootstrap-role-stack.json",
    stackName: "prooftoact-private-recovery-query-bootstrap",
    purpose: "PrivateRecoveryQueryBootstrap",
    stackTagKeys: Object.freeze(["Project"]),
    parameterNames: Object.freeze([
      "ArtifactBucketName",
      "DeploymentWorkflowCommit",
      "GitHubOidcProviderArn",
      "SecretSealWorkflowCommit"
    ]),
    resources: Object.freeze({
      PrivateRecoveryBoundary: Object.freeze({
        type: "AWS::IAM::ManagedPolicy",
        physicalName: "ProofToActPrivateRecoveryQueryBoundary"
      }),
      PrivateRecoveryMcpSecret: Object.freeze({
        type: "AWS::SecretsManager::Secret",
        secretName: "prooftoact/private-recovery-query/managed-mcp"
      }),
      PrivateRecoveryCloudFormationRole: Object.freeze({
        type: "AWS::IAM::Role",
        physicalName: "ProofToActPrivateRecoveryQueryCloudFormation"
      }),
      PrivateRecoveryDeploymentRole: Object.freeze({
        type: "AWS::IAM::Role",
        physicalName: "ProofToActPrivateRecoveryQueryDeployment"
      }),
      PrivateRecoverySecretSealerRole: Object.freeze({
        type: "AWS::IAM::Role",
        physicalName: "ProofToActPrivateRecoveryQuerySecretSealer"
      })
    })
  })
});

const TARGET_KEYS = Object.freeze(Object.keys(TARGET_DEFINITIONS));
const CONDITION_KEYS = Object.freeze(new Set([
  "aws:CalledVia",
  "aws:CurrentTime",
  "aws:MultiFactorAuthAge",
  "aws:MultiFactorAuthPresent",
  "aws:PrincipalArn",
  "aws:SourceIdentity",
  "aws:TagKeys",
  "cloudformation:ChangeSetName",
  "cloudformation:RoleArn",
  "cloudformation:StackPolicyUrl",
  "cloudformation:TemplateUrl",
  "iam:PermissionsBoundary",
  "sts:ExternalId",
  "sts:RoleSessionName",
  "sts:SourceIdentity"
]));
const SUPPORTED_CLOUDFORMATION_ACTIONS = Object.freeze(new Set([
  "cloudformation:CreateChangeSet",
  "cloudformation:CreateStack",
  "cloudformation:CreateStackInstances",
  "cloudformation:CreateStackSet",
  "cloudformation:DeleteStack",
  "cloudformation:DescribeChangeSet",
  "cloudformation:DescribeStackEvents",
  "cloudformation:DescribeStackResource",
  "cloudformation:DescribeStackResources",
  "cloudformation:DescribeStacks",
  "cloudformation:ExecuteChangeSet",
  "cloudformation:GetTemplate",
  "cloudformation:ImportStacksToStackSet",
  "cloudformation:ListChangeSets",
  "cloudformation:ListStackResources",
  "cloudformation:UpdateStack",
  "cloudformation:UpdateStackInstances",
  "cloudformation:UpdateStackSet",
  "cloudformation:UpdateTerminationProtection"
]));

const ROLE_MUTATION_ACTIONS = Object.freeze([
  "iam:CreateRole",
  "iam:DeleteRole",
  "iam:DeleteRolePolicy",
  "iam:PutRolePolicy",
  "iam:TagRole",
  "iam:UntagRole"
]);

const ROLE_METADATA_READ_ACTIONS = Object.freeze([
  "iam:GetRole",
  "iam:GetRolePolicy",
  "iam:ListAttachedRolePolicies",
  "iam:ListRolePolicies",
  "iam:ListRoleTags"
]);

const MANAGED_POLICY_MUTATION_ACTIONS = Object.freeze([
  "iam:CreatePolicy",
  "iam:DeletePolicy",
  "iam:TagPolicy",
  "iam:UntagPolicy"
]);

const MANAGED_POLICY_METADATA_READ_ACTIONS = Object.freeze([
  "iam:GetPolicy",
  "iam:GetPolicyVersion",
  "iam:ListEntitiesForPolicy",
  "iam:ListPolicyTags",
  "iam:ListPolicyVersions"
]);

const SECRET_CONTAINER_MUTATION_ACTIONS = Object.freeze([
  "secretsmanager:CreateSecret",
  "secretsmanager:DeleteSecret",
  "secretsmanager:TagResource",
  "secretsmanager:UntagResource"
]);

const SECRET_METADATA_READ_ACTIONS = Object.freeze([
  "secretsmanager:DescribeSecret",
  "secretsmanager:GetResourcePolicy",
  "secretsmanager:ListSecretVersionIds"
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

function exactKeys(value, keys) {
  return plainObject(value) &&
    Object.keys(value).sort().join("\n") === [...keys].sort().join("\n");
}

function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (plainObject(value)) {
    return Object.fromEntries(Object.keys(value).sort().map((key) =>
      [key, canonicalValue(value[key])]));
  }
  requireCondition(value === null || typeof value === "string" ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isSafeInteger(value)),
  "ONE_TIME_BOOTSTRAP_CANONICAL_VALUE_REJECTED");
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value));
}

function canonicalBytes(value) {
  return Buffer.from(`${canonicalJson(value)}\n`, "utf8");
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function digest(value) {
  return sha256(canonicalBytes(value));
}

function deepFreeze(value) {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function canonicalInstant(value, code) {
  requireCondition(typeof value === "string", code);
  const milliseconds = Date.parse(value);
  requireCondition(Number.isFinite(milliseconds) &&
    new Date(milliseconds).toISOString() === value, code);
  return milliseconds;
}

function checkedRegularFile(filePath, maximumBytes, code) {
  let descriptor;
  try {
    descriptor = fs.openSync(
      filePath,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW
    );
    const before = fs.fstatSync(descriptor);
    requireCondition(before.isFile() && !before.isSymbolicLink() &&
      before.nlink === 1 && before.size > 0 && before.size <= maximumBytes,
    code);
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor);
    const named = fs.lstatSync(filePath);
    requireCondition(bytes.length === before.size &&
      before.dev === after.dev && before.ino === after.ino &&
      before.mode === after.mode && before.size === after.size &&
      named.isFile() && !named.isSymbolicLink() && named.nlink === 1 &&
      named.dev === after.dev && named.ino === after.ino &&
      named.mode === after.mode && named.size === after.size, code);
    return bytes;
  } catch (error) {
    if (error?.message === code) throw error;
    reject(code, error);
  } finally {
    if (Number.isSafeInteger(descriptor)) fs.closeSync(descriptor);
  }
}

function gitEnvironment() {
  return {
    GIT_ATTR_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_NO_LAZY_FETCH: "1",
    GIT_NO_REPLACE_OBJECTS: "1",
    GIT_TERMINAL_PROMPT: "0",
    LANG: "C",
    LC_ALL: "C",
    PATH: "/usr/bin:/bin"
  };
}

function allowedGitCommand(argv) {
  const key = JSON.stringify(argv);
  const fixed = [
    ["rev-parse", "--show-toplevel"],
    ["rev-parse", "--git-dir"],
    ["rev-parse", "--is-bare-repository"],
    ["rev-parse", "HEAD"],
    ["rev-parse", "HEAD^{tree}"],
    ["symbolic-ref", "--quiet", "--short", "HEAD"],
    ["status", "--porcelain=v1", "--untracked-files=all"],
    ["remote", "get-url", "origin"]
  ];
  if (fixed.some((entry) => JSON.stringify(entry) === key)) return true;
  if (argv.length === 4 && argv[0] === "ls-files" &&
    argv[1] === "--error-unmatch" && argv[2] === "--") {
    return [PLANNER_PATH, ROOT_ASSUME_RUNTIME_PATH, CEREMONY_LAUNCHER_PATH,
      CEREMONY_RUNNER_PATH,
      ...RUNTIME_DEPENDENCY_PATHS,
      ...TARGET_KEYS.map((targetKey) =>
      TARGET_DEFINITIONS[targetKey].path)].includes(argv[3]);
  }
  if (argv.length === 2 && argv[0] === "show") {
    const match = /^([0-9a-f]{40}):(.+)$/u.exec(argv[1]);
    return match !== null && [PLANNER_PATH, ROOT_ASSUME_RUNTIME_PATH,
      CEREMONY_LAUNCHER_PATH, CEREMONY_RUNNER_PATH,
      ...RUNTIME_DEPENDENCY_PATHS,
      ...TARGET_KEYS.map((targetKey) => TARGET_DEFINITIONS[targetKey].path)]
      .includes(match[2]);
  }
  return argv.length === 4 && argv[0] === "merge-base" &&
    argv[1] === "--is-ancestor" && HEX_40.test(argv[2]) &&
    argv[3] === "HEAD";
}

function gitArguments(argv) {
  return [
    "-c", "core.attributesFile=/dev/null",
    "-c", "core.autocrlf=false",
    "-c", "core.eol=lf",
    "-c", "core.fsmonitor=false",
    "-c", "core.hooksPath=/dev/null",
    "-c", "core.untrackedCache=false",
    ...argv
  ];
}

function runReadOnlyGit(root, argv) {
  requireCondition(Array.isArray(argv) && allowedGitCommand(argv),
    "ONE_TIME_BOOTSTRAP_GIT_COMMAND_REJECTED");
  try {
    return execFileSync(
      "/usr/bin/git",
      gitArguments(argv),
      {
        cwd: root,
        encoding: "utf8",
        env: gitEnvironment(),
        stdio: ["ignore", "pipe", "pipe"]
      }
    ).trim();
  } catch (error) {
    reject("ONE_TIME_BOOTSTRAP_GIT_READ_REJECTED", error);
  }
}

function runReadOnlyGitBytes(root, argv) {
  requireCondition(Array.isArray(argv) && allowedGitCommand(argv),
    "ONE_TIME_BOOTSTRAP_GIT_COMMAND_REJECTED");
  try {
    return execFileSync("/usr/bin/git", gitArguments(argv), {
      cwd: root,
      encoding: null,
      env: gitEnvironment(),
      maxBuffer: 8 * 1024 * 1024,
      stdio: ["ignore", "pipe", "pipe"]
    });
  } catch (error) {
    reject("ONE_TIME_BOOTSTRAP_GIT_READ_REJECTED", error);
  }
}

function walk(value, visitor, pathParts = []) {
  visitor(value, pathParts);
  if (Array.isArray(value)) {
    value.forEach((child, index) => walk(child, visitor,
      [...pathParts, String(index)]));
  } else if (plainObject(value)) {
    for (const [key, child] of Object.entries(value)) {
      walk(child, visitor, [...pathParts, key]);
    }
  }
}

function intrinsicString(value, substitutions = {}) {
  if (typeof value === "string") return value;
  if (exactKeys(value, ["Fn::Sub"]) && typeof value["Fn::Sub"] === "string") {
    return value["Fn::Sub"].replace(/\$\{([^}]+)\}/gu,
      (match, key) => Object.hasOwn(substitutions, key) ?
        substitutions[key] : match);
  }
  return null;
}

function expectedResourceContract(targetKey, operationId, operationToken) {
  const definition = TARGET_DEFINITIONS[targetKey];
  return Object.entries(definition.resources).map(([logicalId, resource]) => {
    let physicalName = resource.physicalName ?? null;
    if (resource.physicalNamePrefix) {
      physicalName = `${resource.physicalNamePrefix}${operationToken}`;
    }
    let secretName = resource.secretName ?? null;
    if (resource.secretNamePrefix) {
      secretName = `${resource.secretNamePrefix}${operationId}`;
    }
    return {
      logicalId,
      path: resource.path ?? "/",
      physicalName,
      secretName,
      type: resource.type
    };
  }).sort((left, right) => left.logicalId.localeCompare(right.logicalId));
}

function validateRoleResource(targetKey, logicalId, resource,
  expected, operationToken) {
  const code = "ONE_TIME_BOOTSTRAP_TARGET_ROLE_REJECTED";
  const properties = resource.Properties;
  requireCondition(plainObject(properties) &&
    Array.isArray(properties.ManagedPolicyArns) &&
    properties.ManagedPolicyArns.length === 0 &&
    Array.isArray(properties.Policies) && properties.Policies.length > 0,
  code);
  const roleName = intrinsicString(properties.RoleName, {
    OperationToken: operationToken
  });
  requireCondition(roleName === expected.physicalName &&
    (properties.Path ?? "/") === expected.path, code);
  if (targetKey === "freshPrimaryCredentialCustody" &&
    logicalId === "FreshPrimaryCredentialWriterRole") {
    const statements = properties.AssumeRolePolicyDocument?.Statement;
    requireCondition(Array.isArray(statements) && statements.length === 1,
      code);
    const statement = statements[0];
    requireCondition(statement.Effect === "Allow" &&
      canonicalJson(statement.Principal) === canonicalJson({
        AWS: { Ref: "BootstrapCreatorRoleArn" }
      }) && statement.Action === "sts:AssumeRole" &&
      canonicalJson(statement.Condition) === canonicalJson({
        StringEquals: {
          "sts:ExternalId": { Ref: "CredentialSealExternalId" },
          "sts:RoleSessionName": {
            "Fn::Sub": "prooftoact-credential-seal-${OperationToken}"
          }
        }
      }), code);
    requireCondition(Array.isArray(properties.Tags) &&
      properties.Tags.some((tag) => canonicalJson(tag) === canonicalJson({
        Key: "OperatorAuthorizationSha256",
        Value: { Ref: "OperatorAuthorizationSha256" }
      })), code);
  }
  if (targetKey === "privateRecoveryQueryBootstrap" &&
    logicalId === "PrivateRecoveryCloudFormationRole") {
    requireCondition(canonicalJson(properties.PermissionsBoundary) ===
      canonicalJson({ Ref: "PrivateRecoveryBoundary" }), code);
  }
}

function validateTargetTemplate(targetKey, bytes, expectedSha256,
  operationId, operationToken) {
  const code = "ONE_TIME_BOOTSTRAP_TARGET_TEMPLATE_REJECTED";
  requireCondition(Buffer.isBuffer(bytes) && bytes.length <= 51_200 &&
    HEX_64.test(expectedSha256) && sha256(bytes) === expectedSha256, code);
  let template;
  try {
    template = JSON.parse(bytes.toString("utf8"));
  } catch (error) {
    reject(code, error);
  }
  requireCondition(plainObject(template) &&
    template.AWSTemplateFormatVersion === "2010-09-09" &&
    !Object.hasOwn(template, "Transform") && plainObject(template.Parameters) &&
    plainObject(template.Resources), code);
  const definition = TARGET_DEFINITIONS[targetKey];
  requireCondition(Object.keys(template.Parameters).sort().join("\n") ===
    [...definition.parameterNames].sort().join("\n") &&
    Object.keys(template.Resources).sort().join("\n") ===
    Object.keys(definition.resources).sort().join("\n"), code);
  if (targetKey === "privateRecoveryQueryBootstrap") {
    const commitParameter = {
      Type: "String",
      AllowedPattern: "^[0-9a-f]{40}$"
    };
    requireCondition(canonicalJson(
      template.Parameters.DeploymentWorkflowCommit
    ) === canonicalJson(commitParameter) && canonicalJson(
      template.Parameters.SecretSealWorkflowCommit
    ) === canonicalJson(commitParameter), code);
    const expectedWorkflowRefs = {
      PrivateRecoveryDeploymentRole: {
        "Fn::Sub": "Flash-Bri/prooftoact/.github/workflows/" +
          "prooftoact-sealed-private-recovery-deploy.yml@" +
          "${DeploymentWorkflowCommit}"
      },
      PrivateRecoverySecretSealerRole: {
        "Fn::Sub": "Flash-Bri/prooftoact/.github/workflows/" +
          "prooftoact-sealed-private-recovery-secret-seal.yml@" +
          "${SecretSealWorkflowCommit}"
      }
    };
    for (const [logicalId, expectedWorkflowRef] of
      Object.entries(expectedWorkflowRefs)) {
      const statements = template.Resources[logicalId]?.Properties
        ?.AssumeRolePolicyDocument?.Statement;
      requireCondition(Array.isArray(statements) && statements.length === 1 &&
        canonicalJson(statements[0]?.Condition?.StringEquals?.[
          "token.actions.githubusercontent.com:job_workflow_ref"
        ]) === canonicalJson(expectedWorkflowRef), code);
    }
  }
  walk(template, (value, parts) => {
    const key = parts.at(-1);
    requireCondition(!["GenerateSecretString", "SecretBinary", "SecretString",
      "TemplateURL", "TemplateUrl"].includes(key), code);
    if (key === "Type" && typeof value === "string") {
      requireCondition(!value.startsWith("Custom::") &&
        value !== "AWS::CloudFormation::CustomResource" &&
        value !== "AWS::CloudFormation::Stack", code);
    }
  });
  const expectedResources = expectedResourceContract(
    targetKey,
    operationId,
    operationToken
  );
  for (const expected of expectedResources) {
    const resource = template.Resources[expected.logicalId];
    requireCondition(plainObject(resource) && resource.Type === expected.type,
      code);
    if (expected.type === "AWS::IAM::Role") {
      validateRoleResource(targetKey, expected.logicalId, resource,
        expected, operationToken);
    } else if (expected.type === "AWS::IAM::ManagedPolicy") {
      requireCondition(intrinsicString(
        resource.Properties?.ManagedPolicyName
      ) === expected.physicalName &&
        plainObject(resource.Properties?.PolicyDocument), code);
    } else if (expected.type === "AWS::SecretsManager::Secret") {
      const name = intrinsicString(resource.Properties?.Name, {
        OperationId: operationId
      });
      requireCondition(name === expected.secretName, code);
      if ([
        "freshPrimaryCredentialCustody",
        "privateRecoveryQueryBootstrap"
      ].includes(targetKey)) {
        requireCondition(resource.DeletionPolicy === "Retain" &&
          resource.UpdateReplacePolicy === "Retain", code);
      }
    }
  }
  return deepFreeze({
    bytes: bytes.length,
    resourceContract: expectedResources,
    resourceCount: expectedResources.length,
    sha256: expectedSha256
  });
}

export function operationTokenFor(operationId) {
  requireCondition(typeof operationId === "string" && UUID.test(operationId),
    "ONE_TIME_BOOTSTRAP_OPERATION_ID_REJECTED");
  return sha256(Buffer.from(
    `prooftoact-fresh-primary-credential-writer-v1\n${operationId}\n`,
    "utf8"
  )).slice(0, 16);
}

export function cleanupOnlyAuthorizationContract({
  accountId,
  beginsAt,
  expiresAt,
  operationId
}) {
  const code = "ONE_TIME_BOOTSTRAP_CLEANUP_AUTHORIZATION_REJECTED";
  const begins = Date.parse(beginsAt);
  const expires = Date.parse(expiresAt);
  requireCondition(ACCOUNT_ID.test(accountId ?? "") &&
    UUID.test(operationId ?? "") && Number.isFinite(begins) &&
    Number.isFinite(expires) && new Date(begins).toISOString() === beginsAt &&
    new Date(expires).toISOString() === expiresAt && begins < expires &&
    expires - begins === MAX_CLEANUP_WINDOW_MS, code);
  const operationToken = operationTokenFor(operationId);
  const bootstrapRoleName = `ProofToActBootstrapCreator-${operationToken}`;
  return deepFreeze({
    schemaVersion: "prooftoact.one-time-bootstrap-cleanup-authorization.v2",
    mode: "RECONCILE_ONLY",
    beginsAt,
    expiresAt,
    bootstrapRoleArn: `arn:aws:iam::${accountId}:role${ROLE_PATH}` +
      bootstrapRoleName,
    bootstrapRoleName,
    inlinePolicyName: `ProofToActBootstrapCreatorOnly-${operationToken}`,
    exactMutationActions: ["iam:DeleteRolePolicy", "iam:DeleteRole"],
    exactReadbackActions: [
      "cloudformation:DescribeStacks", "cloudformation:GetTemplate",
      "cloudformation:ListChangeSets", "cloudtrail:LookupEvents",
      "iam:GetRole", "iam:GetRolePolicy",
      "iam:ListAttachedRolePolicies", "iam:ListRolePolicies",
      "iam:ListRoleTags", "secretsmanager:DescribeSecret",
      "secretsmanager:ListSecretVersionIds", "sts:GetCallerIdentity",
      "aws:Logout"
    ],
    existingAcceptedJournalRequired: true,
    acceptedCompletionOrAbandonedPartialDispositionRequired: true,
    acceptedCompletionReceiptRequiredForCompletedExecution: true,
    abandonedPartialDispositionRequiredForIncompleteExecution: true,
    createUpdateSealOrProviderMutationAuthorized: false,
    newSessionAssumptionAuthorized: false
  });
}

export function rootLoginProfileMetadataSha256({
  configuredRegion,
  effectiveRegion,
  loginSessionArn,
  profile
}) {
  requireCondition(PROFILE_NAME.test(profile ?? "") &&
    (configuredRegion === null || configuredRegion === REGION) &&
    effectiveRegion === REGION &&
    /^arn:aws:iam::[0-9]{12}:root$/u.test(loginSessionArn ?? ""),
  "ONE_TIME_BOOTSTRAP_ROOT_PROFILE_METADATA_REJECTED");
  return digest({ configuredRegion, effectiveRegion, loginSessionArn, profile });
}

function exactStackName(targetKey, operationId) {
  const definition = TARGET_DEFINITIONS[targetKey];
  return definition.stackName ?? `${definition.stackNamePrefix}${operationId}`;
}

function exactChangeSetName(targetKey, operationToken) {
  const suffixes = {
    freshPrimaryBootstrapRole: "fresh-primary-role",
    freshPrimaryCredentialCustody: "fresh-primary-custody",
    privateRecoveryQueryBootstrap: "private-recovery-query-bootstrap"
  };
  return `prooftoact-b0-${operationToken}-${suffixes[targetKey]}`;
}

function validateTargetDigestInput(value) {
  requireCondition(exactKeys(value, TARGET_KEYS) &&
    TARGET_KEYS.every((key) => HEX_64.test(value[key] ?? "")),
  "ONE_TIME_BOOTSTRAP_TARGET_DIGEST_INPUT_REJECTED");
}

function validatePrivateRecoveryWorkflowCommits(value) {
  requireCondition(exactKeys(value, PRIVATE_RECOVERY_WORKFLOW_KEYS) &&
    PRIVATE_RECOVERY_WORKFLOW_KEYS.every((key) =>
      HEX_40.test(value[key] ?? "") && value[key] !== "0".repeat(40)),
  "ONE_TIME_BOOTSTRAP_WORKFLOW_COMMIT_INPUT_REJECTED");
  return value;
}

export function buildOneTimeBootstrapCostReconciliationReceipt({
  accountId,
  operationId,
  pricingObservedAt,
  pricingSourceSha256,
  sourceCommit,
  targetTemplateSha256,
  treeDigest
}) {
  const code = "ONE_TIME_BOOTSTRAP_COST_RECONCILIATION_REJECTED";
  requireCondition(ACCOUNT_ID.test(accountId ?? "") &&
    UUID.test(operationId ?? "") && HEX_40.test(sourceCommit ?? "") &&
    sourceCommit !== "0".repeat(40) && HEX_40.test(treeDigest ?? "") &&
    treeDigest !== "0".repeat(40), code);
  canonicalInstant(pricingObservedAt, code);
  validateTargetDigestInput(targetTemplateSha256);
  requireCondition(exactKeys(pricingSourceSha256, [
    "awsSecretsManager", "cockroachBasic"
  ]) && Object.values(pricingSourceSha256).every((value) =>
    HEX_64.test(value ?? "")), code);
  const body = {
    schemaVersion: "prooftoact.b0-a1-cost-reconciliation.v1",
    status: "ITEMIZED_EXACT_RESOURCE_ENVELOPE_REVIEWED",
    accountId,
    operationId,
    sourceCommit,
    treeDigest,
    targetTemplateSetSha256: digest(Object.fromEntries(
      TARGET_KEYS.map((key) => [key, targetTemplateSha256[key]])
    )),
    pricingObservedAt,
    pricingSourceSha256: {
      awsSecretsManager: pricingSourceSha256.awsSecretsManager,
      cockroachBasic: pricingSourceSha256.cockroachBasic
    },
    currency: "USD",
    freeBenefitsAssumed: false,
    lineItems: COST_RECONCILIATION_LINE_ITEMS.map((item) => ({ ...item })),
    awsMonthlyResidualCeilingUsdCents: 350,
    cockroachPaidWorstCaseMonthlyUsdCents: 150,
    combinedMonthlyCeilingUsdCents: 500
  };
  return deepFreeze({ ...body, receiptSha256: digest(body) });
}

function validateReconciledCostCeiling(value, binding = null) {
  const code = "ONE_TIME_BOOTSTRAP_COST_CEILING_REJECTED";
  requireCondition(exactKeys(value, [
    "currency",
    "maximumMonthlyUsdCents",
    "maximumOneTimeUsdCents",
    "reconciliationReceipt",
    "reconciliationReceiptSha256"
  ]) && value.currency === "USD" &&
    Number.isSafeInteger(value.maximumMonthlyUsdCents) &&
    value.maximumMonthlyUsdCents ===
      EXACT_MONTHLY_AUTHORIZATION_USD_CENTS &&
    Number.isSafeInteger(value.maximumOneTimeUsdCents) &&
    value.maximumOneTimeUsdCents ===
      EXACT_ONE_TIME_AUTHORIZATION_USD_CENTS &&
    HEX_64.test(value.reconciliationReceiptSha256 ?? ""), code);
  const receipt = value.reconciliationReceipt;
  requireCondition(plainObject(receipt) && exactKeys(receipt, [
    "accountId", "awsMonthlyResidualCeilingUsdCents",
    "cockroachPaidWorstCaseMonthlyUsdCents",
    "combinedMonthlyCeilingUsdCents", "currency", "freeBenefitsAssumed",
    "lineItems", "operationId", "pricingObservedAt", "pricingSourceSha256",
    "receiptSha256", "schemaVersion", "sourceCommit", "status",
    "targetTemplateSetSha256", "treeDigest"
  ]) && receipt.schemaVersion ===
      "prooftoact.b0-a1-cost-reconciliation.v1" &&
    receipt.status === "ITEMIZED_EXACT_RESOURCE_ENVELOPE_REVIEWED" &&
    receipt.currency === "USD" && receipt.freeBenefitsAssumed === false &&
    receipt.awsMonthlyResidualCeilingUsdCents === 350 &&
    receipt.cockroachPaidWorstCaseMonthlyUsdCents === 150 &&
    receipt.combinedMonthlyCeilingUsdCents === 500 &&
    receipt.awsMonthlyResidualCeilingUsdCents +
      receipt.cockroachPaidWorstCaseMonthlyUsdCents ===
        receipt.combinedMonthlyCeilingUsdCents &&
    canonicalJson(receipt.lineItems) ===
      canonicalJson(COST_RECONCILIATION_LINE_ITEMS) &&
    receipt.lineItems.filter(({ resourceClass }) =>
      resourceClass.startsWith("AWS_")).reduce((sum, item) =>
      sum + item.monthlyUsdCents, 0) === 350 &&
    receipt.lineItems.reduce((sum, item) =>
      sum + item.monthlyUsdCents, 0) === 500 &&
    exactKeys(receipt.pricingSourceSha256, [
      "awsSecretsManager", "cockroachBasic"
    ]) && Object.values(receipt.pricingSourceSha256).every((item) =>
      HEX_64.test(item ?? "")) &&
    ACCOUNT_ID.test(receipt.accountId ?? "") &&
    UUID.test(receipt.operationId ?? "") &&
    HEX_40.test(receipt.sourceCommit ?? "") &&
    receipt.sourceCommit !== "0".repeat(40) &&
    HEX_40.test(receipt.treeDigest ?? "") &&
    receipt.treeDigest !== "0".repeat(40) &&
    HEX_64.test(receipt.targetTemplateSetSha256 ?? "") &&
    canonicalInstant(receipt.pricingObservedAt, code) >= 0 &&
    receipt.receiptSha256 === digest(Object.fromEntries(
      Object.entries(receipt).filter(([key]) => key !== "receiptSha256")
    )) && value.reconciliationReceiptSha256 === receipt.receiptSha256,
  code);
  if (binding !== null) {
    requireCondition(plainObject(binding) &&
      receipt.accountId === binding.accountId &&
      receipt.operationId === binding.operationId &&
      receipt.sourceCommit === binding.sourceCommit &&
      receipt.treeDigest === binding.treeDigest &&
      receipt.targetTemplateSetSha256 === digest(Object.fromEntries(
        TARGET_KEYS.map((key) => [key, binding.targetTemplateSha256?.[key]])
      )), code);
    const maximumObservedAt = canonicalInstant(binding.maximumObservedAt,
      code);
    const pricingObservedAt = Date.parse(receipt.pricingObservedAt);
    requireCondition(pricingObservedAt <= maximumObservedAt &&
      maximumObservedAt - pricingObservedAt <=
        COST_RECONCILIATION_MAXIMUM_AGE_MS,
    code);
  }
  return value;
}

function validateRuntimeTreeReceipt(value, code) {
  requireCondition(exactKeys(value, [
    "fileCount", "recordCount", "totalBytes", "treeDigest"
  ]) && Number.isSafeInteger(value.fileCount) && value.fileCount >= 0 &&
    Number.isSafeInteger(value.recordCount) &&
    value.recordCount >= value.fileCount &&
    Number.isSafeInteger(value.totalBytes) && value.totalBytes >= 0 &&
    HEX_64.test(value.treeDigest ?? ""), code);
  return value;
}

function validateRuntimeExecutionBinding(value) {
  const code = "ONE_TIME_BOOTSTRAP_RUNTIME_EXECUTION_REJECTED";
  requireCondition(exactKeys(value, [
    "awsCli", "dependencies", "homeDirectory", "node", "schemaVersion"
  ]) && value.schemaVersion ===
    "prooftoact.one-time-bootstrap-runtime-execution.v1" &&
    path.isAbsolute(value.homeDirectory ?? ""), code);
  requireCondition(exactKeys(value.node, [
    "architecture", "executableSha256", "platform", "realPath", "version"
  ]) && typeof value.node.architecture === "string" &&
    typeof value.node.platform === "string" &&
    typeof value.node.version === "string" &&
    path.isAbsolute(value.node.realPath ?? "") &&
    HEX_64.test(value.node.executableSha256 ?? ""), code);
  requireCondition(exactKeys(value.awsCli, [
    "entrySha256", "fileCount", "realPath", "recordCount", "requestedPath",
    "runtimeRoot", "totalBytes", "treeDigest"
  ]) && path.isAbsolute(value.awsCli.requestedPath ?? "") &&
    path.isAbsolute(value.awsCli.realPath ?? "") &&
    path.isAbsolute(value.awsCli.runtimeRoot ?? "") &&
    HEX_64.test(value.awsCli.entrySha256 ?? ""), code);
  validateRuntimeTreeReceipt(Object.fromEntries(Object.entries(
    value.awsCli
  ).filter(([key]) => [
    "fileCount", "recordCount", "totalBytes", "treeDigest"
  ].includes(key))), code);
  validateRuntimeTreeReceipt(value.dependencies, code);
  return value;
}

export function validateOneTimeBootstrapCheckout({
  awsCliPath,
  expectedCommit,
  expectedTree,
  homeDirectory,
  operationId,
  privateRecoveryWorkflowCommits,
  sourceRoot,
  targetTemplateSha256
}) {
  const code = "ONE_TIME_BOOTSTRAP_CHECKOUT_REJECTED";
  requireCondition(typeof sourceRoot === "string" && sourceRoot.length > 0 &&
    typeof awsCliPath === "string" && path.isAbsolute(awsCliPath) &&
    typeof homeDirectory === "string" && path.isAbsolute(homeDirectory) &&
    HEX_40.test(expectedCommit ?? "") && HEX_40.test(expectedTree ?? "") &&
    UUID.test(operationId ?? ""), code);
  validateTargetDigestInput(targetTemplateSha256);
  validatePrivateRecoveryWorkflowCommits(privateRecoveryWorkflowCommits);
  const resolvedRoot = path.resolve(sourceRoot);
  let realRoot;
  let rootStat;
  let gitStat;
  try {
    realRoot = fs.realpathSync(resolvedRoot);
    rootStat = fs.lstatSync(resolvedRoot);
    gitStat = fs.lstatSync(path.join(resolvedRoot, ".git"));
  } catch (error) {
    reject(code, error);
  }
  requireCondition(realRoot === resolvedRoot && rootStat.isDirectory() &&
    !rootStat.isSymbolicLink() && gitStat.isDirectory() &&
    !gitStat.isSymbolicLink(), code);
  const identity = () => ({
    commit: runReadOnlyGit(resolvedRoot, ["rev-parse", "HEAD"]),
    status: runReadOnlyGit(resolvedRoot,
      ["status", "--porcelain=v1", "--untracked-files=all"]),
    tree: runReadOnlyGit(resolvedRoot, ["rev-parse", "HEAD^{tree}"])
  });
  requireCondition(runReadOnlyGit(resolvedRoot,
    ["rev-parse", "--show-toplevel"]) === resolvedRoot &&
    runReadOnlyGit(resolvedRoot, ["rev-parse", "--git-dir"]) === ".git" &&
    runReadOnlyGit(resolvedRoot,
      ["rev-parse", "--is-bare-repository"]) === "false" &&
    runReadOnlyGit(resolvedRoot,
      ["symbolic-ref", "--quiet", "--short", "HEAD"]) === "main" &&
    runReadOnlyGit(resolvedRoot, ["remote", "get-url", "origin"]) ===
      OFFICIAL_ORIGIN, code);
  const before = identity();
  requireCondition(before.commit === expectedCommit &&
    before.tree === expectedTree && before.status === "", code);
  const requiredPaths = [
    PLANNER_PATH,
    ROOT_ASSUME_RUNTIME_PATH,
    CEREMONY_LAUNCHER_PATH,
    CEREMONY_RUNNER_PATH,
    ...RUNTIME_DEPENDENCY_PATHS,
    ...TARGET_KEYS.map((targetKey) =>
    TARGET_DEFINITIONS[targetKey].path)];
  for (const relativePath of [...new Set(requiredPaths)].sort()) {
    requireCondition(runReadOnlyGit(resolvedRoot,
      ["ls-files", "--error-unmatch", "--", relativePath]) === relativePath,
    code);
  }
  const plannerBytes = checkedRegularFile(
    path.join(resolvedRoot, PLANNER_PATH),
    4 * 1024 * 1024,
    "ONE_TIME_BOOTSTRAP_PLANNER_FILE_REJECTED"
  );
  const executingBytes = checkedRegularFile(
    CURRENT_FILE,
    4 * 1024 * 1024,
    "ONE_TIME_BOOTSTRAP_PLANNER_FILE_REJECTED"
  );
  requireCondition(plannerBytes.equals(executingBytes),
    "ONE_TIME_BOOTSTRAP_PLANNER_IDENTITY_REJECTED");
  const rootAssumeRuntimeBytes = checkedRegularFile(
    path.join(resolvedRoot, ROOT_ASSUME_RUNTIME_PATH),
    512 * 1024,
    "ONE_TIME_BOOTSTRAP_ROOT_ASSUME_RUNTIME_REJECTED"
  );
  const ceremonyLauncherBytes = checkedRegularFile(
    path.join(resolvedRoot, CEREMONY_LAUNCHER_PATH),
    2 * 1024 * 1024,
    "ONE_TIME_BOOTSTRAP_CEREMONY_LAUNCHER_REJECTED"
  );
  const ceremonyRunnerBytes = checkedRegularFile(
    path.join(resolvedRoot, CEREMONY_RUNNER_PATH),
    2 * 1024 * 1024,
    "ONE_TIME_BOOTSTRAP_CEREMONY_RUNNER_REJECTED"
  );
  const runtimeDependencyInventory = [...new Set([
    PLANNER_PATH,
    ROOT_ASSUME_RUNTIME_PATH,
    CEREMONY_LAUNCHER_PATH,
    CEREMONY_RUNNER_PATH,
    ...RUNTIME_DEPENDENCY_PATHS
  ])].sort().map((relativePath) => {
    const bytes = checkedRegularFile(
      path.join(resolvedRoot, relativePath),
      8 * 1024 * 1024,
      "ONE_TIME_BOOTSTRAP_RUNTIME_DEPENDENCY_REJECTED"
    );
    const committedBytes = runReadOnlyGitBytes(resolvedRoot,
      ["show", `${before.commit}:${relativePath}`]);
    requireCondition(bytes.equals(committedBytes),
      "ONE_TIME_BOOTSTRAP_RUNTIME_DEPENDENCY_REJECTED");
    return Object.freeze({
      bytes: bytes.length,
      path: relativePath,
      sha256: sha256(bytes)
    });
  });
  const privateRecoveryWorkflowPins = Object.fromEntries(
    PRIVATE_RECOVERY_WORKFLOW_KEYS.map((key) => {
      const definition = PRIVATE_RECOVERY_WORKFLOW_DEFINITIONS[key];
      const commit = privateRecoveryWorkflowCommits[key];
      runReadOnlyGit(resolvedRoot,
        ["merge-base", "--is-ancestor", commit, "HEAD"]);
      const checkedOutBytes = checkedRegularFile(
        path.join(resolvedRoot, definition.path),
        2 * 1024 * 1024,
        "ONE_TIME_BOOTSTRAP_WORKFLOW_PIN_REJECTED"
      );
      const pinnedBytes = runReadOnlyGitBytes(resolvedRoot,
        ["show", `${commit}:${definition.path}`]);
      requireCondition(checkedOutBytes.equals(pinnedBytes),
        "ONE_TIME_BOOTSTRAP_WORKFLOW_PIN_REJECTED");
      return [key, Object.freeze({
        bytes: pinnedBytes.length,
        commit,
        parameterName: definition.parameterName,
        path: definition.path,
        sha256: sha256(pinnedBytes)
      })];
    })
  );
  const operationToken = operationTokenFor(operationId);
  const targets = {};
  for (const targetKey of TARGET_KEYS) {
    const definition = TARGET_DEFINITIONS[targetKey];
    const bytes = checkedRegularFile(
      path.join(resolvedRoot, definition.path),
      51_200,
      "ONE_TIME_BOOTSTRAP_TARGET_FILE_REJECTED"
    );
    targets[targetKey] = {
      path: definition.path,
      ...validateTargetTemplate(
        targetKey,
        bytes,
        targetTemplateSha256[targetKey],
        operationId,
        operationToken
      )
    };
  }
  const after = identity();
  requireCondition(canonicalJson(after) === canonicalJson(before), code);
  return deepFreeze({
    commit: before.commit,
    ceremonyLauncherSha256: sha256(ceremonyLauncherBytes),
    ceremonyRunnerSha256: sha256(ceremonyRunnerBytes),
    officialOrigin: OFFICIAL_ORIGIN,
    plannerSha256: sha256(plannerBytes),
    privateRecoveryWorkflowPins,
    rootAssumeRuntimeSha256: sha256(rootAssumeRuntimeBytes),
    runtimeDependencyInventory,
    runtimeExecutionBinding: runtimeExecutionBinding(
      resolvedRoot,
      awsCliPath,
      homeDirectory
    ),
    targets,
    tree: before.tree
  });
}

function tagObject(tags) {
  return Object.fromEntries(tags.map(({ Key, Value }) => [Key, Value]));
}

function stackTags(binding, targetKey, templateSha256) {
  void templateSha256;
  const values = {
    OperationId: binding.operationId,
    Project: "ProofToAct"
  };
  return TARGET_DEFINITIONS[targetKey].stackTagKeys.map((Key) => ({
    Key,
    Value: values[Key]
  }));
}

function roleTags(binding) {
  return [
    { Key: "NotAfter", Value: binding.notAfter },
    { Key: "OperationId", Value: binding.operationId },
    { Key: "OperationToken", Value: binding.operationToken },
    { Key: "Project", Value: "ProofToAct" },
    { Key: "Purpose", Value: "OneTimeBootstrapCreator" },
    { Key: "SourceCommit", Value: binding.sourceCommit },
    { Key: "TreeDigest", Value: binding.sourceTree },
    {
      Key: "UserAuthReceiptSha256",
      Value: binding.userAuthorizationReceiptSha256
    }
  ];
}

function sessionTags(binding) {
  return roleTags(binding).filter(({ Key }) => ![
    "NotAfter",
    "OperationToken"
  ].includes(Key));
}

function calledViaCondition() {
  return {
    "ForAllValues:StringEquals": {
      "aws:CalledVia": "cloudformation.amazonaws.com"
    },
    Null: { "aws:CalledVia": "false" }
  };
}

function cloudFormationArns(accountId, target) {
  return [
    `arn:aws:cloudformation:${REGION}:${accountId}:stack/` +
      `${target.stackName}/*`,
    `arn:aws:cloudformation:${REGION}:${accountId}:changeSet/` +
      `${target.changeSetName}/*`
  ];
}

function targetParameters(binding, targetKey, templateSha256) {
  if (targetKey === "freshPrimaryBootstrapRole") {
    return { GitHubOidcProviderArn: binding.githubOidcProviderArn };
  }
  if (targetKey === "freshPrimaryCredentialCustody") {
    return {
      BootstrapCreatorRoleArn: binding.bootstrapRoleArn,
      CredentialSealExternalId: binding.writerExternalId,
      OperationId: binding.operationId,
      OperationToken: binding.operationToken,
      OperatorAuthorizationSha256:
        binding.userAuthorizationReceiptSha256,
      SourceCommit: binding.sourceCommit,
      TemplateSha256: templateSha256,
      TreeDigest: binding.sourceTree
    };
  }
  return {
    ArtifactBucketName: binding.artifactBucketName,
    DeploymentWorkflowCommit:
      binding.privateRecoveryWorkflowCommits.deployment,
    GitHubOidcProviderArn: binding.githubOidcProviderArn,
    SecretSealWorkflowCommit:
      binding.privateRecoveryWorkflowCommits.secretSeal
  };
}

function roleResourceArns(accountId, operationToken) {
  return [
    `arn:aws:iam::${accountId}:role/ProofToActFreshPrimaryBootstrap`,
    `arn:aws:iam::${accountId}:role${ROLE_PATH}` +
      `ProofToActFreshCredentialWriter-${operationToken}`,
    `arn:aws:iam::${accountId}:role/` +
      "ProofToActPrivateRecoveryQueryCloudFormation",
    `arn:aws:iam::${accountId}:role/` +
      "ProofToActPrivateRecoveryQueryDeployment",
    `arn:aws:iam::${accountId}:role/` +
      "ProofToActPrivateRecoveryQuerySecretSealer"
  ];
}

function secretResourceArns(accountId, operationId) {
  const names = [
    "prooftoact/fresh-cluster/auditor",
    "prooftoact/fresh-primary/cloud-api",
    "prooftoact/fresh-primary/runtime-credentials",
    "prooftoact/gate2/managed-mcp",
    "prooftoact/gate2/recovery-publisher",
    `prooftoact/fresh-primary/admin-${operationId}`,
    `prooftoact/fresh-primary/recovery-signer-${operationId}`,
    "prooftoact/private-recovery-query/managed-mcp"
  ];
  return names.map((name) =>
    `arn:aws:secretsmanager:${REGION}:${accountId}:secret:${name}-??????`);
}

function validateConditionKeys(document) {
  const code = "ONE_TIME_BOOTSTRAP_IAM_CONDITION_KEY_REJECTED";
  walk(document, (value, parts) => {
    if (parts.at(-1) !== "Condition" || !plainObject(value)) return;
    for (const operatorValues of Object.values(value)) {
      requireCondition(plainObject(operatorValues), code);
      for (const key of Object.keys(operatorValues)) {
        requireCondition(CONDITION_KEYS.has(key) ||
          /^aws:(?:PrincipalTag|RequestTag)\/[A-Za-z0-9_.:/=+@-]+$/u
            .test(key), code);
      }
    }
  });
}

function validateSupportedCloudFormationActions(document) {
  const code = "ONE_TIME_BOOTSTRAP_CLOUDFORMATION_ACTION_REJECTED";
  for (const statement of document.Statement ?? []) {
    const actions = Array.isArray(statement.Action) ?
      statement.Action : [statement.Action];
    for (const action of actions) {
      if (typeof action === "string" && action.startsWith("cloudformation:")) {
        requireCondition(SUPPORTED_CLOUDFORMATION_ACTIONS.has(action), code);
      }
    }
  }
}

export function buildBootstrapRoleDocuments(binding) {
  const code = "ONE_TIME_BOOTSTRAP_ROLE_BINDING_REJECTED";
  requireCondition(exactKeys(binding, [
    "accountId",
    "artifactBucketName",
    "bootstrapRoleArn",
    "bootstrapRoleName",
    "githubOidcProviderArn",
    "notAfter",
    "operationId",
    "operationToken",
    "privateRecoveryWorkflowCommits",
    "sessionName",
    "sourceCommit",
    "sourceIdentity",
    "sourceTree",
    "targets",
    "userAuthorizationReceiptSha256",
    "writerExternalId",
    "writerRoleArn",
    "writerSessionName"
  ]) && ACCOUNT_ID.test(binding.accountId) && UUID.test(binding.operationId) &&
    HEX_40.test(binding.sourceCommit) && HEX_40.test(binding.sourceTree) &&
    HEX_64.test(binding.userAuthorizationReceiptSha256) &&
    exactKeys(binding.privateRecoveryWorkflowCommits,
      PRIVATE_RECOVERY_WORKFLOW_KEYS) &&
    PRIVATE_RECOVERY_WORKFLOW_KEYS.every((key) =>
      HEX_40.test(binding.privateRecoveryWorkflowCommits[key]) &&
      binding.privateRecoveryWorkflowCommits[key] !== "0".repeat(40)) &&
    HEX_64.test(binding.writerExternalId), code);
  const exactSessionTags = sessionTags(binding);
  const requestTagConditions = Object.fromEntries(exactSessionTags.map(
    ({ Key, Value }) => [`aws:RequestTag/${Key}`, Value]
  ));
  const trustPolicy = {
    Version: "2012-10-17",
    Statement: [{
      Sid: "RootMfaAssumesOneOperationSession",
      Effect: "Allow",
      Principal: { AWS: `arn:aws:iam::${binding.accountId}:root` },
      Action: ["sts:AssumeRole", "sts:SetSourceIdentity", "sts:TagSession"],
      Condition: {
        Bool: { "aws:MultiFactorAuthPresent": "true" },
        DateLessThan: { "aws:CurrentTime": binding.notAfter },
        "ForAllValues:StringEquals": {
          "aws:TagKeys": exactSessionTags.map(({ Key }) => Key)
        },
        NumericLessThanEquals: { "aws:MultiFactorAuthAge": "300" },
        StringEquals: {
          ...requestTagConditions,
          "aws:PrincipalArn": `arn:aws:iam::${binding.accountId}:root`,
          "sts:RoleSessionName": binding.sessionName,
          "sts:SourceIdentity": binding.sourceIdentity
        }
      }
    }]
  };
  const statements = [];
  for (const targetKey of TARGET_KEYS) {
    const target = binding.targets[targetKey];
    const tags = tagObject(target.tags);
    statements.push({
      Sid: `Create${TARGET_DEFINITIONS[targetKey].purpose}ChangeSet`,
      Effect: "Allow",
      Action: "cloudformation:CreateChangeSet",
      Resource: cloudFormationArns(binding.accountId, target),
      Condition: {
        DateLessThan: { "aws:CurrentTime": binding.notAfter },
        "ForAllValues:StringEquals": {
          "aws:TagKeys": Object.keys(tags).sort()
        },
        Null: {
          "cloudformation:RoleArn": "true",
          "cloudformation:StackPolicyUrl": "true",
          "cloudformation:TemplateUrl": "true"
        },
        StringEquals: {
          ...Object.fromEntries(Object.entries(tags).map(([key, value]) =>
            [`aws:RequestTag/${key}`, value])),
          "cloudformation:ChangeSetName": target.changeSetName
        }
      }
    });
  }
  const allCloudFormationArns = TARGET_KEYS.flatMap((targetKey) =>
    cloudFormationArns(binding.accountId, binding.targets[targetKey]));
  const stackArns = TARGET_KEYS.map((targetKey) =>
    cloudFormationArns(binding.accountId, binding.targets[targetKey])[0]);
  statements.push({
    Sid: "DescribeAndExecuteExactBootstrapChangeSets",
    Effect: "Allow",
    Action: [
      "cloudformation:DescribeChangeSet",
      "cloudformation:ExecuteChangeSet",
      "cloudformation:GetTemplate"
    ],
    Resource: allCloudFormationArns,
    Condition: { DateLessThan: { "aws:CurrentTime": binding.notAfter } }
  }, {
    Sid: "ReadBackExactBootstrapStacks",
    Effect: "Allow",
    Action: [
      "cloudformation:DescribeStackEvents",
      "cloudformation:DescribeStackResource",
      "cloudformation:DescribeStackResources",
      "cloudformation:DescribeStacks",
      "cloudformation:GetTemplate",
      "cloudformation:ListChangeSets",
      "cloudformation:ListStackResources"
    ],
    Resource: stackArns,
    Condition: { DateLessThan: { "aws:CurrentTime": binding.notAfter } }
  }, {
    Sid: "EnableTerminationProtectionOnExactBootstrapStacks",
    Effect: "Allow",
    Action: "cloudformation:UpdateTerminationProtection",
    Resource: stackArns,
    Condition: { DateLessThan: { "aws:CurrentTime": binding.notAfter } }
  }, {
    Sid: "CreateOnlyExactBootstrapRolesViaCloudFormation",
    Effect: "Allow",
    Action: ROLE_MUTATION_ACTIONS,
    Resource: roleResourceArns(binding.accountId, binding.operationToken),
    Condition: {
      ...calledViaCondition(),
      DateLessThan: { "aws:CurrentTime": binding.notAfter }
    }
  }, {
    Sid: "PutExactA2CloudFormationRoleBoundaryViaCloudFormation",
    Effect: "Allow",
    Action: "iam:PutRolePermissionsBoundary",
    Resource: `arn:aws:iam::${binding.accountId}:role/` +
      "ProofToActPrivateRecoveryQueryCloudFormation",
    Condition: {
      ...calledViaCondition(),
      DateLessThan: { "aws:CurrentTime": binding.notAfter },
      StringEquals: {
        "iam:PermissionsBoundary": `arn:aws:iam::${binding.accountId}:policy/` +
          "ProofToActPrivateRecoveryQueryBoundary"
      }
    }
  }, {
    Sid: "CreateOnlyExactBootstrapBoundaryViaCloudFormation",
    Effect: "Allow",
    Action: MANAGED_POLICY_MUTATION_ACTIONS,
    Resource: `arn:aws:iam::${binding.accountId}:policy/` +
      "ProofToActPrivateRecoveryQueryBoundary",
    Condition: {
      ...calledViaCondition(),
      DateLessThan: { "aws:CurrentTime": binding.notAfter }
    }
  }, {
    Sid: "CreateOnlyEmptyCredentialContainersViaCloudFormation",
    Effect: "Allow",
    Action: SECRET_CONTAINER_MUTATION_ACTIONS,
    Resource: secretResourceArns(binding.accountId, binding.operationId),
    Condition: {
      ...calledViaCondition(),
      DateLessThan: { "aws:CurrentTime": binding.notAfter }
    }
  }, {
    Sid: "ReadExactBootstrapRoleMetadata",
    Effect: "Allow",
    Action: ROLE_METADATA_READ_ACTIONS,
    Resource: roleResourceArns(binding.accountId, binding.operationToken),
    Condition: { DateLessThan: { "aws:CurrentTime": binding.notAfter } }
  }, {
    Sid: "ReadExactBootstrapBoundaryMetadata",
    Effect: "Allow",
    Action: MANAGED_POLICY_METADATA_READ_ACTIONS,
    Resource: `arn:aws:iam::${binding.accountId}:policy/` +
      "ProofToActPrivateRecoveryQueryBoundary",
    Condition: { DateLessThan: { "aws:CurrentTime": binding.notAfter } }
  }, {
    Sid: "ReadExactBootstrapSecretMetadataNeverValues",
    Effect: "Allow",
    Action: SECRET_METADATA_READ_ACTIONS,
    Resource: secretResourceArns(binding.accountId, binding.operationId),
    Condition: { DateLessThan: { "aws:CurrentTime": binding.notAfter } }
  }, {
    Sid: "ReadExactExistingOidcProviderMetadata",
    Effect: "Allow",
    Action: "iam:GetOpenIDConnectProvider",
    Resource: binding.githubOidcProviderArn,
    Condition: { DateLessThan: { "aws:CurrentTime": binding.notAfter } }
  }, {
    Sid: "SimulateOnlyOwnTemporaryBootstrapRole",
    Effect: "Allow",
    Action: "iam:SimulatePrincipalPolicy",
    Resource: binding.bootstrapRoleArn,
    Condition: { DateLessThan: { "aws:CurrentTime": binding.notAfter } }
  }, {
    Sid: "AssumeOnlyExactA1CredentialWriter",
    Effect: "Allow",
    Action: "sts:AssumeRole",
    Resource: binding.writerRoleArn,
    Condition: {
      DateLessThan: { "aws:CurrentTime": binding.notAfter },
      StringEquals: {
        "aws:PrincipalTag/OperationId": binding.operationId,
        "aws:PrincipalTag/Project": "ProofToAct",
        "aws:SourceIdentity": binding.sourceIdentity,
        "sts:ExternalId": binding.writerExternalId,
        "sts:RoleSessionName": binding.writerSessionName
      }
    }
  }, {
    Sid: "ReadOwnCallerIdentity",
    Effect: "Allow",
    Action: "sts:GetCallerIdentity",
    Resource: "*",
    Condition: { DateLessThan: { "aws:CurrentTime": binding.notAfter } }
  }, {
    Sid: "DenyAnyOtherRoleAssumption",
    Effect: "Deny",
    Action: "sts:AssumeRole",
    NotResource: binding.writerRoleArn
  }, {
    Sid: "DenySecretValueAuthority",
    Effect: "Deny",
    Action: [
      "secretsmanager:BatchGetSecretValue",
      "secretsmanager:GetSecretValue",
      "secretsmanager:PutSecretValue"
    ],
    Resource: "*"
  }, {
    Sid: "DenyDirectPermissionsBoundaryMutation",
    Effect: "Deny",
    Action: "iam:PutRolePermissionsBoundary",
    Resource: "*",
    Condition: { Null: { "aws:CalledVia": "true" } }
  }, {
    Sid: "DenyPassRole",
    Effect: "Deny",
    Action: "iam:PassRole",
    Resource: "*"
  }, {
    Sid: "DenyWorkloadAndArtifactServices",
    Effect: "Deny",
    Action: [
      "apigateway:*",
      "apigatewayv2:*",
      "bedrock:*",
      "dynamodb:*",
      "ec2:*",
      "ecs:*",
      "eks:*",
      "execute-api:*",
      "lambda:*",
      "logs:*",
      "rds:*",
      "s3:*",
      "sns:*",
      "sqs:*"
    ],
    Resource: "*"
  }, {
    Sid: "DenyDirectStackLifecycle",
    Effect: "Deny",
    Action: [
      "cloudformation:CreateStack",
      "cloudformation:CreateStackInstances",
      "cloudformation:CreateStackSet",
      "cloudformation:DeleteStack",
      "cloudformation:ImportStacksToStackSet",
      "cloudformation:UpdateStack",
      "cloudformation:UpdateStackInstances",
      "cloudformation:UpdateStackSet"
    ],
    Resource: "*"
  }, {
    Sid: "DenyUseAfterOperationDeadline",
    Effect: "Deny",
    Action: "*",
    Resource: "*",
    Condition: {
      DateGreaterThanEquals: { "aws:CurrentTime": binding.notAfter }
    }
  });
  const inlinePolicy = {
    Version: "2012-10-17",
    Statement: statements.map(({ Sid: _sid, ...statement }) => {
      if (statement.Effect !== "Allow" || !statement.Condition?.DateLessThan) {
        return statement;
      }
      const condition = { ...statement.Condition };
      delete condition.DateLessThan;
      return Object.keys(condition).length === 0 ?
        Object.fromEntries(Object.entries(statement).filter(
          ([key]) => key !== "Condition"
        )) : { ...statement, Condition: condition };
    })
  };
  validateConditionKeys(trustPolicy);
  validateConditionKeys(inlinePolicy);
  validateSupportedCloudFormationActions(inlinePolicy);
  requireCondition(!canonicalJson(inlinePolicy).includes("sts:DurationSeconds") &&
    !canonicalJson(inlinePolicy).includes("cloudformation:ChangeSetType") &&
    Buffer.byteLength(canonicalJson(inlinePolicy), "utf8") <=
      INLINE_POLICY_MAX_NON_WHITESPACE_BYTES,
  "ONE_TIME_BOOTSTRAP_INLINE_POLICY_SIZE_REJECTED");
  return deepFreeze({ inlinePolicy, trustPolicy });
}

function writerExternalIdFor(binding, custodyTemplateSha256) {
  return sha256(Buffer.from(
    "prooftoact-fresh-primary-credential-seal-external-id-v1\n" +
    `${binding.accountId}\n${binding.operationId}\n` +
    `${binding.operationToken}\n` +
    `${binding.userAuthorizationReceiptSha256}\n` +
    `${binding.sourceCommit}\n${binding.sourceTree}\n` +
    `${custodyTemplateSha256}\n`,
    "utf8"
  ));
}

function planBodySha256(plan) {
  const body = { ...plan };
  delete body.planBodySha256;
  return digest(body);
}

export function verifyOneTimeBootstrapPlan(plan) {
  const code = "ONE_TIME_BOOTSTRAP_PLAN_INTEGRITY_REJECTED";
  requireCondition(plainObject(plan) && HEX_64.test(plan.planBodySha256 ?? "") &&
    plan.planBodySha256 === planBodySha256(plan) &&
    plan.schemaVersion === "prooftoact.one-time-bootstrap-authority-plan.v1" &&
    plan.status === "SOURCE_REVIEWED_CEREMONY_PLAN" &&
    plan.directProviderExecutionPerformed === false &&
    plan.authorization?.activationStatus ===
      "HOLD_PENDING_EXACT_350_CENT_MONTHLY_AWS_AND_500_CENT_ONE_TIME_AUTHORIZATION_AND_LIVE_READBACK" &&
    canonicalJson(plan.authorization?.cleanupOnlyAuthorization) ===
      canonicalJson(cleanupOnlyAuthorizationContract({
        accountId: plan.account?.accountId,
        beginsAt: plan.notAfter,
        expiresAt: new Date(Date.parse(plan.notAfter) +
          MAX_CLEANUP_WINDOW_MS).toISOString(),
        operationId: plan.operation?.operationId
      })) &&
    plan.sessionContract?.durationSeconds === SESSION_DURATION_SECONDS,
  code);
  validateReconciledCostCeiling(plan.costCeiling, {
    accountId: plan.account?.accountId,
    maximumObservedAt: plan.preparedAt,
    operationId: plan.operation?.operationId,
    sourceCommit: plan.source?.commit,
    targetTemplateSha256: Object.fromEntries(TARGET_KEYS.map((key) =>
      [key, plan.targets?.[key]?.templateSha256])),
    treeDigest: plan.source?.tree
  });
  const pins = plan.source?.privateRecoveryWorkflowPins;
  requireCondition(exactKeys(pins, PRIVATE_RECOVERY_WORKFLOW_KEYS) &&
    PRIVATE_RECOVERY_WORKFLOW_KEYS.every((key) => {
      const definition = PRIVATE_RECOVERY_WORKFLOW_DEFINITIONS[key];
      const pin = pins[key];
      return exactKeys(pin, ["bytes", "commit", "parameterName", "path",
        "sha256"]) && Number.isSafeInteger(pin.bytes) && pin.bytes > 0 &&
        HEX_40.test(pin.commit ?? "") && pin.commit !== "0".repeat(40) &&
        pin.parameterName === definition.parameterName &&
        pin.path === definition.path && HEX_64.test(pin.sha256 ?? "") &&
        plan.targets?.privateRecoveryQueryBootstrap?.parameters?.[
          definition.parameterName
        ] === pin.commit;
    }), code);
  const inventory = plan.source?.runtimeDependencyInventory;
  const expectedInventoryPaths = [...new Set([
    PLANNER_PATH,
    ROOT_ASSUME_RUNTIME_PATH,
    CEREMONY_LAUNCHER_PATH,
    CEREMONY_RUNNER_PATH,
    ...RUNTIME_DEPENDENCY_PATHS
  ])].sort();
  requireCondition(Array.isArray(inventory) &&
    inventory.map(({ path: itemPath }) => itemPath).join("\n") ===
      expectedInventoryPaths.join("\n") &&
    inventory.every((item) => exactKeys(item,
      ["bytes", "path", "sha256"]) &&
      Number.isSafeInteger(item.bytes) && item.bytes > 0 &&
      HEX_64.test(item.sha256 ?? "")), code);
  validateRuntimeExecutionBinding(plan.source?.runtimeExecutionBinding);
  requireCondition(path.isAbsolute(plan.source?.ceremonyLauncherPath ?? "") ===
    false && plan.source?.ceremonyLauncherPath === CEREMONY_LAUNCHER_PATH &&
    HEX_64.test(plan.source?.ceremonyLauncherSha256 ?? ""), code);
  return plan;
}

export function serializeOneTimeBootstrapPlan(plan) {
  verifyOneTimeBootstrapPlan(plan);
  return canonicalBytes(plan);
}

export function buildOneTimeBootstrapAuthorityPlan(input) {
  const code = "ONE_TIME_BOOTSTRAP_PLAN_INPUT_REJECTED";
  requireCondition(exactKeys(input, [
    "accountId",
    "artifactBucketName",
    "awsCliPath",
    "expectedSourceCommit",
    "expectedSourceTree",
    "githubOidcProviderArn",
    "homeDirectory",
    "mfaSerialArn",
    "notAfter",
    "now",
    "operationId",
    "privateRecoveryWorkflowCommits",
    "reconciledCostCeiling",
    "rootProfile",
    "rootProfileConfiguredRegion",
    "rootProfileConfigSha256",
    "sourceRoot",
    "targetTemplateSha256",
    "userAuthorizationReceiptSha256"
  ]) && ACCOUNT_ID.test(input.accountId ?? "") &&
    path.isAbsolute(input.awsCliPath ?? "") &&
    path.isAbsolute(input.homeDirectory ?? "") &&
    UUID.test(input.operationId ?? "") && HEX_40.test(
      input.expectedSourceCommit ?? "") &&
    HEX_40.test(input.expectedSourceTree ?? "") &&
    HEX_64.test(input.userAuthorizationReceiptSha256 ?? "") &&
    BUCKET_NAME.test(input.artifactBucketName ?? "") &&
    input.artifactBucketName.length >= 3 &&
    input.artifactBucketName.length <= 63 &&
    PROFILE_NAME.test(input.rootProfile ?? "") &&
    (input.rootProfileConfiguredRegion === null ||
      input.rootProfileConfiguredRegion === REGION), code);
  requireCondition(HEX_64.test(input.rootProfileConfigSha256 ?? "") &&
    input.rootProfileConfigSha256 === rootLoginProfileMetadataSha256({
      configuredRegion: input.rootProfileConfiguredRegion,
      effectiveRegion: REGION,
      loginSessionArn: `arn:aws:iam::${input.accountId}:root`,
      profile: input.rootProfile
    }), code);
  requireCondition(input.githubOidcProviderArn ===
    `arn:aws:iam::${input.accountId}:oidc-provider/` +
      "token.actions.githubusercontent.com" &&
    typeof input.mfaSerialArn === "string" &&
    input.mfaSerialArn.startsWith(`arn:aws:iam::${input.accountId}:mfa/`) &&
    input.mfaSerialArn.length <= 256, code);
  validateTargetDigestInput(input.targetTemplateSha256);
  validatePrivateRecoveryWorkflowCommits(
    input.privateRecoveryWorkflowCommits
  );
  validateReconciledCostCeiling(input.reconciledCostCeiling, {
    accountId: input.accountId,
    maximumObservedAt: input.now,
    operationId: input.operationId,
    sourceCommit: input.expectedSourceCommit,
    targetTemplateSha256: input.targetTemplateSha256,
    treeDigest: input.expectedSourceTree
  });
  const now = canonicalInstant(input.now, code);
  const notAfter = canonicalInstant(input.notAfter, code);
  requireCondition(now < notAfter && notAfter - now === MAX_PLAN_WINDOW_MS,
    "ONE_TIME_BOOTSTRAP_PLAN_TIME_REJECTED");
  const checkout = validateOneTimeBootstrapCheckout({
    awsCliPath: input.awsCliPath,
    expectedCommit: input.expectedSourceCommit,
    expectedTree: input.expectedSourceTree,
    homeDirectory: input.homeDirectory,
    operationId: input.operationId,
    privateRecoveryWorkflowCommits:
      input.privateRecoveryWorkflowCommits,
    sourceRoot: input.sourceRoot,
    targetTemplateSha256: input.targetTemplateSha256
  });
  const operationToken = operationTokenFor(input.operationId);
  const bootstrapRoleName = `ProofToActBootstrapCreator-${operationToken}`;
  const bootstrapRoleArn = `arn:aws:iam::${input.accountId}:role${ROLE_PATH}` +
    bootstrapRoleName;
  const writerRoleArn = `arn:aws:iam::${input.accountId}:role${ROLE_PATH}` +
    `ProofToActFreshCredentialWriter-${operationToken}`;
  const partialBinding = {
    accountId: input.accountId,
    artifactBucketName: input.artifactBucketName,
    bootstrapRoleArn,
    bootstrapRoleName,
    githubOidcProviderArn: input.githubOidcProviderArn,
    notAfter: input.notAfter,
    operationId: input.operationId,
    operationToken,
    privateRecoveryWorkflowCommits: {
      ...input.privateRecoveryWorkflowCommits
    },
    sessionName: `prooftoact-bootstrap-${operationToken}`,
    sourceCommit: checkout.commit,
    sourceIdentity: `prooftoact-b0-${operationToken}`,
    sourceTree: checkout.tree,
    userAuthorizationReceiptSha256: input.userAuthorizationReceiptSha256,
    writerRoleArn,
    writerSessionName: `prooftoact-credential-seal-${operationToken}`
  };
  const writerExternalId = writerExternalIdFor(partialBinding,
    input.targetTemplateSha256.freshPrimaryCredentialCustody);
  const targets = {};
  for (const targetKey of TARGET_KEYS) {
    const target = checkout.targets[targetKey];
    const stackName = exactStackName(targetKey, input.operationId);
    const changeSetName = exactChangeSetName(targetKey, operationToken);
    targets[targetKey] = {
      capabilities: ["CAPABILITY_NAMED_IAM"],
      changeSetName,
      changeSetType: "CREATE",
      parameters: targetParameters({
        ...partialBinding,
        githubOidcProviderArn: input.githubOidcProviderArn,
        writerExternalId
      }, targetKey, target.sha256),
      path: target.path,
      resourceContract: target.resourceContract,
      stackName,
      tags: stackTags(partialBinding, targetKey, target.sha256),
      templateBytes: target.bytes,
      templateSha256: target.sha256,
      templateTransport: "TemplateBody"
    };
  }
  const binding = {
    ...partialBinding,
    targets,
    writerExternalId
  };
  const documents = buildBootstrapRoleDocuments(binding);
  const body = {
    schemaVersion: "prooftoact.one-time-bootstrap-authority-plan.v1",
    status: "SOURCE_REVIEWED_CEREMONY_PLAN",
    evidenceLevel: "LOCAL_EXACT_SOURCE_AND_POLICY_CONTRACT",
    preparedAt: input.now,
    notAfter: input.notAfter,
    directProviderExecutionPerformed: false,
    authorization: {
      activationStatus:
        "HOLD_PENDING_EXACT_350_CENT_MONTHLY_AWS_AND_500_CENT_ONE_TIME_AUTHORIZATION_AND_LIVE_READBACK",
      cleanupOnlyAuthorization: cleanupOnlyAuthorizationContract({
        accountId: input.accountId,
        beginsAt: input.notAfter,
        expiresAt: new Date(Date.parse(input.notAfter) +
          MAX_CLEANUP_WINDOW_MS).toISOString(),
        operationId: input.operationId
      }),
      executionAuthorizationInferred: false,
      userAuthorizationReceiptSha256:
        input.userAuthorizationReceiptSha256
    },
    costCeiling: { ...input.reconciledCostCeiling },
    account: {
      accountId: input.accountId,
      partition: "aws",
      region: REGION,
      rootPrincipalArn: `arn:aws:iam::${input.accountId}:root`,
      rootProfile: input.rootProfile,
      rootProfileConfiguredRegion: input.rootProfileConfiguredRegion,
      rootProfileConfigSha256: input.rootProfileConfigSha256,
      rootProfileEffectiveRegion: REGION,
      rootProfileLoginSessionArn: `arn:aws:iam::${input.accountId}:root`,
      mfaSerialArn: input.mfaSerialArn
    },
    source: {
      commit: checkout.commit,
      tree: checkout.tree,
      officialOrigin: checkout.officialOrigin,
      cleanStandaloneMainCheckout: true,
      ceremonyLauncherPath: CEREMONY_LAUNCHER_PATH,
      ceremonyLauncherSha256: checkout.ceremonyLauncherSha256,
      ceremonyRunnerPath: CEREMONY_RUNNER_PATH,
      ceremonyRunnerSha256: checkout.ceremonyRunnerSha256,
      plannerPath: PLANNER_PATH,
      plannerSha256: checkout.plannerSha256,
      rootAssumeRuntimePath: ROOT_ASSUME_RUNTIME_PATH,
      rootAssumeRuntimeSha256: checkout.rootAssumeRuntimeSha256,
      privateRecoveryWorkflowPins:
        checkout.privateRecoveryWorkflowPins,
      runtimeDependencyInventory: checkout.runtimeDependencyInventory,
      runtimeExecutionBinding: checkout.runtimeExecutionBinding
    },
    existingInputs: {
      artifactBucketName: input.artifactBucketName,
      githubOidcProviderArn: input.githubOidcProviderArn,
      artifactUploadAuthorized: false,
      templateUrlAuthorized: false
    },
    operation: {
      operationId: input.operationId,
      operationToken
    },
    bootstrapRole: {
      arn: bootstrapRoleArn,
      name: bootstrapRoleName,
      path: ROLE_PATH,
      inlinePolicyName: `ProofToActBootstrapCreatorOnly-${operationToken}`,
      maxSessionDuration: 3600,
      roleTags: roleTags(binding),
      trustPolicy: documents.trustPolicy,
      trustPolicySha256: digest(documents.trustPolicy),
      inlinePolicy: documents.inlinePolicy,
      inlinePolicySha256: digest(documents.inlinePolicy),
      inlinePolicyNonWhitespaceBytes:
        Buffer.byteLength(canonicalJson(documents.inlinePolicy), "utf8")
    },
    sessionContract: {
      durationSeconds: SESSION_DURATION_SECONDS,
      exactDurationEnforcedByIam: false,
      exactDurationEnforcement:
        "RENDERED_REQUEST_AND_RETURNED_CREDENTIAL_EXPIRATION_RECEIPT",
      roleSessionName: binding.sessionName,
      sourceIdentity: binding.sourceIdentity,
      sessionTags: sessionTags(binding),
      transitiveTagKeys: []
    },
    writerContract: {
      roleArn: writerRoleArn,
      externalId: writerExternalId,
      roleSessionName: binding.writerSessionName,
      durationSeconds: SESSION_DURATION_SECONDS,
      sourceIdentityPersistsFromBootstrapSession: true,
      a2SealerAssumptionAuthorized: false
    },
    targets,
    hardDenials: {
      directSecretGetOrPut: true,
      passRole: true,
      workloadServices: true,
      artifactBucketAccess: true,
      otherRoleAssumption: true
    },
    rootMutationContract: [
      "iam:CreateRole",
      "iam:TagRole",
      "iam:PutRolePolicy",
      "sts:AssumeRole",
      "iam:DeleteRolePolicy",
      "iam:DeleteRole",
      "aws:Logout"
    ],
    executionBoundary: {
      createChangeSetTypeNotIamConditionable: true,
      createTypeMustPassPreExecuteReadback: true,
      templateDigestNotIamConditionable: true,
      exactTemplateBodyMustPassPreExecuteReadback: true,
      cloudFormationRoleArnRequiredAbsent: true,
      templateBodyOnly: true,
      noS3TemplateTransport: true,
      noWorkloadStack: true
    }
  };
  const plan = deepFreeze({ ...body, planBodySha256: digest(body) });
  verifyOneTimeBootstrapPlan(plan);
  return plan;
}

export function validateRootMfaDiscoveryEvidence(plan, evidence) {
  verifyOneTimeBootstrapPlan(plan);
  const code = "ONE_TIME_BOOTSTRAP_MFA_DISCOVERY_REJECTED";
  requireCondition(exactKeys(evidence, [
    "accountId",
    "devices",
    "observedAt",
    "readOnly",
    "schemaVersion",
    "selectedSerialArn"
  ]) && evidence.schemaVersion ===
    "prooftoact.one-time-bootstrap-mfa-discovery.v1" &&
    evidence.accountId === plan.account.accountId && evidence.readOnly === true &&
    evidence.selectedSerialArn === plan.account.mfaSerialArn &&
    Array.isArray(evidence.devices) && evidence.devices.length > 0 &&
    evidence.devices.length <= 8, code);
  const observedAt = canonicalInstant(evidence.observedAt, code);
  requireCondition(observedAt >= Date.parse(plan.preparedAt) &&
    observedAt < Date.parse(plan.notAfter) && evidence.devices.every((device) =>
      exactKeys(device, ["enabled", "serialArn"]) &&
      device.enabled === true && typeof device.serialArn === "string" &&
      device.serialArn.startsWith(
        `arn:aws:iam::${plan.account.accountId}:mfa/`
      )) && evidence.devices.filter(({ serialArn }) =>
      serialArn === plan.account.mfaSerialArn).length === 1, code);
  const body = {
    schemaVersion: "prooftoact.one-time-bootstrap-mfa-discovery-accepted.v1",
    status: "EXACT_ROOT_MFA_DEVICE_BOUND",
    planBodySha256: plan.planBodySha256,
    observedAt: evidence.observedAt,
    selectedSerialArn: evidence.selectedSerialArn,
    deviceCount: evidence.devices.length
  };
  return deepFreeze({ ...body, receiptSha256: digest(body) });
}

export function verifyRootMfaDiscoveryReceipt(plan, receipt) {
  verifyOneTimeBootstrapPlan(plan);
  const code = "ONE_TIME_BOOTSTRAP_MFA_RECEIPT_REJECTED";
  requireCondition(receiptDigestAccepted(
    receipt,
    "prooftoact.one-time-bootstrap-mfa-discovery-accepted.v1",
    "EXACT_ROOT_MFA_DEVICE_BOUND"
  ) && receipt.planBodySha256 === plan.planBodySha256 &&
    receipt.selectedSerialArn === plan.account.mfaSerialArn &&
    Number.isSafeInteger(receipt.deviceCount) && receipt.deviceCount > 0 &&
    Date.parse(receipt.observedAt) < Date.parse(plan.notAfter), code);
  return receipt;
}

export function validateBootstrapTrustRequest(plan, request) {
  verifyOneTimeBootstrapPlan(plan);
  const code = "ONE_TIME_BOOTSTRAP_TRUST_REQUEST_REJECTED";
  requireCondition(exactKeys(request, [
    "currentTime",
    "mfaAgeSeconds",
    "mfaAuthenticated",
    "mfaSerialArn",
    "principalArn",
    "roleSessionName",
    "sessionTags",
    "sourceIdentity"
  ]), code);
  const currentTime = canonicalInstant(request.currentTime, code);
  requireCondition(request.principalArn === plan.account.rootPrincipalArn &&
    request.mfaAuthenticated === true &&
    Number.isSafeInteger(request.mfaAgeSeconds) &&
    request.mfaAgeSeconds >= 0 && request.mfaAgeSeconds <= 300 &&
    request.mfaSerialArn === plan.account.mfaSerialArn &&
    request.roleSessionName === plan.sessionContract.roleSessionName &&
    request.sourceIdentity === plan.sessionContract.sourceIdentity &&
    canonicalJson(request.sessionTags) ===
      canonicalJson(plan.sessionContract.sessionTags) &&
    currentTime < Date.parse(plan.notAfter), code);
  return deepFreeze({
    accepted: true,
    principalArn: request.principalArn,
    requestSha256: digest(request)
  });
}

function command(id, actor, argv, outputHandling = "PUBLIC_METADATA_ONLY") {
  return { actor, argv, id, outputHandling };
}

function tagArguments(tags) {
  return tags.map(({ Key, Value }) => `Key=${Key},Value=${Value}`);
}

function parameterArguments(parameters) {
  return Object.entries(parameters).sort(([left], [right]) =>
    left.localeCompare(right)).map(([key, value]) =>
    `ParameterKey=${key},ParameterValue=${value}`);
}

export function renderOneTimeBootstrapCeremony(plan, options) {
  verifyOneTimeBootstrapPlan(plan);
  const code = "ONE_TIME_BOOTSTRAP_RENDER_INPUT_REJECTED";
  requireCondition(exactKeys(options, [
    "artifactDirectory", "awsCliPath", "homeDirectory", "mfaTokenFd",
    "sourceRoot"
  ]) &&
    path.isAbsolute(options.artifactDirectory) &&
    path.isAbsolute(options.awsCliPath) &&
    path.isAbsolute(options.homeDirectory) &&
    path.isAbsolute(options.sourceRoot) &&
    options.mfaTokenFd === 3 && options.awsCliPath ===
      plan.source.runtimeExecutionBinding.awsCli.requestedPath &&
    options.homeDirectory === plan.source.runtimeExecutionBinding.homeDirectory,
  code);
  let artifactStat;
  let sourceReal;
  try {
    artifactStat = fs.lstatSync(options.artifactDirectory);
    sourceReal = fs.realpathSync(options.sourceRoot);
  } catch (error) {
    reject(code, error);
  }
  requireCondition(artifactStat.isDirectory() &&
    !artifactStat.isSymbolicLink() && artifactStat.uid === process.getuid() &&
    (artifactStat.mode & 0o077) === 0 && sourceReal === options.sourceRoot,
  code);
  for (const targetKey of TARGET_KEYS) {
    const target = plan.targets[targetKey];
    const bytes = checkedRegularFile(path.join(sourceReal, target.path),
      51_200, code);
    requireCondition(bytes.length === target.templateBytes &&
      sha256(bytes) === target.templateSha256, code);
  }
  const trustPath = path.join(options.artifactDirectory,
    `b0-${plan.operation.operationToken}-trust.json`);
  const policyPath = path.join(options.artifactDirectory,
    `b0-${plan.operation.operationToken}-policy.json`);
  const planPath = path.join(options.artifactDirectory,
    `b0-${plan.operation.operationToken}-plan.json`);
  const rootProfileArgs = ["--profile", plan.account.rootProfile,
    "--region", REGION, "--no-cli-pager"];
  const rootCommands = [
    command("root-caller-identity", "AWS_ROOT_MFA_LOGIN", [
      options.awsCliPath, "sts", "get-caller-identity", ...rootProfileArgs
    ]),
    command("root-discover-bound-mfa-device", "AWS_ROOT_MFA_LOGIN", [
      options.awsCliPath, "iam", "list-mfa-devices", ...rootProfileArgs
    ], "READ_ONLY_MFA_DEVICE_CENSUS"),
    command("root-create-one-bootstrap-role", "AWS_ROOT_MFA_LOGIN", [
      options.awsCliPath, "iam", "create-role",
      "--role-name", plan.bootstrapRole.name,
      "--path", plan.bootstrapRole.path,
      "--max-session-duration", String(plan.bootstrapRole.maxSessionDuration),
      "--assume-role-policy-document", `file://${trustPath}`,
      ...rootProfileArgs
    ]),
    command("root-tag-one-bootstrap-role", "AWS_ROOT_MFA_LOGIN", [
      options.awsCliPath, "iam", "tag-role",
      "--role-name", plan.bootstrapRole.name,
      "--tags", ...tagArguments(plan.bootstrapRole.roleTags),
      ...rootProfileArgs
    ]),
    command("root-put-one-inline-policy", "AWS_ROOT_MFA_LOGIN", [
      options.awsCliPath, "iam", "put-role-policy",
      "--role-name", plan.bootstrapRole.name,
      "--policy-name", plan.bootstrapRole.inlinePolicyName,
      "--policy-document", `file://${policyPath}`,
      ...rootProfileArgs
    ])
  ];
  const changeSetStages = TARGET_KEYS.map((targetKey) => {
    const target = plan.targets[targetKey];
    const templatePath = path.join(sourceReal, target.path);
    return {
      targetKey,
      create: command(`b0-create-${targetKey}-change-set`,
        "B0_PRIVATE_SESSION", [
          options.awsCliPath, "cloudformation", "create-change-set",
          "--region", REGION,
          "--stack-name", target.stackName,
          "--change-set-name", target.changeSetName,
          "--change-set-type", "CREATE",
          "--template-body", `fileb://${templatePath}`,
          "--capabilities", ...target.capabilities,
          "--parameters", ...parameterArguments(target.parameters),
          "--tags", ...tagArguments(target.tags),
          "--no-cli-pager"
        ]),
      preExecuteReadback: [
        command(`b0-describe-${targetKey}-change-set`,
          "B0_PRIVATE_SESSION", [
            options.awsCliPath, "cloudformation", "describe-change-set",
            "--region", REGION,
            "--stack-name", target.stackName,
            "--change-set-name", target.changeSetName,
            "--no-cli-pager"
          ]),
        command(`b0-get-${targetKey}-change-set-template`,
          "B0_PRIVATE_SESSION", [
            options.awsCliPath, "cloudformation", "get-template",
            "--region", REGION,
            "--stack-name", target.stackName,
            "--change-set-name", target.changeSetName,
            "--template-stage", "Original",
            "--no-cli-pager"
          ], "PRIVATE_EXACT_TEMPLATE_READBACK")
      ],
      executeRequires:
        "validatePreExecuteChangeSetEvidence receipt for this plan/target",
      postCreateReadback: [
        command(`b0-wait-${targetKey}-create-complete`,
          "B0_PRIVATE_SESSION", [
            options.awsCliPath, "cloudformation", "wait",
            "stack-create-complete", "--region", REGION,
            "--stack-name", target.stackName,
            "--no-cli-pager"
          ]),
        command(`b0-describe-${targetKey}-stack`,
          "B0_PRIVATE_SESSION", [
            options.awsCliPath, "cloudformation", "describe-stacks",
            "--region", REGION, "--stack-name", target.stackName,
            "--no-cli-pager"
          ]),
        command(`b0-list-${targetKey}-resources`,
          "B0_PRIVATE_SESSION", [
            options.awsCliPath, "cloudformation", "list-stack-resources",
            "--region", REGION, "--stack-name", target.stackName,
            "--no-cli-pager"
          ]),
        command(`b0-get-${targetKey}-deployed-template`,
          "B0_PRIVATE_SESSION", [
            options.awsCliPath, "cloudformation", "get-template",
            "--region", REGION, "--stack-name", target.stackName,
            "--template-stage", "Original", "--no-cli-pager"
          ], "PRIVATE_EXACT_TEMPLATE_READBACK")
      ]
    };
  });
  const writerAssume = command("b0-assume-exact-a1-writer-900s",
    "B0_PRIVATE_SESSION", [
      options.awsCliPath, "sts", "assume-role",
      "--region", REGION,
      "--role-arn", plan.writerContract.roleArn,
      "--role-session-name", plan.writerContract.roleSessionName,
      "--external-id", plan.writerContract.externalId,
      "--duration-seconds", String(SESSION_DURATION_SECONDS),
      "--no-cli-pager"
    ], "PRIVATE_A1_WRITER_CREDENTIAL_RESPONSE_NEVER_LOG_OR_SERIALIZE");
  return deepFreeze({
    schemaVersion: "prooftoact.one-time-bootstrap-ceremony-render.v1",
    planBodySha256: plan.planBodySha256,
    artifacts: [
      {
        path: planPath,
        privateModeRequired: "0600",
        sha256: sha256(canonicalBytes(plan)),
        bytesBase64: canonicalBytes(plan).toString("base64")
      },
      {
        path: trustPath,
        privateModeRequired: "0600",
        sha256: plan.bootstrapRole.trustPolicySha256,
        bytesBase64: canonicalBytes(plan.bootstrapRole.trustPolicy)
          .toString("base64")
      },
      {
        path: policyPath,
        privateModeRequired: "0600",
        sha256: plan.bootstrapRole.inlinePolicySha256,
        bytesBase64: canonicalBytes(plan.bootstrapRole.inlinePolicy)
          .toString("base64")
      }
    ],
    rootSetupAndAssume: rootCommands,
    launcherInvocation: {
      executable: "/usr/bin/env",
      argv: [
        "/usr/bin/env", "-i",
        `HOME=${options.homeDirectory}`,
        "PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C",
        `AWS_PROFILE=${plan.account.rootProfile}`,
        "AWS_REGION=us-east-1", "AWS_DEFAULT_REGION=us-east-1",
        "AWS_EC2_METADATA_DISABLED=true", "AWS_SDK_LOAD_CONFIG=1",
        plan.source.runtimeExecutionBinding.node.realPath,
        path.join(sourceReal, plan.source.ceremonyLauncherPath),
        "--aws-cli-path",
        plan.source.runtimeExecutionBinding.awsCli.requestedPath,
        "--journal-directory", options.artifactDirectory,
        "--mode", "NEW", "--plan-file", planPath,
        "--source-root", sourceReal
      ],
      authorizationReceiptFd: 4,
      identityHmacKeyFd: 11,
      identityRecordFd: 10,
      mfaTokenFd: 3,
      writerValueFds: [5, 6, 7, 8, 9]
    },
    rootAssumeInProcess: {
      modulePath: plan.source.rootAssumeRuntimePath,
      moduleSha256: plan.source.rootAssumeRuntimeSha256,
      exportName: "assumeOneTimeBootstrapRootSession",
      rootProfile: plan.account.rootProfile,
      mfaSerialArn: plan.account.mfaSerialArn,
      mfaTokenFd: options.mfaTokenFd,
      durationSeconds: SESSION_DURATION_SECONDS,
      credentialDisposition: "PRIVATE_IN_MEMORY_CALLBACK_ONLY",
      sanitizedReceiptRequired: true
    },
    rootActionWhitelistByPhase: {
      discovery: ["sts:GetCallerIdentity", "iam:ListMFADevices"],
      setup: [
        "iam:CreateRole", "iam:TagRole", "iam:PutRolePolicy",
        "sts:AssumeRole"
      ],
      cleanupAfterAcceptedCompletionReceipt: [
        "iam:DeleteRolePolicy", "iam:DeleteRole", "iam:GetRole",
        "aws:Logout"
      ]
    },
    rootMutationWrapperRequirement:
      "FAIL_CLOSED_UNLESS_COMMAND_ID_AND_API_MATCH_CURRENT_PHASE_WHITELIST",
    changeSetStages,
    writerAssumeAfterCustodyPostCreateAcceptance: writerAssume,
    cleanupCommandsRendered: false,
    cleanupRequires:
      "validateBootstrapCompletionEvidence then renderAcceptedBootstrapCleanup",
    mfaTokenContract: {
      fd: options.mfaTokenFd,
      ownerOnly: true,
      sixDigitsRequired: true,
      tokenInArgv: false,
      tokenInEnvironment: false,
      tokenInFileArtifact: false,
      tokenLogged: false
    },
    rawCredentialMaterialPresent: false
  });
}

function exactBase64Bytes(value, code) {
  requireCondition(typeof value === "string" && value.length > 0 &&
    value.length <= 100_000 && /^[A-Za-z0-9+/]+={0,2}$/u.test(value), code);
  const bytes = Buffer.from(value, "base64");
  requireCondition(bytes.length > 0 && bytes.toString("base64") === value,
    code);
  return bytes;
}

function exactArn(pattern, value) {
  return new RegExp(`^${pattern}$`, "u").test(value ?? "");
}

function escaped(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

export function validatePreExecuteChangeSetEvidence(plan, targetKey,
  evidence) {
  verifyOneTimeBootstrapPlan(plan);
  const code = "ONE_TIME_BOOTSTRAP_PRE_EXECUTE_EVIDENCE_REJECTED";
  requireCondition(TARGET_KEYS.includes(targetKey) && exactKeys(evidence, [
    "accountId",
    "capabilities",
    "changeSetArn",
    "changeSetName",
    "changeSetType",
    "executionStatus",
    "observedAt",
    "parameters",
    "region",
    "roleArn",
    "stackArn",
    "stackName",
    "status",
    "tags",
    "templateBodyBase64"
  ]), code);
  const target = plan.targets[targetKey];
  const observedAt = canonicalInstant(evidence.observedAt, code);
  requireCondition(observedAt >= Date.parse(plan.preparedAt) &&
    observedAt < Date.parse(plan.notAfter) &&
    evidence.accountId === plan.account.accountId &&
    evidence.region === REGION && evidence.stackName === target.stackName &&
    evidence.changeSetName === target.changeSetName &&
    evidence.changeSetType === "CREATE" &&
    evidence.status === "CREATE_COMPLETE" &&
    evidence.executionStatus === "AVAILABLE" && evidence.roleArn === null &&
    canonicalJson(evidence.capabilities) ===
      canonicalJson(target.capabilities) &&
    canonicalJson(evidence.parameters) ===
      canonicalJson(target.parameters) &&
    canonicalJson(evidence.tags) === canonicalJson(target.tags), code);
  requireCondition(exactArn(
    `arn:aws:cloudformation:${REGION}:${plan.account.accountId}:stack/` +
      `${escaped(target.stackName)}/[0-9a-f-]{36}`,
    evidence.stackArn
  ) && exactArn(
    `arn:aws:cloudformation:${REGION}:${plan.account.accountId}:changeSet/` +
      `${escaped(target.changeSetName)}/[0-9a-f-]{36}`,
    evidence.changeSetArn
  ), code);
  const templateBytes = exactBase64Bytes(evidence.templateBodyBase64, code);
  requireCondition(templateBytes.length === target.templateBytes &&
    sha256(templateBytes) === target.templateSha256, code);
  const body = {
    schemaVersion: "prooftoact.one-time-bootstrap-pre-execute.v1",
    status: "EXACT_CREATE_CHANGE_SET_ACCEPTED_FOR_EXECUTION",
    planBodySha256: plan.planBodySha256,
    targetKey,
    accountId: evidence.accountId,
    region: evidence.region,
    observedAt: evidence.observedAt,
    stackArn: evidence.stackArn,
    changeSetArn: evidence.changeSetArn,
    changeSetName: evidence.changeSetName,
    changeSetType: evidence.changeSetType,
    templateSha256: target.templateSha256,
    roleArnAbsent: true,
    exactParametersAndTags: true
  };
  return deepFreeze({ ...body, receiptSha256: digest(body) });
}

export function renderExecuteAcceptedChangeSet(plan, receipt, awsCliPath) {
  verifyOneTimeBootstrapPlan(plan);
  const code = "ONE_TIME_BOOTSTRAP_EXECUTE_RECEIPT_REJECTED";
  requireCondition(path.isAbsolute(awsCliPath) && plainObject(receipt) &&
    receipt.schemaVersion ===
      "prooftoact.one-time-bootstrap-pre-execute.v1" &&
    receipt.status === "EXACT_CREATE_CHANGE_SET_ACCEPTED_FOR_EXECUTION" &&
    receipt.planBodySha256 === plan.planBodySha256 &&
    TARGET_KEYS.includes(receipt.targetKey) &&
    receipt.receiptSha256 === digest(Object.fromEntries(Object.entries(
      receipt).filter(([key]) => key !== "receiptSha256"))), code);
  const target = plan.targets[receipt.targetKey];
  requireCondition(receipt.changeSetName === target.changeSetName &&
    receipt.changeSetType === "CREATE" &&
    receipt.templateSha256 === target.templateSha256 &&
    Date.parse(receipt.observedAt) < Date.parse(plan.notAfter), code);
  return deepFreeze(command(`b0-execute-${receipt.targetKey}-change-set`,
    "B0_PRIVATE_SESSION", [
      awsCliPath, "cloudformation", "execute-change-set",
      "--region", REGION,
      "--stack-name", target.stackName,
      "--change-set-name", target.changeSetName,
      "--no-cli-pager"
    ]));
}

function physicalIdAccepted(plan, resource, physicalId) {
  if (resource.type === "AWS::IAM::Role") {
    return physicalId === resource.physicalName;
  }
  if (resource.type === "AWS::IAM::ManagedPolicy") {
    return physicalId === `arn:aws:iam::${plan.account.accountId}:policy/` +
      resource.physicalName;
  }
  if (resource.type === "AWS::SecretsManager::Secret") {
    return new RegExp(
      `^arn:aws:secretsmanager:${REGION}:${plan.account.accountId}:secret:` +
      `${escaped(resource.secretName)}-[A-Za-z0-9]{6}$`, "u"
    ).test(physicalId);
  }
  return false;
}

export function validatePostCreateStackEvidence(plan, targetKey, evidence) {
  verifyOneTimeBootstrapPlan(plan);
  const code = "ONE_TIME_BOOTSTRAP_POST_CREATE_EVIDENCE_REJECTED";
  requireCondition(TARGET_KEYS.includes(targetKey) && exactKeys(evidence, [
    "accountId",
    "capabilities",
    "observedAt",
    "parameters",
    "region",
    "resources",
    "roleArn",
    "stackArn",
    "stackName",
    "stackStatus",
    "tags",
    "templateBodyBase64"
  ]), code);
  const target = plan.targets[targetKey];
  const observedAt = canonicalInstant(evidence.observedAt, code);
  requireCondition(observedAt >= Date.parse(plan.preparedAt) &&
    observedAt < Date.parse(plan.notAfter) &&
    evidence.accountId === plan.account.accountId &&
    evidence.region === REGION && evidence.stackName === target.stackName &&
    evidence.stackStatus === "CREATE_COMPLETE" && evidence.roleArn === null &&
    canonicalJson(evidence.capabilities) ===
      canonicalJson(target.capabilities) &&
    canonicalJson(evidence.parameters) ===
      canonicalJson(target.parameters) &&
    canonicalJson(evidence.tags) === canonicalJson(target.tags) &&
    exactArn(
      `arn:aws:cloudformation:${REGION}:${plan.account.accountId}:stack/` +
        `${escaped(target.stackName)}/[0-9a-f-]{36}`,
      evidence.stackArn
    ), code);
  const templateBytes = exactBase64Bytes(evidence.templateBodyBase64, code);
  requireCondition(templateBytes.length === target.templateBytes &&
    sha256(templateBytes) === target.templateSha256 &&
    Array.isArray(evidence.resources) && evidence.resources.length ===
      target.resourceContract.length, code);
  const sortedResources = [...evidence.resources].sort((left, right) =>
    String(left.logicalId).localeCompare(String(right.logicalId)));
  requireCondition(sortedResources.every((resource, index) => {
    const expected = target.resourceContract[index];
    return exactKeys(resource, [
      "logicalId", "physicalId", "resourceStatus", "type"
    ]) && resource.logicalId === expected.logicalId &&
      resource.type === expected.type &&
      resource.resourceStatus === "CREATE_COMPLETE" &&
      physicalIdAccepted(plan, expected, resource.physicalId);
  }), code);
  const body = {
    schemaVersion: "prooftoact.one-time-bootstrap-post-create.v1",
    status: "EXACT_BOOTSTRAP_STACK_CREATE_ACCEPTED",
    planBodySha256: plan.planBodySha256,
    targetKey,
    accountId: evidence.accountId,
    region: evidence.region,
    observedAt: evidence.observedAt,
    stackArn: evidence.stackArn,
    stackName: evidence.stackName,
    templateSha256: target.templateSha256,
    resourceCount: sortedResources.length,
    exactParametersTagsAndResources: true
  };
  return deepFreeze({ ...body, receiptSha256: digest(body) });
}

export function validateBootstrapSessionReceipt(plan, receipt,
  { writer = false } = {}) {
  verifyOneTimeBootstrapPlan(plan);
  const code = "ONE_TIME_BOOTSTRAP_SESSION_RECEIPT_REJECTED";
  requireCondition(exactKeys(receipt, [
    "accountId",
    "assumedRoleArn",
    "credentialMaterialLogged",
    "credentialsExpiration",
    "durationSeconds",
    "issuedAt",
    "mfaAuthenticated",
    "mfaSerialArn",
    "operationId",
    "rawCredentialFieldsPresent",
    "roleArn",
    "roleSessionName",
    "schemaVersion",
    "sourceIdentity",
    "status"
  ]) && receipt.schemaVersion ===
    "prooftoact.one-time-bootstrap-session-receipt.v1" &&
    receipt.status === "SANITIZED_PROVIDER_SESSION_ACCEPTED" &&
    receipt.accountId === plan.account.accountId &&
    receipt.operationId === plan.operation.operationId &&
    receipt.durationSeconds === SESSION_DURATION_SECONDS &&
    receipt.rawCredentialFieldsPresent === false &&
    receipt.credentialMaterialLogged === false, code);
  const issuedAt = canonicalInstant(receipt.issuedAt, code);
  const expiration = canonicalInstant(receipt.credentialsExpiration, code);
  requireCondition(expiration - issuedAt ===
    SESSION_DURATION_SECONDS * 1000, code);
  const expected = writer ? plan.writerContract : {
    roleArn: plan.bootstrapRole.arn,
    roleSessionName: plan.sessionContract.roleSessionName,
    sourceIdentity: plan.sessionContract.sourceIdentity
  };
  requireCondition(receipt.roleArn === expected.roleArn &&
    receipt.roleSessionName === expected.roleSessionName &&
    receipt.sourceIdentity === (writer ?
      plan.sessionContract.sourceIdentity : expected.sourceIdentity) &&
    receipt.mfaAuthenticated === (writer ? false : true) &&
    receipt.mfaSerialArn === (writer ? null : plan.account.mfaSerialArn) &&
    receipt.assumedRoleArn === `arn:aws:sts::${plan.account.accountId}:` +
      `assumed-role/${path.basename(expected.roleArn)}/` +
      expected.roleSessionName, code);
  return deepFreeze({
    expiration: receipt.credentialsExpiration,
    issuedAt: receipt.issuedAt,
    roleArn: receipt.roleArn,
    sessionReceiptSha256: digest(receipt),
    writer
  });
}

export function buildBootstrapNegativeSimulationPlan(plan) {
  verifyOneTimeBootstrapPlan(plan);
  const accountId = plan.account.accountId;
  const operationId = plan.operation.operationId;
  const secret = secretResourceArns(accountId, operationId)[0];
  const workloadStack = `arn:aws:cloudformation:${REGION}:${accountId}:` +
    "stack/prooftoact-workload/*";
  return deepFreeze([
    {
      id: "deny-direct-role-create",
      actionName: "iam:CreateRole",
      resourceArn: `arn:aws:iam::${accountId}:role/` +
        "ProofToActFreshPrimaryBootstrap",
      expectedDecision: "implicitDeny"
    },
    {
      id: "deny-direct-secret-container-create",
      actionName: "secretsmanager:CreateSecret",
      resourceArn: secret,
      expectedDecision: "implicitDeny"
    },
    {
      id: "deny-direct-secret-read",
      actionName: "secretsmanager:GetSecretValue",
      resourceArn: secret,
      expectedDecision: "explicitDeny"
    },
    {
      id: "deny-direct-secret-write",
      actionName: "secretsmanager:PutSecretValue",
      resourceArn: secret,
      expectedDecision: "explicitDeny"
    },
    {
      id: "deny-pass-role",
      actionName: "iam:PassRole",
      resourceArn: `arn:aws:iam::${accountId}:role/` +
        "ProofToActPrivateRecoveryQueryCloudFormation",
      expectedDecision: "explicitDeny"
    },
    {
      id: "deny-direct-permissions-boundary-put",
      actionName: "iam:PutRolePermissionsBoundary",
      resourceArn: `arn:aws:iam::${accountId}:role/` +
        "ProofToActPrivateRecoveryQueryCloudFormation",
      expectedDecision: "explicitDeny"
    },
    {
      id: "deny-workload-lambda-create",
      actionName: "lambda:CreateFunction",
      resourceArn: `arn:aws:lambda:${REGION}:${accountId}:function:` +
        "prooftoact-private-recovery-query",
      expectedDecision: "explicitDeny"
    },
    {
      id: "deny-workload-stack-create",
      actionName: "cloudformation:CreateStack",
      resourceArn: workloadStack,
      expectedDecision: "explicitDeny"
    },
    {
      id: "deny-unlisted-change-set",
      actionName: "cloudformation:CreateChangeSet",
      resourceArn: `arn:aws:cloudformation:${REGION}:${accountId}:` +
        "changeSet/prooftoact-workload-create/*",
      expectedDecision: "implicitDeny"
    },
    {
      id: "deny-a2-sealer-assumption",
      actionName: "sts:AssumeRole",
      resourceArn: `arn:aws:iam::${accountId}:role/` +
        "ProofToActPrivateRecoveryQuerySecretSealer",
      expectedDecision: "explicitDeny"
    },
    {
      id: "deny-artifact-upload",
      actionName: "s3:PutObject",
      resourceArn: `arn:aws:s3:::${plan.existingInputs.artifactBucketName}/` +
        "bootstrap-forbidden",
      expectedDecision: "explicitDeny"
    }
  ]);
}

export function validateBootstrapNegativeSimulation(plan, results) {
  const code = "ONE_TIME_BOOTSTRAP_NEGATIVE_SIMULATION_REJECTED";
  const vectors = buildBootstrapNegativeSimulationPlan(plan);
  requireCondition(Array.isArray(results) && results.length === vectors.length,
    code);
  const sorted = [...results].sort((left, right) =>
    String(left.id).localeCompare(String(right.id)));
  const expected = [...vectors].sort((left, right) =>
    left.id.localeCompare(right.id));
  requireCondition(sorted.every((result, index) => exactKeys(result, [
    "actionName", "evalDecision", "id", "missingContextValues", "resourceArn"
  ]) && result.id === expected[index].id &&
    result.actionName === expected[index].actionName &&
    result.resourceArn === expected[index].resourceArn &&
    result.evalDecision === expected[index].expectedDecision &&
    Array.isArray(result.missingContextValues) &&
    result.missingContextValues.length === 0), code);
  const body = {
    schemaVersion: "prooftoact.one-time-bootstrap-negative-simulation.v1",
    status: "ALL_REQUIRED_NEGATIVE_VECTORS_DENIED",
    planBodySha256: plan.planBodySha256,
    vectorCount: expected.length,
    explicitDenyCount: expected.filter((entry) =>
      entry.expectedDecision === "explicitDeny").length,
    implicitDenyCount: expected.filter((entry) =>
      entry.expectedDecision === "implicitDeny").length
  };
  return deepFreeze({ ...body, receiptSha256: digest(body) });
}

function receiptDigestAccepted(receipt, schemaVersion, status) {
  if (!plainObject(receipt) || receipt.schemaVersion !== schemaVersion ||
    receipt.status !== status || !HEX_64.test(receipt.receiptSha256 ?? "")) {
    return false;
  }
  return receipt.receiptSha256 === digest(Object.fromEntries(Object.entries(
    receipt).filter(([key]) => key !== "receiptSha256")));
}

export function validateBootstrapCompletionEvidence(plan, evidence) {
  verifyOneTimeBootstrapPlan(plan);
  const code = "ONE_TIME_BOOTSTRAP_COMPLETION_EVIDENCE_REJECTED";
  requireCondition(exactKeys(evidence, [
    "a1SecretCensus",
    "a2TargetSecretVersionCount",
    "ambiguousState",
    "b0CredentialsDestroyed",
    "inFlightChangeSets",
    "observedAt",
    "postCreateReceipts",
    "preExecuteReceipts",
    "rawCredentialFieldsPresent",
    "schemaVersion",
    "stackStatuses",
    "writerState"
  ]) && evidence.schemaVersion ===
    "prooftoact.one-time-bootstrap-completion-evidence.v1" &&
    evidence.ambiguousState === false &&
    evidence.b0CredentialsDestroyed === true &&
    evidence.rawCredentialFieldsPresent === false &&
    evidence.a2TargetSecretVersionCount === 0 &&
    Array.isArray(evidence.inFlightChangeSets) &&
    evidence.inFlightChangeSets.length === 0 &&
    exactKeys(evidence.preExecuteReceipts, TARGET_KEYS) &&
    exactKeys(evidence.postCreateReceipts, TARGET_KEYS) &&
    exactKeys(evidence.stackStatuses, TARGET_KEYS), code);
  const observedAt = canonicalInstant(evidence.observedAt, code);
  requireCondition(observedAt >= Date.parse(plan.preparedAt) &&
    TARGET_KEYS.every((targetKey) => {
      const pre = evidence.preExecuteReceipts[targetKey];
      const post = evidence.postCreateReceipts[targetKey];
      return receiptDigestAccepted(pre,
        "prooftoact.one-time-bootstrap-pre-execute.v1",
        "EXACT_CREATE_CHANGE_SET_ACCEPTED_FOR_EXECUTION") &&
        receiptDigestAccepted(post,
          "prooftoact.one-time-bootstrap-post-create.v1",
          "EXACT_BOOTSTRAP_STACK_CREATE_ACCEPTED") &&
        pre.planBodySha256 === plan.planBodySha256 &&
        post.planBodySha256 === plan.planBodySha256 &&
        pre.targetKey === targetKey && post.targetKey === targetKey &&
        evidence.stackStatuses[targetKey] === "CREATE_COMPLETE";
    }), code);
  const expectedInitialized = [
    "prooftoact/fresh-cluster/auditor",
    "prooftoact/fresh-primary/cloud-api",
    "prooftoact/fresh-primary/runtime-credentials",
    "prooftoact/gate2/managed-mcp",
    "prooftoact/gate2/recovery-publisher"
  ].map((secretName) => ({ secretName, versionCount: 1 }));
  const expectedEmpty = [
    `prooftoact/fresh-primary/admin-${plan.operation.operationId}`,
    `prooftoact/fresh-primary/recovery-signer-${plan.operation.operationId}`
  ].map((secretName) => ({ secretName, versionCount: 0 }));
  requireCondition(exactKeys(evidence.a1SecretCensus, [
    "initializedWriterTargets",
    "rawSecretValuesObserved",
    "runtimeGeneratedTargets",
    "sourceReadbackReceiptSha256"
  ]) && evidence.a1SecretCensus.rawSecretValuesObserved === false &&
    HEX_64.test(evidence.a1SecretCensus.sourceReadbackReceiptSha256 ?? "") &&
    canonicalJson(evidence.a1SecretCensus.initializedWriterTargets) ===
      canonicalJson(expectedInitialized) &&
    canonicalJson(evidence.a1SecretCensus.runtimeGeneratedTargets) ===
      canonicalJson(expectedEmpty), code);
  requireCondition(exactKeys(evidence.writerState, [
    "completedExactlyFiveWrites",
    "failedWrites",
    "rawCredentialFieldsPresent",
    "roleArn",
    "sessionExpiration",
    "sessionExpired"
  ]) && evidence.writerState.completedExactlyFiveWrites === true &&
    evidence.writerState.failedWrites === 0 &&
    evidence.writerState.rawCredentialFieldsPresent === false &&
    evidence.writerState.roleArn === plan.writerContract.roleArn &&
    evidence.writerState.sessionExpired === true &&
    canonicalInstant(evidence.writerState.sessionExpiration, code) <=
      observedAt, code);
  const body = {
    schemaVersion: "prooftoact.one-time-bootstrap-completion.v1",
    status: "EXACT_STATE_ACCEPTED_FOR_B0_DELETION",
    planBodySha256: plan.planBodySha256,
    observedAt: evidence.observedAt,
    exactThreeStacksCreateComplete: true,
    exactFiveWriterTargetsOneVersion: true,
    exactTwoRuntimeTargetsZeroVersions: true,
    a2TargetStillEmpty: true,
    noInFlightChangeSets: true,
    noAmbiguousState: true,
    b0CredentialsDestroyed: true
  };
  return deepFreeze({ ...body, receiptSha256: digest(body) });
}

export function renderAcceptedBootstrapCleanup(plan, completionReceipt,
  options) {
  verifyOneTimeBootstrapPlan(plan);
  const code = "ONE_TIME_BOOTSTRAP_CLEANUP_RENDER_REJECTED";
  requireCondition(exactKeys(options, ["awsCliPath"]) &&
    path.isAbsolute(options.awsCliPath) && receiptDigestAccepted(
      completionReceipt,
      "prooftoact.one-time-bootstrap-completion.v1",
      "EXACT_STATE_ACCEPTED_FOR_B0_DELETION"
    ) && completionReceipt.planBodySha256 === plan.planBodySha256 &&
    completionReceipt.exactThreeStacksCreateComplete === true &&
    completionReceipt.exactFiveWriterTargetsOneVersion === true &&
    completionReceipt.exactTwoRuntimeTargetsZeroVersions === true &&
    completionReceipt.a2TargetStillEmpty === true &&
    completionReceipt.noInFlightChangeSets === true &&
    completionReceipt.noAmbiguousState === true &&
    completionReceipt.b0CredentialsDestroyed === true, code);
  const profile = ["--profile", plan.account.rootProfile, "--region", REGION,
    "--no-cli-pager"];
  return deepFreeze({
    schemaVersion: "prooftoact.one-time-bootstrap-cleanup-render.v1",
    planBodySha256: plan.planBodySha256,
    completionReceiptSha256: completionReceipt.receiptSha256,
    failClosedRetentionRule:
      "NO_COMMAND_MAY_RUN_IF_COMPLETION_RECEIPT_IS_MISSING_OR_REJECTED",
    rootActionWhitelist: [
      "iam:DeleteRolePolicy", "iam:DeleteRole", "iam:GetRole", "aws:Logout"
    ],
    commands: [
      command("root-delete-b0-inline-policy", "AWS_ROOT_MFA_LOGIN", [
        options.awsCliPath, "iam", "delete-role-policy",
        "--role-name", plan.bootstrapRole.name,
        "--policy-name", plan.bootstrapRole.inlinePolicyName,
        ...profile
      ]),
      command("root-delete-b0-role", "AWS_ROOT_MFA_LOGIN", [
        options.awsCliPath, "iam", "delete-role",
        "--role-name", plan.bootstrapRole.name,
        ...profile
      ]),
      command("root-verify-b0-role-absent", "AWS_ROOT_MFA_LOGIN", [
        options.awsCliPath, "iam", "get-role",
        "--role-name", plan.bootstrapRole.name,
        ...profile
      ], "REQUIRE_NO_SUCH_ENTITY"),
      command("destroy-local-temporary-credentials", "LOCAL_PROCESS", [
        "unset", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN"
      ], "NO_CHILD_PROCESS_EXECUTION; CALLER_PROCESS_ACTION"),
      command("aws-root-logout", "AWS_ROOT_MFA_LOGIN", [
        options.awsCliPath, "logout", "--profile", plan.account.rootProfile,
        "--region", REGION, "--no-cli-pager"
      ], "REQUIRE_ZERO_EXIT_AND_CACHED_ROOT_SESSION_ABSENT")
    ]
  });
}

export function validateOneTimeBootstrapCleanupReceipt(plan, receipt) {
  verifyOneTimeBootstrapPlan(plan);
  const code = "ONE_TIME_BOOTSTRAP_CLEANUP_RECEIPT_REJECTED";
  requireCondition(exactKeys(receipt, [
    "accountId",
    "awsLogout",
    "b0CredentialEnvironmentKeysPresent",
    "b0CredentialsDestroyed",
    "b0SessionExpiration",
    "bootstrapRoleAbsent",
    "inlinePolicyAbsent",
    "observedAt",
    "operationId",
    "rawCredentialFieldsPresent",
    "rootAssumeEventTimes",
    "rootAssumeSessionCount",
    "rootDirectEvents",
    "schemaVersion",
    "unexpectedRootMutationEvents",
    "writerAssumeEventTimes",
    "writerAssumeSessionCount",
    "writerSessionExpiration",
    "writerSessionExpired"
  ]) && receipt.schemaVersion ===
    "prooftoact.one-time-bootstrap-cleanup.v1" &&
    receipt.accountId === plan.account.accountId &&
    receipt.operationId === plan.operation.operationId &&
    receipt.bootstrapRoleAbsent === true &&
    receipt.inlinePolicyAbsent === true &&
    receipt.b0CredentialsDestroyed === true &&
    receipt.writerSessionExpired === true &&
    receipt.rawCredentialFieldsPresent === false &&
    Number.isSafeInteger(receipt.rootAssumeSessionCount) &&
    receipt.rootAssumeSessionCount >= 1 &&
    receipt.rootAssumeSessionCount <= 2 &&
    Number.isSafeInteger(receipt.writerAssumeSessionCount) &&
    receipt.writerAssumeSessionCount >= 1 &&
    receipt.writerAssumeSessionCount <= 2 &&
    Array.isArray(receipt.rootAssumeEventTimes) &&
    receipt.rootAssumeEventTimes.length === receipt.rootAssumeSessionCount &&
    Array.isArray(receipt.writerAssumeEventTimes) &&
    receipt.writerAssumeEventTimes.length ===
      receipt.writerAssumeSessionCount &&
    Array.isArray(receipt.b0CredentialEnvironmentKeysPresent) &&
    receipt.b0CredentialEnvironmentKeysPresent.length === 0 &&
    Array.isArray(receipt.unexpectedRootMutationEvents) &&
    receipt.unexpectedRootMutationEvents.length === 0, code);
  const observedAt = canonicalInstant(receipt.observedAt, code);
  requireCondition(canonicalInstant(receipt.b0SessionExpiration, code) <=
    observedAt && canonicalInstant(receipt.writerSessionExpiration, code) <=
    observedAt && [...receipt.rootAssumeEventTimes,
      ...receipt.writerAssumeEventTimes].every((value) =>
      canonicalInstant(value, code) <= observedAt), code);
  const setupEvents = [
    {
      eventName: "CreateRole",
      roleName: plan.bootstrapRole.name,
      rolePath: plan.bootstrapRole.path
    },
    {
      eventName: "TagRole",
      roleName: plan.bootstrapRole.name,
      tagsSha256: digest(plan.bootstrapRole.roleTags)
    },
    {
      eventName: "PutRolePolicy",
      policyName: plan.bootstrapRole.inlinePolicyName,
      policySha256: plan.bootstrapRole.inlinePolicySha256,
      roleName: plan.bootstrapRole.name
    }
  ];
  const expectedAssumeEvent = {
      durationSeconds: SESSION_DURATION_SECONDS,
      eventName: "AssumeRole",
      mfaAuthenticated: true,
      serialNumber: plan.account.mfaSerialArn,
      roleArn: plan.bootstrapRole.arn,
      roleSessionName: plan.sessionContract.roleSessionName,
      sourceIdentity: plan.sessionContract.sourceIdentity
  };
  const cleanupEvents = [
    {
      eventName: "DeleteRolePolicy",
      policyName: plan.bootstrapRole.inlinePolicyName,
      roleName: plan.bootstrapRole.name
    },
    { eventName: "DeleteRole", roleName: plan.bootstrapRole.name }
  ];
  requireCondition(Array.isArray(receipt.rootDirectEvents) &&
    receipt.rootDirectEvents.length >= 6 &&
    canonicalJson(receipt.rootDirectEvents.slice(0, 3)) ===
      canonicalJson(setupEvents) &&
    canonicalJson(receipt.rootDirectEvents.slice(-2)) ===
      canonicalJson(cleanupEvents) &&
    receipt.rootDirectEvents.slice(3, -2).length ===
      receipt.rootAssumeSessionCount &&
    receipt.rootDirectEvents.slice(3, -2).every((event) =>
      canonicalJson(event) === canonicalJson(expectedAssumeEvent)) &&
    exactKeys(receipt.awsLogout, [
      "command", "dispatchOutcome", "namedRootLoginSessionUnavailable",
      "noninteractiveCallerIdentityRejected", "profile", "receiptSha256",
      "rootSdkClientsDestroyed", "schemaVersion", "status"
    ]) && receipt.awsLogout.schemaVersion ===
      "prooftoact.one-time-bootstrap-logout.v2" &&
    receipt.awsLogout.status === "NAMED_ROOT_LOGIN_SESSION_UNAVAILABLE" &&
    ["DISPATCHED_AND_NEGATIVELY_VERIFIED",
      "PRESTATE_ABSENT_AFTER_DURABLE_INTENT_OR_DISPATCH"].includes(
      receipt.awsLogout.dispatchOutcome
    ) && receipt.awsLogout.namedRootLoginSessionUnavailable === true &&
    receipt.awsLogout.noninteractiveCallerIdentityRejected === true &&
    receipt.awsLogout.rootSdkClientsDestroyed === true &&
    receipt.awsLogout.receiptSha256 === digest(Object.fromEntries(
      Object.entries(receipt.awsLogout).filter(([key]) =>
        key !== "receiptSha256")
    )) &&
    receipt.awsLogout.profile === plan.account.rootProfile &&
    canonicalJson(receipt.awsLogout.command) === canonicalJson([
      "aws", "logout", "--profile", plan.account.rootProfile
    ]), code);
  const body = {
    schemaVersion: "prooftoact.one-time-bootstrap-cleanup-accepted.v1",
    status: "B0_DELETED_TEMPORARY_CREDENTIALS_EXPIRED_AND_ROOT_LOGGED_OUT",
    planBodySha256: plan.planBodySha256,
    observedAt: receipt.observedAt,
    rootAssumeSessionCount: receipt.rootAssumeSessionCount,
    rootDirectEventCount: receipt.rootDirectEvents.length,
    writerAssumeSessionCount: receipt.writerAssumeSessionCount,
    bootstrapRoleAbsent: true,
    inlinePolicyAbsent: true,
    rootLoggedOut: true,
    noCredentialMaterialRetained: true
  };
  return deepFreeze({ ...body, receiptSha256: digest(body) });
}

export const oneTimeBootstrapConstants = deepFreeze({
  A1_INTEGRATION_RUNTIME_PATHS,
  CONDITION_KEYS: [...CONDITION_KEYS],
  CEREMONY_LAUNCHER_PATH,
  CEREMONY_RUNNER_PATH,
  EXACT_MONTHLY_AUTHORIZATION_USD_CENTS,
  EXACT_ONE_TIME_AUTHORIZATION_USD_CENTS,
  INLINE_POLICY_MAX_NON_WHITESPACE_BYTES,
  MANAGED_POLICY_METADATA_READ_ACTIONS,
  MANAGED_POLICY_MUTATION_ACTIONS,
  MAX_CLEANUP_WINDOW_MS,
  MAX_PLAN_WINDOW_MS,
  OFFICIAL_ORIGIN,
  PLANNER_PATH,
  PRIVATE_RECOVERY_WORKFLOW_DEFINITIONS,
  PRIVATE_RECOVERY_WORKFLOW_KEYS,
  REGION,
  ROOT_ASSUME_RUNTIME_PATH,
  RUNTIME_DEPENDENCY_PATHS,
  ROLE_METADATA_READ_ACTIONS,
  ROLE_MUTATION_ACTIONS,
  ROLE_PATH,
  SECRET_CONTAINER_MUTATION_ACTIONS,
  SECRET_METADATA_READ_ACTIONS,
  SESSION_DURATION_SECONDS,
  SUPPORTED_CLOUDFORMATION_ACTIONS:
    [...SUPPORTED_CLOUDFORMATION_ACTIONS],
  TARGET_DEFINITIONS,
  TARGET_KEYS
});

export const __test = Object.freeze({
  awsCliRuntimeBinding,
  canonicalBytes,
  canonicalJson,
  digest,
  exactChangeSetName,
  exactStackName,
  secretResourceArns,
  sha256,
  runtimeExecutionBinding,
  runtimeTree,
  validateTargetTemplate
});

if (process.argv[1] && path.resolve(process.argv[1]) === CURRENT_FILE) {
  process.stdout.write(
    "HOLD:ONE_TIME_BOOTSTRAP_AUTHORITY_REQUIRES_EXACT_INPUT_AND_STAGED_READBACK\n"
  );
}
