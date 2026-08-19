import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  __test,
  buildBootstrapNegativeSimulationPlan,
  buildOneTimeBootstrapAuthorityPlan,
  oneTimeBootstrapConstants,
  operationTokenFor,
  renderAcceptedBootstrapCleanup,
  renderExecuteAcceptedChangeSet,
  renderOneTimeBootstrapCeremony,
  rootLoginProfileMetadataSha256,
  serializeOneTimeBootstrapPlan,
  validateBootstrapCompletionEvidence,
  validateBootstrapNegativeSimulation,
  validateBootstrapSessionReceipt,
  validateBootstrapTrustRequest,
  validateOneTimeBootstrapCheckout,
  validateOneTimeBootstrapCleanupReceipt,
  validatePostCreateStackEvidence,
  validatePreExecuteChangeSetEvidence,
  validateRootMfaDiscoveryEvidence
} from "../scripts/prepare-one-time-bootstrap-authority.js";
import {
  assumeOneTimeBootstrapRootSession,
  rootStsClientConfiguration
} from "../scripts/assume-one-time-bootstrap-root-session.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PLANNER_BYTES = fs.readFileSync(path.join(
  ROOT,
  oneTimeBootstrapConstants.PLANNER_PATH
));
const ROOT_ASSUME_BYTES = fs.readFileSync(path.join(
  ROOT,
  oneTimeBootstrapConstants.ROOT_ASSUME_RUNTIME_PATH
));
const CEREMONY_RUNNER_BYTES = fs.readFileSync(path.join(
  ROOT,
  oneTimeBootstrapConstants.CEREMONY_RUNNER_PATH
));
const PLANNER_SOURCE = PLANNER_BYTES.toString("utf8");
const ROOT_ASSUME_SOURCE = ROOT_ASSUME_BYTES.toString("utf8");
const ACCOUNT_ID = "123456789012";
const OPERATION_ID = "123e4567-e89b-42d3-a456-426614174000";
const USER_AUTHORIZATION = "a".repeat(64);
const NOW = "2026-08-18T14:00:00.000Z";
const NOT_AFTER = "2026-08-18T15:00:00.000Z";
const MFA_ARN = `arn:aws:iam::${ACCOUNT_ID}:mfa/root-account-mfa-device`;

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function git(root, argv) {
  return execFileSync("/usr/bin/git", argv, {
    cwd: root,
    encoding: "utf8",
    env: {
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
      LANG: "C",
      LC_ALL: "C",
      PATH: "/usr/bin:/bin"
    },
    stdio: ["ignore", "pipe", "pipe"]
  }).trim();
}

function inlinePolicy(name = "Policy") {
  return [{
    PolicyName: name,
    PolicyDocument: {
      Version: "2012-10-17",
      Statement: [{
        Effect: "Allow",
        Action: "sts:GetCallerIdentity",
        Resource: "*"
      }]
    }
  }];
}

function role(name, extra = {}) {
  return {
    Type: "AWS::IAM::Role",
    Properties: {
      RoleName: name,
      AssumeRolePolicyDocument: {
        Version: "2012-10-17",
        Statement: [{
          Effect: "Allow",
          Principal: { Service: "cloudformation.amazonaws.com" },
          Action: "sts:AssumeRole"
        }]
      },
      ManagedPolicyArns: [],
      Policies: inlinePolicy(),
      Tags: [{ Key: "Project", Value: "ProofToAct" }],
      ...extra
    }
  };
}

function secret(name) {
  return {
    Type: "AWS::SecretsManager::Secret",
    DeletionPolicy: "Retain",
    UpdateReplacePolicy: "Retain",
    Properties: {
      Name: name,
      Tags: [{ Key: "Project", Value: "ProofToAct" }]
    }
  };
}

function targetTemplates() {
  const token = operationTokenFor(OPERATION_ID);
  return {
    freshPrimaryBootstrapRole: {
      AWSTemplateFormatVersion: "2010-09-09",
      Parameters: { GitHubOidcProviderArn: { Type: "String" } },
      Resources: {
        FreshPrimaryBootstrapRole: role("ProofToActFreshPrimaryBootstrap")
      },
      Outputs: {}
    },
    freshPrimaryCredentialCustody: {
      AWSTemplateFormatVersion: "2010-09-09",
      Parameters: {
        BootstrapCreatorRoleArn: { Type: "String" },
        CredentialSealExternalId: { Type: "String" },
        OperationId: { Type: "String" },
        OperationToken: { Type: "String" },
        OperatorAuthorizationSha256: { Type: "String" },
        SourceCommit: { Type: "String" },
        TemplateSha256: { Type: "String" },
        TreeDigest: { Type: "String" }
      },
      Resources: {
        FreshClusterAuditorSecret:
          secret("prooftoact/fresh-cluster/auditor"),
        FreshPrimaryAdminSecret: secret({
          "Fn::Sub": "prooftoact/fresh-primary/admin-${OperationId}"
        }),
        FreshPrimaryCloudApiSecret:
          secret("prooftoact/fresh-primary/cloud-api"),
        FreshPrimaryCredentialWriterRole: role({
          "Fn::Sub": "ProofToActFreshCredentialWriter-${OperationToken}"
        }, {
          Path: "/prooftoact/bootstrap/",
          AssumeRolePolicyDocument: {
            Version: "2012-10-17",
            Statement: [{
              Effect: "Allow",
              Principal: { AWS: { Ref: "BootstrapCreatorRoleArn" } },
              Action: "sts:AssumeRole",
              Condition: {
                StringEquals: {
                  "sts:ExternalId": { Ref: "CredentialSealExternalId" },
                  "sts:RoleSessionName": {
                    "Fn::Sub":
                      "prooftoact-credential-seal-${OperationToken}"
                  }
                }
              }
            }]
          },
          Tags: [
            { Key: "Project", Value: "ProofToAct" },
            {
              Key: "OperatorAuthorizationSha256",
              Value: { Ref: "OperatorAuthorizationSha256" }
            }
          ]
        }),
        FreshPrimaryRecoverySignerSecret: secret({
          "Fn::Sub":
            "prooftoact/fresh-primary/recovery-signer-${OperationId}"
        }),
        FreshPrimaryRuntimeCredentialsSecret:
          secret("prooftoact/fresh-primary/runtime-credentials"),
        ManagedMcpSecret: secret("prooftoact/gate2/managed-mcp"),
        RecoveryPublisherSecret:
          secret("prooftoact/gate2/recovery-publisher")
      },
      Outputs: { Token: { Value: token } }
    },
    privateRecoveryQueryBootstrap: {
      AWSTemplateFormatVersion: "2010-09-09",
      Parameters: {
        ArtifactBucketName: { Type: "String" },
        GitHubOidcProviderArn: { Type: "String" }
      },
      Resources: {
        PrivateRecoveryBoundary: {
          Type: "AWS::IAM::ManagedPolicy",
          Properties: {
            ManagedPolicyName: "ProofToActPrivateRecoveryQueryBoundary",
            PolicyDocument: {
              Version: "2012-10-17",
              Statement: [{
                Effect: "Deny",
                Action: "*",
                Resource: "*"
              }]
            }
          }
        },
        PrivateRecoveryCloudFormationRole: role(
          "ProofToActPrivateRecoveryQueryCloudFormation",
          { PermissionsBoundary: { Ref: "PrivateRecoveryBoundary" } }
        ),
        PrivateRecoveryDeploymentRole: role(
          "ProofToActPrivateRecoveryQueryDeployment"
        ),
        PrivateRecoveryMcpSecret:
          secret("prooftoact/private-recovery-query/managed-mcp"),
        PrivateRecoverySecretSealerRole: role(
          "ProofToActPrivateRecoveryQuerySecretSealer"
        )
      },
      Outputs: {}
    }
  };
}

function templateBytes(template) {
  return Buffer.from(`${JSON.stringify(template, null, 2)}\n`, "utf8");
}

function fixture(t, overrides = {}) {
  const parent = fs.mkdtempSync(path.join(
    fs.realpathSync(os.tmpdir()),
    "prooftoact-one-time-bootstrap-"
  ));
  const root = path.join(parent, "checkout");
  const artifacts = path.join(parent, "private");
  fs.mkdirSync(path.join(root, "scripts"), { recursive: true, mode: 0o700 });
  fs.mkdirSync(path.join(root, "infra", "aws"), {
    recursive: true,
    mode: 0o700
  });
  fs.mkdirSync(artifacts, { mode: 0o700 });
  fs.writeFileSync(path.join(root,
    oneTimeBootstrapConstants.PLANNER_PATH), PLANNER_BYTES, { mode: 0o600 });
  fs.writeFileSync(path.join(root,
    oneTimeBootstrapConstants.ROOT_ASSUME_RUNTIME_PATH), ROOT_ASSUME_BYTES,
  { mode: 0o600 });
  fs.writeFileSync(path.join(root,
    oneTimeBootstrapConstants.CEREMONY_RUNNER_PATH), CEREMONY_RUNNER_BYTES,
  { mode: 0o600 });
  const templates = targetTemplates();
  const bytes = {};
  for (const targetKey of oneTimeBootstrapConstants.TARGET_KEYS) {
    const value = overrides[targetKey] ?? templates[targetKey];
    bytes[targetKey] = templateBytes(value);
    fs.writeFileSync(path.join(root,
      oneTimeBootstrapConstants.TARGET_DEFINITIONS[targetKey].path),
    bytes[targetKey], { mode: 0o600 });
  }
  git(root, ["init", "--initial-branch=main"]);
  git(root, ["remote", "add", "origin",
    oneTimeBootstrapConstants.OFFICIAL_ORIGIN]);
  git(root, ["add", "--all"]);
  git(root, [
    "-c", "user.name=ProofToAct Test",
    "-c", "user.email=prooftoact-test@example.invalid",
    "commit", "--no-gpg-sign", "-m", "reviewed bootstrap fixture"
  ]);
  const identity = {
    commit: git(root, ["rev-parse", "HEAD"]),
    tree: git(root, ["rev-parse", "HEAD^{tree}"])
  };
  t.after(() => fs.rmSync(parent, { force: true, recursive: true }));
  return {
    artifacts,
    bytes,
    digests: Object.fromEntries(Object.entries(bytes).map(([key, value]) =>
      [key, sha256(value)])),
    identity,
    parent,
    root
  };
}

function input(checkout) {
  return {
    accountId: ACCOUNT_ID,
    artifactBucketName: "prooftoact-private-artifacts-123456789012",
    expectedSourceCommit: checkout.identity.commit,
    expectedSourceTree: checkout.identity.tree,
    githubOidcProviderArn: `arn:aws:iam::${ACCOUNT_ID}:oidc-provider/` +
      "token.actions.githubusercontent.com",
    mfaSerialArn: MFA_ARN,
    notAfter: NOT_AFTER,
    now: NOW,
    operationId: OPERATION_ID,
    reconciledCostCeiling: {
      currency: "USD",
      maximumMonthlyUsdCents: 1000,
      maximumOneTimeUsdCents: 500,
      reconciliationReceiptSha256: "c".repeat(64)
    },
    rootProfile: "default",
    rootProfileConfiguredRegion: null,
    rootProfileConfigSha256: rootLoginProfileMetadataSha256({
      configuredRegion: null,
      effectiveRegion: "us-east-1",
      loginSessionArn: `arn:aws:iam::${ACCOUNT_ID}:root`,
      profile: "default"
    }),
    sourceRoot: checkout.root,
    targetTemplateSha256: checkout.digests,
    userAuthorizationReceiptSha256: USER_AUTHORIZATION
  };
}

function clone(value) {
  return structuredClone(value);
}

function uuidFor(index) {
  return `00000000-0000-4000-8000-${String(index).padStart(12, "0")}`;
}

function preEvidence(plan, checkout, targetKey, index = 1) {
  const target = plan.targets[targetKey];
  return {
    accountId: ACCOUNT_ID,
    capabilities: clone(target.capabilities),
    changeSetArn: `arn:aws:cloudformation:us-east-1:${ACCOUNT_ID}:changeSet/` +
      `${target.changeSetName}/${uuidFor(index + 10)}`,
    changeSetName: target.changeSetName,
    changeSetType: "CREATE",
    executionStatus: "AVAILABLE",
    observedAt: "2026-08-18T14:05:00.000Z",
    parameters: clone(target.parameters),
    region: "us-east-1",
    roleArn: null,
    stackArn: `arn:aws:cloudformation:us-east-1:${ACCOUNT_ID}:stack/` +
      `${target.stackName}/${uuidFor(index)}`,
    stackName: target.stackName,
    status: "CREATE_COMPLETE",
    tags: clone(target.tags),
    templateBodyBase64: checkout.bytes[targetKey].toString("base64")
  };
}

function physicalId(resource) {
  if (resource.type === "AWS::IAM::Role") return resource.physicalName;
  if (resource.type === "AWS::IAM::ManagedPolicy") {
    return `arn:aws:iam::${ACCOUNT_ID}:policy/${resource.physicalName}`;
  }
  return `arn:aws:secretsmanager:us-east-1:${ACCOUNT_ID}:secret:` +
    `${resource.secretName}-ABC123`;
}

function postEvidence(plan, checkout, targetKey, index = 1) {
  const target = plan.targets[targetKey];
  return {
    accountId: ACCOUNT_ID,
    capabilities: clone(target.capabilities),
    observedAt: "2026-08-18T14:08:00.000Z",
    parameters: clone(target.parameters),
    region: "us-east-1",
    resources: target.resourceContract.map((resource) => ({
      logicalId: resource.logicalId,
      physicalId: physicalId(resource),
      resourceStatus: "CREATE_COMPLETE",
      type: resource.type
    })),
    roleArn: null,
    stackArn: `arn:aws:cloudformation:us-east-1:${ACCOUNT_ID}:stack/` +
      `${target.stackName}/${uuidFor(index)}`,
    stackName: target.stackName,
    stackStatus: "CREATE_COMPLETE",
    tags: clone(target.tags),
    templateBodyBase64: checkout.bytes[targetKey].toString("base64")
  };
}

function mfaEvidence() {
  return {
    schemaVersion: "prooftoact.one-time-bootstrap-mfa-discovery.v1",
    accountId: ACCOUNT_ID,
    observedAt: "2026-08-18T14:01:00.000Z",
    readOnly: true,
    selectedSerialArn: MFA_ARN,
    devices: [{ enabled: true, serialArn: MFA_ARN }]
  };
}

function ownerOnlyMfaFd(t, digits = "123456") {
  const fifo = path.join(fs.mkdtempSync(path.join(
    fs.realpathSync(os.tmpdir()),
    "prooftoact-mfa-fd-"
  )), "token");
  execFileSync("/usr/bin/mkfifo", ["-m", "600", fifo]);
  const fd = fs.openSync(fifo, fs.constants.O_RDWR | fs.constants.O_NONBLOCK);
  fs.writeSync(fd, digits, null, "ascii");
  t.after(() => {
    fs.closeSync(fd);
    fs.rmSync(path.dirname(fifo), { force: true, recursive: true });
  });
  return fd;
}

function mockStsClient(plan, expiration = "2026-08-18T14:17:00.000Z") {
  const inputs = [];
  return {
    inputs,
    async send(commandValue) {
      const name = commandValue.constructor.name;
      inputs.push({ name, input: clone(commandValue.input) });
      if (name === "GetCallerIdentityCommand") {
        return {
          Account: ACCOUNT_ID,
          Arn: `arn:aws:iam::${ACCOUNT_ID}:root`,
          UserId: ACCOUNT_ID
        };
      }
      assert.equal(name, "AssumeRoleCommand");
      return {
        AssumedRoleUser: {
          Arn: `arn:aws:sts::${ACCOUNT_ID}:assumed-role/` +
            `${plan.bootstrapRole.name}/${plan.sessionContract.roleSessionName}`,
          AssumedRoleId: `AROAEXAMPLE:${plan.sessionContract.roleSessionName}`
        },
        Credentials: {
          AccessKeyId: "ASIAEXAMPLEACCESS",
          Expiration: new Date(expiration),
          SecretAccessKey: "example-secret-access-key",
          SessionToken: "example-session-token"
        }
      };
    }
  };
}

function clockSequence(...values) {
  let index = 0;
  return () => new Date(values[Math.min(index++, values.length - 1)]);
}

test("planner binds exact source, A1 formulas, target-specific tags, and policy", (t) => {
  const checkout = fixture(t);
  const plan = buildOneTimeBootstrapAuthorityPlan(input(checkout));
  const token = operationTokenFor(OPERATION_ID);
  const expectedExternalId = sha256(Buffer.from(
    "prooftoact-fresh-primary-credential-seal-external-id-v1\n" +
    `${ACCOUNT_ID}\n${OPERATION_ID}\n${token}\n` +
    `${USER_AUTHORIZATION}\n${checkout.identity.commit}\n` +
    `${checkout.identity.tree}\n` +
    `${checkout.digests.freshPrimaryCredentialCustody}\n`,
    "utf8"
  ));

  assert.equal(plan.operation.operationToken, token);
  assert.equal(plan.bootstrapRole.path, "/prooftoact/bootstrap/");
  assert.equal(plan.bootstrapRole.name,
    `ProofToActBootstrapCreator-${token}`);
  assert.equal(plan.writerContract.externalId, expectedExternalId);
  assert.equal(plan.writerContract.durationSeconds, 900);
  assert.equal(plan.sessionContract.durationSeconds, 900);
  assert.equal(plan.sessionContract.exactDurationEnforcedByIam, false);
  assert.equal(
    plan.targets.freshPrimaryCredentialCustody.parameters
      .OperatorAuthorizationSha256,
    USER_AUTHORIZATION
  );
  assert.deepEqual(plan.targets.freshPrimaryBootstrapRole.tags, [
    { Key: "Project", Value: "ProofToAct" }
  ]);
  assert.deepEqual(plan.targets.freshPrimaryCredentialCustody.tags, [
    { Key: "OperationId", Value: OPERATION_ID },
    { Key: "Project", Value: "ProofToAct" }
  ]);
  assert.deepEqual(plan.targets.privateRecoveryQueryBootstrap.tags, [
    { Key: "Project", Value: "ProofToAct" }
  ]);
  assert.equal(plan.source.commit, checkout.identity.commit);
  assert.equal(plan.source.tree, checkout.identity.tree);
  assert.equal(plan.source.rootAssumeRuntimeSha256, sha256(ROOT_ASSUME_BYTES));
  assert.equal(plan.source.ceremonyRunnerSha256,
    sha256(CEREMONY_RUNNER_BYTES));
  assert.equal(plan.bootstrapRole.inlinePolicyNonWhitespaceBytes <= 10_240,
    true, String(plan.bootstrapRole.inlinePolicyNonWhitespaceBytes));
  assert.equal(Object.isFrozen(plan), true);
  assert.deepEqual(
    serializeOneTimeBootstrapPlan(plan),
    serializeOneTimeBootstrapPlan(buildOneTimeBootstrapAuthorityPlan(
      input(checkout)
    ))
  );

  const trust = plan.bootstrapRole.trustPolicy.Statement[0];
  assert.equal(trust.Principal.AWS, `arn:aws:iam::${ACCOUNT_ID}:root`);
  assert.equal(trust.Condition.StringEquals["aws:PrincipalArn"],
    `arn:aws:iam::${ACCOUNT_ID}:root`);
  assert.equal(trust.Condition.Bool["aws:MultiFactorAuthPresent"], "true");
  const source = JSON.stringify(plan.bootstrapRole.inlinePolicy);
  assert.doesNotMatch(source, /sts:DurationSeconds|ChangeSetType/u);
  assert.doesNotMatch(source, /cloudformation:GetTerminationProtection/u);
  assert.equal(oneTimeBootstrapConstants.SUPPORTED_CLOUDFORMATION_ACTIONS
    .includes("cloudformation:GetTerminationProtection"), false);
  assert.match(source, /cloudformation:RoleArn/u);
  assert.match(source, /aws:CalledVia/u);
  const passStatements = plan.bootstrapRole.inlinePolicy.Statement.filter(
    ({ Action }) => (Array.isArray(Action) ? Action : [Action])
      .includes("iam:PassRole")
  );
  assert.deepEqual(passStatements.map(({ Effect }) => Effect), ["Deny"]);
  assert.throws(() => buildOneTimeBootstrapAuthorityPlan({
    ...input(checkout),
    notAfter: "2026-08-18T14:59:59.999Z"
  }), /ONE_TIME_BOOTSTRAP_PLAN_TIME_REJECTED/u);
});

test("trust request rejects any account IAM user or role despite matching MFA and tags", (t) => {
  const checkout = fixture(t);
  const plan = buildOneTimeBootstrapAuthorityPlan(input(checkout));
  const request = {
    currentTime: "2026-08-18T14:02:00.000Z",
    mfaAgeSeconds: 1,
    mfaAuthenticated: true,
    mfaSerialArn: MFA_ARN,
    principalArn: `arn:aws:iam::${ACCOUNT_ID}:root`,
    roleSessionName: plan.sessionContract.roleSessionName,
    sessionTags: clone(plan.sessionContract.sessionTags),
    sourceIdentity: plan.sessionContract.sourceIdentity
  };
  assert.equal(validateBootstrapTrustRequest(plan, request).accepted, true);
  for (const principalArn of [
    `arn:aws:iam::${ACCOUNT_ID}:user/admin`,
    `arn:aws:iam::${ACCOUNT_ID}:role/Administrator`
  ]) {
    assert.throws(() => validateBootstrapTrustRequest(plan, {
      ...request,
      principalArn
    }), /ONE_TIME_BOOTSTRAP_TRUST_REQUEST_REJECTED/u);
  }
  assert.throws(() => validateBootstrapTrustRequest(plan, {
    ...request,
    mfaSerialArn: `arn:aws:iam::${ACCOUNT_ID}:mfa/other`
  }), /ONE_TIME_BOOTSTRAP_TRUST_REQUEST_REJECTED/u);
});

test("renderer uses TemplateBody, stages execute, and keeps MFA token out of argv and artifacts", (t) => {
  const checkout = fixture(t);
  const plan = buildOneTimeBootstrapAuthorityPlan(input(checkout));
  const rendered = renderOneTimeBootstrapCeremony(plan, {
    artifactDirectory: checkout.artifacts,
    awsCliPath: "/usr/local/bin/aws",
    mfaTokenFd: 3,
    sourceRoot: checkout.root
  });
  const serialized = JSON.stringify(rendered);
  assert.equal(rendered.cleanupCommandsRendered, false);
  assert.equal(rendered.mfaTokenContract.tokenInArgv, false);
  assert.equal(rendered.mfaTokenContract.tokenInEnvironment, false);
  assert.equal(rendered.rootAssumeInProcess.exportName,
    "assumeOneTimeBootstrapRootSession");
  assert.doesNotMatch(serialized, /--token-code|PROOFTOACT_ROOT_MFA_CODE/u);
  assert.doesNotMatch(serialized, /\b[0-9]{6}\b/u);
  assert.equal(rendered.rawCredentialMaterialPresent, false);
  assert.deepEqual(rendered.rootActionWhitelistByPhase.setup, [
    "iam:CreateRole", "iam:TagRole", "iam:PutRolePolicy", "sts:AssumeRole"
  ]);
  assert.equal(rendered.changeSetStages.length, 3);
  for (const stage of rendered.changeSetStages) {
    const argv = stage.create.argv;
    assert.equal(argv.includes("--change-set-type"), true);
    assert.equal(argv[argv.indexOf("--change-set-type") + 1], "CREATE");
    assert.equal(argv.includes("--template-body"), true);
    assert.match(argv[argv.indexOf("--template-body") + 1], /^fileb:\/\//u);
    assert.equal(argv.includes("--template-url"), false);
    assert.equal(argv.includes("--role-arn"), false);
    assert.equal(stage.executeRequires.includes(
      "validatePreExecuteChangeSetEvidence"
    ), true);
  }
  assert.equal(rendered.artifacts.every(({ bytesBase64 }) =>
    !Buffer.from(bytesBase64, "base64").toString("utf8")
      .includes("TokenCode")), true);
});

test("root MFA discovery and sanitized 900-second session bind exact serial", (t) => {
  const checkout = fixture(t);
  const plan = buildOneTimeBootstrapAuthorityPlan(input(checkout));
  const acceptedMfa = validateRootMfaDiscoveryEvidence(plan, mfaEvidence());
  assert.equal(acceptedMfa.selectedSerialArn, MFA_ARN);
  const receipt = {
    schemaVersion: "prooftoact.one-time-bootstrap-session-receipt.v1",
    status: "SANITIZED_PROVIDER_SESSION_ACCEPTED",
    accountId: ACCOUNT_ID,
    operationId: OPERATION_ID,
    roleArn: plan.bootstrapRole.arn,
    assumedRoleArn: `arn:aws:sts::${ACCOUNT_ID}:assumed-role/` +
      `${plan.bootstrapRole.name}/${plan.sessionContract.roleSessionName}`,
    roleSessionName: plan.sessionContract.roleSessionName,
    sourceIdentity: plan.sessionContract.sourceIdentity,
    mfaAuthenticated: true,
    mfaSerialArn: MFA_ARN,
    durationSeconds: 900,
    issuedAt: "2026-08-18T14:02:00.000Z",
    credentialsExpiration: "2026-08-18T14:17:00.000Z",
    rawCredentialFieldsPresent: false,
    credentialMaterialLogged: false
  };
  assert.equal(validateBootstrapSessionReceipt(plan, receipt).writer, false);
  assert.throws(() => validateBootstrapSessionReceipt(plan, {
    ...receipt,
    credentialsExpiration: "2026-08-18T14:17:01.000Z"
  }), /ONE_TIME_BOOTSTRAP_SESSION_RECEIPT_REJECTED/u);
  assert.throws(() => validateBootstrapSessionReceipt(plan, {
    ...receipt,
    mfaSerialArn: `arn:aws:iam::${ACCOUNT_ID}:mfa/other`
  }), /ONE_TIME_BOOTSTRAP_SESSION_RECEIPT_REJECTED/u);
});

test("in-process root AssumeRole credential lease auto-destroys on success, throw, reuse, and abort", async (t) => {
  const checkout = fixture(t);
  const plan = buildOneTimeBootstrapAuthorityPlan(input(checkout));
  const mfaDiscoveryReceipt = validateRootMfaDiscoveryEvidence(
    plan,
    mfaEvidence()
  );
  async function assume() {
    return assumeOneTimeBootstrapRootSession({
      clock: clockSequence(
        "2026-08-18T14:02:00.000Z",
        "2026-08-18T14:02:01.000Z"
      ),
      mfaDiscoveryReceipt,
      mfaFd: ownerOnlyMfaFd(t),
      plan,
      stsClient: mockStsClient(plan)
    });
  }

  const success = await assume();
  let successReference;
  assert.equal(await success.withPrivateCredentials(async (credentials) => {
    successReference = credentials;
    assert.equal(credentials.accessKeyId, "ASIAEXAMPLEACCESS");
    return "accepted";
  }), "accepted");
  assert.equal(successReference.accessKeyId, null);
  assert.equal(successReference.secretAccessKey, null);
  await assert.rejects(() => success.withPrivateCredentials(async () => null),
    /ONE_TIME_BOOTSTRAP_ROOT_ASSUME_REJECTED/u);
  success.destroy();
  success.destroy();

  const thrown = await assume();
  let thrownReference;
  await assert.rejects(() => thrown.withPrivateCredentials(
    async (credentials) => {
      thrownReference = credentials;
      throw new Error("CALLBACK_FAILED");
    }
  ), /CALLBACK_FAILED/u);
  assert.equal(thrownReference.sessionToken, null);
  await assert.rejects(() => thrown.withPrivateCredentials(async () => null),
    /ONE_TIME_BOOTSTRAP_ROOT_ASSUME_REJECTED/u);

  const aborted = await assume();
  aborted.destroy();
  aborted.destroy();
  await assert.rejects(() => aborted.withPrivateCredentials(async () => null),
    /ONE_TIME_BOOTSTRAP_ROOT_ASSUME_REJECTED/u);
});

test("root AssumeRole has one SDK attempt and ambiguous failure never redispatches", async (t) => {
  const configuration = rootStsClientConfiguration();
  assert.equal(configuration.maxAttempts, 1);
  assert.equal(configuration.region, "us-east-1");
  assert.equal(typeof configuration.requestHandler?.handle, "function");

  const checkout = fixture(t);
  const plan = buildOneTimeBootstrapAuthorityPlan(input(checkout));
  const mfaDiscoveryReceipt = validateRootMfaDiscoveryEvidence(
    plan,
    mfaEvidence()
  );
  const commands = [];
  const ambiguousClient = {
    async send(commandValue) {
      commands.push(commandValue.constructor.name);
      if (commandValue.constructor.name === "GetCallerIdentityCommand") {
        return {
          Account: ACCOUNT_ID,
          Arn: `arn:aws:iam::${ACCOUNT_ID}:root`,
          UserId: ACCOUNT_ID
        };
      }
      throw Object.assign(new Error("socket closed after request write"), {
        name: "TimeoutError"
      });
    }
  };
  await assert.rejects(() => assumeOneTimeBootstrapRootSession({
    clock: clockSequence("2026-08-18T14:02:00.000Z"),
    mfaDiscoveryReceipt,
    mfaFd: ownerOnlyMfaFd(t),
    plan,
    stsClient: ambiguousClient
  }), /ONE_TIME_BOOTSTRAP_ROOT_ASSUME_AMBIGUOUS_RECONCILE_CLOUDTRAIL/u);
  assert.deepEqual(commands, [
    "GetCallerIdentityCommand",
    "AssumeRoleCommand"
  ]);
});

test("pre-execute validator rejects UPDATE, template drift, RoleArn, and only then renders execute", (t) => {
  const checkout = fixture(t);
  const plan = buildOneTimeBootstrapAuthorityPlan(input(checkout));
  const targetKey = "freshPrimaryCredentialCustody";
  const evidence = preEvidence(plan, checkout, targetKey);
  const receipt = validatePreExecuteChangeSetEvidence(
    plan,
    targetKey,
    evidence
  );
  const execute = renderExecuteAcceptedChangeSet(
    plan,
    receipt,
    "/usr/local/bin/aws"
  );
  assert.equal(execute.argv.includes("execute-change-set"), true);
  for (const mutated of [
    { ...evidence, changeSetType: "UPDATE" },
    { ...evidence, roleArn: `arn:aws:iam::${ACCOUNT_ID}:role/unsafe` },
    {
      ...evidence,
      templateBodyBase64: Buffer.from("{}\n").toString("base64")
    }
  ]) {
    assert.throws(() => validatePreExecuteChangeSetEvidence(
      plan,
      targetKey,
      mutated
    ), /ONE_TIME_BOOTSTRAP_PRE_EXECUTE_EVIDENCE_REJECTED/u);
  }
  assert.throws(() => renderExecuteAcceptedChangeSet(plan, {
    ...receipt,
    templateSha256: "f".repeat(64)
  }, "/usr/local/bin/aws"),
  /ONE_TIME_BOOTSTRAP_EXECUTE_RECEIPT_REJECTED/u);
});

test("post-create validation accepts only exact three bootstrap resource censuses", (t) => {
  const checkout = fixture(t);
  const plan = buildOneTimeBootstrapAuthorityPlan(input(checkout));
  for (const [index, targetKey] of
    oneTimeBootstrapConstants.TARGET_KEYS.entries()) {
    const evidence = postEvidence(plan, checkout, targetKey, index + 1);
    const receipt = validatePostCreateStackEvidence(
      plan,
      targetKey,
      evidence
    );
    assert.equal(receipt.targetKey, targetKey);
    const unexpected = clone(evidence);
    unexpected.resources.push({
      logicalId: "Workload",
      physicalId: "workload",
      resourceStatus: "CREATE_COMPLETE",
      type: "AWS::Lambda::Function"
    });
    assert.throws(() => validatePostCreateStackEvidence(
      plan,
      targetKey,
      unexpected
    ), /ONE_TIME_BOOTSTRAP_POST_CREATE_EVIDENCE_REJECTED/u);
  }
});

test("negative simulation requires secret, workload, PassRole, A2 sealer, S3, and extra-stack denials", (t) => {
  const checkout = fixture(t);
  const plan = buildOneTimeBootstrapAuthorityPlan(input(checkout));
  const vectors = buildBootstrapNegativeSimulationPlan(plan);
  const results = vectors.map((vector) => ({
    actionName: vector.actionName,
    evalDecision: vector.expectedDecision,
    id: vector.id,
    missingContextValues: [],
    resourceArn: vector.resourceArn
  }));
  const receipt = validateBootstrapNegativeSimulation(plan, results);
  assert.equal(receipt.vectorCount, 11);
  assert.equal(receipt.explicitDenyCount, 8);
  assert.equal(receipt.implicitDenyCount, 3);
  const allowed = clone(results);
  allowed[0].evalDecision = "allowed";
  assert.throws(() => validateBootstrapNegativeSimulation(plan, allowed),
    /ONE_TIME_BOOTSTRAP_NEGATIVE_SIMULATION_REJECTED/u);
});

function completionEvidence(plan, checkout) {
  const preExecuteReceipts = {};
  const postCreateReceipts = {};
  const stackStatuses = {};
  for (const [index, targetKey] of
    oneTimeBootstrapConstants.TARGET_KEYS.entries()) {
    preExecuteReceipts[targetKey] = validatePreExecuteChangeSetEvidence(
      plan,
      targetKey,
      preEvidence(plan, checkout, targetKey, index + 1)
    );
    postCreateReceipts[targetKey] = validatePostCreateStackEvidence(
      plan,
      targetKey,
      postEvidence(plan, checkout, targetKey, index + 1)
    );
    stackStatuses[targetKey] = "CREATE_COMPLETE";
  }
  return {
    schemaVersion: "prooftoact.one-time-bootstrap-completion-evidence.v1",
    a1SecretCensus: {
      initializedWriterTargets: [
        "prooftoact/fresh-cluster/auditor",
        "prooftoact/fresh-primary/cloud-api",
        "prooftoact/fresh-primary/runtime-credentials",
        "prooftoact/gate2/managed-mcp",
        "prooftoact/gate2/recovery-publisher"
      ].map((secretName) => ({ secretName, versionCount: 1 })),
      rawSecretValuesObserved: false,
      sourceReadbackReceiptSha256: "d".repeat(64),
      runtimeGeneratedTargets: [
        `prooftoact/fresh-primary/admin-${OPERATION_ID}`,
        `prooftoact/fresh-primary/recovery-signer-${OPERATION_ID}`
      ].map((secretName) => ({ secretName, versionCount: 0 }))
    },
    a2TargetSecretVersionCount: 0,
    ambiguousState: false,
    b0CredentialsDestroyed: true,
    inFlightChangeSets: [],
    observedAt: "2026-08-18T14:25:00.000Z",
    postCreateReceipts,
    preExecuteReceipts,
    rawCredentialFieldsPresent: false,
    stackStatuses,
    writerState: {
      completedExactlyFiveWrites: true,
      failedWrites: 0,
      rawCredentialFieldsPresent: false,
      roleArn: plan.writerContract.roleArn,
      sessionExpiration: "2026-08-18T14:20:00.000Z",
      sessionExpired: true
    }
  };
}

test("cleanup is fail-closed until three stacks, A1 5/2 census, no inflight work, and expired writer", (t) => {
  const checkout = fixture(t);
  const plan = buildOneTimeBootstrapAuthorityPlan(input(checkout));
  const evidence = completionEvidence(plan, checkout);
  const completion = validateBootstrapCompletionEvidence(plan, evidence);
  const rendered = renderAcceptedBootstrapCleanup(plan, completion, {
    awsCliPath: "/usr/local/bin/aws"
  });
  assert.equal(rendered.commands[0].argv.includes("delete-role-policy"), true);
  assert.equal(rendered.commands[1].argv.includes("delete-role"), true);
  assert.equal(rendered.commands.at(-1).argv.includes("logout"), true);
  for (const mutation of [
    { ambiguousState: true },
    { inFlightChangeSets: ["still-running"] },
    { a2TargetSecretVersionCount: 1 },
    {
      writerState: { ...evidence.writerState, sessionExpired: false }
    }
  ]) {
    assert.throws(() => validateBootstrapCompletionEvidence(plan, {
      ...evidence,
      ...mutation
    }), /ONE_TIME_BOOTSTRAP_COMPLETION_EVIDENCE_REJECTED/u);
  }
  assert.throws(() => renderAcceptedBootstrapCleanup(plan, {
    ...completion,
    noInFlightChangeSets: false
  }, { awsCliPath: "/usr/local/bin/aws" }),
  /ONE_TIME_BOOTSTRAP_CLEANUP_RENDER_REJECTED/u);
});

test("cleanup receipt permits only exact root role lifecycle, serial-bound AssumeRole, and logout", (t) => {
  const checkout = fixture(t);
  const plan = buildOneTimeBootstrapAuthorityPlan(input(checkout));
  const receipt = {
    schemaVersion: "prooftoact.one-time-bootstrap-cleanup.v1",
    accountId: ACCOUNT_ID,
    operationId: OPERATION_ID,
    observedAt: "2026-08-18T14:26:00.000Z",
    b0SessionExpiration: "2026-08-18T14:17:00.000Z",
    writerSessionExpiration: "2026-08-18T14:20:00.000Z",
    bootstrapRoleAbsent: true,
    inlinePolicyAbsent: true,
    b0CredentialsDestroyed: true,
    writerSessionExpired: true,
    rawCredentialFieldsPresent: false,
    b0CredentialEnvironmentKeysPresent: [],
    unexpectedRootMutationEvents: [],
    rootDirectEvents: [
      {
        eventName: "CreateRole",
        roleName: plan.bootstrapRole.name,
        rolePath: plan.bootstrapRole.path
      },
      {
        eventName: "TagRole",
        roleName: plan.bootstrapRole.name,
        tagsSha256: __test.digest(plan.bootstrapRole.roleTags)
      },
      {
        eventName: "PutRolePolicy",
        policyName: plan.bootstrapRole.inlinePolicyName,
        policySha256: plan.bootstrapRole.inlinePolicySha256,
        roleName: plan.bootstrapRole.name
      },
      {
        durationSeconds: 900,
        eventName: "AssumeRole",
        mfaAuthenticated: true,
        serialNumber: MFA_ARN,
        roleArn: plan.bootstrapRole.arn,
        roleSessionName: plan.sessionContract.roleSessionName,
        sourceIdentity: plan.sessionContract.sourceIdentity
      },
      {
        eventName: "DeleteRolePolicy",
        policyName: plan.bootstrapRole.inlinePolicyName,
        roleName: plan.bootstrapRole.name
      },
      { eventName: "DeleteRole", roleName: plan.bootstrapRole.name }
    ],
    awsLogout: {
      cachedRootSessionAbsent: true,
      command: ["aws", "logout", "--profile", plan.account.rootProfile],
      exitCode: 0,
      profile: plan.account.rootProfile
    }
  };
  assert.equal(validateOneTimeBootstrapCleanupReceipt(plan, receipt)
    .rootLoggedOut, true);
  const continued = clone(receipt);
  continued.rootDirectEvents.splice(4, 0,
    clone(continued.rootDirectEvents[3]));
  assert.equal(validateOneTimeBootstrapCleanupReceipt(plan, continued)
    .rootDirectEventCount, 7);
  const forbidden = clone(receipt);
  forbidden.rootDirectEvents.splice(4, 0, {
    eventName: "CreateStack",
    stackName: "prooftoact-workload"
  });
  assert.throws(() => validateOneTimeBootstrapCleanupReceipt(plan, forbidden),
    /ONE_TIME_BOOTSTRAP_CLEANUP_RECEIPT_REJECTED/u);
});

test("target integration hook rejects missing parameter, secret value, workload, retention drift, and byte drift", (t) => {
  const base = targetTemplates();
  const cases = [];
  const missingParameter = clone(base.freshPrimaryCredentialCustody);
  delete missingParameter.Parameters.OperatorAuthorizationSha256;
  cases.push({ freshPrimaryCredentialCustody: missingParameter });
  const secretValue = clone(base.freshPrimaryCredentialCustody);
  secretValue.Resources.ManagedMcpSecret.Properties.SecretString = "forbidden";
  cases.push({ freshPrimaryCredentialCustody: secretValue });
  const workload = clone(base.privateRecoveryQueryBootstrap);
  workload.Resources.Workload = { Type: "AWS::Lambda::Function" };
  cases.push({ privateRecoveryQueryBootstrap: workload });
  const retention = clone(base.freshPrimaryCredentialCustody);
  delete retention.Resources.FreshClusterAuditorSecret.DeletionPolicy;
  cases.push({ freshPrimaryCredentialCustody: retention });
  for (const overrides of cases) {
    const checkout = fixture(t, overrides);
    assert.throws(() => buildOneTimeBootstrapAuthorityPlan(input(checkout)),
      /ONE_TIME_BOOTSTRAP_TARGET_(?:TEMPLATE|ROLE)_REJECTED/u);
  }

  const checkout = fixture(t);
  const wrongDigest = input(checkout);
  wrongDigest.targetTemplateSha256 = {
    ...wrongDigest.targetTemplateSha256,
    freshPrimaryBootstrapRole: "f".repeat(64)
  };
  assert.throws(() => buildOneTimeBootstrapAuthorityPlan(wrongDigest),
    /ONE_TIME_BOOTSTRAP_TARGET_TEMPLATE_REJECTED/u);
});

test("checkout rejects dirty source, linked worktree, and missing reviewed runtime", (t) => {
  const dirty = fixture(t);
  fs.writeFileSync(path.join(dirty.root, "dirty"), "x\n");
  assert.throws(() => validateOneTimeBootstrapCheckout({
    expectedCommit: dirty.identity.commit,
    expectedTree: dirty.identity.tree,
    operationId: OPERATION_ID,
    sourceRoot: dirty.root,
    targetTemplateSha256: dirty.digests
  }), /ONE_TIME_BOOTSTRAP_CHECKOUT_REJECTED/u);

  const base = fixture(t);
  const linked = path.join(base.parent, "linked");
  git(base.root, ["worktree", "add", "-b", "linked-main", linked, "HEAD"]);
  assert.throws(() => validateOneTimeBootstrapCheckout({
    expectedCommit: base.identity.commit,
    expectedTree: base.identity.tree,
    operationId: OPERATION_ID,
    sourceRoot: linked,
    targetTemplateSha256: base.digests
  }), /ONE_TIME_BOOTSTRAP_CHECKOUT_REJECTED/u);
});

test("planner stays built-ins-only; SDK root runtime has no logging or token serialization", () => {
  assert.doesNotMatch(PLANNER_SOURCE, /@aws-sdk|\bfetch\s*\(/u);
  assert.doesNotMatch(PLANNER_SOURCE,
    /from\s+["']node:(?:http|https|net|tls|dns|dgram)["']/u);
  assert.equal((PLANNER_SOURCE.match(/execFileSync\s*\(/gu) ?? []).length, 1);
  assert.match(PLANNER_SOURCE, /execFileSync\(\s*"\/usr\/bin\/git"/u);
  assert.match(ROOT_ASSUME_SOURCE, /@aws-sdk\/client-sts/u);
  assert.doesNotMatch(ROOT_ASSUME_SOURCE,
    /@aws-sdk\/credential-provider-(?:ini|node)/u);
  assert.match(ROOT_ASSUME_SOURCE,
    /process\.env\.AWS_PROFILE === plan\.account\.rootProfile/u);
  assert.match(ROOT_ASSUME_SOURCE, /AWS_CONFIG_FILE/u);
  assert.match(ROOT_ASSUME_SOURCE, /AWS_ENDPOINT_URL/u);
  assert.match(ROOT_ASSUME_SOURCE, /plan\.account\.rootProfile === "default"/u);
  assert.match(ROOT_ASSUME_SOURCE, /\["login_session"\]/u);
  assert.doesNotMatch(ROOT_ASSUME_SOURCE,
    /console\.|process\.(?:stdout|stderr)\.write|JSON\.stringify/u);
  assert.doesNotMatch(ROOT_ASSUME_SOURCE, /--token-code|file:\/\/\/dev\/fd/u);
  const cli = execFileSync(process.execPath, [
    path.join(ROOT, oneTimeBootstrapConstants.PLANNER_PATH)
  ], {
    cwd: ROOT,
    encoding: "utf8",
    env: { PATH: "/usr/bin:/bin" },
    stdio: ["ignore", "pipe", "pipe"]
  });
  assert.equal(cli,
    "HOLD:ONE_TIME_BOOTSTRAP_AUTHORITY_REQUIRES_EXACT_INPUT_AND_STAGED_READBACK\n");
});
