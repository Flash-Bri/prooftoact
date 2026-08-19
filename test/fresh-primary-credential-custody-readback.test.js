import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  __test,
  freshPrimaryCredentialSecretArnsFromStackOutputs,
  verifyFreshPrimaryCredentialCustodyReadback
} from "../scripts/fresh-primary-credential-custody-readback.js";
import {
  __test as sealerTest,
  buildFreshPrimaryCredentialSealApproval
} from "../scripts/fresh-primary-credential-sealer.js";
import {
  __test as planTest,
  prepareFreshPrimaryCredentialCustody
} from "../scripts/prepare-fresh-primary-credential-custody.js";

const ACCOUNT = "111111111111";
const OPERATION = "123e4567-e89b-42d3-a456-426614174000";
const PLAN = prepareFreshPrimaryCredentialCustody({
  accountId: ACCOUNT,
  operationId: OPERATION,
  operatorAuthorizationSha256: "f".repeat(64),
  sourceCommit: "a".repeat(40),
  treeDigest: "b".repeat(40)
});
const TEMPLATE = planTest.readReviewedTemplate().template;
const OUTPUT_NAMES = Object.freeze({
  admin: "AdminSecretArn",
  auditor: "AuditorSecretArn",
  cloudApi: "CloudApiSecretArn",
  credential: "RuntimeCredentialsSecretArn",
  mcp: "ManagedMcpSecretArn",
  publisher: "RecoveryPublisherSecretArn",
  signer: "SignerSecretArn"
});
const LOGICAL_NAMES = Object.freeze({
  admin: "FreshPrimaryAdminSecret",
  auditor: "FreshClusterAuditorSecret",
  cloudApi: "FreshPrimaryCloudApiSecret",
  credential: "FreshPrimaryRuntimeCredentialsSecret",
  mcp: "ManagedMcpSecret",
  publisher: "RecoveryPublisherSecret",
  signer: "FreshPrimaryRecoverySignerSecret"
});
const ARNS = Object.fromEntries(Object.entries(PLAN.secretNames).map(
  ([name, secretName], index) => [name,
    `arn:aws:secretsmanager:us-east-1:${ACCOUNT}:secret:` +
    `${secretName}-${String(index).padStart(6, "A")}`]
));
const DIGESTS = Object.freeze(Object.fromEntries(
  sealerTest.WRITER_TARGETS.map((name, index) =>
    [name, String(index + 1).repeat(64)])
));
const APPROVAL = buildFreshPrimaryCredentialSealApproval({
  approvedAt: "2026-08-19T04:50:00.000Z",
  expectedValueSha256: DIGESTS,
  expiresAt: "2026-08-19T05:20:00.000Z",
  operatorAuthorizationSha256: PLAN.operatorAuthorizationSha256,
  plan: PLAN,
  secretArns: ARNS
});
const COLLECTOR_ROLE_NAME =
  `ProofToActBootstrapCreator-${PLAN.operationToken}`;
const COLLECTOR_SESSION_NAME = `prooftoact-bootstrap-${PLAN.operationToken}`;
const COLLECTOR_BINDING = Object.freeze({
  accountId: ACCOUNT,
  assumedRoleArn: `arn:aws:sts::${ACCOUNT}:assumed-role/` +
    `${COLLECTOR_ROLE_NAME}/${COLLECTOR_SESSION_NAME}`,
  operationId: OPERATION,
  operationToken: PLAN.operationToken,
  operatorAuthorizationSha256: PLAN.operatorAuthorizationSha256,
  roleArn: PLAN.bootstrapCreatorRoleArn,
  roleName: COLLECTOR_ROLE_NAME,
  rolePath: "/prooftoact/bootstrap/",
  sessionName: COLLECTOR_SESSION_NAME,
  sourceCommit: PLAN.sourceCommit,
  sourceIdentity: `prooftoact-b0-${PLAN.operationToken}`,
  treeDigest: PLAN.treeDigest
});

function sourceContract() {
  return __test.sourceContract(PLAN, ARNS, TEMPLATE);
}

function sealReceipt() {
  const sealed = Object.fromEntries(sealerTest.WRITER_TARGETS.map(
    (name, index) => [name, {
      createdAt: `2026-08-19T05:00:0${index}.000Z`,
      dispatchCount: 1,
      reconciledAcknowledgementLoss: false,
      secretArnSha256: APPROVAL.secretBindings[name].secretArnSha256,
      secretValueSha256: APPROVAL.secretBindings[name].expectedValueSha256,
      secretVersionIdSha256:
        rawHash(APPROVAL.secretBindings[name].clientRequestToken),
      versionStage: "AWSCURRENT"
    }]
  ));
  const body = {
    schemaVersion: "prooftoact.fresh-primary-credential-seal-receipt.v1",
    status: "EXACT_FIVE_VERSIONS_SEALED_TWO_TARGETS_EMPTY",
    accountId: ACCOUNT,
    approvalSha256: __test.digest(APPROVAL),
    caller: {
      accountId: ACCOUNT,
      assumedRoleArnSha256: "7".repeat(64),
      roleId: `AROA${"7".repeat(16)}`,
      roleName: PLAN.writerRoleName,
      sessionName: PLAN.writerSessionName
    },
    custodyPlanSha256: PLAN.planSha256,
    immutableVersionCount: 5,
    operationId: OPERATION,
    runtimeGeneratedTargetCount: 2,
    runtimeGeneratedTargetsEmpty: true,
    sealed,
    sourceCommit: PLAN.sourceCommit,
    templateSha256: PLAN.templateSha256,
    treeDigest: PLAN.treeDigest,
    writerRoleArnSha256: rawHash(PLAN.writerRoleArn)
  };
  return { ...body, receiptSha256: __test.digest(body) };
}

function rawHash(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function fixture(phase = "EMPTY", creatorState = "PRESENT") {
  const contract = sourceContract();
  const outputs = {
    WriterRoleArn: PLAN.writerRoleArn,
    ...Object.fromEntries(Object.entries(OUTPUT_NAMES).map(
      ([name, output]) => [output, ARNS[name]]
    ))
  };
  const trust = structuredClone(contract.trust);
  if (creatorState === "DELETED") {
    trust.Statement[0].Principal.AWS = `AROA${"9".repeat(16)}`;
  }
  const secrets = Object.fromEntries(Object.keys(PLAN.secretNames).map(
    (name) => [name, {
      arn: ARNS[name],
      kmsKeyId: null,
      name: PLAN.secretNames[name],
      replicationRegions: [],
      resourcePolicy: null,
      rotationEnabled: false,
      tags: Object.entries(sealerTest.expectedTags(PLAN, name)).map(
        ([Key, Value]) => ({ Key, Value })
      ),
      versions: phase === "SEALED" &&
        sealerTest.WRITER_TARGETS.includes(name)
        ? { [APPROVAL.secretBindings[name].clientRequestToken]: ["AWSCURRENT"] }
        : {}
    }]
  ));
  return {
    collectorBinding: structuredClone(COLLECTOR_BINDING),
    plan: PLAN,
    input: {
      schemaVersion: __test.INPUT_SCHEMA,
      approval: phase === "SEALED" ? APPROVAL : null,
      callerIdentity: {
        Account: ACCOUNT,
        Arn: COLLECTOR_BINDING.assumedRoleArn,
        UserId: `AROA${"0".repeat(16)}:${COLLECTOR_SESSION_NAME}`
      },
      creatorRole: creatorState === "PRESENT"
        ? { assumeRoleDenied: false, getRoleError: null, state: "PRESENT" }
        : {
          assumeRoleDenied: true,
          getRoleError: "NoSuchEntity",
          state: "DELETED"
        },
      deployedTemplate: structuredClone(TEMPLATE),
      observedAt: "2026-08-19T05:10:00.000Z",
      phase,
      resources: [
        ...Object.entries(LOGICAL_NAMES).map(([name, logicalResourceId]) => ({
          logicalResourceId,
          physicalResourceId: ARNS[name],
          resourceStatus: "CREATE_COMPLETE",
          resourceType: "AWS::SecretsManager::Secret"
        })),
        {
          logicalResourceId: "FreshPrimaryCredentialWriterRole",
          physicalResourceId: PLAN.writerRoleName,
          resourceStatus: "CREATE_COMPLETE",
          resourceType: "AWS::IAM::Role"
        }
      ],
      sealReceipt: phase === "SEALED" ? sealReceipt() : null,
      secrets,
      stack: {
        capabilities: ["CAPABILITY_NAMED_IAM"],
        creationTime: "2026-08-19T04:45:00.000Z",
        outputs,
        parameters: PLAN.parameters,
        stackId: `arn:aws:cloudformation:us-east-1:${ACCOUNT}:stack/` +
          `${PLAN.stackName}/123e4567-e89b-42d3-a456-426614174001`,
        stackName: PLAN.stackName,
        stackStatus: "CREATE_COMPLETE",
        tags: Object.entries(PLAN.requiredStackTags).map(([Key, Value]) => ({
          Key, Value
        })),
        terminationProtection: true
      },
      writerRole: {
        arn: PLAN.writerRoleArn,
        attachedPolicyArns: [],
        description: contract.roleDescription,
        inlinePolicy: structuredClone(contract.inlinePolicy),
        inlinePolicyNames: [contract.inlinePolicyName],
        maxSessionDuration: 3600,
        path: PLAN.writerRolePath,
        permissionsBoundaryArn: null,
        roleId: `AROA${"1".repeat(16)}`,
        roleName: PLAN.writerRoleName,
        tags: Object.entries(contract.roleTags).map(([Key, Value]) => ({
          Key, Value
        })),
        trust
      }
    }
  };
}

test("credential custody readback accepts exact seven empty containers", () => {
  const candidate = fixture();
  const receipt = verifyFreshPrimaryCredentialCustodyReadback(candidate);
  assert.equal(receipt.status, "EXACT_SEVEN_EMPTY_CONTAINERS_ACCEPTED");
  assert.equal(receipt.phase, "EMPTY");
  assert.equal(Object.values(receipt.secrets).every((secret) =>
    secret.versionCount === 0), true);
  assert.equal(receipt.writer.creatorPrincipalOpaque, false);
  assert.match(receipt.receiptSha256, /^[0-9a-f]{64}$/u);
  assert.deepEqual(
    freshPrimaryCredentialSecretArnsFromStackOutputs({
      outputs: candidate.input.stack.outputs,
      plan: candidate.plan
    }),
    Object.fromEntries(Object.entries(candidate.input.secrets).map(
      ([name, secret]) => [name, secret.arn]
    ))
  );
});

test("credential readback rejects stack, role, tag, policy, or version drift", () => {
  for (const mutate of [
    ({ collectorBinding }) => {
      collectorBinding.operatorAuthorizationSha256 = "0".repeat(64);
    },
    ({ input }) => {
      input.callerIdentity.Arn = input.callerIdentity.Arn.replace(
        "prooftoact-bootstrap-", "wrong-"
      );
    },
    ({ input }) => { input.stack.terminationProtection = false; },
    ({ input }) => { input.resources.pop(); },
    ({ input }) => { input.writerRole.attachedPolicyArns.push("admin"); },
    ({ input }) => {
      input.writerRole.permissionsBoundaryArn =
        "arn:aws:iam::aws:policy/AdministratorAccess";
    },
    ({ input }) => {
      input.writerRole.inlinePolicy.Statement[0].Action.push("iam:*");
    },
    ({ input }) => {
      input.secrets.admin.tags.push({ Key: "Unexpected", Value: "unsafe" });
    },
    ({ input }) => {
      input.secrets.admin.versions["1".repeat(32)] = ["AWSCURRENT"];
    }
  ]) {
    const candidate = fixture();
    mutate(candidate);
    assert.throws(() => verifyFreshPrimaryCredentialCustodyReadback(candidate),
      /FRESH_(?:CREDENTIAL_READBACK|BOOTSTRAP_COLLECTOR)_/u);
  }
});

test("sealed readback proves five exact versions, two empty targets, and opaque deleted creator", () => {
  const candidate = fixture("SEALED", "DELETED");
  const receipt = verifyFreshPrimaryCredentialCustodyReadback(candidate);
  assert.equal(receipt.status,
    "EXACT_FIVE_SEALED_TWO_EMPTY_CREATOR_LIFECYCLE_ACCEPTED");
  assert.equal(receipt.creatorRoleState, "DELETED");
  assert.equal(receipt.writer.creatorPrincipalOpaque, true);
  assert.equal(receipt.secrets.admin.versionCount, 0);
  assert.equal(receipt.secrets.signer.versionCount, 0);
  assert.equal(sealerTest.WRITER_TARGETS.every((name) =>
    receipt.secrets[name].versionCount === 1), true);

  candidate.input.writerRole.trust.Statement[0].Principal.AWS =
    PLAN.bootstrapCreatorRoleArn;
  assert.throws(() => verifyFreshPrimaryCredentialCustodyReadback(candidate),
    /FRESH_CREDENTIAL_READBACK_WRITER_REJECTED/u);
});
