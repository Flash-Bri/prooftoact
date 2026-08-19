import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  __test,
  buildFreshPrimaryCredentialSealApproval,
  sealFreshPrimaryCredentialCustody
} from "../scripts/fresh-primary-credential-sealer.js";
import {
  prepareFreshPrimaryCredentialCustody
} from "../scripts/prepare-fresh-primary-credential-custody.js";
import {
  FRESH_PRIMARY_RUNTIME_USERS
} from "../scripts/bootstrap-fresh-primary.js";

const ACCOUNT = "111111111111";
const OPERATION_ID = "123e4567-e89b-42d3-a456-426614174000";
const NOW = "2026-08-19T05:00:00.000Z";
const NOW_MS = Date.parse(NOW);
const PLAN = prepareFreshPrimaryCredentialCustody({
  accountId: ACCOUNT,
  operationId: OPERATION_ID,
  operatorAuthorizationSha256: "f".repeat(64),
  sourceCommit: "a".repeat(40),
  treeDigest: "b".repeat(40)
});
const SUFFIXES = Object.freeze({
  admin: "Aa11Bb",
  auditor: "Cc22Dd",
  cloudApi: "Ee33Ff",
  credential: "Gg44Hh",
  mcp: "Ii55Jj",
  publisher: "Kk66Ll",
  signer: "Mm77Nn"
});
const ARNS = Object.fromEntries(Object.entries(PLAN.secretNames).map(
  ([name, secretName]) => [name,
    `arn:aws:secretsmanager:us-east-1:${ACCOUNT}:secret:` +
    `${secretName}-${SUFFIXES[name]}`]
));
const VALUES = Object.freeze({
  auditor: "auditor-token-with-at-least-twenty-private-characters",
  cloudApi: "creator-token-with-at-least-twenty-private-characters",
  credential: `${JSON.stringify({
    passwords: Object.fromEntries(FRESH_PRIMARY_RUNTIME_USERS.map(
      (name, index) => [name, `${String(index).padStart(2, "0")}-` +
        "p".repeat(40)]
    )),
    schemaVersion: "prooftoact.fresh-primary-credentials.v2"
  })}\n`,
  mcp: "managed-mcp-private-transport-value",
  publisher: "recovery-publisher-private-database-value"
});
const DIGESTS = Object.freeze(Object.fromEntries(Object.entries(VALUES).map(
  ([name, value]) => [name, sha256(value)]
)));
const APPROVAL = buildFreshPrimaryCredentialSealApproval({
  approvedAt: "2026-08-19T04:55:00.000Z",
  expectedValueSha256: DIGESTS,
  expiresAt: "2026-08-19T05:25:00.000Z",
  operatorAuthorizationSha256: PLAN.operatorAuthorizationSha256,
  plan: PLAN,
  secretArns: ARNS
});

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

class FakeProvider {
  constructor() {
    this.calls = [];
    this.versions = Object.fromEntries(Object.keys(ARNS).map((name) =>
      [name, {}]));
    this.ackLoss = new Set();
    this.tagMutation = null;
  }

  nameForArn(arn) {
    const pair = Object.entries(ARNS).find(([, candidate]) => candidate === arn);
    assert.ok(pair);
    return pair[0];
  }

  async getCallerIdentity() {
    this.calls.push(["identity"]);
    return {
      Account: ACCOUNT,
      Arn: `arn:aws:sts::${ACCOUNT}:assumed-role/` +
        `${PLAN.writerRoleName}/${PLAN.writerSessionName}`,
      UserId: `AROA${"0".repeat(16)}:${PLAN.writerSessionName}`
    };
  }

  async describeSecret({ arn }) {
    const name = this.nameForArn(arn);
    this.calls.push(["describe", name]);
    const tags = Object.entries(__test.expectedTags(PLAN, name)).map(
      ([Key, Value]) => ({ Key, Value })
    );
    tags.push(
      { Key: "aws:cloudformation:logical-id", Value: logicalId(name) },
      {
        Key: "aws:cloudformation:stack-id",
        Value: `arn:aws:cloudformation:us-east-1:${ACCOUNT}:stack/` +
          `${PLAN.stackName}/123e4567-e89b-42d3-a456-426614174001`
      },
      { Key: "aws:cloudformation:stack-name", Value: PLAN.stackName }
    );
    if (this.tagMutation?.name === name) this.tagMutation.mutate(tags);
    return {
      ARN: arn,
      Name: PLAN.secretNames[name],
      RotationEnabled: false,
      Tags: tags,
      VersionIdsToStages: Object.fromEntries(Object.entries(
        this.versions[name]
      ).map(([versionId, value]) => [versionId, value.VersionStages]))
    };
  }

  async getSecretResourcePolicy({ arn }) {
    const name = this.nameForArn(arn);
    this.calls.push(["policy", name]);
    return { ARN: arn };
  }

  async listSecretVersions({ arn, nextToken }) {
    const name = this.nameForArn(arn);
    this.calls.push(["versions", name, nextToken]);
    assert.equal(nextToken, null);
    return {
      ARN: arn,
      Versions: Object.entries(this.versions[name]).map(
        ([VersionId, value]) => ({
          CreatedDate: new Date(NOW),
          VersionId,
          VersionStages: value.VersionStages
        })
      )
    };
  }

  async putSecretVersion({ arn, clientRequestToken, secretString }) {
    const name = this.nameForArn(arn);
    this.calls.push(["put", name, clientRequestToken]);
    assert.equal(__test.WRITER_TARGETS.includes(name), true);
    const current = this.versions[name][clientRequestToken];
    if (current !== undefined) {
      assert.equal(current.SecretString, secretString);
    } else {
      assert.equal(Object.keys(this.versions[name]).length, 0);
      this.versions[name][clientRequestToken] = {
        SecretString: secretString,
        VersionStages: ["AWSCURRENT"]
      };
    }
    if (this.ackLoss.delete(name)) throw new Error("acknowledgement lost");
    return { ARN: arn, VersionId: clientRequestToken };
  }

  async readSecretVersion({ arn, versionId }) {
    const name = this.nameForArn(arn);
    this.calls.push(["read", name, versionId]);
    const value = this.versions[name][versionId];
    if (value === undefined) return null;
    return {
      ARN: arn,
      CreatedDate: new Date(NOW),
      SecretString: value.SecretString,
      VersionId: versionId,
      VersionStages: value.VersionStages
    };
  }
}

function logicalId(name) {
  return {
    admin: "FreshPrimaryAdminSecret",
    auditor: "FreshClusterAuditorSecret",
    cloudApi: "FreshPrimaryCloudApiSecret",
    credential: "FreshPrimaryRuntimeCredentialsSecret",
    mcp: "ManagedMcpSecret",
    publisher: "RecoveryPublisherSecret",
    signer: "FreshPrimaryRecoverySignerSecret"
  }[name];
}

function seal(provider) {
  return sealFreshPrimaryCredentialCustody({
    approval: APPROVAL,
    clock: () => NOW_MS,
    plan: PLAN,
    provider,
    secretArns: ARNS,
    values: VALUES
  });
}

test("zero-version custody converges to exactly five immutable versions and two empty targets", async () => {
  const provider = new FakeProvider();
  const receipt = await seal(provider);
  assert.equal(receipt.status,
    "EXACT_FIVE_VERSIONS_SEALED_TWO_TARGETS_EMPTY");
  assert.equal(receipt.immutableVersionCount, 5);
  assert.equal(receipt.runtimeGeneratedTargetCount, 2);
  assert.equal(receipt.runtimeGeneratedTargetsEmpty, true);
  assert.equal(receipt.approvalSha256, __test.digest(APPROVAL));
  assert.match(receipt.receiptSha256, /^[0-9a-f]{64}$/u);
  assert.equal(provider.calls.filter(([action]) => action === "put").length, 5);
  for (const name of __test.WRITER_TARGETS) {
    assert.equal(Object.keys(provider.versions[name]).length, 1);
    assert.equal(receipt.sealed[name].dispatchCount, 1);
    assert.equal(receipt.sealed[name].secretValueSha256, DIGESTS[name]);
  }
  for (const name of __test.RUNTIME_TARGETS) {
    assert.equal(Object.keys(provider.versions[name]).length, 0);
    assert.equal(provider.calls.some(([action, target]) =>
      ["put", "read"].includes(action) && target === name), false);
  }
  assert.equal(JSON.stringify(receipt).includes(VALUES.auditor), false);
  assert.equal(JSON.stringify(receipt).includes(ARNS.auditor), false);
});

test("seal approval binds time, source, plan, ARNs, digests, and operator receipt before AWS", async () => {
  for (const [approval, secretArns, clock] of [
    [APPROVAL, ARNS, () => Date.parse(APPROVAL.expiresAt)],
    [{ ...APPROVAL, sourceCommit: "0".repeat(40) }, ARNS, () => NOW_MS],
    [APPROVAL, { ...ARNS, mcp: ARNS.publisher }, () => NOW_MS],
    [{
      ...APPROVAL,
      operatorAuthorizationSha256: "0".repeat(64)
    }, ARNS, () => NOW_MS]
  ]) {
    const provider = new FakeProvider();
    await assert.rejects(sealFreshPrimaryCredentialCustody({
      approval,
      clock,
      plan: PLAN,
      provider,
      secretArns,
      values: VALUES
    }), /FRESH_CREDENTIAL_(?:APPROVAL|ARNS)_REJECTED/u);
    assert.deepEqual(provider.calls, []);
  }
});

test("Put acknowledgement loss reconciles the deterministic version without retry", async () => {
  const provider = new FakeProvider();
  provider.ackLoss.add("credential");
  const receipt = await seal(provider);
  assert.equal(receipt.sealed.credential.reconciledAcknowledgementLoss, true);
  assert.equal(provider.calls.filter(([action, name]) =>
    action === "put" && name === "credential").length, 1);
  assert.equal(Object.keys(provider.versions.credential).length, 1);
});

test("rerun reads exact existing versions and dispatches no second puts", async () => {
  const provider = new FakeProvider();
  await seal(provider);
  provider.calls.length = 0;
  const receipt = await seal(provider);
  assert.equal(provider.calls.some(([action]) => action === "put"), false);
  assert.equal(Object.values(receipt.sealed).every((entry) =>
    entry.reconciledExistingVersion === true && entry.dispatchCount === 0),
  true);
});

test("preexisting runtime target or a second writer version rejects before mutation", async () => {
  for (const mutate of [
    (provider) => {
      provider.versions.admin["1".repeat(32)] = {
        SecretString: "must-remain-empty",
        VersionStages: ["AWSCURRENT"]
      };
    },
    (provider) => {
      provider.versions.auditor["1".repeat(32)] = {
        SecretString: VALUES.auditor,
        VersionStages: ["AWSCURRENT"]
      };
      provider.versions.auditor["2".repeat(32)] = {
        SecretString: VALUES.auditor,
        VersionStages: ["AWSPREVIOUS"]
      };
    }
  ]) {
    const provider = new FakeProvider();
    mutate(provider);
    await assert.rejects(seal(provider),
      /FRESH_CREDENTIAL_(?:RUNTIME_TARGET_NOT_EMPTY|PRESTATE_REJECTED)/u);
    assert.equal(provider.calls.some(([action]) => action === "put"), false);
  }
});

test("wrong tags, ARN, value digest, or version value fail closed without leakage", async () => {
  const tagged = new FakeProvider();
  tagged.tagMutation = {
    name: "admin",
    mutate(tags) {
      tags.find(({ Key }) => Key === "Purpose").Value = "Wrong";
    }
  };
  await assert.rejects(seal(tagged), /FRESH_CREDENTIAL_DESCRIPTION_REJECTED/u);
  assert.equal(tagged.calls.some(([action]) => action === "put"), false);

  await assert.rejects(sealFreshPrimaryCredentialCustody({
    approval: APPROVAL,
    clock: () => NOW_MS,
    plan: PLAN,
    provider: new FakeProvider(),
    secretArns: { ...ARNS, admin: ARNS.signer },
    values: VALUES
  }), /FRESH_CREDENTIAL_ARNS_REJECTED/u);

  await assert.rejects(sealFreshPrimaryCredentialCustody({
    approval: buildFreshPrimaryCredentialSealApproval({
      approvedAt: APPROVAL.approvedAt,
      expectedValueSha256: { ...DIGESTS, mcp: "0".repeat(64) },
      expiresAt: APPROVAL.expiresAt,
      operatorAuthorizationSha256: APPROVAL.operatorAuthorizationSha256,
      plan: PLAN,
      secretArns: ARNS
    }),
    clock: () => NOW_MS,
    plan: PLAN,
    provider: new FakeProvider(),
    secretArns: ARNS,
    values: VALUES
  }), /FRESH_CREDENTIAL_VALUES_REJECTED/u);

  const preexisting = new FakeProvider();
  const token = __test.versionId(
    PLAN, "publisher", ARNS.publisher, DIGESTS.publisher
  );
  preexisting.versions.publisher[token] = {
    SecretString: "wrong-value-with-the-right-deterministic-token",
    VersionStages: ["AWSCURRENT"]
  };
  await assert.rejects(seal(preexisting),
    /FRESH_CREDENTIAL_VERSION_READBACK_REJECTED/u);
  assert.equal(preexisting.calls.some(([action]) => action === "put"), false);
});

test("complete version inventory supports zero/one pages and rejects pagination ambiguity", async () => {
  const arn = ARNS.auditor;
  for (const pages of [
    [
      { ARN: arn, Versions: [], NextToken: "next" },
      { ARN: arn, Versions: [] }
    ],
    [
      { ARN: arn, Versions: [], NextToken: "next" },
      {
        ARN: arn,
        Versions: [{
          VersionId: "1".repeat(32),
          VersionStages: ["AWSCURRENT"]
        }]
      }
    ]
  ]) {
    let index = 0;
    const result = await __test.listAllVersions({
      async listSecretVersions() {
        return pages[index++];
      }
    }, arn);
    assert.equal(Object.keys(result).length,
      pages[1].Versions.length);
  }
  let index = 0;
  const cyclic = [
    { ARN: arn, Versions: [], NextToken: "same" },
    { ARN: arn, Versions: [], NextToken: "same" }
  ];
  await assert.rejects(__test.listAllVersions({
    async listSecretVersions() {
      return cyclic[index++];
    }
  }, arn), /FRESH_CREDENTIAL_VERSION_LIST_REJECTED/u);
});
