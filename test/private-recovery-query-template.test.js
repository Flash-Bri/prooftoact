import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { buildPrivateRecoveryQueryLambda } from
  "../scripts/build-private-recovery-query-lambda.js";
import {
  buildPrivateRecoveryQueryTemplate,
  privateRecoveryQueryTemplateReceipt
} from "../src/cloud/private-recovery-query-template.js";

test("mini-stack owns one private exact-version Lambda with no public trigger", () => {
  const template = buildPrivateRecoveryQueryTemplate();
  const resources = Object.values(template.Resources);
  assert.equal(resources.filter(({ Type }) => Type === "AWS::Lambda::Function")
    .length, 1);
  assert.equal(resources.filter(({ Type }) => Type === "AWS::Lambda::Version")
    .length, 1);
  assert.equal(resources.some(({ Type }) => [
    "AWS::Lambda::Url", "AWS::ApiGatewayV2::Api", "AWS::Lambda::EventSourceMapping"
  ].includes(Type)), false);
  const fn = template.Resources.PrivateRecoveryFunction.Properties;
  assert.equal(fn.ReservedConcurrentExecutions, 1);
  assert.equal(Object.hasOwn(fn, "VpcConfig"), false);
  assert.equal(Object.hasOwn(fn, "DeadLetterConfig"), false);
  assert.equal(fn.Runtime, "nodejs22.x");
  assert.equal(fn.Handler, "index.handler");
  assert.equal(fn.Environment.Variables.AWS_ACCESS_KEY_ID, undefined);
  assert.equal(fn.Environment.Variables.AWS_REGION, undefined);
  assert.equal(resources.some(({ Type }) =>
    Type === "AWS::Lambda::Permission"), false);
  const receipt = privateRecoveryQueryTemplateReceipt();
  assert.equal(receipt.functionUrlCount, 0);
  assert.equal(receipt.publicApiCount, 0);
  assert.equal(receipt.vpcAttached, false);
});

test("runtime and operator are restricted to one operation key and one secret", () => {
  const template = buildPrivateRecoveryQueryTemplate();
  const runtimeStatements = template.Resources.PrivateRecoveryRuntimeRole
    .Properties.Policies[0].PolicyDocument.Statement;
  const operatorStatements = template.Resources.PrivateRecoveryOperatorRole
    .Properties.Policies[0].PolicyDocument.Statement;
  const runtimeDdb = runtimeStatements.find(({ Sid }) =>
    Sid === "UseOnlyPrivateRecoveryQueryItems");
  const operatorDdb = operatorStatements.find(({ Sid }) =>
    Sid === "ReserveAndReadOneShotState");
  for (const statement of [runtimeDdb, operatorDdb]) {
    assert.deepEqual(statement.Action, ["dynamodb:GetItem", "dynamodb:UpdateItem"]);
    assert.deepEqual(
      statement.Condition["ForAllValues:StringEquals"].dynamodbLeadingKeys,
      undefined
    );
    assert.deepEqual(
      statement.Condition["ForAllValues:StringEquals"]["dynamodb:LeadingKeys"],
      [{ "Fn::Sub": "PRIVATE_RECOVERY_QUERY#${OperationGlobalKeySha256}" }]
    );
    assert.deepEqual(statement.Condition.Null, {
      "dynamodb:LeadingKeys": "false"
    });
  }
  const secretAllow = runtimeStatements.find(({ Sid }) =>
    Sid === "ReadOneImmutableMcpSecret");
  assert.equal(secretAllow.Action, "secretsmanager:GetSecretValue");
  assert.deepEqual(secretAllow.Resource, { Ref: "McpSecretArn" });
  assert.equal(operatorStatements.some(({ Action, Effect }) =>
    Effect === "Allow" && (Action === "secretsmanager:GetSecretValue" ||
      (Array.isArray(Action) && Action.includes("secretsmanager:GetSecretValue")))),
  false);
});

test("OIDC trust pins protected environment and immutable reusable workflow", () => {
  const template = buildPrivateRecoveryQueryTemplate();
  const trust = template.Resources.PrivateRecoveryOperatorRole.Properties
    .AssumeRolePolicyDocument.Statement[0].Condition.StringEquals;
  assert.equal(trust["token.actions.githubusercontent.com:environment"],
    "aws-private-recovery-query");
  assert.deepEqual(trust["token.actions.githubusercontent.com:job_workflow_ref"], {
    "Fn::Sub":
      "Flash-Bri/prooftoact/.github/workflows/prooftoact-sealed-private-recovery-query.yml@${SealedWorkflowCommit}"
  });
  assert.equal(trust["token.actions.githubusercontent.com:ref"],
    "refs/heads/main");
  assert.equal(trust["token.actions.githubusercontent.com:workflow"],
    "ProofToAct Private Recovery Query");
  assert.equal(
    Object.hasOwn(trust, "token.actions.githubusercontent.com:repository_owner"),
    false
  );
  const evidenceTrust = template.Resources.PrivateRecoveryEvidenceRole.Properties
    .AssumeRolePolicyDocument.Statement[0].Condition.StringEquals;
  assert.equal(evidenceTrust["token.actions.githubusercontent.com:environment"],
    "aws-private-recovery-evidence");
  assert.deepEqual(
    evidenceTrust["token.actions.githubusercontent.com:job_workflow_ref"],
    { "Fn::Sub": "Flash-Bri/prooftoact/.github/workflows/" +
      "prooftoact-sealed-private-recovery-evidence.yml@${EvidenceWorkflowCommit}" }
  );
  const teardownTrust = template.Resources.PrivateRecoveryTeardownRole.Properties
    .AssumeRolePolicyDocument.Statement[0].Condition.StringEquals;
  assert.equal(teardownTrust["token.actions.githubusercontent.com:environment"],
    "aws-private-recovery-teardown");
  assert.deepEqual(
    teardownTrust["token.actions.githubusercontent.com:job_workflow_ref"],
    { "Fn::Sub": "Flash-Bri/prooftoact/.github/workflows/" +
      "prooftoact-sealed-private-recovery-teardown.yml@${TeardownWorkflowCommit}" }
  );
  const evidenceRead = template.Resources.PrivateRecoveryEvidenceRole.Properties
    .Policies[0].PolicyDocument.Statement.find(({ Sid }) =>
      Sid === "ReadExactLambdaConfiguration");
  assert.equal(JSON.stringify(evidenceRead.Resource).includes(
    "function:prooftoact-private-recovery-query*"), false);
  assert.equal(JSON.stringify(evidenceRead.Resource).includes(
    "function:prooftoact-private-recovery-query:*"), true);
});

test("deterministic builder reproduces identical source bundle and template", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "pta-private-recovery-build-"));
  try {
    const first = await buildPrivateRecoveryQueryLambda(path.join(root, "first"));
    const second = await buildPrivateRecoveryQueryLambda(path.join(root, "second"));
    assert.equal(first.status, "PASS");
    assert.equal(first.artifactSha256, second.artifactSha256);
    assert.equal(first.bundleSha256, second.bundleSha256);
    assert.equal(first.templateSha256, second.templateSha256);
    const archive = fs.readFileSync(path.join(root, "first", first.artifactPath));
    assert.equal(archive.includes(Buffer.from("synthetic-managed-mcp-credential")),
      false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("sealed workflow requires a GitHub-bound authority commit and tree", () => {
  for (const lane of [
    "deploy", "evidence", "query", "secret-seal", "teardown"
  ]) {
    const sealed = fs.readFileSync(new URL(
      `../.github/workflows/prooftoact-sealed-private-recovery-${lane}.yml`,
      import.meta.url), "utf8");
    const caller = fs.readFileSync(new URL(
      `../.github/workflows/prooftoact-private-recovery-${lane}.yml`,
      import.meta.url), "utf8");
    assert.match(sealed,
      /authority_commit:\n\s+required: true\n\s+type: string/u);
    assert.match(sealed,
      /authority_tree:\n\s+required: true\n\s+type: string/u);
    assert.match(sealed,
      /name: Bind immutable reusable source before protected material/u);
    assert.match(sealed,
      /test "\$AUTHORITY_COMMIT" != "0{40}"/u);
    assert.match(caller, new RegExp(
      `prooftoact-sealed-private-recovery-${lane}\\.yml@0{40}`, "u"));
    assert.match(caller, /authority_commit: "0{40}"/u);
    assert.match(caller, /authority_tree: "0{40}"/u);
    assert.match(caller,
      /permissions:\n      contents: read\n      id-token: write/u);
    assert.match(sealed, /ref: \$\{\{ inputs\.authority_commit \}\}/u);
    assert.doesNotMatch(sealed, /REVIEWED_RUNTIME_(?:COMMIT|TREE)/u);
    assert.match(sealed, /npm run security:verify/u);
    assert.match(sealed, /npm run privacy:verify/u);
    assert.match(sealed, /npm run proof:verify/u);
    assert.doesNotMatch(sealed, /pull_request_target|repository_dispatch/u);
    assert.doesNotMatch(caller, /pull_request_target|repository_dispatch/u);
  }
  const deploy = fs.readFileSync(new URL(
    "../.github/workflows/prooftoact-sealed-private-recovery-deploy.yml",
    import.meta.url), "utf8");
  assert.match(deploy,
    /artifact-version-census\.json/u);
  assert.match(deploy, /deploy-private-recovery-query\.js/u);
  assert.match(deploy,
    /lexical minimum is a deterministic version choice across reruns/u);
  assert.doesNotMatch(deploy,
    /change_set=.*GITHUB_RUN_ID|execute-change-set.*GITHUB_RUN_ID/us);
});
