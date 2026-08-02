import assert from "node:assert/strict";
import test from "node:test";

import {
  DEPLOYMENT_API_ROUTE_KEYS,
  DEPLOYMENT_FUNCTIONS
} from "../src/cloud/aws-deployment-attestation.js";
import { buildGate2Template } from "../src/cloud/aws-gate2-template.js";

test("deployment evidence role explicitly denies privilege escalation", () => {
  const template = buildGate2Template();
  const statements =
    template.Resources.DeploymentEvidenceRole.Properties.Policies[0]
      .PolicyDocument.Statement;
  const denied = new Set(
    statements
      .filter((statement) => statement.Effect === "Deny")
      .flatMap((statement) =>
        Array.isArray(statement.Action)
          ? statement.Action
          : [statement.Action]
      )
  );

  assert.equal(denied.has("iam:*"), false);
  assert.equal(denied.has("sts:AssumeRole"), true);
  assert.equal(denied.has("bedrock:*"), true);
  assert.equal(denied.has("kms:*"), true);
  assert.equal(denied.has("lambda:Invoke*"), true);
  assert.equal(denied.has("secretsmanager:*"), true);
  const allowed = statements
    .filter((statement) => statement.Effect === "Allow")
    .flatMap((statement) =>
      Array.isArray(statement.Action)
        ? statement.Action
        : [statement.Action]
    );
  for (const action of allowed) {
    assert.equal(
      [...denied].some(
        (candidate) =>
          candidate === action ||
          (candidate.endsWith("*") &&
            action.startsWith(candidate.slice(0, -1)))
      ),
      false,
      `${action} must not be shadowed by an explicit deny`
    );
  }

  const statementBySid = Object.fromEntries(
    statements.map((statement) => [statement.Sid, statement])
  );
  assert.deepEqual(
    statementBySid.ReadExactHttpApiDeployment.Action,
    ["apigateway:GET"]
  );
  assert.equal(
    statementBySid.ReadExactHttpApiDeployment.Resource.length,
    2
  );
  assert.deepEqual(
    statementBySid.ReadLambdaEventSourceCensus,
    {
      Sid: "ReadLambdaEventSourceCensus",
      Effect: "Allow",
      Action: ["lambda:ListEventSourceMappings"],
      Resource: "*"
    }
  );
  for (const action of [
    "iam:ListRoleTags",
    "lambda:ListAliases",
    "lambda:ListFunctionUrlConfigs",
    "lambda:ListTags"
  ]) {
    assert.equal(allowed.includes(action), true, `${action} must be allowed`);
  }
});

test("deployment evidence drift permission is scoped to attested resources", async () => {
  const { __test } = await import("../scripts/gate2-aws-attestation.js");
  const expected = [
    "DefaultStage",
    "AuthoritySemanticFailureAlarm",
    "BoundarySemanticFailureAlarm",
    "DeploymentEvidenceAlternateRole",
    "DeploymentEvidenceRole",
    "HttpApi",
    ...Object.keys(DEPLOYMENT_API_ROUTE_KEYS),
    ...DEPLOYMENT_FUNCTIONS.flatMap((name) => {
      const title = `${name[0].toUpperCase()}${name.slice(1)}`;
      return [
        `${title}Alias`,
        `${title}Function`,
        `${title}Role`,
        `${title}Version`
      ];
    })
  ].sort();
  assert.equal(expected.length, 37);
  assert.deepEqual(__test.ATTESTED_DRIFT_LOGICAL_IDS, expected);
  assert.equal(expected.includes("BoundaryIntegration"), false);
  assert.equal(expected.includes("DemoIntegration"), false);
});

test("HTTP API integrations bind numeric versions and explicit POST semantics", () => {
  const template = buildGate2Template();
  for (const [logicalId, versionLogicalId] of [
    ["BoundaryIntegration", "BoundaryVersion"],
    ["DemoIntegration", "DemoVersion"]
  ]) {
    const properties = template.Resources[logicalId].Properties;
    assert.equal(properties.IntegrationMethod, "POST");
    assert.deepEqual(properties.IntegrationUri, { Ref: versionLogicalId });
    assert.equal(properties.IntegrationType, "AWS_PROXY");
    assert.equal(properties.PayloadFormatVersion, "2.0");
  }
});

test("semantic failure alarms bind provider-emitted boundary and authority metrics", () => {
  const template = buildGate2Template();
  const expectedDimensions = (service) => [
    { Name: "Deployment", Value: { Ref: "AWS::StackName" } },
    { Name: "Service", Value: service }
  ];

  for (const [logicalId, service] of [
    ["BoundarySemanticFailureAlarm", "boundary"],
    ["AuthoritySemanticFailureAlarm", "authority"]
  ]) {
    assert.deepEqual(template.Resources[logicalId], {
      Type: "AWS::CloudWatch::Alarm",
      Properties: {
        AlarmName: {
          "Fn::Sub": `\${AWS::StackName}-${service}-semantic-failures`
        },
        AlarmDescription:
          "A Tideproof Lambda returned a fail-closed semantic outcome without a platform error.",
        Namespace: "Tideproof/GateTwo",
        MetricName: "SemanticFailures",
        Statistic: "Sum",
        Period: 60,
        EvaluationPeriods: 1,
        DatapointsToAlarm: 1,
        Threshold: 1,
        ComparisonOperator: "GreaterThanOrEqualToThreshold",
        TreatMissingData: "notBreaching",
        Dimensions: expectedDimensions(service)
      }
    });
  }

  assert.deepEqual(
    template.Resources.BoundaryFunction.Properties.Environment.Variables
      .SEMANTIC_METRIC_DEPLOYMENT,
    { Ref: "AWS::StackName" }
  );
  assert.deepEqual(
    template.Resources.AuthorityFunction.Properties.Environment.Variables
      .SEMANTIC_METRIC_DEPLOYMENT,
    { Ref: "AWS::StackName" }
  );
});

test("HTTP API stage binds one route-ordered explicit deployment", () => {
  const template = buildGate2Template();
  const deployment = template.Resources.ApiDeployment;
  const routeLogicalIds = [
    "AdvisoryRoute",
    ...Object.keys(DEPLOYMENT_API_ROUTE_KEYS).filter(
      (logicalId) => logicalId !== "AdvisoryRoute"
    )
  ].sort();

  assert.equal(deployment.Type, "AWS::ApiGatewayV2::Deployment");
  assert.deepEqual(deployment.DependsOn, routeLogicalIds);
  assert.deepEqual(deployment.Properties.ApiId, { Ref: "HttpApi" });
  assert.deepEqual(deployment.Properties.Description, {
    "Fn::Sub":
      "Tideproof exact API deployment ${SourceCommit} ${ConfigDigest}"
  });
  assert.equal(template.Resources.DefaultStage.Properties.AutoDeploy, false);
  assert.deepEqual(template.Resources.DefaultStage.Properties.DeploymentId, {
    Ref: "ApiDeployment"
  });
});
