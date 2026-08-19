import { createHash } from "node:crypto";

import { canonicalJson } from "./canonical-json.js";

const STACK_NAME = "prooftoact-private-recovery-query";
const FUNCTION_NAME = "prooftoact-private-recovery-query";
const RUNTIME_ROLE_NAME = "ProofToActPrivateRecoveryQueryRuntime";
const OPERATOR_ROLE_NAME = "ProofToActPrivateRecoveryQueryOperator";
const EVIDENCE_ROLE_NAME = "ProofToActPrivateRecoveryQueryEvidence";
const TEARDOWN_ROLE_NAME = "ProofToActPrivateRecoveryQueryTeardown";
const WORKFLOW_FILE = "prooftoact-sealed-private-recovery-query.yml";
const EVIDENCE_WORKFLOW_FILE =
  "prooftoact-sealed-private-recovery-evidence.yml";
const TEARDOWN_WORKFLOW_FILE =
  "prooftoact-sealed-private-recovery-teardown.yml";
const CALLER_WORKFLOW_NAME = "ProofToAct Private Recovery Query";
const EVIDENCE_CALLER_WORKFLOW_NAME = "ProofToAct Private Recovery Evidence";
const TEARDOWN_CALLER_WORKFLOW_NAME = "ProofToAct Private Recovery Teardown";
const SEALED_WORKFLOW_NAME = "ProofToAct Sealed Private Recovery Query";

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function sub(value, variables = undefined) {
  return variables === undefined
    ? { "Fn::Sub": value }
    : { "Fn::Sub": [value, variables] };
}

function ref(value) {
  return { Ref: value };
}

function getAtt(resource, attribute) {
  return { "Fn::GetAtt": [resource, attribute] };
}

function denyActions(sid, actions) {
  return {
    Sid: sid,
    Effect: "Deny",
    Action: actions,
    Resource: "*"
  };
}

export function buildPrivateRecoveryQueryTemplate() {
  const template = {
    AWSTemplateFormatVersion: "2010-09-09",
    Description:
      "Private one-shot AWS Lambda retrieval of one signed ProofToAct recovery row through CockroachDB Cloud Managed MCP; no URL, VPC, event source, or public invocation.",
    Metadata: {
      ProofToAct: {
        boundary: "RECOVERED_CONTEXT_ONLY",
        publicEndpoint: false,
        providerCallCount: 1,
        schemaVersion: "prooftoact.private-recovery-query-stack.v1"
      }
    },
    Parameters: {
      ApprovalSha256: {
        Type: "String",
        AllowedPattern: "^[0-9a-f]{64}$"
      },
      ArtifactBucketName: {
        Type: "String",
        AllowedPattern: "^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$"
      },
      ArtifactKey: {
        Type: "String",
        AllowedPattern:
          "^private-recovery-query/[0-9a-f]{40}/private-recovery-query-[0-9a-f]{64}\\.zip$"
      },
      ArtifactObjectVersion: {
        Type: "String",
        AllowedPattern: "^[A-Za-z0-9._~-]{1,1024}$"
      },
      CodeSha256Base64: {
        Type: "String",
        AllowedPattern: "^[A-Za-z0-9+/]{43}=$"
      },
      CodeZipSha256: {
        Type: "String",
        AllowedPattern: "^[0-9a-f]{64}$"
      },
      CloudFormationServiceRoleArn: {
        Type: "String",
        AllowedPattern:
          "^arn:aws:iam::[0-9]{12}:role/ProofToActPrivateRecoveryQueryCloudFormation$"
      },
      ConfigSha256: {
        Type: "String",
        AllowedPattern: "^[0-9a-f]{64}$"
      },
      GitHubOidcProviderArn: {
        Type: "String",
        AllowedPattern:
          "^arn:aws:iam::[0-9]{12}:oidc-provider/token\\.actions\\.githubusercontent\\.com$"
      },
      EvidenceWorkflowCommit: {
        Type: "String",
        AllowedPattern: "^[0-9a-f]{40}$"
      },
      McpSecretArn: {
        Type: "String",
        AllowedPattern:
          "^arn:aws:secretsmanager:us-east-1:[0-9]{12}:secret:prooftoact/private-recovery-query/managed-mcp-[A-Za-z0-9]{6}$"
      },
      McpSecretVersionId: {
        Type: "String",
        AllowedPattern: "^[A-Za-z0-9_-]{32,64}$",
        NoEcho: true
      },
      OperationGlobalKeySha256: {
        Type: "String",
        AllowedPattern: "^[0-9a-f]{64}$"
      },
      PermissionsBoundaryArn: {
        Type: "String",
        AllowedPattern:
          "^arn:aws:iam::[0-9]{12}:policy/ProofToActPrivateRecoveryQueryBoundary$"
      },
      ReleaseControlTableArn: {
        Type: "String",
        AllowedPattern:
          "^arn:aws:dynamodb:us-east-1:[0-9]{12}:table/prooftoact-release-controller$"
      },
      SealedWorkflowCommit: {
        Type: "String",
        AllowedPattern: "^[0-9a-f]{40}$"
      },
      TeardownWorkflowCommit: {
        Type: "String",
        AllowedPattern: "^[0-9a-f]{40}$"
      },
      TemplateSha256: {
        Type: "String",
        AllowedPattern: "^[0-9a-f]{64}$"
      },
      SourceCommit: {
        Type: "String",
        AllowedPattern: "^[0-9a-f]{40}$"
      },
      TreeDigest: {
        Type: "String",
        AllowedPattern: "^[0-9a-f]{40}$"
      }
    },
    Resources: {
      PrivateRecoveryLogGroup: {
        Type: "AWS::Logs::LogGroup",
        Properties: {
          LogGroupName: `/aws/lambda/${FUNCTION_NAME}`,
          RetentionInDays: 1,
          Tags: [
            { Key: "Project", Value: "ProofToAct" },
            { Key: "Purpose", Value: "PrivateRecoveryQuery" }
          ]
        },
        DeletionPolicy: "Delete",
        UpdateReplacePolicy: "Delete"
      },
      PrivateRecoveryRuntimeRole: {
        Type: "AWS::IAM::Role",
        Properties: {
          RoleName: RUNTIME_ROLE_NAME,
          PermissionsBoundary: ref("PermissionsBoundaryArn"),
          AssumeRolePolicyDocument: {
            Version: "2012-10-17",
            Statement: [{
              Effect: "Allow",
              Principal: { Service: "lambda.amazonaws.com" },
              Action: "sts:AssumeRole"
            }]
          },
          Policies: [{
            PolicyName: "ProofToActPrivateRecoveryQueryRuntimeOnly",
            PolicyDocument: {
              Version: "2012-10-17",
              Statement: [
                {
                  Sid: "WriteOnlyThisLogGroup",
                  Effect: "Allow",
                  Action: ["logs:CreateLogStream", "logs:PutLogEvents"],
                  Resource: sub(
                    "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/lambda/prooftoact-private-recovery-query:*"
                  )
                },
                {
                  Sid: "ReadOneImmutableMcpSecret",
                  Effect: "Allow",
                  Action: "secretsmanager:GetSecretValue",
                  Resource: ref("McpSecretArn")
                },
                {
                  Sid: "DenyOtherSecretReads",
                  Effect: "Deny",
                  Action: "secretsmanager:GetSecretValue",
                  NotResource: ref("McpSecretArn")
                },
                {
                  Sid: "UseOnlyPrivateRecoveryQueryItems",
                  Effect: "Allow",
                  Action: ["dynamodb:GetItem", "dynamodb:UpdateItem"],
                  Resource: ref("ReleaseControlTableArn"),
                  Condition: {
                    "ForAllValues:StringEquals": {
                      "dynamodb:LeadingKeys": [sub(
                        "PRIVATE_RECOVERY_QUERY#${OperationGlobalKeySha256}"
                      )]
                    },
                    Null: {
                      "dynamodb:LeadingKeys": "false"
                    }
                  }
                },
                {
                  Sid: "DenyOtherDynamoTables",
                  Effect: "Deny",
                  Action: "dynamodb:*",
                  NotResource: ref("ReleaseControlTableArn")
                },
                denyActions("DenyPrivilegeAndOtherProviders", [
                  "iam:*", "sts:*", "kms:*", "bedrock:*", "lambda:*",
                  "apigateway:*", "apigatewayv2:*", "cloudformation:*",
                  "secretsmanager:ListSecrets", "secretsmanager:PutSecretValue",
                  "secretsmanager:UpdateSecret", "secretsmanager:DeleteSecret"
                ])
              ]
            }
          }],
          Tags: [
            { Key: "Project", Value: "ProofToAct" },
            { Key: "Purpose", Value: "PrivateRecoveryQueryRuntime" }
          ]
        }
      },
      PrivateRecoveryFunction: {
        Type: "AWS::Lambda::Function",
        DependsOn: "PrivateRecoveryLogGroup",
        Properties: {
          FunctionName: FUNCTION_NAME,
          Architectures: ["arm64"],
          Code: {
            S3Bucket: ref("ArtifactBucketName"),
            S3Key: ref("ArtifactKey"),
            S3ObjectVersion: ref("ArtifactObjectVersion")
          },
          Description:
            "Private exact-version one-shot Managed MCP recovery query; emits sanitized receipt only.",
          Environment: {
            Variables: {
              APPROVAL_SHA256: ref("ApprovalSha256"),
              CODE_ZIP_SHA256: ref("CodeZipSha256"),
              CONFIG_SHA256: ref("ConfigSha256"),
              FUNCTION_ARN: sub(
                "arn:${AWS::Partition}:lambda:${AWS::Region}:${AWS::AccountId}:function:prooftoact-private-recovery-query"
              ),
              MCP_SECRET_ARN: ref("McpSecretArn"),
              MCP_SECRET_VERSION_ID: ref("McpSecretVersionId"),
              OPERATION_GLOBAL_KEY_SHA256: ref("OperationGlobalKeySha256"),
              RELEASE_CONTROL_TABLE_ARN: ref("ReleaseControlTableArn"),
              SOURCE_COMMIT: ref("SourceCommit"),
              TREE_DIGEST: ref("TreeDigest")
            }
          },
          EphemeralStorage: { Size: 512 },
          Handler: "index.handler",
          LoggingConfig: {
            ApplicationLogLevel: "ERROR",
            LogFormat: "JSON",
            LogGroup: `/aws/lambda/${FUNCTION_NAME}`,
            SystemLogLevel: "WARN"
          },
          MemorySize: 256,
          ReservedConcurrentExecutions: 1,
          Role: getAtt("PrivateRecoveryRuntimeRole", "Arn"),
          Runtime: "nodejs22.x",
          Tags: [
            { Key: "Project", Value: "ProofToAct" },
            { Key: "Purpose", Value: "PrivateRecoveryQuery" }
          ],
          Timeout: 120,
          TracingConfig: { Mode: "PassThrough" }
        }
      },
      PrivateRecoveryVersion: {
        Type: "AWS::Lambda::Version",
        Properties: {
          CodeSha256: ref("CodeSha256Base64"),
          Description: sub(
            "ProofToAct private recovery query ${SourceCommit}/${ConfigSha256}"
          ),
          FunctionName: ref("PrivateRecoveryFunction")
        }
      },
      PrivateRecoveryOperatorRole: {
        Type: "AWS::IAM::Role",
        Properties: {
          RoleName: OPERATOR_ROLE_NAME,
          PermissionsBoundary: ref("PermissionsBoundaryArn"),
          AssumeRolePolicyDocument: {
            Version: "2012-10-17",
            Statement: [{
              Effect: "Allow",
              Principal: { Federated: ref("GitHubOidcProviderArn") },
              Action: "sts:AssumeRoleWithWebIdentity",
              Condition: {
                StringEquals: {
                  "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                  "token.actions.githubusercontent.com:sub":
                    "repo:Flash-Bri@252500266/prooftoact@1317716765:environment:aws-private-recovery-query",
                  "token.actions.githubusercontent.com:repository":
                    "Flash-Bri/prooftoact",
                  "token.actions.githubusercontent.com:repository_id": "1317716765",
                  "token.actions.githubusercontent.com:repository_owner_id": "252500266",
                  "token.actions.githubusercontent.com:ref": "refs/heads/main",
                  "token.actions.githubusercontent.com:environment":
                    "aws-private-recovery-query",
                  "token.actions.githubusercontent.com:job_workflow_ref": sub(
                    `Flash-Bri/prooftoact/.github/workflows/${WORKFLOW_FILE}@\${SealedWorkflowCommit}`
                  ),
                  "token.actions.githubusercontent.com:workflow":
                    CALLER_WORKFLOW_NAME
                }
              }
            }]
          },
          Policies: [{
            PolicyName: "ProofToActPrivateRecoveryQueryOperatorOnly",
            PolicyDocument: {
              Version: "2012-10-17",
              Statement: [
                {
                  Sid: "InvokeOneNumericVersion",
                  Effect: "Allow",
                  Action: "lambda:InvokeFunction",
                  Resource: sub(
                    "${FunctionArn}:${Version}",
                    {
                      FunctionArn: getAtt("PrivateRecoveryFunction", "Arn"),
                      Version: ref("PrivateRecoveryVersion")
                    }
                  )
                },
                {
                  Sid: "DenyOtherFunctionVersions",
                  Effect: "Deny",
                  Action: "lambda:InvokeFunction",
                  NotResource: sub(
                    "${FunctionArn}:${Version}",
                    {
                      FunctionArn: getAtt("PrivateRecoveryFunction", "Arn"),
                      Version: ref("PrivateRecoveryVersion")
                    }
                  )
                },
                {
                  Sid: "ReserveAndReadOneShotState",
                  Effect: "Allow",
                  Action: ["dynamodb:GetItem", "dynamodb:UpdateItem"],
                  Resource: ref("ReleaseControlTableArn"),
                  Condition: {
                    "ForAllValues:StringEquals": {
                      "dynamodb:LeadingKeys": [sub(
                        "PRIVATE_RECOVERY_QUERY#${OperationGlobalKeySha256}"
                      )]
                    },
                    Null: {
                      "dynamodb:LeadingKeys": "false"
                    }
                  }
                },
                denyActions("DenyCredentialAndMutationExpansion", [
                  "secretsmanager:GetSecretValue", "secretsmanager:ListSecrets",
                  "iam:*", "kms:*", "bedrock:*", "apigateway:*",
                  "apigatewayv2:*", "cloudformation:CreateStack",
                  "cloudformation:UpdateStack", "cloudformation:DeleteStack"
                ])
              ]
            }
          }],
          Tags: [
            { Key: "Project", Value: "ProofToAct" },
            { Key: "Purpose", Value: "PrivateRecoveryQueryOperator" }
          ]
        }
      },
      PrivateRecoveryEvidenceRole: {
        Type: "AWS::IAM::Role",
        Properties: {
          RoleName: EVIDENCE_ROLE_NAME,
          PermissionsBoundary: ref("PermissionsBoundaryArn"),
          AssumeRolePolicyDocument: {
            Version: "2012-10-17",
            Statement: [{
              Effect: "Allow",
              Principal: { Federated: ref("GitHubOidcProviderArn") },
              Action: "sts:AssumeRoleWithWebIdentity",
              Condition: {
                StringEquals: {
                  "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                  "token.actions.githubusercontent.com:sub":
                    "repo:Flash-Bri@252500266/prooftoact@1317716765:environment:aws-private-recovery-evidence",
                  "token.actions.githubusercontent.com:repository":
                    "Flash-Bri/prooftoact",
                  "token.actions.githubusercontent.com:repository_id": "1317716765",
                  "token.actions.githubusercontent.com:repository_owner_id": "252500266",
                  "token.actions.githubusercontent.com:ref": "refs/heads/main",
                  "token.actions.githubusercontent.com:environment":
                    "aws-private-recovery-evidence",
                  "token.actions.githubusercontent.com:job_workflow_ref": sub(
                    `Flash-Bri/prooftoact/.github/workflows/${EVIDENCE_WORKFLOW_FILE}@\${EvidenceWorkflowCommit}`
                  ),
                  "token.actions.githubusercontent.com:workflow":
                    EVIDENCE_CALLER_WORKFLOW_NAME
                }
              }
            }]
          },
          Policies: [{
            PolicyName: "ProofToActPrivateRecoveryQueryEvidenceOnly",
            PolicyDocument: {
              Version: "2012-10-17",
              Statement: [
                {
                  Sid: "ReadExactStack",
                  Effect: "Allow",
                  Action: [
                    "cloudformation:DescribeStackResources",
                    "cloudformation:DescribeStacks",
                    "cloudformation:GetTemplate"
                  ],
                  Resource: sub(
                    "arn:${AWS::Partition}:cloudformation:us-east-1:${AWS::AccountId}:stack/prooftoact-private-recovery-query/*"
                  )
                },
                {
                  Sid: "ReadExactLambdaConfiguration",
                  Effect: "Allow",
                  Action: [
                    "lambda:GetFunction",
                    "lambda:GetFunctionConfiguration",
                    "lambda:GetFunctionConcurrency",
                    "lambda:GetPolicy",
                    "lambda:ListFunctionUrlConfigs",
                    "lambda:ListTags"
                  ],
                  Resource: [
                    sub(
                      "arn:${AWS::Partition}:lambda:us-east-1:${AWS::AccountId}:function:prooftoact-private-recovery-query"
                    ),
                    sub(
                      "arn:${AWS::Partition}:lambda:us-east-1:${AWS::AccountId}:function:prooftoact-private-recovery-query:*"
                    )
                  ]
                },
                {
                  Sid: "ReadLambdaEventSourceCensus",
                  Effect: "Allow",
                  Action: "lambda:ListEventSourceMappings",
                  Resource: "*"
                },
                {
                  Sid: "ReadExactRoles",
                  Effect: "Allow",
                  Action: [
                    "iam:GetRole",
                    "iam:GetRolePolicy",
                    "iam:ListAttachedRolePolicies",
                    "iam:ListRolePolicies",
                    "iam:ListRoleTags"
                  ],
                  Resource: [
                    sub("arn:${AWS::Partition}:iam::${AWS::AccountId}:role/ProofToActPrivateRecoveryQueryRuntime"),
                    sub("arn:${AWS::Partition}:iam::${AWS::AccountId}:role/ProofToActPrivateRecoveryQueryOperator"),
                    sub("arn:${AWS::Partition}:iam::${AWS::AccountId}:role/ProofToActPrivateRecoveryQueryEvidence"),
                    sub("arn:${AWS::Partition}:iam::${AWS::AccountId}:role/ProofToActPrivateRecoveryQueryTeardown"),
                    ref("CloudFormationServiceRoleArn")
                  ]
                },
                {
                  Sid: "ReadSecretMetadataOnly",
                  Effect: "Allow",
                  Action: [
                    "secretsmanager:DescribeSecret",
                    "secretsmanager:ListSecretVersionIds"
                  ],
                  Resource: ref("McpSecretArn")
                },
                {
                  Sid: "ReadReleaseControlTableIdentity",
                  Effect: "Allow",
                  Action: "dynamodb:DescribeTable",
                  Resource: ref("ReleaseControlTableArn")
                },
                {
                  Sid: "ReadExactOperation",
                  Effect: "Allow",
                  Action: "dynamodb:GetItem",
                  Resource: ref("ReleaseControlTableArn"),
                  Condition: {
                    "ForAllValues:StringEquals": {
                      "dynamodb:LeadingKeys": [sub(
                        "PRIVATE_RECOVERY_QUERY#${OperationGlobalKeySha256}"
                      )]
                    },
                    Null: {
                      "dynamodb:LeadingKeys": "false"
                    }
                  }
                },
                {
                  Sid: "ReadOwnIdentity",
                  Effect: "Allow",
                  Action: "sts:GetCallerIdentity",
                  Resource: "*"
                },
                denyActions("DenyEvidenceMutationSecretsAndInvocation", [
                  "bedrock:*", "cloudformation:Create*", "cloudformation:Delete*",
                  "cloudformation:Execute*", "cloudformation:Update*",
                  "dynamodb:BatchWriteItem", "dynamodb:DeleteItem",
                  "dynamodb:PutItem", "dynamodb:TransactWriteItems",
                  "dynamodb:UpdateItem", "iam:Add*", "iam:Attach*", "iam:Create*",
                  "iam:Delete*", "iam:Detach*", "iam:PassRole", "iam:Put*",
                  "iam:Remove*", "iam:Set*", "iam:Tag*", "iam:Untag*",
                  "iam:Update*", "kms:*", "lambda:Invoke*", "s3:Delete*",
                  "s3:Put*", "secretsmanager:GetSecretValue",
                  "secretsmanager:ListSecrets", "secretsmanager:PutSecretValue",
                  "secretsmanager:UpdateSecret", "sts:AssumeRole"
                ])
              ]
            }
          }],
          Tags: [
            { Key: "Project", Value: "ProofToAct" },
            { Key: "Purpose", Value: "PrivateRecoveryQueryEvidence" }
          ]
        }
      },
      PrivateRecoveryTeardownRole: {
        Type: "AWS::IAM::Role",
        Properties: {
          RoleName: TEARDOWN_ROLE_NAME,
          PermissionsBoundary: ref("PermissionsBoundaryArn"),
          AssumeRolePolicyDocument: {
            Version: "2012-10-17",
            Statement: [{
              Effect: "Allow",
              Principal: { Federated: ref("GitHubOidcProviderArn") },
              Action: "sts:AssumeRoleWithWebIdentity",
              Condition: {
                StringEquals: {
                  "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                  "token.actions.githubusercontent.com:sub":
                    "repo:Flash-Bri@252500266/prooftoact@1317716765:environment:aws-private-recovery-teardown",
                  "token.actions.githubusercontent.com:repository":
                    "Flash-Bri/prooftoact",
                  "token.actions.githubusercontent.com:repository_id": "1317716765",
                  "token.actions.githubusercontent.com:repository_owner_id": "252500266",
                  "token.actions.githubusercontent.com:ref": "refs/heads/main",
                  "token.actions.githubusercontent.com:environment":
                    "aws-private-recovery-teardown",
                  "token.actions.githubusercontent.com:job_workflow_ref": sub(
                    `Flash-Bri/prooftoact/.github/workflows/${TEARDOWN_WORKFLOW_FILE}@\${TeardownWorkflowCommit}`
                  ),
                  "token.actions.githubusercontent.com:workflow":
                    TEARDOWN_CALLER_WORKFLOW_NAME
                }
              }
            }]
          },
          Policies: [{
            PolicyName: "ProofToActPrivateRecoveryQueryTeardownOnly",
            PolicyDocument: {
              Version: "2012-10-17",
              Statement: [
                {
                  Sid: "DeleteOnlyExactStack",
                  Effect: "Allow",
                  Action: [
                    "cloudformation:DeleteStack",
                    "cloudformation:DescribeStackEvents",
                    "cloudformation:DescribeStackResources",
                    "cloudformation:DescribeStacks",
                    "cloudformation:GetTemplate",
                    "cloudformation:UpdateTerminationProtection"
                  ],
                  Resource: sub(
                    "arn:${AWS::Partition}:cloudformation:us-east-1:${AWS::AccountId}:stack/prooftoact-private-recovery-query/*"
                  )
                },
                {
                  Sid: "PassOnlyDedicatedCloudFormationRole",
                  Effect: "Allow",
                  Action: "iam:PassRole",
                  Resource: ref("CloudFormationServiceRoleArn"),
                  Condition: {
                    StringEquals: {
                      "iam:PassedToService": "cloudformation.amazonaws.com"
                    }
                  }
                },
                {
                  Sid: "ReadExactTerminalState",
                  Effect: "Allow",
                  Action: "dynamodb:GetItem",
                  Resource: ref("ReleaseControlTableArn"),
                  Condition: {
                    "ForAllValues:StringEquals": {
                      "dynamodb:LeadingKeys": [sub(
                        "PRIVATE_RECOVERY_QUERY#${OperationGlobalKeySha256}"
                      )]
                    },
                    Null: {
                      "dynamodb:LeadingKeys": "false"
                    }
                  }
                },
                {
                  Sid: "ReadOwnIdentity",
                  Effect: "Allow",
                  Action: "sts:GetCallerIdentity",
                  Resource: "*"
                },
                denyActions("DenyNonTeardownCapabilities", [
                  "bedrock:*", "cloudformation:Create*", "cloudformation:Execute*",
                  "cloudformation:UpdateStack", "dynamodb:DeleteItem",
                  "dynamodb:PutItem", "dynamodb:UpdateItem", "iam:Add*",
                  "iam:Attach*", "iam:Create*", "iam:Delete*", "iam:Detach*",
                  "iam:Put*", "iam:Remove*", "iam:Set*", "iam:Tag*",
                  "iam:Untag*", "iam:Update*", "kms:*", "lambda:Invoke*",
                  "s3:Delete*", "s3:Put*", "secretsmanager:*", "sts:AssumeRole"
                ]),
                {
                  Sid: "DenyPassingAnyOtherRole",
                  Effect: "Deny",
                  Action: "iam:PassRole",
                  NotResource: ref("CloudFormationServiceRoleArn")
                }
              ]
            }
          }],
          Tags: [
            { Key: "Project", Value: "ProofToAct" },
            { Key: "Purpose", Value: "PrivateRecoveryQueryTeardown" }
          ]
        }
      },
    },
    Outputs: {
      ApprovalSha256: { Value: ref("ApprovalSha256") },
      CodeZipSha256: { Value: ref("CodeZipSha256") },
      ConfigSha256: { Value: ref("ConfigSha256") },
      FunctionArn: { Value: getAtt("PrivateRecoveryFunction", "Arn") },
      FunctionVersion: { Value: ref("PrivateRecoveryVersion") },
      EvidenceRoleArn: { Value: getAtt("PrivateRecoveryEvidenceRole", "Arn") },
      OperatorRoleArn: { Value: getAtt("PrivateRecoveryOperatorRole", "Arn") },
      OperationGlobalKeySha256: { Value: ref("OperationGlobalKeySha256") },
      RuntimeRoleArn: { Value: getAtt("PrivateRecoveryRuntimeRole", "Arn") },
      SourceCommit: { Value: ref("SourceCommit") },
      TeardownRoleArn: { Value: getAtt("PrivateRecoveryTeardownRole", "Arn") },
      TemplateSha256: { Value: ref("TemplateSha256") },
      TreeDigest: { Value: ref("TreeDigest") }
    }
  };
  return Object.freeze(template);
}

export function privateRecoveryQueryTemplateReceipt() {
  const template = buildPrivateRecoveryQueryTemplate();
  return Object.freeze({
    schemaVersion: "prooftoact.private-recovery-query-template-receipt.v1",
    status: "SOURCE_TEMPLATE_READY",
    functionCount: 1,
    functionUrlCount: 0,
    publicApiCount: 0,
    reservedConcurrency: 1,
    resourceCount: Object.keys(template.Resources).length,
    stackName: STACK_NAME,
    templateSha256: sha256(canonicalJson(template)),
    vpcAttached: false
  });
}

export const __test = Object.freeze({
  FUNCTION_NAME,
  CALLER_WORKFLOW_NAME,
  OPERATOR_ROLE_NAME,
  RUNTIME_ROLE_NAME,
  STACK_NAME,
  SEALED_WORKFLOW_NAME,
  WORKFLOW_FILE
});
