import crypto from "node:crypto";
import { createRequire } from "node:module";
import { PUBLIC_DEMO_PATHS } from "./public-demo.js";

const require = createRequire(import.meta.url);
const {
  PROMPT_TEMPLATE_VERSION,
  VALIDATOR_VERSION
} = require("../../infra/aws/lambda/agent.cjs").__test;

const PUBLIC_DEMO_ROUTE_IDS = Object.freeze({
  "/": "DemoIndexRoute",
  "/app.js": "DemoAppRoute",
  "/styles.css": "DemoStylesRoute",
  "/architecture.svg": "DemoArchitectureRoute",
  "/api/health": "DemoHealthRoute",
  "/api/scenario": "DemoScenarioRoute",
  "/evidence/gate1-authority": "DemoAuthorityEvidenceRoute",
  "/evidence/gate1-recovery": "DemoRecoveryEvidenceRoute",
  "/evidence/gate1-ambiguity": "DemoAmbiguityEvidenceRoute",
  "/claims": "DemoClaimsRoute"
});

function ref(name) {
  return { Ref: name };
}

function getAtt(resource, attribute) {
  return { "Fn::GetAtt": [resource, attribute] };
}

function sub(value) {
  return { "Fn::Sub": value };
}

function fnIf(conditionName, yes, no = ref("AWS::NoValue")) {
  return { "Fn::If": [conditionName, yes, no] };
}

function assumeLambdaRolePolicy() {
  return {
    Version: "2012-10-17",
    Statement: [
      {
        Effect: "Allow",
        Principal: { Service: "lambda.amazonaws.com" },
        Action: "sts:AssumeRole"
      }
    ]
  };
}

function assumeAccountRolePolicy() {
  return {
    Version: "2012-10-17",
    Statement: [
      {
        Effect: "Allow",
        Principal: {
          AWS: sub(
            "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"
          )
        },
        Action: "sts:AssumeRole"
      }
    ]
  };
}

function artifactCode(name) {
  const title = `${name[0].toUpperCase()}${name.slice(1)}`;
  return {
    S3Bucket: ref("ArtifactBucket"),
    S3Key: ref(`${title}ArtifactKey`),
    S3ObjectVersion: ref(`${title}ArtifactVersion`)
  };
}

function exactLogStatement(logicalLogGroup) {
  return {
    Sid: `Write${logicalLogGroup}`,
    Effect: "Allow",
    Action: ["logs:CreateLogStream", "logs:PutLogEvents"],
    Resource: sub(
      `\${${logicalLogGroup}.Arn}:*`
    )
  };
}

function denyPrivilegeEscalation() {
  return {
    Sid: "DenyPrivilegeEscalation",
    Effect: "Deny",
    Action: ["iam:*", "sts:AssumeRole"],
    Resource: "*"
  };
}

function denySecretAccess() {
  return {
    Sid: "DenySecretAccess",
    Effect: "Deny",
    Action: [
      "secretsmanager:BatchGetSecretValue",
      "secretsmanager:GetSecretValue",
      "secretsmanager:ListSecrets"
    ],
    Resource: "*"
  };
}

function denySecretMutation() {
  return {
    Sid: "DenySecretMutation",
    Effect: "Deny",
    Action: [
      "secretsmanager:CreateSecret",
      "secretsmanager:DeleteSecret",
      "secretsmanager:PutResourcePolicy",
      "secretsmanager:PutSecretValue",
      "secretsmanager:RotateSecret",
      "secretsmanager:UpdateSecret"
    ],
    Resource: "*"
  };
}

function denySecretEnumeration() {
  return {
    Sid: "DenySecretEnumeration",
    Effect: "Deny",
    Action: [
      "secretsmanager:BatchGetSecretValue",
      "secretsmanager:ListSecrets"
    ],
    Resource: "*"
  };
}

function denyOtherSecretReads() {
  return {
    Sid: "DenyOtherSecretReads",
    Effect: "Deny",
    Action: ["secretsmanager:GetSecretValue"],
    NotResource: ref("AuthorityDatabaseSecretArn")
  };
}

function denyBedrock() {
  return {
    Sid: "DenyBedrock",
    Effect: "Deny",
    Action: ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
    Resource: "*"
  };
}

function denyKmsSigning() {
  return {
    Sid: "DenyKmsSigning",
    Effect: "Deny",
    Action: ["kms:Sign"],
    Resource: "*"
  };
}

function denyLambdaInvoke() {
  return {
    Sid: "DenyLambdaInvoke",
    Effect: "Deny",
    Action: ["lambda:InvokeFunction"],
    Resource: "*"
  };
}

function roleResource({
  description,
  statements,
  assumeRolePolicy = assumeLambdaRolePolicy()
}) {
  return {
    Type: "AWS::IAM::Role",
    Properties: {
      Description: description,
      AssumeRolePolicyDocument: assumeRolePolicy,
      MaxSessionDuration: 3600,
      Policies: [
        {
          PolicyName: "TideproofExactCapabilities",
          PolicyDocument: {
            Version: "2012-10-17",
            Statement: statements
          }
        }
      ],
      Tags: [
        { Key: "Project", Value: "Tideproof" },
        { Key: "Gate", Value: "Two" }
      ]
    }
  };
}

function lambdaFunction({
  description,
  role,
  code,
  logGroup,
  timeout,
  concurrency,
  environment
}) {
  const properties = {
    Description: description,
    Runtime: "nodejs22.x",
    Architectures: ["arm64"],
    Handler: "index.handler",
    Role: getAtt(role, "Arn"),
    MemorySize: 128,
    Timeout: timeout,
    Environment: { Variables: environment },
    LoggingConfig: {
      LogFormat: "JSON",
      LogGroup: ref(logGroup)
    },
    Code: code,
    Tags: [
      { Key: "Project", Value: "Tideproof" },
      { Key: "Gate", Value: "Two" }
    ]
  };
  if (concurrency !== undefined) {
    properties.ReservedConcurrentExecutions = concurrency;
  }
  return { Type: "AWS::Lambda::Function", Properties: properties };
}

function logGroup() {
  return {
    Type: "AWS::Logs::LogGroup",
    DeletionPolicy: "Delete",
    UpdateReplacePolicy: "Delete",
    Properties: {
      RetentionInDays: 7,
      Tags: [
        { Key: "Project", Value: "Tideproof" },
        { Key: "Gate", Value: "Two" }
      ]
    }
  };
}

function version(functionName, description, artifactName) {
  const title =
    `${artifactName[0].toUpperCase()}${artifactName.slice(1)}`;
  return {
    Type: "AWS::Lambda::Version",
    Properties: {
      FunctionName: ref(functionName),
      CodeSha256: ref(`${title}ArtifactCodeSha256`),
      Description: description
    }
  };
}

function alias(functionName, versionName) {
  return {
    Type: "AWS::Lambda::Alias",
    Properties: {
      Name: "proof",
      FunctionName: ref(functionName),
      FunctionVersion: getAtt(versionName, "Version"),
      Description: "Immutable Gate Two proof alias."
    }
  };
}

function lambdaErrorAlarm(functionName, suffix) {
  return {
    Type: "AWS::CloudWatch::Alarm",
    Properties: {
      AlarmName: sub(`\${AWS::StackName}-${suffix}-errors`),
      AlarmDescription:
        "A Tideproof synthetic Gate Two Lambda recorded an error.",
      Namespace: "AWS/Lambda",
      MetricName: "Errors",
      Statistic: "Sum",
      Period: 60,
      EvaluationPeriods: 1,
      DatapointsToAlarm: 1,
      Threshold: 1,
      ComparisonOperator: "GreaterThanOrEqualToThreshold",
      TreatMissingData: "notBreaching",
      Dimensions: [
        { Name: "FunctionName", Value: ref(functionName) }
      ]
    }
  };
}

function hexParameter(description, length = 64) {
  return {
    Type: "String",
    Description: description,
    AllowedPattern: `^[0-9a-f]{${length}}$`
  };
}

function uuidParameter(description) {
  return {
    Type: "String",
    Description: description,
    AllowedPattern:
      "^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
  };
}

function artifactParameters(name) {
  const title = `${name[0].toUpperCase()}${name.slice(1)}`;
  return {
    [`${title}ArtifactKey`]: {
      Type: "String",
      MinLength: 1,
      Description: `Versioned S3 key for the ${name} artifact.`
    },
    [`${title}ArtifactVersion`]: {
      Type: "String",
      MinLength: 1,
      Description: `Exact S3 object version for the ${name} artifact.`
    },
    [`${title}ArtifactDigest`]: hexParameter(
      `SHA-256 of the uploaded ${name} ZIP.`
    ),
    [`${title}ArtifactCodeSha256`]: {
      Type: "String",
      Description:
        `Base64 SHA-256 of the uploaded ${name} ZIP, enforced by Lambda Version.`,
      AllowedPattern: "^[A-Za-z0-9+/]{43}=$"
    },
    [`${title}SourceDigest`]: hexParameter(
      `SHA-256 of the reviewed ${name} source.`
    )
  };
}

function commonProbeEnvironment(roleClass) {
  return {
    PROBE_ROLE_CLASS: roleClass,
    BEDROCK_MODEL_ID: ref("BedrockModelId"),
    PROBE_OTHER_MODEL_ID: "amazon.nova-lite-v1:0",
    PROBE_KMS_KEY_ARN: getAtt("ReceiptSigningKey", "Arn"),
    PROBE_SECRET_ARN: ref("CapabilityCanarySecret"),
    PROBE_AGENT_FUNCTION_ARN: getAtt("AgentAlias", "AliasArn"),
    PROBE_BOUNDARY_FUNCTION_ARN: getAtt("BoundaryAlias", "AliasArn"),
    PROBE_SIGNER_FUNCTION_ARN: getAtt("SignerAlias", "AliasArn"),
    PROBE_AUTHORITY_FUNCTION_ARN: getAtt("AuthorityAlias", "AliasArn"),
    SOURCE_COMMIT: ref("SourceCommit"),
    CONFIG_DIGEST: ref("ConfigDigest"),
    PROBE_SOURCE_DIGEST: ref("ProbeSourceDigest"),
    PROBE_ARTIFACT_DIGEST: ref("ProbeArtifactDigest"),
    TREE_DIGEST: ref("TreeDigest"),
    PACKAGE_LOCK_DIGEST: ref("PackageLockDigest")
  };
}

function probeFunction(role, logGroup, roleClass) {
  return lambdaFunction({
    description:
      "Disposable Gate Two capability probe using the exact production execution role.",
    role,
    code: artifactCode("probe"),
    logGroup,
    timeout: 25,
    concurrency: 1,
    environment: commonProbeEnvironment(roleClass)
  });
}

function notificationEmailParameter() {
  return {
    Type: "String",
    Description:
      "Private deployment parameter used only for account-wide AWS Budget alerts.",
    AllowedPattern: "^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$",
    NoEcho: true
  };
}

function accountBudgetResource() {
  const notification = (notificationType, threshold) => ({
    Notification: {
      ComparisonOperator: "GREATER_THAN",
      NotificationType: notificationType,
      Threshold: threshold,
      ThresholdType: "ABSOLUTE_VALUE"
    },
    Subscribers: [
      {
        Address: ref("NotificationEmail"),
        SubscriptionType: "EMAIL"
      }
    ]
  });

  return {
    Type: "AWS::Budgets::Budget",
    Properties: {
      Budget: {
        BudgetName: sub("${AWS::StackName}-account-safety"),
        BudgetLimit: { Amount: 15, Unit: "USD" },
        BudgetType: "COST",
        TimeUnit: "MONTHLY"
      },
      NotificationsWithSubscribers: [
        notification("FORECASTED", 15),
        notification("ACTUAL", 1),
        notification("ACTUAL", 5),
        notification("ACTUAL", 10)
      ]
    }
  };
}

export function buildAwsBootstrapTemplate() {
  return {
    AWSTemplateFormatVersion: "2010-09-09",
    Description:
      "Predeployment cost guard and private artifact bucket for Tideproof Gate Two.",
    Parameters: {
      NotificationEmail: notificationEmailParameter()
    },
    Resources: {
      AccountBudget: accountBudgetResource(),
      ArtifactBucket: {
        Type: "AWS::S3::Bucket",
        DependsOn: "AccountBudget",
        DeletionPolicy: "Retain",
        UpdateReplacePolicy: "Retain",
        Properties: {
          BucketEncryption: {
            ServerSideEncryptionConfiguration: [
              {
                ServerSideEncryptionByDefault: {
                  SSEAlgorithm: "AES256"
                }
              }
            ]
          },
          OwnershipControls: {
            Rules: [{ ObjectOwnership: "BucketOwnerEnforced" }]
          },
          PublicAccessBlockConfiguration: {
            BlockPublicAcls: true,
            BlockPublicPolicy: true,
            IgnorePublicAcls: true,
            RestrictPublicBuckets: true
          },
          VersioningConfiguration: { Status: "Enabled" },
          LifecycleConfiguration: {
            Rules: [
              {
                Id: "ExpireNoncurrentArtifacts",
                Status: "Enabled",
                NoncurrentVersionExpiration: {
                  NoncurrentDays: 45
                }
              },
              {
                Id: "AbortIncompleteUploads",
                Status: "Enabled",
                AbortIncompleteMultipartUpload: {
                  DaysAfterInitiation: 1
                }
              }
            ]
          },
          Tags: [
            { Key: "Project", Value: "Tideproof" },
            { Key: "Gate", Value: "Two" }
          ]
        }
      },
      ArtifactBucketPolicy: {
        Type: "AWS::S3::BucketPolicy",
        Properties: {
          Bucket: ref("ArtifactBucket"),
          PolicyDocument: {
            Version: "2012-10-17",
            Statement: [
              {
                Sid: "DenyInsecureTransport",
                Effect: "Deny",
                Principal: "*",
                Action: "s3:*",
                Resource: [
                  getAtt("ArtifactBucket", "Arn"),
                  sub("${ArtifactBucket.Arn}/*")
                ],
                Condition: {
                  Bool: { "aws:SecureTransport": "false" }
                }
              }
            ]
          }
        }
      }
    },
    Outputs: {
      AccountBudgetName: {
        Value: sub("${AWS::StackName}-account-safety")
      },
      ArtifactBucketName: { Value: ref("ArtifactBucket") },
      ArtifactBucketArn: { Value: getAtt("ArtifactBucket", "Arn") }
    }
  };
}

export function buildGate2Template() {
  const parameters = {
    ArtifactBucket: {
      Type: "String",
      MinLength: 3,
      Description:
        "Private, versioned bucket from the reviewed bootstrap stack."
    },
    SourceCommit: hexParameter(
      "Exact clean Git commit deployed by this stack.",
      40
    ),
    ConfigDigest: hexParameter(
      "SHA-256 of the effective nonsecret deployment configuration."
    ),
    TreeDigest: hexParameter(
      "Exact clean Git tree object identifier.",
      40
    ),
    PackageLockDigest: hexParameter("SHA-256 of package-lock.json."),
    BedrockModelId: {
      Type: "String",
      Default: "amazon.nova-micro-v1:0",
      AllowedValues: ["amazon.nova-micro-v1:0"]
    },
    AuthorityDatabaseSecretArn: {
      Type: "String",
      Description:
        "Exact Tideproof-owned Secrets Manager ARN containing only the least-privilege tp_authorizer_user connection string.",
      AllowedPattern:
        "^arn:aws[a-zA-Z-]*:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+$"
    },
    AuthorityTenantId: uuidParameter(
      "Synthetic Gate Two tenant UUID prepared in CockroachDB."
    ),
    AuthorityRunId: uuidParameter(
      "Synthetic active-run UUID prepared in CockroachDB."
    ),
    AuthorityIncidentId: uuidParameter(
      "Synthetic incident UUID bound to the prepared evidence and resource."
    ),
    AuthorityEvidenceId: uuidParameter(
      "Verified synthetic evidence UUID admitted by CockroachDB."
    ),
    AuthorityRaceId: uuidParameter(
      "One exact proof-race UUID accepted by both authority contenders."
    ),
    AuthorityResourceId: {
      Type: "String",
      MinLength: 1,
      MaxLength: 160,
      AllowedPattern: "^[A-Za-z0-9._:-]+$",
      Description:
        "Prepared synthetic resource identifier; never a real-world capability."
    },
    EnableProbeFunctions: {
      Type: "String",
      Default: "false",
      AllowedValues: ["true", "false"],
      Description:
        "Opt in to same-role evidence probes temporarily; update to false after non-final probe receipts are captured."
    },
    ...artifactParameters("agent"),
    ...artifactParameters("boundary"),
    ...artifactParameters("demo"),
    ...artifactParameters("signer"),
    ...artifactParameters("authority"),
    ...artifactParameters("probe")
  };

  const modelArn = sub(
    "arn:${AWS::Partition}:bedrock:${AWS::Region}::foundation-model/${BedrockModelId}"
  );

  const resources = {
    ReceiptSigningKey: {
      Type: "AWS::KMS::Key",
      DeletionPolicy: "Delete",
      UpdateReplacePolicy: "Delete",
      Properties: {
        Description:
          "Synthetic advisory-receipt signer; not an authority or recovery-publisher key.",
        Enabled: true,
        KeySpec: "ECC_NIST_P256",
        KeyUsage: "SIGN_VERIFY",
        Origin: "AWS_KMS",
        MultiRegion: false,
        PendingWindowInDays: 7,
        KeyPolicy: {
          Version: "2012-10-17",
          Statement: [
            {
              Sid: "EnableAccountAdministration",
              Effect: "Allow",
              Principal: {
                AWS: sub(
                  "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"
                )
              },
              Action: "kms:*",
              Resource: "*"
            }
          ]
        },
        Tags: [
          { Key: "Project", Value: "Tideproof" },
          { Key: "Purpose", Value: "SyntheticGateTwoEvidence" }
        ]
      }
    },
    ReceiptSigningAlias: {
      Type: "AWS::KMS::Alias",
      Properties: {
        AliasName: sub("alias/${AWS::StackName}-advisory-receipts"),
        TargetKeyId: ref("ReceiptSigningKey")
      }
    },
    CapabilityCanarySecret: {
      Type: "AWS::SecretsManager::Secret",
      Condition: "ShouldDeployProbes",
      DeletionPolicy: "Delete",
      UpdateReplacePolicy: "Delete",
      Properties: {
        Description:
          "Inert synthetic canary used only to prove runtime secret-read denial.",
        GenerateSecretString: {
          PasswordLength: 32,
          ExcludePunctuation: true
        },
        Tags: [
          { Key: "Project", Value: "Tideproof" },
          { Key: "Purpose", Value: "CapabilityDenialCanary" }
        ]
      }
    },

    AgentLogGroup: logGroup(),
    BoundaryLogGroup: logGroup(),
    DemoLogGroup: logGroup(),
    ApiAccessLogGroup: logGroup(),
    SignerLogGroup: logGroup(),
    AuthorityLogGroup: logGroup(),
    AgentProbeLogGroup: logGroup(),
    BoundaryProbeLogGroup: logGroup(),
    DemoProbeLogGroup: logGroup(),
    SignerProbeLogGroup: logGroup(),
    AuthorityProbeLogGroup: logGroup()
  };

  resources.AgentRole = roleResource({
    description:
      "Proposal-only Bedrock role; no database, MCP, secrets, signing, Lambda invoke, or effect capability.",
    statements: [
      exactLogStatement("AgentLogGroup"),
      fnIf(
        "ShouldDeployProbes",
        exactLogStatement("AgentProbeLogGroup")
      ),
      {
        Sid: "InvokeOneBedrockModel",
        Effect: "Allow",
        Action: ["bedrock:InvokeModel"],
        Resource: modelArn
      },
      {
        Sid: "DenyOtherBedrockModels",
        Effect: "Deny",
        Action: [
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream"
        ],
        NotResource: modelArn
      },
      denySecretAccess(),
      denySecretMutation(),
      denyKmsSigning(),
      denyLambdaInvoke(),
      denyPrivilegeEscalation()
    ]
  });
  resources.SignerRole = roleResource({
    description:
      "Signs software-validated synthetic advisory receipts with one P-256 key; no Bedrock, secrets, Lambda invoke, database, MCP, or effect capability.",
    statements: [
      exactLogStatement("SignerLogGroup"),
      fnIf(
        "ShouldDeployProbes",
        exactLogStatement("SignerProbeLogGroup")
      ),
      {
        Sid: "ReadOneAdvisorySigningKey",
        Effect: "Allow",
        Action: ["kms:GetPublicKey", "kms:Verify"],
        Resource: getAtt("ReceiptSigningKey", "Arn")
      },
      {
        Sid: "SignWithOneAdvisoryKey",
        Effect: "Allow",
        Action: ["kms:Sign"],
        Resource: getAtt("ReceiptSigningKey", "Arn"),
        Condition: {
          StringEquals: {
            "kms:MessageType": "DIGEST",
            "kms:SigningAlgorithm": "ECDSA_SHA_256"
          }
        }
      },
      {
        Sid: "DenyRawSigning",
        Effect: "Deny",
        Action: "kms:Sign",
        Resource: getAtt("ReceiptSigningKey", "Arn"),
        Condition: {
          StringNotEquals: { "kms:MessageType": "DIGEST" }
        }
      },
      {
        Sid: "DenyOtherSigningAlgorithms",
        Effect: "Deny",
        Action: "kms:Sign",
        Resource: getAtt("ReceiptSigningKey", "Arn"),
        Condition: {
          StringNotEquals: {
            "kms:SigningAlgorithm": "ECDSA_SHA_256"
          }
        }
      },
      denyBedrock(),
      denySecretAccess(),
      denySecretMutation(),
      denyLambdaInvoke(),
      denyPrivilegeEscalation()
    ]
  });
  resources.AuthorityRole = roleResource({
    description:
      "Deterministic Cockroach authority role; reads one exact project secret and has no Bedrock, signing, Lambda invoke, IAM, or base-table AWS capability.",
    statements: [
      exactLogStatement("AuthorityLogGroup"),
      fnIf(
        "ShouldDeployProbes",
        exactLogStatement("AuthorityProbeLogGroup")
      ),
      {
        Sid: "ReadOneAuthorityDatabaseSecret",
        Effect: "Allow",
        Action: ["secretsmanager:GetSecretValue"],
        Resource: ref("AuthorityDatabaseSecretArn")
      },
      denyOtherSecretReads(),
      denySecretEnumeration(),
      denyBedrock(),
      denySecretMutation(),
      denyKmsSigning(),
      denyLambdaInvoke(),
      denyPrivilegeEscalation()
    ]
  });
  resources.DemoRole = roleResource({
    description:
      "Public read-only synthetic demo role; bundled content only, with no Bedrock, Lambda invoke, KMS signing, secrets, database, MCP, or authority capability.",
    statements: [
      exactLogStatement("DemoLogGroup"),
      fnIf(
        "ShouldDeployProbes",
        exactLogStatement("DemoProbeLogGroup")
      ),
      denyBedrock(),
      denySecretAccess(),
      denySecretMutation(),
      denyKmsSigning(),
      denyLambdaInvoke(),
      denyPrivilegeEscalation()
    ]
  });

  resources.SignerFunction = lambdaFunction({
    description:
      "KMS-signs one exact synthetic advisory receipt schema.",
    role: "SignerRole",
    code: artifactCode("signer"),
    logGroup: "SignerLogGroup",
    timeout: 8,
    concurrency: 1,
    environment: {
      SIGNING_KEY_ARN: getAtt("ReceiptSigningKey", "Arn"),
      SOURCE_COMMIT: ref("SourceCommit"),
      CONFIG_DIGEST: ref("ConfigDigest"),
      BEDROCK_MODEL_ID: ref("BedrockModelId"),
      AGENT_SOURCE_DIGEST: ref("AgentSourceDigest"),
      BOUNDARY_SOURCE_DIGEST: ref("BoundarySourceDigest"),
      SIGNER_SOURCE_DIGEST: ref("SignerSourceDigest"),
      AGENT_ARTIFACT_DIGEST: ref("AgentArtifactDigest"),
      BOUNDARY_ARTIFACT_DIGEST: ref("BoundaryArtifactDigest"),
      SIGNER_ARTIFACT_DIGEST: ref("SignerArtifactDigest"),
      TREE_DIGEST: ref("TreeDigest"),
      PACKAGE_LOCK_DIGEST: ref("PackageLockDigest")
    }
  });
  resources.SignerVersion = version(
    "SignerFunction",
    sub("Tideproof Gate Two ${SourceCommit} ${ConfigDigest}"),
    "signer"
  );
  resources.SignerAlias = alias("SignerFunction", "SignerVersion");

  resources.AgentFunction = lambdaFunction({
    description:
      "Invokes one Bedrock model over one exact Gate One digest-bound synthetic fixture and returns an untrusted proposal.",
    role: "AgentRole",
    code: artifactCode("agent"),
    logGroup: "AgentLogGroup",
    timeout: 15,
    concurrency: 1,
    environment: {
      BEDROCK_MODEL_ID: ref("BedrockModelId"),
      SOURCE_COMMIT: ref("SourceCommit"),
      CONFIG_DIGEST: ref("ConfigDigest"),
      AGENT_SOURCE_DIGEST: ref("AgentSourceDigest"),
      AGENT_ARTIFACT_DIGEST: ref("AgentArtifactDigest"),
      TREE_DIGEST: ref("TreeDigest"),
      PACKAGE_LOCK_DIGEST: ref("PackageLockDigest")
    }
  });
  resources.AgentVersion = version(
    "AgentFunction",
    sub("Tideproof Gate Two ${SourceCommit} ${ConfigDigest}"),
    "agent"
  );
  resources.AgentAlias = alias("AgentFunction", "AgentVersion");

  resources.AuthorityFunction = lambdaFunction({
    description:
      "Runs one exact synthetic two-contender authority request and later read-only durable proof through least-privilege CockroachDB SECURITY DEFINER surfaces.",
    role: "AuthorityRole",
    code: artifactCode("authority"),
    logGroup: "AuthorityLogGroup",
    timeout: 25,
    concurrency: 2,
    environment: {
      AUTHORITY_DATABASE_SECRET_ARN: ref("AuthorityDatabaseSecretArn"),
      AUTHORITY_TENANT_ID: ref("AuthorityTenantId"),
      AUTHORITY_RUN_ID: ref("AuthorityRunId"),
      AUTHORITY_INCIDENT_ID: ref("AuthorityIncidentId"),
      AUTHORITY_EVIDENCE_ID: ref("AuthorityEvidenceId"),
      AUTHORITY_RACE_ID: ref("AuthorityRaceId"),
      AUTHORITY_RESOURCE_ID: ref("AuthorityResourceId"),
      SOURCE_COMMIT: ref("SourceCommit"),
      CONFIG_DIGEST: ref("ConfigDigest"),
      AUTHORITY_SOURCE_DIGEST: ref("AuthoritySourceDigest"),
      AUTHORITY_ARTIFACT_DIGEST: ref("AuthorityArtifactDigest"),
      TREE_DIGEST: ref("TreeDigest"),
      PACKAGE_LOCK_DIGEST: ref("PackageLockDigest")
    }
  });
  resources.AuthorityVersion = version(
    "AuthorityFunction",
    sub("Tideproof Gate Two ${SourceCommit} ${ConfigDigest}"),
    "authority"
  );
  resources.AuthorityAlias = alias(
    "AuthorityFunction",
    "AuthorityVersion"
  );

  resources.DemoFunction = lambdaFunction({
    description:
      "Serves the signed-out deterministic Tideproof judge path from bundled read-only assets.",
    role: "DemoRole",
    code: artifactCode("demo"),
    logGroup: "DemoLogGroup",
    timeout: 5,
    concurrency: 8,
    environment: {
      EXPECTED_API_ID: ref("HttpApi"),
      SOURCE_COMMIT: ref("SourceCommit"),
      CONFIG_DIGEST: ref("ConfigDigest"),
      DEMO_SOURCE_DIGEST: ref("DemoSourceDigest"),
      DEMO_ARTIFACT_DIGEST: ref("DemoArtifactDigest"),
      TREE_DIGEST: ref("TreeDigest"),
      PACKAGE_LOCK_DIGEST: ref("PackageLockDigest")
    }
  });
  resources.DemoVersion = version(
    "DemoFunction",
    sub("Tideproof public demo ${SourceCommit} ${ConfigDigest}"),
    "demo"
  );
  resources.DemoAlias = alias("DemoFunction", "DemoVersion");

  resources.BoundaryRole = roleResource({
    description:
      "Signed-caller coordinator that invokes only the immutable proposal and receipt-signing aliases.",
    statements: [
      exactLogStatement("BoundaryLogGroup"),
      fnIf(
        "ShouldDeployProbes",
        exactLogStatement("BoundaryProbeLogGroup")
      ),
      {
        Sid: "InvokeOnlyBoundedChildren",
        Effect: "Allow",
        Action: ["lambda:InvokeFunction"],
        Resource: [
          getAtt("AgentAlias", "AliasArn"),
          getAtt("SignerAlias", "AliasArn")
        ]
      },
      {
        Sid: "DenyOtherLambdaTargets",
        Effect: "Deny",
        Action: ["lambda:InvokeFunction"],
        NotResource: [
          getAtt("AgentAlias", "AliasArn"),
          getAtt("SignerAlias", "AliasArn")
        ]
      },
      {
        Sid: "ReadReceiptSigningPublicKey",
        Effect: "Allow",
        Action: ["kms:GetPublicKey"],
        Resource: getAtt("ReceiptSigningKey", "Arn")
      },
      denyBedrock(),
      denySecretAccess(),
      denySecretMutation(),
      denyKmsSigning(),
      denyPrivilegeEscalation()
    ]
  });

  resources.HttpApi = {
    Type: "AWS::ApiGatewayV2::Api",
    Properties: {
      Name: sub("${AWS::StackName}-api"),
      Description:
        "Signed-out read-only Tideproof demo plus an isolated IAM-authenticated advisory endpoint.",
      ProtocolType: "HTTP",
      DisableExecuteApiEndpoint: false,
      Tags: { Project: "Tideproof", Gate: "Two" }
    }
  };

  resources.AdvisoryCallerRole = roleResource({
    description:
      "Short-lived human-assumed caller for one exact IAM-authenticated advisory route; direct Lambda invocation is denied.",
    assumeRolePolicy: assumeAccountRolePolicy(),
    statements: [
      {
        Sid: "InvokeOneAdvisoryRoute",
        Effect: "Allow",
        Action: ["execute-api:Invoke"],
        Resource: sub(
          "arn:${AWS::Partition}:execute-api:${AWS::Region}:${AWS::AccountId}:${HttpApi}/$default/POST/advisory"
        )
      },
      denyLambdaInvoke(),
      denyBedrock(),
      denySecretAccess(),
      denySecretMutation(),
      denyKmsSigning(),
      denyPrivilegeEscalation()
    ]
  });

  resources.AuthorityRaceCallerRole = roleResource({
    description:
      "Short-lived human-assumed caller for the exact immutable authority alias; no model, secret, signing, IAM, or other Lambda capability.",
    assumeRolePolicy: assumeAccountRolePolicy(),
    statements: [
      {
        Sid: "InvokeOnlyAuthorityProof",
        Effect: "Allow",
        Action: ["lambda:InvokeFunction"],
        Resource: getAtt("AuthorityAlias", "AliasArn")
      },
      {
        Sid: "DenyOtherLambdaTargets",
        Effect: "Deny",
        Action: ["lambda:InvokeFunction"],
        NotResource: getAtt("AuthorityAlias", "AliasArn")
      },
      denyBedrock(),
      denySecretAccess(),
      denySecretMutation(),
      denyKmsSigning(),
      denyPrivilegeEscalation()
    ]
  });

  const promptTemplateDigest = sha256Hex(PROMPT_TEMPLATE_VERSION);
  const validatorDigest = sha256Hex(VALIDATOR_VERSION);

  resources.BoundaryFunction = lambdaFunction({
    description:
      "Validates the signed API context and fixed synthetic request before invoking immutable children.",
    role: "BoundaryRole",
    code: artifactCode("boundary"),
    logGroup: "BoundaryLogGroup",
    timeout: 25,
    concurrency: 2,
    environment: {
      AGENT_FUNCTION_ARN: getAtt("AgentAlias", "AliasArn"),
      SIGNER_FUNCTION_ARN: getAtt("SignerAlias", "AliasArn"),
      AGENT_FUNCTION_VERSION: getAtt("AgentVersion", "Version"),
      SIGNER_FUNCTION_VERSION: getAtt("SignerVersion", "Version"),
      SIGNING_KEY_ARN: getAtt("ReceiptSigningKey", "Arn"),
      EXPECTED_API_ID: ref("HttpApi"),
      EXPECTED_ACCOUNT_ID: ref("AWS::AccountId"),
      SOURCE_COMMIT: ref("SourceCommit"),
      CONFIG_DIGEST: ref("ConfigDigest"),
      BEDROCK_MODEL_ID: ref("BedrockModelId"),
      AGENT_SOURCE_DIGEST: ref("AgentSourceDigest"),
      BOUNDARY_SOURCE_DIGEST: ref("BoundarySourceDigest"),
      SIGNER_SOURCE_DIGEST: ref("SignerSourceDigest"),
      AGENT_ARTIFACT_DIGEST: ref("AgentArtifactDigest"),
      BOUNDARY_ARTIFACT_DIGEST: ref("BoundaryArtifactDigest"),
      SIGNER_ARTIFACT_DIGEST: ref("SignerArtifactDigest"),
      TREE_DIGEST: ref("TreeDigest"),
      PACKAGE_LOCK_DIGEST: ref("PackageLockDigest"),
      PROMPT_TEMPLATE_DIGEST: promptTemplateDigest,
      AGENT_VALIDATOR_DIGEST: validatorDigest
    }
  });
  resources.BoundaryVersion = version(
    "BoundaryFunction",
    sub("Tideproof Gate Two ${SourceCommit} ${ConfigDigest}"),
    "boundary"
  );
  resources.BoundaryAlias = alias(
    "BoundaryFunction",
    "BoundaryVersion"
  );

  resources.AgentProbeFunction = probeFunction(
    "AgentRole",
    "AgentProbeLogGroup",
    "agent"
  );
  resources.AgentProbeVersion = version(
    "AgentProbeFunction",
    sub("Disposable agent-role probe ${SourceCommit} ${ConfigDigest}"),
    "probe"
  );
  resources.BoundaryProbeFunction = probeFunction(
    "BoundaryRole",
    "BoundaryProbeLogGroup",
    "boundary"
  );
  resources.BoundaryProbeVersion = version(
    "BoundaryProbeFunction",
    sub("Disposable boundary-role probe ${SourceCommit} ${ConfigDigest}"),
    "probe"
  );
  resources.DemoProbeFunction = probeFunction(
    "DemoRole",
    "DemoProbeLogGroup",
    "demo"
  );
  resources.DemoProbeVersion = version(
    "DemoProbeFunction",
    sub("Disposable demo-role probe ${SourceCommit} ${ConfigDigest}"),
    "probe"
  );
  resources.SignerProbeFunction = probeFunction(
    "SignerRole",
    "SignerProbeLogGroup",
    "signer"
  );
  resources.SignerProbeVersion = version(
    "SignerProbeFunction",
    sub("Disposable signer-role probe ${SourceCommit} ${ConfigDigest}"),
    "probe"
  );
  resources.AuthorityProbeFunction = probeFunction(
    "AuthorityRole",
    "AuthorityProbeLogGroup",
    "authority"
  );
  resources.AuthorityProbeVersion = version(
    "AuthorityProbeFunction",
    sub("Disposable authority-role probe ${SourceCommit} ${ConfigDigest}"),
    "probe"
  );

  for (const name of [
    "AgentProbeLogGroup",
    "BoundaryProbeLogGroup",
    "DemoProbeLogGroup",
    "SignerProbeLogGroup",
    "AuthorityProbeLogGroup",
    "AgentProbeFunction",
    "AgentProbeVersion",
    "BoundaryProbeFunction",
    "BoundaryProbeVersion",
    "DemoProbeFunction",
    "DemoProbeVersion",
    "SignerProbeFunction",
    "SignerProbeVersion",
    "AuthorityProbeFunction",
    "AuthorityProbeVersion"
  ]) {
    resources[name].Condition = "ShouldDeployProbes";
  }

  resources.BoundaryIntegration = {
    Type: "AWS::ApiGatewayV2::Integration",
    Properties: {
      ApiId: ref("HttpApi"),
      IntegrationType: "AWS_PROXY",
      IntegrationUri: getAtt("BoundaryAlias", "AliasArn"),
      PayloadFormatVersion: "2.0",
      TimeoutInMillis: 29_000
    }
  };
  resources.AdvisoryRoute = {
    Type: "AWS::ApiGatewayV2::Route",
    Properties: {
      ApiId: ref("HttpApi"),
      RouteKey: "POST /advisory",
      AuthorizationType: "AWS_IAM",
      Target: {
        "Fn::Join": [
          "/",
          ["integrations", ref("BoundaryIntegration")]
        ]
      }
    }
  };
  resources.DemoIntegration = {
    Type: "AWS::ApiGatewayV2::Integration",
    Properties: {
      ApiId: ref("HttpApi"),
      IntegrationType: "AWS_PROXY",
      IntegrationUri: getAtt("DemoAlias", "AliasArn"),
      PayloadFormatVersion: "2.0",
      TimeoutInMillis: 6_000
    }
  };
  for (const path of PUBLIC_DEMO_PATHS) {
    const logicalId = PUBLIC_DEMO_ROUTE_IDS[path];
    if (!logicalId) {
      throw new Error("PUBLIC_DEMO_ROUTE_ID_MISSING");
    }
    resources[logicalId] = {
      Type: "AWS::ApiGatewayV2::Route",
      Properties: {
        ApiId: ref("HttpApi"),
        RouteKey: `GET ${path}`,
        AuthorizationType: "NONE",
        Target: {
          "Fn::Join": [
            "/",
            ["integrations", ref("DemoIntegration")]
          ]
        }
      }
    };
  }
  resources.DefaultStage = {
    Type: "AWS::ApiGatewayV2::Stage",
    Properties: {
      ApiId: ref("HttpApi"),
      StageName: "$default",
      AutoDeploy: true,
      AccessLogSettings: {
        DestinationArn: getAtt("ApiAccessLogGroup", "Arn"),
        Format: JSON.stringify({
          apiId: "$context.apiId",
          backendStatus: "$context.integration.status",
          callerArn: "$context.identity.userArn",
          lambdaServiceStatus:
            "$context.integration.integrationStatus",
          requestId: "$context.requestId",
          requestTimeEpoch: "$context.requestTimeEpoch",
          routeKey: "$context.routeKey",
          status: "$context.status"
        })
      },
      DefaultRouteSettings: {
        ThrottlingBurstLimit: 8,
        ThrottlingRateLimit: 0.05
      },
      RouteSettings: {
        "POST /advisory": {
          ThrottlingBurstLimit: 1,
          ThrottlingRateLimit: 0.1
        }
      },
      Tags: { Project: "Tideproof", Gate: "Two" }
    }
  };
  resources.BoundaryInvokePermission = {
    Type: "AWS::Lambda::Permission",
    Properties: {
      Action: "lambda:InvokeFunction",
      FunctionName: getAtt("BoundaryAlias", "AliasArn"),
      Principal: "apigateway.amazonaws.com",
      SourceAccount: ref("AWS::AccountId"),
      SourceArn: sub(
        "arn:${AWS::Partition}:execute-api:${AWS::Region}:${AWS::AccountId}:${HttpApi}/$default/POST/advisory"
      )
    }
  };
  resources.DemoRootInvokePermission = {
    Type: "AWS::Lambda::Permission",
    Properties: {
      Action: "lambda:InvokeFunction",
      FunctionName: getAtt("DemoAlias", "AliasArn"),
      Principal: "apigateway.amazonaws.com",
      SourceAccount: ref("AWS::AccountId"),
      SourceArn: sub(
        "arn:${AWS::Partition}:execute-api:${AWS::Region}:${AWS::AccountId}:${HttpApi}/$default/GET/"
      )
    }
  };
  resources.DemoAssetInvokePermission = {
    Type: "AWS::Lambda::Permission",
    Properties: {
      Action: "lambda:InvokeFunction",
      FunctionName: getAtt("DemoAlias", "AliasArn"),
      Principal: "apigateway.amazonaws.com",
      SourceAccount: ref("AWS::AccountId"),
      SourceArn: sub(
        "arn:${AWS::Partition}:execute-api:${AWS::Region}:${AWS::AccountId}:${HttpApi}/$default/GET/*"
      )
    }
  };

  resources.AgentErrorAlarm = lambdaErrorAlarm(
    "AgentFunction",
    "agent"
  );
  resources.BoundaryErrorAlarm = lambdaErrorAlarm(
    "BoundaryFunction",
    "boundary"
  );
  resources.DemoErrorAlarm = lambdaErrorAlarm(
    "DemoFunction",
    "demo"
  );
  resources.SignerErrorAlarm = lambdaErrorAlarm(
    "SignerFunction",
    "signer"
  );
  resources.AuthorityErrorAlarm = lambdaErrorAlarm(
    "AuthorityFunction",
    "authority"
  );
  return {
    AWSTemplateFormatVersion: "2010-09-09",
    Description:
      "Tideproof Gate Two: signed-out read-only judge path, immutable Bedrock proposal path, IAM separation, and KMS-signed synthetic receipts.",
    Parameters: parameters,
    Rules: {
      UsEast1Only: {
        Assertions: [
          {
            Assert: {
              "Fn::Equals": [ref("AWS::Region"), "us-east-1"]
            },
            AssertDescription:
              "The reviewed Gate Two proof is approved only for us-east-1."
          }
        ]
      }
    },
    Conditions: {
      ShouldDeployProbes: {
        "Fn::Equals": [ref("EnableProbeFunctions"), "true"]
      }
    },
    Resources: resources,
    Outputs: {
      ApiEndpoint: {
        Description:
          "Base URL for the signed-out demo and isolated IAM advisory route.",
        Value: sub(
          "https://${HttpApi}.execute-api.${AWS::Region}.amazonaws.com"
        )
      },
      PublicDemoUrl: {
        Description:
          "Signed-out read-only synthetic judge path; not evidence that the advisory path ran.",
        Value: sub(
          "https://${HttpApi}.execute-api.${AWS::Region}.amazonaws.com/"
        )
      },
      AdvisoryCallerRoleArn: {
        Value: getAtt("AdvisoryCallerRole", "Arn")
      },
      AuthorityRaceCallerRoleArn: {
        Value: getAtt("AuthorityRaceCallerRole", "Arn")
      },
      ApiAccessLogGroupName: {
        Value: ref("ApiAccessLogGroup")
      },
      AgentAliasArn: { Value: getAtt("AgentAlias", "AliasArn") },
      BoundaryAliasArn: {
        Value: getAtt("BoundaryAlias", "AliasArn")
      },
      DemoAliasArn: { Value: getAtt("DemoAlias", "AliasArn") },
      SignerAliasArn: { Value: getAtt("SignerAlias", "AliasArn") },
      AuthorityAliasArn: {
        Value: getAtt("AuthorityAlias", "AliasArn")
      },
      AgentProbeVersionArn: {
        Condition: "ShouldDeployProbes",
        Value: ref("AgentProbeVersion")
      },
      BoundaryProbeVersionArn: {
        Condition: "ShouldDeployProbes",
        Value: ref("BoundaryProbeVersion")
      },
      DemoProbeVersionArn: {
        Condition: "ShouldDeployProbes",
        Value: ref("DemoProbeVersion")
      },
      SignerProbeVersionArn: {
        Condition: "ShouldDeployProbes",
        Value: ref("SignerProbeVersion")
      },
      AuthorityProbeVersionArn: {
        Condition: "ShouldDeployProbes",
        Value: ref("AuthorityProbeVersion")
      },
      AuthoritySourceDigest: {
        Value: ref("AuthoritySourceDigest")
      },
      AuthorityArtifactDigest: {
        Value: ref("AuthorityArtifactDigest")
      },
      ProbeSourceDigest: {
        Value: ref("ProbeSourceDigest")
      },
      ProbeArtifactDigest: {
        Value: ref("ProbeArtifactDigest")
      },
      ReceiptSigningKeyArn: {
        Value: getAtt("ReceiptSigningKey", "Arn")
      },
      CapabilityCanarySecretArn: {
        Condition: "ShouldDeployProbes",
        Value: ref("CapabilityCanarySecret")
      },
      BedrockModel: { Value: ref("BedrockModelId") },
      SourceCommit: { Value: ref("SourceCommit") },
      ConfigDigest: { Value: ref("ConfigDigest") }
    }
  };
}

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

export function templateReceipt(template) {
  const formatted = `${JSON.stringify(template, null, 2)}\n`;
  return {
    template,
    templateDigest: sha256Hex(formatted),
    canonicalDigest: sha256Hex(canonicalJson(template)),
    bytes: Buffer.byteLength(formatted)
  };
}

export function deploymentConfigDigest(configuration) {
  const required = [
    "accountId",
    "apiAuthorization",
    "artifactBucket",
    "artifactCodeSha256",
    "artifactDigests",
    "artifactKeys",
    "artifactSourceDigests",
    "artifactVersions",
    "authority",
    "bedrockModelId",
    "budgetUsd",
    "logRetentionDays",
    "notificationEmailDigest",
    "packageLockDigest",
    "probesEnabled",
    "publicDemo",
    "region",
    "reservedConcurrency",
    "sourceCommit",
    "stackName",
    "templateDigest",
    "throttle",
    "treeDigest"
  ];
  if (
    !configuration ||
    Object.keys(configuration).sort().join("\n") !==
      required.sort().join("\n") ||
    !configuration.authority ||
    typeof configuration.authority !== "object" ||
    Array.isArray(configuration.authority) ||
    Object.keys(configuration.authority).sort().join("\n") !==
      [
        "databaseSecretArn",
        "evidenceId",
        "incidentId",
        "raceId",
        "resourceId",
        "runId",
        "tenantId"
      ]
        .sort()
        .join("\n")
  ) {
    throw new Error("DEPLOYMENT_CONFIG_SHAPE_REJECTED");
  }
  return sha256Hex(canonicalJson(configuration));
}
