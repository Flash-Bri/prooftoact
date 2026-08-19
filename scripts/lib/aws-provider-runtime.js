function requireCondition(condition, code) {
  if (!condition) {
    throw new Error(code);
  }
}

function fixedSdkOptions() {
  return {
    authSchemePreference: ["sigv4"],
    defaultsMode: "standard",
    ignoreConfiguredEndpointUrls: true,
    retryMode: "standard",
    sigv4aSigningRegionSet: [],
    useDualstackEndpoint: false,
    useFipsEndpoint: false
  };
}

function normalizeCallerIdentity(value) {
  requireCondition(
    value &&
      typeof value === "object" &&
      typeof value.Account === "string" &&
      typeof value.Arn === "string" &&
      typeof value.UserId === "string",
    "AWS_PROVIDER_CALLER_IDENTITY"
  );
  return {
    Account: value.Account,
    Arn: value.Arn,
    UserId: value.UserId
  };
}

export function decodePolicyDocument(value) {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return value;
  }
  requireCondition(
    typeof value === "string" && value.length > 0,
    "AWS_PROVIDER_POLICY_DOCUMENT"
  );
  const candidates = [value];
  try {
    candidates.push(decodeURIComponent(value));
  } catch {
    throw new Error("AWS_PROVIDER_POLICY_DOCUMENT");
  }
  for (const candidate of candidates) {
    try {
      const parsed = JSON.parse(candidate);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        return parsed;
      }
    } catch {
      // Try the provider's alternate RFC 3986 representation.
    }
  }
  throw new Error("AWS_PROVIDER_POLICY_DOCUMENT");
}

export async function createAwsProviderClients({ credentials, region }) {
  requireCondition(
    credentials &&
      typeof credentials.accessKeyId === "string" &&
      typeof credentials.secretAccessKey === "string" &&
      typeof credentials.sessionToken === "string" &&
      region === "us-east-1",
    "AWS_PROVIDER_CLIENT_CONFIGURATION"
  );
  const [apiGatewayV2, cloudformation, iam, lambda, sts, smithy] =
    await Promise.all([
      import("@aws-sdk/client-apigatewayv2"),
      import("@aws-sdk/client-cloudformation"),
      import("@aws-sdk/client-iam"),
      import("@aws-sdk/client-lambda"),
      import("@aws-sdk/client-sts"),
      import("@smithy/node-http-handler")
    ]);
  const requestHandler = new smithy.NodeHttpHandler({
    connectionTimeout: 1_000,
    socketTimeout: 10_000
  });
  const clientOptions = {
    credentials,
    ...fixedSdkOptions(),
    maxAttempts: 1,
    region,
    requestHandler
  };
  const apiGatewayV2Client = new apiGatewayV2.ApiGatewayV2Client(
    clientOptions
  );
  const cloudformationClient = new cloudformation.CloudFormationClient(
    clientOptions
  );
  const iamClient = new iam.IAMClient(clientOptions);
  const lambdaClient = new lambda.LambdaClient(clientOptions);
  const stsClient = new sts.STSClient(clientOptions);

  async function optionalLambda(command) {
    try {
      return await lambdaClient.send(command);
    } catch (error) {
      if (
        error?.name === "ResourceNotFoundException" &&
        error?.$metadata?.httpStatusCode === 404 &&
        error.$metadata.attempts === 1 &&
        error.$metadata.totalRetryDelay === 0
      ) {
        return null;
      }
      throw error;
    }
  }

  return Object.freeze({
    async assumeRole(targetRoleArn) {
      return stsClient.send(
        new sts.AssumeRoleCommand({
          RoleArn: targetRoleArn,
          RoleSessionName: "tideproof-evidence-denial"
        })
      );
    },
    async callerIdentity() {
      return normalizeCallerIdentity(
        await stsClient.send(new sts.GetCallerIdentityCommand({}))
      );
    },
    async getApi(apiId) {
      return apiGatewayV2Client.send(
        new apiGatewayV2.GetApiCommand({ ApiId: apiId })
      );
    },
    async getDeployment(apiId, deploymentId) {
      return apiGatewayV2Client.send(
        new apiGatewayV2.GetDeploymentCommand({
          ApiId: apiId,
          DeploymentId: deploymentId
        })
      );
    },
    async getDeployments(apiId, nextToken = undefined) {
      return apiGatewayV2Client.send(
        new apiGatewayV2.GetDeploymentsCommand({
          ApiId: apiId,
          MaxResults: "25",
          ...(nextToken === undefined ? {} : { NextToken: nextToken })
        })
      );
    },
    async getIntegration(apiId, integrationId) {
      return apiGatewayV2Client.send(
        new apiGatewayV2.GetIntegrationCommand({
          ApiId: apiId,
          IntegrationId: integrationId
        })
      );
    },
    async getIntegrations(apiId) {
      return apiGatewayV2Client.send(
        new apiGatewayV2.GetIntegrationsCommand({ ApiId: apiId })
      );
    },
    async describeStackDriftDetectionStatus(detectionId) {
      return cloudformationClient.send(
        new cloudformation.DescribeStackDriftDetectionStatusCommand({
          StackDriftDetectionId: detectionId
        })
      );
    },
    async describeStackResourceDrifts(stackName) {
      return cloudformationClient.send(
        new cloudformation.DescribeStackResourceDriftsCommand({
          StackName: stackName
        })
      );
    },
    async describeStackResources(stackName) {
      return cloudformationClient.send(
        new cloudformation.DescribeStackResourcesCommand({
          StackName: stackName
        })
      );
    },
    async describeStacks(stackName) {
      return cloudformationClient.send(
        new cloudformation.DescribeStacksCommand({ StackName: stackName })
      );
    },
    async detectStackDrift(stackName, logicalResourceIds) {
      return cloudformationClient.send(
        new cloudformation.DetectStackDriftCommand({
          LogicalResourceIds: logicalResourceIds,
          StackName: stackName
        })
      );
    },
    async getAlias(functionName, name) {
      return lambdaClient.send(
        new lambda.GetAliasCommand({ FunctionName: functionName, Name: name })
      );
    },
    async getFunctionConcurrency(functionName) {
      return lambdaClient.send(
        new lambda.GetFunctionConcurrencyCommand({
          FunctionName: functionName
        })
      );
    },
    async getFunctionConfiguration(functionName) {
      return lambdaClient.send(
        new lambda.GetFunctionConfigurationCommand({
          FunctionName: functionName
        })
      );
    },
    async getFunctionCodeSigningConfig(functionName) {
      const response = await lambdaClient.send(
        new lambda.GetFunctionCodeSigningConfigCommand({
          FunctionName: functionName
        })
      );
      return {
        codeSigningConfigArn: response.CodeSigningConfigArn ?? null
      };
    },
    async getFunctionPolicy(functionName, qualifier = null) {
      const response = await optionalLambda(
        new lambda.GetPolicyCommand({
          FunctionName: functionName,
          ...(qualifier === null ? {} : { Qualifier: qualifier })
        })
      );
      if (response === null) {
        return null;
      }
      let policy;
      try {
        policy = JSON.parse(response.Policy);
      } catch {
        throw new Error("AWS_PROVIDER_LAMBDA_POLICY");
      }
      return {
        policy,
        revisionId: response.RevisionId ?? null
      };
    },
    async getFunctionRecursionConfig(functionName) {
      const response = await lambdaClient.send(
        new lambda.GetFunctionRecursionConfigCommand({
          FunctionName: functionName
        })
      );
      return { recursiveLoop: response.RecursiveLoop ?? null };
    },
    async getRuntimeManagementConfig(functionName, qualifier) {
      const response = await lambdaClient.send(
        new lambda.GetRuntimeManagementConfigCommand({
          FunctionName: functionName,
          Qualifier: qualifier
        })
      );
      return {
        runtimeVersionArn: response.RuntimeVersionArn ?? null,
        updateRuntimeOn: response.UpdateRuntimeOn ?? null
      };
    },
    async getRole(roleName) {
      const response = await iamClient.send(
        new iam.GetRoleCommand({ RoleName: roleName })
      );
      return {
        ...response,
        Role: response.Role
          ? {
              ...response.Role,
              AssumeRolePolicyDocument: decodePolicyDocument(
                response.Role.AssumeRolePolicyDocument
              )
            }
          : response.Role
      };
    },
    async getRolePolicy(roleName, policyName) {
      const response = await iamClient.send(
        new iam.GetRolePolicyCommand({
          PolicyName: policyName,
          RoleName: roleName
        })
      );
      return {
        ...response,
        PolicyDocument: decodePolicyDocument(response.PolicyDocument)
      };
    },
    async getRoute(apiId, routeId) {
      return apiGatewayV2Client.send(
        new apiGatewayV2.GetRouteCommand({ ApiId: apiId, RouteId: routeId })
      );
    },
    async getRoutes(apiId) {
      return apiGatewayV2Client.send(
        new apiGatewayV2.GetRoutesCommand({ ApiId: apiId })
      );
    },
    async getStage(apiId, stageName) {
      return apiGatewayV2Client.send(
        new apiGatewayV2.GetStageCommand({
          ApiId: apiId,
          StageName: stageName
        })
      );
    },
    async getStages(apiId) {
      return apiGatewayV2Client.send(
        new apiGatewayV2.GetStagesCommand({ ApiId: apiId })
      );
    },
    async getTemplate(stackName) {
      return cloudformationClient.send(
        new cloudformation.GetTemplateCommand({
          StackName: stackName,
          TemplateStage: "Processed"
        })
      );
    },
    async listAttachedRolePolicies(roleName) {
      return iamClient.send(
        new iam.ListAttachedRolePoliciesCommand({ RoleName: roleName })
      );
    },
    async listAliases(functionName) {
      return lambdaClient.send(
        new lambda.ListAliasesCommand({
          FunctionName: functionName,
          MaxItems: 50
        })
      );
    },
    async listEventSourceMappings(functionName) {
      return lambdaClient.send(
        new lambda.ListEventSourceMappingsCommand({
          FunctionName: functionName,
          MaxItems: 100
        })
      );
    },
    async listFunctionUrlConfigs(functionName) {
      return lambdaClient.send(
        new lambda.ListFunctionUrlConfigsCommand({
          FunctionName: functionName,
          MaxItems: 50
        })
      );
    },
    async listProvisionedConcurrencyConfigs(functionName) {
      return lambdaClient.send(
        new lambda.ListProvisionedConcurrencyConfigsCommand({
          FunctionName: functionName,
          MaxItems: 50
        })
      );
    },
    async listRolePolicies(roleName) {
      return iamClient.send(
        new iam.ListRolePoliciesCommand({ RoleName: roleName })
      );
    },
    async listRoleTags(roleName) {
      return iamClient.send(
        new iam.ListRoleTagsCommand({ RoleName: roleName })
      );
    },
    async listTags(resourceArn) {
      return lambdaClient.send(
        new lambda.ListTagsCommand({ Resource: resourceArn })
      );
    }
  });
}

export const __test = Object.freeze({
  decodePolicyDocument,
  fixedSdkOptions,
  normalizeCallerIdentity
});
