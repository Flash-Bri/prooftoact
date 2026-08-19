import { CockroachManagedMcpRecoveryClient } from
  "../../../src/cloud/managed-mcp-client.js";
import {
  buildPrivateRecoveryQueryCommand,
  privateRecoveryQueryApprovalSha256,
  runPrivateRecoveryQuery
} from "../../../src/cloud/private-recovery-query.js";
import { createPrivateRecoveryQueryAwsRuntime } from
  "../../../src/cloud/private-recovery-query-aws-runtime.js";

const EVENT_SCHEMA = "prooftoact.private-recovery-query-invocation.v1";
const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;

function reject(code) {
  throw new Error(code);
}

function plainObject(value) {
  return value !== null && typeof value === "object" &&
    !Array.isArray(value) && [Object.prototype, null].includes(
      Object.getPrototypeOf(value)
    );
}

function exactKeys(value, expected) {
  return plainObject(value) &&
    Object.keys(value).sort().join("\n") === [...expected].sort().join("\n");
}

function readConfiguration(environment) {
  const value = Object.freeze({
    approvalSha256: environment.APPROVAL_SHA256,
    codeZipSha256: environment.CODE_ZIP_SHA256,
    configSha256: environment.CONFIG_SHA256,
    functionArn: environment.FUNCTION_ARN,
    mcpSecretArn: environment.MCP_SECRET_ARN,
    mcpSecretVersionId: environment.MCP_SECRET_VERSION_ID,
    operationGlobalKeySha256: environment.OPERATION_GLOBAL_KEY_SHA256,
    releaseControlTableArn: environment.RELEASE_CONTROL_TABLE_ARN,
    sourceCommit: environment.SOURCE_COMMIT,
    treeDigest: environment.TREE_DIGEST
  });
  if (!HEX_64.test(value.approvalSha256 ?? "") ||
      !HEX_64.test(value.codeZipSha256 ?? "") ||
      !HEX_64.test(value.configSha256 ?? "") ||
      !HEX_64.test(value.operationGlobalKeySha256 ?? "") ||
      !HEX_40.test(value.sourceCommit ?? "") ||
      !HEX_40.test(value.treeDigest ?? "")) {
    reject("PRIVATE_RECOVERY_QUERY_CONFIGURATION_REJECTED");
  }
  return value;
}

export function createPrivateRecoveryQueryHandler({
  clock = () => new Date(),
  createMcpClient = (options) =>
    new CockroachManagedMcpRecoveryClient(options),
  environment = process.env,
  runtimeFactory = createPrivateRecoveryQueryAwsRuntime
} = {}) {
  const configuration = readConfiguration(environment);
  let runtimePromise = null;
  return async function privateRecoveryQueryHandler(event, context) {
    const invocationNow = clock();
    if (!exactKeys(event, ["approval", "schemaVersion"]) ||
        event.schemaVersion !== EVENT_SCHEMA ||
        privateRecoveryQueryApprovalSha256(event.approval) !==
          configuration.approvalSha256 ||
        event.approval.sourceCommit !== configuration.sourceCommit ||
        event.approval.treeDigest !== configuration.treeDigest) {
      reject("PRIVATE_RECOVERY_QUERY_INVOCATION_REJECTED");
    }
    if (!plainObject(context) ||
        !/^(?:[1-9][0-9]{0,8})$/u.test(context.functionVersion ?? "") ||
        context.invokedFunctionArn !==
          `${configuration.functionArn}:${context.functionVersion}`) {
      reject("PRIVATE_RECOVERY_QUERY_LAMBDA_CONTEXT_REJECTED");
    }
    const command = buildPrivateRecoveryQueryCommand({
      approval: event.approval,
      codeZipSha256: configuration.codeZipSha256,
      configSha256: configuration.configSha256,
      functionArn: configuration.functionArn,
      functionVersion: context.functionVersion,
      mcpSecretArn: configuration.mcpSecretArn,
      mcpSecretVersionId: configuration.mcpSecretVersionId,
      releaseControlTableArn: configuration.releaseControlTableArn,
      now: invocationNow
    });
    if (command.globalKeySha256 !== configuration.operationGlobalKeySha256) {
      reject("PRIVATE_RECOVERY_QUERY_OPERATION_KEY_REJECTED");
    }
    runtimePromise ??= runtimeFactory({ environment });
    const runtime = await runtimePromise;
    let firstRuntimeClockRead = true;
    return runPrivateRecoveryQuery({
      approval: event.approval,
      clock: () => {
        if (firstRuntimeClockRead) {
          firstRuntimeClockRead = false;
          return invocationNow;
        }
        return clock();
      },
      command,
      createMcpClient,
      lambdaContext: context,
      secretReader: runtime.secretReader,
      store: runtime.store
    });
  };
}

let productionHandler = null;
export async function handler(event, context) {
  productionHandler ??= createPrivateRecoveryQueryHandler();
  return productionHandler(event, context);
}

export const __test = Object.freeze({ EVENT_SCHEMA, readConfiguration });
