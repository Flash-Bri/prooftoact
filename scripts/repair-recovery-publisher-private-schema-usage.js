import { pathToFileURL } from "node:url";
import {
  RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_CONFIRMATION,
  recoveryPublisherPrivateSchemaRepairPlan,
  repairRecoveryPublisherPrivateSchemaUsage,
  verifyRecoveryPublisherPrivateSchemaUsage
} from "../src/cloud/recovery-security.js";

function requiredEnvironment(environment, name) {
  const value = environment[name]?.trim();
  if (!value) {
    const error = new Error(`${name}_REQUIRED`);
    error.code = `${name}_REQUIRED`;
    throw error;
  }
  return value;
}

function boundOptions(environment) {
  return {
    adminConnectionString: requiredEnvironment(
      environment,
      "RECOVERY_ADMIN_DATABASE_URL"
    ),
    publisherConnectionString: requiredEnvironment(
      environment,
      "RECOVERY_PUBLISHER_DATABASE_URL"
    ),
    expectedRecoveryHostname: requiredEnvironment(
      environment,
      "EXPECTED_RECOVERY_HOSTNAME"
    ),
    expectedRecoveryProviderClusterId: requiredEnvironment(
      environment,
      "EXPECTED_RECOVERY_CLUSTER_ID"
    ),
    expectedRecoverySqlClusterId: requiredEnvironment(
      environment,
      "EXPECTED_RECOVERY_SQL_CLUSTER_ID"
    ),
    expectedPreflightPostureDigest: requiredEnvironment(
      environment,
      "EXPECTED_RECOVERY_PRE_REPAIR_POSTURE_SHA256"
    ),
    expectedClusterPreflightPostureDigest: requiredEnvironment(
      environment,
      "EXPECTED_RECOVERY_CLUSTER_PRE_REPAIR_POSTURE_SHA256"
    ),
    expectedAppendFunctionDefinitionSha256: requiredEnvironment(
      environment,
      "EXPECTED_RECOVERY_APPEND_FUNCTION_DEFINITION_SHA256"
    ),
    expectedResolveFunctionDefinitionSha256: requiredEnvironment(
      environment,
      "EXPECTED_RECOVERY_RESOLVE_FUNCTION_DEFINITION_SHA256"
    ),
    sourceCommit: requiredEnvironment(
      environment,
      "RECOVERY_SCHEMA_REPAIR_SOURCE_COMMIT"
    ),
    sourceTree: requiredEnvironment(
      environment,
      "RECOVERY_SCHEMA_REPAIR_SOURCE_TREE"
    )
  };
}

const REQUIRED_BOUND_ENVIRONMENT = Object.freeze([
  "RECOVERY_ADMIN_DATABASE_URL",
  "RECOVERY_PUBLISHER_DATABASE_URL",
  "EXPECTED_RECOVERY_HOSTNAME",
  "EXPECTED_RECOVERY_CLUSTER_ID",
  "EXPECTED_RECOVERY_SQL_CLUSTER_ID",
  "EXPECTED_RECOVERY_PRE_REPAIR_POSTURE_SHA256",
  "EXPECTED_RECOVERY_CLUSTER_PRE_REPAIR_POSTURE_SHA256",
  "EXPECTED_RECOVERY_APPEND_FUNCTION_DEFINITION_SHA256",
  "EXPECTED_RECOVERY_RESOLVE_FUNCTION_DEFINITION_SHA256",
  "RECOVERY_SCHEMA_REPAIR_SOURCE_COMMIT",
  "RECOVERY_SCHEMA_REPAIR_SOURCE_TREE"
]);

export async function main(
  args = process.argv.slice(2),
  environment = process.env,
  {
    write = (value) => process.stdout.write(
      `${JSON.stringify(value, null, 2)}\n`
    ),
    applyRepair = repairRecoveryPublisherPrivateSchemaUsage,
    verifyRepair = verifyRecoveryPublisherPrivateSchemaUsage
  } = {}
) {
  const [mode] = args;
  if (mode === "--plan") {
    if (args.length !== 1) {
      throw Object.assign(
        new Error("RECOVERY_SCHEMA_REPAIR_MODE_REQUIRED"),
        { code: "RECOVERY_SCHEMA_REPAIR_MODE_REQUIRED" }
      );
    }
    write({
      ...recoveryPublisherPrivateSchemaRepairPlan(),
      mode: "PLAN_ONLY",
      applied: false,
      requiredVerifyEnvironment: REQUIRED_BOUND_ENVIRONMENT,
      requiredApplyEnvironment: [
        ...REQUIRED_BOUND_ENVIRONMENT,
        "RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_CONFIRMATION"
      ]
    });
    return;
  }
  if (!["--apply", "--verify-applied"].includes(mode) || args.length !== 1) {
    throw Object.assign(
      new Error("RECOVERY_SCHEMA_REPAIR_MODE_REQUIRED"),
      { code: "RECOVERY_SCHEMA_REPAIR_MODE_REQUIRED" }
    );
  }
  if (mode === "--verify-applied") {
    const receipt = await verifyRepair(boundOptions(environment));
    if (receipt.status !== "CONFIRMED_PRESENT" || !receipt.applied) {
      const error = Object.assign(
        new Error("RECOVERY_SCHEMA_REPAIR_CONFIRMED_ABSENT"),
        {
          code: "RECOVERY_SCHEMA_REPAIR_CONFIRMED_ABSENT",
          reconciliation: receipt
        }
      );
      throw error;
    }
    write(receipt);
    return receipt;
  }
  const confirmation = requiredEnvironment(
    environment,
    "RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_CONFIRMATION"
  );
  if (confirmation !== RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_CONFIRMATION) {
    throw Object.assign(
      new Error("RECOVERY_SCHEMA_REPAIR_CONFIRMATION_REQUIRED"),
      { code: "RECOVERY_SCHEMA_REPAIR_CONFIRMATION_REQUIRED" }
    );
  }
  const receipt = await applyRepair({
    ...boundOptions(environment),
    confirmation
  });
  write(receipt);
  return receipt;
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  main().catch((error) => {
    process.stderr.write(`${JSON.stringify({
      status: "HOLD",
      code: error?.code ?? "RECOVERY_SCHEMA_REPAIR_FAILED",
      message: error?.message ?? "RECOVERY_SCHEMA_REPAIR_FAILED",
      ...(error?.reconciliation
        ? { reconciliation: error.reconciliation }
        : {})
    })}\n`);
    process.exitCode = 1;
  });
}
