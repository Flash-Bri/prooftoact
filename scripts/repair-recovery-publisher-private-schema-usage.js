import {
  RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_CONFIRMATION,
  recoveryPublisherPrivateSchemaRepairPlan,
  repairRecoveryPublisherPrivateSchemaUsage
} from "../src/cloud/recovery-security.js";

function requiredEnvironment(name) {
  const value = process.env[name]?.trim();
  if (!value) {
    const error = new Error(`${name}_REQUIRED`);
    error.code = `${name}_REQUIRED`;
    throw error;
  }
  return value;
}

function print(value) {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
}

async function main() {
  const [mode] = process.argv.slice(2);
  if (mode === "--plan") {
    print({
      ...recoveryPublisherPrivateSchemaRepairPlan(),
      mode: "PLAN_ONLY",
      applied: false,
      requiredApplyEnvironment: [
        "RECOVERY_ADMIN_DATABASE_URL",
        "RECOVERY_PUBLISHER_DATABASE_URL",
        "EXPECTED_RECOVERY_HOSTNAME",
        "EXPECTED_RECOVERY_PRE_REPAIR_POSTURE_SHA256",
        "RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_CONFIRMATION"
      ]
    });
    return;
  }
  if (mode !== "--apply" || process.argv.length !== 3) {
    throw Object.assign(
      new Error("RECOVERY_SCHEMA_REPAIR_MODE_REQUIRED"),
      { code: "RECOVERY_SCHEMA_REPAIR_MODE_REQUIRED" }
    );
  }
  const confirmation = requiredEnvironment(
    "RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_CONFIRMATION"
  );
  if (confirmation !== RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_CONFIRMATION) {
    throw Object.assign(
      new Error("RECOVERY_SCHEMA_REPAIR_CONFIRMATION_REQUIRED"),
      { code: "RECOVERY_SCHEMA_REPAIR_CONFIRMATION_REQUIRED" }
    );
  }
  print(await repairRecoveryPublisherPrivateSchemaUsage({
    adminConnectionString: requiredEnvironment("RECOVERY_ADMIN_DATABASE_URL"),
    publisherConnectionString: requiredEnvironment(
      "RECOVERY_PUBLISHER_DATABASE_URL"
    ),
    expectedRecoveryHostname: requiredEnvironment(
      "EXPECTED_RECOVERY_HOSTNAME"
    ),
    expectedPreflightPostureDigest: requiredEnvironment(
      "EXPECTED_RECOVERY_PRE_REPAIR_POSTURE_SHA256"
    ),
    confirmation
  }));
}

main().catch((error) => {
  process.stderr.write(`${JSON.stringify({
    status: "HOLD",
    code: error?.code ?? "RECOVERY_SCHEMA_REPAIR_FAILED",
    message: error?.message ?? "RECOVERY_SCHEMA_REPAIR_FAILED"
  })}\n`);
  process.exitCode = 1;
});
