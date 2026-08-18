import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

import {
  disableManagedMcpRecoveryGrants,
  managedMcpRecoveryGrantPlan,
  MANAGED_MCP_RECOVERY_DISABLE_CONFIRMATION,
  MANAGED_MCP_RECOVERY_GRANT_CONFIRMATION,
  MANAGED_MCP_RECOVERY_VIEW_DEFINITION_SHA256,
  preflightManagedMcpRecoveryGrants,
  repairManagedMcpRecoveryGrants,
  verifyManagedMcpRecoveryGrants
} from "../src/cloud/recovery-security.js";

function stableError(code, cause) {
  const error = new Error(code, cause ? { cause } : undefined);
  error.code = code;
  return error;
}

function requiredEnvironment(environment, name) {
  const value = environment[name]?.trim();
  if (!value) throw stableError(`${name}_REQUIRED`);
  return value;
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function boundTargetOptions(environment) {
  return {
    adminConnectionString: requiredEnvironment(
      environment,
      "RECOVERY_ADMIN_DATABASE_URL"
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
    expectedViewDefinitionSha256:
      MANAGED_MCP_RECOVERY_VIEW_DEFINITION_SHA256,
    sourceCommit: requiredEnvironment(
      environment,
      "MANAGED_MCP_RECOVERY_REPAIR_SOURCE_COMMIT"
    ),
    sourceTree: requiredEnvironment(
      environment,
      "MANAGED_MCP_RECOVERY_REPAIR_SOURCE_TREE"
    )
  };
}

function boundOptions(environment) {
  return {
    ...boundTargetOptions(environment),
    expectedPreflightPostureDigest: requiredEnvironment(
      environment,
      "EXPECTED_MANAGED_MCP_PRE_REPAIR_POSTURE_SHA256"
    )
  };
}

const REQUIRED_PREFLIGHT_ENVIRONMENT = Object.freeze([
  "RECOVERY_ADMIN_DATABASE_URL",
  "EXPECTED_RECOVERY_HOSTNAME",
  "EXPECTED_RECOVERY_CLUSTER_ID",
  "EXPECTED_RECOVERY_SQL_CLUSTER_ID",
  "MANAGED_MCP_RECOVERY_REPAIR_SOURCE_COMMIT",
  "MANAGED_MCP_RECOVERY_REPAIR_SOURCE_TREE"
]);
const REQUIRED_VERIFY_ENVIRONMENT = Object.freeze([
  ...REQUIRED_PREFLIGHT_ENVIRONMENT,
  "EXPECTED_MANAGED_MCP_PRE_REPAIR_POSTURE_SHA256"
]);

export function createExclusiveManagedMcpJournal(directory) {
  const resolved = path.resolve(directory);
  let real;
  let stat;
  try {
    real = fs.realpathSync(resolved);
    stat = fs.lstatSync(resolved);
  } catch (error) {
    throw stableError("MANAGED_MCP_RECOVERY_JOURNAL_DIRECTORY_INVALID", error);
  }
  if (
    real !== resolved ||
    !stat.isDirectory() ||
    stat.isSymbolicLink() ||
    stat.uid !== process.getuid() ||
    (stat.mode & 0o777) !== 0o700
  ) {
    throw stableError("MANAGED_MCP_RECOVERY_JOURNAL_DIRECTORY_INVALID");
  }
  function writeExclusiveRecord(target, serialized, existsCode) {
    let descriptor;
    try {
      descriptor = fs.openSync(target, "wx", 0o600);
      fs.writeFileSync(descriptor, serialized, { encoding: "utf8" });
      fs.fsyncSync(descriptor);
    } catch (error) {
      if (descriptor !== undefined) fs.closeSync(descriptor);
      throw stableError(
        error?.code === "EEXIST"
          ? existsCode
          : "MANAGED_MCP_RECOVERY_JOURNAL_WRITE_FAILED",
        error
      );
    }
    fs.closeSync(descriptor);
    const directoryDescriptor = fs.openSync(resolved, "r");
    try {
      fs.fsyncSync(directoryDescriptor);
    } finally {
      fs.closeSync(directoryDescriptor);
    }
  }

  let targetReservation = null;
  const journalIntent = async (intent) => {
    if (
      !targetReservation ||
      intent.operationId !== targetReservation.operationId ||
      intent.targetReservationDigest !== targetReservation.reservationDigest
    ) {
      throw stableError(
        "MANAGED_MCP_RECOVERY_TARGET_RESERVATION_REQUIRED"
      );
    }
    const intentSha256 = sha256(JSON.stringify(intent));
    const fileName = `${intent.operationId}-${intent.step}-${intentSha256}.json`;
    const target = path.join(resolved, fileName);
    if (path.dirname(target) !== resolved) {
      throw stableError("MANAGED_MCP_RECOVERY_JOURNAL_PATH_INVALID");
    }
    const record = Object.freeze({
      schemaVersion: "tideproof.managed-mcp-recovery-local-journal.v1",
      reservation: "UNIQUE_RESERVED",
      operationId: intent.operationId,
      targetReservationDigest: targetReservation.reservationDigest,
      intentSha256,
      intent
    });
    const serialized = `${JSON.stringify(record)}\n`;
    writeExclusiveRecord(
      target,
      serialized,
      "MANAGED_MCP_RECOVERY_JOURNAL_ALREADY_RESERVED"
    );
    return Object.freeze({
      operationId: intent.operationId,
      intentSha256,
      reservation: "UNIQUE_RESERVED",
      targetReservationDigest: targetReservation.reservationDigest,
      journalDigest: sha256(serialized)
    });
  };
  journalIntent.reserveTarget = async (reservationIntent) => {
    const targetBindingSha256 = sha256(JSON.stringify(
      reservationIntent?.targetBinding
    ));
    if (
      reservationIntent?.schemaVersion !==
        "tideproof.managed-mcp-recovery-target-reservation.v1" ||
      typeof reservationIntent?.operationId !== "string" ||
      reservationIntent?.targetBindingSha256 !== targetBindingSha256 ||
      !/^[0-9a-f]{64}$/u.test(targetBindingSha256)
    ) {
      throw stableError(
        "MANAGED_MCP_RECOVERY_TARGET_RESERVATION_INVALID"
      );
    }
    if (targetReservation) {
      if (
        targetReservation.operationId !== reservationIntent.operationId ||
        targetReservation.targetBindingSha256 !== targetBindingSha256
      ) {
        throw stableError(
          "MANAGED_MCP_RECOVERY_TARGET_ALREADY_RESERVED"
        );
      }
      return targetReservation;
    }
    const fileName = `target-${targetBindingSha256}.lock.json`;
    const target = path.join(resolved, fileName);
    const record = Object.freeze({
      schemaVersion: "tideproof.managed-mcp-recovery-target-lock.v1",
      reservation: "TARGET_UNIQUE_RESERVED",
      operationId: reservationIntent.operationId,
      targetBindingSha256,
      targetBinding: reservationIntent.targetBinding
    });
    const serialized = `${JSON.stringify(record)}\n`;
    try {
      writeExclusiveRecord(
        target,
        serialized,
        "MANAGED_MCP_RECOVERY_TARGET_ALREADY_RESERVED"
      );
    } catch (error) {
      if (
        error?.code !== "MANAGED_MCP_RECOVERY_TARGET_ALREADY_RESERVED"
      ) {
        throw error;
      }
      let existing;
      let targetStat;
      try {
        targetStat = fs.lstatSync(target);
        existing = fs.readFileSync(target, "utf8");
      } catch (readError) {
        throw stableError(
          "MANAGED_MCP_RECOVERY_TARGET_RESERVATION_UNRESOLVED",
          readError
        );
      }
      if (
        !targetStat.isFile() ||
        targetStat.isSymbolicLink() ||
        targetStat.uid !== process.getuid() ||
        (targetStat.mode & 0o777) !== 0o600 ||
        existing !== serialized
      ) {
        throw stableError(
          "MANAGED_MCP_RECOVERY_TARGET_ALREADY_RESERVED",
          error
        );
      }
    }
    targetReservation = Object.freeze({
      operationId: reservationIntent.operationId,
      reservation: "TARGET_UNIQUE_RESERVED",
      targetBindingSha256,
      reservationDigest: sha256(serialized)
    });
    return targetReservation;
  };
  return journalIntent;
}

export async function main(
  args = process.argv.slice(2),
  environment = process.env,
  {
    write = (value) => process.stdout.write(
      `${JSON.stringify(value, null, 2)}\n`
    ),
    applyRepair = repairManagedMcpRecoveryGrants,
    preflightRepair = preflightManagedMcpRecoveryGrants,
    verifyRepair = verifyManagedMcpRecoveryGrants,
    disableRepair = disableManagedMcpRecoveryGrants,
    createJournal = createExclusiveManagedMcpJournal
  } = {}
) {
  const [mode] = args;
  if (args.length !== 1 || ![
    "--plan",
    "--preflight",
    "--verify",
    "--apply",
    "--disable"
  ].includes(mode)) {
    throw stableError("MANAGED_MCP_RECOVERY_REPAIR_MODE_REQUIRED");
  }
  if (mode === "--plan") {
    const receipt = {
      ...managedMcpRecoveryGrantPlan(),
      mode: "PLAN_ONLY",
      applied: false,
      requiredPreflightEnvironment: REQUIRED_PREFLIGHT_ENVIRONMENT,
      requiredVerifyEnvironment: REQUIRED_VERIFY_ENVIRONMENT,
      requiredMutationEnvironment: [
        ...REQUIRED_VERIFY_ENVIRONMENT,
        "MANAGED_MCP_RECOVERY_OPERATION_ID",
        "MANAGED_MCP_RECOVERY_JOURNAL_DIRECTORY"
      ],
      requiredApplyEnvironment: [
        ...REQUIRED_VERIFY_ENVIRONMENT,
        "MANAGED_MCP_RECOVERY_OPERATION_ID",
        "MANAGED_MCP_RECOVERY_JOURNAL_DIRECTORY",
        "MANAGED_MCP_RECOVERY_GRANT_CONFIRMATION"
      ],
      requiredDisableEnvironment: [
        ...REQUIRED_VERIFY_ENVIRONMENT,
        "MANAGED_MCP_RECOVERY_OPERATION_ID",
        "MANAGED_MCP_RECOVERY_JOURNAL_DIRECTORY",
        "MANAGED_MCP_RECOVERY_DISABLE_CONFIRMATION"
      ],
      operationIdGenerationCommand:
        "uuidgen | tr '[:upper:]' '[:lower:]'",
      journalDirectoryBoundary:
        "Use one canonical, non-symlink, owner-only 0700 directory as the single mutation authority for this target. Reuse the original operation ID for reconciliation or disable; do not create a competing journal directory."
    };
    write(receipt);
    return receipt;
  }
  if (mode === "--preflight") {
    const receipt = await preflightRepair(boundTargetOptions(environment));
    write(receipt);
    return receipt;
  }
  const options = boundOptions(environment);
  if (mode === "--verify") {
    const receipt = await verifyRepair(options);
    write(receipt);
    return receipt;
  }
  const operationId = requiredEnvironment(
    environment,
    "MANAGED_MCP_RECOVERY_OPERATION_ID"
  );
  if (mode === "--apply") {
    const confirmation = requiredEnvironment(
      environment,
      "MANAGED_MCP_RECOVERY_GRANT_CONFIRMATION"
    );
    if (confirmation !== MANAGED_MCP_RECOVERY_GRANT_CONFIRMATION) {
      throw stableError("MANAGED_MCP_RECOVERY_CONFIRMATION_REQUIRED");
    }
    const journalIntent = createJournal(requiredEnvironment(
      environment,
      "MANAGED_MCP_RECOVERY_JOURNAL_DIRECTORY"
    ));
    const receipt = await applyRepair({
      ...options,
      operationId,
      journalIntent,
      confirmation
    });
    write(receipt);
    return receipt;
  }
  const confirmation = requiredEnvironment(
    environment,
    "MANAGED_MCP_RECOVERY_DISABLE_CONFIRMATION"
  );
  if (confirmation !== MANAGED_MCP_RECOVERY_DISABLE_CONFIRMATION) {
    throw stableError(
      "MANAGED_MCP_RECOVERY_DISABLE_CONFIRMATION_REQUIRED"
    );
  }
  const journalIntent = createJournal(requiredEnvironment(
    environment,
    "MANAGED_MCP_RECOVERY_JOURNAL_DIRECTORY"
  ));
  const receipt = await disableRepair({
    ...options,
    operationId,
    journalIntent,
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
      code: error?.code ?? "MANAGED_MCP_RECOVERY_REPAIR_FAILED",
      message: error?.message ?? "MANAGED_MCP_RECOVERY_REPAIR_FAILED",
      ...(error?.reconciliation
        ? { reconciliation: error.reconciliation }
        : {}),
      ...(error?.emergencyDisable
        ? { emergencyDisable: error.emergencyDisable }
        : {})
    })}\n`);
    process.exitCode = 1;
  });
}
