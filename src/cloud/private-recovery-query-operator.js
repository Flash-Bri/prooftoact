import {
  reconcilePrivateRecoveryQuery,
  reservePrivateRecoveryQuery,
  validatePrivateRecoveryQueryCommand,
  validatePrivateRecoveryQueryReceipt
} from "./private-recovery-query.js";

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}
function requireCondition(condition, code) {
  if (!condition) reject(code);
}

export async function executePrivateRecoveryQueryOnce({
  approval,
  command: rawCommand,
  invoker,
  store
}) {
  const command = validatePrivateRecoveryQueryCommand(rawCommand);
  requireCondition(invoker && typeof invoker.invokeExactVersion === "function",
    "PRIVATE_RECOVERY_QUERY_INVOKER_REJECTED");
  const reserved = await reservePrivateRecoveryQuery({ command, store });
  if (["FINAL", "FAILED", "UNKNOWN"].includes(reserved.status)) {
    return validatePrivateRecoveryQueryReceipt(reserved.receipt);
  }
  requireCondition(reserved.status === "RESERVED",
    "PRIVATE_RECOVERY_QUERY_RESERVATION_REJECTED");
  let response;
  try {
    response = await invoker.invokeExactVersion({
      event: Object.freeze({
        schemaVersion: "prooftoact.private-recovery-query-invocation.v1",
        approval
      }),
      functionArn: command.functionArn,
      functionVersion: command.functionVersion
    });
  } catch (cause) {
    const reconciliation = await reconcilePrivateRecoveryQuery({
      command,
      store
    });
    if (["PASS", "FAILED_NO_PROVIDER_CALL", "UNKNOWN_DO_NOT_RETRY"]
      .includes(reconciliation.status)) {
      return validatePrivateRecoveryQueryReceipt(reconciliation);
    }
    return Object.freeze({
      ...reconciliation,
      invocationErrorCode: "PRIVATE_RECOVERY_QUERY_INVOCATION_ACK_UNKNOWN"
    });
  }
  const receipt = validatePrivateRecoveryQueryReceipt(response);
  requireCondition(receipt.commandSha256 === command.commandSha256 &&
    receipt.operationId === command.operationId,
  "PRIVATE_RECOVERY_QUERY_INVOCATION_RECEIPT_REJECTED");
  const observed = await reconcilePrivateRecoveryQuery({ command, store });
  requireCondition(["PASS", "FAILED_NO_PROVIDER_CALL", "UNKNOWN_DO_NOT_RETRY"]
    .includes(observed.status) &&
    observed.receiptSha256 === receipt.receiptSha256,
  "PRIVATE_RECOVERY_QUERY_FINAL_READBACK_REJECTED");
  return receipt;
}
