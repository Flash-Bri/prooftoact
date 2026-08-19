import { canonicalJson } from "./canonical-json.js";
import {
  validatePrivateRecoveryQueryCommand,
  validatePrivateRecoveryQueryReceipt
} from "./private-recovery-query.js";

const TABLE_NAME = "prooftoact-release-controller";
const ITEM_SCHEMA = "prooftoact.private-recovery-query-state.v1";
const HEX_64 = /^[0-9a-f]{64}$/u;

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
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

function s(value) {
  return { S: value };
}

function n(value) {
  return { N: String(value) };
}

function b(value) {
  return { B: Buffer.from(canonicalJson(value), "utf8") };
}

function stringAttribute(item, name, code) {
  requireCondition(typeof item?.[name]?.S === "string", code);
  return item[name].S;
}

function integerAttribute(item, name, code) {
  const raw = item?.[name]?.N;
  requireCondition(/^(?:0|[1-9][0-9]*)$/u.test(raw ?? ""), code);
  const value = Number(raw);
  requireCondition(Number.isSafeInteger(value), code);
  return value;
}

function decodeCanonical(attribute, code) {
  requireCondition(attribute?.B !== undefined, code);
  const bytes = Buffer.from(attribute.B);
  requireCondition(bytes.length > 0 && bytes.length <= 128 * 1024, code);
  let value;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch (cause) {
    reject(code, cause);
  }
  requireCondition(canonicalJson(value) === bytes.toString("utf8"), code);
  return value;
}

function stateKey(command) {
  return `PRIVATE_RECOVERY_QUERY#${command.globalKeySha256}`;
}

function decodeItem(item, command) {
  const code = "PRIVATE_RECOVERY_QUERY_DDB_ITEM_REJECTED";
  requireCondition(plainObject(item), code);
  const status = stringAttribute(item, "status", code);
  const baseKeys = [
    "command", "commandSha256", "operationId", "pk", "schemaVersion",
    "status", "version"
  ];
  const expectedKeys = status === "RESERVED"
    ? baseKeys
    : status === "DISPATCHING"
      ? [...baseKeys, "dispatch"]
      : [...baseKeys, "receipt"];
  requireCondition(exactKeys(item, expectedKeys) &&
    stringAttribute(item, "pk", code) === stateKey(command) &&
    stringAttribute(item, "schemaVersion", code) === ITEM_SCHEMA &&
    stringAttribute(item, "commandSha256", code) === command.commandSha256 &&
    stringAttribute(item, "operationId", code) === command.operationId &&
    ["RESERVED", "DISPATCHING", "FINAL", "FAILED", "UNKNOWN"]
      .includes(status), code);
  const storedCommand = validatePrivateRecoveryQueryCommand(
    decodeCanonical(item.command, code)
  );
  requireCondition(canonicalJson(storedCommand) === canonicalJson(command), code);
  const version = integerAttribute(item, "version", code);
  if (status === "RESERVED") {
    requireCondition(version === 0, code);
    return Object.freeze({
      commandSha256: command.commandSha256,
      operationId: command.operationId,
      status,
      version
    });
  }
  if (status === "DISPATCHING") {
    const dispatch = decodeCanonical(item.dispatch, code);
    requireCondition(exactKeys(dispatch, [
      "lambdaRequestIdSha256", "logicalRequestSha256", "querySha256",
      "secretValueSha256"
    ]) && Object.values(dispatch).every((value) =>
      HEX_64.test(value ?? "")) && version === 1, code);
    return Object.freeze({
      commandSha256: command.commandSha256,
      dispatch,
      operationId: command.operationId,
      status,
      version
    });
  }
  const receipt = validatePrivateRecoveryQueryReceipt(
    decodeCanonical(item.receipt, code)
  );
  requireCondition(receipt.commandSha256 === command.commandSha256 &&
    receipt.operationId === command.operationId &&
    ((status === "FINAL" && receipt.status === "PASS") ||
      (status === "FAILED" && receipt.status === "FAILED_NO_PROVIDER_CALL") ||
      (status === "UNKNOWN" && receipt.status === "UNKNOWN_DO_NOT_RETRY")) &&
    version === 2, code);
  return Object.freeze({
    commandSha256: command.commandSha256,
    operationId: command.operationId,
    receipt,
    status,
    version
  });
}

function updateBase(command) {
  return {
    TableName: TABLE_NAME,
    Key: { pk: s(stateKey(command)) },
    ReturnValues: "ALL_NEW",
    ReturnConsumedCapacity: "NONE"
  };
}

function desiredTerminalStatus(receipt) {
  if (receipt.status === "PASS") return "FINAL";
  if (receipt.status === "FAILED_NO_PROVIDER_CALL") return "FAILED";
  if (receipt.status === "UNKNOWN_DO_NOT_RETRY") return "UNKNOWN";
  reject("PRIVATE_RECOVERY_QUERY_DDB_TERMINAL_REJECTED");
}

export function createPrivateRecoveryQueryAwsStore({ runtime }) {
  requireCondition(runtime && ["getReleaseControlItem", "updateReleaseControlItem"]
    .every((name) => typeof runtime[name] === "function"),
  "PRIVATE_RECOVERY_QUERY_DDB_RUNTIME_REJECTED");

  const read = async (rawCommand) => {
    const command = validatePrivateRecoveryQueryCommand(rawCommand);
    const result = await runtime.getReleaseControlItem({
      TableName: TABLE_NAME,
      Key: { pk: s(stateKey(command)) },
      ConsistentRead: true,
      ReturnConsumedCapacity: "NONE"
    });
    requireCondition(result?.Item !== undefined,
      "PRIVATE_RECOVERY_QUERY_DDB_ITEM_ABSENT");
    return decodeItem(result.Item, command);
  };

  const apply = async (command, input, accept) => {
    try {
      const response = await runtime.updateReleaseControlItem(input);
      return decodeItem(response?.Attributes, command);
    } catch (cause) {
      let observed;
      try {
        observed = await read(command);
      } catch (readCause) {
        reject("PRIVATE_RECOVERY_QUERY_DDB_ACK_UNKNOWN", {
          cause,
          readCause
        });
      }
      requireCondition(accept(observed),
        "PRIVATE_RECOVERY_QUERY_DDB_TRANSITION_CONFLICT");
      return observed;
    }
  };

  const terminal = async (rawCommand, receipt, expectedStatus, dispatch = null) => {
    const command = validatePrivateRecoveryQueryCommand(rawCommand);
    const acceptedReceipt = validatePrivateRecoveryQueryReceipt(receipt);
    const terminalStatus = desiredTerminalStatus(acceptedReceipt);
    requireCondition(terminalStatus === expectedStatus &&
      acceptedReceipt.commandSha256 === command.commandSha256 &&
      acceptedReceipt.operationId === command.operationId,
    "PRIVATE_RECOVERY_QUERY_DDB_TERMINAL_REJECTED");
    const input = {
      ...updateBase(command),
      ConditionExpression:
        "#status = :expected AND #version = :expectedVersion " +
        "AND #commandSha256 = :commandSha256",
      UpdateExpression:
        "SET #status = :status, #version = :version, #receipt = :receipt " +
        "REMOVE #dispatch",
      ExpressionAttributeNames: {
        "#commandSha256": "commandSha256",
        "#dispatch": "dispatch",
        "#receipt": "receipt",
        "#status": "status",
        "#version": "version"
      },
      ExpressionAttributeValues: {
        ":commandSha256": s(command.commandSha256),
        ":expected": s(dispatch === null ? "RESERVED" : "DISPATCHING"),
        ":expectedVersion": n(dispatch === null ? 0 : 1),
        ":receipt": b(acceptedReceipt),
        ":status": s(terminalStatus),
        ":version": n(2)
      }
    };
    if (dispatch !== null) {
      requireCondition(plainObject(dispatch),
        "PRIVATE_RECOVERY_QUERY_DDB_TERMINAL_REJECTED");
      input.ConditionExpression += " AND #dispatch = :dispatch";
      input.ExpressionAttributeValues[":dispatch"] = b(dispatch);
    }
    return apply(command, input, (observed) =>
      observed.status === expectedStatus &&
      canonicalJson(observed.receipt) === canonicalJson(acceptedReceipt));
  };

  return Object.freeze({
    async reserve(rawCommand) {
      const command = validatePrivateRecoveryQueryCommand(rawCommand);
      const input = {
        ...updateBase(command),
        ConditionExpression: "attribute_not_exists(#pk)",
        UpdateExpression:
          "SET #schemaVersion = :schemaVersion, #status = :status, " +
          "#command = :command, #commandSha256 = :commandSha256, " +
          "#operationId = :operationId, #version = :version",
        ExpressionAttributeNames: {
          "#command": "command",
          "#commandSha256": "commandSha256",
          "#operationId": "operationId",
          "#pk": "pk",
          "#schemaVersion": "schemaVersion",
          "#status": "status",
          "#version": "version"
        },
        ExpressionAttributeValues: {
          ":command": b(command),
          ":commandSha256": s(command.commandSha256),
          ":operationId": s(command.operationId),
          ":schemaVersion": s(ITEM_SCHEMA),
          ":status": s("RESERVED"),
          ":version": n(0)
        }
      };
      return apply(command, input, (observed) =>
        observed.commandSha256 === command.commandSha256);
    },

    read,

    async markDispatch(rawCommand, dispatch) {
      const command = validatePrivateRecoveryQueryCommand(rawCommand);
      requireCondition(exactKeys(dispatch, [
        "lambdaRequestIdSha256", "logicalRequestSha256", "querySha256",
        "secretValueSha256"
      ]) && Object.values(dispatch).every((value) => HEX_64.test(value ?? "")),
      "PRIVATE_RECOVERY_QUERY_DDB_DISPATCH_REJECTED");
      const input = {
        ...updateBase(command),
        ConditionExpression:
          "#status = :expected AND #version = :expectedVersion " +
          "AND #commandSha256 = :commandSha256",
        UpdateExpression:
          "SET #status = :status, #version = :version, #dispatch = :dispatch",
        ExpressionAttributeNames: {
          "#commandSha256": "commandSha256",
          "#dispatch": "dispatch",
          "#status": "status",
          "#version": "version"
        },
        ExpressionAttributeValues: {
          ":commandSha256": s(command.commandSha256),
          ":dispatch": b(dispatch),
          ":expected": s("RESERVED"),
          ":expectedVersion": n(0),
          ":status": s("DISPATCHING"),
          ":version": n(1)
        }
      };
      return apply(command, input, (observed) =>
        observed.status === "DISPATCHING" &&
        canonicalJson(observed.dispatch) === canonicalJson(dispatch));
    },

    finalize(command, dispatch, receipt) {
      return terminal(command, receipt, "FINAL", dispatch);
    },

    failBeforeDispatch(command, receipt) {
      return terminal(command, receipt, "FAILED");
    },

    async markUnknown(rawCommand, receipt) {
      const command = validatePrivateRecoveryQueryCommand(rawCommand);
      const current = await read(command);
      if (["FINAL", "FAILED", "UNKNOWN"].includes(current.status)) {
        return current;
      }
      requireCondition(current.status === "DISPATCHING",
        "PRIVATE_RECOVERY_QUERY_DDB_TERMINAL_REJECTED");
      return terminal(command, receipt, "UNKNOWN", current.dispatch);
    }
  });
}

export const __test = Object.freeze({
  ITEM_SCHEMA,
  TABLE_NAME,
  decodeItem,
  stateKey
});
