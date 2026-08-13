import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import {
  runIntegratedLiveDrillDispatchBroker
} from "../../src/cloud/integrated-live-drill-dispatch-broker.js";

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function required(name) {
  const value = process.env[name];
  if (typeof value !== "string" || value.length === 0 || /[\0\r\n]/u.test(value)) {
    throw new Error("BROKER_CHILD_ENVIRONMENT_REJECTED");
  }
  return value;
}

function result(binding, row, transitionOutcome) {
  return Object.freeze({
    authorizationId: binding.authorizationId,
    controlBindingSha256: binding.controlBindingSha256,
    databaseNow: binding.issuedAt,
    expiresAt: binding.expiresAt,
    grantId: row.grantId,
    mcpResultSha256: null,
    sessionCloseSha256: null,
    state: row.state,
    transitionOutcome,
    workerSpecSha256: row.workerSpecSha256
  });
}

function readRow(statePath) {
  for (let count = 0; count < 2_000; count += 1) {
    try {
      const text = fs.readFileSync(statePath, "utf8");
      if (text.endsWith("\n")) return JSON.parse(text);
    } catch (cause) {
      if (cause?.code !== "ENOENT") throw cause;
    }
  }
  throw new Error("BROKER_CHILD_STATE_UNAVAILABLE");
}

function writeInitialRow(statePath, value) {
  let descriptor;
  try {
    descriptor = fs.openSync(
      statePath,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL,
      0o600
    );
    fs.writeFileSync(descriptor, `${JSON.stringify(value)}\n`);
    fs.fsyncSync(descriptor);
    return true;
  } catch (cause) {
    if (cause?.code === "EEXIST") return false;
    throw cause;
  } finally {
    if (Number.isSafeInteger(descriptor)) fs.closeSync(descriptor);
  }
}

function replaceRow(statePath, value) {
  const temporaryPath = `${statePath}.${process.pid}.tmp`;
  fs.writeFileSync(temporaryPath, `${JSON.stringify(value)}\n`, {
    flag: "wx",
    mode: 0o600
  });
  fs.renameSync(temporaryPath, statePath);
}

async function main() {
  if (Object.hasOwn(process.env, "MCP_API_KEY")) {
    throw new Error("BROKER_CHILD_PROVIDER_CREDENTIAL_PRESENT");
  }
  const request = JSON.parse(required("BROKER_REQUEST_JSON"));
  const statePath = required("BROKER_SHARED_STATE_PATH");
  const candidate = { value: null };
  const claimControl = Object.freeze({
    async claim(binding, input) {
      candidate.value = input;
      const created = writeInitialRow(statePath, {
        executionCapabilitySha256: input.executionCapabilitySha256,
        grantId: input.grantId,
        state: "GRANTED",
        workerSpecSha256: input.workerSpecSha256
      });
      const row = readRow(statePath);
      return result(
        binding,
        row,
        created || row.grantId === input.grantId
          ? "DISPATCH_GRANTED"
          : "ALREADY_TERMINAL_OR_EXECUTING"
      );
    }
  });
  const beginControl = Object.freeze({
    async begin(binding, input) {
      const row = readRow(statePath);
      if (
        row.grantId !== input.grantId ||
        row.executionCapabilitySha256 !== sha256(input.executionCapability) ||
        row.workerSpecSha256 !== input.workerSpecSha256 ||
        candidate.value?.grantId !== input.grantId
      ) {
        throw new Error("BROKER_CHILD_BEGIN_REJECTED");
      }
      if (row.state === "GRANTED") {
        replaceRow(statePath, { ...row, state: "EXECUTING" });
        row.state = "EXECUTING";
        return result(binding, row, "EXECUTION_STARTED");
      }
      return result(binding, row, "ALREADY_EXECUTING_DO_NOT_START");
    }
  });
  const receipt = await runIntegratedLiveDrillDispatchBroker({
    beginControl,
    brokerRootPath: required("BROKER_PRIVATE_ROOT"),
    claimControl,
    executionGrantPath: required("BROKER_EXECUTION_GRANT_PATH"),
    executionGrantRootPath: required("BROKER_EXECUTION_GRANT_ROOT"),
    request
  });
  process.stdout.write(`${JSON.stringify(receipt)}\n`);
}

main().catch((error) => {
  process.stderr.write(`${String(error?.message ?? error)}\n`);
  process.exitCode = 1;
});
