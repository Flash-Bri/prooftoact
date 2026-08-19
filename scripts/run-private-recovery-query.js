import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { canonicalJson } from "../src/cloud/canonical-json.js";
import {
  buildPrivateRecoveryQueryCommand,
  reconcilePrivateRecoveryQuery,
  validatePrivateRecoveryQueryApproval
} from "../src/cloud/private-recovery-query.js";
import { createPrivateRecoveryQueryOperatorAwsRuntime } from
  "../src/cloud/private-recovery-query-operator-aws.js";
import { executePrivateRecoveryQueryOnce } from
  "../src/cloud/private-recovery-query-operator.js";

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function parseArguments(args) {
  const accepted = new Set([
    "--approval-file", "--code-zip-sha256", "--config-sha256",
    "--expected-commit", "--expected-tree", "--function-arn",
    "--function-version", "--mcp-secret-arn", "--mcp-secret-version-id",
    "--mode", "--receipt-output", "--release-control-table-arn"
  ]);
  requireCondition(args.length === accepted.size * 2,
    "PRIVATE_RECOVERY_QUERY_CLI_ARGUMENT_REJECTED");
  const parsed = {};
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    requireCondition(accepted.has(name) && !Object.hasOwn(parsed, name) &&
      typeof args[index + 1] === "string" && args[index + 1].length > 0,
    "PRIVATE_RECOVERY_QUERY_CLI_ARGUMENT_REJECTED");
    parsed[name] = args[index + 1];
  }
  requireCondition(["execute", "reconcile-only"].includes(parsed["--mode"]) &&
    /^[0-9a-f]{40}$/u.test(parsed["--expected-commit"]) &&
    /^[0-9a-f]{40}$/u.test(parsed["--expected-tree"]) &&
    [parsed["--code-zip-sha256"], parsed["--config-sha256"]]
      .every((value) => /^[0-9a-f]{64}$/u.test(value)),
  "PRIVATE_RECOVERY_QUERY_CLI_ARGUMENT_REJECTED");
  return Object.freeze(parsed);
}

function readJson(filePath, maximumBytes) {
  const resolved = path.resolve(filePath);
  const stat = fs.lstatSync(resolved);
  requireCondition(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1 &&
    stat.size > 0 && stat.size <= maximumBytes,
  "PRIVATE_RECOVERY_QUERY_CLI_INPUT_REJECTED");
  const bytes = fs.readFileSync(resolved);
  let value;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch (cause) {
    reject("PRIVATE_RECOVERY_QUERY_CLI_INPUT_REJECTED", cause);
  }
  requireCondition(bytes.toString("utf8") === `${canonicalJson(value)}\n`,
    "PRIVATE_RECOVERY_QUERY_CLI_INPUT_REJECTED");
  return value;
}

function publishReceipt(filePath, receipt) {
  const resolved = path.resolve(filePath);
  requireCondition(!fs.existsSync(resolved),
    "PRIVATE_RECOVERY_QUERY_CLI_OUTPUT_REJECTED");
  fs.mkdirSync(path.dirname(resolved), { recursive: true, mode: 0o700 });
  const descriptor = fs.openSync(resolved,
    fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY, 0o600);
  try {
    fs.writeFileSync(descriptor, `${canonicalJson(receipt)}\n`, "utf8");
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  return crypto.createHash("sha256").update(fs.readFileSync(resolved)).digest("hex");
}

export async function main(
  args = process.argv.slice(2),
  environment = process.env,
  runtimeFactory = createPrivateRecoveryQueryOperatorAwsRuntime
) {
  const parsed = parseArguments(args);
  const observedAt = parsed["--mode"] === "execute" ? new Date() : null;
  const approval = validatePrivateRecoveryQueryApproval(
    readJson(parsed["--approval-file"], 64 * 1024),
    observedAt
  );
  requireCondition(approval.sourceCommit === parsed["--expected-commit"] &&
    approval.treeDigest === parsed["--expected-tree"],
  "PRIVATE_RECOVERY_QUERY_CLI_SOURCE_REJECTED");
  const command = buildPrivateRecoveryQueryCommand({
    approval,
    codeZipSha256: parsed["--code-zip-sha256"],
    configSha256: parsed["--config-sha256"],
    functionArn: parsed["--function-arn"],
    functionVersion: parsed["--function-version"],
    mcpSecretArn: parsed["--mcp-secret-arn"],
    mcpSecretVersionId: parsed["--mcp-secret-version-id"],
    releaseControlTableArn: parsed["--release-control-table-arn"],
    now: observedAt
  });
  const runtime = await runtimeFactory({
    environment,
    releaseControlTableArn: command.releaseControlTableArn
  });
  const receipt = parsed["--mode"] === "execute"
    ? await executePrivateRecoveryQueryOnce({
      approval,
      command,
      invoker: runtime.invoker,
      store: runtime.store
    })
    : await reconcilePrivateRecoveryQuery({ command, store: runtime.store });
  const receiptSha256 = publishReceipt(parsed["--receipt-output"], receipt);
  process.stdout.write(
    `PRIVATE_RECOVERY_QUERY_${receipt.status}:${receiptSha256}\n`
  );
  return receipt;
}

const isDirect = process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (isDirect) {
  main().catch((cause) => {
    const code = /^PRIVATE_RECOVERY_QUERY_[A-Z0-9_]{1,100}$/u.test(
      cause?.message ?? ""
    ) ? cause.message : "PRIVATE_RECOVERY_QUERY_UNKNOWN_HOLD";
    process.stderr.write(`${code}\n`);
    process.exitCode = 1;
  });
}

export const __test = Object.freeze({ parseArguments, publishReceipt, readJson });
