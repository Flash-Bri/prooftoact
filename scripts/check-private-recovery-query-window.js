import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { canonicalJson } from "../src/cloud/canonical-json.js";
import {
  privateRecoveryQueryApprovalSha256,
  validatePrivateRecoveryQueryApproval
} from "../src/cloud/private-recovery-query.js";

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function readCanonicalJson(filePath) {
  const resolved = path.resolve(filePath);
  const stat = fs.lstatSync(resolved);
  requireCondition(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1 &&
    stat.size > 0 && stat.size <= 128 * 1024,
  "PRIVATE_RECOVERY_QUERY_WINDOW_INPUT_REJECTED");
  const text = fs.readFileSync(resolved, "utf8");
  let value;
  try { value = JSON.parse(text); } catch (cause) {
    reject("PRIVATE_RECOVERY_QUERY_WINDOW_INPUT_REJECTED", cause);
  }
  requireCondition(text === `${canonicalJson(value)}\n`,
    "PRIVATE_RECOVERY_QUERY_WINDOW_INPUT_REJECTED");
  return value;
}

export function checkPrivateRecoveryQueryWindow({
  approval: rawApproval,
  minimumRemainingSeconds,
  now = new Date()
}) {
  const code = "PRIVATE_RECOVERY_QUERY_WINDOW_REJECTED";
  requireCondition(now instanceof Date && Number.isFinite(now.getTime()) &&
    Number.isSafeInteger(minimumRemainingSeconds) &&
    minimumRemainingSeconds >= 60 && minimumRemainingSeconds <= 30 * 60, code);
  const approval = validatePrivateRecoveryQueryApproval(rawApproval, now);
  const remainingMilliseconds = Date.parse(approval.expiresAt) - now.getTime();
  requireCondition(remainingMilliseconds >= minimumRemainingSeconds * 1_000,
    code);
  return Object.freeze({
    schemaVersion: "prooftoact.private-recovery-query-window-check.v1",
    status: "PASS",
    approvalSha256: privateRecoveryQueryApprovalSha256(approval),
    minimumRemainingSeconds,
    remainingSeconds: Math.floor(remainingMilliseconds / 1_000)
  });
}

function parseArguments(args) {
  requireCondition(args.length === 4 && args[0] === "--approval-file" &&
    args[2] === "--minimum-remaining-seconds" &&
    /^[0-9]{2,4}$/u.test(args[3] ?? ""),
  "PRIVATE_RECOVERY_QUERY_WINDOW_ARGUMENT_REJECTED");
  return Object.freeze({
    approvalFile: args[1],
    minimumRemainingSeconds: Number(args[3])
  });
}

export async function main(args = process.argv.slice(2)) {
  const parsed = parseArguments(args);
  const result = checkPrivateRecoveryQueryWindow({
    approval: readCanonicalJson(parsed.approvalFile),
    minimumRemainingSeconds: parsed.minimumRemainingSeconds
  });
  process.stdout.write(`${canonicalJson(result)}\n`);
  return result;
}

const isDirect = process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (isDirect) {
  main().catch((cause) => {
    const code = /^PRIVATE_RECOVERY_QUERY_[A-Z0-9_]{1,120}$/u.test(
      cause?.message ?? ""
    ) ? cause.message : "PRIVATE_RECOVERY_QUERY_WINDOW_UNKNOWN_HOLD";
    process.stderr.write(`${code}\n`);
    process.exitCode = 1;
  });
}

export const __test = Object.freeze({ parseArguments });
