import crypto from "node:crypto";
import { spawnSync } from "node:child_process";

import {
  exactNpmCli,
  isolatedEnvironment
} from "../build-gate2-exact.js";

function requireCondition(condition, code) {
  if (!condition) {
    throw new Error(code);
  }
}

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

export function exactBuildRecord(bytes, code) {
  requireCondition(
    Buffer.isBuffer(bytes) &&
      bytes.length > 0 &&
      bytes.length <= 5 * 1024 * 1024,
    code
  );
  try {
    return Object.freeze({
      bytes,
      digest: sha256(bytes),
      value: JSON.parse(bytes.toString("utf8"))
    });
  } catch {
    throw new Error(code);
  }
}

export function reproduceExactBuild({
  projectRoot,
  environment = process.env,
  codePrefix = "AWS_ATTEST_EXACT_BUILD"
}) {
  const npmCli = exactNpmCli(environment);
  const result = spawnSync(
    process.execPath,
    [npmCli, "run", "--silent", "build:gate2"],
    {
      cwd: projectRoot,
      encoding: null,
      env: {
        ...isolatedEnvironment(environment),
        npm_execpath: npmCli,
        npm_node_execpath: process.execPath
      },
      maxBuffer: 64 * 1024 * 1024,
      stdio: ["ignore", "pipe", "ignore"]
    }
  );
  requireCondition(
    !result.error && result.status === 0,
    `${codePrefix}_REPRODUCTION`
  );
  return exactBuildRecord(result.stdout, `${codePrefix}_RECEIPT`);
}

export function validateExactBuildReproduction(
  provided,
  reproduced,
  code = "AWS_ATTEST_EXACT_BUILD_MISMATCH"
) {
  requireCondition(
    provided &&
      reproduced &&
      Buffer.isBuffer(provided.bytes) &&
      Buffer.isBuffer(reproduced.bytes) &&
      provided.digest === sha256(provided.bytes) &&
      reproduced.digest === sha256(reproduced.bytes) &&
      provided.digest === reproduced.digest &&
      provided.bytes.equals(reproduced.bytes),
    code
  );
  return Object.freeze({
    buildReceiptSha256: provided.digest,
    reproducedBuildReceiptSha256: reproduced.digest
  });
}
