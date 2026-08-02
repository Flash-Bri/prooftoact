import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { assertSafeProjectPath } from "./exact-git-source.js";

const HEX_64 = /^[0-9a-f]{64}$/;
const RUNTIME_PATH = /^dist\/aws\/evidence-provider-[0-9a-f]{64}\.mjs$/;

function requireCondition(condition, code) {
  if (!condition) {
    throw new Error(code);
  }
}

function exactKeys(value, keys) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join("\n") === [...keys].sort().join("\n")
  );
}

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

export async function loadAwsProviderRuntime({ buildReceipt, projectRoot }) {
  const receipt = buildReceipt?.evidenceProviderRuntime;
  requireCondition(
    exactKeys(receipt, [
      "bundledPackages",
      "bytes",
      "exactGitInputs",
      "externalImports",
      "path",
      "sha256"
    ]) &&
      RUNTIME_PATH.test(receipt.path) &&
      HEX_64.test(receipt.sha256) &&
      receipt.path === `dist/aws/evidence-provider-${receipt.sha256}.mjs` &&
      Number.isSafeInteger(receipt.bytes) &&
      receipt.bytes > 0 &&
      receipt.bytes <= 5 * 1024 * 1024,
    "AWS_PROVIDER_RUNTIME_RECEIPT"
  );
  const resolvedRoot = path.resolve(projectRoot);
  const resolved = path.resolve(resolvedRoot, receipt.path);
  const relative = path.relative(resolvedRoot, resolved);
  requireCondition(
    relative === receipt.path.split("/").join(path.sep) &&
      relative !== ".." &&
      !relative.startsWith(`..${path.sep}`) &&
      !path.isAbsolute(relative),
    "AWS_PROVIDER_RUNTIME_PATH"
  );
  assertSafeProjectPath({
    rootDir: resolvedRoot,
    filePath: resolved,
    code: "AWS_PROVIDER_RUNTIME_PATH"
  });
  const stat = fs.lstatSync(resolved);
  requireCondition(
    stat.isFile() && !stat.isSymbolicLink() && stat.size === receipt.bytes,
    "AWS_PROVIDER_RUNTIME_FILE"
  );
  const bytes = fs.readFileSync(resolved);
  requireCondition(
    bytes.length === receipt.bytes && sha256(bytes) === receipt.sha256,
    "AWS_PROVIDER_RUNTIME_DIGEST"
  );
  const moduleUrl = `data:text/javascript;base64,${bytes.toString("base64")}`;
  const providerModule = await import(moduleUrl);
  requireCondition(
    Object.keys(providerModule).join("\n") === "createAwsProviderClients" &&
      typeof providerModule.createAwsProviderClients === "function",
    "AWS_PROVIDER_RUNTIME_EXPORTS"
  );
  return Object.freeze({
    createAwsProviderClients: providerModule.createAwsProviderClients,
    runtimeSha256: receipt.sha256
  });
}

export const __test = Object.freeze({ exactKeys, RUNTIME_PATH, sha256 });
