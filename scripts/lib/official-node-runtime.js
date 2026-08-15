import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {
  OFFICIAL_NODE_RUNTIME,
  OFFICIAL_NODE_RUNTIME_DISTRIBUTION
} from "../../src/cloud/official-node-runtime-contract.js";
const MAX_NODE_BYTES = 160 * 1024 * 1024;

function requireCondition(condition, code) {
  if (!condition) throw new Error(code);
}

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function readNodeRuntime({
  architecture = process.arch,
  filePath = process.execPath,
  platform = process.platform
} = {}, officialRuntimes = OFFICIAL_NODE_RUNTIME) {
  const code = "OFFICIAL_NODE_RUNTIME_REJECTED";
  const expected = officialRuntimes[`${platform}-${architecture}`];
  requireCondition(
    expected !== undefined &&
      typeof filePath === "string" &&
      path.isAbsolute(filePath) &&
      path.resolve(filePath) === filePath &&
      fs.realpathSync(filePath) === filePath,
    code
  );
  let descriptor;
  try {
    descriptor = fs.openSync(
      filePath,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW
    );
    const before = fs.fstatSync(descriptor);
    requireCondition(
      before.isFile() &&
        !before.isSymbolicLink() &&
        before.nlink === 1 &&
        before.size > 0 &&
        before.size <= MAX_NODE_BYTES,
      code
    );
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor);
    const digest = sha256(bytes);
    requireCondition(
      before.dev === after.dev &&
        before.ino === after.ino &&
        before.mode === after.mode &&
        before.size === after.size &&
        before.uid === after.uid &&
        bytes.length === before.size &&
        digest === expected.sha256,
      code
    );
    return Object.freeze({
      architecture,
      bytes,
      distribution: OFFICIAL_NODE_RUNTIME_DISTRIBUTION,
      platform,
      sha256: digest,
      version: expected.version
    });
  } catch (cause) {
    if (cause?.message === code) throw cause;
    throw new Error(code, { cause });
  } finally {
    if (Number.isSafeInteger(descriptor)) fs.closeSync(descriptor);
  }
}

export function readOfficialNodeRuntime(options = {}) {
  return readNodeRuntime(options, OFFICIAL_NODE_RUNTIME);
}

export const __test = Object.freeze({
  MAX_NODE_BYTES,
  OFFICIAL_NODE_RUNTIME,
  OFFICIAL_NODE_RUNTIME_DISTRIBUTION,
  readNodeRuntime
});
