import fs from "node:fs";
import path from "node:path";

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

export function readSystemdCredential({
  credentialsDirectory,
  maximumBytes = 16 * 1024,
  name
}) {
  const code = "INTEGRATED_LIVE_DRILL_SYSTEMD_CREDENTIAL_REJECTED";
  requireCondition(
    typeof credentialsDirectory === "string" &&
      path.isAbsolute(credentialsDirectory) &&
      path.resolve(credentialsDirectory) === credentialsDirectory &&
      typeof name === "string" && /^[a-z][a-z0-9-]{1,79}$/u.test(name) &&
      Number.isSafeInteger(maximumBytes) && maximumBytes > 0 &&
      maximumBytes <= 8 * 1024 * 1024,
    code
  );
  let descriptor;
  try {
    const filePath = path.join(credentialsDirectory, name);
    requireCondition(path.dirname(filePath) === credentialsDirectory, code);
    descriptor = fs.openSync(
      filePath,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW
    );
    const before = fs.fstatSync(descriptor);
    requireCondition(
      before.isFile() && !before.isSymbolicLink() && before.nlink === 1 &&
        before.size > 0 && before.size <= maximumBytes &&
        (before.mode & 0o077) === 0,
      code
    );
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor);
    requireCondition(
      before.dev === after.dev && before.ino === after.ino &&
        before.uid === after.uid && before.gid === after.gid &&
        before.mode === after.mode && before.size === after.size,
      code
    );
    return bytes;
  } catch (cause) {
    if (String(cause?.message ?? "") === code) throw cause;
    reject(code, cause);
  } finally {
    if (Number.isSafeInteger(descriptor)) fs.closeSync(descriptor);
  }
}

export function readSystemdCredentialText(args) {
  const code = "INTEGRATED_LIVE_DRILL_SYSTEMD_CREDENTIAL_REJECTED";
  const value = readSystemdCredential(args).toString("utf8");
  requireCondition(
    value.length > 0 && value.endsWith("\n") &&
      !/[\0\r]/u.test(value) && !value.slice(0, -1).includes("\n"),
    code
  );
  return value.slice(0, -1);
}
