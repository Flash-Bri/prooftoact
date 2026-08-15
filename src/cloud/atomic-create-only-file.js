import { randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const PUBLICATION_SETTLE_ATTEMPTS = 8;
const PUBLICATION_ABSENT_CAUSE = Symbol("exact-publication-absent");
const PUBLICATION_SETTLE_CAUSE = Symbol("exact-publication-settle");

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function readAll(descriptor, length, code) {
  const bytes = Buffer.alloc(length);
  let offset = 0;
  while (offset < length) {
    const count = fs.readSync(
      descriptor,
      bytes,
      offset,
      length - offset,
      offset
    );
    requireCondition(count > 0, code);
    offset += count;
  }
  return bytes;
}

function writeAll(descriptor, bytes, code) {
  let offset = 0;
  while (offset < bytes.length) {
    const count = fs.writeSync(
      descriptor,
      bytes,
      offset,
      bytes.length - offset,
      offset
    );
    requireCondition(count > 0, code);
    offset += count;
  }
}

function syncDirectory(rootPath, code) {
  let descriptor;
  let primaryCause;
  try {
    descriptor = fs.openSync(
      rootPath,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW |
        (fs.constants.O_DIRECTORY ?? 0)
    );
    requireCondition(fs.fstatSync(descriptor).isDirectory(), code);
    fs.fsyncSync(descriptor);
  } catch (cause) {
    primaryCause = cause;
  } finally {
    if (Number.isSafeInteger(descriptor)) {
      try { fs.closeSync(descriptor); } catch (cause) { primaryCause ??= cause; }
    }
  }
  if (primaryCause?.message === code) throw primaryCause;
  if (primaryCause) reject(code, primaryCause);
}

function unlinkTemporaryIfPresent(temporary) {
  try {
    fs.unlinkSync(temporary);
  } catch (cause) {
    if (cause?.code !== "ENOENT") throw cause;
  }
}

function hasPublishedTemporaryLink({ filePath, identity, rootPath, uid }) {
  const prefix = `.${path.basename(filePath)}.publish-`;
  for (const name of fs.readdirSync(rootPath)) {
    if (!name.startsWith(prefix) ||
      !/^[0-9a-f]{32}$/u.test(name.slice(prefix.length))) continue;
    let candidate;
    try {
      candidate = fs.lstatSync(path.join(rootPath, name));
    } catch (cause) {
      if (cause?.code === "ENOENT") continue;
      throw cause;
    }
    if (
      candidate.isFile() && !candidate.isSymbolicLink() &&
      candidate.uid === uid && candidate.nlink === 2 &&
      candidate.dev === identity.dev && candidate.ino === identity.ino
    ) return true;
  }
  return false;
}

function removePublishedTemporaryLinks({ filePath, rootPath, uid }) {
  let final;
  try {
    final = fs.lstatSync(filePath);
  } catch (cause) {
    if (cause?.code === "ENOENT") return;
    throw cause;
  }
  if (!final.isFile() || final.isSymbolicLink()) return;
  const prefix = `.${path.basename(filePath)}.publish-`;
  for (const name of fs.readdirSync(rootPath)) {
    if (!name.startsWith(prefix) ||
      !/^[0-9a-f]{32}$/u.test(name.slice(prefix.length))) continue;
    const temporary = path.join(rootPath, name);
    let candidate;
    try { candidate = fs.lstatSync(temporary); } catch (cause) {
      if (cause?.code === "ENOENT") continue;
      throw cause;
    }
    if (
      candidate.isFile() && !candidate.isSymbolicLink() &&
      candidate.uid === uid && candidate.nlink === 2 &&
      candidate.dev === final.dev && candidate.ino === final.ino
    ) unlinkTemporaryIfPresent(temporary);
  }
}

export function readExactOwnedFile({
  bytes,
  code,
  filePath,
  maximumBytes = bytes.length,
  mode,
  rootPath,
  uid
}) {
  requireCondition(
    Buffer.isBuffer(bytes) && bytes.length > 0 &&
      path.dirname(filePath) === rootPath,
    code
  );
  let descriptor;
  let primaryCause;
  let result;
  try {
    try {
      descriptor = fs.openSync(
        filePath,
        fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW
      );
    } catch (cause) {
      if (cause?.code === "ENOENT") {
        throw new Error(code, { cause: PUBLICATION_ABSENT_CAUSE });
      }
      throw cause;
    }
    const before = fs.fstatSync(descriptor);
    requireCondition(
      before.isFile() && (before.nlink === 1 || before.nlink === 2) &&
        before.uid === uid && (before.mode & 0o777) === mode &&
        before.size === bytes.length && before.size <= maximumBytes,
      code
    );
    const observed = readAll(descriptor, before.size, code);
    const after = fs.fstatSync(descriptor);
    const named = fs.lstatSync(filePath);
    requireCondition(
      observed.equals(bytes) && before.dev === after.dev &&
        before.ino === after.ino && before.mode === after.mode &&
        before.uid === after.uid && before.size === after.size &&
        (after.nlink === 1 || after.nlink === 2) &&
        named.isFile() && !named.isSymbolicLink() &&
        (named.nlink === 1 || named.nlink === 2) &&
        named.dev === after.dev && named.ino === after.ino &&
        named.mode === after.mode && named.uid === after.uid &&
        named.size === after.size,
      code
    );
    if (before.nlink === 2) {
      let exactPublicationPending = after.nlink === 1 && named.nlink === 1;
      if (!exactPublicationPending &&
        after.nlink === 2 && named.nlink === 2) {
        exactPublicationPending = hasPublishedTemporaryLink({
          filePath,
          identity: after,
          rootPath,
          uid
        });
      }
      if (!exactPublicationPending && after.nlink === 2) {
        const settled = fs.fstatSync(descriptor);
        const settledNamed = fs.lstatSync(filePath);
        exactPublicationPending = settled.nlink === 1 &&
          settledNamed.nlink === 1 && settled.dev === after.dev &&
          settled.ino === after.ino && settled.mode === after.mode &&
          settled.uid === after.uid && settled.size === after.size &&
          settledNamed.isFile() && !settledNamed.isSymbolicLink() &&
          settledNamed.dev === settled.dev &&
          settledNamed.ino === settled.ino &&
          settledNamed.mode === settled.mode &&
          settledNamed.uid === settled.uid &&
          settledNamed.size === settled.size;
      }
      if (exactPublicationPending) {
        throw new Error(code, { cause: PUBLICATION_SETTLE_CAUSE });
      }
    }
    requireCondition(
      before.nlink === 1 && after.nlink === 1 && named.nlink === 1,
      code
    );
    result = Object.freeze({ bytes: observed, stat: after });
  } catch (cause) {
    primaryCause = cause;
  } finally {
    if (Number.isSafeInteger(descriptor)) {
      try { fs.closeSync(descriptor); } catch (cause) { primaryCause ??= cause; }
    }
  }
  if (primaryCause?.message === code) throw primaryCause;
  if (primaryCause) reject(code, primaryCause);
  return result;
}

function readPublishedFileOrNull(options) {
  let lastCause;
  for (let attempt = 0; attempt < PUBLICATION_SETTLE_ATTEMPTS; attempt += 1) {
    try {
      options.assertRoot();
      removePublishedTemporaryLinks(options);
      return readExactOwnedFile(options);
    } catch (cause) {
      if (cause?.cause === PUBLICATION_ABSENT_CAUSE) return null;
      if (cause?.cause !== PUBLICATION_SETTLE_CAUSE) throw cause;
      lastCause = cause;
    }
  }
  throw lastCause;
}

export function publishOrReadExactOwnedFile({
  assertRoot = () => {},
  bytes,
  code,
  fault = () => {},
  filePath,
  maximumBytes = bytes.length,
  mode = 0o600,
  rootPath,
  uid = typeof process.getuid === "function" ? process.getuid() : 0
}) {
  requireCondition(
    Buffer.isBuffer(bytes) && bytes.length > 0 &&
      bytes.length <= maximumBytes && path.dirname(filePath) === rootPath,
    code
  );
  requireCondition(
    typeof assertRoot === "function" && typeof fault === "function",
    code
  );
  assertRoot();
  try {
    const existing = readPublishedFileOrNull({
      assertRoot,
      bytes,
      code,
      filePath,
      maximumBytes,
      mode,
      rootPath,
      uid
    });
    if (existing !== null) {
      assertRoot();
      syncDirectory(rootPath, code);
      return Object.freeze({ ...existing, created: false });
    }
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  }
  const temporary = path.join(
    rootPath,
    `.${path.basename(filePath)}.publish-${randomBytes(16).toString("hex")}`
  );
  let descriptor;
  let openedIdentity;
  let published = false;
  let primaryCause;
  try {
    descriptor = fs.openSync(
      temporary,
      fs.constants.O_RDWR | fs.constants.O_CREAT |
        fs.constants.O_EXCL | fs.constants.O_NOFOLLOW,
      mode
    );
    fault("after-open");
    const created = fs.fstatSync(descriptor);
    openedIdentity = Object.freeze({ dev: created.dev, ino: created.ino });
    requireCondition(
      created.isFile() && created.nlink === 1 && created.uid === uid &&
        created.size === 0,
      code
    );
    writeAll(descriptor, bytes, code);
    fault("after-write");
    fs.fchmodSync(descriptor, mode);
    fault("after-mode");
    fs.fsyncSync(descriptor);
    fault("after-file-fsync");
    const settled = fs.fstatSync(descriptor);
    const namedTemporary = fs.lstatSync(temporary);
    requireCondition(
      settled.isFile() && settled.nlink === 1 && settled.uid === uid &&
        (settled.mode & 0o777) === mode && settled.size === bytes.length &&
        readAll(descriptor, bytes.length, code).equals(bytes) &&
        namedTemporary.isFile() && !namedTemporary.isSymbolicLink() &&
        namedTemporary.dev === settled.dev &&
        namedTemporary.ino === settled.ino && namedTemporary.nlink === 1 &&
        namedTemporary.uid === uid && namedTemporary.mode === settled.mode &&
        namedTemporary.size === settled.size,
      code
    );
    fault("after-readback");
    assertRoot();
    fs.linkSync(temporary, filePath);
    published = true;
    fault("after-link");
    const namedFinal = fs.lstatSync(filePath);
    const linkedTemporary = fs.lstatSync(temporary);
    requireCondition(
      namedFinal.isFile() && !namedFinal.isSymbolicLink() &&
        namedFinal.dev === settled.dev && namedFinal.ino === settled.ino &&
        namedFinal.nlink === 2 && linkedTemporary.dev === settled.dev &&
        linkedTemporary.ino === settled.ino && linkedTemporary.nlink === 2,
      code
    );
    unlinkTemporaryIfPresent(temporary);
    fault("after-temp-unlink");
  } catch (cause) {
    primaryCause = cause;
  } finally {
    if (Number.isSafeInteger(descriptor)) {
      try { fs.closeSync(descriptor); } catch (cause) { primaryCause ??= cause; }
    }
    try {
      if (fs.existsSync(temporary)) {
        const temporaryStat = fs.lstatSync(temporary);
        const finalStat = fs.existsSync(filePath) ? fs.lstatSync(filePath) : null;
        if (
          openedIdentity !== undefined &&
          temporaryStat.isFile() && !temporaryStat.isSymbolicLink() &&
          temporaryStat.dev === openedIdentity.dev &&
          temporaryStat.ino === openedIdentity.ino &&
          temporaryStat.uid === uid &&
          (temporaryStat.nlink === 1 ||
            temporaryStat.nlink === 2 && finalStat?.dev === temporaryStat.dev &&
              finalStat?.ino === temporaryStat.ino)
        ) unlinkTemporaryIfPresent(temporary);
      }
    } catch (cause) {
      primaryCause ??= cause;
    }
  }
  if (published || fs.existsSync(filePath)) {
    try {
      assertRoot();
      removePublishedTemporaryLinks({ filePath, rootPath, uid });
      const observed = readExactOwnedFile({
        bytes,
        code,
        filePath,
        maximumBytes,
        mode,
        rootPath,
        uid
      });
      assertRoot();
      syncDirectory(rootPath, code);
      fault("after-directory-fsync");
      return Object.freeze({ ...observed, created: published });
    } catch (cause) {
      primaryCause ??= cause;
    }
  }
  if (primaryCause?.message === code) throw primaryCause;
  reject(code, primaryCause);
}
