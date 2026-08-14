import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { publishOrReadExactOwnedFile, readExactOwnedFile } from
  "../src/cloud/atomic-create-only-file.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const CHILD = path.join(
  ROOT,
  "test/fixtures/provider-execution-attempt-child.js"
);

function privateDirectory(parent, name) {
  const value = path.join(parent, name);
  fs.mkdirSync(value, { mode: 0o700 });
  fs.chmodSync(value, 0o700);
  return fs.realpathSync(value);
}

function runChild(environment) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CHILD], {
      cwd: ROOT,
      env: Object.freeze({
        LANG: "C",
        PATH: process.env.PATH,
        ...environment
      }),
      stdio: ["ignore", "pipe", "pipe"]
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.setEncoding("utf8").on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stderr, stdout }));
  });
}

test("real worker contenders have one create-only execution-attempt winner", async (t) => {
  const temporaryRoot = fs.mkdtempSync(
    path.join(fs.realpathSync(os.tmpdir()), "prooftoact-execution-fence-")
  );
  fs.chmodSync(temporaryRoot, 0o700);
  t.after(() => fs.rmSync(temporaryRoot, { force: true, recursive: true }));
  const evidenceRoot = privateDirectory(temporaryRoot, "evidence");
  const forbiddenRoot = privateDirectory(temporaryRoot, "forbidden");
  const attemptPath = path.join(evidenceRoot, "execution-attempt.json");
  const environment = Object.freeze({
    EXECUTION_ATTEMPT_PATH: attemptPath,
    EXECUTION_EVIDENCE_ROOT: evidenceRoot,
    EXECUTION_FORBIDDEN_ROOT: forbiddenRoot
  });
  const results = await Promise.all([
    runChild(environment),
    runChild(environment),
    runChild(environment),
    runChild(environment)
  ]);
  assert.deepEqual(
    results.map((result) => result.code),
    [0, 0, 0, 0],
    results.map((result) => result.stderr).join("\n")
  );
  const created = results.map((result) => JSON.parse(result.stdout).created);
  assert.equal(created.filter(Boolean).length, 1);
  assert.equal(created.filter((value) => !value).length, 3);
  assert.deepEqual(JSON.parse(fs.readFileSync(attemptPath, "utf8")), {
    authorizationId: "11111111-1111-4111-8111-111111111111",
    marker: "provider-execution-attempt-fence-v1"
  });
  assert.equal(fs.statSync(attemptPath).mode & 0o777, 0o600);
  assert.equal(fs.statSync(attemptPath).nlink, 1);
});

test("published temporary-link cleanup tolerates an exact concurrent unlink", (t) => {
  const temporaryRoot = fs.mkdtempSync(
    path.join(fs.realpathSync(os.tmpdir()), "prooftoact-publish-cleanup-")
  );
  fs.chmodSync(temporaryRoot, 0o700);
  t.after(() => fs.rmSync(temporaryRoot, { force: true, recursive: true }));
  const filePath = path.join(temporaryRoot, "execution-attempt.json");
  const temporaryPath = path.join(
    temporaryRoot,
    `.execution-attempt.json.publish-${"a".repeat(32)}`
  );
  const bytes = Buffer.from('{"marker":"provider-execution-attempt-fence-v1"}\n');
  fs.writeFileSync(filePath, bytes, { mode: 0o600 });
  fs.chmodSync(filePath, 0o600);
  fs.linkSync(filePath, temporaryPath);
  assert.equal(fs.statSync(filePath).nlink, 2);

  const unlinkSync = fs.unlinkSync;
  let simulated = false;
  fs.unlinkSync = (target) => {
    if (!simulated && target === temporaryPath) {
      simulated = true;
      unlinkSync(target);
      throw Object.assign(new Error("simulated concurrent unlink"), {
        code: "ENOENT"
      });
    }
    return unlinkSync(target);
  };
  let result;
  try {
    result = publishOrReadExactOwnedFile({
      bytes,
      code: "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_WRITE_REJECTED",
      filePath,
      rootPath: temporaryRoot
    });
  } finally {
    fs.unlinkSync = unlinkSync;
  }

  assert.equal(simulated, true);
  assert.equal(result.created, false);
  assert.equal(fs.existsSync(temporaryPath), false);
  assert.equal(fs.statSync(filePath).nlink, 1);
  assert.deepEqual(fs.readFileSync(filePath), bytes);
});

test("exact read settles only a winner linked after cleanup observed absence", (t) => {
  const temporaryRoot = fs.mkdtempSync(
    path.join(fs.realpathSync(os.tmpdir()), "prooftoact-publish-settle-")
  );
  fs.chmodSync(temporaryRoot, 0o700);
  t.after(() => fs.rmSync(temporaryRoot, { force: true, recursive: true }));
  const filePath = path.join(temporaryRoot, "execution-attempt.json");
  const temporaryPath = path.join(
    temporaryRoot,
    `.execution-attempt.json.publish-${"c".repeat(32)}`
  );
  const bytes = Buffer.from('{"marker":"provider-execution-attempt-fence-v1"}\n');
  fs.writeFileSync(temporaryPath, bytes, { mode: 0o600 });
  fs.chmodSync(temporaryPath, 0o600);
  fs.linkSync(temporaryPath, filePath);

  const lstatSync = fs.lstatSync;
  let absenceSimulated = false;
  let rootAssertions = 0;
  fs.lstatSync = (target) => {
    if (!absenceSimulated && target === filePath) {
      absenceSimulated = true;
      throw Object.assign(new Error("simulated pre-publication absence"), {
        code: "ENOENT"
      });
    }
    return lstatSync(target);
  };
  let result;
  try {
    result = publishOrReadExactOwnedFile({
      assertRoot() {
        rootAssertions += 1;
      },
      bytes,
      code: "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_WRITE_REJECTED",
      filePath,
      rootPath: temporaryRoot
    });
  } finally {
    fs.lstatSync = lstatSync;
  }

  assert.equal(absenceSimulated, true);
  assert.equal(rootAssertions, 4);
  assert.equal(result.created, false);
  assert.equal(fs.existsSync(temporaryPath), false);
  assert.equal(fs.statSync(filePath).nlink, 1);
});

test("exact read settles a two-link descriptor after peer cleanup", (t) => {
  const temporaryRoot = fs.mkdtempSync(
    path.join(fs.realpathSync(os.tmpdir()), "prooftoact-publish-mixed-link-")
  );
  fs.chmodSync(temporaryRoot, 0o700);
  t.after(() => fs.rmSync(temporaryRoot, { force: true, recursive: true }));
  const filePath = path.join(temporaryRoot, "execution-attempt.json");
  const temporaryPath = path.join(
    temporaryRoot,
    `.execution-attempt.json.publish-${"e".repeat(32)}`
  );
  const bytes = Buffer.from('{"marker":"provider-execution-attempt-fence-v1"}\n');
  fs.writeFileSync(temporaryPath, bytes, { mode: 0o600 });
  fs.chmodSync(temporaryPath, 0o600);
  fs.linkSync(temporaryPath, filePath);

  const lstatSync = fs.lstatSync;
  let fileStats = 0;
  let peerCleanupSimulated = false;
  fs.lstatSync = (target) => {
    if (target === filePath) {
      fileStats += 1;
      if (fileStats === 1) {
        throw Object.assign(new Error("simulated pre-publication absence"), {
          code: "ENOENT"
        });
      }
      if (!peerCleanupSimulated) {
        peerCleanupSimulated = true;
        fs.unlinkSync(temporaryPath);
      }
    }
    return lstatSync(target);
  };
  let result;
  try {
    result = publishOrReadExactOwnedFile({
      bytes,
      code: "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_WRITE_REJECTED",
      filePath,
      rootPath: temporaryRoot
    });
  } finally {
    fs.lstatSync = lstatSync;
  }

  assert.equal(peerCleanupSimulated, true);
  assert.equal(result.created, false);
  assert.equal(fs.existsSync(temporaryPath), false);
  assert.equal(fs.statSync(filePath).nlink, 1);
});

test("published temporary-link cleanup rejects every non-ENOENT failure", (t) => {
  const temporaryRoot = fs.mkdtempSync(
    path.join(fs.realpathSync(os.tmpdir()), "prooftoact-publish-failure-")
  );
  fs.chmodSync(temporaryRoot, 0o700);
  t.after(() => fs.rmSync(temporaryRoot, { force: true, recursive: true }));
  const filePath = path.join(temporaryRoot, "execution-attempt.json");
  const temporaryPath = path.join(
    temporaryRoot,
    `.execution-attempt.json.publish-${"b".repeat(32)}`
  );
  const bytes = Buffer.from('{"marker":"provider-execution-attempt-fence-v1"}\n');
  fs.writeFileSync(filePath, bytes, { mode: 0o600 });
  fs.chmodSync(filePath, 0o600);
  fs.linkSync(filePath, temporaryPath);

  const unlinkSync = fs.unlinkSync;
  fs.unlinkSync = (target) => {
    if (target === temporaryPath) {
      throw Object.assign(new Error("simulated cleanup I/O failure"), {
        code: "EIO"
      });
    }
    return unlinkSync(target);
  };
  try {
    assert.throws(
      () => publishOrReadExactOwnedFile({
        bytes,
        code: "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_WRITE_REJECTED",
        filePath,
        rootPath: temporaryRoot
      }),
      /INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_WRITE_REJECTED/u
    );
  } finally {
    fs.unlinkSync = unlinkSync;
  }

  assert.equal(fs.existsSync(temporaryPath), true);
  const recovered = publishOrReadExactOwnedFile({
    bytes,
    code: "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_WRITE_REJECTED",
    filePath,
    rootPath: temporaryRoot
  });
  assert.equal(recovered.created, false);
  assert.equal(fs.existsSync(temporaryPath), false);
  assert.equal(fs.statSync(filePath).nlink, 1);
});

test("exact published-file read does not retry transient I/O failure", (t) => {
  const temporaryRoot = fs.mkdtempSync(
    path.join(fs.realpathSync(os.tmpdir()), "prooftoact-publish-read-")
  );
  fs.chmodSync(temporaryRoot, 0o700);
  t.after(() => fs.rmSync(temporaryRoot, { force: true, recursive: true }));
  const filePath = path.join(temporaryRoot, "execution-attempt.json");
  const bytes = Buffer.from('{"marker":"provider-execution-attempt-fence-v1"}\n');
  fs.writeFileSync(filePath, bytes, { mode: 0o600 });
  fs.chmodSync(filePath, 0o600);

  const readSync = fs.readSync;
  let reads = 0;
  fs.readSync = (...args) => {
    reads += 1;
    throw Object.assign(new Error("simulated exact-read I/O failure"), {
      code: "EIO"
    });
  };
  try {
    assert.throws(
      () => publishOrReadExactOwnedFile({
        bytes,
        code: "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_WRITE_REJECTED",
        filePath,
        rootPath: temporaryRoot
      }),
      /INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_WRITE_REJECTED/u
    );
  } finally {
    fs.readSync = readSync;
  }

  assert.equal(reads, 1);
  assert.equal(publishOrReadExactOwnedFile({
    bytes,
    code: "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_WRITE_REJECTED",
    filePath,
    rootPath: temporaryRoot
  }).created, false);
});

test("post-open final disappearance is fatal rather than initial absence", (t) => {
  const temporaryRoot = fs.mkdtempSync(
    path.join(fs.realpathSync(os.tmpdir()), "prooftoact-publish-disappear-")
  );
  fs.chmodSync(temporaryRoot, 0o700);
  t.after(() => fs.rmSync(temporaryRoot, { force: true, recursive: true }));
  const filePath = path.join(temporaryRoot, "execution-attempt.json");
  const bytes = Buffer.from('{"marker":"provider-execution-attempt-fence-v1"}\n');
  fs.writeFileSync(filePath, bytes, { mode: 0o600 });
  fs.chmodSync(filePath, 0o600);

  const lstatSync = fs.lstatSync;
  let finalStats = 0;
  fs.lstatSync = (target) => {
    if (target === filePath) {
      finalStats += 1;
      if (finalStats === 2) {
        throw Object.assign(new Error("simulated post-open disappearance"), {
          code: "ENOENT"
        });
      }
    }
    return lstatSync(target);
  };
  try {
    assert.throws(
      () => publishOrReadExactOwnedFile({
        bytes,
        code: "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_WRITE_REJECTED",
        filePath,
        rootPath: temporaryRoot
      }),
      /INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_WRITE_REJECTED/u
    );
  } finally {
    fs.lstatSync = lstatSync;
  }

  assert.equal(finalStats, 2);
  assert.deepEqual(fs.readFileSync(filePath), bytes);
});

test("conflicting two-link file never enters publication settle retry", (t) => {
  const temporaryRoot = fs.mkdtempSync(
    path.join(fs.realpathSync(os.tmpdir()), "prooftoact-publish-conflict-")
  );
  fs.chmodSync(temporaryRoot, 0o700);
  t.after(() => fs.rmSync(temporaryRoot, { force: true, recursive: true }));
  const filePath = path.join(temporaryRoot, "execution-attempt.json");
  const temporaryPath = path.join(
    temporaryRoot,
    `.execution-attempt.json.publish-${"d".repeat(32)}`
  );
  const expected = Buffer.from("expected-publication-bytes\n");
  const conflicting = Buffer.from("conflict-publication-bytes\n");
  assert.equal(conflicting.length, expected.length);
  fs.writeFileSync(temporaryPath, conflicting, { mode: 0o600 });
  fs.chmodSync(temporaryPath, 0o600);
  fs.linkSync(temporaryPath, filePath);

  const lstatSync = fs.lstatSync;
  const readSync = fs.readSync;
  let absenceSimulated = false;
  let reads = 0;
  fs.lstatSync = (target) => {
    if (!absenceSimulated && target === filePath) {
      absenceSimulated = true;
      throw Object.assign(new Error("simulated conflict cleanup absence"), {
        code: "ENOENT"
      });
    }
    return lstatSync(target);
  };
  fs.readSync = (...args) => {
    reads += 1;
    return readSync(...args);
  };
  try {
    assert.throws(
      () => publishOrReadExactOwnedFile({
        bytes: expected,
        code: "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_WRITE_REJECTED",
        filePath,
        rootPath: temporaryRoot
      }),
      /INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_WRITE_REJECTED/u
    );
  } finally {
    fs.lstatSync = lstatSync;
    fs.readSync = readSync;
  }

  assert.equal(absenceSimulated, true);
  assert.equal(reads, 1);
  assert.equal(fs.existsSync(temporaryPath), true);
  assert.deepEqual(fs.readFileSync(filePath), conflicting);
});

test("exact owned-file primitive rejects an empty expected file", (t) => {
  const temporaryRoot = fs.mkdtempSync(
    path.join(fs.realpathSync(os.tmpdir()), "prooftoact-empty-exact-")
  );
  fs.chmodSync(temporaryRoot, 0o700);
  t.after(() => fs.rmSync(temporaryRoot, { force: true, recursive: true }));
  const filePath = path.join(temporaryRoot, "empty.json");
  fs.writeFileSync(filePath, Buffer.alloc(0), { mode: 0o600 });
  fs.chmodSync(filePath, 0o600);
  assert.throws(
    () => readExactOwnedFile({
      bytes: Buffer.alloc(0),
      code: "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_WRITE_REJECTED",
      filePath,
      maximumBytes: 0,
      mode: 0o600,
      rootPath: temporaryRoot,
      uid: process.getuid()
    }),
    /INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_WRITE_REJECTED/u
  );
});

test("exact read rejects a new matching hardlink after one-link open", (t) => {
  const temporaryRoot = fs.mkdtempSync(
    path.join(fs.realpathSync(os.tmpdir()), "prooftoact-publish-new-link-")
  );
  fs.chmodSync(temporaryRoot, 0o700);
  t.after(() => fs.rmSync(temporaryRoot, { force: true, recursive: true }));
  const filePath = path.join(temporaryRoot, "execution-attempt.json");
  const temporaryPath = path.join(
    temporaryRoot,
    `.execution-attempt.json.publish-${"f".repeat(32)}`
  );
  const bytes = Buffer.from('{"marker":"provider-execution-attempt-fence-v1"}\n');
  fs.writeFileSync(filePath, bytes, { mode: 0o600 });
  fs.chmodSync(filePath, 0o600);

  const readSync = fs.readSync;
  let injected = false;
  fs.readSync = (...args) => {
    const count = readSync(...args);
    if (!injected) {
      injected = true;
      fs.linkSync(filePath, temporaryPath);
    }
    return count;
  };
  try {
    assert.throws(
      () => publishOrReadExactOwnedFile({
        bytes,
        code: "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_WRITE_REJECTED",
        filePath,
        rootPath: temporaryRoot
      }),
      /INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_WRITE_REJECTED/u
    );
  } finally {
    fs.readSync = readSync;
  }

  assert.equal(injected, true);
  assert.equal(fs.existsSync(temporaryPath), true);
  assert.equal(fs.statSync(filePath).nlink, 2);
});
