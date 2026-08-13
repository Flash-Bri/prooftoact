import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

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
