import crypto from "node:crypto";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { canonicalJson } from "../src/cloud/canonical-json.js";
import {
  assertExactGitSourceContext,
  gitEnvironment,
  gitInvariantArguments,
  trustedGitExecutable
} from "./lib/exact-git-source.js";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const SCHEMA = "tideproof.integrated-live-drill-stress-receipt.v1";
const TARGET =
  "concurrent RESUMEs atomically choose stop or globally guarded reconciliation";
const TEST_PATH = "test/integrated-live-drill.test.js";
const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;

function reject(code) {
  throw new Error(code);
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function exactKeys(value, keys) {
  return value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join("\n") === [...keys].sort().join("\n");
}

function summaryCount(output, name) {
  const matches = [...output.matchAll(
    new RegExp(`^# ${name} ([0-9]+)$`, "gmu")
  )];
  requireCondition(
    matches.length === 1 && Number.isSafeInteger(Number(matches[0][1])),
    "INTEGRATED_LIVE_DRILL_STRESS_TAP_REJECTED"
  );
  return Number(matches[0][1]);
}

export function parseIntegratedLiveDrillStressTap(output) {
  requireCondition(
    typeof output === "string" && output.startsWith("TAP version 13\n"),
    "INTEGRATED_LIVE_DRILL_STRESS_TAP_REJECTED"
  );
  const summary = Object.freeze({
    fail: summaryCount(output, "fail"),
    pass: summaryCount(output, "pass"),
    skipped: summaryCount(output, "skipped"),
    tests: summaryCount(output, "tests")
  });
  requireCondition(
    summary.tests === 1 &&
      summary.pass === 1 &&
      summary.fail === 0 &&
      summary.skipped === 0 &&
      output.includes(`# Subtest: ${TARGET}\n`) &&
      output.includes(`ok 1 - ${TARGET}\n`),
    "INTEGRATED_LIVE_DRILL_STRESS_TAP_REJECTED"
  );
  return summary;
}

function countBindingFor(receipt) {
  return sha256(canonicalJson({
    iterationCount: receipt.iterationCount,
    iterations: receipt.iterations,
    observedIterationCount: receipt.observedIterationCount,
    observedTargetPassCount: receipt.observedTargetPassCount,
    sourceCommit: receipt.sourceCommit,
    target: receipt.target,
    testPath: receipt.testPath,
    treeDigest: receipt.treeDigest
  }));
}

export function validateIntegratedLiveDrillStressReceipt(value) {
  requireCondition(
    exactKeys(value, [
      "claimBoundary",
      "countBindingSha256",
      "iterationCount",
      "iterations",
      "observedIterationCount",
      "observedTargetPassCount",
      "schemaVersion",
      "sourceCommit",
      "status",
      "target",
      "testPath",
      "treeDigest"
    ]) &&
      value.schemaVersion === SCHEMA &&
      value.status === "PASS" &&
      HEX_40.test(value.sourceCommit ?? "") &&
      HEX_40.test(value.treeDigest ?? "") &&
      value.target === TARGET &&
      value.testPath === TEST_PATH &&
      Number.isSafeInteger(value.iterationCount) &&
      value.iterationCount >= 1 &&
      value.iterationCount <= 100 &&
      value.observedIterationCount === value.iterationCount &&
      value.observedTargetPassCount === value.iterationCount &&
      Array.isArray(value.iterations) &&
      value.iterations.length === value.iterationCount &&
      value.iterations.every((entry, index) =>
        exactKeys(entry, ["index", "tapSha256"]) &&
          entry.index === index + 1 &&
          HEX_64.test(entry.tapSha256 ?? "")
      ) &&
      typeof value.claimBoundary === "string" &&
      value.claimBoundary.length > 100 &&
      HEX_64.test(value.countBindingSha256 ?? "") &&
      value.countBindingSha256 === countBindingFor(value),
    "INTEGRATED_LIVE_DRILL_STRESS_RECEIPT_REJECTED"
  );
  return Object.freeze(value);
}

function gitText(rootDir, args) {
  const result = spawnSync(
    trustedGitExecutable(),
    [...gitInvariantArguments(), ...args],
    {
      cwd: rootDir,
      encoding: "utf8",
      env: gitEnvironment(process.env)
    }
  );
  requireCondition(
    !result.error && result.status === 0,
    "INTEGRATED_LIVE_DRILL_STRESS_GIT_REJECTED"
  );
  return result.stdout.trim();
}

export function runIntegratedLiveDrillStress({
  iterations = Number(
    process.env.TIDEPROOF_INTEGRATED_LIVE_DRILL_STRESS_RUNS ?? "20"
  ),
  rootDir = ROOT,
  run = spawnSync
} = {}) {
  requireCondition(
    Number.isSafeInteger(iterations) && iterations >= 1 && iterations <= 100,
    "INTEGRATED_LIVE_DRILL_STRESS_COUNT_REJECTED"
  );
  const sourceCommit = gitText(rootDir, ["rev-parse", "HEAD"]);
  const treeDigest = gitText(rootDir, ["rev-parse", "HEAD^{tree}"]);
  assertExactGitSourceContext({ rootDir, sourceCommit });
  requireCondition(
    gitText(rootDir, ["status", "--short"]) === "",
    "INTEGRATED_LIVE_DRILL_STRESS_DIRTY_TREE"
  );
  const childEnvironment = Object.fromEntries(
    Object.entries(process.env).filter(([name]) =>
      !/^(?:DYLD_.*|LD_PRELOAD|NODE_OPTIONS|NODE_PATH)$/u.test(name)
    )
  );
  const records = [];
  for (let index = 1; index <= iterations; index += 1) {
    const result = run(
      process.execPath,
      [
        "--test",
        `--test-name-pattern=^${TARGET}$`,
        TEST_PATH
      ],
      {
        cwd: rootDir,
        encoding: "utf8",
        env: childEnvironment,
        maxBuffer: 16 * 1024 * 1024,
        timeout: 120_000
      }
    );
    requireCondition(
      result && !result.error && result.status === 0 &&
        typeof result.stdout === "string" && result.stderr === "",
      "INTEGRATED_LIVE_DRILL_STRESS_CHILD_REJECTED"
    );
    parseIntegratedLiveDrillStressTap(result.stdout);
    records.push(Object.freeze({
      index,
      tapSha256: sha256(result.stdout)
    }));
  }
  requireCondition(
    gitText(rootDir, ["rev-parse", "HEAD"]) === sourceCommit &&
      gitText(rootDir, ["rev-parse", "HEAD^{tree}"]) === treeDigest &&
      gitText(rootDir, ["status", "--short"]) === "",
    "INTEGRATED_LIVE_DRILL_STRESS_SOURCE_CHANGED"
  );
  const body = {
    schemaVersion: SCHEMA,
    status: "PASS",
    sourceCommit,
    treeDigest,
    testPath: TEST_PATH,
    target: TARGET,
    iterationCount: iterations,
    observedIterationCount: records.length,
    observedTargetPassCount: records.length,
    iterations: records,
    claimBoundary:
      "This count-bound receipt proves only repeated local execution of one named fake-transport concurrency regression against one clean exact commit. It does not prove live provider behavior, cross-host database isolation, deployment, hostile-host safety, or release acceptance."
  };
  return validateIntegratedLiveDrillStressReceipt(Object.freeze({
    ...body,
    countBindingSha256: countBindingFor(body)
  }));
}

async function main() {
  requireCondition(
    process.argv.length === 2,
    "INTEGRATED_LIVE_DRILL_STRESS_ARGUMENT_REJECTED"
  );
  process.stdout.write(
    `${JSON.stringify(runIntegratedLiveDrillStress(), null, 2)}\n`
  );
}

const startedDirectly = process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (startedDirectly) {
  main().catch((error) => {
    const code = /^INTEGRATED_LIVE_DRILL_STRESS_[A-Z0-9_]{1,120}$/u.test(
      String(error?.message ?? "")
    )
      ? error.message
      : "INTEGRATED_LIVE_DRILL_STRESS_UNKNOWN";
    process.stderr.write(`${code}\n`);
    process.exitCode = 1;
  });
}

export const __test = Object.freeze({
  SCHEMA,
  TARGET,
  TEST_PATH,
  countBindingFor,
  sha256
});
