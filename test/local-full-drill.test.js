import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  LOCAL_FULL_DRILL_CLAIM_BOUNDARY,
  LOCAL_FULL_DRILL_RUN_COUNT,
  LOCAL_FULL_DRILL_SCHEMA,
  buildLocalFullDrillReceipt,
  localFullDrillSourceBindings,
  serializeLocalFullDrillReceipt,
  validateLocalFullDrillReceipt,
  validateLocalFullDrillReceiptBytes
} from "../src/local-full-drill.js";
import { runScenario } from "../src/scenario.js";

const ROOT = path.resolve(fileURLToPath(new URL("..", import.meta.url)));

function currentReceipt() {
  return buildLocalFullDrillReceipt({
    sourceBindings: localFullDrillSourceBindings(ROOT)
  });
}

test("the local full-drill harness emits exactly 100 deterministic bounded runs", () => {
  const receipt = currentReceipt();
  const replayed = currentReceipt();

  assert.equal(receipt.schemaVersion, LOCAL_FULL_DRILL_SCHEMA);
  assert.equal(receipt.status, "PASS");
  assert.equal(receipt.claimBoundary, LOCAL_FULL_DRILL_CLAIM_BOUNDARY);
  assert.equal(receipt.execution.expectedRunCount, LOCAL_FULL_DRILL_RUN_COUNT);
  assert.equal(receipt.execution.actualRunCount, LOCAL_FULL_DRILL_RUN_COUNT);
  assert.equal(receipt.execution.uniqueRunDigestCount, LOCAL_FULL_DRILL_RUN_COUNT);
  assert.equal(receipt.execution.providerBacked, false);
  assert.equal(receipt.execution.awsLambdaConcurrencyProven, false);
  assert.equal(receipt.execution.cockroachDbExecuted, false);
  assert.equal(receipt.execution.managedMcpExecuted, false);
  assert.equal(receipt.execution.concurrencyModel, "SEQUENTIAL_IN_MEMORY_SPECIFICATION");
  assert.equal(receipt.invariants.violationCount, 0);
  assert.equal(receipt.runs.length, LOCAL_FULL_DRILL_RUN_COUNT);
  assert.deepEqual(
    receipt.runs.map(({ runNumber }) => runNumber),
    Array.from({ length: LOCAL_FULL_DRILL_RUN_COUNT }, (_, index) => index + 1)
  );
  assert.equal(
    new Set(receipt.runs.map(({ runSha256 }) => runSha256)).size,
    LOCAL_FULL_DRILL_RUN_COUNT
  );
  assert.equal(
    new Set(receipt.runs.map(({ scenarioSha256 }) => scenarioSha256)).size,
    1
  );
  assert.deepEqual(replayed, receipt);
});

test("the validator recomputes through the shared local implementation", () => {
  const sourceBindings = localFullDrillSourceBindings(ROOT);
  const receipt = buildLocalFullDrillReceipt({ sourceBindings });
  const verification = validateLocalFullDrillReceipt(receipt, {
    sourceBindings
  });

  assert.equal(verification.status, "PASS");
  assert.equal(verification.runCount, LOCAL_FULL_DRILL_RUN_COUNT);
  assert.equal(verification.invariantViolationCount, 0);
  assert.equal(verification.receiptBatchDigestSha256, receipt.batchDigestSha256);
  assert.equal(verification.providerBacked, false);
  assert.equal(verification.liveClaimSatisfied, false);
});

test("the harness fails before publishing a run with one false invariant", () => {
  let calls = 0;
  assert.throws(
    () =>
      buildLocalFullDrillReceipt({
        sourceBindings: localFullDrillSourceBindings(ROOT),
        runScenarioFn: () => {
          calls += 1;
          const scenario = structuredClone(runScenario());
          if (calls === 37) {
            scenario.invariants.changedOperationRejected = false;
          }
          return scenario;
        }
      }),
    /LOCAL_FULL_DRILL_INVARIANT_FAILURE/
  );
  assert.equal(calls, 37);
});

test("the harness rejects nondeterministic output even when invariants pass", () => {
  let calls = 0;
  assert.throws(
    () =>
      buildLocalFullDrillReceipt({
        sourceBindings: localFullDrillSourceBindings(ROOT),
        runScenarioFn: () => {
          calls += 1;
          const scenario = structuredClone(runScenario());
          if (calls === 2) {
            scenario.timeline[0].label = "drifted but still passing";
          }
          return scenario;
        }
      }),
    /LOCAL_FULL_DRILL_NONDETERMINISTIC/
  );
  assert.equal(calls, 2);
});

test("the harness rejects weakened invariant and timeline contracts", () => {
  for (const mutate of [
    (scenario) => delete scenario.invariants.outageFailsClosed,
    (scenario) => scenario.timeline.pop(),
    (scenario) => {
      scenario.fixedTime = "2026-08-01T12:00:00.001Z";
    }
  ]) {
    assert.throws(
      () =>
        buildLocalFullDrillReceipt({
          sourceBindings: localFullDrillSourceBindings(ROOT),
          runScenarioFn: () => {
            const scenario = structuredClone(runScenario());
            mutate(scenario);
            return scenario;
          }
        }),
      /LOCAL_FULL_DRILL_SCENARIO_REJECTED/
    );
  }
});

test("the harness rejects values with ambiguous JSON canonicalization", () => {
  assert.throws(
    () =>
      buildLocalFullDrillReceipt({
        sourceBindings: localFullDrillSourceBindings(ROOT),
        runScenarioFn: () => {
          const scenario = structuredClone(runScenario());
          scenario.timeline[0].detail.confidence = Number.NaN;
          return scenario;
        }
      }),
    /LOCAL_FULL_DRILL_CANONICAL_JSON_REJECTED/
  );
});

test("the validator rejects count, ordering, digest, source, and claim-boundary drift", () => {
  const sourceBindings = localFullDrillSourceBindings(ROOT);
  const receipt = buildLocalFullDrillReceipt({ sourceBindings });
  const mutations = [
    (value) => value.runs.pop(),
    (value) => value.runs.reverse(),
    (value) => {
      value.runs[0].runSha256 = "0".repeat(64);
    },
    (value) => {
      value.source.files[0].sha256 = "0".repeat(64);
    },
    (value) => {
      value.execution.providerBacked = true;
    },
    (value) => {
      value.execution.concurrencyModel = "AWS_LAMBDA";
    },
    (value) => {
      value.claimBoundary = "provider-backed claim satisfied";
    },
    (value) => {
      value.batchDigestSha256 = "f".repeat(64);
    }
  ];

  for (const mutate of mutations) {
    const changed = structuredClone(receipt);
    mutate(changed);
    assert.throws(
      () => validateLocalFullDrillReceipt(changed, { sourceBindings }),
      /LOCAL_FULL_DRILL_RECEIPT_REJECTED/
    );
  }
});

test("receipt bytes must use the one exact serializer", () => {
  const sourceBindings = localFullDrillSourceBindings(ROOT);
  const receipt = buildLocalFullDrillReceipt({ sourceBindings });
  const bytes = serializeLocalFullDrillReceipt(receipt);
  assert.equal(
    validateLocalFullDrillReceiptBytes(bytes, { sourceBindings }).status,
    "PASS"
  );
  assert.throws(
    () => validateLocalFullDrillReceiptBytes(` ${bytes}`, { sourceBindings }),
    /LOCAL_FULL_DRILL_RECEIPT_BYTES_REJECTED/
  );
  assert.throws(
    () => validateLocalFullDrillReceiptBytes(`${bytes}\n`, { sourceBindings }),
    /LOCAL_FULL_DRILL_RECEIPT_BYTES_REJECTED/
  );
  const { schemaVersion, status, ...rest } = receipt;
  const reordered = { status, schemaVersion, ...rest };
  assert.throws(
    () =>
      validateLocalFullDrillReceiptBytes(
        serializeLocalFullDrillReceipt(reordered),
        { sourceBindings }
      ),
    /LOCAL_FULL_DRILL_RECEIPT_REJECTED/
  );
  assert.throws(
    () =>
      validateLocalFullDrillReceiptBytes(
        bytes.replace("{\n", "{\n  \"status\": \"PASS\",\n"),
        { sourceBindings }
      ),
    /LOCAL_FULL_DRILL_RECEIPT_(?:BYTES_)?REJECTED/
  );
});

test("source binding loader covers the harness, verifier, scenario, and deployment entry", () => {
  const bindings = localFullDrillSourceBindings(ROOT);
  const paths = bindings.map(({ path: sourcePath }) => sourcePath);
  for (const required of [
    "infra/aws/lambda/demo.js",
    "scripts/run-local-full-drills.js",
    "scripts/verify-local-full-drill-receipt.js",
    "src/cloud/canonical-json.js",
    "src/local-full-drill.js",
    "src/protocol.js",
    "src/scenario.js"
  ]) {
    assert(paths.includes(required), required);
  }
  assert.deepEqual(paths, [...paths].sort());
  assert(bindings.every(({ sha256 }) => /^[0-9a-f]{64}$/.test(sha256)));
});

test("the evidence contract preserves generator and validator trust boundaries", () => {
  const evidenceContract = readFileSync(
    path.join(ROOT, "docs/FULL_DRILL_EVIDENCE.md"),
    "utf8"
  );

  assert.match(
    evidenceContract,
    /`npm run --silent full-drill:local -- --output evidence\/local-full-drill-100-2026-08-04\.json`/u
  );
  assert.match(evidenceContract, /shared local implementation/u);
  assert.match(evidenceContract, /common-mode defects remain possible/u);
  assert.match(evidenceContract, /clean, quiescent, controlled worktree/u);
  assert.match(
    evidenceContract,
    /not a hostile-host or concurrent-filesystem immutability proof/u
  );
  assert.match(evidenceContract, /TOCTOU residual/u);
  assert.doesNotMatch(evidenceContract, /independently reruns all 100/u);
});
