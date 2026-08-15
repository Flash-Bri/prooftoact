import assert from "node:assert/strict";
import test from "node:test";

import {
  __test as stressTest,
  parseIntegratedLiveDrillStressTap,
  validateIntegratedLiveDrillStressReceipt
} from "../scripts/run-integrated-live-drill-stress.js";

function tap(target = stressTest.TARGET) {
  return [
    "TAP version 13",
    `# Subtest: ${target}`,
    `ok 1 - ${target}`,
    "1..1",
    "# tests 1",
    "# suites 0",
    "# pass 1",
    "# fail 0",
    "# cancelled 0",
    "# skipped 0",
    "# todo 0",
    "# duration_ms 1.000000",
    ""
  ].join("\n");
}

function receipt() {
  const body = {
    schemaVersion: stressTest.SCHEMA,
    status: "PASS",
    sourceCommit: "1".repeat(40),
    treeDigest: "2".repeat(40),
    testPath: stressTest.TEST_PATH,
    target: stressTest.TARGET,
    iterationCount: 2,
    observedIterationCount: 2,
    observedTargetPassCount: 2,
    iterations: [
      { index: 1, tapSha256: "a".repeat(64) },
      { index: 2, tapSha256: "b".repeat(64) }
    ],
    claimBoundary:
      "This count-bound fixture proves only two named local regression executions and deliberately makes no provider, deployment, cross-host, hostile-host, or release claim."
  };
  return {
    ...body,
    countBindingSha256: stressTest.countBindingFor(body)
  };
}

test("stress TAP parser accepts exactly one named pass", () => {
  assert.deepEqual(parseIntegratedLiveDrillStressTap(tap()), {
    fail: 0,
    pass: 1,
    skipped: 0,
    tests: 1
  });
  assert.throws(
    () => parseIntegratedLiveDrillStressTap(tap("a different test")),
    /INTEGRATED_LIVE_DRILL_STRESS_TAP_REJECTED/u
  );
});

test("stress receipt binds the claimed count to every iteration digest", () => {
  const value = receipt();
  assert.equal(validateIntegratedLiveDrillStressReceipt(value), value);
  for (const mutate of [
    (candidate) => { candidate.observedIterationCount = 1; },
    (candidate) => { candidate.observedTargetPassCount = 1; },
    (candidate) => { candidate.iterations.pop(); },
    (candidate) => { candidate.iterations[0].tapSha256 = "c".repeat(64); }
  ]) {
    const changed = structuredClone(value);
    mutate(changed);
    assert.throws(
      () => validateIntegratedLiveDrillStressReceipt(changed),
      /INTEGRATED_LIVE_DRILL_STRESS_RECEIPT_REJECTED/u
    );
  }
});
