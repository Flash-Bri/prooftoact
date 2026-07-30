import assert from "node:assert/strict";
import test from "node:test";
import { runScenario } from "../src/scenario.js";

test("the deterministic scenario satisfies every declared local invariant", () => {
  const scenario = runScenario();
  assert.ok(Object.keys(scenario.invariants).length >= 8);
  assert.ok(Object.values(scenario.invariants).every(Boolean));
  assert.ok(scenario.timeline.length >= 12);
  assert.ok(
    scenario.timeline.some(({ step }) => step === "out-of-scope")
  );
  assert.ok(
    scenario.timeline.some(
      ({ step }) => step === "checkpoint-termination"
    )
  );
  assert.match(scenario.disclosure, /Synthetic scenario/);
  assert.match(
    scenario.proofStates.gateOne.label,
    /CockroachDB Cloud/
  );
  assert.match(
    scenario.proofStates.gateTwo.label,
    /live AWS evidence pending/
  );
});
