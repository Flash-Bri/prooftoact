import assert from "node:assert/strict";
import test from "node:test";
import { runScenario } from "../src/scenario.js";

test("the deterministic scenario satisfies every declared local invariant", () => {
  const scenario = runScenario();
  assert.ok(Object.keys(scenario.invariants).length >= 7);
  assert.ok(Object.values(scenario.invariants).every(Boolean));
  assert.ok(scenario.timeline.length >= 9);
  assert.match(scenario.disclosure, /Synthetic scenario/);
});
