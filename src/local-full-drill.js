import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { canonicalJson } from "./cloud/canonical-json.js";
import { runScenario } from "./scenario.js";

export const LOCAL_FULL_DRILL_SCHEMA =
  "tideproof.highwater-drill-local-batch.v1";
export const LOCAL_FULL_DRILL_VERIFICATION_SCHEMA =
  "tideproof.highwater-drill-local-batch-verification.v1";
export const LOCAL_FULL_DRILL_RUN_COUNT = 100;
export const LOCAL_FULL_DRILL_CLAIM_BOUNDARY =
  "Local synthetic specification only. This receipt proves the offline half of the approved 100+1 target: 100 deterministic in-memory scenario executions against the hash-bound source set, 1,100 invariant evaluations, and zero declared invariant violations. It does not prove or substitute for the one exact-release provider-backed integrated drill, CockroachDB DVI execution, serializable provider concurrency, AWS Lambda overlap, Managed MCP recovery, a deployed artifact, production safety, or final release readiness.";

const LOCAL_RUN_SCHEMA = "tideproof.highwater-drill-local-run.v1";
const FIXED_TIME = "2026-08-01T12:00:00.000Z";
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const MAX_RECEIPT_BYTES = 1024 * 1024;

export const LOCAL_FULL_DRILL_SOURCE_PATHS = Object.freeze([
  "infra/aws/lambda/demo.js",
  "package-lock.json",
  "package.json",
  "scripts/run-local-full-drills.js",
  "scripts/verify-local-full-drill-receipt.js",
  "src/cloud/canonical-json.js",
  "src/cloud/public-demo.js",
  "src/local-full-drill.js",
  "src/protocol.js",
  "src/scenario.js"
]);

const EXPECTED_INVARIANTS = Object.freeze([
  "authorityNotTransferred",
  "changedOperationRejected",
  "exactOperationReplay",
  "exactlyOneLocalWinner",
  "expiredEvidenceExcluded",
  "invalidProvenanceExcluded",
  "outOfScopeEvidenceExcluded",
  "outageFailsClosed",
  "recoveredCapabilitiesAbsent",
  "unresolvedConflictDenied",
  "unresolvedConflictExcludedFromRanking"
]);

const EXPECTED_TIMELINE_STEPS = Object.freeze([
  "fresh-evidence",
  "expired-evidence",
  "invalid-provenance",
  "out-of-scope",
  "conflict-preserved",
  "policy-before-vector",
  "conflict-fails-closed",
  "one-winner-race",
  "checkpoint-termination",
  "successor-recovery",
  "exact-operation-replay",
  "changed-operation-rejected",
  "memory-outage"
]);

function fail(code) {
  throw new Error(code);
}

function sameJson(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function exactKeys(value, expected, code) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    !sameJson(Object.keys(value).sort(), [...expected].sort())
  ) {
    fail(code);
  }
}

function assertCanonicalJsonValue(value, ancestors = new Set()) {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value) || Object.is(value, -0)) {
      fail("LOCAL_FULL_DRILL_CANONICAL_JSON_REJECTED");
    }
    return;
  }
  if (typeof value !== "object" || ancestors.has(value)) {
    fail("LOCAL_FULL_DRILL_CANONICAL_JSON_REJECTED");
  }

  const prototype = Object.getPrototypeOf(value);
  if (
    !Array.isArray(value) &&
    prototype !== Object.prototype &&
    prototype !== null
  ) {
    fail("LOCAL_FULL_DRILL_CANONICAL_JSON_REJECTED");
  }
  ancestors.add(value);
  if (Array.isArray(value)) {
    for (const nested of value) {
      assertCanonicalJsonValue(nested, ancestors);
    }
  } else {
    for (const [key, nested] of Object.entries(value)) {
      if (key.length === 0) {
        fail("LOCAL_FULL_DRILL_CANONICAL_JSON_REJECTED");
      }
      assertCanonicalJsonValue(nested, ancestors);
    }
  }
  ancestors.delete(value);
}

function sha256Bytes(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function canonicalDigest(domain, value) {
  assertCanonicalJsonValue(value);
  return crypto
    .createHash("sha256")
    .update(`${domain}\0`, "utf8")
    .update(canonicalJson(value), "utf8")
    .digest("hex");
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const nested of Object.values(value)) {
      deepFreeze(nested);
    }
  }
  return value;
}

function normalizedSourceBindings(sourceBindings) {
  if (
    !Array.isArray(sourceBindings) ||
    sourceBindings.length !== LOCAL_FULL_DRILL_SOURCE_PATHS.length
  ) {
    fail("LOCAL_FULL_DRILL_SOURCE_BINDING_REJECTED");
  }
  const normalized = sourceBindings.map((binding) => {
    exactKeys(
      binding,
      ["path", "sha256"],
      "LOCAL_FULL_DRILL_SOURCE_BINDING_REJECTED"
    );
    if (
      typeof binding.path !== "string" ||
      !LOCAL_FULL_DRILL_SOURCE_PATHS.includes(binding.path) ||
      !SHA256_PATTERN.test(binding.sha256)
    ) {
      fail("LOCAL_FULL_DRILL_SOURCE_BINDING_REJECTED");
    }
    return { path: binding.path, sha256: binding.sha256 };
  });
  normalized.sort(({ path: left }, { path: right }) =>
    left < right ? -1 : left > right ? 1 : 0
  );
  if (
    !sameJson(
      normalized.map(({ path: sourcePath }) => sourcePath),
      LOCAL_FULL_DRILL_SOURCE_PATHS
    )
  ) {
    fail("LOCAL_FULL_DRILL_SOURCE_BINDING_REJECTED");
  }
  return normalized;
}

function readBoundedRegularFile(rootDir, relativePath) {
  const resolvedRoot = path.resolve(rootDir);
  const resolved = path.resolve(resolvedRoot, relativePath);
  const fromRoot = path.relative(resolvedRoot, resolved);
  if (
    fromRoot === "" ||
    fromRoot === ".." ||
    fromRoot.startsWith(`..${path.sep}`)
  ) {
    fail("LOCAL_FULL_DRILL_SOURCE_FILE_REJECTED");
  }
  let current = resolvedRoot;
  let stat;
  for (const segment of relativePath.split("/")) {
    current = path.join(current, segment);
    stat = fs.lstatSync(current);
    if (stat.isSymbolicLink()) {
      fail("LOCAL_FULL_DRILL_SOURCE_FILE_REJECTED");
    }
  }
  if (!stat?.isFile() || stat.size <= 0 || stat.size > 2 * 1024 * 1024) {
    fail("LOCAL_FULL_DRILL_SOURCE_FILE_REJECTED");
  }
  return fs.readFileSync(resolved);
}

export function localFullDrillSourceBindings(rootDir) {
  if (typeof rootDir !== "string" || rootDir.length === 0) {
    fail("LOCAL_FULL_DRILL_SOURCE_ROOT_REJECTED");
  }
  return deepFreeze(
    LOCAL_FULL_DRILL_SOURCE_PATHS.map((sourcePath) => ({
      path: sourcePath,
      sha256: sha256Bytes(readBoundedRegularFile(rootDir, sourcePath))
    }))
  );
}

function validateScenario(scenario) {
  assertCanonicalJsonValue(scenario);
  exactKeys(
    scenario,
    [
      "disclosure",
      "fixedTime",
      "incidentId",
      "invariants",
      "proofStates",
      "timeline",
      "title"
    ],
    "LOCAL_FULL_DRILL_SCENARIO_REJECTED"
  );
  const invariantNames = Object.keys(scenario.invariants ?? {}).sort();
  const timelineSteps = Array.isArray(scenario.timeline)
    ? scenario.timeline.map(({ step }) => step)
    : null;
  if (
    scenario.title !==
      "ProofToAct — Admissibility Memory for High-Stakes Agents" ||
    scenario.disclosure !==
      "Synthetic scenario; not operational emergency software." ||
    scenario.fixedTime !== FIXED_TIME ||
    scenario.incidentId !== "incident-highwater-001" ||
    !sameJson(invariantNames, EXPECTED_INVARIANTS) ||
    !sameJson(timelineSteps, EXPECTED_TIMELINE_STEPS) ||
    scenario.proofStates?.local?.label !== "LOCAL DETERMINISTIC REPLAY" ||
    scenario.proofStates?.local?.scope !== "Synthetic in-memory specification" ||
    scenario.proofStates?.local?.limitation !== "No live cloud claim" ||
    scenario.proofStates?.gateTwo?.badge !== "GATE TWO · LOCAL" ||
    scenario.proofStates?.gateTwo?.sourceCommit !== "UNBOUND LOCAL" ||
    scenario.proofStates?.gateTwo?.hostReceipt !== null ||
    !scenario.proofStates?.gateTwo?.label?.includes("live AWS evidence pending")
  ) {
    fail("LOCAL_FULL_DRILL_SCENARIO_REJECTED");
  }
  const invariantViolations = invariantNames.filter(
    (name) => scenario.invariants[name] !== true
  );
  if (invariantViolations.length > 0) {
    fail("LOCAL_FULL_DRILL_INVARIANT_FAILURE");
  }
  return {
    invariantNames,
    timelineSteps,
    scenarioSha256: canonicalDigest(
      "tideproof-highwater-local-scenario-v1",
      scenario
    )
  };
}

function buildUnsignedReceipt({ sourceBindings, runScenarioFn }) {
  if (typeof runScenarioFn !== "function") {
    fail("LOCAL_FULL_DRILL_RUNNER_REJECTED");
  }
  const sourceFiles = normalizedSourceBindings(sourceBindings);
  const sourceDigestSha256 = canonicalDigest(
    "tideproof-highwater-local-source-set-v1",
    sourceFiles
  );
  const batchDefinitionSha256 = canonicalDigest(
    "tideproof-highwater-local-batch-definition-v1",
    {
      schemaVersion: LOCAL_FULL_DRILL_SCHEMA,
      expectedRunCount: LOCAL_FULL_DRILL_RUN_COUNT,
      fixedTime: FIXED_TIME,
      sourceDigestSha256
    }
  );

  const runs = [];
  let deterministicScenarioSha256;
  for (let index = 0; index < LOCAL_FULL_DRILL_RUN_COUNT; index += 1) {
    const runNumber = index + 1;
    const scenario = runScenarioFn();
    const validated = validateScenario(scenario);
    if (
      deterministicScenarioSha256 !== undefined &&
      deterministicScenarioSha256 !== validated.scenarioSha256
    ) {
      fail("LOCAL_FULL_DRILL_NONDETERMINISTIC");
    }
    deterministicScenarioSha256 ??= validated.scenarioSha256;
    const runBindingSha256 = canonicalDigest(
      "tideproof-highwater-local-run-binding-v1",
      {
        schemaVersion: LOCAL_RUN_SCHEMA,
        batchDefinitionSha256,
        runNumber
      }
    );
    const runSha256 = canonicalDigest(
      "tideproof-highwater-local-run-result-v1",
      {
        schemaVersion: LOCAL_RUN_SCHEMA,
        runBindingSha256,
        scenario
      }
    );
    runs.push({
      runNumber,
      runBindingSha256,
      scenarioSha256: validated.scenarioSha256,
      runSha256,
      invariantCount: validated.invariantNames.length,
      invariantViolationCount: 0,
      timelineStepCount: validated.timelineSteps.length
    });
  }

  const uniqueRunDigestCount = new Set(
    runs.map(({ runSha256 }) => runSha256)
  ).size;
  if (uniqueRunDigestCount !== LOCAL_FULL_DRILL_RUN_COUNT) {
    fail("LOCAL_FULL_DRILL_RUN_IDENTITY_COLLISION");
  }

  return {
    schemaVersion: LOCAL_FULL_DRILL_SCHEMA,
    status: "PASS",
    evidenceClass: "LOCAL_SYNTHETIC_SPECIFICATION",
    claimBoundary: LOCAL_FULL_DRILL_CLAIM_BOUNDARY,
    source: {
      files: sourceFiles,
      digestSha256: sourceDigestSha256,
      runtimePathBinding:
        "The local harness and the candidate AWS Demo entry both import src/scenario.js; source hashes do not prove the built or deployed artifact."
    },
    execution: {
      expectedRunCount: LOCAL_FULL_DRILL_RUN_COUNT,
      actualRunCount: runs.length,
      orderedConsecutive: true,
      uniqueRunDigestCount,
      fixedTime: FIXED_TIME,
      deterministic: true,
      concurrencyModel: "SEQUENTIAL_IN_MEMORY_SPECIFICATION",
      providerBacked: false,
      cockroachDbExecuted: false,
      awsLambdaConcurrencyProven: false,
      managedMcpExecuted: false,
      deployedArtifactProven: false
    },
    scenario: {
      scenarioSha256: deterministicScenarioSha256,
      invariantCount: EXPECTED_INVARIANTS.length,
      timelineStepCount: EXPECTED_TIMELINE_STEPS.length,
      timelineSteps: [...EXPECTED_TIMELINE_STEPS]
    },
    invariants: {
      names: [...EXPECTED_INVARIANTS],
      perRunCount: EXPECTED_INVARIANTS.length,
      totalEvaluations:
        EXPECTED_INVARIANTS.length * LOCAL_FULL_DRILL_RUN_COUNT,
      violationCount: 0
    },
    runs
  };
}

export function buildLocalFullDrillReceipt({
  sourceBindings,
  runScenarioFn = runScenario
} = {}) {
  const unsigned = buildUnsignedReceipt({ sourceBindings, runScenarioFn });
  return deepFreeze({
    ...unsigned,
    batchDigestSha256: canonicalDigest(
      "tideproof-highwater-local-batch-result-v1",
      unsigned
    )
  });
}

function validateReceiptEnvelope(receipt) {
  assertCanonicalJsonValue(receipt);
  exactKeys(
    receipt,
    [
      "batchDigestSha256",
      "claimBoundary",
      "evidenceClass",
      "execution",
      "invariants",
      "runs",
      "scenario",
      "schemaVersion",
      "source",
      "status"
    ],
    "LOCAL_FULL_DRILL_RECEIPT_REJECTED"
  );
  exactKeys(
    receipt.source,
    ["digestSha256", "files", "runtimePathBinding"],
    "LOCAL_FULL_DRILL_RECEIPT_REJECTED"
  );
  exactKeys(
    receipt.execution,
    [
      "actualRunCount",
      "awsLambdaConcurrencyProven",
      "cockroachDbExecuted",
      "concurrencyModel",
      "deployedArtifactProven",
      "deterministic",
      "expectedRunCount",
      "fixedTime",
      "managedMcpExecuted",
      "orderedConsecutive",
      "providerBacked",
      "uniqueRunDigestCount"
    ],
    "LOCAL_FULL_DRILL_RECEIPT_REJECTED"
  );
  exactKeys(
    receipt.scenario,
    ["invariantCount", "scenarioSha256", "timelineStepCount", "timelineSteps"],
    "LOCAL_FULL_DRILL_RECEIPT_REJECTED"
  );
  exactKeys(
    receipt.invariants,
    ["names", "perRunCount", "totalEvaluations", "violationCount"],
    "LOCAL_FULL_DRILL_RECEIPT_REJECTED"
  );
  if (
    receipt.schemaVersion !== LOCAL_FULL_DRILL_SCHEMA ||
    receipt.status !== "PASS" ||
    receipt.evidenceClass !== "LOCAL_SYNTHETIC_SPECIFICATION" ||
    receipt.claimBoundary !== LOCAL_FULL_DRILL_CLAIM_BOUNDARY ||
    !SHA256_PATTERN.test(receipt.batchDigestSha256) ||
    !Array.isArray(receipt.runs) ||
    receipt.runs.length !== LOCAL_FULL_DRILL_RUN_COUNT
  ) {
    fail("LOCAL_FULL_DRILL_RECEIPT_REJECTED");
  }
  for (const [index, run] of receipt.runs.entries()) {
    exactKeys(
      run,
      [
        "invariantCount",
        "invariantViolationCount",
        "runBindingSha256",
        "runNumber",
        "runSha256",
        "scenarioSha256",
        "timelineStepCount"
      ],
      "LOCAL_FULL_DRILL_RECEIPT_REJECTED"
    );
    if (
      run.runNumber !== index + 1 ||
      !SHA256_PATTERN.test(run.runBindingSha256) ||
      !SHA256_PATTERN.test(run.scenarioSha256) ||
      !SHA256_PATTERN.test(run.runSha256) ||
      run.invariantViolationCount !== 0
    ) {
      fail("LOCAL_FULL_DRILL_RECEIPT_REJECTED");
    }
  }
}

export function serializeLocalFullDrillReceipt(receipt) {
  assertCanonicalJsonValue(receipt);
  return `${JSON.stringify(receipt, null, 2)}\n`;
}

export function validateLocalFullDrillReceipt(
  receipt,
  { sourceBindings, runScenarioFn = runScenario } = {}
) {
  validateReceiptEnvelope(receipt);
  const expected = buildLocalFullDrillReceipt({
    sourceBindings,
    runScenarioFn
  });
  if (
    serializeLocalFullDrillReceipt(receipt) !==
    serializeLocalFullDrillReceipt(expected)
  ) {
    fail("LOCAL_FULL_DRILL_RECEIPT_REJECTED");
  }
  return deepFreeze({
    schemaVersion: LOCAL_FULL_DRILL_VERIFICATION_SCHEMA,
    status: "PASS",
    receiptSchemaVersion: receipt.schemaVersion,
    receiptSha256: sha256Bytes(serializeLocalFullDrillReceipt(receipt)),
    receiptBatchDigestSha256: receipt.batchDigestSha256,
    sourceDigestSha256: receipt.source.digestSha256,
    runCount: receipt.runs.length,
    uniqueRunDigestCount: receipt.execution.uniqueRunDigestCount,
    invariantViolationCount: receipt.invariants.violationCount,
    providerBacked: false,
    liveClaimSatisfied: false,
    claimBoundary: LOCAL_FULL_DRILL_CLAIM_BOUNDARY
  });
}

export function validateLocalFullDrillReceiptBytes(
  bytes,
  options = {}
) {
  const text = Buffer.isBuffer(bytes) ? bytes.toString("utf8") : bytes;
  if (
    typeof text !== "string" ||
    Buffer.byteLength(text, "utf8") <= 0 ||
    Buffer.byteLength(text, "utf8") > MAX_RECEIPT_BYTES
  ) {
    fail("LOCAL_FULL_DRILL_RECEIPT_BYTES_REJECTED");
  }
  let receipt;
  try {
    receipt = JSON.parse(text);
  } catch {
    fail("LOCAL_FULL_DRILL_RECEIPT_BYTES_REJECTED");
  }
  const verification = validateLocalFullDrillReceipt(receipt, options);
  if (serializeLocalFullDrillReceipt(receipt) !== text) {
    fail("LOCAL_FULL_DRILL_RECEIPT_BYTES_REJECTED");
  }
  return verification;
}
