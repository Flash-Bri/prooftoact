import assert from "node:assert/strict";
import test from "node:test";

import {
  INTEGRATED_LIVE_DRILL_PROCESS_BOUNDARY_SCHEMA,
  verifyIntegratedLiveDrillProcessBoundaries
} from "../scripts/verify-integrated-live-drill-process-boundaries.js";

test("provider worker and finalizer import graphs preserve process boundaries", () => {
  const receipt = verifyIntegratedLiveDrillProcessBoundaries();
  assert.equal(
    receipt.schemaVersion,
    INTEGRATED_LIVE_DRILL_PROCESS_BOUNDARY_SCHEMA
  );
  assert.equal(receipt.status, "PASS");
  assert.deepEqual(receipt.finalizer.externalPackages, []);
  assert.deepEqual(receipt.worker.externalPackages, ["pg"]);
  assert.equal(
    receipt.supervisor.path,
    "scripts/gate1-integrated-live-drill-provider-supervisor.js"
  );
  assert.equal(receipt.supervisor.legacyRecoveryEntryPointImported, false);
  assert.equal(receipt.supervisor.managedMcpClientConstructed, false);
  assert.equal(receipt.supervisor.providerWorkerEnvironmentRequired, true);
  assert.equal(receipt.supervisor.providerFinalizerEnvironmentRequired, true);
  assert.equal(
    receipt.supervisor.directImports.includes("./gate1-recovery-broker.js"),
    false
  );
  assert.equal(
    receipt.supervisor.directImports.includes(
      "../src/cloud/managed-mcp-client.js"
    ),
    false
  );
  for (const forbidden of [
    "infra/aws/",
    "src/cloud/aws-gate2-template.js",
    "src/cloud/database-runtime.js",
    "src/cloud/integrated-live-drill-provider-recovery.js",
    "src/cloud/integrated-live-drill-provider-worker.js",
    "src/cloud/managed-mcp-client.js",
    "src/cloud/recovery-broker.js"
  ]) {
    assert.equal(
      receipt.finalizer.modules.some((entry) => entry.includes(forbidden)),
      false,
      forbidden
    );
  }
  for (const graph of [receipt.finalizer, receipt.worker]) {
    for (const forbidden of [
      "node:child_process",
      "node:dns",
      "node:http",
      "node:https",
      "node:net",
      "node:tls"
    ]) {
      assert.equal(graph.builtins.includes(forbidden), false, forbidden);
    }
  }
  assert.equal(
    receipt.finalizer.modules.includes(
      "src/cloud/integrated-live-drill-provider-evidence.js"
    ),
    true
  );
  for (const required of [
    "src/cloud/integrated-live-drill-provider-orchestration.js",
    "src/cloud/integrated-live-drill-provider-recovery.js",
    "src/cloud/managed-mcp-client.js",
    "src/cloud/recovery-broker.js"
  ]) {
    assert.equal(receipt.worker.modules.includes(required), true, required);
  }
});
