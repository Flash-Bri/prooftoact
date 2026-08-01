import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import { AuthorityStore } from "../src/cloud/authority-store.js";
import { authorizeSyntheticProposal } from "./lib/synthetic-authority-proposal.js";
import { createSyntheticEvidenceSigner } from "./lib/synthetic-evidence.js";

const CHILD_PATH = fileURLToPath(
  new URL("./ambiguous-commit-child.js", import.meta.url)
);
const SYNTHETIC_SIGNER = createSyntheticEvidenceSigner();

function requireDatabaseUrl() {
  const value = process.env.DATABASE_URL;
  if (!value) {
    throw new Error("DATABASE_URL is required");
  }
  return value;
}

function positiveInteger(value, fallback, name) {
  if (value === undefined) {
    return fallback;
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new TypeError(`${name} must be a positive integer`);
  }
  return parsed;
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function completeReservedSnapshot(snapshot) {
  return (
    snapshot.receipts.length === 1 &&
    snapshot.receipts[0].outcome === "resource_reserved" &&
    snapshot.outbox.length === 1 &&
    snapshot.effects.length === 0 &&
    snapshot.resource.current_fence === "1"
  );
}

function emptyAuthoritySnapshot(snapshot) {
  return (
    snapshot.receipts.length === 0 &&
    snapshot.outbox.length === 0 &&
    snapshot.effects.length === 0 &&
    snapshot.resource.current_fence === "0"
  );
}

function isoFromNow(offsetMs) {
  return new Date(Date.now() + offsetMs).toISOString();
}

function requestFor({ tenantId, runId, incidentId, resourceId, evidenceId }) {
  return {
    tenantId,
    runId,
    incidentId,
    resourceId,
    evidenceId,
    operationId: randomUUID(),
    agentId: "synthetic-ambiguity-agent",
    agency: "rescue",
    intentNonce: randomUUID(),
    effectKey: randomUUID(),
    leaseMs: 300_000,
    payload: {
      scenario: "synthetic-highwater",
      action: "dispatch_rescue_unit",
      destination: "synthetic-zone-ambiguity"
    }
  };
}

async function prepareFixture(store, label) {
  const tenantId = randomUUID();
  const runId = randomUUID();
  const incidentId = randomUUID();
  const evidenceId = randomUUID();
  const resourceId = label;
  await SYNTHETIC_SIGNER.register(store, tenantId);
  const appended = await SYNTHETIC_SIGNER.append(store, {
    tenantId,
    evidenceId,
    incidentId,
    agencyScope: "rescue",
    claimKey: "rescue_unit_status",
    claimValue: "available",
    observedAt: isoFromNow(-60_000),
    validFrom: isoFromNow(-120_000),
    validUntil: isoFromNow(30 * 60_000),
    conflictStatus: "none",
    assertion: "Synthetic ambiguity-boundary evidence.",
    embedding: [0.73, 0.19, 0.08]
  });
  assert(appended.outcome === "evidence_verified", "evidence was not verified");
  await store.prepareResource({ tenantId, runId, resourceId });
  const rawRequest = requestFor({
    tenantId,
    runId,
    incidentId,
    resourceId,
    evidenceId
  });
  const authorization = await authorizeSyntheticProposal(store, rawRequest);
  return {
    request: {
      ...rawRequest,
      dviAuthorization: authorization.dviAuthorization
    },
    tenantId,
    resourceId
  };
}

function runKilledChild({ mode, request, connectionString, timeoutMs = 20_000 }) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CHILD_PATH], {
      env: {
        ...process.env,
        DATABASE_URL: connectionString,
        TIDEPROOF_AMBIGUITY_MODE: mode,
        TIDEPROOF_REQUEST_JSON: JSON.stringify(request)
      },
      stdio: ["ignore", "pipe", "pipe", "pipe"]
    });
    let markerText = "";
    let stderr = "";
    child.stdio[3].setEncoding("utf8");
    child.stdio[3].on("data", (chunk) => {
      markerText += chunk;
    });
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });

    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`${mode} child timed out`));
    }, timeoutMs);
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once("exit", (code, signal) => {
      clearTimeout(timer);
      let marker;
      try {
        marker = JSON.parse(markerText.trim());
      } catch {
        reject(
          new Error(
            `${mode} child produced no valid boundary marker; code=${code}; signal=${signal}; stderr=${stderr.trim()}`
          )
        );
        return;
      }
      resolve({
        code,
        signal,
        marker,
        stderr: stderr.trim()
      });
    });
  });
}

async function reconcileBoundedly(store, request, attempts = 20) {
  const trace = [];
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    const observedAt = new Date().toISOString();
    const result = await store.reconcileRequest(request);
    trace.push({
      attempt,
      observedAt,
      status: result.status,
      reason: result.reason ?? null
    });
    if (result.status === "COMMITTED") {
      return { result, trace };
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  return {
    result: await store.reconcileRequest(request),
    trace
  };
}

async function runBoundary(store, connectionString, proofLabel, mode, index) {
  const fixture = await prepareFixture(
    store,
    `${proofLabel}-${mode}-${String(index).padStart(3, "0")}`
  );
  const child = await runKilledChild({
    mode,
    request: fixture.request,
    connectionString
  });
  assert(child.signal === "SIGKILL", `${mode} child was not killed`);
  assert(child.code === null, `${mode} child returned an exit code`);
  assert(child.stderr === "", `${mode} child emitted stderr`);
  assert(
    child.marker.operationId === fixture.request.operationId,
    `${mode} marker operation mismatch`
  );
  assert(
    child.marker.event ===
      (mode === "before_commit"
        ? "dml_staged_commit_not_sent"
        : mode === "commit_dispatched"
          ? "commit_bytes_flushed_ack_unread"
          : "commit_acknowledged_response_not_sent"),
    `${mode} marker did not prove the intended boundary`
  );

  const reconciliation = await reconcileBoundedly(
    store,
    fixture.request,
    mode === "before_commit" ? 3 : 20
  );
  const snapshot = await store.snapshot({
    tenantId: fixture.tenantId,
    resourceId: fixture.resourceId
  });

  if (mode === "before_commit") {
    assert(
      reconciliation.result.status === "UNKNOWN_DO_NOT_ACT",
      "before-COMMIT death unexpectedly produced a terminal receipt"
    );
    assert(
      emptyAuthoritySnapshot(snapshot),
      "before-COMMIT death left partial authority state"
    );
    const retry = await store.spendAuthority(fixture.request);
    assert(
      retry.outcome === "resource_reserved",
      "exact request did not commit after proven pre-COMMIT abort"
    );
    const afterRetry = await store.snapshot({
      tenantId: fixture.tenantId,
      resourceId: fixture.resourceId
    });
    assert(
      completeReservedSnapshot(afterRetry),
      "safe exact retry did not produce one complete transaction"
    );
    return {
      mode,
      childPid: child.marker.pid,
      childExitSignal: child.signal,
      boundaryMarker: child.marker.event,
      reconciliationStatus: reconciliation.result.status,
      reconciliationReason: reconciliation.result.reason ?? null,
      reconciliationTrace: reconciliation.trace,
      preRetryReceiptCount: snapshot.receipts.length,
      preRetryOutboxCount: snapshot.outbox.length,
      preRetryEffectCount: snapshot.effects.length,
      preRetryResourceFence: snapshot.resource.current_fence,
      exactRetryOutcome: retry.outcome,
      finalReceiptCount: afterRetry.receipts.length,
      finalOutboxCount: afterRetry.outbox.length,
      finalEffectCount: afterRetry.effects.length,
      finalResourceFence: afterRetry.resource.current_fence
    };
  } else if (reconciliation.result.status === "COMMITTED") {
    assert(
      completeReservedSnapshot(snapshot),
      "committed response loss did not reconcile to one complete transaction"
    );
  } else {
    assert(
      mode === "commit_dispatched",
      "acknowledged commit was not recovered"
    );
    assert(
      emptyAuthoritySnapshot(snapshot),
      "unresolved ambiguity exposed partial state"
    );
  }

  return {
    mode,
    childPid: child.marker.pid,
    childExitSignal: child.signal,
    boundaryMarker: child.marker.event,
    reconciliationStatus: reconciliation.result.status,
    reconciliationReason: reconciliation.result.reason ?? null,
    reconciliationTrace: reconciliation.trace,
    receiptCount: snapshot.receipts.length,
    outboxCount: snapshot.outbox.length,
    effectCount: snapshot.effects.length,
    resourceFence: snapshot.resource.current_fence
  };
}

async function main() {
  const runs = positiveInteger(process.env.AMBIGUITY_RUNS, 3, "AMBIGUITY_RUNS");
  const connectionString = requireDatabaseUrl();
  const proofLabel = `ambiguity-${randomUUID()}`;
  const store = new AuthorityStore({
    connectionString,
    databaseName: "tideproof",
    maxConnections: 4
  });
  try {
    await store.migrate();
    const beforeCommit = [];
    const commitDispatched = [];
    const afterCommitBeforeResponse = [];
    for (let index = 1; index <= runs; index += 1) {
      beforeCommit.push(
        await runBoundary(
          store,
          connectionString,
          proofLabel,
          "before_commit",
          index
        )
      );
      commitDispatched.push(
        await runBoundary(
          store,
          connectionString,
          proofLabel,
          "commit_dispatched",
          index
        )
      );
      afterCommitBeforeResponse.push(
        await runBoundary(
          store,
          connectionString,
          proofLabel,
          "after_commit_before_response",
          index
        )
      );
    }
    assert(
      commitDispatched.every(({ reconciliationStatus }) =>
        ["COMMITTED", "UNKNOWN_DO_NOT_ACT"].includes(reconciliationStatus)
      ),
      "a COMMIT-dispatched run produced an invalid reconciliation state"
    );
    assert(
      afterCommitBeforeResponse.every(
        ({ reconciliationStatus }) => reconciliationStatus === "COMMITTED"
      ),
      "an acknowledged commit was not recovered after response loss"
    );

    console.log(
      JSON.stringify(
        {
          gate: "commit-ambiguity",
          passed: true,
          proofLabel,
          database: "tideproof",
          runsPerBoundary: runs,
          beforeCommit,
          commitDispatched,
          afterCommitBeforeResponse,
          invariantViolations: 0,
          blindRetries: 0,
          claimBoundary:
            "Pre-COMMIT process death is retried only after a strong read proves zero authority state. COMMIT-dispatched process death is never blindly retried. A separate deterministic boundary proves recovery after COMMIT acknowledgement but before the application response. COMMIT dispatch observation alone does not prove that CockroachDB received every dispatched COMMIT."
        },
        null,
        2
      )
    );
  } finally {
    await store.close();
  }
}

main().catch((error) => {
  console.error(
    JSON.stringify({
      gate: "commit-ambiguity",
      passed: false,
      name: error.name,
      code: error.code,
      message: error.message
    })
  );
  process.exitCode = 1;
});
