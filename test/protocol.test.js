import assert from "node:assert/strict";
import test from "node:test";
import {
  EvidenceStatus,
  MemoryUnavailableError,
  TideproofMemory
} from "../src/protocol.js";

const NOW = "2026-08-01T12:00:00.000Z";
const INCIDENT = "test-incident";

function record(overrides) {
  return {
    id: "evidence-default",
    incidentId: INCIDENT,
    claimKey: "shelter-capacity",
    claimValue: "18",
    assertion: "Synthetic shelter has capacity for 18.",
    issuer: "test-sensor",
    scopes: ["rescue"],
    observedAt: "2026-08-01T11:50:00.000Z",
    validFrom: "2026-08-01T11:50:00.000Z",
    validUntil: "2026-08-01T12:30:00.000Z",
    signatureValid: true,
    confidence: 0.8,
    embedding: [0.5, 0.5],
    ...overrides
  };
}

test("filters provenance, validity, and scope before vector ranking", () => {
  const memory = new TideproofMemory({ clock: () => NOW });

  memory.ingestEvidence(
    record({
      id: "valid",
      embedding: [0.5, 0.5]
    })
  );
  memory.ingestEvidence(
    record({
      id: "expired-high-similarity",
      claimKey: "expired-claim",
      validFrom: "2026-08-01T09:00:00.000Z",
      validUntil: "2026-08-01T10:00:00.000Z",
      embedding: [1, 0]
    })
  );
  memory.ingestEvidence(
    record({
      id: "invalid-high-similarity",
      claimKey: "invalid-claim",
      signatureValid: false,
      embedding: [1, 0]
    })
  );
  memory.ingestEvidence(
    record({
      id: "out-of-scope-high-similarity",
      claimKey: "private-claim",
      scopes: ["medical"],
      embedding: [1, 0]
    })
  );

  const results = memory.retrieveEvidence({
    incidentId: INCIDENT,
    agency: "rescue",
    queryVector: [1, 0],
    limit: 10
  });

  assert.deepEqual(
    results.map(({ id }) => id),
    ["valid"]
  );
  assert.equal(results[0].actionEligible, true);
});

test("preserves conflict and denies action authorization", () => {
  const memory = new TideproofMemory({ clock: () => NOW });
  const open = memory.ingestEvidence(
    record({
      id: "road-open",
      claimKey: "road-status",
      claimValue: "open",
      assertion: "Synthetic road is open."
    })
  );
  const closed = memory.ingestEvidence(
    record({
      id: "road-closed",
      claimKey: "road-status",
      claimValue: "closed",
      assertion: "Synthetic road is closed."
    })
  );

  const records = memory.listEvidence({ incidentId: INCIDENT });
  assert.equal(
    records.find(({ id }) => id === open.id).status,
    EvidenceStatus.CONFLICTED
  );
  assert.equal(
    records.find(({ id }) => id === closed.id).status,
    EvidenceStatus.CONFLICTED
  );

  assert.deepEqual(
    memory.retrieveEvidence({
      incidentId: INCIDENT,
      agency: "rescue",
      queryVector: [1, 0],
      limit: 10
    }),
    []
  );

  assert.deepEqual(
    memory.evaluateDecision({
      incidentId: INCIDENT,
      agency: "rescue",
      evidenceIds: [open.id]
    }),
    {
      allowed: false,
      reason: "evidence_conflict",
      evidenceId: open.id
    }
  );
});

test("allows exactly one local resource-race winner", async () => {
  const memory = new TideproofMemory({ clock: () => NOW });
  const accepted = memory.ingestEvidence(record({ id: "capacity" }));

  const attempts = await Promise.all(
    ["alpha", "bravo", "charlie"].map(async (agent) =>
      memory.reserveResource({
        operationId: `operation-${agent}`,
        incidentId: INCIDENT,
        resourceId: "rescue-unit-7",
        agentId: `agent-${agent}`,
        agency: "rescue",
        evidenceIds: [accepted.id]
      })
    )
  );

  assert.equal(
    attempts.filter(({ outcome }) => outcome === "resource_reserved").length,
    1
  );
  assert.equal(
    attempts.filter(({ outcome }) => outcome === "resource_held_denied").length,
    2
  );
  assert.equal(
    attempts.find(({ outcome }) => outcome === "resource_reserved").fencingToken,
    1
  );
});

function containsForbiddenCapabilityKey(value) {
  if (!value || typeof value !== "object") {
    return false;
  }
  const forbidden = new Set([
    "effectKey",
    "fencingToken",
    "leases",
    "operationId",
    "receipts"
  ]);
  return Object.entries(value).some(
    ([key, nested]) =>
      forbidden.has(key) || containsForbiddenCapabilityKey(nested)
  );
}

test("successor recovers context without capabilities and replay is digest-bound", () => {
  const memory = new TideproofMemory({ clock: () => NOW });
  const accepted = memory.ingestEvidence(record({ id: "capacity" }));
  const original = memory.reserveResource({
    operationId: "operation-alpha",
    incidentId: INCIDENT,
    resourceId: "rescue-unit-7",
    agentId: "agent-alpha",
    agency: "rescue",
    evidenceIds: [accepted.id]
  });

  memory.checkpointAgent({
    checkpointId: "checkpoint-alpha",
    incidentId: INCIDENT,
    agentId: "agent-alpha",
    lastEvidenceIds: [accepted.id],
    receiptOperationId: "operation-alpha",
    state: { phase: "reserved" }
  });

  const recovery = memory.recoverSuccessor({
    incidentId: INCIDENT,
    failedAgentId: "agent-alpha",
    successorAgentId: "agent-successor"
  });
  assert.equal(recovery.authorityTransferred, false);
  assert.equal(recovery.requiresFreshAuthorization, true);
  assert.equal(recovery.operationalCapabilitiesReturned, false);
  assert.equal(recovery.checkpointSummary.phase, "successor-context-recovery");
  assert.equal(recovery.evidenceSummary.admittedCount, 1);
  assert.equal(
    recovery.receiptReference.receiptSummary.outcome,
    "resource_reserved"
  );
  assert.equal(
    recovery.receiptReference.receiptSummary.durableIntentPresent,
    false
  );
  assert.equal(containsForbiddenCapabilityKey(recovery), false);

  const exactReplay = memory.reserveResource({
    operationId: original.operationId,
    incidentId: INCIDENT,
    resourceId: "rescue-unit-7",
    agentId: "agent-alpha",
    agency: "rescue",
    evidenceIds: [accepted.id]
  });
  assert.equal(exactReplay.outcome, "operation_replay");
  assert.equal(exactReplay.originalReceipt.outcome, "resource_reserved");

  const changedReplay = memory.reserveResource({
    operationId: original.operationId,
    incidentId: INCIDENT,
    resourceId: "rescue-unit-7",
    agentId: "agent-successor",
    agency: "rescue",
    evidenceIds: [accepted.id]
  });
  assert.deepEqual(changedReplay, {
    outcome: "operation_digest_mismatch_denied",
    operationId: original.operationId,
    reason: "operation_parameters_changed"
  });
});

test("successor recovery is bound to the checkpoint's explicit receipt summary", () => {
  const memory = new TideproofMemory({ clock: () => NOW });
  const accepted = memory.ingestEvidence(record({ id: "capacity" }));
  for (const [operationId, resourceId] of [
    ["operation-old", "rescue-unit-old"],
    ["operation-new", "rescue-unit-new"]
  ]) {
    memory.reserveResource({
      operationId,
      incidentId: INCIDENT,
      resourceId,
      agentId: "agent-alpha",
      agency: "rescue",
      evidenceIds: [accepted.id]
    });
  }
  const checkpoint = memory.checkpointAgent({
    checkpointId: "checkpoint-latest",
    incidentId: INCIDENT,
    agentId: "agent-alpha",
    lastEvidenceIds: [accepted.id],
    receiptOperationId: "operation-new",
    state: { phase: "reserved" }
  });
  const recovery = memory.recoverSuccessor({
    incidentId: INCIDENT,
    failedAgentId: "agent-alpha",
    successorAgentId: "agent-successor"
  });
  assert.equal(
    checkpoint.receiptReference.receiptSummary.resourceLabel,
    "rescue-unit-new"
  );
  assert.deepEqual(
    recovery.receiptReference,
    checkpoint.receiptReference
  );
  assert.equal(
    containsForbiddenCapabilityKey(recovery),
    false
  );
});

test("checkpoint receipt digests bind the full durable receipt", () => {
  const checkpoints = ["operation-alpha", "operation-bravo"].map(
    (operationId) => {
      const memory = new TideproofMemory({ clock: () => NOW });
      const accepted = memory.ingestEvidence(record({ id: "capacity" }));
      memory.reserveResource({
        operationId,
        incidentId: INCIDENT,
        resourceId: "rescue-unit-7",
        agentId: "agent-alpha",
        agency: "rescue",
        evidenceIds: [accepted.id]
      });
      return memory.checkpointAgent({
        checkpointId: `checkpoint-${operationId}`,
        incidentId: INCIDENT,
        agentId: "agent-alpha",
        lastEvidenceIds: [accepted.id],
        receiptOperationId: operationId
      });
    }
  );
  assert.deepEqual(
    checkpoints[0].receiptReference.receiptSummary,
    checkpoints[1].receiptReference.receiptSummary
  );
  assert.notEqual(
    checkpoints[0].receiptReference.receiptDigest,
    checkpoints[1].receiptReference.receiptDigest
  );
});

test("checkpointing fails closed for ambiguous receipts and unsafe evidence ids", () => {
  const memory = new TideproofMemory({ clock: () => NOW });
  const accepted = memory.ingestEvidence(record({ id: "capacity" }));
  for (const operationId of ["operation-one", "operation-two"]) {
    memory.reserveResource({
      operationId,
      incidentId: INCIDENT,
      resourceId: `resource-${operationId}`,
      agentId: "agent-alpha",
      agency: "rescue",
      evidenceIds: [accepted.id]
    });
  }
  assert.throws(
    () => memory.checkpointAgent({
      checkpointId: "ambiguous-checkpoint",
      incidentId: INCIDENT,
      agentId: "agent-alpha",
      lastEvidenceIds: [accepted.id]
    }),
    /binding is ambiguous/u
  );
  assert.throws(
    () => memory.checkpointAgent({
      checkpointId: "duplicate-evidence-checkpoint",
      incidentId: INCIDENT,
      agentId: "agent-alpha",
      lastEvidenceIds: [accepted.id, accepted.id],
      receiptOperationId: "operation-one"
    }),
    /must be unique/u
  );
  assert.throws(
    () => memory.checkpointAgent({
      checkpointId: "oversized-evidence-checkpoint",
      incidentId: INCIDENT,
      agentId: "agent-alpha",
      lastEvidenceIds: ["x".repeat(129)],
      receiptOperationId: "operation-one"
    }),
    /exceeds 128 bytes/u
  );
  assert.throws(
    () => memory.checkpointAgent({
      checkpointId: "missing-evidence-checkpoint",
      incidentId: INCIDENT,
      agentId: "agent-alpha",
      lastEvidenceIds: ["missing-evidence"],
      receiptOperationId: "operation-one"
    }),
    /evidence binding mismatch/u
  );
  const otherEvidence = memory.ingestEvidence(record({
    id: "other-capacity",
    claimKey: "different-safe-claim"
  }));
  assert.throws(
    () => memory.checkpointAgent({
      checkpointId: "receipt-evidence-mismatch-checkpoint",
      incidentId: INCIDENT,
      agentId: "agent-alpha",
      lastEvidenceIds: [otherEvidence.id],
      receiptOperationId: "operation-one"
    }),
    /receipt evidence binding mismatch/u
  );
});

test("fails closed when memory is unavailable", () => {
  const memory = new TideproofMemory({ clock: () => NOW });
  const accepted = memory.ingestEvidence(record({ id: "capacity" }));
  memory.setAvailable(false);

  assert.throws(
    () =>
      memory.evaluateDecision({
        incidentId: INCIDENT,
        agency: "rescue",
        evidenceIds: [accepted.id]
      }),
    (error) =>
      error instanceof MemoryUnavailableError &&
      error.code === "MEMORY_UNAVAILABLE_FAIL_CLOSED"
  );
});
