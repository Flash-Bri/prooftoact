import {
  MemoryUnavailableError,
  TideproofMemory
} from "./protocol.js";

const INCIDENT_ID = "incident-highwater-001";
const FIXED_NOW = "2026-08-01T12:00:00.000Z";

function evidence(overrides) {
  return {
    incidentId: INCIDENT_ID,
    issuer: "synthetic-county-sensor",
    scopes: ["rescue"],
    observedAt: "2026-08-01T11:55:00.000Z",
    validFrom: "2026-08-01T11:55:00.000Z",
    validUntil: "2026-08-01T12:25:00.000Z",
    signatureValid: true,
    confidence: 0.9,
    embedding: [0.8, 0.1, 0.1],
    ...overrides
  };
}

export function runScenario() {
  const memory = new TideproofMemory({ clock: () => FIXED_NOW });
  const timeline = [];

  const admitted = memory.ingestEvidence(
    evidence({
      id: "ev-shelter-capacity",
      claimKey: "shelter-river-capacity",
      claimValue: "18",
      assertion: "River Shelter has capacity for 18 synthetic evacuees."
    })
  );
  timeline.push({
    step: "fresh-evidence",
    label: "Fresh, attributable evidence admitted",
    detail: admitted
  });

  const expired = memory.ingestEvidence(
    evidence({
      id: "ev-expired-bridge",
      claimKey: "bridge-delta-status",
      claimValue: "open",
      assertion: "Delta Bridge is open.",
      observedAt: "2026-08-01T09:00:00.000Z",
      validFrom: "2026-08-01T09:00:00.000Z",
      validUntil: "2026-08-01T10:00:00.000Z",
      confidence: 0.99,
      embedding: [1, 0, 0]
    })
  );
  timeline.push({
    step: "expired-evidence",
    label: "Highly similar but expired evidence excluded",
    detail: expired
  });

  const invalid = memory.ingestEvidence(
    evidence({
      id: "ev-invalid-shelter",
      claimKey: "shelter-river-status",
      claimValue: "closed",
      assertion: "River Shelter is closed.",
      issuer: "unverified-radio",
      signatureValid: false,
      confidence: 0.99,
      embedding: [1, 0, 0]
    })
  );
  timeline.push({
    step: "invalid-provenance",
    label: "Invalid provenance quarantined before ranking",
    detail: invalid
  });

  const outOfScope = memory.ingestEvidence(
    evidence({
      id: "ev-medical-private",
      claimKey: "medical-private-status",
      claimValue: "restricted",
      assertion:
        "A synthetic medical status exists outside the rescue scope.",
      issuer: "synthetic-medical-agency",
      scopes: ["medical"],
      confidence: 0.99,
      embedding: [1, 0, 0]
    })
  );
  timeline.push({
    step: "out-of-scope",
    label: "Current but out-of-scope evidence excluded before ranking",
    detail: outOfScope
  });

  const roadOpen = memory.ingestEvidence(
    evidence({
      id: "ev-road-open",
      claimKey: "road-9-status",
      claimValue: "open",
      assertion: "Synthetic Road 9 is open.",
      issuer: "synthetic-transport-agency",
      embedding: [0.6, 0.4, 0]
    })
  );
  const roadClosed = memory.ingestEvidence(
    evidence({
      id: "ev-road-closed",
      claimKey: "road-9-status",
      claimValue: "closed",
      assertion: "Synthetic Road 9 is closed.",
      issuer: "synthetic-field-team",
      embedding: [0.6, 0.4, 0]
    })
  );
  timeline.push({
    step: "conflict-preserved",
    label: "Contradictory current reports remain visible but not actionable",
    detail: [roadOpen.id, roadClosed.id]
  });

  const retrieved = memory.retrieveEvidence({
    incidentId: INCIDENT_ID,
    agency: "rescue",
    queryVector: [1, 0, 0],
    limit: 10
  });
  timeline.push({
    step: "policy-before-vector",
    label: "Admissibility filters run before vector ranking",
    detail: {
      returnedIds: retrieved.map(({ id }) => id),
      excludedIds: [expired.id, invalid.id, outOfScope.id]
    }
  });

  const conflictDecision = memory.evaluateDecision({
    incidentId: INCIDENT_ID,
    agency: "rescue",
    evidenceIds: [roadOpen.id]
  });
  timeline.push({
    step: "conflict-fails-closed",
    label: "Unresolved conflict blocks action",
    detail: conflictDecision
  });

  const contenders = [
    {
      operationId: "op-reserve-alpha",
      agentId: "agent-alpha"
    },
    {
      operationId: "op-reserve-bravo",
      agentId: "agent-bravo"
    }
  ];
  const race = contenders.map((contender) =>
    memory.reserveResource({
      ...contender,
      incidentId: INCIDENT_ID,
      resourceId: "synthetic-rescue-unit-7",
      agency: "rescue",
      evidenceIds: [admitted.id]
    })
  );
  const winner = race.find(({ outcome }) => outcome === "resource_reserved");
  timeline.push({
    step: "one-winner-race",
    label: "One local contender receives the scarce resource",
    detail: race
  });

  const checkpoint = memory.checkpointAgent({
    checkpointId: "checkpoint-before-handoff",
    incidentId: INCIDENT_ID,
    agentId: winner.agentId,
    lastEvidenceIds: [admitted.id],
    state: { phase: "resource-reserved", operationId: winner.operationId }
  });
  timeline.push({
    step: "checkpoint-termination",
    label: "Winning agent checkpoints, then terminates",
    detail: {
      checkpoint,
      termination: {
        agentId: winner.agentId,
        status: "PROCESS_TERMINATED_AFTER_CHECKPOINT"
      }
    }
  });

  const recovery = memory.recoverSuccessor({
    incidentId: INCIDENT_ID,
    failedAgentId: winner.agentId,
    successorAgentId: "agent-successor"
  });
  timeline.push({
    step: "successor-recovery",
    label: "Successor recovers context but not spent authority",
    detail: recovery
  });

  const replay = memory.reserveResource({
    operationId: winner.operationId,
    incidentId: INCIDENT_ID,
    resourceId: "synthetic-rescue-unit-7",
    agentId: "agent-successor",
    agency: "rescue",
    evidenceIds: [admitted.id]
  });
  timeline.push({
    step: "replay-denied",
    label: "Original operation cannot be replayed",
    detail: replay
  });

  memory.setAvailable(false);
  let outage;
  try {
    memory.evaluateDecision({
      incidentId: INCIDENT_ID,
      agency: "rescue",
      evidenceIds: [admitted.id]
    });
  } catch (error) {
    if (!(error instanceof MemoryUnavailableError)) {
      throw error;
    }
    outage = { code: error.code, message: error.message };
  }
  timeline.push({
    step: "memory-outage",
    label: "Memory outage fails closed",
    detail: outage
  });

  return {
    title: "Tideproof — Admissibility Memory for High-Stakes Agents",
    disclosure: "Synthetic scenario; not operational emergency software.",
    fixedTime: FIXED_NOW,
    incidentId: INCIDENT_ID,
    invariants: {
      expiredEvidenceExcluded: !retrieved.some(({ id }) => id === expired.id),
      invalidProvenanceExcluded: !retrieved.some(({ id }) => id === invalid.id),
      outOfScopeEvidenceExcluded:
        !retrieved.some(({ id }) => id === outOfScope.id),
      unresolvedConflictDenied: conflictDecision.allowed === false,
      exactlyOneLocalWinner:
        race.filter(({ outcome }) => outcome === "resource_reserved").length === 1,
      authorityNotTransferred: recovery.authorityTransferred === false,
      replayDenied: replay.outcome === "duplicate_operation_denied",
      outageFailsClosed: outage?.code === "MEMORY_UNAVAILABLE_FAIL_CLOSED"
    },
    timeline,
    proofStates: {
      local: {
        label: "LOCAL DETERMINISTIC REPLAY",
        scope: "Synthetic in-memory specification",
        limitation: "No live cloud claim"
      },
      gateOne: {
        label:
          "RECORDED GATE ONE — CockroachDB Cloud, synthetic scope, 2026-07-30",
        sourceCommit: "55892bf25a5286af30e30908ab5711e24f106629",
        authorityEvidence: "/evidence/gate1-authority",
        recoveryEvidence: "/evidence/gate1-recovery",
        ambiguityEvidence: "/evidence/gate1-ambiguity"
      },
      gateTwo: {
        badge: "GATE TWO · LOCAL",
        label:
          "GATE TWO — local AWS candidate; live AWS evidence pending",
        heading: "AWS proposal boundary · live evidence pending",
        summary:
          "The candidate binds receipts to one exact KMS public key, separates proposal from authority, logs the API path, and fails closed. It is not a live AWS claim.",
        sourceCommit: "UNBOUND LOCAL",
        cloudState: "Main stack not deployed",
        limitation:
          "Bedrock, KMS, IAM, API Gateway, and CloudFormation are unverified live.",
        boundarySummary:
          "CockroachDB transactions, Distributed Vector Indexing, and Managed MCP are recorded Gate One evidence in synthetic scope. The AWS path is a locally verified candidate awaiting live Gate Two receipts. Tideproof makes no production, disaster-readiness, truth-detection, or exactly-once real-world-effect claim.",
        hostReceipt: null
      }
    }
  };
}
