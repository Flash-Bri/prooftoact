import { createHash } from "node:crypto";

const EvidenceStatus = Object.freeze({
  ADMITTED: "admitted",
  CONFLICTED: "conflicted",
  INVALID_PROVENANCE: "invalid_provenance",
  NOT_YET_VALID: "not_yet_valid",
  EXPIRED: "expired"
});

export { EvidenceStatus };

export class MemoryUnavailableError extends Error {
  constructor() {
    super("Evidence memory unavailable; authorization failed closed.");
    this.name = "MemoryUnavailableError";
    this.code = "MEMORY_UNAVAILABLE_FAIL_CLOSED";
  }
}

function clone(value) {
  return structuredClone(value);
}

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, nested]) => `${JSON.stringify(key)}:${canonicalJson(nested)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function requireText(value, name) {
  if (typeof value !== "string" || value.trim() === "") {
    throw new TypeError(`${name} must be a non-empty string`);
  }
  return value.trim();
}

function timestamp(value, name) {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) {
    throw new TypeError(`${name} must be an ISO-compatible timestamp`);
  }
  return parsed;
}

function validateVector(vector, name = "embedding") {
  if (
    !Array.isArray(vector) ||
    vector.length === 0 ||
    vector.some((value) => !Number.isFinite(value))
  ) {
    throw new TypeError(`${name} must be a non-empty array of finite numbers`);
  }
  return [...vector];
}

function cosineSimilarity(left, right) {
  if (left.length !== right.length) {
    throw new TypeError("vectors must have the same dimensions");
  }

  let dot = 0;
  let leftMagnitude = 0;
  let rightMagnitude = 0;

  for (let index = 0; index < left.length; index += 1) {
    dot += left[index] * right[index];
    leftMagnitude += left[index] ** 2;
    rightMagnitude += right[index] ** 2;
  }

  if (leftMagnitude === 0 || rightMagnitude === 0) {
    return 0;
  }

  return dot / Math.sqrt(leftMagnitude * rightMagnitude);
}

export class InMemoryVectorIndex {
  #vectors = new Map();

  upsert(id, vector) {
    this.#vectors.set(requireText(id, "id"), validateVector(vector));
  }

  search({ queryVector, candidateIds, limit = 5 }) {
    const query = validateVector(queryVector, "queryVector");
    const allowed = new Set(candidateIds);

    return [...this.#vectors.entries()]
      .filter(([id]) => allowed.has(id))
      .map(([id, vector]) => ({
        id,
        score: cosineSimilarity(query, vector)
      }))
      .sort((left, right) => right.score - left.score || left.id.localeCompare(right.id))
      .slice(0, limit);
  }
}

export class TideproofMemory {
  #available = true;
  #checkpoints = [];
  #clock;
  #evidence = new Map();
  #fencingTokens = new Map();
  #leases = new Map();
  #operationRequests = new Map();
  #receipts = new Map();
  #vectorIndex;

  constructor({
    clock = () => new Date(),
    vectorIndex = new InMemoryVectorIndex()
  } = {}) {
    this.#clock = clock;
    this.#vectorIndex = vectorIndex;
  }

  setAvailable(available) {
    this.#available = Boolean(available);
  }

  #assertAvailable() {
    if (!this.#available) {
      throw new MemoryUnavailableError();
    }
  }

  #now() {
    const value = this.#clock();
    const parsed = value instanceof Date ? value.getTime() : Date.parse(value);
    if (!Number.isFinite(parsed)) {
      throw new TypeError("clock must return a Date or ISO-compatible timestamp");
    }
    return parsed;
  }

  #statusAt(record, at) {
    if (!record.signatureValid) {
      return EvidenceStatus.INVALID_PROVENANCE;
    }
    if (at < record.validFromMs) {
      return EvidenceStatus.NOT_YET_VALID;
    }
    if (at >= record.validUntilMs) {
      return EvidenceStatus.EXPIRED;
    }
    return record.conflicted
      ? EvidenceStatus.CONFLICTED
      : EvidenceStatus.ADMITTED;
  }

  ingestEvidence(input) {
    this.#assertAvailable();

    const id = requireText(input.id, "id");
    if (this.#evidence.has(id)) {
      throw new Error(`evidence id already exists: ${id}`);
    }

    if (!Array.isArray(input.scopes) || input.scopes.length === 0) {
      throw new TypeError("scopes must contain at least one agency or *");
    }
    if (typeof input.signatureValid !== "boolean") {
      throw new TypeError("signatureValid must be a boolean");
    }
    if (
      !Number.isFinite(input.confidence) ||
      input.confidence < 0 ||
      input.confidence > 1
    ) {
      throw new TypeError("confidence must be between 0 and 1");
    }

    const validFromMs = timestamp(input.validFrom, "validFrom");
    const validUntilMs = timestamp(input.validUntil, "validUntil");
    if (validUntilMs <= validFromMs) {
      throw new RangeError("validUntil must be later than validFrom");
    }

    const record = {
      id,
      incidentId: requireText(input.incidentId, "incidentId"),
      claimKey: requireText(input.claimKey, "claimKey"),
      claimValue: requireText(input.claimValue, "claimValue"),
      assertion: requireText(input.assertion, "assertion"),
      issuer: requireText(input.issuer, "issuer"),
      scopes: [...new Set(input.scopes.map((scope) => requireText(scope, "scope")))],
      observedAt: new Date(timestamp(input.observedAt, "observedAt")).toISOString(),
      validFrom: new Date(validFromMs).toISOString(),
      validUntil: new Date(validUntilMs).toISOString(),
      validFromMs,
      validUntilMs,
      signatureValid: input.signatureValid,
      confidence: input.confidence,
      embedding: input.embedding
        ? validateVector(input.embedding)
        : null,
      conflicted: false,
      status: null
    };

    record.status = this.#statusAt(record, this.#now());

    if (record.status === EvidenceStatus.ADMITTED) {
      for (const existing of this.#evidence.values()) {
        const sameClaim =
          existing.incidentId === record.incidentId &&
          existing.claimKey === record.claimKey;
        const differentValue = existing.claimValue !== record.claimValue;
        const overlappingScope = existing.scopes.some(
          (scope) => scope === "*" || record.scopes.includes(scope)
        ) || record.scopes.includes("*");
        const existingCurrent =
          this.#statusAt(existing, this.#now()) === EvidenceStatus.ADMITTED ||
          this.#statusAt(existing, this.#now()) === EvidenceStatus.CONFLICTED;

        if (sameClaim && differentValue && overlappingScope && existingCurrent) {
          existing.conflicted = true;
          existing.status = EvidenceStatus.CONFLICTED;
          record.conflicted = true;
          record.status = EvidenceStatus.CONFLICTED;
        }
      }
    }

    this.#evidence.set(record.id, record);
    if (record.embedding) {
      this.#vectorIndex.upsert(record.id, record.embedding);
    }

    return this.#publicEvidence(record, this.#now());
  }

  #publicEvidence(record, at) {
    return {
      id: record.id,
      incidentId: record.incidentId,
      claimKey: record.claimKey,
      claimValue: record.claimValue,
      assertion: record.assertion,
      issuer: record.issuer,
      scopes: [...record.scopes],
      observedAt: record.observedAt,
      validFrom: record.validFrom,
      validUntil: record.validUntil,
      signatureValid: record.signatureValid,
      confidence: record.confidence,
      status: this.#statusAt(record, at),
      actionEligible:
        this.#statusAt(record, at) === EvidenceStatus.ADMITTED
    };
  }

  listEvidence({ incidentId } = {}) {
    this.#assertAvailable();
    const at = this.#now();
    return [...this.#evidence.values()]
      .filter((record) => !incidentId || record.incidentId === incidentId)
      .map((record) => this.#publicEvidence(record, at))
      .sort((left, right) => left.id.localeCompare(right.id));
  }

  retrieveEvidence({
    incidentId,
    agency,
    queryVector,
    at = new Date(this.#now()).toISOString(),
    limit = 5
  }) {
    this.#assertAvailable();
    const incident = requireText(incidentId, "incidentId");
    const requester = requireText(agency, "agency");
    const atMs = timestamp(at, "at");

    // Provenance, valid-time, and scope are applied before vector ranking.
    const candidates = [...this.#evidence.values()].filter((record) => {
      const status = this.#statusAt(record, atMs);
      const current = status === EvidenceStatus.ADMITTED;
      const inScope =
        record.scopes.includes("*") || record.scopes.includes(requester);
      return record.incidentId === incident && current && inScope;
    });

    let ranked;
    if (queryVector) {
      const scores = this.#vectorIndex.search({
        queryVector,
        candidateIds: candidates.map(({ id }) => id),
        limit
      });
      const byId = new Map(candidates.map((record) => [record.id, record]));
      ranked = scores.map(({ id, score }) => ({
        ...this.#publicEvidence(byId.get(id), atMs),
        similarity: score
      }));
    } else {
      ranked = candidates
        .sort(
          (left, right) =>
            right.confidence - left.confidence ||
            left.id.localeCompare(right.id)
        )
        .slice(0, limit)
        .map((record) => this.#publicEvidence(record, atMs));
    }

    return clone(ranked);
  }

  evaluateDecision({
    incidentId,
    agency,
    evidenceIds,
    at = new Date(this.#now()).toISOString()
  }) {
    this.#assertAvailable();
    const incident = requireText(incidentId, "incidentId");
    const requester = requireText(agency, "agency");
    const atMs = timestamp(at, "at");

    if (!Array.isArray(evidenceIds) || evidenceIds.length === 0) {
      return { allowed: false, reason: "no_evidence" };
    }

    for (const id of evidenceIds) {
      const record = this.#evidence.get(id);
      if (!record || record.incidentId !== incident) {
        return { allowed: false, reason: "missing_evidence", evidenceId: id };
      }
      const status = this.#statusAt(record, atMs);
      if (status === EvidenceStatus.CONFLICTED) {
        return { allowed: false, reason: "evidence_conflict", evidenceId: id };
      }
      if (status !== EvidenceStatus.ADMITTED) {
        return {
          allowed: false,
          reason: `evidence_${status}`,
          evidenceId: id
        };
      }
      if (!record.scopes.includes("*") && !record.scopes.includes(requester)) {
        return {
          allowed: false,
          reason: "evidence_out_of_scope",
          evidenceId: id
        };
      }
    }

    return { allowed: true, reason: "evidence_admissible" };
  }

  reserveResource({
    operationId,
    incidentId,
    resourceId,
    agentId,
    agency,
    evidenceIds,
    leaseMs = 60_000
  }) {
    this.#assertAvailable();
    const operation = requireText(operationId, "operationId");
    const incident = requireText(incidentId, "incidentId");
    const resource = requireText(resourceId, "resourceId");
    const agent = requireText(agentId, "agentId");
    const requester = requireText(agency, "agency");
    if (!Array.isArray(evidenceIds) || evidenceIds.length === 0) {
      throw new TypeError("evidenceIds must contain at least one evidence id");
    }
    const normalizedEvidenceIds = evidenceIds.map((evidenceId) =>
      requireText(evidenceId, "evidenceId")
    );
    if (!Number.isSafeInteger(leaseMs) || leaseMs <= 0) {
      throw new TypeError("leaseMs must be a positive safe integer");
    }
    const request = {
      agentId: agent,
      agency: requester,
      evidenceIds: normalizedEvidenceIds,
      incidentId: incident,
      leaseMs,
      resourceId: resource
    };

    const previous = this.#receipts.get(operation);
    if (previous) {
      const previousRequest = this.#operationRequests.get(operation);
      if (canonicalJson(previousRequest) !== canonicalJson(request)) {
        return {
          outcome: "operation_digest_mismatch_denied",
          operationId: operation,
          reason: "operation_parameters_changed"
        };
      }
      return {
        outcome: "operation_replay",
        operationId: operation,
        originalReceipt: clone(previous)
      };
    }

    const now = this.#now();
    const decision = this.evaluateDecision({
      incidentId: incident,
      agency: requester,
      evidenceIds: normalizedEvidenceIds,
      at: new Date(now).toISOString()
    });

    if (!decision.allowed) {
      const receipt = {
        operationId: operation,
        incidentId: incident,
        resourceId: resource,
        agentId: agent,
        outcome: "authorization_denied",
        reason: decision.reason,
        evidenceIds: [...normalizedEvidenceIds],
        recordedAt: new Date(now).toISOString()
      };
      this.#operationRequests.set(operation, clone(request));
      this.#receipts.set(operation, receipt);
      return clone(receipt);
    }

    const leaseKey = `${incident}:${resource}`;
    const currentLease = this.#leases.get(leaseKey);
    if (currentLease && currentLease.expiresAtMs > now) {
      const receipt = {
        operationId: operation,
        incidentId: incident,
        resourceId: resource,
        agentId: agent,
        outcome: "resource_held_denied",
        heldBy: currentLease.agentId,
        fencingToken: currentLease.fencingToken,
        evidenceIds: [...normalizedEvidenceIds],
        recordedAt: new Date(now).toISOString()
      };
      this.#operationRequests.set(operation, clone(request));
      this.#receipts.set(operation, receipt);
      return clone(receipt);
    }

    const fencingToken = (this.#fencingTokens.get(leaseKey) ?? 0) + 1;
    this.#fencingTokens.set(leaseKey, fencingToken);

    const lease = {
      incidentId: incident,
      resourceId: resource,
      agentId: agent,
      operationId: operation,
      fencingToken,
      acquiredAt: new Date(now).toISOString(),
      expiresAt: new Date(now + leaseMs).toISOString(),
      expiresAtMs: now + leaseMs
    };
    this.#leases.set(leaseKey, lease);

    const receipt = {
      operationId: operation,
      incidentId: incident,
      resourceId: resource,
      agentId: agent,
      outcome: "resource_reserved",
      fencingToken,
      evidenceIds: [...normalizedEvidenceIds],
      recordedAt: new Date(now).toISOString()
    };
    this.#operationRequests.set(operation, clone(request));
    this.#receipts.set(operation, receipt);
    return clone(receipt);
  }

  checkpointAgent({
    checkpointId,
    incidentId,
    agentId,
    lastEvidenceIds,
    receiptOperationId,
    state
  }) {
    this.#assertAvailable();
    if (
      !Array.isArray(lastEvidenceIds) ||
      lastEvidenceIds.length > 100
    ) {
      throw new TypeError("lastEvidenceIds must be an array of at most 100 ids");
    }

    const incident = requireText(incidentId, "incidentId");
    const agent = requireText(agentId, "agentId");
    const normalizedEvidenceIds = lastEvidenceIds.map((value) => {
      const evidenceId = requireText(value, "lastEvidenceId");
      if (Buffer.byteLength(evidenceId, "utf8") > 128) {
        throw new TypeError("lastEvidenceId exceeds 128 bytes");
      }
      return evidenceId;
    });
    if (new Set(normalizedEvidenceIds).size !== normalizedEvidenceIds.length) {
      throw new TypeError("lastEvidenceIds must be unique");
    }
    for (const evidenceId of normalizedEvidenceIds) {
      const record = this.#evidence.get(evidenceId);
      if (!record || record.incidentId !== incident) {
        throw new Error("checkpoint evidence binding mismatch");
      }
    }
    const matchingReceipts = [...this.#receipts.values()].filter(
      (receipt) =>
        receipt.incidentId === incident && receipt.agentId === agent
    );
    let boundReceipt = null;
    if (receiptOperationId !== undefined) {
      const operation = requireText(receiptOperationId, "receiptOperationId");
      boundReceipt = this.#receipts.get(operation) ?? null;
      if (
        !boundReceipt ||
        boundReceipt.incidentId !== incident ||
        boundReceipt.agentId !== agent
      ) {
        throw new Error("checkpoint receipt binding mismatch");
      }
    } else if (matchingReceipts.length > 1) {
      throw new Error("checkpoint receipt binding is ambiguous");
    } else {
      boundReceipt = matchingReceipts[0] ?? null;
    }
    const boundRequest = boundReceipt
      ? this.#operationRequests.get(boundReceipt.operationId) ?? null
      : null;
    if (
      boundReceipt &&
      (
        !boundRequest ||
        canonicalJson([...normalizedEvidenceIds].sort()) !==
          canonicalJson([...(boundReceipt.evidenceIds ?? [])].sort())
      )
    ) {
      throw new Error("checkpoint receipt evidence binding mismatch");
    }
    const receiptSummary = boundReceipt
      ? {
          durableIntentPresent: false,
          outcome: boundReceipt.outcome,
          reason: boundReceipt.reason ?? null,
          resourceLabel: boundReceipt.resourceId
        }
      : null;
    const checkpoint = {
      checkpointId: requireText(checkpointId, "checkpointId"),
      incidentId: incident,
      agentId: agent,
      lastEvidenceIds: normalizedEvidenceIds,
      receiptReference: receiptSummary
        ? {
            receiptDigest: sha256(
              `tideproof.local-receipt-reference.v1\0${canonicalJson({
                receipt: boundReceipt,
                request: boundRequest
              })}`
            ),
            receiptSummary
          }
        : null,
      state: clone(state ?? {}),
      recordedAt: new Date(this.#now()).toISOString()
    };
    this.#checkpoints.push(checkpoint);
    return clone(checkpoint);
  }

  recoverSuccessor({ incidentId, failedAgentId, successorAgentId }) {
    this.#assertAvailable();
    const incident = requireText(incidentId, "incidentId");
    const failed = requireText(failedAgentId, "failedAgentId");
    const successor = requireText(successorAgentId, "successorAgentId");

    const checkpoint = [...this.#checkpoints]
      .reverse()
      .find(
        (candidate) =>
          candidate.incidentId === incident && candidate.agentId === failed
      );
    const evidenceIds = checkpoint?.lastEvidenceIds ?? [];
    const evidence = evidenceIds
      .map((evidenceId) => this.#evidence.get(evidenceId))
      .filter(Boolean);
    const now = this.#now();
    const unresolvedCount = evidence.filter(
      (record) => this.#statusAt(record, now) === EvidenceStatus.CONFLICTED
    ).length;
    const receiptReference = checkpoint?.receiptReference ?? null;

    return clone({
      incidentId: incident,
      failedAgentId: failed,
      successorAgentId: successor,
      checkpointSummary: checkpoint
        ? {
            checkpointVersion: 1,
            failedAgent: failed,
            phase: "successor-context-recovery",
            scenario: "synthetic-highwater"
          }
        : null,
      evidenceSummary: {
        admittedCount: evidence.filter(
          (record) =>
            this.#statusAt(record, now) === EvidenceStatus.ADMITTED
        ).length,
        classification: "synthetic",
        evidenceDigest: sha256(canonicalJson([...evidenceIds].sort()))
      },
      conflictSummary: {
        status: unresolvedCount > 0 ? "quarantined" : "none",
        unresolvedCount
      },
      receiptReference: receiptReference
        ? {
            receiptDigest: receiptReference.receiptDigest,
            receiptSummary: receiptReference.receiptSummary
          }
        : null,
      authorityTransferred: false,
      requiresFreshAuthorization: true,
      operationalCapabilitiesReturned: false
    });
  }
}
