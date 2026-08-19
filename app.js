const invariantLabels = {
  expiredEvidenceExcluded: "Expired evidence excluded before ranking",
  invalidProvenanceExcluded: "Invalid provenance excluded before ranking",
  outOfScopeEvidenceExcluded: "Out-of-scope evidence excluded before ranking",
  unresolvedConflictDenied: "Unresolved conflict denied authority",
  exactlyOneLocalWinner: "Exactly one bounded race winner",
  authorityNotTransferred: "Recovery transferred no authority",
  recoveredCapabilitiesAbsent: "Recovery returned no operational capability",
  exactOperationReplay: "Exact duplicate returned its original receipt",
  changedOperationRejected: "Changed operation inputs were rejected",
  outageFailsClosed: "Evidence memory outage returned UNKNOWN_DO_NOT_ACT"
};

const eventPresentation = {
  "fresh-evidence": {
    state: "ADMITTED",
    claim:
      "A signed, current, rescue-scoped record enters the eligible set."
  },
  "expired-evidence": {
    state: "EXCLUDED",
    claim:
      "High similarity cannot revive evidence after its validity window."
  },
  "invalid-provenance": {
    state: "QUARANTINED",
    claim:
      "An unverified issuer is rejected before vector similarity is consulted."
  },
  "out-of-scope": {
    state: "OUT_OF_SCOPE",
    claim:
      "Current evidence for a different agency remains unavailable to rescue."
  },
  "conflict-preserved": {
    state: "CONFLICT_VISIBLE",
    claim:
      "Two current reports survive retrieval as a conflict—not a false consensus."
  },
  "policy-before-vector": {
    state: "ELIGIBLE_IDS_RANKED",
    claim:
      "The vector index receives only records that already passed deterministic policy."
  },
  "conflict-fails-closed": {
    state: "DENIED",
    claim:
      "Unresolved contradiction blocks authorization without changing authority state."
  },
  "one-winner-race": {
    state: "ONE_WINNER",
    claim:
      "One bounded contender receives the outcome; the competing contender is denied."
  },
  "checkpoint-termination": {
    state: "CHECKPOINTED",
    claim:
      "The winning process records its last safe state before it disappears."
  },
  "successor-recovery": {
    state: "CONTEXT_ONLY",
    claim:
      "The successor receives context but no inherited right to act."
  },
  "exact-operation-replay": {
    state: "EXACT_REPLAY",
    claim:
      "An exact duplicate returns the original decision without creating new authority."
  },
  "changed-operation-rejected": {
    state: "DIGEST_MISMATCH_DENIED",
    claim:
      "Changing the agent or any authority input under the same operation ID is rejected before authority state can change."
  },
  "memory-outage": {
    state: "UNKNOWN_DO_NOT_ACT",
    claim:
      "When evidence memory is unavailable, authorization stops."
  }
};

const actDefinitions = [
  {
    roman: "I",
    title: "Admit / Refuse",
    takeaway: "Retrieved memory is evidence, not truth.",
    mode: "local",
    introDetail: {
      "Judge takeaway": "Policy precedes similarity.",
      "Visible proof":
        "Fresh, expired, invalid-provenance, out-of-scope, and conflicting records remain distinguishable."
    },
    steps: [
      "fresh-evidence",
      "expired-evidence",
      "invalid-provenance",
      "out-of-scope",
      "conflict-preserved",
      "policy-before-vector",
      "conflict-fails-closed"
    ]
  },
  {
    roman: "II",
    title: "Commit One",
    takeaway: "Shared memory can carry scarce authority without giving it to the model.",
    mode: "recorded",
    introDetail: {
      "Visible result": "One bounded winner and one denied contender",
      "Authority rule": "The model proposes; the authority boundary decides"
    },
    steps: ["one-winner-race"]
  },
  {
    roman: "III",
    title: "Recover Safely",
    takeaway: "Context can survive process death without transferring authority.",
    mode: "recorded",
    introDetail: {
      "Recovery path":
        "Checkpoint → termination → context-only successor",
      "Authority rule": "Fresh authorization remains mandatory",
      "Protected effect": "Synthetic resource reservation"
    },
    steps: [
      "checkpoint-termination",
      "successor-recovery",
      "exact-operation-replay",
      "changed-operation-rejected",
      "memory-outage"
    ]
  }
];

const evidenceForStep = {
  "one-winner-race": {
    href: "https://github.com/Flash-Bri/prooftoact/blob/e800a8592ad5dbcdfaf280da097e68121a386d1f/evidence/gate1-authority-2026-07-30.md",
    label: "Open the source authority document"
  },
  "checkpoint-termination": {
    href: "https://github.com/Flash-Bri/prooftoact/blob/e800a8592ad5dbcdfaf280da097e68121a386d1f/evidence/gate1-recovery-broker-2026-07-30.md",
    label: "Open the source recovery document"
  },
  "successor-recovery": {
    href: "https://github.com/Flash-Bri/prooftoact/blob/e800a8592ad5dbcdfaf280da097e68121a386d1f/evidence/gate1-recovery-broker-2026-07-30.md",
    label: "Open the source recovery document"
  },
  "exact-operation-replay": {
    href: "https://github.com/Flash-Bri/prooftoact/blob/e800a8592ad5dbcdfaf280da097e68121a386d1f/evidence/gate1-authority-2026-07-30.md",
    label: "Open the source authority document"
  },
  "changed-operation-rejected": {
    href: "https://github.com/Flash-Bri/prooftoact/blob/e800a8592ad5dbcdfaf280da097e68121a386d1f/evidence/gate1-authority-2026-07-30.md",
    label: "Open the source authority document"
  }
};

let scenario;
let acts = [];
let activeAct = 0;
let activeStep = 0;
let playTimer;

const stage = document.querySelector("#step-stage");
const progress = document.querySelector("#step-progress");
const status = document.querySelector("#load-status");
const previousButton = document.querySelector("#previous-step");
const nextButton = document.querySelector("#next-step");
const playButton = document.querySelector("#play-pause");
const restartButton = document.querySelector("#restart-demo");
const actButtons = [...document.querySelectorAll("[data-act]")];
const judgePath = document.querySelector("#judge-path");

function humanKey(key) {
  return key
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replaceAll("_", " ")
    .replace(/^./, (letter) => letter.toUpperCase());
}

function renderGateTwoState() {
}

function isExactValue(key, value) {
  return (
    typeof value === "string" &&
    (/id$|digest$|status$|outcome$|reason$|code$|token$/i.test(key) ||
      /^op-|^ev-|^agent-|^checkpoint-|^[0-9a-f]{40,64}$/.test(value) ||
      /^[A-Z][A-Z0-9_]+$/.test(value))
  );
}

function valueNode(value, key = "") {
  if (value === null || value === undefined) {
    const empty = document.createElement("span");
    empty.textContent = "—";
    return empty;
  }

  if (Array.isArray(value)) {
    const list = document.createElement("ul");
    list.className = "detail-list";
    for (const item of value) {
      const listItem = document.createElement("li");
      listItem.append(valueNode(item, key));
      list.append(listItem);
    }
    return list;
  }

  if (typeof value === "object") {
    const definitionList = document.createElement("dl");
    definitionList.className = "detail-grid";
    for (const [childKey, childValue] of Object.entries(value)) {
      const row = document.createElement("div");
      const term = document.createElement("dt");
      const definition = document.createElement("dd");
      term.textContent = humanKey(childKey);
      definition.append(valueNode(childValue, childKey));
      row.append(term, definition);
      definitionList.append(row);
    }
    return definitionList;
  }

  const element = isExactValue(key, value)
    ? document.createElement("code")
    : document.createElement("span");
  element.textContent = String(value);
  return element;
}

function stepHighlights(step) {
  const detail = step.detail;
  switch (step.step) {
    case "fresh-evidence":
      return {
        evidenceId: detail.id,
        status: detail.status,
        scope: detail.scopes,
        signatureValid: detail.signatureValid,
        actionEligible: detail.actionEligible
      };
    case "expired-evidence":
      return {
        evidenceId: detail.id,
        status: detail.status,
        validUntil: detail.validUntil,
        actionEligible: detail.actionEligible
      };
    case "invalid-provenance":
      return {
        evidenceId: detail.id,
        issuer: detail.issuer,
        signatureValid: detail.signatureValid,
        status: detail.status,
        actionEligible: detail.actionEligible
      };
    case "out-of-scope":
      return {
        evidenceId: detail.id,
        evidenceScope: detail.scopes,
        requestedScope: "rescue",
        result: "EXCLUDED_BEFORE_RANKING"
      };
    case "conflict-preserved":
      return {
        conflictingEvidenceIds: detail,
        result: "CONFLICT_RETAINED"
      };
    case "policy-before-vector":
      return {
        returnedIds: detail.returnedIds,
        excludedIds: detail.excludedIds
      };
    case "conflict-fails-closed":
      return {
        allowed: detail.allowed,
        reason: detail.reason,
        evidenceId: detail.evidenceId
      };
    case "one-winner-race": {
      const winner = detail.find(
        ({ outcome }) => outcome === "resource_reserved"
      );
      const denied = detail.find(
        ({ outcome }) => outcome !== "resource_reserved"
      );
      return {
        resourceId: winner?.resourceId,
        winningOperationId: winner?.operationId,
        winningAgentId: winner?.agentId,
        winningOutcome: winner?.outcome,
        deniedOperationId: denied?.operationId,
        deniedOutcome: denied?.outcome,
        fencingToken: winner?.fencingToken
      };
    }
    case "checkpoint-termination":
      return {
        checkpointId: detail.checkpoint.checkpointId,
        agentId: detail.checkpoint.agentId,
        terminationStatus: detail.termination.status
      };
    case "successor-recovery": {
      return {
        failedAgentId: detail.failedAgentId,
        successorAgentId: detail.successorAgentId,
        checkpointPhase: detail.checkpointSummary?.phase,
        admittedEvidenceCount: detail.evidenceSummary.admittedCount,
        conflictStatus: detail.conflictSummary.status,
        priorOutcome:
          detail.receiptReference?.receiptSummary?.outcome,
        resourceLabel:
          detail.receiptReference?.receiptSummary?.resourceLabel,
        authorityTransferred: detail.authorityTransferred,
        requiresFreshAuthorization: detail.requiresFreshAuthorization,
        operationalCapabilitiesReturned:
          detail.operationalCapabilitiesReturned
      };
    }
    case "exact-operation-replay":
      return {
        replayOutcome: detail.outcome,
        originalReceiptOutcome: detail.originalReceipt.outcome,
        requestBinding: "exact original request"
      };
    case "changed-operation-rejected":
      return {
        replayOutcome: detail.outcome,
        reason: detail.reason,
        requestBinding: "successor changed agent identity"
      };
    case "memory-outage":
      return {
        code: detail.code,
        result: "UNKNOWN_DO_NOT_ACT"
      };
    default:
      return detail;
  }
}

function renderStepDetails(step) {
  if (step.kind === "intro") {
    const detail = document.createElement("div");
    detail.className = "step-detail";
    detail.append(valueNode(step.detail));
    return [detail];
  }

  const summary = document.createElement("div");
  summary.className = "step-summary";
  summary.append(valueNode(stepHighlights(step)));

  const disclosure = document.createElement("details");
  disclosure.className = "step-detail";
  const control = document.createElement("summary");
  control.textContent = "View exact event payload";
  const body = document.createElement("div");
  body.className = "step-detail-body";
  body.append(valueNode(step.detail));
  disclosure.append(control, body);
  return [summary, disclosure];
}

function proofMetadata(mode) {
  return {
    className: "local",
    label: "HIGHWATER DRILL",
    source: "main@e800a85 · scenario.json",
    limitation: mode === "recorded"
      ? "Bounded event with linked evidence context."
      : "Evidence-governed scenario transition."
  };
}

function introStep(act, index) {
  return {
    kind: "intro",
    step: `act-${index + 1}-intro`,
    label: `Act ${act.roman} — ${act.title}`,
    claim: act.takeaway,
    state: "ACT_READY",
    detail: act.introDetail,
    mode: act.mode
  };
}

function buildActs() {
  const timeline = new Map(
    scenario.timeline.map((event) => [event.step, event])
  );
  return actDefinitions.map((definition, index) => {
    const eventSteps = definition.steps.map((stepId) => {
      const event = timeline.get(stepId);
      if (!event) {
        throw new Error(`missing scenario step: ${stepId}`);
      }
      return {
        ...event,
        ...eventPresentation[stepId],
        mode:
          definition.mode === "recorded" &&
          stepId !== "memory-outage"
            ? "recorded"
            : "local"
      };
    });
    return {
      ...definition,
      renderedSteps: [introStep(definition, index), ...eventSteps]
    };
  });
}

function renderEvidenceLink(container, stepId) {
  const evidence = evidenceForStep[stepId];
  if (!evidence) {
    return;
  }
  const link = document.createElement("a");
  link.className = "step-evidence-link";
  link.href = evidence.href;
  link.rel = "noreferrer";
  link.textContent = evidence.label;
  container.append(link);
}

function renderStep({ focus = false } = {}) {
  const act = acts[activeAct];
  const step = act.renderedSteps[activeStep];
  const proof = proofMetadata(step.mode);

  const header = document.createElement("header");
  header.className = "step-header";

  const labels = document.createElement("div");
  labels.className = "step-labels";
  const actLabel = document.createElement("span");
  actLabel.className = "act-label";
  actLabel.textContent = `ACT ${act.roman} · ${act.title.toUpperCase()}`;
  const proofLabel = document.createElement("span");
  proofLabel.className = `proof-state ${proof.className}`;
  proofLabel.textContent = proof.label;
  labels.append(actLabel, proofLabel);
  if (proof.backingLabel) {
    const backingLabel = document.createElement("span");
    backingLabel.className = "proof-state recorded";
    backingLabel.textContent = proof.backingLabel;
    labels.append(backingLabel);
  }

  const outcome = document.createElement("span");
  outcome.className = "domain-state";
  outcome.textContent = step.state;
  header.append(labels, outcome);

  const title = document.createElement("h3");
  title.textContent = step.label;
  const claim = document.createElement("p");
  claim.className = "step-claim";
  claim.textContent = step.claim;

  const details = renderStepDetails(step);

  const footer = document.createElement("footer");
  footer.className = "step-proof";
  const source = document.createElement("p");
  const sourceLabel = document.createElement("span");
  sourceLabel.textContent = "Source";
  const sourceValue = document.createElement("code");
  sourceValue.textContent = proof.source;
  source.append(sourceLabel, sourceValue);
  const limitation = document.createElement("p");
  const limitationLabel = document.createElement("span");
  limitationLabel.textContent = "Boundary";
  const limitationValue = document.createElement("strong");
  limitationValue.textContent = proof.limitation;
  limitation.append(limitationLabel, limitationValue);
  footer.append(source, limitation);
  if (proof.backingSource) {
    const backing = document.createElement("p");
    const backingLabel = document.createElement("span");
    backingLabel.textContent = "Recorded backing";
    const backingValue = document.createElement("code");
    backingValue.textContent = proof.backingSource;
    backing.append(backingLabel, backingValue);
    footer.append(backing);
  }
  renderEvidenceLink(footer, step.step);

  stage.replaceChildren(header, title, claim, ...details, footer);

  for (const [index, button] of actButtons.entries()) {
    button.setAttribute("aria-pressed", String(index === activeAct));
  }

  progress.textContent =
    `Act ${activeAct + 1} of ${acts.length} · ` +
    `Step ${activeStep + 1} of ${act.renderedSteps.length}`;
  previousButton.disabled = activeAct === 0 && activeStep === 0;
  nextButton.disabled =
    activeAct === acts.length - 1 &&
    activeStep === act.renderedSteps.length - 1;

  if (focus) {
    stage.focus({ preventScroll: true });
  }
}

function pause() {
  if (playTimer) {
    window.clearInterval(playTimer);
    playTimer = undefined;
  }
  playButton.textContent = "Play";
  playButton.setAttribute("aria-pressed", "false");
}

function nextStep({ fromAutoplay = false, focus = false } = {}) {
  const current = acts[activeAct];
  if (activeStep < current.renderedSteps.length - 1) {
    activeStep += 1;
  } else if (activeAct < acts.length - 1) {
    activeAct += 1;
    activeStep = 0;
  } else {
    pause();
    if (fromAutoplay) {
      status.textContent = "The three-act proof is complete.";
    }
    return;
  }
  renderStep({ focus });
  if (fromAutoplay) {
    const step = acts[activeAct].renderedSteps[activeStep];
    status.textContent =
      `${progress.textContent}. ${step.label}. Outcome ${step.state}.`;
  }
}

function previousStep() {
  if (activeStep > 0) {
    activeStep -= 1;
  } else if (activeAct > 0) {
    activeAct -= 1;
    activeStep = acts[activeAct].renderedSteps.length - 1;
  }
  pause();
  renderStep({ focus: true });
}

function play() {
  if (playTimer) {
    pause();
    return;
  }
  playButton.textContent = "Pause";
  playButton.setAttribute("aria-pressed", "true");
  status.textContent = "Automatic presentation started.";
  playTimer = window.setInterval(
    () => nextStep({ fromAutoplay: true }),
    8_500
  );
}

function restart() {
  pause();
  activeAct = 0;
  activeStep = 0;
  renderStep({ focus: true });
  status.textContent = "The proof restarted at Act I.";
}

function selectAct(index) {
  if (!acts[index]) {
    return;
  }
  pause();
  activeAct = index;
  activeStep = 0;
  renderStep({ focus: true });
  status.textContent = `Act ${index + 1}, ${acts[index].title}, selected.`;
}

function renderInvariants() {
  const container = document.querySelector("#invariants");
  const checks = Object.entries(scenario.invariants);
  container.replaceChildren();

  for (const [key, passed] of checks) {
    const item = document.createElement("li");
    const state = document.createElement("span");
    state.className = passed ? "check-passed" : "check-failed";
    state.textContent = passed ? "CHECK PASSED" : "CHECK FAILED";
    const label = document.createElement("strong");
    label.textContent = invariantLabels[key] ?? humanKey(key);
    item.append(state, label);
    container.append(item);
  }

  const passed = checks.filter(([, value]) => value).length;
  document.querySelector("#verification-count").textContent =
    `${passed} of ${checks.length} evidence checks passed`;
}

function renderFailedInvariants(keys) {
  const container = document.querySelector("#invariants");
  container.replaceChildren();
  for (const key of keys) {
    const item = document.createElement("li");
    const state = document.createElement("span");
    state.className = "check-failed";
    state.textContent = "CHECK FAILED";
    const label = document.createElement("strong");
    label.textContent =
      key === "NO_INVARIANTS"
        ? "No invariants were supplied"
        : invariantLabels[key] ?? humanKey(key);
    item.append(state, label);
    container.append(item);
  }
}

function showLoadFailure(error) {
  pause();
  acts = [];
  const failedInvariantKeys = Array.isArray(error?.failedInvariantKeys)
    ? error.failedInvariantKeys
    : [];
  const verificationRejected = failedInvariantKeys.length > 0;
  const wrapper = document.createElement("div");
  wrapper.className = "load-error";
  const kicker = document.createElement("p");
  kicker.className = "step-kicker";
  kicker.textContent = "UNKNOWN_DO_NOT_ACT";
  const heading = document.createElement("h3");
  heading.textContent = verificationRejected
    ? "The proof failed verification."
    : "The proof could not be loaded.";
  const explanation = document.createElement("p");
  explanation.textContent = verificationRejected
    ? "One or more invariants did not pass. Playback is disabled and no PASS state is shown."
    : "No PASS state is shown when the proof surface is unavailable.";
  const retry = document.createElement("button");
  retry.type = "button";
  retry.textContent = "Retry proof";
  retry.addEventListener("click", loadScenario);
  wrapper.append(kicker, heading, explanation, retry);
  stage.replaceChildren(wrapper);
  if (verificationRejected) {
    renderFailedInvariants(failedInvariantKeys);
    document.querySelector("#verification-count").textContent =
      `Proof rejected · ${failedInvariantKeys.length} failed ` +
      `${failedInvariantKeys.length === 1 ? "check" : "checks"}`;
    progress.textContent = "Proof rejected";
  } else {
    document.querySelector("#invariants").replaceChildren();
    document.querySelector("#verification-count").textContent =
      "Verification unavailable";
    progress.textContent = "Proof unavailable";
  }
  previousButton.disabled = true;
  nextButton.disabled = true;
  playButton.disabled = true;
  restartButton.disabled = true;
  actButtons.forEach((button) => {
    button.disabled = true;
  });
  status.textContent = verificationRejected
    ? `The proof was rejected. ${failedInvariantKeys.length} ` +
      `${failedInvariantKeys.length === 1 ? "check failed" : "checks failed"}.`
    : "The proof is unavailable. No invariant is represented as passing.";
  console.error(error);
}

async function loadScenario() {
  status.textContent = "Loading the proof.";
  try {
    const response = await fetch("./scenario.json", {
      headers: { accept: "application/json" },
      cache: "no-store"
    });
    if (!response.ok) {
      throw new Error(`scenario request failed: ${response.status}`);
    }
    scenario = await response.json();
    if (
      !scenario?.proofStates ||
      !Array.isArray(scenario.timeline) ||
      !scenario.invariants
    ) {
      throw new Error("scenario shape rejected");
    }
    const invariantEntries = Object.entries(scenario.invariants);
    const failedInvariantKeys = invariantEntries
      .filter(([, passed]) => passed !== true)
      .map(([key]) => key);
    if (invariantEntries.length === 0 || failedInvariantKeys.length > 0) {
      const error = new Error("LOCAL_INVARIANT_REJECTED");
      error.failedInvariantKeys =
        failedInvariantKeys.length > 0
          ? failedInvariantKeys
          : ["NO_INVARIANTS"];
      throw error;
    }
    acts = buildActs();
    activeAct = 0;
    activeStep = 0;
    renderGateTwoState();
    previousButton.disabled = false;
    nextButton.disabled = false;
    playButton.disabled = false;
    restartButton.disabled = false;
    actButtons.forEach((button) => {
      button.disabled = false;
    });
    renderInvariants();
    renderStep();
    const checkCount = Object.keys(scenario.invariants).length;
    status.textContent =
      `Highwater Drill loaded. ${checkCount} evidence checks rendered.`;
  } catch (error) {
    showLoadFailure(error);
  }
}

previousButton.addEventListener("click", previousStep);
nextButton.addEventListener("click", () => {
  pause();
  nextStep({ focus: true });
});
playButton.addEventListener("click", play);
restartButton.addEventListener("click", restart);
actButtons.forEach((button, index) => {
  button.addEventListener("click", () => selectAct(index));
});

document.addEventListener("keydown", (event) => {
  const ownsPresenterShortcuts =
    event.target === stage || event.target === judgePath;
  if (!acts.length || !ownsPresenterShortcuts) {
    return;
  }
  if (event.key === "ArrowRight") {
    event.preventDefault();
    pause();
    nextStep({ focus: true });
  } else if (event.key === "ArrowLeft") {
    event.preventDefault();
    previousStep();
  } else if (event.key === " ") {
    event.preventDefault();
    play();
  } else if (event.key === "Home") {
    event.preventDefault();
    restart();
  }
});

document.addEventListener("visibilitychange", () => {
  if (document.hidden && playTimer) {
    pause();
    status.textContent =
      "Automatic presentation paused while this page is hidden.";
  }
});

const LIVE_PROVIDER_ENDPOINT =
  "https://ug5abyn4lg.execute-api.us-east-1.amazonaws.com/api/judge-proof";
const LIVE_PROVIDER_SOURCE =
  "0321d498b645e10a993808c36a920958370348ed";
const LIVE_PROVIDER_BUNDLE =
  "78ad7269424e13785711b5106083a2aac9fbf9f77996f70db4b9e13df869d991";
const LIVE_PROVIDER_SIGNATURE =
  "86315d12c864c4184176bb1d8a0ce071c80e7e14cdccc021f56d4b39eb178947";

const livePanel = document.querySelector("#live-provider-proof");
const liveTitle = document.querySelector("#live-provider-title");
const liveCopy = document.querySelector("#live-provider-copy");
const liveState = document.querySelector("#live-provider-state");
const liveButton = document.querySelector("#check-live-provider");
const liveFacts = document.querySelector("#live-provider-facts");
const liveReceiptLink = document.querySelector("#open-live-provider-receipt");
const liveAnnouncement = document.querySelector("#live-provider-announcement");
const liveAws = document.querySelector("#live-provider-aws");
const liveCockroach = document.querySelector("#live-provider-cockroach");
const liveSource = document.querySelector("#live-provider-source");
const liveObserved = document.querySelector("#live-provider-observed");

function hasExactKeys(value, keys) {
  return value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join("\n") === [...keys].sort().join("\n");
}

function isSha256(value) {
  return typeof value === "string" && /^[0-9a-f]{64}$/u.test(value);
}

function validateLiveProviderReceipt(value) {
  const topKeys = [
    "lambdaVersion",
    "managedMcp",
    "observedAt",
    "proof",
    "proofSha256",
    "receiptExpiredContext",
    "responseSha256",
    "schemaVersion",
    "sourceCommit",
    "status"
  ];
  const proofKeys = [
    "authorityTransferred",
    "bindingSha256",
    "bundleDigest",
    "expiresAt",
    "publisherKeySha256",
    "receiptBoundary",
    "receiptReason",
    "requiresFreshAuthorization",
    "schemaVersion",
    "signatureDigest",
    "sourceClusterIdSha256",
    "sourceCommitTs",
    "sourceDigest"
  ];
  const mcpKeys = [
    "closeHttpStatus",
    "clusterIdSha256",
    "endpointAuthority",
    "initializeHttpStatus",
    "notificationHttpStatus",
    "protocolVersion",
    "redirectPolicy",
    "responseLimitBytes",
    "semanticRequestEvidenceSha256",
    "sessionClosed",
    "toolCallHttpStatus"
  ];
  const observed = Date.parse(value?.observedAt);
  if (
    !hasExactKeys(value, topKeys) ||
    value.schemaVersion !== "prooftoact.public-judge-proof.v1" ||
    value.status !== "LIVE_MANAGED_MCP_READ" ||
    value.sourceCommit !== LIVE_PROVIDER_SOURCE ||
    value.lambdaVersion !== "3" ||
    typeof value.receiptExpiredContext !== "boolean" ||
    !Number.isFinite(observed) ||
    Math.abs(Date.now() - observed) > 5 * 60 * 1_000 ||
    !hasExactKeys(value.proof, proofKeys) ||
    value.proof.schemaVersion !== 1 ||
    value.proof.receiptBoundary !==
      "HISTORICAL_SIGNED_RECOVERY_CONTEXT_ONLY" ||
    value.proof.bundleDigest !== LIVE_PROVIDER_BUNDLE ||
    value.proof.signatureDigest !== LIVE_PROVIDER_SIGNATURE ||
    value.proof.authorityTransferred !== false ||
    value.proof.requiresFreshAuthorization !== true ||
    value.proof.receiptReason !== "transport-proof-only" ||
    !hasExactKeys(value.managedMcp, mcpKeys) ||
    value.managedMcp.endpointAuthority !== "cockroachlabs.cloud" ||
    value.managedMcp.protocolVersion !== "2025-03-26" ||
    value.managedMcp.initializeHttpStatus !== 200 ||
    value.managedMcp.notificationHttpStatus !== 202 ||
    value.managedMcp.toolCallHttpStatus !== 200 ||
    value.managedMcp.closeHttpStatus !== 204 ||
    value.managedMcp.sessionClosed !== true ||
    value.managedMcp.redirectPolicy !== "error" ||
    value.managedMcp.responseLimitBytes !== 32 * 1024 ||
    !isSha256(value.proofSha256) ||
    !isSha256(value.responseSha256) ||
    !isSha256(value.managedMcp.clusterIdSha256) ||
    !isSha256(value.managedMcp.semanticRequestEvidenceSha256)
  ) {
    throw new Error("LIVE_PROVIDER_RECEIPT_REJECTED");
  }
  return value;
}

function setLiveProviderState(state, receipt) {
  livePanel.dataset.state = state;
  livePanel.setAttribute("aria-busy", state === "loading" ? "true" : "false");
  liveButton.disabled = state === "loading";
  liveFacts.hidden = state !== "success";
  liveReceiptLink.hidden = state !== "success";
  if (state === "loading") {
    liveState.textContent = "CHECKING";
    liveTitle.textContent = "Checking the provider path…";
    liveCopy.textContent =
      "Requesting one bounded read from AWS Lambda through Managed MCP.";
    liveButton.textContent = "Checking…";
    liveAnnouncement.textContent =
      "Checking the live AWS and CockroachDB Managed MCP path.";
    return;
  }
  if (state === "success") {
    liveState.textContent = "LIVE READ VERIFIED";
    liveTitle.textContent = "AWS + CockroachDB responded.";
    liveCopy.textContent =
      "A current Lambda invocation completed the fixed Managed MCP read and closed its session. The signed recovery context transferred no authority.";
    liveButton.textContent = "Check again";
    liveAws.textContent = `Lambda v${receipt.lambdaVersion} · HTTP 200`;
    liveCockroach.textContent = "Managed MCP · session closed";
    liveSource.textContent = `${receipt.sourceCommit.slice(0, 12)}…`;
    liveObserved.textContent = new Date(receipt.observedAt).toLocaleString();
    liveObserved.setAttribute("datetime", receipt.observedAt);
    liveAnnouncement.textContent =
      "Live AWS and CockroachDB Managed MCP read verified.";
    return;
  }
  liveState.textContent = "UNAVAILABLE";
  liveTitle.textContent = "Live receipt unavailable.";
  liveCopy.textContent =
    "The provider receipt could not be verified just now. The submitted three-act walkthrough remains available.";
  liveButton.textContent = "Try again";
  liveAnnouncement.textContent = "Live provider receipt unavailable.";
}

let liveProviderRequest = null;
let liveProviderCooldown = null;

function startLiveProviderCooldown() {
  clearTimeout(liveProviderCooldown);
  liveButton.disabled = true;
  liveButton.textContent =
    livePanel.dataset.state === "success"
      ? "Verified just now"
      : "Retry in 10 seconds";
  liveProviderCooldown = setTimeout(() => {
    if (livePanel.dataset.state !== "loading") {
      liveButton.disabled = false;
      liveButton.textContent =
        livePanel.dataset.state === "success" ? "Check again" : "Try again";
    }
  }, 10_000);
}

async function checkLiveProvider() {
  if (liveProviderRequest !== null) return liveProviderRequest;
  setLiveProviderState("loading");
  liveProviderRequest = (async () => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 24_000);
    try {
      const response = await fetch(LIVE_PROVIDER_ENDPOINT, {
        method: "GET",
        headers: { accept: "application/json" },
        cache: "no-store",
        credentials: "omit",
        redirect: "error",
        signal: controller.signal
      });
      if (!response.ok || response.url !== LIVE_PROVIDER_ENDPOINT) {
        throw new Error("LIVE_PROVIDER_RESPONSE_REJECTED");
      }
      const receipt = validateLiveProviderReceipt(await response.json());
      setLiveProviderState("success", receipt);
    } catch (error) {
      setLiveProviderState("error");
      console.error(error);
    } finally {
      clearTimeout(timeout);
      startLiveProviderCooldown();
      liveProviderRequest = null;
    }
  })();
  return liveProviderRequest;
}

liveButton.addEventListener("click", checkLiveProvider);
if ("IntersectionObserver" in window) {
  const liveObserver = new IntersectionObserver((entries, observer) => {
    if (entries.some((entry) => entry.isIntersecting)) {
      observer.disconnect();
      checkLiveProvider();
    }
  }, { rootMargin: "160px" });
  liveObserver.observe(livePanel);
}

loadScenario();
