const invariantLabels = {
  expiredEvidenceExcluded: "Expired evidence excluded before ranking",
  invalidProvenanceExcluded: "Invalid provenance excluded before ranking",
  outOfScopeEvidenceExcluded: "Out-of-scope evidence excluded before ranking",
  unresolvedConflictDenied: "Unresolved conflict denied authority",
  exactlyOneLocalWinner: "Exactly one local race winner",
  authorityNotTransferred: "Recovery transferred no authority",
  replayDenied: "Duplicate operation returned its original receipt",
  outageFailsClosed: "Local memory outage returned UNKNOWN_DO_NOT_ACT"
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
      "This local replay models the same one-winner invariant proven by the linked recorded CockroachDB receipt."
  },
  "checkpoint-termination": {
    state: "CHECKPOINTED",
    claim:
      "The winning process records its last safe state before it disappears."
  },
  "successor-recovery": {
    state: "CONTEXT_ONLY",
    claim:
      "The successor receives evidence and receipt lineage, but no inherited right to act; the linked cloud receipt proves the bounded recovery path."
  },
  "replay-denied": {
    state: "DUPLICATE_DENIED",
    claim:
      "CockroachDB returns the original durable receipt and creates no second authority intent."
  },
  "memory-outage": {
    state: "UNKNOWN_DO_NOT_ACT",
    claim:
      "When the local memory specification is unavailable, authorization stops."
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
      "Recorded receipt": "100 live CockroachDB races × 50 contenders",
      "Acceptance": "Exactly one winner and 49 durable denials per race",
      "Invariant violations": 0
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
        "Checkpoint → process termination → bounded Managed MCP context",
      "Authority rule": "Fresh authorization remains mandatory",
      "Protected effect": "Synthetic database sink only"
    },
    steps: [
      "checkpoint-termination",
      "successor-recovery",
      "replay-denied",
      "memory-outage"
    ]
  }
];

const evidenceForStep = {
  "one-winner-race": {
    href: "/evidence/gate1-authority",
    label: "Recorded Gate One authority receipt"
  },
  "checkpoint-termination": {
    href: "/evidence/gate1-recovery",
    label: "Recorded Gate One recovery receipt"
  },
  "successor-recovery": {
    href: "/evidence/gate1-recovery",
    label: "Recorded Gate One recovery receipt"
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

function humanKey(key) {
  return key
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replaceAll("_", " ")
    .replace(/^./, (letter) => letter.toUpperCase());
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

function proofMetadata(mode) {
  if (mode === "recorded") {
    return {
      className: "local",
      label: scenario.proofStates.local.label,
      source: "current local tree",
      limitation:
        "Displayed event is local; the separately linked receipt is recorded provider evidence.",
      backingLabel: scenario.proofStates.gateOne.label,
      backingSource: scenario.proofStates.gateOne.sourceCommit.slice(0, 7)
    };
  }
  return {
    className: "local",
    label: scenario.proofStates.local.label,
    source: "current local tree",
    limitation: scenario.proofStates.local.limitation
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
          stepId !== "memory-outage" &&
          stepId !== "replay-denied"
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

  const detail = document.createElement("div");
  detail.className = "step-detail";
  detail.append(valueNode(step.detail));

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

  stage.replaceChildren(header, title, claim, detail, footer);

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
      status.textContent = "The three-act local replay is complete.";
    }
    return;
  }
  renderStep({ focus });
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
  status.textContent = "The local replay restarted at Act I.";
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
    `${passed} of ${checks.length} scoped local checks passed`;
}

function showLoadFailure(error) {
  pause();
  const wrapper = document.createElement("div");
  wrapper.className = "load-error";
  const kicker = document.createElement("p");
  kicker.className = "step-kicker";
  kicker.textContent = "UNKNOWN_DO_NOT_ACT";
  const heading = document.createElement("h3");
  heading.textContent = "The local proof could not be loaded.";
  const explanation = document.createElement("p");
  explanation.textContent =
    "No PASS state is shown when the proof surface is unavailable.";
  const retry = document.createElement("button");
  retry.type = "button";
  retry.textContent = "Retry local proof";
  retry.addEventListener("click", loadScenario);
  wrapper.append(kicker, heading, explanation, retry);
  stage.replaceChildren(wrapper);
  document.querySelector("#invariants").replaceChildren();
  document.querySelector("#verification-count").textContent =
    "Verification unavailable";
  progress.textContent = "Proof unavailable";
  previousButton.disabled = true;
  nextButton.disabled = true;
  playButton.disabled = true;
  restartButton.disabled = true;
  actButtons.forEach((button) => {
    button.disabled = true;
  });
  status.textContent =
    "The local proof is unavailable. No invariant is represented as passing.";
  console.error(error);
}

async function loadScenario() {
  status.textContent = "Loading the local proof.";
  try {
    const response = await fetch("/api/scenario", {
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
    acts = buildActs();
    activeAct = 0;
    activeStep = 0;
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
      `Local deterministic replay loaded. ${checkCount} scoped checks rendered.`;
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
  if (
    !acts.length ||
    (event.target instanceof Element &&
      event.target.closest("button, a, summary, input, textarea, select"))
  ) {
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

loadScenario();
