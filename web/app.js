const labelForInvariant = {
  expiredEvidenceExcluded: "Expired evidence excluded",
  invalidProvenanceExcluded: "Invalid provenance excluded",
  unresolvedConflictDenied: "Unresolved conflict denied",
  exactlyOneLocalWinner: "Exactly one local winner",
  authorityNotTransferred: "Authority not inherited",
  replayDenied: "Replay denied",
  outageFailsClosed: "Outage fails closed"
};

function compactDetail(detail) {
  if (Array.isArray(detail)) {
    if (detail.every((item) => item && typeof item === "object")) {
      return detail
        .map((item) =>
          [
            item.agentId,
            item.outcome?.replaceAll("_", " "),
            item.fencingToken ? `fence ${item.fencingToken}` : null
          ]
            .filter(Boolean)
            .join(": ")
        )
        .join(" · ");
    }
    return detail.join(" · ");
  }
  if (detail && typeof detail === "object") {
    if (detail.outcome) {
      return [
        detail.outcome.replaceAll("_", " "),
        detail.fencingToken ? `fence ${detail.fencingToken}` : null,
        detail.reason ? `reason: ${detail.reason}` : null
      ]
        .filter(Boolean)
        .join(" · ");
    }
    if (detail.status) {
      return `${detail.status.replaceAll("_", " ")} · ${detail.id}`;
    }
    if (detail.allowed === false) {
      return `denied · ${detail.reason.replaceAll("_", " ")}`;
    }
    if ("authorityTransferred" in detail) {
      return detail.authorityTransferred
        ? "authority transferred"
        : "context recovered · fresh authorization required";
    }
    if (detail.returnedIds) {
      return `${detail.returnedIds.length} admissible records ranked · ${detail.excludedIds.length} excluded first`;
    }
    if (detail.code) {
      return detail.code.replaceAll("_", " ");
    }
  }
  return String(detail);
}

function renderInvariant(container, [key, passed]) {
  const article = document.createElement("article");
  article.className = `invariant ${passed ? "passed" : "failed"}`;

  const state = document.createElement("span");
  state.className = "invariant-state";
  state.textContent = passed ? "PASS" : "FAIL";

  const label = document.createElement("p");
  label.textContent = labelForInvariant[key] ?? key;

  article.append(state, label);
  container.append(article);
}

function renderTimeline(container, event, index) {
  const item = document.createElement("li");
  const marker = document.createElement("span");
  marker.className = "timeline-marker";
  marker.textContent = String(index + 1).padStart(2, "0");

  const content = document.createElement("div");
  content.className = "timeline-content";

  const title = document.createElement("h3");
  title.textContent = event.label;

  const detail = document.createElement("p");
  detail.textContent = compactDetail(event.detail);

  content.append(title, detail);
  item.append(marker, content);
  container.append(item);
}

async function loadScenario() {
  const invariants = document.querySelector("#invariants");
  const timeline = document.querySelector("#timeline");

  try {
    const response = await fetch("/api/scenario", {
      headers: { accept: "application/json" }
    });
    if (!response.ok) {
      throw new Error(`scenario request failed: ${response.status}`);
    }
    const scenario = await response.json();

    invariants.replaceChildren();
    for (const invariant of Object.entries(scenario.invariants)) {
      renderInvariant(invariants, invariant);
    }
    scenario.timeline.forEach((event, index) =>
      renderTimeline(timeline, event, index)
    );
  } catch (error) {
    invariants.replaceChildren();
    const message = document.createElement("p");
    message.className = "load-error";
    message.textContent = "The local proof could not be loaded.";
    invariants.append(message);
    console.error(error);
  }
}

loadScenario();
