import assert from "node:assert/strict";
import test from "node:test";

import axeCore from "axe-core";

import { __test } from "../scripts/verify-browser-accessibility.js";

function axNode(role, name, properties = []) {
  return {
    ignored: false,
    role: { value: role },
    name: { value: name },
    properties
  };
}

function passingSnapshot() {
  return {
    document: {
      title: "Tideproof — Admissibility Memory",
      language: "en",
      readyState: "complete",
      status: "Local deterministic replay loaded. 8 scoped checks rendered.",
      progress: "Act 1 of 3 · Step 1 of 8",
      invariantCount: 8,
      failedInvariantCount: 0,
      buttonCount: 7,
      enabledButtonCount: 6,
      previousDisabled: true,
      minimumButtonHeight: 44
    },
    skipLink: {
      activeClass: "skip-link",
      text: "Skip to the judge path",
      visible: true
    },
    keyboard: {
      advanced: true,
      progress: "Act 1 of 3 · Step 2 of 8",
      activeElementId: "step-stage",
      restarted: true,
      restartProgress: "Act 1 of 3 · Step 1 of 8"
    },
    presenter: {
      actSelected: true,
      actProgress: "Act 2 of 3 · Step 1 of 2",
      playStarted: true,
      playStopped: true
    },
    reducedMotion: { matches: true, scrollBehavior: "auto" },
    mobile: {
      innerWidth: 390,
      horizontalPageOverflow: false,
      singleColumnActs: true,
      ribbonScrollable: true
    },
    ax: {
      roles: { RootWebArea: 1, main: 1, navigation: 1 },
      buttons: __test.EXPECTED_BUTTON_NAMES.map((name) => ({
        name,
        disabled: false
      })),
      headingCount: 9,
      unnamedHeadingCount: 0,
      linkCount: 6,
      unnamedLinkCount: 0,
      unnamedInteractiveCount: 0
    },
    browserErrors: [],
    failedRequests: [],
    faviconStatus: 404,
    axe: {
      standardTags: [...__test.AXE_TAGS],
      desktop: {
        engine: { name: "axe-core", version: axeCore.version },
        violationIds: [],
        incompleteIds: [],
        passCount: 32,
        inapplicableCount: 54
      },
      mobile: {
        engine: { name: "axe-core", version: axeCore.version },
        violationIds: [],
        incompleteIds: [],
        passCount: 32,
        inapplicableCount: 54
      }
    },
    expectedOmissions: ["/favicon.ico:404"],
    loadedPaths: [
      "/",
      "/api/scenario",
      "/app.js",
      "/architecture.svg",
      "/styles.css"
    ]
  };
}

test("DevTools port receipt parser rejects malformed endpoints", () => {
  assert.deepEqual(
    __test.parseDevToolsActivePort(
      "43117\n/devtools/browser/12345678-abcd-4321-bcde-123456789abc\n"
    ),
    {
      port: 43117,
      browserPath:
        "/devtools/browser/12345678-abcd-4321-bcde-123456789abc"
    }
  );
  assert.throws(
    () => __test.parseDevToolsActivePort("0\n/devtools/browser/invalid\n"),
    /BROWSER_ACCESSIBILITY_DEVTOOLS_PORT/
  );
  assert.throws(
    () => __test.parseDevToolsActivePort("43117\nhttp:\/\/remote.invalid\n"),
    /BROWSER_ACCESSIBILITY_DEVTOOLS_PORT/
  );
});

test("unexpected browser diagnostics are bounded and sanitized", () => {
  const diagnostic = __test.formatUnexpectedFailure({
    name: "ProtocolError",
    code: "E_FAIL",
    message: "bad\nvalue <secret>"
  });
  assert.equal(
    diagnostic,
    "ProtocolError:E_FAIL:bad?value ?secret?"
  );
  assert.equal(__test.formatUnexpectedFailure(undefined), "UnknownError");
});

test("browser profile cleanup retries repeated late directory entries", async () => {
  const calls = [];
  const waits = [];
  let remainingLateEntries = 4;
  await __test.removeProfileDirectory(
    "/tmp/tideproof-browser-profile-fixture",
    (profileDir, options) => {
      calls.push({ profileDir, options });
      if (remainingLateEntries > 0) {
        remainingLateEntries -= 1;
        const error = new Error("late profile entry");
        error.code = "ENOTEMPTY";
        throw error;
      }
    },
    async (milliseconds) => waits.push(milliseconds)
  );
  assert.equal(calls.length, 5);
  assert.deepEqual(
    calls,
    Array.from({ length: 5 }, () => ({
      profileDir: "/tmp/tideproof-browser-profile-fixture",
      options: {
        recursive: true,
        force: true,
        maxRetries: 2,
        retryDelay: 100
      }
    }))
  );
  assert.deepEqual(waits, [100, 100, 100, 100]);
});

test("browser teardown signals the full Unix process group", () => {
  const signals = [];
  const chrome = {
    pid: 43117,
    exitCode: null,
    kill: (signal) => signals.push(["child", signal])
  };
  __test.signalChrome(chrome, "SIGTERM", {
    kill: (pid, signal) => signals.push([pid, signal]),
    platform: "linux"
  });
  assert.deepEqual(signals, [[-43117, "SIGTERM"]]);
});

test("accessibility tree summary exposes names, roles, and disabled state", () => {
  const disabled = [
    {
      name: "disabled",
      value: { value: true }
    }
  ];
  const summary = __test.summarizeAxTree([
    axNode("RootWebArea", "Tideproof — Admissibility Memory"),
    axNode("main", ""),
    axNode("heading", "Memory should preserve evidence—not inherit authority."),
    axNode("navigation", "Choose a demonstration act"),
    axNode("button", "Play", disabled),
    axNode("link", "Public MIT source"),
    { ignored: true, role: { value: "button" }, name: { value: "" } }
  ]);

  assert.equal(summary.exposedNodeCount, 6);
  assert.equal(summary.roles.RootWebArea, 1);
  assert.equal(summary.roles.button, 1);
  assert.deepEqual(summary.buttons, [{ name: "Play", disabled: true }]);
  assert.equal(summary.headingCount, 1);
  assert.equal(summary.linkCount, 1);
  assert.equal(summary.unnamedInteractiveCount, 0);
});

test("canonical browser snapshot passes the bounded rendered gate", () => {
  assert.deepEqual(__test.AXE_TAGS, [
    "wcag2a",
    "wcag2aa",
    "wcag21a",
    "wcag21aa",
    "wcag22aa"
  ]);
  assert.equal(__test.validateBrowserSnapshot(passingSnapshot()), true);
});

test("browser snapshot rejects maintained rules-engine violations", () => {
  const rulesFailure = passingSnapshot();
  rulesFailure.axe.mobile.violationIds.push("color-contrast");
  assert.throws(
    () => __test.validateBrowserSnapshot(rulesFailure),
    /BROWSER_ACCESSIBILITY_AXE_RULES_ENGINE/
  );

  const incomplete = passingSnapshot();
  incomplete.axe.desktop.incompleteIds.push("aria-prohibited-attr");
  assert.throws(
    () => __test.validateBrowserSnapshot(incomplete),
    /BROWSER_ACCESSIBILITY_AXE_RULES_ENGINE/
  );
});

test("browser snapshot rejects unnamed controls and browser failures", () => {
  const unnamed = passingSnapshot();
  unnamed.ax.unnamedInteractiveCount = 1;
  assert.throws(
    () => __test.validateBrowserSnapshot(unnamed),
    /BROWSER_ACCESSIBILITY_AX_SEMANTICS/
  );

  const browserFailure = passingSnapshot();
  browserFailure.failedRequests.push("/app.js:500");
  assert.throws(
    () => __test.validateBrowserSnapshot(browserFailure),
    /BROWSER_ACCESSIBILITY_BROWSER_ERRORS/
  );
});

test("browser snapshot rejects keyboard, motion, and reflow regressions", () => {
  const keyboard = passingSnapshot();
  keyboard.keyboard.activeElementId = "judge-path";
  assert.throws(
    () => __test.validateBrowserSnapshot(keyboard),
    /BROWSER_ACCESSIBILITY_KEYBOARD/
  );

  const motion = passingSnapshot();
  motion.reducedMotion.scrollBehavior = "smooth";
  assert.throws(
    () => __test.validateBrowserSnapshot(motion),
    /BROWSER_ACCESSIBILITY_REDUCED_MOTION/
  );

  const reflow = passingSnapshot();
  reflow.mobile.horizontalPageOverflow = true;
  assert.throws(
    () => __test.validateBrowserSnapshot(reflow),
    /BROWSER_ACCESSIBILITY_MOBILE_REFLOW/
  );
});
