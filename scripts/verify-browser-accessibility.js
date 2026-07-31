import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { createTideproofServer } from "../src/server.js";
import { verifyAccessibility } from "./verify-accessibility.js";

const SCHEMA = "tideproof.accessibility-browser.v1";
const STANDARD_TARGET = "WCAG_2_2_AA";
const EXPECTED_BUTTON_NAMES = Object.freeze([
  "ACT I Admit / Refuse",
  "ACT II Commit One",
  "ACT III Recover Safely",
  "Next →",
  "Play",
  "Restart",
  "← Previous"
]);
const REMAINING_REQUIREMENTS = Object.freeze([
  "Run a maintained automated accessibility rules engine against the exact public release and deployed bytes.",
  "Complete keyboard-only, 200% zoom, mobile reflow, and reduced-motion private review on the exact public release.",
  "Complete screen-reader review on the exact public release."
]);

function invariant(condition, code) {
  if (!condition) {
    throw new Error(code);
  }
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function formatUnexpectedFailure(error) {
  const parts = [error?.name, error?.code, error?.message]
    .filter((value) => typeof value === "string" && value.length > 0)
    .map((value) => value.replace(/[^A-Za-z0-9 ._:/-]/g, "?"));
  return (parts.join(":") || "UnknownError").slice(0, 400);
}

function chromeCandidates(preferred) {
  return [
    preferred,
    process.env.CHROME_BIN,
    process.platform === "darwin"
      ? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
      : undefined,
    process.platform === "darwin"
      ? "/Applications/Chromium.app/Contents/MacOS/Chromium"
      : undefined,
    process.platform === "win32"
      ? path.join(
          process.env.PROGRAMFILES ?? "C:\\Program Files",
          "Google/Chrome/Application/chrome.exe"
        )
      : undefined,
    "google-chrome",
    "google-chrome-stable",
    "chromium",
    "chromium-browser"
  ].filter(
    (candidate, index, candidates) =>
      typeof candidate === "string" &&
      candidate.length > 0 &&
      candidates.indexOf(candidate) === index
  );
}

function resolveChrome(preferred) {
  for (const candidate of chromeCandidates(preferred)) {
    const result = spawnSync(candidate, ["--version"], {
      encoding: "utf8",
      timeout: 5_000,
      windowsHide: true
    });
    const version = `${result.stdout ?? ""}${result.stderr ?? ""}`.trim();
    if (
      result.status === 0 &&
      /^(?:Google Chrome|Chromium)\s+[0-9]+(?:\.[0-9]+){1,3}$/i.test(version)
    ) {
      return { command: candidate, version };
    }
  }
  throw new Error("BROWSER_ACCESSIBILITY_CHROMIUM_REQUIRED");
}

function parseDevToolsActivePort(source) {
  const lines = source.trim().split(/\r?\n/);
  const port = Number.parseInt(lines[0] ?? "", 10);
  invariant(
    Number.isSafeInteger(port) &&
      port > 0 &&
      port <= 65_535 &&
      /^\/devtools\/browser\/[A-Za-z0-9-]+$/.test(lines[1] ?? ""),
    "BROWSER_ACCESSIBILITY_DEVTOOLS_PORT"
  );
  return { port, browserPath: lines[1] };
}

async function waitForDevTools(profileDir, chrome, timeoutMs = 15_000) {
  const activePortPath = path.join(profileDir, "DevToolsActivePort");
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    invariant(
      chrome.exitCode === null,
      "BROWSER_ACCESSIBILITY_CHROMIUM_EARLY_EXIT"
    );
    try {
      return parseDevToolsActivePort(fs.readFileSync(activePortPath, "utf8"));
    } catch (error) {
      if (
        error?.code !== "ENOENT" &&
        error?.message !== "BROWSER_ACCESSIBILITY_DEVTOOLS_PORT"
      ) {
        throw error;
      }
    }
    await delay(50);
  }
  throw new Error("BROWSER_ACCESSIBILITY_DEVTOOLS_TIMEOUT");
}

async function waitForPageTarget(port, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/json/list`);
      if (response.ok) {
        const targets = await response.json();
        const page = targets.find(
          (target) =>
            target?.type === "page" &&
            typeof target.webSocketDebuggerUrl === "string"
        );
        if (page) {
          return page;
        }
      }
    } catch {
      // DevTools may need a few more milliseconds after publishing its port.
    }
    await delay(50);
  }
  throw new Error("BROWSER_ACCESSIBILITY_PAGE_TARGET_TIMEOUT");
}

class CdpClient {
  constructor(url) {
    this.nextId = 1;
    this.pending = new Map();
    this.listeners = new Map();
    this.socket = new WebSocket(url);
    this.opened = new Promise((resolve, reject) => {
      const timeout = setTimeout(
        () => reject(new Error("BROWSER_ACCESSIBILITY_CDP_OPEN_TIMEOUT")),
        10_000
      );
      this.socket.addEventListener(
        "open",
        () => {
          clearTimeout(timeout);
          resolve();
        },
        { once: true }
      );
      this.socket.addEventListener(
        "error",
        () => {
          clearTimeout(timeout);
          reject(new Error("BROWSER_ACCESSIBILITY_CDP_OPEN"));
        },
        { once: true }
      );
    });
    this.socket.addEventListener("message", (event) => {
      const message = JSON.parse(String(event.data));
      if (Number.isSafeInteger(message.id)) {
        const pending = this.pending.get(message.id);
        if (!pending) {
          return;
        }
        this.pending.delete(message.id);
        clearTimeout(pending.timeout);
        if (message.error) {
          pending.reject(
            new Error(
              `BROWSER_ACCESSIBILITY_CDP_${message.error.code ?? "ERROR"}`
            )
          );
        } else {
          pending.resolve(message.result ?? {});
        }
        return;
      }
      const listeners = this.listeners.get(message.method) ?? [];
      for (const listener of listeners) {
        listener(message.params ?? {});
      }
    });
  }

  on(method, listener) {
    const listeners = this.listeners.get(method) ?? [];
    listeners.push(listener);
    this.listeners.set(method, listeners);
  }

  async send(method, params = {}) {
    await this.opened;
    const id = this.nextId;
    this.nextId += 1;
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`BROWSER_ACCESSIBILITY_CDP_TIMEOUT_${method}`));
      }, 10_000);
      this.pending.set(id, { resolve, reject, timeout });
      this.socket.send(JSON.stringify({ id, method, params }));
    });
  }

  close() {
    if (this.socket.readyState < WebSocket.CLOSING) {
      this.socket.close();
    }
  }
}

async function evaluate(client, expression) {
  const response = await client.send("Runtime.evaluate", {
    expression,
    awaitPromise: true,
    returnByValue: true,
    userGesture: true
  });
  invariant(
    !response.exceptionDetails,
    "BROWSER_ACCESSIBILITY_RUNTIME_EVALUATION"
  );
  return response.result?.value;
}

async function waitForExpression(client, expression, timeoutMs = 15_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      if (await evaluate(client, expression)) {
        return;
      }
    } catch (error) {
      if (error?.message !== "BROWSER_ACCESSIBILITY_RUNTIME_EVALUATION") {
        throw error;
      }
    }
    await delay(50);
  }
  throw new Error("BROWSER_ACCESSIBILITY_PAGE_READY_TIMEOUT");
}

function axValue(node, property) {
  return node?.[property]?.value;
}

function axProperty(node, name) {
  return node?.properties?.find((property) => property.name === name)?.value
    ?.value;
}

function summarizeAxTree(nodes) {
  invariant(Array.isArray(nodes), "BROWSER_ACCESSIBILITY_AX_TREE");
  const exposed = nodes.filter((node) => node?.ignored !== true);
  const roles = new Map();
  for (const node of exposed) {
    const role = axValue(node, "role");
    if (typeof role === "string") {
      roles.set(role, (roles.get(role) ?? 0) + 1);
    }
  }
  const interactiveRoles = new Set([
    "button",
    "DisclosureTriangle",
    "link",
    "navigation"
  ]);
  const unnamedInteractive = exposed.filter(
    (node) =>
      interactiveRoles.has(axValue(node, "role")) &&
      String(axValue(node, "name") ?? "").trim().length === 0
  );
  const buttons = exposed
    .filter((node) => axValue(node, "role") === "button")
    .map((node) => ({
      name: String(axValue(node, "name") ?? "").trim(),
      disabled: axProperty(node, "disabled") === true
    }))
    .sort((left, right) => left.name.localeCompare(right.name));
  const headings = exposed
    .filter((node) => axValue(node, "role") === "heading")
    .map((node) => String(axValue(node, "name") ?? "").trim());
  const links = exposed
    .filter((node) => axValue(node, "role") === "link")
    .map((node) => String(axValue(node, "name") ?? "").trim());
  return {
    exposedNodeCount: exposed.length,
    roles: Object.fromEntries([...roles].sort(([left], [right]) => left.localeCompare(right))),
    buttons,
    headingCount: headings.length,
    unnamedHeadingCount: headings.filter((name) => name.length === 0).length,
    linkCount: links.length,
    unnamedLinkCount: links.filter((name) => name.length === 0).length,
    unnamedInteractiveCount: unnamedInteractive.length
  };
}

function validateBrowserSnapshot(snapshot) {
  invariant(
    snapshot?.document?.title === "Tideproof — Admissibility Memory" &&
      snapshot.document.language === "en" &&
      snapshot.document.readyState === "complete",
    "BROWSER_ACCESSIBILITY_DOCUMENT"
  );
  invariant(
    snapshot.document.status ===
      "Local deterministic replay loaded. 8 scoped checks rendered." &&
      snapshot.document.progress === "Act 1 of 3 · Step 1 of 8" &&
      snapshot.document.invariantCount === 8 &&
      snapshot.document.failedInvariantCount === 0,
    "BROWSER_ACCESSIBILITY_VERIFIED_STATE"
  );
  invariant(
    snapshot.document.buttonCount === 7 &&
      snapshot.document.enabledButtonCount === 6 &&
      snapshot.document.previousDisabled === true &&
      snapshot.document.minimumButtonHeight >= 44,
    "BROWSER_ACCESSIBILITY_CONTROLS"
  );
  invariant(
    snapshot.skipLink?.activeClass === "skip-link" &&
      snapshot.skipLink.visible === true &&
      snapshot.skipLink.text === "Skip to the judge path",
    "BROWSER_ACCESSIBILITY_SKIP_LINK"
  );
  invariant(
    snapshot.keyboard?.advanced === true &&
      snapshot.keyboard.activeElementId === "step-stage" &&
      snapshot.keyboard.progress === "Act 1 of 3 · Step 2 of 8" &&
      snapshot.keyboard.restarted === true &&
      snapshot.keyboard.restartProgress === "Act 1 of 3 · Step 1 of 8",
    "BROWSER_ACCESSIBILITY_KEYBOARD"
  );
  invariant(
    snapshot.presenter?.actSelected === true &&
      snapshot.presenter.actProgress === "Act 2 of 3 · Step 1 of 2" &&
      snapshot.presenter.playStarted === true &&
      snapshot.presenter.playStopped === true,
    "BROWSER_ACCESSIBILITY_PRESENTER"
  );
  invariant(
    snapshot.reducedMotion?.matches === true &&
      snapshot.reducedMotion.scrollBehavior === "auto",
    "BROWSER_ACCESSIBILITY_REDUCED_MOTION"
  );
  invariant(
    snapshot.mobile?.innerWidth === 390 &&
      snapshot.mobile.horizontalPageOverflow === false &&
      snapshot.mobile.singleColumnActs === true &&
      snapshot.mobile.ribbonScrollable === true,
    "BROWSER_ACCESSIBILITY_MOBILE_REFLOW"
  );
  invariant(
    snapshot.ax?.roles?.RootWebArea === 1 &&
      snapshot.ax.roles.main === 1 &&
      snapshot.ax.roles.navigation >= 1 &&
      snapshot.ax.headingCount >= 9 &&
      snapshot.ax.unnamedHeadingCount === 0 &&
      snapshot.ax.linkCount >= 6 &&
      snapshot.ax.unnamedLinkCount === 0 &&
      snapshot.ax.unnamedInteractiveCount === 0,
    "BROWSER_ACCESSIBILITY_AX_SEMANTICS"
  );
  const buttonNames = snapshot.ax.buttons
    .map(({ name }) => name)
    .sort((left, right) => left.localeCompare(right));
  invariant(
    JSON.stringify(buttonNames) ===
      JSON.stringify(
        [...EXPECTED_BUTTON_NAMES].sort((left, right) => left.localeCompare(right))
      ),
    "BROWSER_ACCESSIBILITY_AX_CONTROLS"
  );
  invariant(
    snapshot.browserErrors.length === 0 &&
      snapshot.failedRequests.length === 0 &&
      snapshot.faviconStatus === 404 &&
      JSON.stringify(snapshot.expectedOmissions) ===
        JSON.stringify(["/favicon.ico:404"]),
    "BROWSER_ACCESSIBILITY_BROWSER_ERRORS"
  );
  invariant(
    [
      "/",
      "/api/scenario",
      "/app.js",
      "/architecture.svg",
      "/styles.css"
    ].every((pathname) => snapshot.loadedPaths.includes(pathname)),
    "BROWSER_ACCESSIBILITY_LOADED_PATHS"
  );
  return true;
}

async function startServer() {
  const server = createTideproofServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  assert(address && typeof address === "object");
  return { server, origin: `http://127.0.0.1:${address.port}` };
}

async function stopServer(server) {
  if (!server.listening) {
    return;
  }
  await new Promise((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve()))
  );
}

async function stopChrome(chrome) {
  if (chrome.exitCode !== null) {
    return;
  }
  chrome.kill("SIGTERM");
  const exited = await Promise.race([
    new Promise((resolve) => chrome.once("exit", () => resolve(true))),
    delay(2_000).then(() => false)
  ]);
  if (!exited && chrome.exitCode === null) {
    const killedPromise = new Promise((resolve) =>
      chrome.once("exit", () => resolve(true))
    );
    chrome.kill("SIGKILL");
    const killed = await Promise.race([
      killedPromise,
      delay(2_000).then(() => false)
    ]);
    invariant(
      killed || chrome.exitCode !== null,
      "BROWSER_ACCESSIBILITY_CHROMIUM_STOP_TIMEOUT"
    );
  }
}

async function dispatchKey(client, key, code, virtualKeyCode) {
  await client.send("Input.dispatchKeyEvent", {
    type: "keyDown",
    key,
    code,
    windowsVirtualKeyCode: virtualKeyCode,
    nativeVirtualKeyCode: virtualKeyCode
  });
  await client.send("Input.dispatchKeyEvent", {
    type: "keyUp",
    key,
    code,
    windowsVirtualKeyCode: virtualKeyCode,
    nativeVirtualKeyCode: virtualKeyCode
  });
}

async function collectBrowserSnapshot(client, origin) {
  const browserErrors = [];
  const failedRequests = [];
  const expectedOmissions = [];
  const loadedPaths = new Set();
  client.on("Runtime.exceptionThrown", ({ exceptionDetails }) => {
    browserErrors.push(`exception:${exceptionDetails?.text ?? "unknown"}`);
  });
  client.on("Runtime.consoleAPICalled", ({ type, args }) => {
    if (type === "error") {
      browserErrors.push(
        `console:${args?.map((argument) => argument.value ?? argument.description).join(" ")}`
      );
    }
  });
  client.on("Log.entryAdded", ({ entry }) => {
    if (
      entry?.level === "error" &&
      entry.url === `${origin}/favicon.ico` &&
      /status of 404/.test(entry.text ?? "")
    ) {
      return;
    }
    if (entry?.level === "error") {
      browserErrors.push(`log:${entry.text ?? "unknown"}`);
    }
  });
  client.on("Network.loadingFailed", ({ errorText, canceled }) => {
    if (!canceled) {
      failedRequests.push(errorText ?? "unknown");
    }
  });
  client.on("Network.responseReceived", ({ response }) => {
    if (typeof response?.url !== "string" || !response.url.startsWith(origin)) {
      return;
    }
    const url = new URL(response.url);
    if (url.pathname === "/favicon.ico" && response.status === 404) {
      expectedOmissions.push("/favicon.ico:404");
      return;
    }
    if (response.status < 200 || response.status >= 300) {
      failedRequests.push(`${url.pathname}:${response.status}`);
      return;
    }
    loadedPaths.add(url.pathname);
  });

  await Promise.all([
    client.send("Accessibility.enable"),
    client.send("Log.enable"),
    client.send("Network.enable"),
    client.send("Page.enable"),
    client.send("Runtime.enable")
  ]);
  await client.send("Emulation.setDeviceMetricsOverride", {
    width: 1440,
    height: 900,
    deviceScaleFactor: 1,
    mobile: false
  });
  await client.send("Page.navigate", { url: origin });
  await client.send("Page.bringToFront");
  await waitForExpression(
    client,
    `document.readyState === "complete" &&
      document.querySelector("#load-status")?.textContent.includes("loaded") &&
      document.querySelectorAll("#invariants .check-passed").length === 8`
  );
  const faviconStatus = await evaluate(
    client,
    `fetch("/favicon.ico", { cache: "no-store" }).then((response) => response.status)`
  );

  const document = await evaluate(
    client,
    `(() => {
      const buttons = [...document.querySelectorAll("button")];
      return {
        title: document.title,
        language: document.documentElement.lang,
        readyState: document.readyState,
        status: document.querySelector("#load-status")?.textContent.trim(),
        progress: document.querySelector("#step-progress")?.textContent.trim(),
        invariantCount: document.querySelectorAll("#invariants li").length,
        failedInvariantCount: document.querySelectorAll("#invariants .check-failed").length,
        buttonCount: buttons.length,
        enabledButtonCount: buttons.filter((button) => !button.disabled).length,
        previousDisabled: document.querySelector("#previous-step")?.disabled,
        minimumButtonHeight: Math.min(
          ...buttons.map((button) => button.getBoundingClientRect().height)
        )
      };
    })()`
  );

  await evaluate(
    client,
    `document.querySelector(".skip-link").focus(); true`
  );
  await delay(50);
  const skipLink = await evaluate(
    client,
    `(() => {
      const link = document.querySelector(".skip-link");
      const rect = link.getBoundingClientRect();
      const style = getComputedStyle(link);
      return {
        activeClass: document.activeElement?.className,
        text: link.textContent.trim(),
        visible:
          rect.width > 0 &&
          rect.height > 0 &&
          rect.bottom > 0 &&
          style.visibility !== "hidden" &&
          style.display !== "none"
      };
    })()`
  );

  await evaluate(
    client,
    `document.querySelector("#judge-path").focus({ preventScroll: true }); true`
  );
  await dispatchKey(client, "ArrowRight", "ArrowRight", 39);
  const advanced = await evaluate(
    client,
    `({
      progress: document.querySelector("#step-progress")?.textContent.trim(),
      activeElementId: document.activeElement?.id
    })`
  );
  await dispatchKey(client, "Home", "Home", 36);
  const restarted = await evaluate(
    client,
    `({
      progress: document.querySelector("#step-progress")?.textContent.trim(),
      activeElementId: document.activeElement?.id
    })`
  );
  const keyboard = {
    advanced: advanced.progress === "Act 1 of 3 · Step 2 of 8",
    progress: advanced.progress,
    activeElementId: advanced.activeElementId,
    restarted: restarted.activeElementId === "step-stage",
    restartProgress: restarted.progress
  };

  const presenter = await evaluate(
    client,
    `(() => {
      document.querySelector('[data-act="1"]').click();
      const actProgress = document.querySelector("#step-progress").textContent.trim();
      const actSelected =
        document.querySelector('[data-act="1"]').getAttribute("aria-pressed") === "true";
      const play = document.querySelector("#play-pause");
      play.click();
      const playStarted =
        play.textContent.trim() === "Pause" &&
        play.getAttribute("aria-pressed") === "true";
      play.click();
      const playStopped =
        play.textContent.trim() === "Play" &&
        play.getAttribute("aria-pressed") === "false";
      return { actProgress, actSelected, playStarted, playStopped };
    })()`
  );

  await client.send("Emulation.setEmulatedMedia", {
    media: "screen",
    features: [{ name: "prefers-reduced-motion", value: "reduce" }]
  });
  const reducedMotion = await evaluate(
    client,
    `({
      matches: matchMedia("(prefers-reduced-motion: reduce)").matches,
      scrollBehavior: getComputedStyle(document.documentElement).scrollBehavior
    })`
  );

  await client.send("Emulation.setDeviceMetricsOverride", {
    width: 390,
    height: 844,
    deviceScaleFactor: 2,
    mobile: true
  });
  await delay(100);
  const mobile = await evaluate(
    client,
    `(() => {
      const acts = document.querySelector(".act-nav");
      const ribbon = document.querySelector(".proof-ribbon");
      return {
        innerWidth,
        horizontalPageOverflow:
          document.documentElement.scrollWidth > document.documentElement.clientWidth,
        singleColumnActs:
          getComputedStyle(acts).gridTemplateColumns.trim().split(/\\s+/).length === 1,
        ribbonScrollable:
          getComputedStyle(ribbon).overflowY === "auto" &&
          ribbon.scrollHeight >= ribbon.clientHeight
      };
    })()`
  );

  const axTree = await client.send("Accessibility.getFullAXTree");
  const ax = summarizeAxTree(axTree.nodes);
  return {
    document,
    skipLink,
    keyboard,
    presenter,
    reducedMotion,
    mobile,
    ax,
    browserErrors,
    failedRequests,
    faviconStatus,
    expectedOmissions: [...new Set(expectedOmissions)].sort(),
    loadedPaths: [...loadedPaths].sort()
  };
}

export async function verifyBrowserAccessibility({ chromePath } = {}) {
  const staticReceipt = verifyAccessibility();
  invariant(
    staticReceipt.status === "STATIC_SOURCE_PASS" &&
      staticReceipt.finalReleaseReady === false &&
      Object.values(staticReceipt.checks).every((value) => value === true),
    "BROWSER_ACCESSIBILITY_STATIC_PREREQUISITE"
  );
  const browser = resolveChrome(chromePath);
  const profileDir = fs.mkdtempSync(
    path.join(os.tmpdir(), "tideproof-browser-accessibility-")
  );
  const { server, origin } = await startServer();
  const chrome = spawn(
    browser.command,
    [
      "--headless=new",
      "--disable-background-networking",
      "--disable-component-update",
      "--disable-default-apps",
      "--disable-extensions",
      "--disable-features=Translate",
      "--disable-gpu",
      "--disable-sync",
      "--metrics-recording-only",
      "--mute-audio",
      "--no-default-browser-check",
      "--no-first-run",
      "--remote-debugging-address=127.0.0.1",
      "--remote-debugging-port=0",
      `--user-data-dir=${profileDir}`,
      "--window-size=1440,900",
      "about:blank"
    ],
    { stdio: "ignore", windowsHide: true }
  );
  let client;
  try {
    const { port } = await waitForDevTools(profileDir, chrome);
    const page = await waitForPageTarget(port);
    client = new CdpClient(page.webSocketDebuggerUrl);
    const snapshot = await collectBrowserSnapshot(client, origin);
    validateBrowserSnapshot(snapshot);
    return {
      schemaVersion: SCHEMA,
      status: "LOCAL_BROWSER_PASS",
      finalReleaseReady: false,
      standardTarget: STANDARD_TARGET,
      browser: browser.version,
      staticPrerequisite: {
        status: staticReceipt.status,
        rightsManifestSha256: staticReceipt.rightsManifestSha256,
        reviewedFiles: staticReceipt.reviewedFiles
      },
      summary: {
        loadedPaths: snapshot.loadedPaths.length,
        expectedOmissions: snapshot.expectedOmissions.length,
        accessibilityNodes: snapshot.ax.exposedNodeCount,
        accessibilityHeadings: snapshot.ax.headingCount,
        accessibilityLinks: snapshot.ax.linkCount,
        accessibilityButtons: snapshot.ax.buttons.length,
        localInvariants: snapshot.document.invariantCount,
        desktopViewport: "1440x900",
        mobileViewport: "390x844@2x"
      },
      checks: {
        staticRightsBoundPrerequisite: true,
        localHttpSurfaceLoaded: true,
        browserErrorsAbsent: true,
        accessibilityTreeNamed: true,
        presenterControlsNamed: true,
        verifiedStateRendered: true,
        skipNavigationRendered: true,
        keyboardPresenterPathRendered: true,
        presenterStateTransitionsRendered: true,
        reducedMotionRendered: true,
        mobileReflowRendered: true
      },
      remainingRequirements: [...REMAINING_REQUIREMENTS],
      claimBoundary:
        "This receipt runs the rights-bound current source in an isolated local headless Chromium process, inspects the rendered accessibility tree, exercises the keyboard presenter path and state controls, emulates reduced motion and a 390-pixel mobile viewport, and rejects browser, network, naming, or reflow failures. It is not a WCAG conformance claim, a maintained rules-engine scan, assistive-technology testing, human usability review, or proof of the exact deployed public release."
    };
  } finally {
    client?.close();
    await stopChrome(chrome);
    await stopServer(server);
    fs.rmSync(profileDir, { recursive: true, force: true });
  }
}

export const __test = Object.freeze({
  EXPECTED_BUTTON_NAMES,
  REMAINING_REQUIREMENTS,
  SCHEMA,
  STANDARD_TARGET,
  formatUnexpectedFailure,
  parseDevToolsActivePort,
  summarizeAxTree,
  validateBrowserSnapshot
});

const startedDirectly =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (startedDirectly) {
  verifyBrowserAccessibility()
    .then((receipt) => {
      process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
    })
    .catch((error) => {
      const message = String(error?.message ?? error);
      const code = /^BROWSER_ACCESSIBILITY_[A-Z0-9_]{1,120}$/.test(message)
        ? message
        : "BROWSER_ACCESSIBILITY_FAILED";
      process.stderr.write(`${code}\n`);
      if (code === "BROWSER_ACCESSIBILITY_FAILED") {
        process.stderr.write(
          `BROWSER_ACCESSIBILITY_DIAGNOSTIC ${formatUnexpectedFailure(error)}\n`
        );
      }
      process.exitCode = 1;
    });
}
