import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { verifyReleaseRights } from "./verify-release-rights.js";

const DEFAULT_ROOT = fileURLToPath(new URL("..", import.meta.url));
const SCHEMA = "tideproof.accessibility-static.v1";
const STANDARD_TARGET = "WCAG_2_2_AA";
const REQUIRED_FILES = Object.freeze({
  "architecture-svg": "docs/media/architecture.svg",
  "browser-app": "web/app.js",
  "browser-document": "web/index.html",
  "browser-styles": "web/styles.css"
});
const CONTRAST_PAIRS = Object.freeze([
  ["blue-on-page", "blue", "page", 4.5],
  ["blue-on-surface", "blue", "surface", 4.5],
  ["focus-on-page", "focus", "page", 3],
  ["green-on-green-surface", "green", "green-surface", 4.5],
  ["ink-on-page", "ink", "page", 4.5],
  ["ink-on-surface", "ink", "surface", 4.5],
  ["line-strong-on-surface", "line-strong", "surface", 3],
  ["muted-on-page", "muted", "page", 4.5],
  ["muted-on-surface", "muted", "surface", 4.5],
  ["red-on-red-surface", "red", "red-surface", 4.5],
  ["amber-on-amber-surface", "amber", "amber-surface", 4.5]
]);
const REMAINING_REQUIREMENTS = Object.freeze([
  "Automated browser accessibility scan on the exact public release.",
  "Keyboard-only, 200% zoom, mobile reflow, and reduced-motion private review on the exact public release.",
  "Screen-reader review on the exact public release."
]);
const HEX_64 = /^[0-9a-f]{64}$/;

function assert(condition, code) {
  if (!condition) {
    throw new Error(code);
  }
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function readRegularFile(rootDir, relativePath, code) {
  assert(
    typeof relativePath === "string" &&
      relativePath.length > 0 &&
      relativePath === relativePath.replaceAll("\\", "/") &&
      !path.posix.isAbsolute(relativePath) &&
      relativePath.split("/").every((part) => part !== "" && part !== ".."),
    code
  );
  let current = rootDir;
  let stat;
  for (const part of relativePath.split("/")) {
    current = path.join(current, part);
    try {
      stat = fs.lstatSync(current);
    } catch {
      throw new Error(code);
    }
    assert(!stat.isSymbolicLink(), code);
  }
  assert(stat?.isFile(), code);
  return fs.readFileSync(current);
}

function parseCanonicalJson(bytes, code) {
  const source = bytes.toString("utf8");
  let value;
  try {
    value = JSON.parse(source);
  } catch {
    throw new Error(code);
  }
  assert(`${JSON.stringify(value, null, 2)}\n` === source, code);
  return value;
}

function tags(source, tagName) {
  return [
    ...source.matchAll(new RegExp(`<${tagName}\\b[^>]*>`, "gi"))
  ].map((match) => match[0]);
}

function attributes(tag) {
  const values = new Map();
  for (const match of tag.matchAll(
    /\s([A-Za-z_:][A-Za-z0-9_.:-]*)(?:\s*=\s*(["'])(.*?)\2)?/g
  )) {
    const name = match[1].toLowerCase();
    assert(!values.has(name), "ACCESSIBILITY_DUPLICATE_ATTRIBUTE");
    values.set(name, match[2] ? match[3] : true);
  }
  return values;
}

function textContent(tag) {
  return tag
    .replace(/<[^>]+>/g, " ")
    .replace(/&(?:amp|apos|gt|lt|quot);/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function allOpeningTags(source) {
  return [...source.matchAll(/<[A-Za-z][^>]*>/g)].map((match) => match[0]);
}

function validateRightsBinding(rootDir, verifyRights) {
  const rights = verifyRights({ rootDir });
  assert(
    rights?.schemaVersion ===
      "tideproof.release-rights-verification.v1" &&
      rights.status === "CURRENT_SURFACES_PASS" &&
      rights.finalReleaseReady === false &&
      rights.manifestPath === "docs/media/RIGHTS_MANIFEST.json" &&
      HEX_64.test(rights.manifestSha256) &&
      rights.checks &&
      Object.values(rights.checks).every((value) => value === true),
    "ACCESSIBILITY_RIGHTS_RECEIPT"
  );
  const manifestBytes = readRegularFile(
    rootDir,
    rights.manifestPath,
    "ACCESSIBILITY_RIGHTS_MANIFEST"
  );
  assert(
    sha256(manifestBytes) === rights.manifestSha256,
    "ACCESSIBILITY_RIGHTS_MANIFEST_DIGEST"
  );
  const manifest = parseCanonicalJson(
    manifestBytes,
    "ACCESSIBILITY_RIGHTS_MANIFEST_JSON"
  );
  assert(
    Array.isArray(manifest.distributedFiles),
    "ACCESSIBILITY_RIGHTS_DISTRIBUTED"
  );
  const byPath = new Map(
    manifest.distributedFiles.map((entry) => [entry?.path, entry])
  );
  const files = [];
  for (const [id, relativePath] of Object.entries(REQUIRED_FILES)) {
    const entry = byPath.get(relativePath);
    const bytes = readRegularFile(
      rootDir,
      relativePath,
      "ACCESSIBILITY_SOURCE_FILE"
    );
    assert(
      entry?.id === id &&
        entry.rightsState === "CLEARED_CURRENT" &&
        HEX_64.test(entry.sha256) &&
        sha256(bytes) === entry.sha256,
      "ACCESSIBILITY_SOURCE_DIGEST"
    );
    files.push({ id, path: relativePath, sha256: entry.sha256, bytes });
  }
  return {
    rights,
    files: files.sort((left, right) => left.id.localeCompare(right.id))
  };
}

function validateDocument(source) {
  assert(/^<!doctype html>\n/i.test(source), "ACCESSIBILITY_DOCTYPE");
  const htmlTags = tags(source, "html");
  assert(
    htmlTags.length === 1 && attributes(htmlTags[0]).get("lang") === "en",
    "ACCESSIBILITY_LANGUAGE"
  );
  assert(
    /<meta\s+charset="utf-8">/i.test(source) &&
      /name="viewport"\s+content="width=device-width, initial-scale=1"/i.test(
        source
      ) &&
      !/(?:maximum-scale|minimum-scale|user-scalable)/i.test(source) &&
      tags(source, "title").length === 1 &&
      /<meta[\s\S]*?name="description"[\s\S]*?content="[^"]+"[\s\S]*?>/i.test(
        source
      ),
    "ACCESSIBILITY_METADATA"
  );
  assert(
    !/<(?:blink|marquee)\b/i.test(source) &&
      !/<meta\b[^>]*http-equiv="refresh"/i.test(source) &&
      !/\b(?:accesskey|autofocus|contenteditable)\b/i.test(source),
    "ACCESSIBILITY_UNSAFE_DOCUMENT_BEHAVIOR"
  );

  const openingTags = allOpeningTags(source);
  const idValues = openingTags
    .map((tag) => attributes(tag).get("id"))
    .filter((value) => typeof value === "string");
  const ids = new Set(idValues);
  assert(
    ids.size === idValues.length &&
      idValues.every((value) => /^[A-Za-z][A-Za-z0-9_.:-]*$/.test(value)),
    "ACCESSIBILITY_IDS"
  );
  for (const tag of openingTags) {
    const values = attributes(tag);
    for (const name of ["aria-controls", "aria-describedby", "aria-labelledby"]) {
      const references = values.get(name);
      if (typeof references !== "string") {
        continue;
      }
      assert(
        references
          .split(/\s+/)
          .every((reference) => reference.length > 0 && ids.has(reference)),
        "ACCESSIBILITY_ARIA_REFERENCE"
      );
    }
    const tabIndex = values.get("tabindex");
    assert(
      tabIndex === undefined || tabIndex === "0" || tabIndex === "-1",
      "ACCESSIBILITY_TABINDEX"
    );
  }

  const headings = [
    ...source.matchAll(/<h([1-6])\b[^>]*>/gi)
  ].map((match) => Number(match[1]));
  assert(
    headings.length > 0 &&
      headings[0] === 1 &&
      headings.filter((level) => level === 1).length === 1 &&
      headings.every(
        (level, index) => index === 0 || level <= headings[index - 1] + 1
      ),
    "ACCESSIBILITY_HEADING_ORDER"
  );
  assert(tags(source, "main").length === 1, "ACCESSIBILITY_MAIN_LANDMARK");
  for (const section of tags(source, "section")) {
    const label = attributes(section).get("aria-labelledby");
    assert(
      typeof label === "string" && ids.has(label),
      "ACCESSIBILITY_SECTION_LABEL"
    );
  }
  for (const tag of openingTags.filter(
    (entry) => attributes(entry).get("role") === "region"
  )) {
    const values = attributes(tag);
    assert(
      typeof values.get("aria-label") === "string" ||
        typeof values.get("aria-labelledby") === "string",
      "ACCESSIBILITY_REGION_LABEL"
    );
  }

  const anchors = tags(source, "a");
  const anchorBlocks = [
    ...source.matchAll(/<a\b[^>]*>[\s\S]*?<\/a>/gi)
  ].map((match) => match[0]);
  assert(
    anchorBlocks.length === anchors.length &&
      anchorBlocks.every((block) => textContent(block).length > 0),
    "ACCESSIBILITY_LINK_NAME"
  );
  const skipLinks = anchors.filter((tag) =>
    String(attributes(tag).get("class") ?? "")
      .split(/\s+/)
      .includes("skip-link")
  );
  assert(
    skipLinks.length === 1 &&
      attributes(skipLinks[0]).get("href") === "#judge-path" &&
      /Skip to the judge path/.test(source) &&
      ids.has("judge-path") &&
      /id="judge-path"[\s\S]*?tabindex="-1"/.test(source),
    "ACCESSIBILITY_SKIP_LINK"
  );
  for (const anchor of anchors) {
    const values = attributes(anchor);
    const href = values.get("href");
    assert(
      typeof href === "string" && href.length > 0,
      "ACCESSIBILITY_LINK_HREF"
    );
    if (href.startsWith("#")) {
      assert(ids.has(href.slice(1)), "ACCESSIBILITY_FRAGMENT_TARGET");
    }
    if (/^https:\/\//i.test(href)) {
      assert(
        String(values.get("rel") ?? "").split(/\s+/).includes("noreferrer"),
        "ACCESSIBILITY_EXTERNAL_LINK"
      );
    }
  }

  const images = tags(source, "img");
  assert(images.length > 0, "ACCESSIBILITY_IMAGE_SET");
  for (const image of images) {
    const values = attributes(image);
    assert(
      typeof values.get("alt") === "string" &&
        values.get("alt").trim().length > 0 &&
        /^[1-9][0-9]*$/.test(values.get("width")) &&
        /^[1-9][0-9]*$/.test(values.get("height")),
      "ACCESSIBILITY_IMAGE_ALTERNATIVE"
    );
  }

  const buttons = tags(source, "button");
  const buttonBlocks = [
    ...source.matchAll(/<button\b[^>]*>[\s\S]*?<\/button>/gi)
  ].map((match) => match[0]);
  assert(
    buttons.length === 7 &&
      buttonBlocks.length === buttons.length &&
      buttonBlocks.every((block) => textContent(block).length > 0),
    "ACCESSIBILITY_CONTROL_SET"
  );
  for (const button of buttons) {
    const values = attributes(button);
    assert(
      values.get("type") === "button" &&
        values.get("disabled") === true &&
        values.get("aria-controls") === "step-stage",
      "ACCESSIBILITY_INITIAL_CONTROL"
    );
  }
  assert(
    buttons.filter((button) => attributes(button).has("data-act")).length ===
      3 &&
      buttons.filter(
        (button) => attributes(button).get("id") === "play-pause"
      ).length === 1,
    "ACCESSIBILITY_PRESENTER_CONTROLS"
  );
  assert(
    /id="load-status"[\s\S]*?role="status"[\s\S]*?aria-live="polite"[\s\S]*?aria-atomic="true"/.test(
      source
    ),
    "ACCESSIBILITY_LIVE_STATUS"
  );
  return {
    headingCount: headings.length,
    imageCount: images.length,
    buttonCount: buttons.length,
    landmarkSectionCount: tags(source, "section").length
  };
}

function cssToken(source, name) {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const matches = [
    ...source.matchAll(new RegExp(`--${escaped}\\s*:\\s*(#[0-9a-fA-F]{6})\\s*;`, "g"))
  ];
  assert(matches.length === 1, "ACCESSIBILITY_COLOR_TOKEN");
  return matches[0][1].toLowerCase();
}

function relativeLuminance(hex) {
  const channels = hex
    .slice(1)
    .match(/../g)
    .map((value) => Number.parseInt(value, 16) / 255)
    .map((value) =>
      value <= 0.04045
        ? value / 12.92
        : ((value + 0.055) / 1.055) ** 2.4
    );
  return (
    0.2126 * channels[0] +
    0.7152 * channels[1] +
    0.0722 * channels[2]
  );
}

function contrastRatio(foreground, background) {
  const first = relativeLuminance(foreground);
  const second = relativeLuminance(background);
  return (Math.max(first, second) + 0.05) / (Math.min(first, second) + 0.05);
}

function validateStylesheet(source) {
  assert(
    /:focus-visible\s*\{[^}]*outline:\s*3px solid var\(--focus\);[^}]*outline-offset:\s*4px;/s.test(
      source
    ) &&
      !/outline\s*:\s*(?:0|none)\b/i.test(source),
    "ACCESSIBILITY_FOCUS_VISIBLE"
  );
  assert(
    /\.skip-link:focus\s*\{[^}]*transform:\s*translateY\(0\);/s.test(source),
    "ACCESSIBILITY_SKIP_FOCUS"
  );
  assert(
    /@media \(prefers-reduced-motion: reduce\)\s*\{\s*html\s*\{\s*scroll-behavior:\s*auto;\s*\}\s*\}/s.test(
      source
    ) &&
      !/(?:animation|transition)\s*:/i.test(source),
    "ACCESSIBILITY_REDUCED_MOTION"
  );
  assert(
    /\.sr-only\s*\{[^}]*width:\s*1px;[^}]*height:\s*1px;[^}]*overflow:\s*hidden;[^}]*clip:\s*rect\(0, 0, 0, 0\);[^}]*white-space:\s*nowrap;/s.test(
      source
    ),
    "ACCESSIBILITY_SCREEN_READER_TEXT"
  );
  assert(
    /\.act-nav button,[\s\S]*?\.load-error button\s*\{[^}]*min-height:\s*2\.75rem;/s.test(
      source
    ),
    "ACCESSIBILITY_TOUCH_TARGET"
  );
  assert(
    /@media \(max-width: 50rem\)/.test(source) &&
      /@media \(max-width: 34rem\)/.test(source) &&
      /\.architecture-shell\s*\{[^}]*overflow-x:\s*auto;/s.test(source) &&
      /body\s*\{[^}]*min-width:\s*0;/s.test(source),
    "ACCESSIBILITY_REFLOW_GUARD"
  );

  const contrast = CONTRAST_PAIRS.map(
    ([id, foregroundToken, backgroundToken, minimumRatio]) => {
      const foreground = cssToken(source, foregroundToken);
      const background = cssToken(source, backgroundToken);
      const ratio = Number(contrastRatio(foreground, background).toFixed(3));
      assert(ratio >= minimumRatio, "ACCESSIBILITY_CONTRAST");
      return {
        id,
        foregroundToken,
        backgroundToken,
        foreground,
        background,
        minimumRatio,
        ratio
      };
    }
  );
  return contrast.sort((left, right) => left.id.localeCompare(right.id));
}

function validateScript(source) {
  assert(
    !/\.(?:innerHTML|outerHTML)\s*=|insertAdjacentHTML\s*\(|document\.write\s*\(|\beval\s*\(|\bnew\s+Function\b/.test(
      source
    ) &&
      source.includes(".textContent =") &&
      source.includes(".replaceChildren("),
    "ACCESSIBILITY_SAFE_DYNAMIC_CONTENT"
  );
  assert(
    source.includes('document.addEventListener("keydown"') &&
      ["ArrowRight", "ArrowLeft", " ", "Home"].every((key) =>
        source.includes(`event.key === ${JSON.stringify(key)}`)
      ) &&
      source.includes("event.target === stage || event.target === judgePath") &&
      source.includes("stage.focus({ preventScroll: true });"),
    "ACCESSIBILITY_KEYBOARD_PATH"
  );
  assert(
    source.includes('document.addEventListener("visibilitychange"') &&
      source.includes("document.hidden && playTimer") &&
      source.includes(
        '"Automatic presentation paused while this page is hidden."'
      ) &&
      source.includes("window.setInterval(") &&
      source.includes("8_500"),
    "ACCESSIBILITY_HIDDEN_PAGE_PAUSE"
  );
  assert(
    source.includes(
      'playButton.setAttribute("aria-pressed", "false");'
    ) &&
      source.includes(
        'playButton.setAttribute("aria-pressed", "true");'
      ) &&
      source.includes(
        'state.textContent = passed ? "CHECK PASSED" : "CHECK FAILED";'
      ) &&
      source.includes("status.textContent ="),
    "ACCESSIBILITY_STATE_ANNOUNCEMENT"
  );
  assert(
    source.includes("previousButton.disabled = false;") &&
      source.includes("nextButton.disabled = false;") &&
      source.includes("playButton.disabled = false;") &&
      source.includes("restartButton.disabled = false;") &&
      source.includes("previousButton.disabled = true;") &&
      source.includes("nextButton.disabled = true;") &&
      source.includes("playButton.disabled = true;") &&
      source.includes("restartButton.disabled = true;"),
    "ACCESSIBILITY_FAIL_CLOSED_CONTROLS"
  );
}

function validateArchitecture(source) {
  const svg = tags(source, "svg");
  assert(svg.length === 1, "ACCESSIBILITY_SVG_ROOT");
  const root = attributes(svg[0]);
  assert(
    root.get("role") === "img" &&
      root.get("aria-labelledby") === "title description" &&
      root.get("width") === "2200" &&
      root.get("height") === "720" &&
      root.get("viewbox") === "0 0 1100 360",
    "ACCESSIBILITY_SVG_SEMANTICS"
  );
  assert(
    /<title id="title">[^<]+<\/title>/.test(source) &&
      /<desc id="description">[\s\S]*?\S[\s\S]*?<\/desc>/.test(source),
    "ACCESSIBILITY_SVG_ALTERNATIVE"
  );
}

export function verifyAccessibility({
  rootDir = DEFAULT_ROOT,
  verifyRights = verifyReleaseRights
} = {}) {
  const resolvedRoot = path.resolve(rootDir);
  const binding = validateRightsBinding(resolvedRoot, verifyRights);
  const byId = new Map(binding.files.map((file) => [file.id, file]));
  const documentResult = validateDocument(
    byId.get("browser-document").bytes.toString("utf8")
  );
  const contrast = validateStylesheet(
    byId.get("browser-styles").bytes.toString("utf8")
  );
  validateScript(byId.get("browser-app").bytes.toString("utf8"));
  validateArchitecture(
    byId.get("architecture-svg").bytes.toString("utf8")
  );

  return {
    schemaVersion: SCHEMA,
    status: "STATIC_SOURCE_PASS",
    finalReleaseReady: false,
    standardTarget: STANDARD_TARGET,
    rightsManifestSha256: binding.rights.manifestSha256,
    reviewedFiles: binding.files.map(({ id, path: filePath, sha256: digest }) => ({
      id,
      path: filePath,
      sha256: digest
    })),
    contrast,
    summary: documentResult,
    remainingRequirements: [...REMAINING_REQUIREMENTS],
    checks: {
      exactRightsBoundSources: true,
      documentLanguageAndMetadata: true,
      landmarksAndHeadingOrder: true,
      skipNavigation: true,
      uniqueIdsAndAriaReferences: true,
      namedImagesAndControls: true,
      controlsFailClosedDuringLoad: true,
      keyboardPresenterPath: true,
      liveStatusAnnouncements: true,
      hiddenPageAutoplayPause: true,
      focusVisibility: true,
      reducedMotionSourceSupport: true,
      responsiveReflowGuards: true,
      minimumControlHeight: true,
      contrastPairsPass: true,
      unsafeDynamicHtmlAbsent: true,
      textualStatusLabelsPresent: true,
      architectureAlternativePresent: true
    },
    claimBoundary:
      "This deterministic receipt binds the current reviewed browser source and architecture SVG to the current-surface rights manifest, verifies targeted semantic, keyboard, focus, motion, reflow, dynamic-content, and contrast rules, and records no failure in those static checks. It is not a WCAG conformance claim and does not replace an automated browser scan, assistive-technology testing, or exact-release human review."
  };
}

async function main() {
  assert(process.argv.length === 2, "ACCESSIBILITY_ARGUMENT");
  process.stdout.write(`${JSON.stringify(verifyAccessibility(), null, 2)}\n`);
}

const startedDirectly =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (startedDirectly) {
  main().catch((error) => {
    const message = String(error?.message ?? "");
    const code = /^ACCESSIBILITY_[A-Z0-9_]{1,120}$/.test(message)
      ? message
      : "ACCESSIBILITY_UNKNOWN";
    process.stderr.write(`TIDEPROOF_ACCESSIBILITY_FAILED:${code}\n`);
    process.exitCode = 1;
  });
}

export const __test = Object.freeze({
  CONTRAST_PAIRS,
  REMAINING_REQUIREMENTS,
  REQUIRED_FILES,
  SCHEMA,
  STANDARD_TARGET,
  contrastRatio
});
