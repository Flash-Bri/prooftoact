import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  __test,
  verifyAccessibility
} from "../scripts/verify-accessibility.js";

const ROOT = fileURLToPath(new URL("..", import.meta.url));

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function writeCanonicalJson(filePath, value) {
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function fixture() {
  const rootDir = fs.mkdtempSync(
    path.join(os.tmpdir(), "tideproof-accessibility-")
  );
  const paths = [
    ...Object.values(__test.REQUIRED_FILES),
    "docs/media/RIGHTS_MANIFEST.json"
  ];
  for (const relativePath of paths) {
    const destination = path.join(rootDir, relativePath);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.copyFileSync(path.join(ROOT, relativePath), destination);
  }
  const manifestPath = path.join(
    rootDir,
    "docs/media/RIGHTS_MANIFEST.json"
  );
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  for (const relativePath of Object.values(__test.REQUIRED_FILES)) {
    const entry = manifest.distributedFiles.find(
      (candidate) => candidate.path === relativePath
    );
    assert(entry, `missing rights entry for ${relativePath}`);
    entry.sha256 = sha256(fs.readFileSync(path.join(rootDir, relativePath)));
  }
  writeCanonicalJson(manifestPath, manifest);

  return {
    rootDir,
    manifestPath,
    verifyRights() {
      return {
        schemaVersion: "tideproof.release-rights-verification.v1",
        status: "CURRENT_SURFACES_PASS",
        finalReleaseReady: false,
        manifestPath: "docs/media/RIGHTS_MANIFEST.json",
        manifestSha256: sha256(fs.readFileSync(manifestPath)),
        checks: { fixtureRightsPass: true }
      };
    },
    cleanup() {
      fs.rmSync(rootDir, { recursive: true, force: true });
    }
  };
}

function refreshDigest(current, relativePath) {
  const manifest = JSON.parse(
    fs.readFileSync(current.manifestPath, "utf8")
  );
  const entry = manifest.distributedFiles.find(
    (candidate) => candidate.path === relativePath
  );
  assert(entry, `missing rights entry for ${relativePath}`);
  entry.sha256 = sha256(
    fs.readFileSync(path.join(current.rootDir, relativePath))
  );
  writeCanonicalJson(current.manifestPath, manifest);
}

function mutate(current, relativePath, before, after) {
  const filePath = path.join(current.rootDir, relativePath);
  const source = fs.readFileSync(filePath, "utf8");
  assert(source.includes(before), `missing mutation source: ${before}`);
  fs.writeFileSync(filePath, source.replace(before, after));
  refreshDigest(current, relativePath);
}

function verifyFixture(current) {
  return verifyAccessibility({
    rootDir: current.rootDir,
    verifyRights: current.verifyRights
  });
}

test("current browser source passes the bounded static accessibility gate", () => {
  const receipt = verifyAccessibility({ rootDir: ROOT });

  assert.equal(receipt.schemaVersion, __test.SCHEMA);
  assert.equal(receipt.status, "STATIC_SOURCE_PASS");
  assert.equal(receipt.finalReleaseReady, false);
  assert.equal(receipt.standardTarget, __test.STANDARD_TARGET);
  assert.equal(receipt.reviewedFiles.length, 4);
  assert.equal(receipt.contrast.length, __test.CONTRAST_PAIRS.length);
  assert.equal(receipt.summary.headingCount, 9);
  assert.equal(receipt.summary.imageCount, 1);
  assert.equal(receipt.summary.buttonCount, 7);
  assert.equal(receipt.summary.landmarkSectionCount, 5);
  assert.deepEqual(
    receipt.remainingRequirements,
    __test.REMAINING_REQUIREMENTS
  );
  assert.equal(
    Object.values(receipt.checks).every((value) => value === true),
    true
  );
});

test("accessibility gate rejects source bytes not bound by rights", () => {
  const current = fixture();
  try {
    fs.appendFileSync(
      path.join(current.rootDir, "web/index.html"),
      "\n"
    );
    assert.throws(
      () => verifyFixture(current),
      /ACCESSIBILITY_SOURCE_DIGEST/
    );
  } finally {
    current.cleanup();
  }
});

test("accessibility gate rejects zoom restrictions and heading skips", () => {
  const zoom = fixture();
  try {
    mutate(
      zoom,
      "web/index.html",
      "width=device-width, initial-scale=1",
      "width=device-width, initial-scale=1, user-scalable=no"
    );
    assert.throws(
      () => verifyFixture(zoom),
      /ACCESSIBILITY_METADATA/
    );
  } finally {
    zoom.cleanup();
  }

  const heading = fixture();
  try {
    mutate(heading, "web/index.html", "<h2 id=", "<h4 id=");
    assert.throws(
      () => verifyFixture(heading),
      /ACCESSIBILITY_HEADING_ORDER/
    );
  } finally {
    heading.cleanup();
  }
});

test("accessibility gate rejects invalid focus order and missing references", () => {
  const tabIndex = fixture();
  try {
    mutate(tabIndex, "web/index.html", 'tabindex="0"', 'tabindex="2"');
    assert.throws(
      () => verifyFixture(tabIndex),
      /ACCESSIBILITY_TABINDEX/
    );
  } finally {
    tabIndex.cleanup();
  }

  const reference = fixture();
  try {
    mutate(
      reference,
      "web/index.html",
      'aria-controls="step-stage"',
      'aria-controls="missing-stage"'
    );
    assert.throws(
      () => verifyFixture(reference),
      /ACCESSIBILITY_ARIA_REFERENCE/
    );
  } finally {
    reference.cleanup();
  }
});

test("accessibility gate requires inert loading controls and image alternatives", () => {
  const controls = fixture();
  try {
    mutate(
      controls,
      "web/index.html",
      "            disabled\n          >",
      "          >"
    );
    assert.throws(
      () => verifyFixture(controls),
      /ACCESSIBILITY_INITIAL_CONTROL/
    );
  } finally {
    controls.cleanup();
  }

  const image = fixture();
  try {
    mutate(
      image,
      "web/index.html",
      'alt="ProofToAct trust boundaries:',
      'alt="" data-note="ProofToAct trust boundaries:'
    );
    assert.throws(
      () => verifyFixture(image),
      /ACCESSIBILITY_IMAGE_ALTERNATIVE/
    );
  } finally {
    image.cleanup();
  }
});

test("accessibility gate rejects low contrast and focus suppression", () => {
  const contrast = fixture();
  try {
    mutate(
      contrast,
      "web/styles.css",
      "--muted: #bdc8c0;",
      "--muted: #202823;"
    );
    assert.throws(
      () => verifyFixture(contrast),
      /ACCESSIBILITY_CONTRAST/
    );
  } finally {
    contrast.cleanup();
  }

  const focus = fixture();
  try {
    mutate(
      focus,
      "web/styles.css",
      "outline: 3px solid var(--focus);",
      "outline: none;"
    );
    assert.throws(
      () => verifyFixture(focus),
      /ACCESSIBILITY_FOCUS_VISIBLE/
    );
  } finally {
    focus.cleanup();
  }
});

test("accessibility gate rejects motion, keyboard, and hidden-page regressions", () => {
  const motion = fixture();
  try {
    mutate(
      motion,
      "web/styles.css",
      "scroll-behavior: auto;",
      "scroll-behavior: smooth;"
    );
    assert.throws(
      () => verifyFixture(motion),
      /ACCESSIBILITY_REDUCED_MOTION/
    );
  } finally {
    motion.cleanup();
  }

  const keyboard = fixture();
  try {
    mutate(keyboard, "web/app.js", 'event.key === "Home"', 'event.key === "End"');
    assert.throws(
      () => verifyFixture(keyboard),
      /ACCESSIBILITY_KEYBOARD_PATH/
    );
  } finally {
    keyboard.cleanup();
  }

  const visibility = fixture();
  try {
    mutate(
      visibility,
      "web/app.js",
      'document.addEventListener("visibilitychange"',
      'document.addEventListener("pagechange"'
    );
    assert.throws(
      () => verifyFixture(visibility),
      /ACCESSIBILITY_HIDDEN_PAGE_PAUSE/
    );
  } finally {
    visibility.cleanup();
  }
});

test("accessibility gate rejects unsafe dynamic HTML and SVG name loss", () => {
  const dynamicHtml = fixture();
  try {
    const appPath = path.join(dynamicHtml.rootDir, "web/app.js");
    fs.appendFileSync(appPath, '\nstage.innerHTML = "unsafe";\n');
    refreshDigest(dynamicHtml, "web/app.js");
    assert.throws(
      () => verifyFixture(dynamicHtml),
      /ACCESSIBILITY_SAFE_DYNAMIC_CONTENT/
    );
  } finally {
    dynamicHtml.cleanup();
  }

  const svg = fixture();
  try {
    mutate(
      svg,
      "docs/media/architecture.svg",
      'role="img"',
      'role="presentation"'
    );
    assert.throws(
      () => verifyFixture(svg),
      /ACCESSIBILITY_SVG_SEMANTICS/
    );
  } finally {
    svg.cleanup();
  }
});

test("contrast helper follows the WCAG relative-luminance formula", () => {
  assert.equal(Number(__test.contrastRatio("#000000", "#ffffff").toFixed(3)), 21);
  assert.equal(Number(__test.contrastRatio("#ffffff", "#ffffff").toFixed(3)), 1);
});
