import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  __test,
  verifyReleaseRights
} from "../scripts/verify-release-rights.js";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const FIXTURE_FILES = Object.freeze([
  "CLAIMS.md",
  "README.md",
  "RENAME_MIGRATION_MANIFEST.json",
  "docs/RENAME_MIGRATION.md",
  "docs/VISUAL_RELEASE_SYSTEM.md",
  "docs/media/RIGHTS.md",
  "docs/media/RIGHTS_MANIFEST.json",
  "docs/media/architecture.png",
  "docs/media/architecture.svg",
  "evidence/architecture-asset-rename-2026-08-03.md",
  "evidence/gate1-ambiguity-2026-07-30.md",
  "evidence/gate1-authority-2026-07-30.md",
  "evidence/gate1-recovery-broker-2026-07-30.md",
  "infra/aws/lambda/demo.js",
  "scripts/gate2-public-demo-verify.js",
  "src/cloud/public-demo-verifier.js",
  "src/cloud/public-demo.js",
  "src/server.js",
  "web/app.js",
  "web/index.html",
  "web/styles.css"
]);

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function copyFixture() {
  const rootDir = fs.mkdtempSync(
    path.join(os.tmpdir(), "tideproof-release-rights-")
  );
  for (const relativePath of FIXTURE_FILES) {
    const destination = path.join(rootDir, relativePath);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.copyFileSync(path.join(ROOT, relativePath), destination);
  }
  return {
    rootDir,
    trackedFiles: [...FIXTURE_FILES],
    cleanup() {
      fs.rmSync(rootDir, { recursive: true, force: true });
    }
  };
}

function manifestPath(rootDir) {
  return path.join(rootDir, __test.MANIFEST_PATH);
}

function readManifest(rootDir) {
  return JSON.parse(fs.readFileSync(manifestPath(rootDir), "utf8"));
}

function writeManifest(rootDir, manifest) {
  fs.writeFileSync(
    manifestPath(rootDir),
    `${JSON.stringify(manifest, null, 2)}\n`
  );
}

function refreshControl(rootDir, relativePath) {
  const manifest = readManifest(rootDir);
  const control = manifest.controlFiles.find(
    (entry) => entry.path === relativePath
  );
  assert(control, `missing control ${relativePath}`);
  control.sha256 = sha256(
    fs.readFileSync(path.join(rootDir, relativePath))
  );
  writeManifest(rootDir, manifest);
}

function refreshDistributed(rootDir, relativePath) {
  const manifest = readManifest(rootDir);
  const entry = manifest.distributedFiles.find(
    (candidate) => candidate.path === relativePath
  );
  assert(entry, `missing distributed file ${relativePath}`);
  const nextDigest = sha256(
    fs.readFileSync(path.join(rootDir, relativePath))
  );
  const ledgerPath = path.join(rootDir, "docs/media/RIGHTS.md");
  const ledger = fs.readFileSync(ledgerPath, "utf8");
  assert(ledger.includes(entry.sha256));
  fs.writeFileSync(ledgerPath, ledger.replaceAll(entry.sha256, nextDigest));
  entry.sha256 = nextDigest;
  const ledgerControl = manifest.controlFiles.find(
    (control) => control.path === "docs/media/RIGHTS.md"
  );
  ledgerControl.sha256 = sha256(fs.readFileSync(ledgerPath));
  writeManifest(rootDir, manifest);
}

function verifyFixture(fixture) {
  return verifyReleaseRights({
    rootDir: fixture.rootDir,
    trackedFiles: fixture.trackedFiles
  });
}

test("current rights inventory passes without claiming final release", () => {
  const receipt = verifyReleaseRights({ rootDir: ROOT });

  assert.equal(receipt.status, "CURRENT_SURFACES_PASS");
  assert.equal(receipt.finalReleaseReady, false);
  assert.equal(receipt.distributedFileCount, 5);
  assert.equal(receipt.currentClearedFileCount, 5);
  assert.equal(receipt.interimOnlyFileCount, 0);
  assert.equal(receipt.repositoryMediaFileCount, 2);
  assert.equal(receipt.prohibitedSourceDigestCount, 3);
  assert.equal(receipt.checks.awsDistributionBindingsExact, true);
});

test("rights inventory rejects one-byte drift across browser source and media", () => {
  for (const relativePath of [
    "web/app.js",
    "web/index.html",
    "web/styles.css"
  ]) {
    const fixture = copyFixture();
    try {
      fs.appendFileSync(path.join(fixture.rootDir, relativePath), "\n");
      assert.throws(
        () => verifyFixture(fixture),
        /RELEASE_RIGHTS_DISTRIBUTED_DIGEST/
      );
    } finally {
      fixture.cleanup();
    }
  }
});

test("rights inventory rejects extensionless and uncommon media signatures", () => {
  const candidates = [
    {
      relativePath: "notes/preview.bin",
      bytes: Buffer.from([137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 0])
    },
    {
      relativePath: "notes/preview.heic",
      bytes: Buffer.from([0, 0, 0, 24, 102, 116, 121, 112, 104, 101, 105, 99])
    }
  ];
  for (const { relativePath, bytes } of candidates) {
    const fixture = copyFixture();
    try {
      const destination = path.join(fixture.rootDir, relativePath);
      fs.mkdirSync(path.dirname(destination), { recursive: true });
      fs.writeFileSync(destination, bytes);
      fixture.trackedFiles.push(relativePath);
      assert.throws(
        () => verifyFixture(fixture),
        /RELEASE_RIGHTS_MEDIA_INVENTORY/
      );
    } finally {
      fixture.cleanup();
    }
  }
});

test("rights inventory rejects a tracked blocked planned-asset path", () => {
  const fixture = copyFixture();
  try {
    const relativePath = "web/brand/reference.txt";
    const destination = path.join(fixture.rootDir, relativePath);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.writeFileSync(destination, "reference only\n");
    fixture.trackedFiles.push(relativePath);
    assert.throws(
      () => verifyFixture(fixture),
      /RELEASE_RIGHTS_BLOCKED_PATH/
    );
  } finally {
    fixture.cleanup();
  }
});

test("rights inventory rejects cross-row ledger substitution", () => {
  const fixture = copyFixture();
  try {
    const manifest = readManifest(fixture.rootDir);
    const cssDigest = manifest.distributedFiles.find(
      (entry) => entry.path === "web/styles.css"
    ).sha256;
    const htmlDigest = manifest.distributedFiles.find(
      (entry) => entry.path === "web/index.html"
    ).sha256;
    const ledgerPath = path.join(fixture.rootDir, "docs/media/RIGHTS.md");
    const lines = fs.readFileSync(ledgerPath, "utf8").split("\n");
    const changed = lines.map((line) => {
      if (line.startsWith("| `C03` |")) {
        return line.replace(cssDigest, htmlDigest);
      }
      if (line.startsWith("| `C04` |")) {
        return `${line} \`${cssDigest}\``;
      }
      return line;
    });
    fs.writeFileSync(ledgerPath, changed.join("\n"));
    refreshControl(fixture.rootDir, "docs/media/RIGHTS.md");
    assert.throws(
      () => verifyFixture(fixture),
      /RELEASE_RIGHTS_LEDGER_BINDING/
    );
  } finally {
    fixture.cleanup();
  }
});

test("rights inventory rejects remote CSS resources and font drift", () => {
  const mutations = [
    '@import url("https://example.test/theme.css");\n',
    '.unsafe { background-image: url("/extra.png"); }\n',
    '@font-face { font-family: "Remote"; }\n',
    '.unsafe { font: 700 1rem "Comic Sans MS", cursive; }\n'
  ];
  for (const mutation of mutations) {
    const fixture = copyFixture();
    try {
      fs.appendFileSync(
        path.join(fixture.rootDir, "web/styles.css"),
        mutation
      );
      refreshDistributed(fixture.rootDir, "web/styles.css");
      assert.throws(
        () => verifyFixture(fixture),
        /RELEASE_RIGHTS_STYLESHEET_(?:RESOURCE|SHORTHAND)/
      );
    } finally {
      fixture.cleanup();
    }
  }
});

test("rights inventory rejects data media and unsafe navigation schemes", () => {
  const replacements = [
    [
      "</main>",
      '<img src="data:image/png;base64,AA==" alt="unsafe">\n</main>',
      /RELEASE_RIGHTS_BROWSER_ASSETS/
    ],
    [
      "https://github.com/Flash-Bri/prooftoact",
      "//trustagentic.ai",
      /RELEASE_RIGHTS_BROWSER_NAVIGATION/
    ],
    [
      "https://github.com/Flash-Bri/prooftoact",
      "javascript:alert(1)",
      /RELEASE_RIGHTS_BROWSER_NAVIGATION/
    ],
    [
      "https://github.com/Flash-Bri/prooftoact",
      "&#104;ttps://trustagentic.ai",
      /RELEASE_RIGHTS_BROWSER_NAVIGATION/
    ]
  ];
  for (const [before, after, expected] of replacements) {
    const fixture = copyFixture();
    try {
      const htmlPath = path.join(fixture.rootDir, "web/index.html");
      const source = fs.readFileSync(htmlPath, "utf8");
      assert(source.includes(before));
      fs.writeFileSync(htmlPath, source.replace(before, after));
      refreshDistributed(fixture.rootDir, "web/index.html");
      assert.throws(() => verifyFixture(fixture), expected);
    } finally {
      fixture.cleanup();
    }
  }
});

test("rights inventory rejects browser metadata and dynamic media creation", () => {
  const fixture = copyFixture();
  try {
    const htmlPath = path.join(fixture.rootDir, "web/index.html");
    fs.appendFileSync(
      htmlPath,
      '<meta property="og:image" content="https://example.test/preview.png">\n'
    );
    refreshDistributed(fixture.rootDir, "web/index.html");
    assert.throws(
      () => verifyFixture(fixture),
      /RELEASE_RIGHTS_BROWSER_EMBED/
    );
  } finally {
    fixture.cleanup();
  }

  const scriptFixture = copyFixture();
  try {
    fs.appendFileSync(
      path.join(scriptFixture.rootDir, "web/app.js"),
      '\nconst unsafeImage = new Image(); unsafeImage.src = "/extra.png";\n'
    );
    refreshDistributed(scriptFixture.rootDir, "web/app.js");
    assert.throws(
      () => verifyFixture(scriptFixture),
      /RELEASE_RIGHTS_BROWSER_SCRIPT/
    );
  } finally {
    scriptFixture.cleanup();
  }
});

test("rights inventory rejects reference-style and inline README media", () => {
  const additions = [
    "\n![Unreviewed][preview]\n\n[preview]: https://example.test/preview.png\n",
    "\n<svg><text>Unreviewed</text></svg>\n"
  ];
  for (const addition of additions) {
    const fixture = copyFixture();
    try {
      fs.appendFileSync(path.join(fixture.rootDir, "README.md"), addition);
      refreshControl(fixture.rootDir, "README.md");
      assert.throws(
        () => verifyFixture(fixture),
        /RELEASE_RIGHTS_README_MEDIA/
      );
    } finally {
      fixture.cleanup();
    }
  }
});

test("rights inventory rejects local-server and AWS-only route drift", () => {
  const serverFixture = copyFixture();
  try {
    const serverPath = path.join(serverFixture.rootDir, "src/server.js");
    const source = fs.readFileSync(serverPath, "utf8");
    fs.writeFileSync(
      serverPath,
      source.replace(
        "const assets = new Map([",
        'const assets = new Map([\n  ["/extra", ["../README.md", "text/plain"]],'
      )
    );
    refreshControl(serverFixture.rootDir, "src/server.js");
    assert.throws(
      () => verifyFixture(serverFixture),
      /RELEASE_RIGHTS_SERVER_BINDING/
    );
  } finally {
    serverFixture.cleanup();
  }

  const awsFixture = copyFixture();
  try {
    const entryPath = path.join(
      awsFixture.rootDir,
      "infra/aws/lambda/demo.js"
    );
    let source = fs.readFileSync(entryPath, "utf8");
    source = `import extraRaw from "../../../README.md?raw";\n${source}`;
    source = source.replace(
      "assets: {",
      'assets: {\n    "/extra": extraRaw,'
    );
    fs.writeFileSync(entryPath, source);
    refreshControl(awsFixture.rootDir, "infra/aws/lambda/demo.js");
    assert.throws(
      () => verifyFixture(awsFixture),
      /RELEASE_RIGHTS_AWS_ENTRY/
    );
  } finally {
    awsFixture.cleanup();
  }
});

test("rights inventory rejects re-enabling data images in the AWS CSP", () => {
  const fixture = copyFixture();
  try {
    const runtimePath = path.join(
      fixture.rootDir,
      "src/cloud/public-demo.js"
    );
    const source = fs.readFileSync(runtimePath, "utf8");
    fs.writeFileSync(
      runtimePath,
      source.replace("img-src 'self'", "img-src 'self' data:")
    );
    refreshControl(fixture.rootDir, "src/cloud/public-demo.js");
    assert.throws(
      () => verifyFixture(fixture),
      /RELEASE_RIGHTS_AWS_RUNTIME_CSP/
    );
  } finally {
    fixture.cleanup();
  }
});

test("rights inventory rejects a reintroduced favicon or altered protected hashes", () => {
  const fixture = copyFixture();
  try {
    const relativePath = "web/favicon.svg";
    fs.writeFileSync(
      path.join(fixture.rootDir, relativePath),
      '<svg xmlns="http://www.w3.org/2000/svg"></svg>\n'
    );
    fixture.trackedFiles.push(relativePath);
    assert.throws(
      () => verifyFixture(fixture),
      /RELEASE_RIGHTS_MEDIA_INVENTORY/
    );
  } finally {
    fixture.cleanup();
  }

  const digestFixture = copyFixture();
  try {
    const manifest = readManifest(digestFixture.rootDir);
    manifest.prohibitedSourceDigests[0].sha256 = "0".repeat(64);
    writeManifest(digestFixture.rootDir, manifest);
    assert.throws(
      () => verifyFixture(digestFixture),
      /RELEASE_RIGHTS_PROHIBITED_BOUNDARY/
    );
  } finally {
    digestFixture.cleanup();
  }
});
