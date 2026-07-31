import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const DEFAULT_ROOT = fileURLToPath(new URL("..", import.meta.url));
const MANIFEST_PATH = "docs/media/RIGHTS_MANIFEST.json";
const MANIFEST_SCHEMA = "tideproof.release-rights.v1";
const MANIFEST_STATUS =
  "CURRENT_SURFACES_REVIEWED_FINAL_RELEASE_PENDING";
const RECEIPT_SCHEMA = "tideproof.release-rights-verification.v1";
const HEX_64 = /^[0-9a-f]{64}$/;
const MEDIA_EXTENSIONS = new Set([
  ".avif",
  ".eot",
  ".flac",
  ".gif",
  ".ico",
  ".jpeg",
  ".jpg",
  ".m4a",
  ".m4v",
  ".mov",
  ".mp3",
  ".mp4",
  ".ogg",
  ".otf",
  ".png",
  ".srt",
  ".svg",
  ".ttf",
  ".vtt",
  ".wav",
  ".webm",
  ".webp",
  ".woff",
  ".woff2"
]);
const DENIED_RELEASE_PREFIXES = Object.freeze([
  "docs/media/demo-",
  "docs/media/tideproof-",
  "evidence/release/screenshots/",
  "source-private/",
  "web/brand/",
  "web/media/"
]);
const REQUIRED_FINAL_RELEASE_ITEMS = Object.freeze([
  "Exact-release private rights review receipt.",
  "Final-production asset decision recorded as cleared exact hashes or deliberate omission."
]);
const EXPECTED_DISTRIBUTED = Object.freeze({
  "architecture-png": {
    path: "docs/media/architecture.png",
    rightsState: "CLEARED_CURRENT",
    ledgerRowId: "C08 / V09",
    roles: ["repository-media"]
  },
  "architecture-svg": {
    path: "docs/media/architecture.svg",
    rightsState: "CLEARED_CURRENT",
    ledgerRowId: "C08 / V09",
    roles: ["browser-media", "readme-media", "repository-media"]
  },
  "browser-app": {
    path: "web/app.js",
    rightsState: "CLEARED_CURRENT",
    ledgerRowId: "C04",
    roles: ["browser-source"]
  },
  "browser-document": {
    path: "web/index.html",
    rightsState: "CLEARED_CURRENT",
    ledgerRowId: "C04",
    roles: ["browser-source"]
  },
  "browser-styles": {
    path: "web/styles.css",
    rightsState: "CLEARED_CURRENT",
    ledgerRowId: "C03",
    roles: ["browser-source"]
  }
});
const EXPECTED_CONTROLS = Object.freeze({
  "aws-demo-entry": "infra/aws/lambda/demo.js",
  "aws-demo-runtime": "src/cloud/public-demo.js",
  "aws-demo-verifier": "scripts/gate2-public-demo-verify.js",
  "media-rights-ledger": "docs/media/RIGHTS.md",
  "public-demo-response-verifier": "src/cloud/public-demo-verifier.js",
  "readme-surface": "README.md",
  "server-surface": "src/server.js",
  "visual-release-system": "docs/VISUAL_RELEASE_SYSTEM.md"
});
const EXPECTED_PROHIBITED_DIGESTS = Object.freeze({
  "trustagentic-source-board":
    "fdb14d41236a6eac106887ce05be85bd8cc1da910135d9ffcf2b6f9c80f42c7c",
  "trustagentic-symbol-candidate":
    "e6693445d91e63aa5a84a54d58273a792bdacce88ae8caae15d3872b165c320f",
  "trustagentic-wordmark-candidate":
    "1d1aec3649f161d7e706c941baa763f73ff480b7ef09072a290373ebf2544b44"
});
const EXPECTED_SURFACE_BINDINGS = Object.freeze({
  awsDemoEntryPath: "infra/aws/lambda/demo.js",
  awsDemoRuntimePath: "src/cloud/public-demo.js",
  awsDemoVerifierPath: "scripts/gate2-public-demo-verify.js",
  browserDocumentPath: "web/index.html",
  browserLocalAssetUrls: [
    "/app.js",
    "/architecture.svg",
    "/styles.css"
  ],
  browserNavigationUrls: [
    "/claims",
    "/evidence/gate1-ambiguity",
    "/evidence/gate1-authority",
    "/evidence/gate1-recovery",
    "#judge-path",
    "https://github.com/Flash-Bri/tideproof"
  ],
  readmePath: "README.md",
  readmeImagePaths: ["docs/media/architecture.svg"],
  publicDemoResponseVerifierPath: "src/cloud/public-demo-verifier.js",
  serverPath: "src/server.js",
  publicAssetRoutes: [
    {
      route: "/",
      path: "web/index.html",
      contentType: "text/html; charset=utf-8"
    },
    {
      route: "/app.js",
      path: "web/app.js",
      contentType: "text/javascript; charset=utf-8"
    },
    {
      route: "/architecture.svg",
      path: "docs/media/architecture.svg",
      contentType: "image/svg+xml"
    },
    {
      route: "/claims",
      path: "CLAIMS.md",
      contentType: "text/markdown; charset=utf-8"
    },
    {
      route: "/evidence/gate1-ambiguity",
      path: "evidence/gate1-ambiguity-2026-07-30.md",
      contentType: "text/markdown; charset=utf-8"
    },
    {
      route: "/evidence/gate1-authority",
      path: "evidence/gate1-authority-2026-07-30.md",
      contentType: "text/markdown; charset=utf-8"
    },
    {
      route: "/evidence/gate1-recovery",
      path: "evidence/gate1-recovery-broker-2026-07-30.md",
      contentType: "text/markdown; charset=utf-8"
    },
    {
      route: "/styles.css",
      path: "web/styles.css",
      contentType: "text/css; charset=utf-8"
    }
  ],
  stylesheetFontFamilies: [
    "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
    "ui-monospace, SFMono-Regular, Menlo, monospace",
    "ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, \"Segoe UI\", sans-serif"
  ],
  svgFontFamilies: [
    "Helvetica, Arial, sans-serif",
    "Menlo, Monaco, monospace"
  ]
});

function assert(condition, code) {
  if (!condition) {
    throw new Error(code);
  }
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function sorted(values) {
  return [...values].sort((left, right) => left.localeCompare(right));
}

function sameJson(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function exactKeys(value, keys, code) {
  assert(
    value &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      sameJson(sorted(Object.keys(value)), sorted(keys)),
    code
  );
}

function identifier(value, code) {
  assert(
    typeof value === "string" &&
      /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(value),
    code
  );
}

function nonemptyString(value, code) {
  assert(
    typeof value === "string" &&
      value.trim() === value &&
      value.length > 0,
    code
  );
}

function stringList(value, code) {
  assert(
    Array.isArray(value) &&
      value.every(
        (entry) =>
          typeof entry === "string" &&
          entry.trim() === entry &&
          entry.length > 0
      ) &&
      new Set(value).size === value.length &&
      sameJson(value, sorted(value)),
    code
  );
}

function safeRelativePath(value, code) {
  assert(
    typeof value === "string" &&
      value.length > 0 &&
      value === value.replaceAll("\\", "/") &&
      !path.posix.isAbsolute(value) &&
      value.split("/").every((part) => part !== "" && part !== ".."),
    code
  );
  return value;
}

function readRegularFile(rootDir, relativePath, code) {
  safeRelativePath(relativePath, code);
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

function childEnvironment(source) {
  const environment = {};
  for (const [name, value] of Object.entries(source)) {
    if (
      name.startsWith("GIT_") ||
      /^(?:BASH_ENV|CDPATH|DYLD_.+|ENV|LD_PRELOAD|NODE_OPTIONS|NODE_PATH)$/i.test(
        name
      )
    ) {
      continue;
    }
    environment[name] = value;
  }
  environment.GIT_CONFIG_GLOBAL = "/dev/null";
  environment.GIT_CONFIG_NOSYSTEM = "1";
  environment.GIT_TERMINAL_PROMPT = "0";
  return environment;
}

function defaultTrackedFiles(rootDir) {
  const result = spawnSync("git", ["ls-files", "-z", "--"], {
    cwd: rootDir,
    encoding: "utf8",
    env: childEnvironment(process.env),
    maxBuffer: 8 * 1024 * 1024
  });
  assert(
    !result.error && result.status === 0 && typeof result.stdout === "string",
    "RELEASE_RIGHTS_GIT_TRACKED"
  );
  return result.stdout.length === 0
    ? []
    : result.stdout
        .split("\0")
        .filter((relativePath) => relativePath.length > 0);
}

function validateTrackedFiles(rootDir, values) {
  assert(Array.isArray(values), "RELEASE_RIGHTS_TRACKED_FILES");
  const trackedFiles = sorted(values);
  assert(
    trackedFiles.length > 0 &&
      new Set(trackedFiles).size === trackedFiles.length,
    "RELEASE_RIGHTS_TRACKED_FILES"
  );
  for (const relativePath of trackedFiles) {
    safeRelativePath(relativePath, "RELEASE_RIGHTS_TRACKED_PATH");
    let stat;
    try {
      stat = fs.lstatSync(path.join(rootDir, relativePath));
    } catch {
      throw new Error("RELEASE_RIGHTS_TRACKED_FILE");
    }
    assert(
      stat.isFile() && !stat.isSymbolicLink(),
      "RELEASE_RIGHTS_TRACKED_FILE"
    );
  }
  return trackedFiles;
}

function parseLedgerRows(source) {
  const rows = new Map();
  for (const line of source.split("\n")) {
    const match = /^\| `([^`]+)` \|/.exec(line);
    if (!match) {
      continue;
    }
    assert(!rows.has(match[1]), "RELEASE_RIGHTS_LEDGER_DUPLICATE_ROW");
    rows.set(match[1], line);
  }
  assert(rows.size > 0, "RELEASE_RIGHTS_LEDGER_ROWS");
  return rows;
}

function validateDistributedFiles(rootDir, files, ledgerRows) {
  assert(Array.isArray(files), "RELEASE_RIGHTS_DISTRIBUTED_FILES");
  const ids = files.map((entry) => entry?.id);
  assert(
    sameJson(ids, sorted(ids)) && new Set(ids).size === ids.length,
    "RELEASE_RIGHTS_DISTRIBUTED_ORDER"
  );
  exactKeys(
    Object.fromEntries(
      files.map((entry) => [entry?.id, entry])
    ),
    Object.keys(EXPECTED_DISTRIBUTED),
    "RELEASE_RIGHTS_DISTRIBUTED_SET"
  );

  for (const entry of files) {
    exactKeys(
      entry,
      [
        "id",
        "ledgerRowId",
        "path",
        "rightsState",
        "roles",
        "sha256"
      ],
      "RELEASE_RIGHTS_DISTRIBUTED_ENTRY"
    );
    identifier(entry.id, "RELEASE_RIGHTS_DISTRIBUTED_ID");
    const expected = EXPECTED_DISTRIBUTED[entry.id];
    assert(expected, "RELEASE_RIGHTS_DISTRIBUTED_ID");
    stringList(entry.roles, "RELEASE_RIGHTS_DISTRIBUTED_ROLES");
    assert(
      entry.path === expected.path &&
        entry.rightsState === expected.rightsState &&
        entry.ledgerRowId === expected.ledgerRowId &&
        sameJson(entry.roles, expected.roles) &&
        HEX_64.test(entry.sha256),
      "RELEASE_RIGHTS_DISTRIBUTED_BOUNDARY"
    );
    const bytes = readRegularFile(
      rootDir,
      entry.path,
      "RELEASE_RIGHTS_DISTRIBUTED_FILE"
    );
    assert(
      sha256(bytes) === entry.sha256,
      "RELEASE_RIGHTS_DISTRIBUTED_DIGEST"
    );
    const ledgerRow = ledgerRows.get(entry.ledgerRowId);
    assert(
      ledgerRow?.includes(`\`${entry.path}\``) &&
        ledgerRow.includes(`\`${entry.sha256}\``) &&
        ledgerRow.includes(`\`${entry.rightsState}\``),
      "RELEASE_RIGHTS_LEDGER_BINDING"
    );
  }
  return Object.fromEntries(files.map((entry) => [entry.path, entry]));
}

function validateLedgerSemantics({ ledgerRows, distributedByPath, bindings }) {
  const html = distributedByPath["web/index.html"];
  const relationshipRow = ledgerRows.get("C07");
  assert(
    relationshipRow?.includes("`web/index.html`") &&
      relationshipRow.includes(`\`${html.sha256}\``) &&
      relationshipRow.includes("`TEXT_ONLY_REVIEWED`") &&
      ledgerRows.get("C06")?.includes("`TEXT_ONLY_REVIEWED`"),
    "RELEASE_RIGHTS_LEDGER_TRADEMARK_BOUNDARY"
  );
  const fontRow = ledgerRows.get("C05");
  const fontTokens = new Set(
    [
      ...bindings.stylesheetFontFamilies,
      ...bindings.svgFontFamilies
    ].flatMap((family) =>
      family
        .split(",")
        .map((token) => token.trim())
    )
  );
  assert(
    fontRow?.includes("`PLATFORM_ONLY`") &&
      [...fontTokens].every((token) => fontRow.includes(`\`${token}\``)),
    "RELEASE_RIGHTS_LEDGER_FONT_BOUNDARY"
  );
}

function validateControlFiles(rootDir, files) {
  assert(Array.isArray(files), "RELEASE_RIGHTS_CONTROL_FILES");
  const ids = files.map((entry) => entry?.id);
  assert(
    sameJson(ids, sorted(ids)) && new Set(ids).size === ids.length,
    "RELEASE_RIGHTS_CONTROL_ORDER"
  );
  exactKeys(
    Object.fromEntries(files.map((entry) => [entry?.id, entry])),
    Object.keys(EXPECTED_CONTROLS),
    "RELEASE_RIGHTS_CONTROL_SET"
  );
  for (const entry of files) {
    exactKeys(
      entry,
      ["id", "path", "sha256"],
      "RELEASE_RIGHTS_CONTROL_ENTRY"
    );
    identifier(entry.id, "RELEASE_RIGHTS_CONTROL_ID");
    assert(
      entry.path === EXPECTED_CONTROLS[entry.id] &&
        HEX_64.test(entry.sha256),
      "RELEASE_RIGHTS_CONTROL_BOUNDARY"
    );
    assert(
      sha256(
        readRegularFile(
          rootDir,
          entry.path,
          "RELEASE_RIGHTS_CONTROL_FILE"
        )
      ) === entry.sha256,
      "RELEASE_RIGHTS_CONTROL_DIGEST"
    );
  }
}

function validateProhibitedDigests(entries) {
  assert(Array.isArray(entries), "RELEASE_RIGHTS_PROHIBITED_DIGESTS");
  const ids = entries.map((entry) => entry?.id);
  assert(
    sameJson(ids, sorted(ids)) && new Set(ids).size === ids.length,
    "RELEASE_RIGHTS_PROHIBITED_ORDER"
  );
  exactKeys(
    Object.fromEntries(entries.map((entry) => [entry?.id, entry])),
    Object.keys(EXPECTED_PROHIBITED_DIGESTS),
    "RELEASE_RIGHTS_PROHIBITED_SET"
  );
  for (const entry of entries) {
    exactKeys(
      entry,
      ["id", "sha256"],
      "RELEASE_RIGHTS_PROHIBITED_ENTRY"
    );
    identifier(entry.id, "RELEASE_RIGHTS_PROHIBITED_ID");
    assert(
      entry.sha256 === EXPECTED_PROHIBITED_DIGESTS[entry.id],
      "RELEASE_RIGHTS_PROHIBITED_BOUNDARY"
    );
  }
  return new Set(entries.map((entry) => entry.sha256));
}

function validateSurfaceBindings(bindings) {
  exactKeys(
    bindings,
    [
      "awsDemoEntryPath",
      "awsDemoRuntimePath",
      "awsDemoVerifierPath",
      "browserDocumentPath",
      "browserLocalAssetUrls",
      "browserNavigationUrls",
      "publicAssetRoutes",
      "publicDemoResponseVerifierPath",
      "readmeImagePaths",
      "readmePath",
      "serverPath",
      "stylesheetFontFamilies",
      "svgFontFamilies"
    ],
    "RELEASE_RIGHTS_SURFACE_BINDINGS"
  );
  for (const key of [
    "browserLocalAssetUrls",
    "browserNavigationUrls",
    "readmeImagePaths",
    "stylesheetFontFamilies",
    "svgFontFamilies"
  ]) {
    stringList(bindings[key], "RELEASE_RIGHTS_SURFACE_LIST");
  }
  assert(
    sameJson(bindings, EXPECTED_SURFACE_BINDINGS),
    "RELEASE_RIGHTS_SURFACE_BOUNDARY"
  );
  for (const route of bindings.publicAssetRoutes) {
    exactKeys(
      route,
      ["contentType", "path", "route"],
      "RELEASE_RIGHTS_SERVER_ROUTE"
    );
  }
}

function attributeValues(source, tagName, attributeName) {
  const values = [];
  const tagPattern = new RegExp(`<${tagName}\\b[^>]*>`, "gi");
  const attributePattern = new RegExp(
    `\\b${attributeName}\\s*=\\s*([\"'])(.*?)\\1`,
    "i"
  );
  for (const match of source.matchAll(tagPattern)) {
    const attribute = attributePattern.exec(match[0]);
    if (attribute) {
      values.push(attribute[2]);
    }
  }
  return values;
}

function validateBrowserDocument(source, bindings) {
  assert(
    !/<(?:audio|base|canvas|embed|form|iframe|object|picture|source|style|svg|video)\b/i.test(
      source
    ) &&
      !/\bsrcset\s*=/i.test(source) &&
      !/\bstyle\s*=/i.test(source) &&
      !/<meta\b[^>]*(?:\bproperty\s*=|\bhttp-equiv\s*=|\bname\s*=\s*["']twitter:)/i.test(
        source
      ),
    "RELEASE_RIGHTS_BROWSER_EMBED"
  );
  const localAssets = sorted([
    ...attributeValues(source, "link", "href"),
    ...attributeValues(source, "img", "src"),
    ...attributeValues(source, "script", "src")
  ]);
  assert(
    sameJson(localAssets, bindings.browserLocalAssetUrls) &&
      localAssets.every(
        (value) =>
          value.startsWith("/") &&
          !value.startsWith("//") &&
          !/^(?:data|blob):/i.test(value)
      ),
    "RELEASE_RIGHTS_BROWSER_ASSETS"
  );
  const navigations = sorted(attributeValues(source, "a", "href"));
  assert(
    sameJson(navigations, bindings.browserNavigationUrls),
    "RELEASE_RIGHTS_BROWSER_NAVIGATION"
  );
}

function validateBrowserScript(source) {
  const fetches = sorted(
    [...source.matchAll(/\bfetch\(\s*(["'])(.*?)\1/g)].map(
      (match) => match[2]
    )
  );
  assert(
    sameJson(fetches, ["/api/scenario"]) &&
      !/["'`](?:https?:\/\/|\/\/|data:|blob:)/i.test(source) &&
      !/\b(?:EventSource|WebSocket)\s*\(/.test(source) &&
      !/\bnew\s+Image\s*\(/i.test(source) &&
      !/\.(?:src|srcset)\s*=/i.test(source) &&
      !/setAttribute\(\s*(["'])(?:src|srcset)\1\s*,/i.test(source) &&
      !/createElement\(\s*(["'])(?:audio|canvas|embed|iframe|img|object|picture|source|video)\1\s*\)/i.test(
        source
      ),
    "RELEASE_RIGHTS_BROWSER_SCRIPT"
  );
}

function normalizeCssValue(value) {
  return value.replace(/\s+/g, " ").trim();
}

function validateStylesheet(source, bindings) {
  assert(
    !/@(?:font-face|import)\b/i.test(source) && !/url\s*\(/i.test(source),
    "RELEASE_RIGHTS_STYLESHEET_RESOURCE"
  );
  const fontFamilies = new Set(
    [...source.matchAll(/font-family\s*:\s*([^;]+);/gi)].map((match) =>
      normalizeCssValue(match[1])
    )
  );
  for (const match of source.matchAll(/\bfont\s*:\s*([^;]+);/gi)) {
    const shorthand = normalizeCssValue(match[1]);
    if (shorthand === "inherit") {
      continue;
    }
    const endings = bindings.stylesheetFontFamilies.filter((family) =>
      shorthand.endsWith(family)
    );
    assert(endings.length === 1, "RELEASE_RIGHTS_STYLESHEET_SHORTHAND");
    fontFamilies.add(endings[0]);
  }
  assert(
    sameJson(sorted(fontFamilies), bindings.stylesheetFontFamilies),
    "RELEASE_RIGHTS_STYLESHEET_FONTS"
  );
}

function validateSvg(source) {
  assert(
    /^<\?xml\b/.test(source) || /^<svg\b/.test(source),
    "RELEASE_RIGHTS_SVG_ROOT"
  );
  assert(
    !/<(?:foreignObject|image|script|style|use)\b/i.test(source) &&
      !/\b(?:href|xlink:href)\s*=/i.test(source),
    "RELEASE_RIGHTS_SVG_EMBED"
  );
  const withoutNamespace = source.replace(
    "http://www.w3.org/2000/svg",
    ""
  );
  assert(
    !/(?:https?:\/\/|\/\/|data:|blob:)/i.test(withoutNamespace),
    "RELEASE_RIGHTS_SVG_REMOTE"
  );
  const urlReferences = [
    ...source.matchAll(/url\(\s*(["']?)(.*?)\1\s*\)/gi)
  ].map((match) => match[2]);
  assert(
    urlReferences.every((value) => /^#[A-Za-z][A-Za-z0-9._:-]*$/.test(value)),
    "RELEASE_RIGHTS_SVG_URL"
  );
  return [
    ...source.matchAll(/\bfont-family\s*=\s*(["'])(.*?)\1/gi)
  ].map((match) => normalizeCssValue(match[2]));
}

function validateReadme(source, bindings) {
  const images = sorted(
    [...source.matchAll(/!\[[^\]]*\]\(([^)\s]+)(?:\s+[^)]*)?\)/g)].map(
      (match) => match[1]
    )
  );
  const imageMarkerCount = [...source.matchAll(/!\[[^\]]*\]/g)].length;
  assert(
    sameJson(images, bindings.readmeImagePaths) &&
      imageMarkerCount === images.length &&
      images.every(
        (value) =>
          !/^(?:https?:\/\/|\/\/|data:|blob:)/i.test(value)
      ) &&
      !/<(?:audio|embed|iframe|img|object|picture|source|svg|video)\b/i.test(
        source
      ),
    "RELEASE_RIGHTS_README_MEDIA"
  );
}

function normalizedRoutes(routes) {
  return [...routes].sort((left, right) =>
    left.route.localeCompare(right.route)
  );
}

function assertExactRouteSet(actual, expected, code) {
  for (const route of actual) {
    exactKeys(route, ["contentType", "path", "route"], code);
  }
  assert(
    actual.length === new Set(actual.map((entry) => entry.route)).size &&
      sameJson(normalizedRoutes(actual), normalizedRoutes(expected)),
    code
  );
}

function quotedObjectEntries(source, name, code) {
  const escapedName = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const block = new RegExp(
    `${escapedName}\\s*=\\s*Object\\.freeze\\(\\{([\\s\\S]*?)\\}\\);`
  ).exec(source)?.[1];
  assert(block, code);
  return [...block.matchAll(/"([^"]+)"\s*:\s*"([^"]+)"/g)].map(
    (match) => [match[1], match[2]]
  );
}

function validateServer(source, bindings) {
  const block = /const assets\s*=\s*new Map\(\[([\s\S]*?)\]\);/.exec(
    source
  )?.[1];
  assert(block, "RELEASE_RIGHTS_SERVER_BINDING");
  const routes = [
    ...block.matchAll(
      /\[\s*"([^"]+)"\s*,\s*\[\s*"\.\.\/([^"]+)"\s*,\s*"([^"]+)"\s*\]\s*\]/g
    )
  ].map((match) => ({
    route: match[1],
    path: match[2],
    contentType: match[3]
  }));
  assertExactRouteSet(
    routes,
    bindings.publicAssetRoutes,
    "RELEASE_RIGHTS_SERVER_BINDING"
  );
}

function validateAwsDemoEntry(source, bindings) {
  const imports = new Map(
    [...source.matchAll(
      /import\s+([A-Za-z_$][A-Za-z0-9_$]*)\s+from\s+"\.\.\/\.\.\/\.\.\/([^"?]+)\?raw";/g
    )].map((match) => [match[1], match[2]])
  );
  const assetsBlock = /assets\s*:\s*\{([\s\S]*?)\n\s*\},\n\s*binding\s*:/.exec(
    source
  )?.[1];
  assert(assetsBlock, "RELEASE_RIGHTS_AWS_ENTRY");
  const routes = [
    ...assetsBlock.matchAll(
      /"([^"]+)"\s*:\s*([A-Za-z_$][A-Za-z0-9_$]*)/g
    )
  ].map((match) => ({
    route: match[1],
    path: imports.get(match[2]),
    contentType: bindings.publicAssetRoutes.find(
      (entry) => entry.route === match[1]
    )?.contentType
  }));
  assert(
    imports.size === bindings.publicAssetRoutes.length &&
      routes.every((entry) => typeof entry.path === "string"),
    "RELEASE_RIGHTS_AWS_ENTRY"
  );
  assertExactRouteSet(
    routes,
    bindings.publicAssetRoutes,
    "RELEASE_RIGHTS_AWS_ENTRY"
  );
}

function validateAwsDemoRuntime(source, bindings) {
  const pathBlock = /PUBLIC_DEMO_PATHS\s*=\s*Object\.freeze\(\[([\s\S]*?)\]\);/.exec(
    source
  )?.[1];
  assert(pathBlock, "RELEASE_RIGHTS_AWS_RUNTIME");
  const publicPaths = sorted(
    [...pathBlock.matchAll(/"([^"]+)"/g)].map((match) => match[1])
  );
  const expectedPaths = sorted([
    ...bindings.publicAssetRoutes.map((entry) => entry.route),
    "/api/health",
    "/api/scenario"
  ]);
  assert(
    sameJson(publicPaths, expectedPaths) &&
      new Set(publicPaths).size === publicPaths.length,
    "RELEASE_RIGHTS_AWS_RUNTIME_PATHS"
  );
  const contentTypes = quotedObjectEntries(
    source,
    "CONTENT_TYPES",
    "RELEASE_RIGHTS_AWS_RUNTIME_TYPES"
  ).map(([route, contentType]) => ({
    route,
    path: bindings.publicAssetRoutes.find((entry) => entry.route === route)
      ?.path,
    contentType
  }));
  assertExactRouteSet(
    contentTypes,
    bindings.publicAssetRoutes,
    "RELEASE_RIGHTS_AWS_RUNTIME_TYPES"
  );
  assert(
    source.includes("\"img-src 'self'\"") &&
      !source.includes("img-src 'self' data:") &&
      !source.includes("img-src 'self' blob:"),
    "RELEASE_RIGHTS_AWS_RUNTIME_CSP"
  );
}

function validateAwsDemoVerifier(source, bindings) {
  const entries = quotedObjectEntries(
    source,
    "ASSET_FILES",
    "RELEASE_RIGHTS_AWS_VERIFIER"
  );
  const routes = entries.map(([route, filePath]) => ({
    route,
    path: filePath,
    contentType: bindings.publicAssetRoutes.find(
      (entry) => entry.route === route
    )?.contentType
  }));
  assertExactRouteSet(
    routes,
    bindings.publicAssetRoutes,
    "RELEASE_RIGHTS_AWS_VERIFIER"
  );
}

function validatePublicDemoResponseVerifier(source) {
  assert(
    source.includes("\"img-src 'self'\"") &&
      !source.includes("img-src 'self' data:") &&
      !source.includes("img-src 'self' blob:"),
    "RELEASE_RIGHTS_PUBLIC_VERIFIER_CSP"
  );
}

function looksLikeMedia(bytes, relativePath) {
  if (MEDIA_EXTENSIONS.has(path.extname(relativePath).toLowerCase())) {
    return true;
  }
  const prefix = bytes.subarray(0, 16);
  const ascii = prefix.toString("ascii");
  const trimmed = bytes.subarray(0, 512).toString("utf8").trimStart();
  return (
    prefix.subarray(0, 8).equals(
      Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])
    ) ||
    (prefix[0] === 0xff && prefix[1] === 0xd8 && prefix[2] === 0xff) ||
    ascii.startsWith("GIF87a") ||
    ascii.startsWith("GIF89a") ||
    ascii.startsWith("ID3") ||
    ascii.startsWith("OggS") ||
    ascii.startsWith("fLaC") ||
    ascii.startsWith("wOFF") ||
    ascii.startsWith("wOF2") ||
    ascii.startsWith("OTTO") ||
    prefix.subarray(0, 4).equals(Buffer.from([0, 1, 0, 0])) ||
    prefix.subarray(0, 4).equals(Buffer.from([0x1a, 0x45, 0xdf, 0xa3])) ||
    (ascii.startsWith("RIFF") &&
      ["WAVE", "WEBP"].includes(bytes.subarray(8, 12).toString("ascii"))) ||
    bytes.subarray(4, 8).toString("ascii") === "ftyp" ||
    /^<svg\b/i.test(trimmed) ||
    /^<\?xml[\s\S]{0,300}<svg\b/i.test(trimmed)
  );
}

function validateRepositoryInventory({
  rootDir,
  trackedFiles,
  distributedByPath,
  prohibitedDigests
}) {
  for (const relativePath of trackedFiles) {
    assert(
      !DENIED_RELEASE_PREFIXES.some((prefix) =>
        relativePath.startsWith(prefix)
      ),
      "RELEASE_RIGHTS_BLOCKED_PATH"
    );
    const digest = sha256(fs.readFileSync(path.join(rootDir, relativePath)));
    assert(
      !prohibitedDigests.has(digest),
      "RELEASE_RIGHTS_PROHIBITED_SOURCE"
    );
  }
  const mediaFiles = trackedFiles.filter((relativePath) =>
    looksLikeMedia(fs.readFileSync(path.join(rootDir, relativePath)), relativePath)
  );
  const expectedMediaFiles = sorted(
    Object.keys(distributedByPath).filter((relativePath) =>
      MEDIA_EXTENSIONS.has(path.extname(relativePath).toLowerCase())
    )
  );
  assert(
    sameJson(mediaFiles, expectedMediaFiles),
    "RELEASE_RIGHTS_MEDIA_INVENTORY"
  );
  return mediaFiles;
}

function parseManifest(rootDir) {
  const bytes = readRegularFile(
    rootDir,
    MANIFEST_PATH,
    "RELEASE_RIGHTS_MANIFEST_FILE"
  );
  const source = bytes.toString("utf8");
  let manifest;
  try {
    manifest = JSON.parse(source);
  } catch {
    throw new Error("RELEASE_RIGHTS_MANIFEST_JSON");
  }
  assert(
    `${JSON.stringify(manifest, null, 2)}\n` === source,
    "RELEASE_RIGHTS_MANIFEST_CANONICAL"
  );
  return { bytes, manifest };
}

export function verifyReleaseRights({
  rootDir = DEFAULT_ROOT,
  trackedFiles
} = {}) {
  const resolvedRoot = path.resolve(rootDir);
  const { bytes: manifestBytes, manifest } = parseManifest(resolvedRoot);
  exactKeys(
    manifest,
    [
      "claimBoundary",
      "controlFiles",
      "distributedFiles",
      "finalReleaseRequirements",
      "prohibitedSourceDigests",
      "reviewedOn",
      "schema",
      "status",
      "surfaceBindings"
    ],
    "RELEASE_RIGHTS_MANIFEST_KEYS"
  );
  assert(
    manifest.schema === MANIFEST_SCHEMA &&
      manifest.status === MANIFEST_STATUS &&
      /^\d{4}-\d{2}-\d{2}$/.test(manifest.reviewedOn),
    "RELEASE_RIGHTS_MANIFEST_BOUNDARY"
  );
  nonemptyString(manifest.claimBoundary, "RELEASE_RIGHTS_CLAIM_BOUNDARY");
  stringList(
    manifest.finalReleaseRequirements,
    "RELEASE_RIGHTS_FINAL_REQUIREMENTS"
  );
  assert(
    sameJson(
      manifest.finalReleaseRequirements,
      REQUIRED_FINAL_RELEASE_ITEMS
    ),
    "RELEASE_RIGHTS_FINAL_REQUIREMENTS"
  );

  const ledgerSource = readRegularFile(
    resolvedRoot,
    "docs/media/RIGHTS.md",
    "RELEASE_RIGHTS_LEDGER_FILE"
  ).toString("utf8");
  const ledgerRows = parseLedgerRows(ledgerSource);
  validateSurfaceBindings(manifest.surfaceBindings);
  const distributedByPath = validateDistributedFiles(
    resolvedRoot,
    manifest.distributedFiles,
    ledgerRows
  );
  validateControlFiles(resolvedRoot, manifest.controlFiles);
  validateLedgerSemantics({
    ledgerRows,
    distributedByPath,
    bindings: manifest.surfaceBindings
  });
  const prohibitedDigests = validateProhibitedDigests(
    manifest.prohibitedSourceDigests
  );
  const acceptedTrackedFiles = validateTrackedFiles(
    resolvedRoot,
    trackedFiles ?? defaultTrackedFiles(resolvedRoot)
  );
  const trackedSet = new Set(acceptedTrackedFiles);
  assert(
    [
      ...manifest.distributedFiles.map((entry) => entry.path),
      ...manifest.controlFiles.map((entry) => entry.path),
      ...manifest.surfaceBindings.publicAssetRoutes.map((entry) => entry.path)
    ].every((relativePath) => trackedSet.has(relativePath)),
    "RELEASE_RIGHTS_REQUIRED_TRACKED"
  );
  const mediaFiles = validateRepositoryInventory({
    rootDir: resolvedRoot,
    trackedFiles: acceptedTrackedFiles,
    distributedByPath,
    prohibitedDigests
  });

  const browserDocument = readRegularFile(
    resolvedRoot,
    manifest.surfaceBindings.browserDocumentPath,
    "RELEASE_RIGHTS_BROWSER_FILE"
  ).toString("utf8");
  validateBrowserDocument(browserDocument, manifest.surfaceBindings);
  validateBrowserScript(
    readRegularFile(
      resolvedRoot,
      "web/app.js",
      "RELEASE_RIGHTS_BROWSER_SCRIPT_FILE"
    ).toString("utf8")
  );
  validateStylesheet(
    readRegularFile(
      resolvedRoot,
      "web/styles.css",
      "RELEASE_RIGHTS_STYLESHEET_FILE"
    ).toString("utf8"),
    manifest.surfaceBindings
  );
  const svgFontFamilies = new Set();
  for (const svgPath of mediaFiles.filter(
    (relativePath) => path.extname(relativePath).toLowerCase() === ".svg"
  )) {
    for (const family of validateSvg(
      readRegularFile(
        resolvedRoot,
        svgPath,
        "RELEASE_RIGHTS_SVG_FILE"
      ).toString("utf8")
    )) {
      svgFontFamilies.add(family);
    }
  }
  assert(
    sameJson(
      sorted(svgFontFamilies),
      manifest.surfaceBindings.svgFontFamilies
    ),
    "RELEASE_RIGHTS_SVG_FONTS"
  );
  validateReadme(
    readRegularFile(
      resolvedRoot,
      manifest.surfaceBindings.readmePath,
      "RELEASE_RIGHTS_README_FILE"
    ).toString("utf8"),
    manifest.surfaceBindings
  );
  validateServer(
    readRegularFile(
      resolvedRoot,
      manifest.surfaceBindings.serverPath,
      "RELEASE_RIGHTS_SERVER_FILE"
    ).toString("utf8"),
    manifest.surfaceBindings
  );
  validateAwsDemoEntry(
    readRegularFile(
      resolvedRoot,
      manifest.surfaceBindings.awsDemoEntryPath,
      "RELEASE_RIGHTS_AWS_ENTRY_FILE"
    ).toString("utf8"),
    manifest.surfaceBindings
  );
  validateAwsDemoRuntime(
    readRegularFile(
      resolvedRoot,
      manifest.surfaceBindings.awsDemoRuntimePath,
      "RELEASE_RIGHTS_AWS_RUNTIME_FILE"
    ).toString("utf8"),
    manifest.surfaceBindings
  );
  validateAwsDemoVerifier(
    readRegularFile(
      resolvedRoot,
      manifest.surfaceBindings.awsDemoVerifierPath,
      "RELEASE_RIGHTS_AWS_VERIFIER_FILE"
    ).toString("utf8"),
    manifest.surfaceBindings
  );
  validatePublicDemoResponseVerifier(
    readRegularFile(
      resolvedRoot,
      manifest.surfaceBindings.publicDemoResponseVerifierPath,
      "RELEASE_RIGHTS_PUBLIC_VERIFIER_FILE"
    ).toString("utf8")
  );

  return {
    schemaVersion: RECEIPT_SCHEMA,
    status: "CURRENT_SURFACES_PASS",
    finalReleaseReady: false,
    reviewedOn: manifest.reviewedOn,
    manifestPath: MANIFEST_PATH,
    manifestSha256: sha256(manifestBytes),
    ledgerSha256: sha256(Buffer.from(ledgerSource)),
    distributedFileCount: manifest.distributedFiles.length,
    currentClearedFileCount: manifest.distributedFiles.filter(
      (entry) => entry.rightsState === "CLEARED_CURRENT"
    ).length,
    interimOnlyFileCount: manifest.distributedFiles.filter(
      (entry) => entry.rightsState === "CLEARED_INTERIM_ONLY"
    ).length,
    repositoryMediaFileCount: mediaFiles.length,
    trackedFileCount: acceptedTrackedFiles.length,
    prohibitedSourceDigestCount: prohibitedDigests.size,
    finalReleaseRequirements: manifest.finalReleaseRequirements,
    checks: {
      canonicalManifest: true,
      exactFileHashes: true,
      ledgerBindings: true,
      completeRepositoryMediaInventory: true,
      blockedPlannedPathsAbsent: true,
      prohibitedReferenceBytesAbsent: true,
      remoteEmbeddedMediaAbsent: true,
      redistributedFontsAbsent: true,
      localServerBindingsExact: true,
      awsDistributionBindingsExact: true,
      publicDemoCspRejectsDataImages: true
    },
    claimBoundary:
      "This technical receipt proves that the current repository, README, and browser surfaces match the reviewed hashes and contain no unlisted media, remote embedded media, redistributed fonts, blocked planned-asset paths, or known reference-asset bytes. It does not grant rights, clear future assets, replace legal review, approve final marketing art, or satisfy the exact-release private-review receipt."
  };
}

async function main() {
  assert(process.argv.length === 2, "RELEASE_RIGHTS_ARGUMENT");
  process.stdout.write(`${JSON.stringify(verifyReleaseRights(), null, 2)}\n`);
}

const startedDirectly =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (startedDirectly) {
  main().catch((error) => {
    const message = String(error?.message ?? "");
    const code = /^RELEASE_RIGHTS_[A-Z0-9_]{1,120}$/.test(message)
      ? message
      : "RELEASE_RIGHTS_UNKNOWN";
    process.stderr.write(`TIDEPROOF_RELEASE_RIGHTS_FAILED:${code}\n`);
    process.exitCode = 1;
  });
}

export const __test = Object.freeze({
  DENIED_RELEASE_PREFIXES,
  EXPECTED_CONTROLS,
  EXPECTED_DISTRIBUTED,
  EXPECTED_PROHIBITED_DIGESTS,
  EXPECTED_SURFACE_BINDINGS,
  MANIFEST_PATH,
  MANIFEST_SCHEMA,
  MANIFEST_STATUS
});
