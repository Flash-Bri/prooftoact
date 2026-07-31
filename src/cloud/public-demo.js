const HEX_40 = /^[0-9a-f]{40}$/;
const HEX_64 = /^[0-9a-f]{64}$/;

export const PUBLIC_DEMO_PATHS = Object.freeze([
  "/",
  "/app.js",
  "/styles.css",
  "/favicon.svg",
  "/api/health",
  "/api/scenario",
  "/evidence/gate1-authority",
  "/evidence/gate1-recovery",
  "/evidence/gate1-ambiguity",
  "/claims"
]);

const PUBLIC_ASSET_PATHS = PUBLIC_DEMO_PATHS.filter(
  (path) => !path.startsWith("/api/")
);

const CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "connect-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
  "upgrade-insecure-requests"
].join("; ");

const CONTENT_TYPES = Object.freeze({
  "/": "text/html; charset=utf-8",
  "/app.js": "text/javascript; charset=utf-8",
  "/styles.css": "text/css; charset=utf-8",
  "/favicon.svg": "image/svg+xml",
  "/evidence/gate1-authority": "text/markdown; charset=utf-8",
  "/evidence/gate1-recovery": "text/markdown; charset=utf-8",
  "/evidence/gate1-ambiguity": "text/markdown; charset=utf-8",
  "/claims": "text/markdown; charset=utf-8"
});

function exactKeys(value, keys) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join("\n") ===
      [...keys].sort().join("\n")
  );
}

function validateBinding(binding) {
  const keys = [
    "configDigest",
    "demoArtifactDigest",
    "demoSourceDigest",
    "expectedApiId",
    "functionVersion",
    "packageLockDigest",
    "sourceCommit",
    "treeDigest"
  ];
  if (
    !exactKeys(binding, keys) ||
    !HEX_40.test(binding.sourceCommit) ||
    !HEX_40.test(binding.treeDigest) ||
    !HEX_64.test(binding.configDigest) ||
    !HEX_64.test(binding.demoArtifactDigest) ||
    !HEX_64.test(binding.demoSourceDigest) ||
    !HEX_64.test(binding.packageLockDigest) ||
    !/^[a-z0-9]{4,32}$/.test(binding.expectedApiId) ||
    !/^[1-9][0-9]*$/.test(binding.functionVersion)
  ) {
    throw new Error("PUBLIC_DEMO_BINDING_REJECTED");
  }
  return Object.freeze({ ...binding });
}

function validateAssets(assets) {
  if (!exactKeys(assets, PUBLIC_ASSET_PATHS)) {
    throw new Error("PUBLIC_DEMO_ASSET_SET_REJECTED");
  }
  for (const path of PUBLIC_ASSET_PATHS) {
    const body = assets[path];
    if (
      typeof body !== "string" ||
      body.length === 0 ||
      Buffer.byteLength(body, "utf8") > 1_000_000
    ) {
      throw new Error("PUBLIC_DEMO_ASSET_REJECTED");
    }
  }
  return Object.freeze({ ...assets });
}

function validateScenario(scenario) {
  if (
    !scenario ||
    typeof scenario !== "object" ||
    !scenario.proofStates ||
    !scenario.proofStates.gateTwo ||
    !Array.isArray(scenario.timeline) ||
    scenario.timeline.length === 0 ||
    !scenario.invariants ||
    Object.keys(scenario.invariants).length === 0 ||
    !Object.values(scenario.invariants).every(
      (value) => value === true
    )
  ) {
    throw new Error("PUBLIC_DEMO_SCENARIO_REJECTED");
  }
  return scenario;
}

function publicHeaders(contentType, cacheControl = "no-store") {
  return {
    "cache-control": cacheControl,
    "content-security-policy": CONTENT_SECURITY_POLICY,
    "content-type": contentType,
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    "permissions-policy":
      "camera=(), geolocation=(), microphone=(), payment=(), usb=()",
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY"
  };
}

function response(
  statusCode,
  body,
  contentType,
  cacheControl = "no-store"
) {
  return {
    statusCode,
    headers: publicHeaders(contentType, cacheControl),
    body,
    isBase64Encoded: false
  };
}

function jsonResponse(statusCode, body) {
  return response(
    statusCode,
    JSON.stringify(body),
    "application/json; charset=utf-8"
  );
}

function awsHostedScenario(runScenario, binding) {
  const scenario = validateScenario(runScenario());
  const hostReceipt = Object.freeze({
    schemaVersion: "tideproof.public-demo-host.v1",
    platform: "AWS Lambda + API Gateway",
    sourceCommit: binding.sourceCommit,
    treeDigest: binding.treeDigest,
    configDigest: binding.configDigest,
    demoSourceDigest: binding.demoSourceDigest,
    demoArtifactDigest: binding.demoArtifactDigest,
    packageLockDigest: binding.packageLockDigest,
    functionVersion: binding.functionVersion,
    signedOut: true,
    syntheticOnly: true,
    authorityCapability: false
  });
  scenario.proofStates.gateTwo = {
    badge: "GATE TWO · AWS HOST",
    label:
      "GATE TWO HOST — AWS Lambda + API Gateway; advisory evidence pending",
    heading: "AWS-hosted judge surface · advisory evidence pending",
    summary:
      "This signed-out AWS route serves only the deterministic replay. Its Lambda role can write bounded logs but cannot invoke Bedrock, Lambda, KMS signing, secrets, database, MCP, or authority paths.",
    sourceCommit: binding.sourceCommit.slice(0, 7),
    cloudState: "Read-only demo host live",
    limitation:
      "Bedrock, KMS, the IAM advisory path, and the CockroachDB-to-AWS handoff require separate accepted live receipts.",
    boundarySummary:
      "This page is hosted by a content-only AWS Lambda whose application role can write bounded logs and has no proposal or authority capabilities. The separate proposal path remains IAM-authenticated and unproved live until its receipts pass review. Tideproof makes no production, disaster-readiness, truth-detection, or exactly-once real-world-effect claim.",
    hostReceipt
  };
  return Object.freeze(scenario);
}

function requestPath(event, expectedApiId) {
  const path = event?.rawPath;
  const method = event?.requestContext?.http?.method;
  const expectedRouteKey = `GET ${path}`;
  if (
    event?.version !== "2.0" ||
    event?.requestContext?.apiId !== expectedApiId ||
    event?.requestContext?.stage !== "$default" ||
    method !== "GET" ||
    event?.requestContext?.routeKey !== expectedRouteKey ||
    !PUBLIC_DEMO_PATHS.includes(path) ||
    (event.body !== undefined &&
      event.body !== null &&
      event.body !== "")
  ) {
    return null;
  }
  return path;
}

export function createPublicDemoHandler({
  assets,
  binding,
  runScenario
}) {
  const checkedAssets = validateAssets(assets);
  const checkedBinding = validateBinding(binding);
  if (typeof runScenario !== "function") {
    throw new Error("PUBLIC_DEMO_SCENARIO_RUNNER_REJECTED");
  }
  const scenario = awsHostedScenario(runScenario, checkedBinding);
  const scenarioBody = JSON.stringify(scenario);
  const healthBody = Object.freeze({
    schemaVersion: "tideproof.public-demo-health.v1",
    ok: true,
    mode: "AWS_READ_ONLY_DEMO",
    sourceCommit: checkedBinding.sourceCommit,
    treeDigest: checkedBinding.treeDigest,
    configDigest: checkedBinding.configDigest,
    demoSourceDigest: checkedBinding.demoSourceDigest,
    demoArtifactDigest: checkedBinding.demoArtifactDigest,
    packageLockDigest: checkedBinding.packageLockDigest,
    functionVersion: checkedBinding.functionVersion,
    signedOut: true,
    syntheticOnly: true,
    authorityCapability: false
  });

  return async function handler(event) {
    const path = requestPath(event, checkedBinding.expectedApiId);
    if (!path) {
      return jsonResponse(404, { error: "not_found" });
    }
    if (path === "/api/health") {
      return jsonResponse(200, healthBody);
    }
    if (path === "/api/scenario") {
      return response(
        200,
        scenarioBody,
        "application/json; charset=utf-8"
      );
    }
    const cacheControl =
      path === "/app.js" ||
      path === "/styles.css" ||
      path === "/favicon.svg"
        ? "public, max-age=300, must-revalidate"
        : "no-store";
    return response(
      200,
      checkedAssets[path],
      CONTENT_TYPES[path],
      cacheControl
    );
  };
}
