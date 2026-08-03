import crypto from "node:crypto";
import { PUBLIC_DEMO_PATHS } from "./public-demo.js";

const HEX_40 = /^[0-9a-f]{40}$/;
const HEX_64 = /^[0-9a-f]{64}$/;
const POSITIVE_INTEGER = /^[1-9][0-9]*$/;
const MAX_RESPONSE_BYTES = 1_100_000;
const INITIAL_BURST_REQUESTS = 8;
const REFILL_DELAY_MS = 21_000;

const PUBLIC_ASSET_PATHS = PUBLIC_DEMO_PATHS.filter(
  (path) => !path.startsWith("/api/")
);

const CONTENT_TYPES = Object.freeze({
  "/": "text/html; charset=utf-8",
  "/app.js": "text/javascript; charset=utf-8",
  "/styles.css": "text/css; charset=utf-8",
  "/architecture.svg": "image/svg+xml",
  "/api/health": "application/json; charset=utf-8",
  "/api/scenario": "application/json; charset=utf-8",
  "/evidence/gate1-authority": "text/markdown; charset=utf-8",
  "/evidence/gate1-recovery": "text/markdown; charset=utf-8",
  "/evidence/gate1-ambiguity": "text/markdown; charset=utf-8",
  "/claims": "text/markdown; charset=utf-8"
});

const SECURITY_HEADERS = Object.freeze({
  "content-security-policy": [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self'",
    "connect-src 'self'",
    "img-src 'self'",
    "font-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
    "upgrade-insecure-requests"
  ].join("; "),
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
  "permissions-policy":
    "camera=(), geolocation=(), microphone=(), payment=(), usb=()",
  "referrer-policy": "no-referrer",
  "strict-transport-security": "max-age=31536000",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "x-permitted-cross-domain-policies": "none"
});

const NEGATIVE_PROBES = Object.freeze([
  Object.freeze({
    method: "GET",
    path: "/__tideproof_not_found__",
    acceptedStatuses: Object.freeze([404])
  }),
  Object.freeze({
    method: "GET",
    path: "/favicon.svg",
    acceptedStatuses: Object.freeze([404])
  }),
  Object.freeze({
    method: "HEAD",
    path: "/",
    acceptedStatuses: Object.freeze([404, 405])
  }),
  Object.freeze({
    method: "POST",
    path: "/api/scenario",
    acceptedStatuses: Object.freeze([404, 405])
  }),
  Object.freeze({
    method: "GET",
    path: "/advisory",
    acceptedStatuses: Object.freeze([404, 405])
  }),
  Object.freeze({
    method: "POST",
    path: "/advisory",
    acceptedStatuses: Object.freeze([401, 403]),
    body: "{}",
    headers: Object.freeze({
      "content-type": "application/json"
    })
  })
]);

function exactKeys(value, keys) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join("\n") ===
      [...keys].sort().join("\n")
  );
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function cacheControl(path) {
  return path === "/app.js" ||
    path === "/styles.css" ||
    path === "/architecture.svg"
    ? "public, max-age=300, must-revalidate"
    : "no-store";
}

function normalizeBaseUrl(value, allowHttpLoopback) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error("PUBLIC_DEMO_VERIFY_URL");
  }
  const loopback =
    url.hostname === "127.0.0.1" ||
    url.hostname === "localhost" ||
    url.hostname === "[::1]" ||
    url.hostname === "::1";
  if (
    (url.protocol !== "https:" &&
      !(allowHttpLoopback && url.protocol === "http:" && loopback)) ||
    url.username ||
    url.password ||
    url.pathname !== "/" ||
    url.search ||
    url.hash
  ) {
    throw new Error("PUBLIC_DEMO_VERIFY_URL");
  }
  return `${url.origin}/`;
}

function validateExpectedBinding(value) {
  const keys = [
    "configDigest",
    "demoArtifactDigest",
    "demoSourceDigest",
    "packageLockDigest",
    "sourceCommit",
    "treeDigest"
  ];
  if (
    !exactKeys(value, keys) ||
    !HEX_40.test(value.sourceCommit) ||
    !HEX_40.test(value.treeDigest) ||
    !HEX_64.test(value.configDigest) ||
    !HEX_64.test(value.demoArtifactDigest) ||
    !HEX_64.test(value.demoSourceDigest) ||
    !HEX_64.test(value.packageLockDigest)
  ) {
    throw new Error("PUBLIC_DEMO_VERIFY_BINDING");
  }
  return Object.freeze({ ...value });
}

function validateExpectedAssets(value) {
  if (!exactKeys(value, PUBLIC_ASSET_PATHS)) {
    throw new Error("PUBLIC_DEMO_VERIFY_ASSET_SET");
  }
  const assets = {};
  for (const path of PUBLIC_ASSET_PATHS) {
    const source = value[path];
    let body;
    if (typeof source === "string") {
      body = Buffer.from(source, "utf8");
    } else if (Buffer.isBuffer(source) || ArrayBuffer.isView(source)) {
      body = Buffer.from(
        source.buffer,
        source.byteOffset,
        source.byteLength
      );
    } else {
      throw new Error("PUBLIC_DEMO_VERIFY_ASSET");
    }
    if (body.length === 0 || body.length > MAX_RESPONSE_BYTES) {
      throw new Error("PUBLIC_DEMO_VERIFY_ASSET");
    }
    assets[path] = body;
  }
  return Object.freeze(assets);
}

function asBoundedBuffer(value, code) {
  let body;
  if (typeof value === "string") {
    body = Buffer.from(value, "utf8");
  } else if (Buffer.isBuffer(value) || ArrayBuffer.isView(value)) {
    body = Buffer.from(
      value.buffer,
      value.byteOffset,
      value.byteLength
    );
  } else {
    throw new Error(code);
  }
  if (body.length === 0 || body.length > MAX_RESPONSE_BYTES) {
    throw new Error(code);
  }
  return body;
}

async function expectedDynamicBodies(factory, functionVersion) {
  let responses;
  try {
    responses = await factory(functionVersion);
  } catch {
    throw new Error("PUBLIC_DEMO_VERIFY_EXPECTED_DYNAMIC");
  }
  const paths = ["/api/health", "/api/scenario"];
  if (!exactKeys(responses, paths)) {
    throw new Error("PUBLIC_DEMO_VERIFY_EXPECTED_DYNAMIC");
  }
  return Object.freeze(
    Object.fromEntries(
      paths.map((path) => [
        path,
        asBoundedBuffer(
          responses[path],
          "PUBLIC_DEMO_VERIFY_EXPECTED_DYNAMIC"
        )
      ])
    )
  );
}

async function readBoundedBody(response) {
  const declaredLength = response.headers.get("content-length");
  if (
    declaredLength !== null &&
    (!/^[0-9]+$/.test(declaredLength) ||
      Number(declaredLength) > MAX_RESPONSE_BYTES)
  ) {
    throw new Error("PUBLIC_DEMO_VERIFY_RESPONSE_SIZE");
  }
  if (!response.body) {
    return Buffer.alloc(0);
  }
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    total += value.byteLength;
    if (total > MAX_RESPONSE_BYTES) {
      await reader.cancel();
      throw new Error("PUBLIC_DEMO_VERIFY_RESPONSE_SIZE");
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks, total);
}

async function boundedFetch(fetchImpl, url, options, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  timer.unref?.();
  try {
    const response = await fetchImpl(url, {
      ...options,
      credentials: "omit",
      redirect: "manual",
      referrerPolicy: "no-referrer",
      signal: controller.signal
    });
    const body = await readBoundedBody(response);
    return { response, body };
  } catch (error) {
    if (error?.name === "AbortError") {
      throw new Error("PUBLIC_DEMO_VERIFY_TIMEOUT");
    }
    if (
      error instanceof Error &&
      error.message.startsWith("PUBLIC_DEMO_VERIFY_")
    ) {
      throw error;
    }
    throw new Error("PUBLIC_DEMO_VERIFY_REQUEST");
  } finally {
    clearTimeout(timer);
  }
}

function waitFor(milliseconds) {
  return new Promise((resolve) => {
    setTimeout(resolve, milliseconds);
  });
}

function assertPositiveHeaders(response, path) {
  if (
    response.status !== 200 ||
    response.headers.get("content-type") !== CONTENT_TYPES[path] ||
    response.headers.get("cache-control") !== cacheControl(path)
  ) {
    throw new Error("PUBLIC_DEMO_VERIFY_RESPONSE_CONTRACT");
  }
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
    if (response.headers.get(name) !== value) {
      throw new Error("PUBLIC_DEMO_VERIFY_SECURITY_HEADERS");
    }
  }
  if (
    response.headers.has("set-cookie") ||
    response.headers.has("access-control-allow-origin")
  ) {
    throw new Error("PUBLIC_DEMO_VERIFY_AMBIENT_AUTH");
  }
}

function parseJson(body, code) {
  try {
    return JSON.parse(body.toString("utf8"));
  } catch {
    throw new Error(code);
  }
}

function assertBoundValue(actual, expected, key) {
  if (actual[key] !== expected[key]) {
    throw new Error("PUBLIC_DEMO_VERIFY_BINDING_MISMATCH");
  }
}

function validateHealth(body, expected) {
  const health = parseJson(body, "PUBLIC_DEMO_VERIFY_HEALTH_JSON");
  const keys = [
    "authorityCapability",
    "configDigest",
    "demoArtifactDigest",
    "demoSourceDigest",
    "functionVersion",
    "mode",
    "ok",
    "packageLockDigest",
    "schemaVersion",
    "signedOut",
    "sourceCommit",
    "syntheticOnly",
    "treeDigest"
  ];
  if (
    !exactKeys(health, keys) ||
    health.schemaVersion !== "tideproof.public-demo-health.v1" ||
    health.ok !== true ||
    health.mode !== "AWS_READ_ONLY_DEMO" ||
    health.signedOut !== true ||
    health.syntheticOnly !== true ||
    health.authorityCapability !== false ||
    !POSITIVE_INTEGER.test(health.functionVersion)
  ) {
    throw new Error("PUBLIC_DEMO_VERIFY_HEALTH");
  }
  for (const key of Object.keys(expected)) {
    assertBoundValue(health, expected, key);
  }
  return health;
}

function validateScenario(body, expected, functionVersion) {
  const scenario = parseJson(
    body,
    "PUBLIC_DEMO_VERIFY_SCENARIO_JSON"
  );
  const gateTwo = scenario?.proofStates?.gateTwo;
  const hostReceipt = gateTwo?.hostReceipt;
  const hostReceiptKeys = [
    "authorityCapability",
    "configDigest",
    "demoArtifactDigest",
    "demoSourceDigest",
    "functionVersion",
    "packageLockDigest",
    "platform",
    "schemaVersion",
    "signedOut",
    "sourceCommit",
    "syntheticOnly",
    "treeDigest"
  ];
  if (
    !Array.isArray(scenario?.timeline) ||
    scenario.timeline.length === 0 ||
    !scenario?.invariants ||
    Object.keys(scenario.invariants).length === 0 ||
    !Object.values(scenario.invariants).every((value) => value === true) ||
    gateTwo?.badge !== "GATE TWO · AWS HOST" ||
    !exactKeys(hostReceipt, hostReceiptKeys) ||
    hostReceipt.schemaVersion !== "tideproof.public-demo-host.v1" ||
    hostReceipt.platform !== "AWS Lambda + API Gateway" ||
    hostReceipt.signedOut !== true ||
    hostReceipt.syntheticOnly !== true ||
    hostReceipt.authorityCapability !== false ||
    hostReceipt.functionVersion !== functionVersion
  ) {
    throw new Error("PUBLIC_DEMO_VERIFY_SCENARIO");
  }
  for (const key of Object.keys(expected)) {
    assertBoundValue(hostReceipt, expected, key);
  }
  return scenario;
}

function validateRootDisclosure(body) {
  const html = body.toString("utf8");
  const required = [
    "Synthetic scenario · Not operational emergency software",
    "A TrustAgentic.ai project",
    "https://github.com/Flash-Bri/prooftoact",
    "id=\"gate-two-proof-state\""
  ];
  if (!required.every((value) => html.includes(value))) {
    throw new Error("PUBLIC_DEMO_VERIFY_DISCLOSURE");
  }
}

export async function verifyPublicDemo({
  baseUrl,
  expectedAssets,
  expectedBinding,
  expectedDynamicResponses,
  fetchImpl = globalThis.fetch,
  timeoutMs = 10_000,
  allowHttpLoopback = false,
  now = () => new Date(),
  wait = waitFor
}) {
  if (
    typeof fetchImpl !== "function" ||
    typeof expectedDynamicResponses !== "function" ||
    typeof wait !== "function" ||
    !Number.isInteger(timeoutMs) ||
    timeoutMs < 1_000 ||
    timeoutMs > 30_000
  ) {
    throw new Error("PUBLIC_DEMO_VERIFY_OPTIONS");
  }
  const root = normalizeBaseUrl(baseUrl, allowHttpLoopback);
  const assets = validateExpectedAssets(expectedAssets);
  const binding = validateExpectedBinding(expectedBinding);
  const routeReceipts = [];
  let health;
  let scenario;
  let dynamicBodies;
  let requestIndex = 0;
  let pacingWaits = 0;

  async function paceRequest() {
    if (requestIndex >= INITIAL_BURST_REQUESTS) {
      try {
        await wait(REFILL_DELAY_MS);
      } catch {
        throw new Error("PUBLIC_DEMO_VERIFY_PACING");
      }
      pacingWaits += 1;
    }
    requestIndex += 1;
  }

  for (const path of PUBLIC_DEMO_PATHS) {
    const url = new URL(path, root);
    await paceRequest();
    const { response, body } = await boundedFetch(
      fetchImpl,
      url,
      { method: "GET" },
      timeoutMs
    );
    assertPositiveHeaders(response, path);
    if (path === "/api/health") {
      health = validateHealth(body, binding);
      dynamicBodies = await expectedDynamicBodies(
        expectedDynamicResponses,
        health.functionVersion
      );
      if (!body.equals(dynamicBodies[path])) {
        throw new Error("PUBLIC_DEMO_VERIFY_DYNAMIC_MISMATCH");
      }
    } else if (path === "/api/scenario") {
      if (!health) {
        throw new Error("PUBLIC_DEMO_VERIFY_HEALTH_ORDER");
      }
      if (!body.equals(dynamicBodies[path])) {
        throw new Error("PUBLIC_DEMO_VERIFY_DYNAMIC_MISMATCH");
      }
      scenario = validateScenario(
        body,
        binding,
        health.functionVersion
      );
    } else if (!body.equals(assets[path])) {
      throw new Error("PUBLIC_DEMO_VERIFY_ASSET_MISMATCH");
    }
    if (path === "/") {
      validateRootDisclosure(body);
    }
    routeReceipts.push({
      path,
      status: response.status,
      contentType: response.headers.get("content-type"),
      bytes: body.length,
      sha256: sha256(body)
    });
  }

  const negativeReceipts = [];
  for (const probe of NEGATIVE_PROBES) {
    await paceRequest();
    const { response } = await boundedFetch(
      fetchImpl,
      new URL(probe.path, root),
      {
        method: probe.method,
        body: probe.body,
        headers: probe.headers
      },
      timeoutMs
    );
    if (!probe.acceptedStatuses.includes(response.status)) {
      throw new Error("PUBLIC_DEMO_VERIFY_NEGATIVE_PROBE");
    }
    negativeReceipts.push({
      method: probe.method,
      path: probe.path,
      status: response.status
    });
  }

  const observedAt = now();
  if (
    !(observedAt instanceof Date) ||
    Number.isNaN(observedAt.getTime())
  ) {
    throw new Error("PUBLIC_DEMO_VERIFY_CLOCK");
  }

  return {
    schemaVersion: "tideproof.public-demo-verification.v1",
    status: "PASS",
    observedAt: observedAt.toISOString(),
    baseUrl: root,
    requestCount:
      routeReceipts.length + negativeReceipts.length,
    pacing: {
      initialBurstRequests: INITIAL_BURST_REQUESTS,
      refillDelayMs: REFILL_DELAY_MS,
      waits: pacingWaits
    },
    binding: {
      ...binding,
      functionVersion: health.functionVersion
    },
    routes: routeReceipts,
    negativeProbes: negativeReceipts,
    invariantCount: Object.keys(scenario.invariants).length,
    signedOut: true,
    syntheticOnly: true,
    authorityCapability: false
  };
}

export const __test = Object.freeze({
  CONTENT_TYPES,
  INITIAL_BURST_REQUESTS,
  NEGATIVE_PROBES,
  PUBLIC_ASSET_PATHS,
  REFILL_DELAY_MS,
  SECURITY_HEADERS
});
