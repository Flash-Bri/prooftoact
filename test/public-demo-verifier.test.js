import assert from "node:assert/strict";
import http from "node:http";
import test from "node:test";
import {
  createPublicDemoHandler,
  PUBLIC_DEMO_PATHS
} from "../src/cloud/public-demo.js";
import {
  verifyPublicDemo,
  __test
} from "../src/cloud/public-demo-verifier.js";
import { runScenario } from "../src/scenario.js";
import {
  __test as scriptTest
} from "../scripts/gate2-public-demo-verify.js";

const binding = Object.freeze({
  expectedApiId: "demo1234",
  sourceCommit: "1".repeat(40),
  treeDigest: "2".repeat(40),
  configDigest: "3".repeat(64),
  demoSourceDigest: "4".repeat(64),
  demoArtifactDigest: "5".repeat(64),
  packageLockDigest: "6".repeat(64),
  functionVersion: "7"
});

const expectedBinding = Object.freeze({
  sourceCommit: binding.sourceCommit,
  treeDigest: binding.treeDigest,
  configDigest: binding.configDigest,
  demoSourceDigest: binding.demoSourceDigest,
  demoArtifactDigest: binding.demoArtifactDigest,
  packageLockDigest: binding.packageLockDigest
});

function assets() {
  return {
    "/": [
      "<!doctype html>",
      "<title>Tideproof</title>",
      "Synthetic scenario · Not operational emergency software",
      "A TrustAgentic.ai project",
      "https://github.com/Flash-Bri/tideproof",
      '<span id="gate-two-proof-state">pending</span>'
    ].join("\n"),
    "/app.js": "export const tideproof = true;\n",
    "/styles.css": ":root { color-scheme: dark; }\n",
    "/favicon.svg":
      '<svg xmlns="http://www.w3.org/2000/svg"></svg>\n',
    "/architecture.svg": [
      '<svg xmlns="http://www.w3.org/2000/svg" role="img">',
      "<title>Tideproof trust boundaries</title>",
      "</svg>",
      ""
    ].join("\n"),
    "/evidence/gate1-authority": "# Authority evidence\n",
    "/evidence/gate1-recovery": "# Recovery evidence\n",
    "/evidence/gate1-ambiguity": "# Ambiguity evidence\n",
    "/claims": "# Claims\n"
  };
}

function event(path) {
  return {
    version: "2.0",
    rawPath: path,
    requestContext: {
      apiId: binding.expectedApiId,
      stage: "$default",
      routeKey: `GET ${path}`,
      http: { method: "GET", path }
    }
  };
}

async function expectedDynamicResponses(functionVersion) {
  const expectedApiId = "local123";
  const handler = createPublicDemoHandler({
    assets: assets(),
    binding: {
      ...binding,
      expectedApiId,
      functionVersion
    },
    runScenario
  });
  const request = (path) => ({
    version: "2.0",
    rawPath: path,
    requestContext: {
      apiId: expectedApiId,
      stage: "$default",
      routeKey: `GET ${path}`,
      http: { method: "GET", path }
    }
  });
  const health = await handler(request("/api/health"));
  const scenario = await handler(request("/api/scenario"));
  return {
    "/api/health": health.body,
    "/api/scenario": scenario.body
  };
}

async function withDemoServer(options, callback) {
  const handler = createPublicDemoHandler({
    assets: assets(),
    binding,
    runScenario
  });
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url, "http://127.0.0.1");
    let result;
    if (request.method === "POST" && url.pathname === "/advisory") {
      result = {
        statusCode: options.advisoryStatus ?? 403,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ message: "Forbidden" })
      };
    } else if (
      request.method !== "GET" ||
      !PUBLIC_DEMO_PATHS.includes(url.pathname)
    ) {
      result = {
        statusCode: 404,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ message: "Not Found" })
      };
    } else {
      result = await handler(event(url.pathname));
    }
    if (options.mutate) {
      result =
        options.mutate({
          method: request.method,
          path: url.pathname,
          result
        }) ?? result;
    }
    response.writeHead(result.statusCode, result.headers);
    response.end(result.body);
  });

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}/`;
  try {
    return await callback(baseUrl);
  } finally {
    await new Promise((resolve, reject) => {
      server.close((error) => {
        if (error) {
          reject(error);
        } else {
          resolve();
        }
      });
    });
  }
}

function verify(baseUrl, overrides = {}) {
  return verifyPublicDemo({
    baseUrl,
    expectedAssets: assets(),
    expectedBinding,
    expectedDynamicResponses,
    allowHttpLoopback: true,
    now: () => new Date("2026-07-31T04:00:00.000Z"),
    wait: async () => {},
    ...overrides
  });
}

test("public demo verifier binds every route and denial", async () => {
  await withDemoServer({}, async (baseUrl) => {
    const receipt = await verify(baseUrl);
    assert.equal(receipt.status, "PASS");
    assert.equal(
      receipt.schemaVersion,
      "tideproof.public-demo-verification.v1"
    );
    assert.equal(
      receipt.observedAt,
      "2026-07-31T04:00:00.000Z"
    );
    assert.equal(
      receipt.requestCount,
      PUBLIC_DEMO_PATHS.length + __test.NEGATIVE_PROBES.length
    );
    assert.deepEqual(
      receipt.routes.map((route) => route.path),
      PUBLIC_DEMO_PATHS
    );
    assert.equal(receipt.binding.functionVersion, "7");
    assert.equal(receipt.invariantCount, 8);
    assert.equal(receipt.authorityCapability, false);
    assert.deepEqual(receipt.pacing, {
      initialBurstRequests: 8,
      refillDelayMs: 21_000,
      waits: 8
    });
    assert.deepEqual(
      receipt.negativeProbes.map(
        ({ method, path, status }) => `${method} ${path} ${status}`
      ),
      [
        "GET /__tideproof_not_found__ 404",
        "HEAD / 404",
        "POST /api/scenario 404",
        "GET /advisory 404",
        "POST /advisory 403"
      ]
    );
  });
});

test("public demo verifier rejects changed public bytes", async () => {
  await withDemoServer(
    {
      mutate({ path, result }) {
        return path === "/app.js"
          ? { ...result, body: `${result.body}// changed\n` }
          : result;
      }
    },
    async (baseUrl) => {
      await assert.rejects(
        verify(baseUrl),
        /PUBLIC_DEMO_VERIFY_ASSET_MISMATCH/
      );
    }
  );
});

test("public demo verifier rejects weakened browser headers", async () => {
  await withDemoServer(
    {
      mutate({ path, result }) {
        if (path !== "/styles.css") {
          return result;
        }
        const headers = { ...result.headers };
        delete headers["strict-transport-security"];
        return { ...result, headers };
      }
    },
    async (baseUrl) => {
      await assert.rejects(
        verify(baseUrl),
        /PUBLIC_DEMO_VERIFY_SECURITY_HEADERS/
      );
    }
  );
});

test("public demo verifier rejects changed health bindings", async () => {
  await withDemoServer({}, async (baseUrl) => {
    await assert.rejects(
      verify(baseUrl, {
        expectedBinding: {
          ...expectedBinding,
          configDigest: "9".repeat(64)
        }
      }),
      /PUBLIC_DEMO_VERIFY_BINDING_MISMATCH/
    );
  });
});

test("public demo verifier rejects changed dynamic response bytes", async () => {
  await withDemoServer(
    {
      mutate({ path, result }) {
        return path === "/api/scenario"
          ? { ...result, body: `${result.body}\n` }
          : result;
      }
    },
    async (baseUrl) => {
      await assert.rejects(
        verify(baseUrl),
        /PUBLIC_DEMO_VERIFY_DYNAMIC_MISMATCH/
      );
    }
  );
});

test("public demo verifier rejects a signed-out advisory success", async () => {
  await withDemoServer({ advisoryStatus: 200 }, async (baseUrl) => {
    await assert.rejects(
      verify(baseUrl),
      /PUBLIC_DEMO_VERIFY_NEGATIVE_PROBE/
    );
  });
});

test("public demo verifier rejects non-TLS public origins", async () => {
  await assert.rejects(
    verifyPublicDemo({
      baseUrl: "http://example.com/",
      expectedAssets: assets(),
      expectedBinding,
      expectedDynamicResponses
    }),
    /PUBLIC_DEMO_VERIFY_URL/
  );
});

test("public demo verifier CLI accepts only the exact argument pair", () => {
  assert.deepEqual(
    scriptTest.parseArguments([
      "--config-digest",
      "a".repeat(64),
      "--url",
      "https://demo.example/"
    ]),
    {
      baseUrl: "https://demo.example/",
      configDigest: "a".repeat(64)
    }
  );
  assert.throws(
    () =>
      scriptTest.parseArguments([
        "--url",
        "https://demo.example/",
        "--config-digest",
        "not-a-digest"
      ]),
    /PUBLIC_DEMO_VERIFY_USAGE/
  );
  assert.throws(
    () =>
      scriptTest.parseArguments([
        "--url",
        "https://demo.example/",
        "--url",
        "https://other.example/"
      ]),
    /PUBLIC_DEMO_VERIFY_USAGE/
  );
});

test("public demo verifier CLI recreates bound dynamic responses", async () => {
  const dynamic = await scriptTest.localDynamicResponses(
    Object.fromEntries(
      Object.entries(assets()).map(([path, body]) => [
        path,
        Buffer.from(body, "utf8")
      ])
    ),
    expectedBinding,
    "19"
  );
  const health = JSON.parse(dynamic["/api/health"]);
  const scenario = JSON.parse(dynamic["/api/scenario"]);
  assert.equal(health.functionVersion, "19");
  assert.equal(health.demoArtifactDigest, binding.demoArtifactDigest);
  assert.equal(
    scenario.proofStates.gateTwo.hostReceipt.functionVersion,
    "19"
  );
  assert.equal(
    scenario.proofStates.gateTwo.hostReceipt.authorityCapability,
    false
  );
});
