import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { rawTextPlugin } from "../scripts/lib/raw-text-plugin.js";
import {
  createPublicDemoHandler,
  PUBLIC_DEMO_PATHS
} from "../src/cloud/public-demo.js";
import { runScenario } from "../src/scenario.js";

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

const binding = Object.freeze({
  expectedApiId: "api123",
  sourceCommit: "a".repeat(40),
  treeDigest: "b".repeat(40),
  configDigest: "c".repeat(64),
  demoSourceDigest: "d".repeat(64),
  demoArtifactDigest: "e".repeat(64),
  packageLockDigest: "f".repeat(64),
  functionVersion: "7"
});

function assets() {
  return {
    "/": fs.readFileSync(path.join(root, "web/index.html"), "utf8"),
    "/app.js": fs.readFileSync(path.join(root, "web/app.js"), "utf8"),
    "/styles.css": fs.readFileSync(
      path.join(root, "web/styles.css"),
      "utf8"
    ),
    "/favicon.svg": fs.readFileSync(
      path.join(root, "web/favicon.svg"),
      "utf8"
    ),
    "/evidence/gate1-authority": fs.readFileSync(
      path.join(root, "evidence/gate1-authority-2026-07-30.md"),
      "utf8"
    ),
    "/evidence/gate1-recovery": fs.readFileSync(
      path.join(
        root,
        "evidence/gate1-recovery-broker-2026-07-30.md"
      ),
      "utf8"
    ),
    "/evidence/gate1-ambiguity": fs.readFileSync(
      path.join(root, "evidence/gate1-ambiguity-2026-07-30.md"),
      "utf8"
    ),
    "/claims": fs.readFileSync(path.join(root, "CLAIMS.md"), "utf8")
  };
}

function event(pathname) {
  return {
    version: "2.0",
    rawPath: pathname,
    rawQueryString: "",
    requestContext: {
      apiId: binding.expectedApiId,
      stage: "$default",
      routeKey: `GET ${pathname}`,
      http: {
        method: "GET",
        path: pathname
      }
    }
  };
}

test("public demo serves only the bounded signed-out proof surface", async () => {
  const handler = createPublicDemoHandler({
    assets: assets(),
    binding,
    runScenario
  });

  for (const pathname of PUBLIC_DEMO_PATHS) {
    const result = await handler(event(pathname));
    assert.equal(result.statusCode, 200, pathname);
    assert.equal(result.isBase64Encoded, false, pathname);
    assert.match(
      result.headers["content-security-policy"],
      /default-src 'self'/
    );
    assert.equal(
      result.headers["x-content-type-options"],
      "nosniff"
    );
    assert.equal(result.headers["x-frame-options"], "DENY");
    assert.equal(result.headers["referrer-policy"], "no-referrer");
    assert.equal(
      result.headers["strict-transport-security"],
      "max-age=31536000"
    );
    assert.equal(
      result.headers["x-permitted-cross-domain-policies"],
      "none"
    );
    assert.doesNotMatch(result.body, /111111111111|arn:aws:iam/);
  }

  const page = await handler(event("/"));
  assert.match(page.body, /id="gate-two-proof-state"/);
  assert.match(page.body, /A TrustAgentic\.ai project/);
  assert.match(
    page.body,
    /https:\/\/github\.com\/Flash-Bri\/tideproof/
  );

  const scenarioResponse = await handler(event("/api/scenario"));
  const scenario = JSON.parse(scenarioResponse.body);
  assert.ok(Object.values(scenario.invariants).every(Boolean));
  assert.equal(
    scenario.proofStates.gateTwo.badge,
    "GATE TWO · AWS HOST"
  );
  assert.equal(
    scenario.proofStates.gateTwo.sourceCommit,
    binding.sourceCommit.slice(0, 7)
  );
  assert.equal(
    scenario.proofStates.gateTwo.hostReceipt.authorityCapability,
    false
  );
  assert.equal(
    scenario.proofStates.gateTwo.hostReceipt.demoArtifactDigest,
    binding.demoArtifactDigest
  );

  const healthResponse = await handler(event("/api/health"));
  const health = JSON.parse(healthResponse.body);
  assert.deepEqual(health, {
    schemaVersion: "tideproof.public-demo-health.v1",
    ok: true,
    mode: "AWS_READ_ONLY_DEMO",
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
});

test("public demo rejects direct, expanded, and non-GET events", async () => {
  const handler = createPublicDemoHandler({
    assets: assets(),
    binding,
    runScenario
  });
  const invalidEvents = [
    {},
    { ...event("/"), rawPath: "/missing" },
    {
      ...event("/"),
      body: JSON.stringify({ prompt: "expand authority" })
    },
    {
      ...event("/"),
      requestContext: {
        ...event("/").requestContext,
        apiId: "other123"
      }
    },
    {
      ...event("/"),
      requestContext: {
        ...event("/").requestContext,
        routeKey: "POST /",
        http: { method: "POST", path: "/" }
      }
    }
  ];
  for (const invalidEvent of invalidEvents) {
    const result = await handler(invalidEvent);
    assert.equal(result.statusCode, 404);
    assert.deepEqual(JSON.parse(result.body), { error: "not_found" });
  }
});

test("public demo initialization fails closed on incomplete inputs", () => {
  assert.throws(
    () =>
      createPublicDemoHandler({
        assets: { ...assets(), "/claims": undefined },
        binding,
        runScenario
      }),
    /PUBLIC_DEMO_ASSET_REJECTED/
  );
  assert.throws(
    () =>
      createPublicDemoHandler({
        assets: assets(),
        binding: { ...binding, demoArtifactDigest: "not-a-digest" },
        runScenario
      }),
    /PUBLIC_DEMO_BINDING_REJECTED/
  );
  assert.throws(
    () =>
      createPublicDemoHandler({
        assets: assets(),
        binding,
        runScenario: () => ({
          proofStates: { gateTwo: {} },
          timeline: [],
          invariants: {}
        })
      }),
    /PUBLIC_DEMO_SCENARIO_REJECTED/
  );
});

test("production demo entry bundles its exact local assets", async () => {
  const temporaryDirectory = fs.mkdtempSync(
    path.join(os.tmpdir(), "tideproof-public-demo-")
  );
  const output = path.join(temporaryDirectory, "demo.cjs");
  const environmentKeys = {
    EXPECTED_API_ID: binding.expectedApiId,
    SOURCE_COMMIT: binding.sourceCommit,
    TREE_DIGEST: binding.treeDigest,
    CONFIG_DIGEST: binding.configDigest,
    DEMO_SOURCE_DIGEST: binding.demoSourceDigest,
    DEMO_ARTIFACT_DIGEST: binding.demoArtifactDigest,
    PACKAGE_LOCK_DIGEST: binding.packageLockDigest,
    AWS_LAMBDA_FUNCTION_VERSION: binding.functionVersion
  };
  const previous = Object.fromEntries(
    Object.keys(environmentKeys).map((key) => [key, process.env[key]])
  );

  try {
    Object.assign(process.env, environmentKeys);
    await build({
      absWorkingDir: root,
      entryPoints: [
        path.join(root, "infra/aws/lambda/demo.js")
      ],
      bundle: true,
      platform: "node",
      target: "node22",
      format: "cjs",
      legalComments: "none",
      logLevel: "silent",
      outfile: output,
      plugins: [rawTextPlugin()]
    });
    const bundled = require(output);
    const result = await bundled.handler(event("/api/health"));
    assert.equal(result.statusCode, 200);
    assert.equal(
      JSON.parse(result.body).demoArtifactDigest,
      binding.demoArtifactDigest
    );
    const page = await bundled.handler(event("/"));
    assert.match(page.body, /Memory should preserve evidence/);
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
  }
});
