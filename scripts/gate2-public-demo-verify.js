import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createPublicDemoHandler } from "../src/cloud/public-demo.js";
import { verifyPublicDemo } from "../src/cloud/public-demo-verifier.js";
import { runScenario } from "../src/scenario.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");
const HEX_40 = /^[0-9a-f]{40}$/;
const HEX_64 = /^[0-9a-f]{64}$/;

const ASSET_FILES = Object.freeze({
  "/": "web/index.html",
  "/app.js": "web/app.js",
  "/styles.css": "web/styles.css",
  "/favicon.svg": "web/favicon.svg",
  "/architecture.svg": "docs/media/architecture.svg",
  "/evidence/gate1-authority":
    "evidence/gate1-authority-2026-07-30.md",
  "/evidence/gate1-recovery":
    "evidence/gate1-recovery-broker-2026-07-30.md",
  "/evidence/gate1-ambiguity":
    "evidence/gate1-ambiguity-2026-07-30.md",
  "/claims": "CLAIMS.md"
});

function fail(code) {
  throw new Error(code);
}

function sha256File(filePath) {
  return crypto
    .createHash("sha256")
    .update(fs.readFileSync(filePath))
    .digest("hex");
}

function command(args, code) {
  const result = spawnSync(args[0], args.slice(1), {
    cwd: root,
    encoding: "utf8",
    maxBuffer: 20 * 1024 * 1024
  });
  if (result.error || result.status !== 0) {
    fail(code);
  }
  return result.stdout.trim();
}

function parseArguments(args) {
  const allowed = new Set(["--url", "--config-digest"]);
  const values = {};
  for (let index = 0; index < args.length; index += 2) {
    const key = args[index];
    const value = args[index + 1];
    if (
      !allowed.has(key) ||
      typeof value !== "string" ||
      value.length === 0 ||
      Object.hasOwn(values, key)
    ) {
      fail("PUBLIC_DEMO_VERIFY_USAGE");
    }
    values[key] = value;
  }
  if (
    args.length !== 4 ||
    !values["--url"] ||
    !HEX_64.test(values["--config-digest"])
  ) {
    fail("PUBLIC_DEMO_VERIFY_USAGE");
  }
  return {
    baseUrl: values["--url"],
    configDigest: values["--config-digest"]
  };
}

function exactDemoArtifact(receipt) {
  const artifacts = receipt?.artifacts;
  const demos = Array.isArray(artifacts)
    ? artifacts.filter((artifact) => artifact?.name === "demo")
    : [];
  if (demos.length !== 1) {
    fail("PUBLIC_DEMO_VERIFY_BUILD_RECEIPT");
  }
  return demos[0];
}

function validateBuildReceipt(receipt, sourceCommit, treeDigest) {
  const demo = exactDemoArtifact(receipt);
  if (
    receipt?.schemaVersion !== "tideproof.gate2-build.v2" ||
    receipt?.mode !== "CLEAN_ARTIFACT_BUILD" ||
    receipt?.workingTreeClean !== true ||
    receipt?.workingTreeCleanBeforeGeneration !== true ||
    receipt?.sourceCommit !== sourceCommit ||
    receipt?.treeDigest !== treeDigest ||
    !HEX_40.test(receipt.sourceCommit) ||
    !HEX_40.test(receipt.treeDigest) ||
    !HEX_64.test(receipt.packageLockDigest) ||
    demo.sourcePath !== "infra/aws/lambda/demo.js" ||
    !HEX_64.test(demo.sourceDigest) ||
    !HEX_64.test(demo.artifactDigest) ||
    !Number.isInteger(demo.artifactBytes) ||
    demo.artifactBytes < 1 ||
    typeof demo.artifactPath !== "string"
  ) {
    fail("PUBLIC_DEMO_VERIFY_BUILD_RECEIPT");
  }

  const artifactPath = path.resolve(root, demo.artifactPath);
  if (
    !artifactPath.startsWith(`${path.join(root, "dist", "aws")}${path.sep}`) ||
    !fs.existsSync(artifactPath) ||
    !fs.statSync(artifactPath).isFile() ||
    sha256File(artifactPath) !== demo.artifactDigest ||
    fs.statSync(artifactPath).size !== demo.artifactBytes ||
    sha256File(path.join(root, demo.sourcePath)) !== demo.sourceDigest ||
    sha256File(path.join(root, "package-lock.json")) !==
      receipt.packageLockDigest
  ) {
    fail("PUBLIC_DEMO_VERIFY_BUILD_ARTIFACT");
  }
  return demo;
}

function readExpectedAssets() {
  return Object.fromEntries(
    Object.entries(ASSET_FILES).map(([route, filePath]) => [
      route,
      fs.readFileSync(path.join(root, filePath))
    ])
  );
}

async function localDynamicResponses(
  expectedAssets,
  expectedBinding,
  functionVersion
) {
  const expectedApiId = "verify123";
  const handler = createPublicDemoHandler({
    assets: Object.fromEntries(
      Object.entries(expectedAssets).map(([route, body]) => [
        route,
        body.toString("utf8")
      ])
    ),
    binding: {
      expectedApiId,
      ...expectedBinding,
      functionVersion
    },
    runScenario
  });
  const request = (pathName) => ({
    version: "2.0",
    rawPath: pathName,
    requestContext: {
      apiId: expectedApiId,
      stage: "$default",
      routeKey: `GET ${pathName}`,
      http: { method: "GET", path: pathName }
    }
  });
  const health = await handler(request("/api/health"));
  const scenario = await handler(request("/api/scenario"));
  if (health.statusCode !== 200 || scenario.statusCode !== 200) {
    fail("PUBLIC_DEMO_VERIFY_LOCAL_DYNAMIC");
  }
  return {
    "/api/health": health.body,
    "/api/scenario": scenario.body
  };
}

export async function runPublicDemoVerification(args) {
  const { baseUrl, configDigest } = parseArguments(args);
  const sourceCommit = command(
    ["git", "rev-parse", "HEAD"],
    "PUBLIC_DEMO_VERIFY_GIT_HEAD"
  );
  const treeDigest = command(
    ["git", "rev-parse", "HEAD^{tree}"],
    "PUBLIC_DEMO_VERIFY_GIT_TREE"
  );
  if (
    command(
      ["git", "status", "--short"],
      "PUBLIC_DEMO_VERIFY_GIT_STATUS"
    ).length !== 0
  ) {
    fail("PUBLIC_DEMO_VERIFY_DIRTY_TREE");
  }

  const buildOutput = command(
    [process.execPath, "scripts/build-gate2-template.js"],
    "PUBLIC_DEMO_VERIFY_CLEAN_BUILD"
  );
  let buildReceipt;
  try {
    buildReceipt = JSON.parse(buildOutput);
  } catch {
    fail("PUBLIC_DEMO_VERIFY_BUILD_JSON");
  }
  const demo = validateBuildReceipt(
    buildReceipt,
    sourceCommit,
    treeDigest
  );

  if (
    command(
      ["git", "status", "--short"],
      "PUBLIC_DEMO_VERIFY_GIT_STATUS"
    ).length !== 0
  ) {
    fail("PUBLIC_DEMO_VERIFY_BUILD_DIRTIED_TREE");
  }

  const expectedAssets = readExpectedAssets();
  const expectedBinding = {
    sourceCommit,
    treeDigest,
    configDigest,
    demoSourceDigest: demo.sourceDigest,
    demoArtifactDigest: demo.artifactDigest,
    packageLockDigest: buildReceipt.packageLockDigest
  };
  return verifyPublicDemo({
    baseUrl,
    expectedAssets,
    expectedBinding,
    expectedDynamicResponses: (functionVersion) =>
      localDynamicResponses(
        expectedAssets,
        expectedBinding,
        functionVersion
      )
  });
}

async function main() {
  const receipt = await runPublicDemoVerification(
    process.argv.slice(2)
  );
  process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
}

const invokedPath = process.argv[1]
  ? path.resolve(process.argv[1])
  : "";
if (invokedPath === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(
      `${JSON.stringify({
        schemaVersion: "tideproof.public-demo-verification.v1",
        status: "FAIL",
        error:
          error instanceof Error
            ? error.message
            : "PUBLIC_DEMO_VERIFY_UNKNOWN"
      })}\n`
    );
    process.exitCode = 1;
  });
}

export const __test = Object.freeze({
  ASSET_FILES,
  localDynamicResponses,
  parseArguments,
  validateBuildReceipt
});
