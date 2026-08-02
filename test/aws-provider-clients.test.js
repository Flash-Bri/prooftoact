import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import { builtinModules } from "node:module";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { build } from "esbuild";

import {
  __test,
  createAwsProviderClients
} from "../scripts/lib/aws-provider-runtime.js";
import { loadAwsProviderRuntime } from "../scripts/lib/aws-provider-runtime-loader.js";
import {
  exactBuildRecord,
  validateExactBuildReproduction
} from "../scripts/lib/exact-build-reproduction.js";

test("AWS provider policy decoding accepts only structured JSON policies", () => {
  const policy = {
    Statement: [{ Action: "sts:AssumeRole", Effect: "Allow", Resource: "*" }],
    Version: "2012-10-17"
  };
  assert.deepEqual(
    __test.decodePolicyDocument(encodeURIComponent(JSON.stringify(policy))),
    policy
  );
  assert.throws(
    () => __test.decodePolicyDocument("not-json"),
    /AWS_PROVIDER_POLICY_DOCUMENT/
  );
  assert.throws(
    () => __test.decodePolicyDocument("%E0%A4%A"),
    /AWS_PROVIDER_POLICY_DOCUMENT/
  );
});

test("AWS provider caller identity strips transport metadata", () => {
  assert.deepEqual(
    __test.normalizeCallerIdentity({
      Account: "111111111111",
      Arn: "arn:aws:sts::111111111111:assumed-role/example/session",
      UserId: "AROAEXAMPLE:session",
      $metadata: { attempts: 1, httpStatusCode: 200 }
    }),
    {
      Account: "111111111111",
      Arn: "arn:aws:sts::111111111111:assumed-role/example/session",
      UserId: "AROAEXAMPLE:session"
    }
  );
  assert.throws(
    () => __test.normalizeCallerIdentity({ Account: "111111111111" }),
    /AWS_PROVIDER_CALLER_IDENTITY/
  );
});

test("AWS provider clients pin endpoints, signing, defaults, and retries", () => {
  assert.deepEqual(__test.fixedSdkOptions(), {
    authSchemePreference: ["sigv4"],
    defaultsMode: "standard",
    ignoreConfiguredEndpointUrls: true,
    retryMode: "standard",
    sigv4aSigningRegionSet: [],
    useDualstackEndpoint: false,
    useFipsEndpoint: false
  });
});

test("AWS provider clients load only the pinned explicit-credential SDK surface", async () => {
  const clients = await createAwsProviderClients({
    credentials: {
      accessKeyId: "fixture-access-key-id",
      secretAccessKey: "fixture-secret-access-key",
      sessionToken: "fixture-session-token"
    },
    region: "us-east-1"
  });
  for (const method of [
    "callerIdentity",
    "describeStacks",
    "getApi",
    "getDeployment",
    "getDeployments",
    "getFunctionConfiguration",
    "getIntegration",
    "getRole",
    "getRoute",
    "getStage",
    "listAliases",
    "listEventSourceMappings",
    "listFunctionUrlConfigs",
    "listProvisionedConcurrencyConfigs"
  ]) {
    assert.equal(typeof clients[method], "function");
  }
});

test("content-addressed production provider bundle loads every client", async () => {
  const projectRoot = path.resolve(import.meta.dirname, "..");
  const outputRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "tideproof-aws-provider-bundle-")
  );
  try {
    const builtins = new Set(
      builtinModules.map((name) => name.replace(/^node:/, ""))
    );
    const result = await build({
      absWorkingDir: projectRoot,
      banner: {
        js:
          "import { builtinModules as __tideproofBuiltins, createRequire as __tideproofCreateRequire } from \"node:module\"; const __tideproofNativeRequire = __tideproofCreateRequire(\"/tideproof-evidence-provider-runtime.mjs\"); const __tideproofAllowedRequires = new Set(__tideproofBuiltins.flatMap((name) => [name, name.startsWith(\"node:\") ? name : `node:${name}`])); const require = (specifier) => { if (!__tideproofAllowedRequires.has(specifier)) throw new Error(\"AWS_PROVIDER_RUNTIME_EXTERNAL_REQUIRE\"); return __tideproofNativeRequire(specifier.startsWith(\"node:\") ? specifier : `node:${specifier}`); };"
      },
      bundle: true,
      entryPoints: ["scripts/lib/aws-provider-bundle-entry.js"],
      format: "esm",
      legalComments: "none",
      logLevel: "silent",
      platform: "node",
      plugins: [
        {
          name: "test-node-builtins",
          setup(context) {
            context.onResolve({ filter: /.*/ }, (args) => {
              const candidate = args.path.replace(/^node:/, "");
              return builtins.has(candidate)
                ? { external: true, path: `node:${candidate}` }
                : null;
            });
          }
        }
      ],
      splitting: false,
      target: "node22",
      write: false
    });
    assert.equal(result.outputFiles.length, 1);
    const bytes = Buffer.from(result.outputFiles[0].contents);
    const digest = crypto.createHash("sha256").update(bytes).digest("hex");
    const relativePath = `dist/aws/evidence-provider-${digest}.mjs`;
    const filePath = path.join(outputRoot, relativePath);
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, bytes);
    const loaded = await loadAwsProviderRuntime({
      buildReceipt: {
        evidenceProviderRuntime: {
          bundledPackages: ["production-provider-fixture"],
          bytes: bytes.length,
          exactGitInputs: [],
          externalImports: ["node:module"],
          path: relativePath,
          sha256: digest
        }
      },
      projectRoot: outputRoot
    });
    const clients = await loaded.createAwsProviderClients({
      credentials: {
        accessKeyId: "fixture-access-key-id",
        secretAccessKey: "fixture-secret-access-key",
        sessionToken: "fixture-session-token"
      },
      region: "us-east-1"
    });
    for (const method of [
      "assumeRole",
      "callerIdentity",
      "describeStackResourceDrifts",
      "getAlias",
      "getDeployment",
      "getDeployments",
      "getIntegrations",
      "getRolePolicy",
      "getRoutes",
      "getStages",
      "getTemplate"
    ]) {
      assert.equal(typeof clients[method], "function");
    }
  } finally {
    fs.rmSync(outputRoot, { force: true, recursive: true });
  }
});

test("AWS evidence runners do not execute a PATH-selected AWS CLI", () => {
  for (const relativePath of [
    "scripts/gate2-aws-attestation.js",
    "scripts/gate2-evidence-operator-denial.js"
  ]) {
    const source = fs.readFileSync(
      path.join(path.resolve(import.meta.dirname, ".."), relativePath),
      "utf8"
    );
    assert.match(source, /loadAwsProviderRuntime/);
    assert.doesNotMatch(source, /spawnSync\(\s*["']aws["']/);
  }
});

test("alternate denial rejects a fabricated provider receipt before runtime load", () => {
  const source = fs.readFileSync(
    path.resolve(
      import.meta.dirname,
      "../scripts/gate2-evidence-operator-denial.js"
    ),
    "utf8"
  );
  const reproduction = source.indexOf(
    "const reproducedBuild = reproduceExactBuild({"
  );
  const comparison = source.indexOf(
    "validateExactBuildReproduction(",
    reproduction
  );
  const providerLoad = source.indexOf(
    "const providerRuntime = await loadAwsProviderRuntime({"
  );
  assert.equal(reproduction >= 0, true);
  assert.equal(comparison > reproduction, true);
  assert.equal(providerLoad > comparison, true);

  const fabricated = exactBuildRecord(
    Buffer.from(
      '{"evidenceProviderRuntime":{"path":"dist/aws/fabricated.mjs"}}\n'
    ),
    "FIXTURE_FABRICATED"
  );
  const reproduced = exactBuildRecord(
    Buffer.from(
      '{"evidenceProviderRuntime":{"path":"dist/aws/exact.mjs"}}\n'
    ),
    "FIXTURE_REPRODUCED"
  );
  assert.throws(
    () =>
      validateExactBuildReproduction(
        fabricated,
        reproduced,
        "AWS_ATTEST_DENIAL_EXACT_BUILD_MISMATCH"
      ),
    /AWS_ATTEST_DENIAL_EXACT_BUILD_MISMATCH/
  );
});

test("AWS provider runtime imports the exact receipt-hashed bytes", async () => {
  const projectRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "tideproof-aws-provider-runtime-")
  );
  try {
    const exactSource = Buffer.from(
      "export async function createAwsProviderClients(){return 'EXACT_RUNTIME';}\n"
    );
    const digest = crypto.createHash("sha256").update(exactSource).digest("hex");
    const relativePath = `dist/aws/evidence-provider-${digest}.mjs`;
    const filePath = path.join(projectRoot, relativePath);
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, exactSource);
    const buildReceipt = {
      evidenceProviderRuntime: {
        bundledPackages: ["fixture"],
        bytes: exactSource.length,
        exactGitInputs: [],
        externalImports: ["node:module"],
        path: relativePath,
        sha256: digest
      }
    };
    const loaded = await loadAwsProviderRuntime({ buildReceipt, projectRoot });
    fs.writeFileSync(
      filePath,
      "export async function createAwsProviderClients(){return 'SWAPPED';}\n"
    );
    assert.equal(await loaded.createAwsProviderClients(), "EXACT_RUNTIME");
    await assert.rejects(
      loadAwsProviderRuntime({ buildReceipt, projectRoot }),
      /AWS_PROVIDER_RUNTIME_FILE|AWS_PROVIDER_RUNTIME_DIGEST/
    );
  } finally {
    fs.rmSync(projectRoot, { force: true, recursive: true });
  }
});
