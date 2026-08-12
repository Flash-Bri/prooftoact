import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { build } from "esbuild";

import {
  packageNamesFromMetafile,
  renderBundledThirdPartyNotices,
  verifyBundledThirdPartyNotices
} from "./lib/bundled-third-party-notices.js";
import { rawTextPlugin } from "./lib/raw-text-plugin.js";

const DEFAULT_ROOT = fileURLToPath(new URL("..", import.meta.url));
const NOTICE_PATH = "THIRD_PARTY_NOTICES.txt";
const BUNDLED_COMPONENTS = Object.freeze({
  agent: "infra/aws/lambda/agent.cjs",
  authority: "infra/aws/lambda/authority.cjs",
  boundary: "infra/aws/lambda/boundary.cjs",
  demo: "infra/aws/lambda/demo.js",
  evidenceProvider: "scripts/lib/aws-provider-bundle-entry.js",
  probe: "infra/aws/lambda/probe.cjs",
  signer: "infra/aws/lambda/signer.cjs",
  runtimeAuthorityRace:
    "scripts/runtime-entries/integrated-live-drill-authority-race.js",
  runtimeDvi: "scripts/runtime-entries/integrated-live-drill-dvi.js",
  runtimeFinalizer:
    "scripts/runtime-entries/integrated-live-drill-finalizer.js",
  runtimeOrchestrator:
    "scripts/runtime-entries/integrated-live-drill-orchestrator.js",
  runtimeReconciler:
    "scripts/runtime-entries/integrated-live-drill-reconciler.js",
  runtimeRecovery:
    "scripts/runtime-entries/integrated-live-drill-recovery.js",
  runtimeSupervisor:
    "scripts/runtime-entries/integrated-live-drill-supervisor.js",
  runtimeWorker: "scripts/runtime-entries/integrated-live-drill-worker.js"
});

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function sorted(values) {
  return [...values].sort((left, right) =>
    left < right ? -1 : left > right ? 1 : 0
  );
}

export async function collectBundledPackageNames({
  rootDir = DEFAULT_ROOT
} = {}) {
  const resolvedRoot = path.resolve(rootDir);
  const artifactPackages = {};
  const packageUnion = new Set();
  for (const [name, entryPoint] of Object.entries(BUNDLED_COMPONENTS)) {
    const providerRuntime =
      name === "evidenceProvider" || name.startsWith("runtime");
    const result = await build({
      absWorkingDir: resolvedRoot,
      entryPoints: [entryPoint],
      bundle: true,
      platform: "node",
      target: "node22",
      format: providerRuntime ? "esm" : "cjs",
      banner: providerRuntime
        ? {
            js:
              "import { builtinModules as __tideproofBuiltins, createRequire as __tideproofCreateRequire } from \"node:module\"; const __tideproofNativeRequire = __tideproofCreateRequire(\"/tideproof-evidence-provider-runtime.mjs\"); const __tideproofAllowedRequires = new Set(__tideproofBuiltins.flatMap((name) => [name, name.startsWith(\"node:\") ? name : `node:${name}`])); const require = (specifier) => { if (!__tideproofAllowedRequires.has(specifier)) throw new Error(\"AWS_PROVIDER_RUNTIME_EXTERNAL_REQUIRE\"); return __tideproofNativeRequire(specifier.startsWith(\"node:\") ? specifier : `node:${specifier}`); };"
          }
        : undefined,
      legalComments: "none",
      logLevel: "silent",
      metafile: true,
      write: false,
      plugins: [rawTextPlugin()]
    });
    const packageNames = packageNamesFromMetafile(result.metafile);
    artifactPackages[name] = packageNames;
    packageNames.forEach((packageName) => packageUnion.add(packageName));
  }
  const packageNames = sorted(packageUnion);
  assert(packageNames.length > 0, "Gate Two bundles contain no npm packages");
  return { artifactPackages, packageNames };
}

export async function verifyCurrentBundledThirdPartyNotices({
  rootDir = DEFAULT_ROOT
} = {}) {
  const bundled = await collectBundledPackageNames({ rootDir });
  return {
    ...verifyBundledThirdPartyNotices({
      rootDir,
      packageNames: bundled.packageNames
    }),
    artifactPackages: bundled.artifactPackages
  };
}

async function main() {
  const args = process.argv.slice(2);
  assert(
    args.length <= 1 &&
      (args.length === 0 || args[0] === "--print" || args[0] === "--write"),
    "usage: node scripts/verify-bundled-third-party-notices.js [--print|--write]"
  );
  const bundled = await collectBundledPackageNames();
  if (args[0] === "--print" || args[0] === "--write") {
    const rendered = renderBundledThirdPartyNotices({
      packageNames: bundled.packageNames
    });
    if (args[0] === "--write") {
      fs.writeFileSync(path.join(DEFAULT_ROOT, NOTICE_PATH), rendered.content, {
        encoding: "utf8",
        mode: 0o644
      });
      process.stdout.write(
        `${JSON.stringify(
          {
            status: "WROTE",
            noticePath: NOTICE_PATH,
            noticeSha256: rendered.noticeSha256,
            noticeBytes: rendered.noticeBytes,
            packageNames: rendered.packageNames,
            packageCount: rendered.packageCount,
            licenseTextCount: rendered.licenseTextCount,
            fallbackCount: rendered.fallbackCount
          },
          null,
          2
        )}\n`
      );
    } else {
      process.stdout.write(rendered.content);
    }
    return;
  }
  process.stdout.write(
    `${JSON.stringify(
      {
        ...verifyBundledThirdPartyNotices({
          packageNames: bundled.packageNames
        }),
        artifactPackages: bundled.artifactPackages
      },
      null,
      2
    )}\n`
  );
}

const startedDirectly =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (startedDirectly) {
  main().catch((error) => {
    process.stderr.write(`BUNDLED_THIRD_PARTY_NOTICES_FAIL: ${error.message}\n`);
    process.exitCode = 1;
  });
}
