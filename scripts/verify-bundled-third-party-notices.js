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
const ARTIFACT_NAMES = Object.freeze([
  "agent",
  "authority",
  "boundary",
  "demo",
  "probe",
  "signer"
]);

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
  for (const name of ARTIFACT_NAMES) {
    const extension = name === "demo" ? "js" : "cjs";
    const result = await build({
      absWorkingDir: resolvedRoot,
      entryPoints: [`infra/aws/lambda/${name}.${extension}`],
      bundle: true,
      platform: "node",
      target: "node22",
      format: "cjs",
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
