import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { builtinModules } from "node:module";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import {
  packageNamesFromMetafile,
  verifyBundledThirdPartyNotices
} from "./lib/bundled-third-party-notices.js";
import { writeDeterministicZip } from "./lib/deterministic-zip.js";
import {
  validateBuildToolchain,
  validateDependencySnapshot
} from "./lib/dependency-snapshot.js";
import { collectBundledPackageNames } from "./verify-bundled-third-party-notices.js";
import {
  buildAwsBootstrapTemplate,
  buildGate2Template,
  templateReceipt
} from "../src/cloud/aws-gate2-template.js";
import {
  assertExactGitSourceContext,
  exactGitSourcePlugin,
  gitInvariantArguments,
  gitEnvironment,
  readExactGitBlob,
  trustedGitExecutable,
  trustedTemporaryRoot
} from "./lib/exact-git-source.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");
const lambdaRoot = path.join(root, "infra/aws/lambda");
const artifactNames = [
  "agent",
  "authority",
  "boundary",
  "demo",
  "probe",
  "signer"
];
const buildControlPaths = Object.freeze([
  "infra/aws/lambda/agent.cjs",
  "scripts/build-gate2-exact.js",
  "scripts/build-gate2-template.js",
  "scripts/lib/aws-provider-bundle-entry.js",
  "scripts/lib/aws-provider-runtime.js",
  "scripts/lib/aws-provider-runtime-loader.js",
  "scripts/lib/bundled-third-party-notices.js",
  "scripts/lib/dependency-snapshot.js",
  "scripts/lib/deterministic-zip.js",
  "scripts/lib/exact-build-reproduction.js",
  "scripts/lib/exact-git-source.js",
  "scripts/lib/raw-text-plugin.js",
  "scripts/verify-bundled-third-party-notices.js",
  "src/cloud/aws-gate2-template.js",
  "src/cloud/public-demo.js"
]);
const nodeBuiltins = new Set(
  builtinModules.map((name) => name.replace(/^node:/, ""))
);
const argumentsList = process.argv.slice(2);
const templatesOnly =
  argumentsList.length === 1 && argumentsList[0] === "--templates-only";
const isolatedBuild =
  argumentsList.length === 2 && argumentsList[0] === "--isolated-output";
if (!templatesOnly && !isolatedBuild) {
  throw new Error("UNKNOWN_BUILD_ARGUMENT");
}
const outputRoot = isolatedBuild
  ? path.resolve(argumentsList[1])
  : root;
const distRoot = path.join(outputRoot, "dist/aws");
const templateRoot = path.join(outputRoot, "infra/aws");

function sha256File(filePath) {
  return crypto
    .createHash("sha256")
    .update(fs.readFileSync(filePath))
    .digest("hex");
}

function sha256FileBase64(filePath) {
  return crypto
    .createHash("sha256")
    .update(fs.readFileSync(filePath))
    .digest("base64");
}

function gitValue(args) {
  const result = spawnSync(
    trustedGitExecutable(),
    [...gitInvariantArguments(), ...args],
    {
      cwd: root,
      encoding: "utf8",
      env: gitEnvironment()
    }
  );
  if (result.status !== 0) {
    throw new Error(`git ${args.join(" ")} failed`);
  }
  return result.stdout.trim();
}

function gitStatus() {
  const result = spawnSync(
    trustedGitExecutable(),
    [...gitInvariantArguments(), "status", "--short"],
    {
      cwd: root,
      encoding: "utf8",
      env: gitEnvironment()
    }
  );
  if (result.status !== 0) {
    throw new Error("git status --short failed");
  }
  return result.stdout.trim();
}

async function buildArtifact(
  name,
  sourceCommit,
  noticeBytes,
  expectedPackages
) {
  const sourcePath = path.join(
    lambdaRoot,
    `${name}.${name === "demo" ? "js" : "cjs"}`
  );
  const sourceRecord = readExactGitBlob({
    rootDir: root,
    sourceCommit,
    filePath: sourcePath
  });
  const sourceDigest = sourceRecord.sha256;
  const exactSource = exactGitSourcePlugin({
    rootDir: root,
    sourceCommit,
    dependencyRoot: fs.realpathSync(path.join(root, "node_modules"))
  });
  const temporaryDirectory = fs.mkdtempSync(
    path.join(trustedTemporaryRoot(), "tideproof-gate2-")
  );
  const stagedPath = path.join(temporaryDirectory, "index.js");
  const provisionalPath = path.join(
    temporaryDirectory,
    `${name}-provisional.zip`
  );
  let result;
  try {
    result = await build({
      absWorkingDir: root,
      entryPoints: [sourcePath],
      bundle: true,
      platform: "node",
      target: "node22",
      format: "cjs",
      legalComments: "none",
      logLevel: "silent",
      metafile: true,
      outfile: stagedPath,
      plugins: [exactSource.plugin]
    });
  } catch (error) {
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
    throw new Error(`esbuild failed for ${name}: ${error.message}`);
  }
  const bundledPackages = packageNamesFromMetafile(result.metafile);
  if (JSON.stringify(bundledPackages) !== JSON.stringify(expectedPackages)) {
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
    throw new Error(`BUNDLED_PACKAGE_SET_DRIFT:${name}`);
  }
  writeDeterministicZip(provisionalPath, [
    {
      fileName: "THIRD_PARTY_NOTICES.txt",
      content: noticeBytes
    },
    {
      fileName: "index.js",
      content: fs.readFileSync(stagedPath)
    }
  ]);
  const artifactDigest = sha256File(provisionalPath);
  const artifactPath = path.join(
    distRoot,
    `${name}-${artifactDigest}.zip`
  );
  if (fs.existsSync(artifactPath)) {
    if (sha256File(artifactPath) !== artifactDigest) {
      fs.rmSync(temporaryDirectory, { recursive: true, force: true });
      throw new Error("EXISTING_ARTIFACT_DIGEST_MISMATCH");
    }
  } else {
    fs.renameSync(provisionalPath, artifactPath);
  }
  fs.rmSync(temporaryDirectory, { recursive: true, force: true });
  return {
    name,
    sourcePath: path.relative(root, sourcePath),
    sourceDigest,
    artifactPath,
    artifactFile: path.basename(artifactPath),
    artifactDigest,
    artifactCodeSha256: sha256FileBase64(artifactPath),
    artifactBytes: fs.statSync(artifactPath).size,
    bundledPackages,
    exactGitInputs: exactSource.inputRecords(),
    suggestedS3Key: `gate2/${sourceCommit}/${name}-${artifactDigest}.zip`
  };
}

function nodeBuiltinExternalPlugin() {
  return {
    name: "tideproof-node-builtins",
    setup(context) {
      context.onResolve({ filter: /.*/ }, (args) => {
        const candidate = args.path.replace(/^node:/, "");
        if (nodeBuiltins.has(candidate)) {
          return { external: true, path: `node:${candidate}` };
        }
        return null;
      });
    }
  };
}

async function buildEvidenceProviderRuntime(
  sourceCommit,
  expectedPackages
) {
  const sourcePath = path.join(
    root,
    "scripts/lib/aws-provider-bundle-entry.js"
  );
  const exactSource = exactGitSourcePlugin({
    rootDir: root,
    sourceCommit,
    dependencyRoot: fs.realpathSync(path.join(root, "node_modules"))
  });
  const temporaryDirectory = fs.mkdtempSync(
    path.join(trustedTemporaryRoot(), "tideproof-provider-")
  );
  const stagedPath = path.join(temporaryDirectory, "provider.mjs");
  let result;
  try {
    result = await build({
      absWorkingDir: root,
      entryPoints: [sourcePath],
      bundle: true,
      platform: "node",
      target: "node22",
      format: "esm",
      legalComments: "none",
      logLevel: "silent",
      metafile: true,
      outfile: stagedPath,
      splitting: false,
      banner: {
        js:
          "import { builtinModules as __tideproofBuiltins, createRequire as __tideproofCreateRequire } from \"node:module\"; const __tideproofNativeRequire = __tideproofCreateRequire(\"/tideproof-evidence-provider-runtime.mjs\"); const __tideproofAllowedRequires = new Set(__tideproofBuiltins.flatMap((name) => [name, name.startsWith(\"node:\") ? name : `node:${name}`])); const require = (specifier) => { if (!__tideproofAllowedRequires.has(specifier)) throw new Error(\"AWS_PROVIDER_RUNTIME_EXTERNAL_REQUIRE\"); return __tideproofNativeRequire(specifier.startsWith(\"node:\") ? specifier : `node:${specifier}`); };"
      },
      plugins: [nodeBuiltinExternalPlugin(), exactSource.plugin]
    });
  } catch (error) {
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
    throw new Error(`EVIDENCE_PROVIDER_BUILD:${error.message}`);
  }
  const bundledPackages = packageNamesFromMetafile(result.metafile);
  if (JSON.stringify(bundledPackages) !== JSON.stringify(expectedPackages)) {
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
    throw new Error("EVIDENCE_PROVIDER_PACKAGE_SET_DRIFT");
  }
  const externalImports = [
    ...new Set(
      Object.values(result.metafile.outputs).flatMap((output) =>
        output.imports
          .filter((candidate) => candidate.external)
          .map((candidate) => candidate.path)
      )
    )
  ].sort();
  if (
    externalImports.length === 0 ||
    externalImports.some((candidate) => !/^node:[a-z0-9_./-]+$/.test(candidate))
  ) {
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
    throw new Error("EVIDENCE_PROVIDER_EXTERNAL_IMPORT");
  }
  const bytes = fs.readFileSync(stagedPath);
  const digest = crypto.createHash("sha256").update(bytes).digest("hex");
  const relativePath = `dist/aws/evidence-provider-${digest}.mjs`;
  const outputPath = path.join(outputRoot, relativePath);
  if (fs.existsSync(outputPath)) {
    if (sha256File(outputPath) !== digest) {
      fs.rmSync(temporaryDirectory, { recursive: true, force: true });
      throw new Error("EXISTING_PROVIDER_RUNTIME_DIGEST_MISMATCH");
    }
  } else {
    fs.renameSync(stagedPath, outputPath);
  }
  fs.rmSync(temporaryDirectory, { recursive: true, force: true });
  return Object.freeze({
    bundledPackages,
    bytes: bytes.length,
    exactGitInputs: exactSource.inputRecords(),
    externalImports,
    path: relativePath,
    sha256: digest
  });
}

const sourceCommit = gitValue(["rev-parse", "HEAD"]);
const treeDigest = gitValue(["rev-parse", "HEAD^{tree}"]);
assertExactGitSourceContext({ rootDir: root, sourceCommit });
const packageJsonRecord = readExactGitBlob({
  rootDir: root,
  sourceCommit,
  filePath: path.join(root, "package.json")
});
const packageLockRecord = readExactGitBlob({
  rootDir: root,
  sourceCommit,
  filePath: path.join(root, "package-lock.json")
});
let dependencySnapshot = null;
let toolchain = null;
if (isolatedBuild) {
  if (
    process.env.TIDEPROOF_EXACT_BUILD_SOURCE_COMMIT !== sourceCommit ||
    process.env.TIDEPROOF_EXACT_BUILD_TREE_DIGEST !== treeDigest
  ) {
    throw new Error("GATE2_ISOLATED_BUILD_BINDING");
  }
  try {
    dependencySnapshot = validateDependencySnapshot(
      JSON.parse(process.env.TIDEPROOF_EXACT_BUILD_DEPENDENCY_SNAPSHOT ?? ""),
      {
        packageJsonDigest: packageJsonRecord.sha256,
        packageLockDigest: packageLockRecord.sha256
      }
    );
    toolchain = validateBuildToolchain(
      JSON.parse(process.env.TIDEPROOF_EXACT_BUILD_TOOLCHAIN ?? "")
    );
  } catch {
    throw new Error("GATE2_ISOLATED_DEPENDENCY_BINDING");
  }
}
const workingTreeCleanBeforeGeneration = gitStatus().length === 0;
if (isolatedBuild && !workingTreeCleanBeforeGeneration) {
  throw new Error(
    "GATE2_ARTIFACT_BUILD_REQUIRES_CLEAN_GIT_TREE"
  );
}

const bootstrap = templateReceipt(buildAwsBootstrapTemplate());
const gate2 = templateReceipt(buildGate2Template());
const bootstrapPath = path.join(templateRoot, "bootstrap-template.json");
const gate2Path = path.join(templateRoot, "gate2-template.json");
const bootstrapBytes = `${JSON.stringify(bootstrap.template, null, 2)}\n`;
const gate2Bytes = `${JSON.stringify(gate2.template, null, 2)}\n`;
if (isolatedBuild) {
  const committedBootstrap = readExactGitBlob({
    rootDir: root,
    sourceCommit,
    filePath: path.join(root, "infra/aws/bootstrap-template.json")
  });
  const committedGate2 = readExactGitBlob({
    rootDir: root,
    sourceCommit,
    filePath: path.join(root, "infra/aws/gate2-template.json")
  });
  if (
    !committedBootstrap.bytes.equals(Buffer.from(bootstrapBytes)) ||
    !committedGate2.bytes.equals(Buffer.from(gate2Bytes))
  ) {
    throw new Error("GATE2_GENERATED_TEMPLATE_DRIFT_REQUIRES_COMMIT");
  }
}
fs.mkdirSync(templateRoot, { recursive: true });
fs.writeFileSync(
  bootstrapPath,
  bootstrapBytes,
  "utf8"
);
fs.writeFileSync(
  gate2Path,
  gate2Bytes,
  "utf8"
);

const workingTreeClean = gitStatus().length === 0;
if (isolatedBuild && !workingTreeClean) {
  throw new Error(
    "GATE2_GENERATED_TEMPLATE_DRIFT_REQUIRES_COMMIT"
  );
}

let artifacts = [];
let thirdPartyNotices = null;
let evidenceProviderRuntime = null;
if (!templatesOnly) {
  const bundled = await collectBundledPackageNames({ rootDir: root });
  thirdPartyNotices = verifyBundledThirdPartyNotices({
    rootDir: root,
    packageNames: bundled.packageNames
  });
  const noticeBytes = readExactGitBlob({
    rootDir: root,
    sourceCommit,
    filePath: path.join(root, thirdPartyNotices.noticePath)
  }).bytes;
  fs.mkdirSync(distRoot, { recursive: true });
  evidenceProviderRuntime = await buildEvidenceProviderRuntime(
    sourceCommit,
    bundled.artifactPackages.evidenceProvider
  );
  for (const name of artifactNames) {
    artifacts.push(
      await buildArtifact(
        name,
        sourceCommit,
        noticeBytes,
        bundled.artifactPackages[name]
      )
    );
  }
}

const receipt = {
  schemaVersion: "tideproof.gate2-build.v6",
  mode: templatesOnly ? "TEMPLATES_ONLY_UNBOUND" : "CLEAN_ARTIFACT_BUILD",
  projectSourceMode: templatesOnly
    ? "WORKTREE_UNBOUND"
    : "ISOLATED_EXACT_GIT_CHECKOUT_AND_BLOBS",
  sourceCommit,
  treeDigest,
  workingTreeClean,
  workingTreeCleanBeforeGeneration,
  archiveFormat: "ZIP_STORED_TWO_FILE_V2",
  dependencySnapshot,
  evidenceProviderRuntime,
  toolchain,
  buildControlInputs: isolatedBuild
    ? buildControlPaths.map((filePath) => {
        const record = readExactGitBlob({
          rootDir: root,
          sourceCommit,
          filePath: path.join(root, filePath)
        });
        return {
          gitBlobId: record.gitBlobId,
          path: record.path,
          sha256: record.sha256
        };
      })
    : [],
  packageJsonDigest: packageJsonRecord.sha256,
  packageLockDigest: packageLockRecord.sha256,
  thirdPartyNotices,
  bootstrapTemplate: {
    path: "infra/aws/bootstrap-template.json",
    templateDigest: bootstrap.templateDigest,
    canonicalDigest: bootstrap.canonicalDigest,
    bytes: bootstrap.bytes
  },
  gate2Template: {
    path: "infra/aws/gate2-template.json",
    templateDigest: gate2.templateDigest,
    canonicalDigest: gate2.canonicalDigest,
    bytes: gate2.bytes
  },
  artifacts: artifacts.map(({ artifactPath, ...artifact }) => ({
    ...artifact,
    artifactPath: `dist/aws/${path.basename(artifactPath)}`
  }))
};

process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
