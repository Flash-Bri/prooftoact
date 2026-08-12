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
import { readOfficialNodeRuntime } from
  "./lib/official-node-runtime.js";
import {
  GATE2_BUILD_CONTROL_PATHS,
  GATE2_BUILD_SCHEMA
} from "./lib/gate2-build-contract.js";
import { collectBundledPackageNames } from "./verify-bundled-third-party-notices.js";
import {
  reviewBuildOutputFindings,
  scanBuildOutputBuffer,
  validateManifest as validatePrivacyManifest
} from "./verify-release-privacy.js";
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
const runtimeDistRoot = path.join(outputRoot, "dist/runtime");
const templateRoot = path.join(outputRoot, "infra/aws");
const runtimeComponentDefinitions = Object.freeze({
  "authority-race": Object.freeze({
    entry: "scripts/runtime-entries/integrated-live-drill-authority-race.js",
    packageKey: "runtimeAuthorityRace"
  }),
  dvi: Object.freeze({
    entry: "scripts/runtime-entries/integrated-live-drill-dvi.js",
    packageKey: "runtimeDvi"
  }),
  finalizer: Object.freeze({
    entry: "scripts/runtime-entries/integrated-live-drill-finalizer.js",
    packageKey: "runtimeFinalizer"
  }),
  orchestrator: Object.freeze({
    entry: "scripts/runtime-entries/integrated-live-drill-orchestrator.js",
    packageKey: "runtimeOrchestrator"
  }),
  recovery: Object.freeze({
    entry: "scripts/runtime-entries/integrated-live-drill-recovery.js",
    packageKey: "runtimeRecovery"
  }),
  supervisor: Object.freeze({
    entry: "scripts/runtime-entries/integrated-live-drill-supervisor.js",
    packageKey: "runtimeSupervisor"
  }),
  worker: Object.freeze({
    entry: "scripts/runtime-entries/integrated-live-drill-worker.js",
    packageKey: "runtimeWorker"
  })
});

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

function verifyBuildOutputPrivacy(
  relativePaths,
  sourceCommit,
  pinnedOfficialNodePath
) {
  if (
    !Array.isArray(relativePaths) ||
    relativePaths.length === 0 ||
    new Set(relativePaths).size !== relativePaths.length ||
    relativePaths.some((relativePath) =>
      typeof relativePath !== "string" ||
      path.isAbsolute(relativePath) ||
      relativePath.split("/").some((part) => !part || part === "..")
    )
  ) {
    throw new Error("GATE2_BUILD_OUTPUT_PRIVACY_PATHS");
  }
  const privacyManifest = validatePrivacyManifest(JSON.parse(
    readExactGitBlob({
      rootDir: root,
      sourceCommit,
      filePath: path.join(root, "RELEASE_PRIVACY_MANIFEST.json")
    }).bytes.toString("utf8")
  ));
  const findings = [];
  let scannedBytes = 0;
  let pinnedOfficialToolchainBytes = 0;
  let pinnedOfficialToolchainOutputCount = 0;
  const outputs = [...relativePaths].sort().map((relativePath) => {
    const absolutePath = path.join(outputRoot, relativePath);
    const stat = fs.lstatSync(absolutePath);
    if (
      !stat.isFile() ||
      stat.isSymbolicLink() ||
      stat.nlink !== 1 ||
      fs.realpathSync(absolutePath) !== absolutePath
    ) {
      throw new Error("GATE2_BUILD_OUTPUT_PRIVACY_FILE");
    }
    const bytes = fs.readFileSync(absolutePath);
    if (relativePath === pinnedOfficialNodePath) {
      pinnedOfficialToolchainBytes += bytes.length;
      pinnedOfficialToolchainOutputCount += 1;
    } else {
      scannedBytes += bytes.length;
      findings.push(...scanBuildOutputBuffer(bytes, relativePath));
    }
    return Object.freeze({
      bytes: bytes.length,
      path: relativePath,
      sha256: crypto.createHash("sha256").update(bytes).digest("hex")
    });
  });
  const review = reviewBuildOutputFindings(findings, privacyManifest);
  const inventorySha256 = crypto.createHash("sha256")
    .update(JSON.stringify(outputs))
    .digest("hex");
  return Object.freeze({
    schemaVersion: "tideproof.gate2-build-output-privacy.v1",
    status: "PASS",
    ...review,
    inventorySha256,
    outputCount: outputs.length,
    outputs,
    pinnedOfficialToolchainBytes,
    pinnedOfficialToolchainOutputCount,
    scannedBytes
  });
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
    path.join(trustedTemporaryRoot(), "prooftoact-gate2-")
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

async function buildLiveDrillRuntime({
  expectedPackages,
  packageLockDigest,
  runtimeNode,
  sourceCommit,
  treeDigest,
  toolchain
}) {
  fs.mkdirSync(runtimeDistRoot, { recursive: true });
  const components = {};
  for (const [name, definition] of Object.entries(
    runtimeComponentDefinitions
  )) {
    const sourcePath = path.join(root, definition.entry);
    const exactSource = exactGitSourcePlugin({
      rootDir: root,
      sourceCommit,
      dependencyRoot: fs.realpathSync(path.join(root, "node_modules"))
    });
    const temporaryDirectory = fs.mkdtempSync(
      path.join(trustedTemporaryRoot(), `tideproof-runtime-${name}-`)
    );
    const stagedPath = path.join(temporaryDirectory, `${name}.mjs`);
    let result;
    try {
      result = await build({
        absWorkingDir: root,
        alias: {
          "pg-native": path.join(
            root,
            "scripts/lib/pg-native-unavailable.cjs"
          )
        },
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
            "import { builtinModules as __tideproofBuiltins, createRequire as __tideproofCreateRequire } from \"node:module\"; const __tideproofNativeRequire = __tideproofCreateRequire(\"/tideproof-integrated-live-drill-runtime.mjs\"); const __tideproofAllowedRequires = new Set(__tideproofBuiltins.flatMap((name) => [name, name.startsWith(\"node:\") ? name : `node:${name}`])); const require = (specifier) => { if (!__tideproofAllowedRequires.has(specifier)) throw new Error(\"INTEGRATED_LIVE_DRILL_RUNTIME_EXTERNAL_REQUIRE\"); return __tideproofNativeRequire(specifier.startsWith(\"node:\") ? specifier : `node:${specifier}`); };"
        },
        plugins: [nodeBuiltinExternalPlugin(), exactSource.plugin]
      });
    } catch (error) {
      fs.rmSync(temporaryDirectory, { recursive: true, force: true });
      throw new Error(`INTEGRATED_LIVE_DRILL_RUNTIME_BUILD:${name}:${error.message}`);
    }
    const bundledPackages = packageNamesFromMetafile(result.metafile);
    if (
      JSON.stringify(bundledPackages) !==
        JSON.stringify(expectedPackages[definition.packageKey])
    ) {
      fs.rmSync(temporaryDirectory, { recursive: true, force: true });
      throw new Error(`INTEGRATED_LIVE_DRILL_RUNTIME_PACKAGE_SET_DRIFT:${name}`);
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
      externalImports.some((candidate) =>
        !/^node:[a-z0-9_./-]+$/u.test(candidate)
      )
    ) {
      fs.rmSync(temporaryDirectory, { recursive: true, force: true });
      throw new Error(`INTEGRATED_LIVE_DRILL_RUNTIME_EXTERNAL_IMPORT:${name}`);
    }
    const bytes = fs.readFileSync(stagedPath);
    const digest = crypto.createHash("sha256").update(bytes).digest("hex");
    const file = `${name}-${digest}.mjs`;
    const outputPath = path.join(runtimeDistRoot, file);
    if (fs.existsSync(outputPath)) {
      if (sha256File(outputPath) !== digest) {
        fs.rmSync(temporaryDirectory, { recursive: true, force: true });
        throw new Error("INTEGRATED_LIVE_DRILL_RUNTIME_OUTPUT_CONFLICT");
      }
    } else {
      fs.renameSync(stagedPath, outputPath);
    }
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
    components[name] = Object.freeze({
      bundledPackages,
      bytes: bytes.length,
      exactGitInputs: exactSource.inputRecords(),
      externalImports,
      file,
      path: `dist/runtime/${file}`,
      sha256: digest
    });
  }

  const launcherRecord = readExactGitBlob({
    rootDir: root,
    sourceCommit,
    filePath: path.join(
      root,
      "scripts/lib/verified-node-bundle-launcher.pl"
    )
  });
  const launcherFile = "verified-node-bundle-launcher.pl";
  const launcherPath = path.join(runtimeDistRoot, launcherFile);
  fs.writeFileSync(launcherPath, launcherRecord.bytes, { mode: 0o555 });

  const nodeSha256 = runtimeNode.sha256;
  const nodeFile = `node-${nodeSha256}`;
  const nodePath = path.join(runtimeDistRoot, nodeFile);
  if (!fs.existsSync(nodePath)) {
    fs.writeFileSync(nodePath, runtimeNode.bytes, {
      flag: "wx",
      mode: 0o555
    });
  }
  if (sha256File(nodePath) !== nodeSha256) {
    throw new Error("INTEGRATED_LIVE_DRILL_RUNTIME_NODE_CONFLICT");
  }
  fs.chmodSync(nodePath, 0o555);

  const manifest = Object.freeze({
    schemaVersion: "tideproof.integrated-live-drill-runtime-manifest.v1",
    sourceCommit,
    treeDigest,
    packageLockDigest,
    toolchainSha256: crypto.createHash("sha256")
      .update(JSON.stringify(toolchain))
      .digest("hex"),
    launcher: Object.freeze({
      file: launcherFile,
      sha256: launcherRecord.sha256
    }),
    node: Object.freeze({
      architecture: runtimeNode.architecture,
      distribution: runtimeNode.distribution,
      file: nodeFile,
      platform: runtimeNode.platform,
      sha256: nodeSha256,
      version: runtimeNode.version
    }),
    components: Object.freeze(Object.fromEntries(
      Object.entries(components).map(([name, component]) => [
        name,
        Object.freeze({
          bundledPackages: component.bundledPackages,
          bytes: component.bytes,
          externalImports: component.externalImports,
          file: component.file,
          sha256: component.sha256
        })
      ])
    ))
  });
  const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`);
  const manifestSha256 = crypto.createHash("sha256")
    .update(manifestBytes)
    .digest("hex");
  const manifestFile = `runtime-manifest-${manifestSha256}.json`;
  fs.writeFileSync(
    path.join(runtimeDistRoot, manifestFile),
    manifestBytes,
    { mode: 0o444 }
  );
  return Object.freeze({
    components,
    launcher: Object.freeze({
      path: `dist/runtime/${launcherFile}`,
      sha256: launcherRecord.sha256
    }),
    manifestPath: `dist/runtime/${manifestFile}`,
    manifestSha256,
    node: Object.freeze({
      architecture: runtimeNode.architecture,
      distribution: runtimeNode.distribution,
      path: `dist/runtime/${nodeFile}`,
      platform: runtimeNode.platform,
      sha256: nodeSha256,
      version: runtimeNode.version
    })
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
let runtimeNode = null;
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
    runtimeNode = readOfficialNodeRuntime({
      filePath: process.env.TIDEPROOF_EXACT_RUNTIME_NODE_PATH
    });
    if (
      runtimeNode.sha256 !==
        process.env.TIDEPROOF_EXACT_RUNTIME_NODE_SHA256
    ) {
      throw new Error("GATE2_ISOLATED_RUNTIME_NODE_BINDING");
    }
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
let liveDrillRuntime = null;
let outputPrivacy = null;
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
  liveDrillRuntime = await buildLiveDrillRuntime({
    expectedPackages: bundled.artifactPackages,
    packageLockDigest: packageLockRecord.sha256,
    runtimeNode,
    sourceCommit,
    treeDigest,
    toolchain
  });
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
  outputPrivacy = verifyBuildOutputPrivacy([
    "infra/aws/bootstrap-template.json",
    "infra/aws/gate2-template.json",
    evidenceProviderRuntime.path,
    liveDrillRuntime.manifestPath,
    liveDrillRuntime.launcher.path,
    liveDrillRuntime.node.path,
    ...Object.values(liveDrillRuntime.components).map(({ path }) => path),
    ...artifacts.map(({ artifactPath }) =>
      `dist/aws/${path.basename(artifactPath)}`
    )
  ], sourceCommit, liveDrillRuntime.node.path);
}

const receipt = {
  schemaVersion: GATE2_BUILD_SCHEMA,
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
  liveDrillRuntime,
  outputPrivacy,
  toolchain,
  buildControlInputs: isolatedBuild
    ? GATE2_BUILD_CONTROL_PATHS.map((filePath) => {
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
