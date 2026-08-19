import crypto from "node:crypto";
import fs from "node:fs";
import { builtinModules } from "node:module";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { build, version as esbuildVersion } from "esbuild";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const HEX_40 = /^[0-9a-f]{40}$/u;
const SPECS = Object.freeze([
  Object.freeze({
    capability: "PERMIT_READER",
    entry: "src/release-provider-permit-entry.js",
    exports: Object.freeze([
      "createAwsPreparePermitTransport", "createPreparePermitReader"
    ]),
    forbidden: Object.freeze([
      "CreateChangeSetCommand", "DeleteStackCommand", "ExecuteChangeSetCommand",
      "InvokeFunctionCommand", "PutObjectCommand", "TransactWriteItemsCommand",
      "UpdateItemCommand"
    ])
  }),
  Object.freeze({
    capability: "EXECUTE_PERMIT_READER",
    entry: "src/release-provider-execute-permit-entry.js",
    exports: Object.freeze([
      "createAwsExecutePermitTransport", "createExecutePermitReader"
    ]),
    forbidden: Object.freeze([
      "CreateChangeSetCommand", "DeleteStackCommand", "ExecuteChangeSetCommand",
      "InvokeFunctionCommand", "PutObjectCommand", "TransactWriteItemsCommand",
      "UpdateItemCommand", "UpdateTerminationProtectionCommand"
    ])
  }),
  Object.freeze({
    capability: "EXECUTE_DISPATCHER",
    entry: "src/release-provider-execute-dispatch-entry.js",
    exports: Object.freeze([
      "createAwsExecuteDispatcherTransport", "createExecuteDispatcher"
    ]),
    forbidden: Object.freeze([
      "AssumeRoleCommand", "CreateChangeSetCommand", "DeleteStackCommand",
      "DescribeStackEventsCommand", "GetObjectCommand", "InvokeFunctionCommand",
      "PutItemCommand", "PutObjectCommand", "TransactWriteItemsCommand",
      "UpdateItemCommand"
    ])
  }),
  Object.freeze({
    capability: "EXECUTE_READBACK",
    entry: "src/release-provider-execute-readback-entry.js",
    exports: Object.freeze([
      "createAwsExecuteReadbackTransport", "createExecuteReadback"
    ]),
    forbidden: Object.freeze([
      "AssumeRoleCommand", "CreateChangeSetCommand", "DeleteStackCommand",
      "ExecuteChangeSetCommand", "GetObjectCommand", "InvokeFunctionCommand",
      "PutItemCommand", "PutObjectCommand", "TransactWriteItemsCommand",
      "UpdateItemCommand", "UpdateTerminationProtectionCommand"
    ])
  }),
  Object.freeze({
    capability: "PREPARE_DISPATCHER",
    entry: "src/release-provider-prepare-dispatch-entry.js",
    exports: Object.freeze([
      "createAwsPrepareDispatcherTransport", "createPrepareDispatcher"
    ]),
    forbidden: Object.freeze([
      "AssumeRoleCommand", "DeleteStackCommand", "ExecuteChangeSetCommand",
      "InvokeFunctionCommand", "PutItemCommand", "TransactWriteItemsCommand",
      "UpdateItemCommand"
    ])
  }),
  Object.freeze({
    capability: "PREPARE_READBACK",
    entry: "src/release-provider-prepare-readback-entry.js",
    exports: Object.freeze([
      "createAwsPrepareReadbackTransport", "createPrepareReadback"
    ]),
    forbidden: Object.freeze([
      "AssumeRoleCommand", "CreateChangeSetCommand", "DeleteStackCommand",
      "ExecuteChangeSetCommand", "InvokeFunctionCommand",
      "ListStackResourcesCommand", "PutObjectCommand",
      "TransactWriteItemsCommand", "UpdateItemCommand"
    ])
  })
]);

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function jsonDigest(value) {
  return sha256(Buffer.from(`${JSON.stringify(value)}\n`, "utf8"));
}

function exactFile(root, relative, maximumBytes = 5 * 1024 * 1024) {
  const filePath = path.resolve(root, relative);
  const expected = relative.split("/").join(path.sep);
  if (path.relative(root, filePath) !== expected ||
    fs.realpathSync(filePath) !== filePath) {
    throw new Error("RELEASE_PROVIDER_SOURCE_REALPATH_REJECTED");
  }
  const stat = fs.lstatSync(filePath);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 ||
    stat.size <= 0 || stat.size > maximumBytes) {
    throw new Error("RELEASE_PROVIDER_SOURCE_FILE_REJECTED");
  }
  const bytes = fs.readFileSync(filePath);
  return Object.freeze({ bytes: bytes.length, path: relative,
    sha256: sha256(bytes) });
}

function builtinPlugin() {
  const names = new Set(builtinModules.map((name) =>
    name.replace(/^node:/u, "")));
  return {
    name: "release-provider-node-builtins",
    setup(context) {
      context.onResolve({ filter: /.*/ }, (args) => {
        const name = args.path.replace(/^node:/u, "");
        return names.has(name) ? { external: true, path: `node:${name}` } : null;
      });
    }
  };
}

function denyCredentialChainPlugin() {
  return {
    name: "release-provider-deny-credential-chain",
    setup(context) {
      context.onResolve({ filter: /^@aws-sdk\/credential-provider-node$/ },
        () => ({ namespace: "release-provider-denied", path: "credentials" }));
      context.onLoad({ filter: /^credentials$/,
        namespace: "release-provider-denied" }, () => ({
        contents: "export function defaultProvider(){throw new Error(\"RELEASE_PROVIDER_CREDENTIAL_CHAIN_DISABLED\");}",
        loader: "js"
      }));
    }
  };
}

function packageNames(metafile) {
  return [...new Set(Object.keys(metafile.inputs).flatMap((input) => {
    const match = /(?:^|\/)node_modules\/((?:@[^/]+\/)?[^/]+)/u.exec(input);
    return match ? [match[1]] : [];
  }))].sort();
}

function packageInventory(root, names) {
  return Object.freeze(names.map((name) => {
    const relative = `node_modules/${name}/package.json`;
    const record = exactFile(root, relative, 1024 * 1024);
    const manifest = JSON.parse(fs.readFileSync(path.join(root, relative),
      "utf8"));
    if (manifest.name !== name || typeof manifest.version !== "string" ||
      manifest.version.length === 0) {
      throw new Error("RELEASE_PROVIDER_PACKAGE_INVENTORY_REJECTED");
    }
    return Object.freeze({ name, packageJsonSha256: record.sha256,
      version: manifest.version });
  }));
}

function toolchain(root) {
  const nodePath = fs.realpathSync(process.execPath);
  const packageRecord = exactFile(root, "node_modules/esbuild/package.json");
  const launcherRecord = exactFile(root, "node_modules/esbuild/bin/esbuild");
  const platformRoots = fs.readdirSync(path.join(root, "node_modules", "@esbuild"));
  const binaries = platformRoots.map((name) =>
    path.join(root, "node_modules", "@esbuild", name, "bin", "esbuild"))
    .filter((candidate) => fs.existsSync(candidate));
  if (binaries.length !== 1 || fs.realpathSync(binaries[0]) !== binaries[0]) {
    throw new Error("RELEASE_PROVIDER_ESBUILD_BINARY_REJECTED");
  }
  return Object.freeze({
    esbuildBinarySha256: sha256(fs.readFileSync(binaries[0])),
    esbuildLauncherSha256: launcherRecord.sha256,
    esbuildPackageJsonSha256: packageRecord.sha256,
    esbuildVersion,
    nodeArch: process.arch,
    nodeExecutableSha256: sha256(fs.readFileSync(nodePath)),
    nodePlatform: process.platform,
    nodeVersion: process.version
  });
}

function sourceInventory(root, repositoryRoot) {
  const sourceRoot = path.join(root, "src");
  const local = fs.readdirSync(sourceRoot).filter((name) => name.endsWith(".js"))
    .map((name) => `release-provider/src/${name}`);
  return Object.freeze([
    ...local,
    "scripts/lib/release-control-table-identity.js",
    "src/cloud/canonical-json.js"
  ].sort().map((relative) => exactFile(repositoryRoot, relative)));
}

async function buildOne({ output, root, spec }) {
  const result = await build({
    absWorkingDir: root,
    banner: {
      js: "import { builtinModules as __ptaBuiltins, createRequire as __ptaCreateRequire } from \"node:module\"; const __ptaNativeRequire = __ptaCreateRequire(\"/prooftoact-release-provider-runtime.mjs\"); const __ptaAllowedRequires = new Set(__ptaBuiltins.flatMap((name) => [name, name.startsWith(\"node:\") ? name : `node:${name}`])); const require = (specifier) => { if (!__ptaAllowedRequires.has(specifier)) throw new Error(\"RELEASE_PROVIDER_RUNTIME_EXTERNAL_REQUIRE\"); return __ptaNativeRequire(specifier.startsWith(\"node:\") ? specifier : `node:${specifier}`); };"
    },
    bundle: true,
    entryPoints: [spec.entry],
    format: "esm",
    legalComments: "none",
    logLevel: "silent",
    metafile: true,
    platform: "node",
    plugins: [denyCredentialChainPlugin(), builtinPlugin()],
    splitting: false,
    target: "node22",
    treeShaking: true,
    write: false
  });
  if (result.outputFiles.length !== 1 || Object.keys(result.metafile.inputs)
    .some((input) => input.includes("node_modules/") &&
      !input.startsWith("node_modules/"))) {
    throw new Error("RELEASE_PROVIDER_RUNTIME_BUILD_REJECTED");
  }
  const packages = packageNames(result.metafile);
  if (packages.some((name) =>
    name.startsWith("@aws-sdk/credential-provider-") ||
    name === "@aws-sdk/token-providers" ||
    name === "@smithy/credential-provider-imds")) {
    throw new Error("RELEASE_PROVIDER_CREDENTIAL_CHAIN_PRESENT");
  }
  const bytes = Buffer.from(result.outputFiles[0].contents);
  const text = bytes.toString("utf8");
  const leakedCapability = spec.forbidden.find((needle) => text.includes(needle));
  if (leakedCapability) {
    throw new Error(
      `RELEASE_PROVIDER_${spec.capability}_CAPABILITY_LEAK_${leakedCapability}`
    );
  }
  const digest = sha256(bytes);
  const slug = spec.capability.toLowerCase().replaceAll("_", "-");
  const relativePath = `dist/aws/release-provider-${slug}-${digest}.mjs`;
  const filePath = path.join(output, relativePath);
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  try {
    fs.writeFileSync(filePath, bytes, { flag: "wx", mode: 0o600 });
  } catch (error) {
    if (error?.code !== "EEXIST" ||
      sha256(fs.readFileSync(filePath)) !== digest) throw error;
  }
  const stat = fs.lstatSync(filePath);
  const uid = typeof process.getuid === "function" ? process.getuid() : null;
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 ||
    stat.size !== bytes.length || (stat.mode & 0o777) !== 0o600 ||
    uid !== null && stat.uid !== uid || fs.realpathSync(filePath) !== filePath) {
    throw new Error("RELEASE_PROVIDER_RUNTIME_OUTPUT_REJECTED");
  }
  const externalImports = [...new Set(
    Object.values(result.metafile.outputs).flatMap((entry) =>
      entry.imports.filter(({ external }) => external).map(({ path: name }) =>
        name))
  )].sort();
  if (externalImports.length === 0 || externalImports.some((name) =>
    !/^node:[a-z0-9_./-]+$/u.test(name))) {
    throw new Error("RELEASE_PROVIDER_EXTERNAL_IMPORT_REJECTED");
  }
  const inventory = packageInventory(root, packages);
  return Object.freeze({
    bundledPackages: packages,
    bytes: bytes.length,
    capability: spec.capability,
    exports: spec.exports,
    externalImports,
    packageInventory: inventory,
    packageInventorySha256: jsonDigest(inventory),
    path: relativePath,
    sha256: digest
  });
}

export async function buildReleaseProviderRuntimes({
  controlPlaneCommit,
  controlPlaneTree,
  outputRoot,
  projectRoot = ROOT
}) {
  if (!HEX_40.test(controlPlaneCommit ?? "") ||
    !HEX_40.test(controlPlaneTree ?? "")) {
    throw new Error("RELEASE_PROVIDER_IDENTITY_REJECTED");
  }
  const root = fs.realpathSync(projectRoot);
  const repositoryRoot = fs.realpathSync(path.resolve(root, ".."));
  const packageJson = fs.readFileSync(path.join(root, "package.json"));
  const packageLock = fs.readFileSync(path.join(root, "package-lock.json"));
  const manifest = JSON.parse(packageJson.toString("utf8"));
  const expectedDependencies = {
    "@aws-sdk/client-cloudformation": "3.1098.0",
    "@aws-sdk/client-dynamodb": "3.1098.0",
    "@aws-sdk/client-s3": "3.1098.0",
    "@aws-sdk/client-sts": "3.1098.0",
    "@smithy/node-http-handler": "4.9.13"
  };
  if (manifest.name !== "@prooftoact/release-provider-runtime" ||
    manifest.private !== true || manifest.type !== "module" ||
    JSON.stringify(manifest.dependencies) !== JSON.stringify(expectedDependencies) ||
    manifest.devDependencies?.esbuild !== "0.28.1") {
    throw new Error("RELEASE_PROVIDER_PACKAGE_CONTRACT_REJECTED");
  }
  const requested = path.resolve(outputRoot);
  fs.mkdirSync(requested, { recursive: true, mode: 0o700 });
  const output = fs.realpathSync(requested);
  const runtimes = [];
  for (const spec of SPECS) runtimes.push(await buildOne({ output, root, spec }));
  const sources = sourceInventory(root, repositoryRoot);
  const tools = toolchain(root);
  const base = {
    schemaVersion: "prooftoact.release-provider-runtime-build.v1",
    builderSha256: exactFile(repositoryRoot,
      "release-provider/build-release-provider-runtimes.js").sha256,
    controlPlaneCommit,
    controlPlaneTree,
    esbuildBinarySha256: tools.esbuildBinarySha256,
    esbuildLauncherSha256: tools.esbuildLauncherSha256,
    esbuildPackageJsonSha256: tools.esbuildPackageJsonSha256,
    esbuildVersion: tools.esbuildVersion,
    nodeArch: tools.nodeArch,
    nodeExecutableSha256: tools.nodeExecutableSha256,
    nodePlatform: tools.nodePlatform,
    nodeVersion: tools.nodeVersion,
    packageJsonSha256: sha256(packageJson),
    packageLockSha256: sha256(packageLock),
    runtimes,
    sourceInventory: sources,
    sourceInventorySha256: jsonDigest(sources)
  };
  const runtimeSetSha256 = jsonDigest(runtimes.map(({ capability, path,
    sha256: digest }) => ({ capability, path, sha256: digest })));
  const receipt = { ...base, runtimeSetSha256 };
  return Object.freeze({
    ...receipt,
    provenanceSha256: jsonDigest(receipt)
  });
}

async function main(args = process.argv.slice(2)) {
  if (args.length !== 3 || !path.isAbsolute(args[0]) ||
    !HEX_40.test(args[1]) || !HEX_40.test(args[2])) {
    throw new Error("usage: build-release-provider-runtimes.js /absolute/output/root control-plane-commit control-plane-tree");
  }
  process.stdout.write(`${JSON.stringify(await buildReleaseProviderRuntimes({
    outputRoot: args[0], controlPlaneCommit: args[1], controlPlaneTree: args[2]
  }))}\n`);
}

if (process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}

export const __test = Object.freeze({
  SPECS, builtinPlugin, denyCredentialChainPlugin, exactFile, jsonDigest,
  packageInventory, packageNames, sha256, sourceInventory, toolchain
});
