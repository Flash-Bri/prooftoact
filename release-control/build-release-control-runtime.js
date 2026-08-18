import crypto from "node:crypto";
import fs from "node:fs";
import { builtinModules } from "node:module";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { build, version as esbuildVersion } from "esbuild";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const HEX_40 = /^[0-9a-f]{40}$/u;
const FIRST_PARTY_SOURCES = Object.freeze([
  "release-control/src/release-control-aws-runtime.js",
  "release-control/src/release-control-bundle-entry.js",
  "release-control/src/release-control-dynamodb-store.js",
  "release-control/src/release-control-runtime-loader.js",
  "scripts/lib/release-control-table-identity.js",
  "src/cloud/canonical-json.js"
]);

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function jsonDigest(value) {
  return sha256(Buffer.from(`${JSON.stringify(value)}\n`, "utf8"));
}

function fileRecord(repositoryRoot, relativePath, maximumBytes = 5 * 1024 * 1024) {
  const filePath = path.resolve(repositoryRoot, relativePath);
  if (path.relative(repositoryRoot, filePath) !==
      relativePath.split("/").join(path.sep) ||
    fs.realpathSync(filePath) !== filePath) {
    throw new Error("RELEASE_CONTROL_SOURCE_REALPATH_REJECTED");
  }
  const stat = fs.lstatSync(filePath);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 ||
    stat.size <= 0 || stat.size > maximumBytes) {
    throw new Error("RELEASE_CONTROL_SOURCE_FILE_REJECTED");
  }
  const bytes = fs.readFileSync(filePath);
  return Object.freeze({
    bytes: bytes.length,
    path: relativePath,
    sha256: sha256(bytes)
  });
}

function optionalArtifact(repositoryRoot, relativePath) {
  const filePath = path.resolve(repositoryRoot, relativePath);
  if (!fs.existsSync(filePath)) {
    return Object.freeze({
      bytes: 0,
      path: relativePath,
      sha256: null,
      status: "ABSENT"
    });
  }
  return Object.freeze({
    ...fileRecord(repositoryRoot, relativePath),
    status: "PRESENT"
  });
}

function exactPackageBytes(root, name) {
  const filePath = path.join(root, name);
  if (fs.realpathSync(filePath) !== filePath) {
    throw new Error("RELEASE_CONTROL_PACKAGE_REALPATH_REJECTED");
  }
  const stat = fs.lstatSync(filePath);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 ||
    stat.size <= 0 || stat.size > 2 * 1024 * 1024) {
    throw new Error("RELEASE_CONTROL_PACKAGE_FILE_REJECTED");
  }
  return fs.readFileSync(filePath);
}

function packageNames(metafile) {
  return [...new Set(Object.keys(metafile.inputs).flatMap((input) => {
    const match = /(?:^|\/)node_modules\/((?:@[^/]+\/)?[^/]+)/u.exec(input);
    return match ? [match[1]] : [];
  }))].sort();
}

function packageInventory(root, names) {
  return Object.freeze(names.map((name) => {
    const packageJsonPath = path.join(
      root,
      "node_modules",
      ...name.split("/"),
      "package.json"
    );
    const bytes = fs.readFileSync(packageJsonPath);
    let manifest;
    try {
      manifest = JSON.parse(bytes.toString("utf8"));
    } catch (cause) {
      throw new Error("RELEASE_CONTROL_BUNDLED_PACKAGE_REJECTED", { cause });
    }
    if (manifest.name !== name || typeof manifest.version !== "string" ||
      manifest.version.length === 0 || fs.realpathSync(packageJsonPath) !==
        packageJsonPath) {
      throw new Error("RELEASE_CONTROL_BUNDLED_PACKAGE_REJECTED");
    }
    return Object.freeze({
      name,
      packageJsonSha256: sha256(bytes),
      version: manifest.version
    });
  }));
}

function toolchainReceipt(root, repositoryRoot) {
  const nodeExecutable = fs.realpathSync(process.execPath);
  const nodeBytes = fs.readFileSync(nodeExecutable);
  const esbuildPackage = fileRecord(
    repositoryRoot,
    "release-control/node_modules/esbuild/package.json"
  );
  const esbuildLauncher = fileRecord(
    repositoryRoot,
    "release-control/node_modules/esbuild/bin/esbuild"
  );
  const esbuildRoots = fs.readdirSync(path.join(root, "node_modules", "@esbuild"));
  const binaries = esbuildRoots.map((name) =>
    path.join(root, "node_modules", "@esbuild", name, "bin", "esbuild")
  ).filter((candidate) => fs.existsSync(candidate));
  if (binaries.length !== 1 || fs.realpathSync(binaries[0]) !== binaries[0]) {
    throw new Error("RELEASE_CONTROL_ESBUILD_BINARY_REJECTED");
  }
  const binaryStat = fs.lstatSync(binaries[0]);
  if (!binaryStat.isFile() || binaryStat.isSymbolicLink() ||
    binaryStat.nlink !== 1 || binaryStat.size <= 0) {
    throw new Error("RELEASE_CONTROL_ESBUILD_BINARY_REJECTED");
  }
  return Object.freeze({
    esbuildBinarySha256: sha256(fs.readFileSync(binaries[0])),
    esbuildLauncherSha256: esbuildLauncher.sha256,
    esbuildPackageJsonSha256: esbuildPackage.sha256,
    esbuildVersion,
    nodeArch: process.arch,
    nodeExecutableSha256: sha256(nodeBytes),
    nodePlatform: process.platform,
    nodeVersion: process.version
  });
}

function builtinPlugin() {
  const names = new Set(builtinModules.map((name) => name.replace(/^node:/u, "")));
  return {
    name: "release-control-node-builtins",
    setup(context) {
      context.onResolve({ filter: /.*/ }, (args) => {
        const candidate = args.path.replace(/^node:/u, "");
        return names.has(candidate)
          ? { external: true, path: `node:${candidate}` }
          : null;
      });
    }
  };
}

function denyCredentialChainPlugin() {
  return {
    name: "release-control-deny-credential-chain",
    setup(context) {
      context.onResolve(
        { filter: /^@aws-sdk\/credential-provider-node$/ },
        () => ({
          namespace: "release-control-denied-capability",
          path: "credential-provider-node"
        })
      );
      context.onLoad(
        {
          filter: /^credential-provider-node$/,
          namespace: "release-control-denied-capability"
        },
        () => ({
          contents:
            "export function defaultProvider() { throw new Error(\"RELEASE_CONTROL_RUNTIME_CREDENTIAL_CHAIN_DISABLED\"); }",
          loader: "js"
        })
      );
    }
  };
}

export async function buildReleaseControlRuntime({
  controlPlaneCommit,
  controlPlaneTree,
  outputRoot,
  projectRoot = ROOT
}) {
  if (!HEX_40.test(controlPlaneCommit ?? "") ||
    !HEX_40.test(controlPlaneTree ?? "")) {
    throw new Error("RELEASE_CONTROL_IDENTITY_INPUT_REJECTED");
  }
  const root = fs.realpathSync(projectRoot);
  const repositoryRoot = fs.realpathSync(path.resolve(root, ".."));
  const packageJsonBytes = exactPackageBytes(root, "package.json");
  const packageLockBytes = exactPackageBytes(root, "package-lock.json");
  let packageJson;
  try {
    packageJson = JSON.parse(packageJsonBytes.toString("utf8"));
  } catch (cause) {
    throw new Error("RELEASE_CONTROL_PACKAGE_JSON_REJECTED", { cause });
  }
  if (packageJson.name !== "@prooftoact/release-control-runtime" ||
    packageJson.private !== true || packageJson.type !== "module" ||
    packageJson.dependencies?.["@aws-sdk/client-dynamodb"] !== "3.1098.0" ||
    packageJson.dependencies?.["@aws-sdk/client-sts"] !== "3.1098.0" ||
    packageJson.dependencies?.["@smithy/node-http-handler"] !== "4.9.13" ||
    packageJson.devDependencies?.esbuild !== "0.28.1") {
    throw new Error("RELEASE_CONTROL_PACKAGE_CONTRACT_REJECTED");
  }
  const requestedOutput = path.resolve(outputRoot);
  fs.mkdirSync(requestedOutput, { recursive: true, mode: 0o700 });
  const output = fs.realpathSync(requestedOutput);
  const result = await build({
    absWorkingDir: root,
    banner: {
      js:
        "import { builtinModules as __ptaBuiltins, createRequire as __ptaCreateRequire } from \"node:module\"; const __ptaNativeRequire = __ptaCreateRequire(\"/prooftoact-release-control-runtime.mjs\"); const __ptaAllowedRequires = new Set(__ptaBuiltins.flatMap((name) => [name, name.startsWith(\"node:\") ? name : `node:${name}`])); const require = (specifier) => { if (!__ptaAllowedRequires.has(specifier)) throw new Error(\"RELEASE_CONTROL_RUNTIME_EXTERNAL_REQUIRE\"); return __ptaNativeRequire(specifier.startsWith(\"node:\") ? specifier : `node:${specifier}`); };"
    },
    bundle: true,
    entryPoints: ["src/release-control-bundle-entry.js"],
    format: "esm",
    legalComments: "none",
    logLevel: "silent",
    metafile: true,
    platform: "node",
    plugins: [denyCredentialChainPlugin(), builtinPlugin()],
    splitting: false,
    target: "node22",
    write: false
  });
  if (result.outputFiles.length !== 1) {
    throw new Error("RELEASE_CONTROL_RUNTIME_BUILD_OUTPUT_REJECTED");
  }
  if (Object.keys(result.metafile.inputs).some((input) =>
    input.includes("node_modules/") && !input.startsWith("node_modules/"))) {
    throw new Error("RELEASE_CONTROL_RUNTIME_PARENT_DEPENDENCY_REJECTED");
  }
  const packages = packageNames(result.metafile);
  if (packages.some((name) =>
    name.startsWith("@aws-sdk/credential-provider-") ||
    name === "@aws-sdk/token-providers" ||
    name === "@smithy/credential-provider-imds")) {
    throw new Error("RELEASE_CONTROL_RUNTIME_CREDENTIAL_CHAIN_PRESENT");
  }
  const bytes = Buffer.from(result.outputFiles[0].contents);
  const digest = sha256(bytes);
  const relativePath = `dist/aws/release-control-provider-${digest}.mjs`;
  const filePath = path.join(output, relativePath);
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  if (fs.realpathSync(path.dirname(filePath)) !== path.dirname(filePath)) {
    throw new Error("RELEASE_CONTROL_RUNTIME_OUTPUT_REALPATH_REJECTED");
  }
  try {
    fs.writeFileSync(filePath, bytes, { flag: "wx", mode: 0o600 });
  } catch (error) {
    if (error?.code !== "EEXIST" ||
      sha256(fs.readFileSync(filePath)) !== digest) throw error;
  }
  const stat = fs.lstatSync(filePath);
  const expectedUid = typeof process.getuid === "function"
    ? process.getuid() : null;
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 ||
    stat.size !== bytes.length || (stat.mode & 0o777) !== 0o600 ||
    expectedUid !== null && stat.uid !== expectedUid ||
    fs.realpathSync(filePath) !== filePath ||
    sha256(fs.readFileSync(filePath)) !== digest) {
    throw new Error("RELEASE_CONTROL_RUNTIME_OUTPUT_FILE_REJECTED");
  }
  const externalImports = [...new Set(
    Object.values(result.metafile.outputs).flatMap((entry) =>
      entry.imports.filter(({ external }) => external).map(({ path: name }) => name)
    )
  )].sort();
  if (externalImports.length === 0 ||
    externalImports.some((name) => !/^node:[a-z0-9_./-]+$/u.test(name))) {
    throw new Error("RELEASE_CONTROL_RUNTIME_EXTERNAL_IMPORT_REJECTED");
  }
  const sources = Object.freeze(FIRST_PARTY_SOURCES.map((sourcePath) =>
    fileRecord(repositoryRoot, sourcePath)
  ));
  const packageUnion = packageInventory(root, packages);
  const optionalArtifacts = Object.freeze([
    optionalArtifact(repositoryRoot,
      "release-control/DEPENDENCY_INVENTORY.json"),
    optionalArtifact(repositoryRoot,
      "release-control/THIRD_PARTY_NOTICES.txt")
  ]);
  const builderSha256 = fileRecord(
    repositoryRoot,
    "release-control/build-release-control-runtime.js"
  ).sha256;
  const sourceInventorySha256 = jsonDigest(sources);
  const packageInventorySha256 = jsonDigest(packageUnion);
  const toolchain = toolchainReceipt(root, repositoryRoot);
  const packageJsonSha256 = sha256(packageJsonBytes);
  const packageLockSha256 = sha256(packageLockBytes);
  const controlPlaneIdentitySha256 = jsonDigest({
    builderSha256,
    commit: controlPlaneCommit,
    packageInventorySha256,
    packageJsonSha256,
    packageLockSha256,
    sourceInventorySha256,
    tree: controlPlaneTree
  });
  const receipt = {
    bundledPackages: packages,
    builderSha256,
    bytes: bytes.length,
    controlPlaneCommit,
    controlPlaneIdentitySha256,
    controlPlaneTree,
    esbuildBinarySha256: toolchain.esbuildBinarySha256,
    esbuildLauncherSha256: toolchain.esbuildLauncherSha256,
    esbuildPackageJsonSha256: toolchain.esbuildPackageJsonSha256,
    esbuildVersion: toolchain.esbuildVersion,
    externalImports,
    nodeArch: toolchain.nodeArch,
    nodeExecutableSha256: toolchain.nodeExecutableSha256,
    nodePlatform: toolchain.nodePlatform,
    nodeVersion: toolchain.nodeVersion,
    optionalArtifacts,
    packageInventory: packageUnion,
    packageInventorySha256,
    packageJsonSha256,
    packageLockSha256,
    path: relativePath,
    sha256: digest,
    sourceInventory: sources,
    sourceInventorySha256
  };
  return Object.freeze({
    ...receipt,
    provenanceSha256: jsonDigest(receipt)
  });
}

async function main(args = process.argv.slice(2)) {
  if (args.length !== 3 || !path.isAbsolute(args[0]) ||
    !HEX_40.test(args[1]) || !HEX_40.test(args[2])) {
    throw new Error(
      "usage: build-release-control-runtime.js /absolute/output/root control-plane-commit control-plane-tree"
    );
  }
  process.stdout.write(`${JSON.stringify(await buildReleaseControlRuntime({
    outputRoot: args[0],
    controlPlaneCommit: args[1],
    controlPlaneTree: args[2]
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
  builtinPlugin,
  denyCredentialChainPlugin,
  exactPackageBytes,
  fileRecord,
  jsonDigest,
  optionalArtifact,
  packageInventory,
  packageNames,
  sha256,
  toolchainReceipt
});
