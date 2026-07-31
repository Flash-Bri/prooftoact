import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { writeSingleFileZip } from "./lib/deterministic-zip.js";
import { rawTextPlugin } from "./lib/raw-text-plugin.js";
import {
  buildAwsBootstrapTemplate,
  buildGate2Template,
  templateReceipt
} from "../src/cloud/aws-gate2-template.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");
const lambdaRoot = path.join(root, "infra/aws/lambda");
const distRoot = path.join(root, "dist/aws");
const templateRoot = path.join(root, "infra/aws");
const artifactNames = [
  "agent",
  "authority",
  "boundary",
  "demo",
  "probe",
  "signer"
];
const templatesOnly = process.argv.includes("--templates-only");
const unexpectedArguments = process.argv
  .slice(2)
  .filter((value) => value !== "--templates-only");
if (unexpectedArguments.length > 0) {
  throw new Error("UNKNOWN_BUILD_ARGUMENT");
}

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
  const result = spawnSync("git", args, {
    cwd: root,
    encoding: "utf8"
  });
  if (result.status !== 0) {
    throw new Error(`git ${args.join(" ")} failed`);
  }
  return result.stdout.trim();
}

function gitStatus() {
  const result = spawnSync("git", ["status", "--short"], {
    cwd: root,
    encoding: "utf8"
  });
  if (result.status !== 0) {
    throw new Error("git status --short failed");
  }
  return result.stdout.trim();
}

async function buildArtifact(name, sourceCommit) {
  const sourcePath = path.join(
    lambdaRoot,
    `${name}.${name === "demo" ? "js" : "cjs"}`
  );
  const sourceDigest = sha256File(sourcePath);
  const temporaryDirectory = fs.mkdtempSync(
    path.join(os.tmpdir(), "tideproof-gate2-")
  );
  const stagedPath = path.join(temporaryDirectory, "index.js");
  const provisionalPath = path.join(
    temporaryDirectory,
    `${name}-provisional.zip`
  );
  try {
    await build({
      absWorkingDir: root,
      entryPoints: [sourcePath],
      bundle: true,
      platform: "node",
      target: "node22",
      format: "cjs",
      legalComments: "none",
      logLevel: "silent",
      outfile: stagedPath,
      plugins: [rawTextPlugin()]
    });
  } catch (error) {
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
    throw new Error(`esbuild failed for ${name}: ${error.message}`);
  }
  writeSingleFileZip(
    provisionalPath,
    "index.js",
    fs.readFileSync(stagedPath)
  );
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
    suggestedS3Key: `gate2/${sourceCommit}/${name}-${artifactDigest}.zip`
  };
}

const sourceCommit = gitValue(["rev-parse", "HEAD"]);
const treeDigest = gitValue(["rev-parse", "HEAD^{tree}"]);
const workingTreeCleanBeforeGeneration = gitStatus().length === 0;
if (!templatesOnly && !workingTreeCleanBeforeGeneration) {
  throw new Error(
    "GATE2_ARTIFACT_BUILD_REQUIRES_CLEAN_GIT_TREE"
  );
}

const bootstrap = templateReceipt(buildAwsBootstrapTemplate());
const gate2 = templateReceipt(buildGate2Template());
const bootstrapPath = path.join(templateRoot, "bootstrap-template.json");
const gate2Path = path.join(templateRoot, "gate2-template.json");
fs.writeFileSync(
  bootstrapPath,
  `${JSON.stringify(bootstrap.template, null, 2)}\n`,
  "utf8"
);
fs.writeFileSync(
  gate2Path,
  `${JSON.stringify(gate2.template, null, 2)}\n`,
  "utf8"
);

const workingTreeClean = gitStatus().length === 0;
if (!templatesOnly && !workingTreeClean) {
  throw new Error(
    "GATE2_GENERATED_TEMPLATE_DRIFT_REQUIRES_COMMIT"
  );
}

let artifacts = [];
if (!templatesOnly) {
  fs.mkdirSync(distRoot, { recursive: true });
  for (const name of artifactNames) {
    artifacts.push(await buildArtifact(name, sourceCommit));
  }
}

const receipt = {
  schemaVersion: "tideproof.gate2-build.v2",
  mode: templatesOnly ? "TEMPLATES_ONLY_UNBOUND" : "CLEAN_ARTIFACT_BUILD",
  sourceCommit,
  treeDigest,
  workingTreeClean,
  workingTreeCleanBeforeGeneration,
  archiveFormat: "ZIP_STORED_SINGLE_FILE_V1",
  packageLockDigest: sha256File(path.join(root, "package-lock.json")),
  bootstrapTemplate: {
    path: path.relative(root, bootstrapPath),
    templateDigest: bootstrap.templateDigest,
    canonicalDigest: bootstrap.canonicalDigest,
    bytes: bootstrap.bytes
  },
  gate2Template: {
    path: path.relative(root, gate2Path),
    templateDigest: gate2.templateDigest,
    canonicalDigest: gate2.canonicalDigest,
    bytes: gate2.bytes
  },
  artifacts: artifacts.map(({ artifactPath, ...artifact }) => ({
    ...artifact,
    artifactPath: path.relative(root, artifactPath)
  }))
};

process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
