#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

import {
  canonicalHostedJson,
  hostedSha256,
  verifyHostedDualRootArtifact
} from "./hosted-dual-root-verification.js";

const LOG_SEPARATOR = Buffer.from("\n---STDERR---\n", "utf8");

function invariant(condition, code) {
  if (!condition) throw new Error(code);
}

function parse(arguments_) {
  const allowed = new Set([
    "--application-root", "--control-root", "--npm-cli", "--output-root",
    "--tamper-root"
  ]);
  const values = new Map();
  for (let index = 0; index < arguments_.length; index += 2) {
    const name = arguments_[index];
    const value = arguments_[index + 1];
    if (!allowed.has(name) || values.has(name) ||
      typeof value !== "string" || !path.isAbsolute(value)) {
      throw new Error("HOSTED_DUAL_ROOT_TAMPER_ARGUMENT_REJECTED");
    }
    values.set(name, path.resolve(value));
  }
  invariant(values.size === allowed.size,
    "HOSTED_DUAL_ROOT_TAMPER_ARGUMENT_REJECTED");
  return values;
}

function exactEmptyDirectory(candidate) {
  const resolved = fs.realpathSync(candidate);
  const stat = fs.lstatSync(resolved);
  invariant(path.resolve(candidate) === resolved && stat.isDirectory() &&
    !stat.isSymbolicLink() && (stat.mode & 0o777) === 0o700 &&
    fs.readdirSync(resolved).length === 0,
  "HOSTED_DUAL_ROOT_TAMPER_ROOT_REJECTED");
  return resolved;
}

function normalizeModes(root) {
  const pending = [root];
  while (pending.length > 0) {
    const current = pending.pop();
    const stat = fs.lstatSync(current);
    invariant(!stat.isSymbolicLink(),
      "HOSTED_DUAL_ROOT_TAMPER_COPY_REJECTED");
    if (stat.isDirectory()) {
      fs.chmodSync(current, 0o700);
      for (const name of fs.readdirSync(current)) {
        pending.push(path.join(current, name));
      }
    } else {
      invariant(stat.isFile(), "HOSTED_DUAL_ROOT_TAMPER_COPY_REJECTED");
      fs.chmodSync(current, 0o600);
    }
  }
}

function manifestPath(root) {
  return path.join(root, "manifest.json");
}

function readManifest(root) {
  return JSON.parse(fs.readFileSync(manifestPath(root), "utf8"));
}

function resealManifest(root, manifest) {
  delete manifest.manifestSha256;
  manifest.manifestSha256 = hostedSha256(Buffer.from(
    canonicalHostedJson(manifest), "utf8"));
  fs.writeFileSync(manifestPath(root),
    Buffer.from(`${canonicalHostedJson(manifest)}\n`, "utf8"), { mode: 0o600 });
}

function updateLogBinding(manifest, relativePath, bytes, nestedDescriptor) {
  const file = manifest.files.find(({ path: item }) => item === relativePath);
  invariant(file && nestedDescriptor,
    "HOSTED_DUAL_ROOT_TAMPER_FIXTURE_REJECTED");
  for (const descriptor of [file, nestedDescriptor]) {
    descriptor.bytes = bytes.length;
    descriptor.sha256 = hostedSha256(bytes);
  }
}

function splitLog(bytes) {
  const separator = bytes.indexOf(LOG_SEPARATOR);
  invariant(separator > 0,
    "HOSTED_DUAL_ROOT_TAMPER_FIXTURE_REJECTED");
  return {
    stderr: bytes.subarray(separator + LOG_SEPARATOR.length),
    stdout: bytes.subarray(0, separator)
  };
}

function expectVerifierReject(options, expectedCode) {
  let rejected = false;
  try {
    verifyHostedDualRootArtifact(options);
  } catch (cause) {
    invariant(String(cause?.message ?? "") === expectedCode,
      "HOSTED_DUAL_ROOT_TAMPER_WRONG_REJECTION");
    rejected = true;
  }
  invariant(rejected, "HOSTED_DUAL_ROOT_TAMPER_NOT_REJECTED");
}

function restoreFiles(source, target) {
  const pending = [""];
  while (pending.length > 0) {
    const relativeDirectory = pending.pop();
    const directory = path.join(source, relativeDirectory);
    for (const name of fs.readdirSync(directory)) {
      const relativePath = path.join(relativeDirectory, name);
      const sourcePath = path.join(source, relativePath);
      const targetPath = path.join(target, relativePath);
      const stat = fs.lstatSync(sourcePath);
      invariant(!stat.isSymbolicLink(),
        "HOSTED_DUAL_ROOT_TAMPER_COPY_REJECTED");
      if (stat.isDirectory()) {
        invariant(fs.statSync(targetPath).isDirectory(),
          "HOSTED_DUAL_ROOT_TAMPER_COPY_REJECTED");
        pending.push(relativePath);
      } else {
        invariant(stat.isFile(), "HOSTED_DUAL_ROOT_TAMPER_COPY_REJECTED");
        fs.copyFileSync(sourcePath, targetPath);
        fs.chmodSync(targetPath, 0o600);
      }
    }
  }
}

function runVector({ canonicalRoot, expectedCode, name, options, tamperRoot,
  mutate }) {
  const backup = path.join(tamperRoot, name);
  fs.cpSync(canonicalRoot, backup, { errorOnExist: true, recursive: true });
  normalizeModes(backup);
  try {
    const before = verifyHostedDualRootArtifact({ ...options,
      outputRoot: canonicalRoot });
    mutate(canonicalRoot);
    expectVerifierReject({ ...options, outputRoot: canonicalRoot },
      expectedCode);
    restoreFiles(backup, canonicalRoot);
    const restored = verifyHostedDualRootArtifact({ ...options,
      outputRoot: canonicalRoot });
    invariant(restored.manifestSha256 === before.manifestSha256,
      "HOSTED_DUAL_ROOT_TAMPER_RESTORE_REJECTED");
  } finally {
    restoreFiles(backup, canonicalRoot);
    fs.rmSync(backup, { force: true, recursive: true });
  }
}

export function runTamperMatrix({ applicationRoot, controlRoot, npmCli,
  outputRoot, tamperRoot }) {
  const root = exactEmptyDirectory(tamperRoot);
  const options = { applicationRoot, controlRoot, npmCli };
  const canonical = verifyHostedDualRootArtifact({ ...options, outputRoot });
  const vectors = [
    {
      expectedCode: "HOSTED_DUAL_ROOT_ARTIFACT_SET_REJECTED",
      name: "missing-required-artifact",
      mutate(copy) {
        fs.unlinkSync(path.join(copy, "logs/safety.tap"));
      }
    },
    {
      expectedCode: "HOSTED_DUAL_ROOT_ARTIFACT_SET_REJECTED",
      name: "unbound-log-byte",
      mutate(copy) {
        fs.appendFileSync(path.join(copy, "logs/process-boundaries.log"),
          "tamper\n");
      }
    },
    {
      expectedCode: "HOSTED_DUAL_ROOT_REQUIRED_SUITE_EVIDENCE_REJECTED",
      name: "resealed-command-argument",
      mutate(copy) {
        const manifest = readManifest(copy);
        const command = manifest.tests.requiredSuites.safety.command;
        command.arguments[0] = "--tampered-test-command";
        command.argumentsSha256 = hostedSha256(Buffer.from(
          canonicalHostedJson(command.arguments), "utf8"));
        resealManifest(copy, manifest);
      }
    },
    {
      expectedCode: "HOSTED_DUAL_ROOT_REQUIRED_SUITE_EVIDENCE_REJECTED",
      name: "resealed-command-source-hash",
      mutate(copy) {
        const manifest = readManifest(copy);
        manifest.tests.requiredSuites.safety.command.sourceFiles[0].sha256 =
          "0".repeat(64);
        resealManifest(copy, manifest);
      }
    },
    {
      expectedCode: "HOSTED_DUAL_ROOT_REQUIRED_SUITE_EVIDENCE_REJECTED",
      name: "resealed-command-executable-hash",
      mutate(copy) {
        const manifest = readManifest(copy);
        manifest.tests.requiredSuites.safety.command.executableSha256 =
          "0".repeat(64);
        resealManifest(copy, manifest);
      }
    },
    {
      expectedCode: "HOSTED_DUAL_ROOT_REQUIRED_TEST_SKIPPED",
      name: "resealed-skipped-tap",
      mutate(copy) {
        const manifest = readManifest(copy);
        const relative = "logs/safety.tap";
        const filePath = path.join(copy, relative);
        const source = fs.readFileSync(filePath, "utf8");
        const index = source.lastIndexOf("# skipped 0");
        invariant(index >= 0, "HOSTED_DUAL_ROOT_TAMPER_FIXTURE_REJECTED");
        const changed = Buffer.from(`${source.slice(0, index)}# skipped 1${
          source.slice(index + "# skipped 0".length)}`, "utf8");
        fs.writeFileSync(filePath, changed);
        const record = manifest.tests.requiredSuites.safety;
        record.summary.skipped = 1;
        updateLogBinding(manifest, relative, changed, record.log);
        resealManifest(copy, manifest);
      }
    },
    {
      expectedCode: "HOSTED_DUAL_ROOT_SECURITY_RECEIPT_REJECTED",
      name: "resealed-security-receipt",
      mutate(copy) {
        const manifest = readManifest(copy);
        const relative = "logs/source-security-verifier.json";
        const filePath = path.join(copy, relative);
        const split = splitLog(fs.readFileSync(filePath));
        const receipt = JSON.parse(split.stdout.toString("utf8"));
        receipt.checks.canonicalManifest = false;
        const changed = Buffer.concat([
          Buffer.from(`${JSON.stringify(receipt, null, 2)}\n`, "utf8"),
          LOG_SEPARATOR,
          split.stderr
        ]);
        fs.writeFileSync(filePath, changed);
        const record = manifest.tests.requiredSuites.sourceSecurityVerifier;
        record.receipt.checks.canonicalManifest = false;
        updateLogBinding(manifest, relative, changed, record.log);
        resealManifest(copy, manifest);
      }
    },
    {
      expectedCode: "HOSTED_DUAL_ROOT_REQUIRED_SUITE_EVIDENCE_REJECTED",
      name: "resealed-process-receipt",
      mutate(copy) {
        const manifest = readManifest(copy);
        const relative = "logs/process-boundaries.log";
        const filePath = path.join(copy, relative);
        const split = splitLog(fs.readFileSync(filePath));
        const receipts = split.stdout.toString("utf8").trim().split("\n")
          .map((line) => JSON.parse(line));
        receipts[0].worker.modules.push("src/cloud/tampered.js");
        const changed = Buffer.concat([
          Buffer.from(`${receipts.map((receipt) =>
            JSON.stringify(receipt)).join("\n")}\n`, "utf8"),
          LOG_SEPARATOR,
          split.stderr
        ]);
        fs.writeFileSync(filePath, changed);
        const record = manifest.tests.requiredSuites.processBoundaries;
        record.receipts[0].worker.modules.push("src/cloud/tampered.js");
        updateLogBinding(manifest, relative, changed, record.log);
        resealManifest(copy, manifest);
      }
    }
  ];
  for (const vector of vectors) runVector({
    canonicalRoot: outputRoot,
    expectedCode: vector.expectedCode,
    name: vector.name,
    options,
    tamperRoot: root,
    mutate: vector.mutate
  });
  invariant(fs.readdirSync(root).length === 0,
    "HOSTED_DUAL_ROOT_TAMPER_CLEANUP_REJECTED");
  const finalVerification = verifyHostedDualRootArtifact({ ...options,
    outputRoot });
  invariant(finalVerification.manifestSha256 === canonical.manifestSha256,
    "HOSTED_DUAL_ROOT_TAMPER_FINAL_RESTORE_REJECTED");
  return Object.freeze({
    canonicalManifestSha256: canonical.manifestSha256,
    providerExecutionAuthorized: false,
    status: "HOSTED_DUAL_ROOT_TAMPER_MATRIX_PASS",
    vectorCount: vectors.length
  });
}

async function main() {
  const values = parse(process.argv.slice(2));
  const result = runTamperMatrix({
    applicationRoot: values.get("--application-root"),
    controlRoot: values.get("--control-root"),
    npmCli: values.get("--npm-cli"),
    outputRoot: values.get("--output-root"),
    tamperRoot: values.get("--tamper-root")
  });
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

if (process.argv[1] && import.meta.url ===
  pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch((cause) => {
    const message = String(cause?.message ?? "");
    const code = /^HOSTED_DUAL_ROOT_[A-Z0-9_]{1,120}$/u.test(message)
      ? message : "HOSTED_DUAL_ROOT_TAMPER_UNKNOWN_HOLD";
    process.stderr.write(`HOLD:${code}\n`);
    process.exitCode = 1;
  });
}
