import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const HEX_40 = /^[0-9a-f]{40}$/u;
const CONTRACTS = Object.freeze({
  coordinator: Object.freeze({
    environment: "aws-release-coordination",
    phases: Object.freeze(new Set(["reserve", "finalize"]))
  }),
  prepare: Object.freeze({
    environment: "aws-release-deployment",
    phases: Object.freeze(new Set(["dispatch"]))
  })
});

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function exactOutputRoot(candidate) {
  const code = "RELEASE_CREDENTIAL_SEAL_OUTPUT_REJECTED";
  requireCondition(typeof candidate === "string" && path.isAbsolute(candidate),
  code);
  try {
    fs.mkdirSync(candidate, { mode: 0o700 });
    const resolved = fs.realpathSync(candidate);
    const stat = fs.lstatSync(resolved);
    requireCondition(resolved === path.resolve(candidate) && stat.isDirectory() &&
      !stat.isSymbolicLink() && (stat.mode & 0o777) === 0o700 &&
      fs.readdirSync(resolved).length === 0, code);
    return resolved;
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  }
}

function publishExact(root, name, bytes) {
  const code = "RELEASE_CREDENTIAL_SEAL_PUBLICATION_REJECTED";
  const target = path.join(root, name);
  let descriptor;
  try {
    descriptor = fs.openSync(target, fs.constants.O_CREAT |
      fs.constants.O_EXCL | fs.constants.O_WRONLY |
      fs.constants.O_NOFOLLOW, 0o600);
    let offset = 0;
    while (offset < bytes.length) {
      const written = fs.writeSync(descriptor, bytes, offset,
        bytes.length - offset, offset);
      requireCondition(written > 0, code);
      offset += written;
    }
    fs.fsyncSync(descriptor);
    const stat = fs.fstatSync(descriptor);
    requireCondition(stat.isFile() && stat.nlink === 1 &&
      (stat.mode & 0o777) === 0o600 && stat.size === bytes.length, code);
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  } finally {
    if (Number.isSafeInteger(descriptor)) fs.closeSync(descriptor);
  }
  requireCondition(fs.realpathSync(target) === target &&
    sha256(fs.readFileSync(target)) === sha256(bytes), code);
  return Object.freeze({ bytes: bytes.length, path: target,
    sha256: sha256(bytes) });
}

export function buildReleaseCredentialSeal({
  authorityCommit,
  authorityTree,
  environment,
  lane,
  outputRoot,
  phase
}) {
  const code = "RELEASE_CREDENTIAL_SEAL_INPUT_REJECTED";
  const normalizedLane = typeof lane === "string" ? lane.toLowerCase() : "";
  const contract = CONTRACTS[normalizedLane];
  requireCondition(contract !== undefined && HEX_40.test(authorityCommit ?? "") &&
    HEX_40.test(authorityTree ?? "") && authorityCommit !== authorityTree &&
    environment === contract.environment && contract.phases.has(phase), code);
  const root = exactOutputRoot(outputRoot);
  const laneName = normalizedLane.toUpperCase();
  const command = Object.freeze({
    action: "HOLD_NO_PROVIDER_EXECUTION",
    authorityCommit,
    authorityTree,
    lane: laneName,
    phase,
    schemaVersion: "prooftoact.sealed-credential-command.v1"
  });
  const commandBytes = Buffer.from(`${JSON.stringify(command)}\n`, "utf8");
  const commandRecord = publishExact(root, "command.json", commandBytes);
  const manifest = Object.freeze({
    authorityCommit,
    authorityTree,
    commandSha256: commandRecord.sha256,
    environment,
    lane: laneName,
    phase,
    schemaVersion: "prooftoact.sealed-credential-manifest.v1",
    status: "HASH_BOUND_NOT_EXECUTABLE"
  });
  const manifestRecord = publishExact(root, "manifest.json",
    Buffer.from(`${JSON.stringify(manifest)}\n`, "utf8"));
  const directory = fs.openSync(root, fs.constants.O_RDONLY);
  try {
    fs.fsyncSync(directory);
  } finally {
    fs.closeSync(directory);
  }
  return Object.freeze({
    commandBase64: commandBytes.toString("base64"),
    commandSha256: commandRecord.sha256,
    manifestBase64: fs.readFileSync(manifestRecord.path).toString("base64"),
    manifestSha256: manifestRecord.sha256,
    status: "SEALED_NON_EXECUTABLE_COMMAND_GENERATED"
  });
}

export function main(args = process.argv.slice(2)) {
  requireCondition(args.length === 6,
    "RELEASE_CREDENTIAL_SEAL_ARGUMENT_REJECTED");
  const [outputRoot, lane, environment, phase, authorityCommit,
    authorityTree] = args;
  process.stdout.write(`${JSON.stringify(buildReleaseCredentialSeal({
    authorityCommit,
    authorityTree,
    environment,
    lane,
    outputRoot,
    phase
  }))}\n`);
}

if (process.argv[1] && import.meta.url ===
  pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    main();
  } catch (cause) {
    const message = /^RELEASE_CREDENTIAL_SEAL_[A-Z0-9_]+$/u
      .test(cause?.message ?? "")
      ? cause.message : "RELEASE_CREDENTIAL_SEAL_UNKNOWN_HOLD";
    process.stderr.write(`HOLD:${message}\n`);
    process.exitCode = 1;
  }
}

export const __test = Object.freeze({ CONTRACTS, publishExact, sha256 });
