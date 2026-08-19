import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

import {
  __test as sealerTest,
  sealFreshPrimaryCredentialCustody,
  validateFreshPrimaryCredentialSealApproval
} from "./fresh-primary-credential-sealer.js";
import {
  createFreshPrimaryCredentialSealerAwsRuntime
} from "./fresh-primary-credential-sealer-aws-runtime.js";
import {
  verifyFreshPrimaryCredentialCustodyPlan
} from "./prepare-fresh-primary-credential-custody.js";

const OPTIONS = Object.freeze([
  "--secret-arns-file",
  "--approval-file",
  "--auditor-file",
  "--cloud-api-file",
  "--credential-file",
  "--mcp-file",
  "--plan-file",
  "--publisher-file"
]);

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function parseArguments(argv) {
  const code = "FRESH_CREDENTIAL_RUNNER_ARGUMENTS_REJECTED";
  requireCondition(Array.isArray(argv) && argv.length === OPTIONS.length * 2,
    code);
  const parsed = {};
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    requireCondition(OPTIONS.includes(name) && !Object.hasOwn(parsed, name) &&
      typeof value === "string" && path.isAbsolute(value), code);
    parsed[name] = value;
  }
  requireCondition(Object.keys(parsed).sort().join("\n") ===
    [...OPTIONS].sort().join("\n"), code);
  return Object.freeze(parsed);
}

function assertPrivateDirectory(directoryPath, code) {
  requireCondition(path.isAbsolute(directoryPath), code);
  const resolved = fs.realpathSync(directoryPath);
  const stat = fs.lstatSync(resolved);
  requireCondition(resolved === directoryPath && stat.isDirectory() &&
    !stat.isSymbolicLink() && stat.uid === process.getuid() &&
    (stat.mode & 0o077) === 0, code);
  return resolved;
}

function readPrivateFile(filePath, maximumBytes, code) {
  requireCondition(path.isAbsolute(filePath), code);
  const parent = assertPrivateDirectory(path.dirname(filePath), code);
  let descriptor;
  try {
    descriptor = fs.openSync(
      filePath,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW
    );
    const before = fs.fstatSync(descriptor);
    requireCondition(before.isFile() && !before.isSymbolicLink() &&
      before.nlink === 1 && before.uid === process.getuid() &&
      (before.mode & 0o077) === 0 && before.size > 0 &&
      before.size <= maximumBytes && path.dirname(filePath) === parent, code);
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor);
    const named = fs.lstatSync(filePath);
    requireCondition(bytes.length === before.size &&
      before.dev === after.dev && before.ino === after.ino &&
      before.mode === after.mode && before.size === after.size &&
      named.isFile() && !named.isSymbolicLink() && named.nlink === 1 &&
      named.dev === after.dev && named.ino === after.ino &&
      named.mode === after.mode && named.size === after.size, code);
    return bytes;
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  } finally {
    if (Number.isSafeInteger(descriptor)) fs.closeSync(descriptor);
  }
}

function parseJson(bytes, code) {
  try {
    return JSON.parse(bytes.toString("utf8"));
  } catch (cause) {
    reject(code, cause);
  }
}

export async function runFreshPrimaryCredentialSealer({
  argv,
  clock = Date.now,
  providerFactory = createFreshPrimaryCredentialSealerAwsRuntime
}) {
  const parsed = parseArguments(argv);
  const plan = verifyFreshPrimaryCredentialCustodyPlan(parseJson(
    readPrivateFile(parsed["--plan-file"], 256 * 1024,
      "FRESH_CREDENTIAL_RUNNER_PLAN_REJECTED"),
    "FRESH_CREDENTIAL_RUNNER_PLAN_REJECTED"
  ));
  const secretArns = parseJson(readPrivateFile(
    parsed["--secret-arns-file"], 64 * 1024,
    "FRESH_CREDENTIAL_RUNNER_ARNS_REJECTED"
  ), "FRESH_CREDENTIAL_RUNNER_ARNS_REJECTED");
  const rawApproval = parseJson(
    readPrivateFile(parsed["--approval-file"], 256 * 1024,
      "FRESH_CREDENTIAL_RUNNER_APPROVAL_REJECTED"),
    "FRESH_CREDENTIAL_RUNNER_APPROVAL_REJECTED"
  );
  const approval = validateFreshPrimaryCredentialSealApproval(rawApproval, {
    clock, plan, secretArns
  });

  const valueFiles = Object.freeze({
    auditor: "--auditor-file",
    cloudApi: "--cloud-api-file",
    credential: "--credential-file",
    mcp: "--mcp-file",
    publisher: "--publisher-file"
  });
  const buffers = [];
  const values = {};
  try {
    for (const [name, option] of Object.entries(valueFiles)) {
      const buffer = readPrivateFile(
        parsed[option], sealerTest.MAXIMUM_BYTES[name],
        "FRESH_CREDENTIAL_RUNNER_VALUE_REJECTED"
      );
      buffers.push(buffer);
      values[name] = buffer.toString("utf8");
    }
    const provider = await providerFactory({
      secretArns: Object.values(secretArns)
    });
    const receipt = await sealFreshPrimaryCredentialCustody({
      approval: rawApproval,
      clock,
      plan,
      provider,
      secretArns,
      values
    });
    const secretCoordinates = Object.fromEntries([
      ...sealerTest.WRITER_TARGETS.map((name) => [name, {
        arn: secretArns[name],
        versionId: approval.secretBindings[name].clientRequestToken
      }]),
      ...sealerTest.RUNTIME_TARGETS.map((name) => [name, {
        arn: secretArns[name],
        versionId: sealerTest.runtimeVersionId(
          plan, name, secretArns[name]
        )
      }])
    ]);
    return Object.freeze({
      schemaVersion:
        "prooftoact.fresh-primary-credential-sealer-private-output.v1",
      status: "SEALED_PRIVATE_COORDINATES_READY",
      approvalSha256: approval.approvalSha256,
      custodyPlanSha256: plan.planSha256,
      operationId: plan.operationId,
      receipt,
      secretCoordinates
    });
  } finally {
    for (const buffer of buffers) buffer.fill(0);
    for (const name of Object.keys(values)) values[name] = "";
  }
}

async function main() {
  const output = await runFreshPrimaryCredentialSealer({
    argv: process.argv.slice(2)
  });
  process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
}

const startedDirectly = process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;

if (startedDirectly) {
  main().catch((cause) => {
    const message = String(cause?.message ?? "");
    const code = /^FRESH_CREDENTIAL_[A-Z0-9_]{1,100}$/u.test(message)
      ? message
      : "FRESH_CREDENTIAL_RUNNER_UNKNOWN";
    process.stderr.write(`${code}\n`);
    process.exitCode = 1;
  });
}

export const __test = Object.freeze({
  OPTIONS,
  assertPrivateDirectory,
  parseArguments,
  parseJson,
  readPrivateFile
});
