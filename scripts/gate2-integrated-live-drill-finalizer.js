import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { canonicalJson } from "../src/cloud/canonical-json.js";
import { parseIntegratedLiveDrillSpec } from
  "../src/cloud/integrated-live-drill.js";
import { integratedLiveDrillChildCommittedTrustRoot } from
  "../src/cloud/integrated-live-drill-child-authorization.js";
import { validateIntegratedLiveDrillPacketAFinalization } from
  "../src/cloud/integrated-live-drill-finalizer.js";
import { loadCommittedRecoveryPublisherTrustRoot } from
  "./lib/recovery-publisher-key.js";

export const INTEGRATED_LIVE_DRILL_PACKET_A_INPUT_SCHEMA =
  "tideproof.highwater-drill-packet-a-untrusted-finalizer-input.v1";
export const INTEGRATED_LIVE_DRILL_PACKET_A_TRUSTED_CONTEXT_SCHEMA =
  "tideproof.highwater-drill-packet-a-trusted-finalizer-context.v1";

const MAX_INPUT_BYTES = 16 * 1024 * 1024;
const MODULE_ROOT = fs.realpathSync(path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  ".."
));

function exactKeys(value, keys) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join("\n") === [...keys].sort().join("\n")
  );
}

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

export function parseIntegratedLiveDrillPacketAFinalizerInput(value) {
  if (
    !exactKeys(value, [
      "authorizationAttestation",
      "candidateReceipt",
      "deploymentAttestationPair",
      "evidenceAttestations",
      "expectation",
      "finalizationStatement",
      "schemaVersion"
    ]) ||
    value.schemaVersion !== INTEGRATED_LIVE_DRILL_PACKET_A_INPUT_SCHEMA
  ) {
    reject("INTEGRATED_LIVE_DRILL_PACKET_A_INPUT_REJECTED");
  }
  return Object.freeze({ ...value });
}

export function parseIntegratedLiveDrillPacketAFinalizerTrustedContext(value) {
  if (
    !exactKeys(value, [
      "committedTrustRoot",
      "forbiddenRootPath",
      "humanAuthorizationTrustRoot",
      "ledgerRootPath",
      "runnerIdentity",
      "schemaVersion",
      "spec"
    ]) ||
    value.schemaVersion !==
      INTEGRATED_LIVE_DRILL_PACKET_A_TRUSTED_CONTEXT_SCHEMA
  ) {
    reject("INTEGRATED_LIVE_DRILL_PACKET_A_TRUSTED_CONTEXT_REJECTED");
  }
  return Object.freeze({ ...value });
}

export function runIntegratedLiveDrillPacketAFinalizer(
  untrustedValue,
  trustedValue,
  { now = Date.now() } = {}
) {
  const input = parseIntegratedLiveDrillPacketAFinalizerInput(untrustedValue);
  const trusted =
    parseIntegratedLiveDrillPacketAFinalizerTrustedContext(trustedValue);
  return validateIntegratedLiveDrillPacketAFinalization({
    authorizationAttestation: input.authorizationAttestation,
    candidateReceipt: input.candidateReceipt,
    committedTrustRoot: trusted.committedTrustRoot,
    deploymentAttestationPair: input.deploymentAttestationPair,
    evidenceAttestations: input.evidenceAttestations,
    expectation: input.expectation,
    finalizationStatement: input.finalizationStatement,
    forbiddenRootPath: trusted.forbiddenRootPath,
    humanAuthorizationTrustRoot: trusted.humanAuthorizationTrustRoot,
    ledgerRootPath: trusted.ledgerRootPath,
    runnerIdentity: trusted.runnerIdentity,
    spec: trusted.spec,
    now
  });
}

function requiredEnvironment(environment, name, maximum = 4096) {
  const value = environment?.[name];
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maximum ||
    /[\0\r\n]/u.test(value)
  ) {
    reject("INTEGRATED_LIVE_DRILL_PACKET_A_TRUSTED_CONTEXT_REJECTED");
  }
  return value;
}

function canonicalEnvironmentJson(environment, name, maximum) {
  const raw = requiredEnvironment(environment, name, maximum);
  let value;
  try {
    value = JSON.parse(raw);
  } catch (cause) {
    reject("INTEGRATED_LIVE_DRILL_PACKET_A_TRUSTED_CONTEXT_REJECTED", cause);
  }
  if (raw !== canonicalJson(value)) {
    reject("INTEGRATED_LIVE_DRILL_PACKET_A_TRUSTED_CONTEXT_REJECTED");
  }
  return value;
}

export function loadIntegratedLiveDrillPacketAFinalizerTrustedContext(
  environment = process.env
) {
  let committedTrustRoot;
  try {
    committedTrustRoot = integratedLiveDrillChildCommittedTrustRoot(
      loadCommittedRecoveryPublisherTrustRoot(environment)
    );
  } catch (cause) {
    reject("INTEGRATED_LIVE_DRILL_PACKET_A_TRUSTED_CONTEXT_REJECTED", cause);
  }
  return parseIntegratedLiveDrillPacketAFinalizerTrustedContext({
    schemaVersion:
      INTEGRATED_LIVE_DRILL_PACKET_A_TRUSTED_CONTEXT_SCHEMA,
    committedTrustRoot,
    forbiddenRootPath: MODULE_ROOT,
    humanAuthorizationTrustRoot: canonicalEnvironmentJson(
      environment,
      "TIDEPROOF_INTEGRATED_LIVE_DRILL_HUMAN_AUTHORIZATION_TRUST_ROOT",
      16_384
    ),
    ledgerRootPath: requiredEnvironment(
      environment,
      "TIDEPROOF_INTEGRATED_LIVE_DRILL_AUTHORIZATION_LEDGER_ROOT",
      4096
    ),
    runnerIdentity: requiredEnvironment(
      environment,
      "TIDEPROOF_INTEGRATED_LIVE_DRILL_RUNNER_IDENTITY",
      512
    ),
    spec: parseIntegratedLiveDrillSpec(canonicalEnvironmentJson(
      environment,
      "TIDEPROOF_INTEGRATED_LIVE_DRILL_SPEC",
      8192
    ))
  });
}

function readCanonicalInputFile(inputPath) {
  if (
    typeof inputPath !== "string" ||
    !path.isAbsolute(inputPath) ||
    path.resolve(inputPath) !== inputPath
  ) {
    reject("INTEGRATED_LIVE_DRILL_PACKET_A_INPUT_PATH_REJECTED");
  }
  let canonicalPath;
  let stat;
  let bytes;
  try {
    canonicalPath = fs.realpathSync(inputPath);
    stat = fs.lstatSync(inputPath);
    if (
      canonicalPath !== inputPath ||
      !stat.isFile() ||
      stat.isSymbolicLink() ||
      stat.nlink !== 1 ||
      stat.size <= 0 ||
      stat.size > MAX_INPUT_BYTES ||
      (typeof process.getuid === "function" && stat.uid !== process.getuid()) ||
      (stat.mode & 0o777) !== 0o600
    ) {
      reject("INTEGRATED_LIVE_DRILL_PACKET_A_INPUT_PATH_REJECTED");
    }
    bytes = fs.readFileSync(inputPath);
  } catch (cause) {
    if (cause?.message ===
      "INTEGRATED_LIVE_DRILL_PACKET_A_INPUT_PATH_REJECTED") {
      throw cause;
    }
    reject("INTEGRATED_LIVE_DRILL_PACKET_A_INPUT_PATH_REJECTED", cause);
  }
  let input;
  try {
    input = JSON.parse(bytes.toString("utf8"));
  } catch (cause) {
    reject("INTEGRATED_LIVE_DRILL_PACKET_A_INPUT_REJECTED", cause);
  }
  if (!bytes.equals(Buffer.from(`${canonicalJson(input)}\n`, "utf8"))) {
    reject("INTEGRATED_LIVE_DRILL_PACKET_A_INPUT_REJECTED");
  }
  return parseIntegratedLiveDrillPacketAFinalizerInput(input);
}

export function safeIntegratedLiveDrillPacketAFinalizerFailureCode(error) {
  const value = String(error?.message ?? "");
  return /^(?:INTEGRATED_LIVE_DRILL|AWS_ATTEST)_[A-Z0-9_]{1,100}$/u.test(
    value
  )
    ? value
    : "INTEGRATED_LIVE_DRILL_UNKNOWN";
}

export function main(
  argv = process.argv.slice(2),
  environment = process.env
) {
  if (argv.length !== 2 || argv[0] !== "--packet") {
    reject("INTEGRATED_LIVE_DRILL_PACKET_A_INPUT_PATH_REJECTED");
  }
  const receipt = runIntegratedLiveDrillPacketAFinalizer(
    readCanonicalInputFile(argv[1]),
    loadIntegratedLiveDrillPacketAFinalizerTrustedContext(environment)
  );
  process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
}

const startedDirectly =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (startedDirectly) {
  try {
    main();
  } catch (error) {
    process.stderr.write(
      `${safeIntegratedLiveDrillPacketAFinalizerFailureCode(error)}\n`
    );
    process.exitCode = 1;
  }
}
