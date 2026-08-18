import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { loadReleaseControlRuntime } from
  "../release-control/src/release-control-runtime-loader.js";
import { loadReleaseProviderRuntime } from
  "../release-provider/src/release-provider-runtime-loader.js";
import {
  brokerCanonicalBytes,
  dispatchReservedProviderOneShotIntent,
  finalizeProviderOneShotIntent,
  reserveProviderOneShotIntent
} from "./release-provider-one-shot-broker.js";
import {
  canonicalDigest,
  canonicalJson,
  normalizeCallerIdentity
} from "../release-provider/src/release-provider-common.js";
import { publishOrReadExactOwnedFile } from
  "../src/cloud/atomic-create-only-file.js";
import {
  consumeExplicitTemporaryCredentials,
  decodePhaseLookup,
  encodePhaseLookup,
  sanitizedBrokerEnvironment
} from "./run-release-prepare-common.js";
import { buildPrepareExecutableSet } from
  "./run-release-prepare-phase.js";
import {
  acceptedExecuteApproval,
  buildExecutePhaseRuntime,
  phaseRuntimeIdentity,
  validateExecuteWorkflowContext
} from "./run-release-execute-common.js";

const HEX_64 = /^[0-9a-f]{64}$/u;

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function exactTemporaryRoot(environment) {
  const code = "RELEASE_EXECUTE_TEMPORARY_ROOT_REJECTED";
  const candidate = environment.RUNNER_TEMP;
  requireCondition(typeof candidate === "string" && path.isAbsolute(candidate),
  code);
  try {
    const real = fs.realpathSync(candidate);
    const stat = fs.lstatSync(real);
    requireCondition(real === path.resolve(candidate) && stat.isDirectory() &&
      !stat.isSymbolicLink(), code);
    return real;
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  }
}

function phaseContext(environment, phaseName, approvalEnvelope) {
  const validated = validateExecuteWorkflowContext(environment, phaseName);
  return Object.freeze({
    ...validated,
    approvalEnvelope,
    environment: Object.freeze({ ...environment })
  });
}

function writeLookupOutput(environment, lookup, dispatchPermitted) {
  const code = "RELEASE_EXECUTE_GITHUB_OUTPUT_REJECTED";
  const file = environment.GITHUB_OUTPUT;
  requireCondition(typeof file === "string" && path.isAbsolute(file), code);
  const encoded = encodePhaseLookup(lookup);
  requireCondition(!encoded.includes("\n") && encoded.length <= 32 * 1024 &&
    typeof dispatchPermitted === "boolean", code);
  let descriptor;
  try {
    requireCondition(fs.realpathSync(file) === path.resolve(file), code);
    descriptor = fs.openSync(file, fs.constants.O_WRONLY |
      fs.constants.O_APPEND | fs.constants.O_NOFOLLOW);
    const stat = fs.fstatSync(descriptor);
    const expectedUid = typeof process.getuid === "function"
      ? process.getuid() : stat.uid;
    requireCondition(stat.isFile() && stat.nlink === 1 &&
      stat.uid === expectedUid && stat.size <= 1024 * 1024, code);
    fs.writeFileSync(descriptor, `lookup_b64=${encoded}\n` +
      `dispatch_permitted=${dispatchPermitted ? "true" : "false"}\n`, {
      encoding: "utf8"
    });
    fs.fsyncSync(descriptor);
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  } finally {
    if (Number.isSafeInteger(descriptor)) fs.closeSync(descriptor);
  }
}

async function controlRuntime({ approval, credentials, executable }) {
  const receipt = executable.controlReceipt;
  const loaded = await loadReleaseControlRuntime({
    expectedControlPlaneCommit: approval.claims.controlPlane.commit,
    expectedControlPlaneTree: approval.claims.controlPlane.tree,
    expectedPackageJsonSha256: receipt.packageJsonSha256,
    expectedPackageLockSha256: receipt.packageLockSha256,
    projectRoot: executable.controlOutputRoot,
    receipt
  });
  const tableArn = approval.claims.globalStore.namespaceArn;
  const provider = await loaded.createReleaseControlAwsRuntime({
    credentials,
    region: "us-east-1",
    tableArn
  });
  const callerIdentity = await provider.getReleaseControlCallerIdentity();
  const [describeResponse, listTagsResponse] = await Promise.all([
    provider.describeReleaseControlTable({
      TableName: "prooftoact-release-controller"
    }),
    provider.listReleaseControlTags({ ResourceArn: tableArn })
  ]);
  const tableIdentity = loaded.attestReleaseControlTable({
    describeResponse,
    expectedAccountId: approval.providerAccountId,
    listTagsResponse,
    region: "us-east-1"
  });
  requireCondition(canonicalJson(tableIdentity) ===
    canonicalJson(approval.claims.globalStore),
  "RELEASE_EXECUTE_LIVE_TABLE_IDENTITY_REJECTED");
  const store = loaded.createReleaseControlDynamoDbStore({
    provider,
    tableArn
  });
  return Object.freeze({ callerIdentity, loaded, provider, receipt, store,
    tableIdentity });
}

async function providerRuntime({ approval, capability, executable }) {
  const receipt = executable.providerReceipt;
  const loaded = await loadReleaseProviderRuntime({
    capability,
    expectedControlPlaneCommit: approval.claims.controlPlane.commit,
    expectedControlPlaneTree: approval.claims.controlPlane.tree,
    expectedPackageJsonSha256: receipt.packageJsonSha256,
    expectedPackageLockSha256: receipt.packageLockSha256,
    outputRoot: executable.providerOutputRoot,
    receipt
  });
  return Object.freeze({ loaded, receipt });
}

function makePhaseRuntime({ accepted, callerIdentity, context, executable,
  now, phaseName }) {
  return buildExecutePhaseRuntime({
    actualControlPlaneBuildSha256: executable.identity.buildSha256,
    approval: accepted.approval,
    approvalEnvelope: accepted.envelope,
    brokerArtifactSha256: executable.identity.manifest.brokerSha256,
    callerIdentity,
    context,
    now,
    phaseName
  });
}

async function buildExecutable({ accepted, context }) {
  return buildPrepareExecutableSet({
    approval: accepted.approval,
    context,
    operatorPublicKey: accepted.publicKey,
    runnerTemp: exactTemporaryRoot(context.environment)
  });
}

async function runReserve({ clock = Date.now, environment }) {
  const preliminary = validateExecuteWorkflowContext(environment, "reserve");
  const accepted = acceptedExecuteApproval(environment,
    preliminary.controlRoot, "reserve", clock);
  const credentials = consumeExplicitTemporaryCredentials(environment);
  const brokerEnvironment = sanitizedBrokerEnvironment(environment);
  const context = phaseContext(environment, "reserve", accepted.envelope);
  const executable = await buildExecutable({ accepted, context });
  try {
    accepted.boundary();
    const control = await controlRuntime({ approval: accepted.approval,
      credentials, executable });
    const boundary = accepted.boundary();
    const runtime = makePhaseRuntime({ accepted,
      callerIdentity: control.callerIdentity, context, executable,
      now: boundary.now, phaseName: "reserve" });
    const store = Object.freeze({
      async appendIntent(request) {
        accepted.boundary();
        return control.store.appendIntent(request);
      },
      async consumeOnce(request) {
        accepted.boundary();
        return control.store.consumeOnce(request);
      },
      async readStrong(request) {
        accepted.boundary();
        return control.store.readStrong(request);
      }
    });
    const result = await reserveProviderOneShotIntent({
      approvalEnvelope: accepted.envelope,
      clock,
      coordinatorRuntime: runtime,
      environment: brokerEnvironment,
      globalStore: store,
      trustedOperatorPublicKey: accepted.publicKey
    });
    requireCondition(["INTENT_RECORDED", "INTENT_ALREADY_RECORDED",
      "TERMINAL_ALREADY_RECORDED"]
      .includes(result.receipt.status),
    "RELEASE_EXECUTE_RESERVE_NOT_DISPATCHABLE");
    const dispatchPermitted = result.receipt.status === "INTENT_RECORDED";
    writeLookupOutput(context.environment, result.lookup, dispatchPermitted);
    return Object.freeze({ lookupSha256: result.lookup.lookupSha256,
      dispatchPermitted, status: result.receipt.status });
  } finally {
    executable.cleanup();
  }
}

async function runDispatch({ clock = Date.now, environment }) {
  const preliminary = validateExecuteWorkflowContext(environment, "dispatch");
  const accepted = acceptedExecuteApproval(environment,
    preliminary.controlRoot, "dispatch", clock);
  const lookup = decodePhaseLookup(
    environment.PROOFTOACT_RELEASE_EXECUTE_LOOKUP_B64);
  delete environment.PROOFTOACT_RELEASE_EXECUTE_LOOKUP_B64;
  const credentials = consumeExplicitTemporaryCredentials(environment);
  const brokerEnvironment = sanitizedBrokerEnvironment(environment);
  const context = phaseContext(environment, "dispatch", accepted.envelope);
  const executable = await buildExecutable({ accepted, context });
  try {
    accepted.boundary();
    const permitBundle = await providerRuntime({
      approval: accepted.approval,
      capability: "EXECUTE_PERMIT_READER",
      executable
    });
    const dispatcherBundle = await providerRuntime({
      approval: accepted.approval,
      capability: "EXECUTE_DISPATCHER",
      executable
    });
    const permitTransport = await permitBundle.loaded.exports
      .createAwsExecutePermitTransport({
        credentials,
        tableArn: accepted.approval.claims.globalStore.namespaceArn
      });
    const permitReader = permitBundle.loaded.exports.createExecutePermitReader({
      accountId: accepted.approval.providerAccountId,
      expectedTableIdentity: accepted.approval.claims.globalStore,
      transport: permitTransport
    });
    const dispatchTransport = await dispatcherBundle.loaded.exports
      .createAwsExecuteDispatcherTransport({ credentials });
    const providerDispatcher = dispatcherBundle.loaded.exports
      .createExecuteDispatcher({ transport: dispatchTransport });
    accepted.boundary();
    const caller = normalizeCallerIdentity(
      await permitTransport.getCallerIdentity(),
      "ProofToActReleaseExecution"
    );
    const dispatchBoundary = accepted.boundary();
    const runtime = makePhaseRuntime({ accepted,
      callerIdentity: caller, context, executable,
      now: dispatchBoundary.now, phaseName: "dispatch" });
    let capturedRecord = null;
    const intentReader = Object.freeze({
      async readStrong(request) {
        accepted.boundary();
        capturedRecord = await permitReader.readStrong(request);
        return capturedRecord;
      }
    });
    const dispatcher = Object.freeze({
      async dispatch(input) {
        accepted.boundary();
        requireCondition(capturedRecord?.status === "INTENT" &&
          capturedRecord.intent?.intentId === input.intent.intentId &&
          capturedRecord.command?.commandSha256 === input.command.commandSha256,
        "RELEASE_EXECUTE_CAPTURED_INTENT_REJECTED");
        const permit = await permitReader.readIntent({
          commandSha256: input.command.commandSha256,
          globalKeySha256: input.command.globalKeySha256,
          intentId: input.intent.intentId
        });
        requireCondition(permit.intent.intentId === input.intent.intentId &&
          permit.command.commandSha256 === input.command.commandSha256,
        "RELEASE_EXECUTE_PERMIT_REJECTED");
        accepted.boundary();
        const outcome = await providerDispatcher.dispatch({
          ...input,
          authorityNotAfter: runtime.authorityReceipts.expiresAt
        });
        accepted.boundary();
        return outcome;
      }
    });
    const result = await dispatchReservedProviderOneShotIntent({
      approvalEnvelope: accepted.envelope,
      clock,
      dispatcher,
      environment: brokerEnvironment,
      intentReader,
      lookup,
      providerRuntime: runtime,
      trustedOperatorPublicKey: accepted.publicKey
    });
    requireCondition(["DISPATCH_OUTCOME_UNKNOWN", "DISPATCH_OBSERVED"]
      .includes(result.receipt.status) && result.receipt.retryAllowed === false,
    "RELEASE_EXECUTE_DISPATCH_DISPOSITION_REJECTED");
    return Object.freeze({ status: result.receipt.status });
  } finally {
    executable.cleanup();
  }
}

function exactReceiptRoot(environment) {
  const code = "RELEASE_EXECUTE_RECEIPT_ROOT_REJECTED";
  const runnerTemp = exactTemporaryRoot(environment);
  const rootPath = path.join(runnerTemp, "prooftoact-execute-receipts");
  try {
    fs.mkdirSync(rootPath, { mode: 0o700 });
  } catch (cause) {
    if (cause?.code !== "EEXIST") reject(code, cause);
  }
  const stat = fs.lstatSync(rootPath);
  const uid = typeof process.getuid === "function" ? process.getuid() : stat.uid;
  requireCondition(fs.realpathSync(rootPath) === rootPath &&
    stat.isDirectory() && !stat.isSymbolicLink() && stat.uid === uid &&
    (stat.mode & 0o077) === 0, code);
  return rootPath;
}

function publishFinalizerReceipt({ accepted, context, result, runtime,
  observedAt }) {
  const code = "RELEASE_EXECUTE_RECEIPT_PUBLICATION_REJECTED";
  requireCondition(result?.receipt && HEX_64.test(
    result.receipt.receiptSha256 ?? ""), code);
  const body = {
    schemaVersion: "prooftoact.execute-finalizer-publication.v1",
    approvalSha256: accepted.approval.approvalSha256,
    controlPlaneCommit: accepted.approval.claims.controlPlane.commit,
    controlPlaneIdentitySha256:
      accepted.approval.claims.controlPlane.identitySha256,
    finalizerPhaseReceipt: result.receipt,
    observedAt: new Date(observedAt).toISOString(),
    phaseRuntimeIdentity: phaseRuntimeIdentity(runtime),
    status: result.receipt.status
  };
  const publication = Object.freeze({
    ...body,
    publicationSha256: canonicalDigest(body)
  });
  const bytes = brokerCanonicalBytes(publication);
  const rootPath = exactReceiptRoot(context.environment);
  const filePath = path.join(rootPath,
    `${publication.publicationSha256}.json`);
  const output = publishOrReadExactOwnedFile({
    assertRoot: () => exactReceiptRoot(context.environment),
    bytes,
    code,
    filePath,
    maximumBytes: 1024 * 1024,
    mode: 0o600,
    rootPath
  });
  return Object.freeze({ created: output.created, filePath,
    publicationSha256: publication.publicationSha256 });
}

async function runFinalize({ clock = Date.now, environment }) {
  const preliminary = validateExecuteWorkflowContext(environment, "finalize");
  const accepted = acceptedExecuteApproval(environment,
    preliminary.controlRoot, "finalize", clock);
  const lookup = decodePhaseLookup(
    environment.PROOFTOACT_RELEASE_EXECUTE_LOOKUP_B64);
  delete environment.PROOFTOACT_RELEASE_EXECUTE_LOOKUP_B64;
  const credentials = consumeExplicitTemporaryCredentials(environment);
  const brokerEnvironment = sanitizedBrokerEnvironment(environment);
  const context = phaseContext(environment, "finalize", accepted.envelope);
  const executable = await buildExecutable({ accepted, context });
  try {
    accepted.boundary();
    const control = await controlRuntime({ approval: accepted.approval,
      credentials, executable });
    const readbackBundle = await providerRuntime({
      approval: accepted.approval,
      capability: "EXECUTE_READBACK",
      executable
    });
    const finalizeBoundary = accepted.boundary();
    const runtime = makePhaseRuntime({ accepted,
      callerIdentity: control.callerIdentity, context, executable,
      now: finalizeBoundary.now, phaseName: "finalize" });
    const store = Object.freeze({
      async finalize(request) {
        accepted.boundary();
        return control.store.finalize(request);
      },
      async readStrong(request) {
        accepted.boundary();
        return control.store.readStrong(request);
      }
    });
    const transport = await readbackBundle.loaded.exports
      .createAwsExecuteReadbackTransport({ credentials });
    const reader = readbackBundle.loaded.exports.createExecuteReadback({
      transport
    });
    const identity = phaseRuntimeIdentity(runtime);
    const providerReadback = Object.freeze({
      async readback(input) {
        accepted.boundary();
        const readback = await reader.readback({
          ...input,
          readerPhaseRuntimeIdentitySha256:
            identity.phaseRuntimeIdentitySha256
        });
        accepted.boundary();
        return readback;
      }
    });
    const result = await finalizeProviderOneShotIntent({
      approvalEnvelope: accepted.envelope,
      clock,
      coordinatorRuntime: runtime,
      dispatcherOutcome: null,
      environment: brokerEnvironment,
      globalStore: store,
      lookup,
      providerReadback,
      trustedOperatorPublicKey: accepted.publicKey
    });
    const publishedBoundary = accepted.boundary();
    const publication = publishFinalizerReceipt({ accepted, context, result,
      runtime, observedAt: publishedBoundary.now });
    return Object.freeze({ publication, status: result.receipt.status });
  } finally {
    executable.cleanup();
  }
}

export async function runExecutePhase(phaseName, {
  clock = Date.now,
  environment = process.env
} = {}) {
  requireCondition(["reserve", "dispatch", "finalize"].includes(phaseName),
    "RELEASE_EXECUTE_PHASE_REJECTED");
  if (phaseName === "reserve") return runReserve({ clock, environment });
  if (phaseName === "dispatch") return runDispatch({ clock, environment });
  return runFinalize({ clock, environment });
}

export async function main(args = process.argv.slice(2),
  environment = process.env) {
  requireCondition(args.length === 1,
    "RELEASE_EXECUTE_PHASE_ARGUMENT_REJECTED");
  const result = await runExecutePhase(args[0], { environment });
  process.stdout.write(`PROOFTOACT_EXECUTE_${args[0].toUpperCase()}_PASS:` +
    `${result.status}\n`);
  if (args[0] === "finalize") {
    requireCondition(result.status === "CONFIRMED",
      "RELEASE_EXECUTE_FINALIZER_NOT_CONFIRMED");
  }
}

if (process.argv[1] && import.meta.url ===
  pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch((cause) => {
    const message = String(cause?.message ?? "");
    const code = /^RELEASE_(?:EXECUTE|PREPARE)_[A-Z0-9_]{1,100}$/u
      .test(message) ? message : "RELEASE_EXECUTE_UNKNOWN_HOLD";
    process.stderr.write(`HOLD:${code}\n`);
    process.exitCode = 1;
  });
}

export const __test = Object.freeze({
  exactReceiptRoot,
  exactTemporaryRoot,
  publishFinalizerReceipt,
  writeLookupOutput
});
