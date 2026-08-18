import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { buildReleaseControlRuntime } from
  "../release-control/build-release-control-runtime.js";
import { loadReleaseControlRuntime } from
  "../release-control/src/release-control-runtime-loader.js";
import { buildReleaseProviderRuntimes } from
  "../release-provider/build-release-provider-runtimes.js";
import { loadReleaseProviderRuntime } from
  "../release-provider/src/release-provider-runtime-loader.js";
import {
  brokerCanonicalBytes,
  brokerSha256,
  dispatchReservedProviderOneShotIntent,
  finalizeProviderOneShotIntent,
  reserveProviderOneShotIntent
} from "./release-provider-one-shot-broker.js";
import {
  bindPrepareRequestToCommand,
  buildPhaseRuntime,
  buildPrepareProviderRequest,
  consumeBoundedSignedApproval,
  consumeExplicitTemporaryCredentials,
  consumePrivatePrepareConfiguration,
  decodePhaseLookup,
  encodePhaseLookup,
  phaseRuntimeIdentity,
  readTrackedOperatorPublicKey,
  sanitizedBrokerEnvironment,
  validatePrepareWorkflowContext,
  validateProtectedBootstrapGate,
  verifyControlPlaneExecutableManifest,
  verifyLiveControlCheckout
} from "./run-release-prepare-common.js";

const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const nested of Object.values(value)) deepFreeze(nested);
  }
  return value;
}

function exactTemporaryRoot(environment) {
  const code = "RELEASE_PREPARE_TEMPORARY_ROOT_REJECTED";
  const candidate = environment.RUNNER_TEMP;
  requireCondition(typeof candidate === "string" && path.isAbsolute(candidate),
  code);
  let real;
  try {
    real = fs.realpathSync(candidate);
    const stat = fs.lstatSync(real);
    requireCondition(real === path.resolve(candidate) && stat.isDirectory() &&
      !stat.isSymbolicLink(), code);
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  }
  return real;
}

function temporaryOutputRoot(runnerTemp, prefix) {
  const root = fs.mkdtempSync(path.join(runnerTemp, prefix));
  fs.chmodSync(root, 0o700);
  return fs.realpathSync(root);
}

export async function buildPrepareExecutableSet({
  approval,
  context,
  operatorPublicKey,
  runnerTemp
}) {
  verifyLiveControlCheckout({
    controlRoot: context.controlRoot,
    expectedCommit: approval.claims.controlPlane.commit,
    expectedTree: approval.claims.controlPlane.tree
  });
  const root = temporaryOutputRoot(runnerTemp, "pta-executable-set-");
  const controlOutputRoot = path.join(root, "control");
  const providerOutputRoot = path.join(root, "provider");
  try {
    const controlReceipt = await buildReleaseControlRuntime({
      controlPlaneCommit: approval.claims.controlPlane.commit,
      controlPlaneTree: approval.claims.controlPlane.tree,
      outputRoot: controlOutputRoot,
      projectRoot: path.join(context.controlRoot, "release-control")
    });
    const providerReceipt = await buildReleaseProviderRuntimes({
      controlPlaneCommit: approval.claims.controlPlane.commit,
      controlPlaneTree: approval.claims.controlPlane.tree,
      outputRoot: providerOutputRoot,
      projectRoot: path.join(context.controlRoot, "release-provider")
    });
    const identity = verifyControlPlaneExecutableManifest({
      approval,
      controlReceipt,
      controlRoot: context.controlRoot,
      operatorPublicKey,
      providerReceipt
    });
    return Object.freeze({
      cleanup() {
        fs.rmSync(root, { force: true, recursive: true });
      },
      controlOutputRoot,
      controlReceipt,
      identity,
      providerOutputRoot,
      providerReceipt
    });
  } catch (cause) {
    fs.rmSync(root, { force: true, recursive: true });
    throw cause;
  }
}

function exactJsonFile(filePath, maximumBytes, code) {
  requireCondition(typeof filePath === "string" && path.isAbsolute(filePath),
  code);
  let descriptor;
  try {
    const real = fs.realpathSync(filePath);
    requireCondition(real === path.resolve(filePath), code);
    descriptor = fs.openSync(real,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const stat = fs.fstatSync(descriptor);
    requireCondition(stat.isFile() && stat.nlink === 1 && stat.size > 0 &&
      stat.size <= maximumBytes, code);
    const bytes = fs.readFileSync(descriptor);
    return Object.freeze({ bytes, value: JSON.parse(bytes.toString("utf8")) });
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  } finally {
    if (Number.isSafeInteger(descriptor)) fs.closeSync(descriptor);
  }
}

async function controlRuntime({ approval, credentials, executable }) {
  const receipt = executable.controlReceipt;
  const outputRoot = executable.controlOutputRoot;
  try {
    const loaded = await loadReleaseControlRuntime({
      expectedControlPlaneCommit: approval.claims.controlPlane.commit,
      expectedControlPlaneTree: approval.claims.controlPlane.tree,
      expectedPackageJsonSha256: receipt.packageJsonSha256,
      expectedPackageLockSha256: receipt.packageLockSha256,
      projectRoot: outputRoot,
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
    requireCondition(brokerCanonicalBytes(tableIdentity).equals(
      brokerCanonicalBytes(approval.claims.globalStore)),
    "RELEASE_PREPARE_LIVE_TABLE_IDENTITY_REJECTED");
    const store = loaded.createReleaseControlDynamoDbStore({
      provider,
      tableArn
    });
    return Object.freeze({ callerIdentity, loaded, provider, receipt, store,
      tableIdentity });
  } catch (cause) {
    throw cause;
  }
}

async function providerRuntime({ approval, capability, executable }) {
  const outputRoot = executable.providerOutputRoot;
  try {
    const receipt = executable.providerReceipt;
    const loaded = await loadReleaseProviderRuntime({
      capability,
      expectedControlPlaneCommit: approval.claims.controlPlane.commit,
      expectedControlPlaneTree: approval.claims.controlPlane.tree,
      expectedPackageJsonSha256: receipt.packageJsonSha256,
      expectedPackageLockSha256: receipt.packageLockSha256,
      outputRoot,
      receipt
    });
    return Object.freeze({ loaded, receipt });
  } catch (cause) {
    throw cause;
  }
}

async function validatedPrepareRequest({ approval, applicationRoot,
  configuration, environment, intentId }) {
  const receipt = exactJsonFile(
    environment.PROOFTOACT_RELEASE_BUILD_RECEIPT_PATH,
    16 * 1024 * 1024,
    "RELEASE_PREPARE_BUILD_RECEIPT_REJECTED"
  );
  const readinessUrl = pathToFileURL(path.join(applicationRoot,
    "scripts/gate2-aws-readiness.js")).href;
  const readiness = await import(readinessUrl);
  requireCondition(typeof readiness.validateBuildReceipt === "function",
    "RELEASE_PREPARE_BUILD_VALIDATOR_REJECTED");
  const validatedBuild = readiness.validateBuildReceipt(receipt.value, {
    projectRoot: applicationRoot,
    sourceCommit: approval.claims.appSource.commit,
    treeDigest: approval.claims.appSource.tree
  });
  return buildPrepareProviderRequest({
    accountId: approval.providerAccountId,
    applicationRoot,
    approvalClaims: approval.claims,
    buildReceiptBytes: receipt.bytes,
    configuration,
    intentId,
    validatedBuild
  });
}

function phaseContext(environment, phaseName, approvalEnvelope) {
  const validated = validatePrepareWorkflowContext(environment, phaseName);
  return Object.freeze({
    ...validated,
    approvalEnvelope,
    environment: Object.freeze({ ...environment })
  });
}

function writeLookupOutput(environment, lookup) {
  const code = "RELEASE_PREPARE_GITHUB_OUTPUT_REJECTED";
  const file = environment.GITHUB_OUTPUT;
  requireCondition(typeof file === "string" && path.isAbsolute(file), code);
  const encoded = encodePhaseLookup(lookup);
  requireCondition(!encoded.includes("\n") && encoded.length <= 32 * 1024,
    code);
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
    fs.writeFileSync(descriptor, `lookup_b64=${encoded}\n`, {
      encoding: "utf8"
    });
    fs.fsyncSync(descriptor);
  } catch (cause) {
    reject(code, cause);
  } finally {
    if (Number.isSafeInteger(descriptor)) fs.closeSync(descriptor);
  }
}

function acceptedApproval(environment, context, phaseName, clock) {
  const publicKey = readTrackedOperatorPublicKey(context.controlRoot);
  const accepted = consumeBoundedSignedApproval({
    clock,
    environment,
    phaseName,
    trustedOperatorPublicKey: publicKey
  });
  requireCondition(accepted.approval.claims.controlPlane.commit ===
    environment.GITHUB_SHA,
  "RELEASE_PREPARE_CONTROL_PLANE_COMMIT_REJECTED");
  validateProtectedBootstrapGate({
    approval: accepted.approval,
    controlRoot: context.controlRoot,
    environment,
    phaseName
  });
  return Object.freeze({ ...accepted, publicKey });
}

function makePhaseRuntime({ accepted, brokerDigest, buildDigest,
  callerIdentity, context, phaseName, now }) {
  return buildPhaseRuntime({
    actualControlPlaneBuildSha256: buildDigest,
    approval: accepted.approval,
    brokerArtifactSha256: brokerDigest,
    callerIdentity,
    context: Object.freeze({ ...context,
      approvalEnvelope: accepted.envelope }),
    now,
    phaseName
  });
}

async function runReserve({ clock = Date.now, environment }) {
  const preliminary = validatePrepareWorkflowContext(environment, "reserve");
  const accepted = acceptedApproval(environment,
    { controlRoot: preliminary.controlRoot }, "reserve", clock);
  const credentials = consumeExplicitTemporaryCredentials(environment);
  const brokerEnvironment = sanitizedBrokerEnvironment(environment);
  const context = phaseContext(environment, "reserve", accepted.envelope);
  const runnerTemp = exactTemporaryRoot(context.environment);
  const executable = await buildPrepareExecutableSet({
    approval: accepted.approval,
    context,
    operatorPublicKey: accepted.publicKey,
    runnerTemp
  });
  try {
    accepted.boundary();
    const control = await controlRuntime({ approval: accepted.approval,
      credentials, executable });
    const boundary = accepted.boundary();
    const runtime = makePhaseRuntime({
      accepted,
      brokerDigest: executable.identity.manifest.brokerSha256,
      buildDigest: executable.identity.buildSha256,
      callerIdentity: control.callerIdentity,
      context,
      now: boundary.now,
      phaseName: "reserve"
    });
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
    requireCondition(["INTENT_RECORDED", "INTENT_ALREADY_RECORDED"]
      .includes(result.receipt.status),
    "RELEASE_PREPARE_RESERVE_NOT_DISPATCHABLE");
    writeLookupOutput(context.environment, result.lookup);
    return Object.freeze({ lookupSha256: result.lookup.lookupSha256,
      status: result.receipt.status });
  } finally {
    executable.cleanup();
  }
}

function dispatcherOutcome(providerReceipt, command, now) {
  const requestId = UUID.test(providerReceipt?.providerRequestId ?? "")
    ? providerReceipt.providerRequestId
    : null;
  requireCondition(HEX_64.test(providerReceipt?.providerReceiptSha256 ?? ""),
    "RELEASE_PREPARE_PROVIDER_RECEIPT_REJECTED");
  return Object.freeze({
    schemaVersion: "prooftoact.provider-dispatch-outcome.v1",
    observedAt: new Date(now).toISOString(),
    operationIdentitySha256: command.operationIdentitySha256,
    possibleMutation: true,
    providerReceiptSha256: providerReceipt.providerReceiptSha256,
    providerRequestId: requestId,
    status: "AMBIGUOUS"
  });
}

async function runDispatch({ clock = Date.now, environment }) {
  const preliminary = validatePrepareWorkflowContext(environment, "dispatch");
  const accepted = acceptedApproval(environment,
    { controlRoot: preliminary.controlRoot }, "dispatch", clock);
  const lookup = decodePhaseLookup(
    environment.PROOFTOACT_RELEASE_PREPARE_LOOKUP_B64);
  delete environment.PROOFTOACT_RELEASE_PREPARE_LOOKUP_B64;
  const configuration = consumePrivatePrepareConfiguration(environment,
    accepted.approval.providerAccountId);
  const credentials = consumeExplicitTemporaryCredentials(environment);
  const brokerEnvironment = sanitizedBrokerEnvironment(environment);
  const context = phaseContext(environment, "dispatch", accepted.envelope);
  const runnerTemp = exactTemporaryRoot(context.environment);
  const executable = await buildPrepareExecutableSet({
    approval: accepted.approval,
    context,
    operatorPublicKey: accepted.publicKey,
    runnerTemp
  });
  try {
    accepted.boundary();
    const permitBundle = await providerRuntime({
      approval: accepted.approval,
      capability: "PERMIT_READER",
      executable
    });
    const dispatcherBundle = await providerRuntime({
      approval: accepted.approval,
      capability: "PREPARE_DISPATCHER",
      executable
    });
    const permitTransport = await permitBundle.loaded.exports
      .createAwsPreparePermitTransport({
        credentials,
        tableArn: accepted.approval.claims.globalStore.namespaceArn
      });
    const permitReader = permitBundle.loaded.exports.createPreparePermitReader({
      accountId: accepted.approval.providerAccountId,
      expectedTableIdentity: accepted.approval.claims.globalStore,
      transport: permitTransport
    });
    requireCondition(typeof permitReader.readStrong === "function" &&
      typeof permitReader.readIntent === "function",
    "RELEASE_PREPARE_BROKER_READER_INTERFACE_REJECTED");
    const dispatchTransport = await dispatcherBundle.loaded.exports
      .createAwsPrepareDispatcherTransport({ credentials });
    const providerDispatcher = dispatcherBundle.loaded.exports
      .createPrepareDispatcher({ transport: dispatchTransport });
    let capturedRecord = null;
    const intentReader = Object.freeze({
      async readStrong(request) {
        accepted.boundary();
        capturedRecord = await permitReader.readStrong(request);
        return capturedRecord;
      }
    });
    const requestWithoutCommand = await validatedPrepareRequest({
      approval: accepted.approval,
      applicationRoot: context.applicationRoot,
      configuration,
      environment: context.environment,
      intentId: "00000000-0000-4000-8000-000000000000"
    });
    const dispatcher = Object.freeze({
      async dispatch({ command, intent }) {
        accepted.boundary();
        requireCondition(capturedRecord?.status === "INTENT" &&
          capturedRecord.intent?.intentId === intent.intentId &&
          capturedRecord.command?.commandSha256 === command.commandSha256,
        "RELEASE_PREPARE_CAPTURED_INTENT_REJECTED");
        const permit = await permitReader.readIntent({
          commandSha256: command.commandSha256,
          globalKeySha256: command.globalKeySha256,
          intentId: intent.intentId
        });
        const request = bindPrepareRequestToCommand({
          ...requestWithoutCommand,
          intentId: intent.intentId
        }, command);
        accepted.boundary();
        const providerReceipt = await providerDispatcher.dispatch({
          authorityNotAfter: accepted.envelope.expiresAt,
          permit,
          request
        });
        const completed = accepted.boundary();
        return dispatcherOutcome(providerReceipt, command,
          completed.now);
      }
    });
    accepted.boundary();
    const caller = await permitTransport.getCallerIdentity();
    const callerIdentity = Object.freeze({
      accountId: caller.Account,
      assumedRoleArn: caller.Arn,
      roleId: String(caller.UserId ?? "").split(":")[0],
      roleName: "ProofToActReleaseDeployment",
      sessionName: String(caller.UserId ?? "").split(":")[1]
    });
    const dispatchBoundary = accepted.boundary();
    const runtime = makePhaseRuntime({
      accepted,
      brokerDigest: executable.identity.manifest.brokerSha256,
      buildDigest: executable.identity.buildSha256,
      callerIdentity,
      context,
      now: dispatchBoundary.now,
      phaseName: "dispatch"
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
    requireCondition(result.receipt.status === "DISPATCH_OUTCOME_UNKNOWN" &&
      result.receipt.retryAllowed === false,
    "RELEASE_PREPARE_DISPATCH_DISPOSITION_REJECTED");
    return Object.freeze({ status: result.receipt.status });
  } finally {
    executable.cleanup();
  }
}

function readbackPermit({ command, intent, record, tableIdentity }) {
  requireCondition(record?.status === "INTENT" &&
    record.intent?.intentId === intent.intentId,
  "RELEASE_PREPARE_READBACK_RECORD_REJECTED");
  const base = {
    schemaVersion: "prooftoact.prepare-provider-permit.v1",
    status: "EXACT_DURABLE_INTENT_CONFIRMED",
    command,
    consumptionSha256: canonicalHash(record.consumption),
    intent,
    tableIdentity,
    readOnly: true,
    stronglyConsistent: true
  };
  return deepFreeze({ ...base, permitSha256: canonicalHash(base) });
}

function canonicalHash(value) {
  return brokerSha256(brokerCanonicalBytes(value));
}

function createSealedPrepareReader(providerExports, transport) {
  requireCondition(providerExports !== null &&
    typeof providerExports === "object" &&
    typeof providerExports.createPrepareReadback === "function",
  "RELEASE_PREPARE_READBACK_FACTORY_REJECTED");
  return providerExports.createPrepareReadback({ transport });
}

async function runFinalize({ clock = Date.now, environment }) {
  const preliminary = validatePrepareWorkflowContext(environment, "finalize");
  const accepted = acceptedApproval(environment,
    { controlRoot: preliminary.controlRoot }, "finalize", clock);
  const lookup = decodePhaseLookup(
    environment.PROOFTOACT_RELEASE_PREPARE_LOOKUP_B64);
  delete environment.PROOFTOACT_RELEASE_PREPARE_LOOKUP_B64;
  const configuration = consumePrivatePrepareConfiguration(environment,
    accepted.approval.providerAccountId);
  const credentials = consumeExplicitTemporaryCredentials(environment);
  const brokerEnvironment = sanitizedBrokerEnvironment(environment);
  const context = phaseContext(environment, "finalize", accepted.envelope);
  const runnerTemp = exactTemporaryRoot(context.environment);
  const executable = await buildPrepareExecutableSet({
    approval: accepted.approval,
    context,
    operatorPublicKey: accepted.publicKey,
    runnerTemp
  });
  try {
    accepted.boundary();
    const control = await controlRuntime({ approval: accepted.approval,
      credentials, executable });
    const readbackBundle = await providerRuntime({
      approval: accepted.approval,
      capability: "PREPARE_READBACK",
      executable
    });
    const finalizeBoundary = accepted.boundary();
    const runtime = makePhaseRuntime({
      accepted,
      brokerDigest: executable.identity.manifest.brokerSha256,
      buildDigest: executable.identity.buildSha256,
      callerIdentity: control.callerIdentity,
      context,
      now: finalizeBoundary.now,
      phaseName: "finalize"
    });
    let capturedRecord = null;
    const store = Object.freeze({
      async finalize(request) {
        accepted.boundary();
        return control.store.finalize(request);
      },
      async readStrong(request) {
        accepted.boundary();
        capturedRecord = await control.store.readStrong(request);
        return capturedRecord;
      }
    });
    const requestWithoutCommand = await validatedPrepareRequest({
      approval: accepted.approval,
      applicationRoot: context.applicationRoot,
      configuration,
      environment: context.environment,
      intentId: "00000000-0000-4000-8000-000000000000"
    });
    const transport = await readbackBundle.loaded.exports
      .createAwsPrepareReadbackTransport({ credentials });
    const reader = createSealedPrepareReader(
      readbackBundle.loaded.exports, transport);
    const identity = phaseRuntimeIdentity(runtime);
    const providerReadback = Object.freeze({
      async readback({ command, intent }) {
        accepted.boundary();
        const permit = readbackPermit({
          command,
          intent,
          record: capturedRecord,
          tableIdentity: accepted.approval.claims.globalStore
        });
        const result = await reader.readback({
          permit,
          readerPhaseRuntimeIdentitySha256:
            identity.phaseRuntimeIdentitySha256,
          request: bindPrepareRequestToCommand({
            ...requestWithoutCommand,
            intentId: intent.intentId
          }, command)
        });
        accepted.boundary();
        return result;
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
    requireCondition(result.receipt.status === "CONFIRMED" &&
      result.preparedRelease !== null,
    "RELEASE_PREPARE_FINALIZER_NOT_CONFIRMED");
    return Object.freeze({ status: result.receipt.status });
  } finally {
    executable.cleanup();
  }
}

export async function runPreparePhase(phaseName, {
  clock = Date.now,
  environment = process.env,
} = {}) {
  requireCondition(["reserve", "dispatch", "finalize"].includes(phaseName),
    "RELEASE_PREPARE_PHASE_REJECTED");
  if (phaseName === "reserve") return runReserve({ clock, environment });
  if (phaseName === "dispatch") return runDispatch({ clock, environment });
  return runFinalize({ clock, environment });
}

export async function main(args = process.argv.slice(2),
  environment = process.env) {
  requireCondition(args.length === 1,
    "RELEASE_PREPARE_PHASE_ARGUMENT_REJECTED");
  const result = await runPreparePhase(args[0], { environment });
  process.stdout.write(`PROOFTOACT_PREPARE_${args[0].toUpperCase()}_PASS:` +
    `${result.status}\n`);
}

if (process.argv[1] && import.meta.url ===
  pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch((cause) => {
    const message = String(cause?.message ?? "");
    const code = /^RELEASE_PREPARE_[A-Z0-9_]{1,100}$/u.test(message)
      ? message
      : "RELEASE_PREPARE_UNKNOWN_HOLD";
    process.stderr.write(`HOLD:${code}\n`);
    process.exitCode = 1;
  });
}

export const __test = Object.freeze({
  createSealedPrepareReader,
  dispatcherOutcome,
  exactJsonFile,
  readbackPermit,
  temporaryOutputRoot,
  writeLookupOutput
});
