import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const CONTROLLER = "infra/systemd/prooftoact-integrated-live-drill@.service";
const STAGE_VERIFY =
  "infra/systemd/prooftoact-integrated-live-drill-stage-verify@.service";
const RESUME =
  "infra/systemd/prooftoact-integrated-live-drill-resume@.service";
const BROKER =
  "infra/systemd/prooftoact-integrated-live-drill-dispatch-broker@.service";
const EXECUTOR =
  "infra/systemd/prooftoact-integrated-live-drill-executor@.service";
const PROVIDER_OPERATION =
  "infra/systemd/prooftoact-integrated-live-drill-provider-operation@.service";
const PROVIDER_OPERATION_SOCKET =
  "infra/systemd/prooftoact-integrated-live-drill-provider-operation@.socket";
const PROVIDER_ACTIVATION =
  "infra/systemd/prooftoact-integrated-live-drill-provider-activation@.service";
const PROVIDER_ACTIVATION_SOCKET =
  "infra/systemd/prooftoact-integrated-live-drill-provider-activation@.socket";
const PROVIDER_CALLBACK_SOCKET =
  "infra/systemd/prooftoact-integrated-live-drill-provider-callback@.socket";
const PROVIDER_EXCHANGE =
  "infra/systemd/prooftoact-integrated-live-drill-provider-exchange@.service";
const PROVIDER_TERMINALIZER =
  "infra/systemd/prooftoact-integrated-live-drill-provider-terminalizer@.service";
const PROVIDER_TERMINALIZER_TIMER =
  "infra/systemd/prooftoact-integrated-live-drill-provider-terminalizer@.timer";
const RECONCILE =
  "infra/systemd/prooftoact-integrated-live-drill-reconcile@.service";
const EXACT_UNSET_ENVIRONMENT =
  "UnsetEnvironment=NODE_OPTIONS NODE_PATH NODE_EXTRA_CA_CERTS NODE_ICU_DATA ICU_DATA OPENSSL_CONF OPENSSL_MODULES SSL_CERT_FILE SSL_CERT_DIR SSLKEYLOGFILE CURL_CA_BUNDLE REQUESTS_CA_BUNDLE HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy TZDIR MALLOC_CONF MALLOC_OPTIONS ASAN_OPTIONS LSAN_OPTIONS MSAN_OPTIONS TSAN_OPTIONS UBSAN_OPTIONS LD_PRELOAD LD_AUDIT LD_LIBRARY_PATH DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH DYLD_FRAMEWORK_PATH GLIBC_TUNABLES GCONV_PATH PERL5OPT PERL5LIB PERLLIB";
const EXACT_UNSET_CAPABILITIES =
  "UnsetEnvironment=MCP_API_KEY OPENAI_API_KEY DATABASE_URL AUTHORIZER_DATABASE_URL DISPATCH_DATABASE_URL RECOVERY_DATABASE_URL PRIMARY_AUDIT_DATABASE_URL PRIMARY_RECOVERY_SOURCE_DATABASE_URL RECOVERY_PUBLISHER_DATABASE_URL RECOVERY_PUBLISHER_PRIVATE_KEY_PKCS8_BASE64 RECOVERY_PUBLISHER_PASSWORD TIDEPROOF_AUDITOR_DATABASE_URL TIDEPROOF_INTEGRATED_LIVE_DRILL_CHILD_LAUNCH_PRIVATE_KEY_PKCS8_BASE64 PRIMARY_PROVIDER_CLAIM_DATABASE_URL PRIMARY_PROVIDER_BEGIN_DATABASE_URL PRIMARY_PROVIDER_REDEEM_DATABASE_URL PRIMARY_PROVIDER_FINALIZE_DATABASE_URL PRIMARY_PROVIDER_RECONCILE_DATABASE_URL PRIMARY_PROVIDER_ACTIVATE_DATABASE_URL PRIMARY_PROVIDER_TERMINALIZE_DATABASE_URL PGPASSWORD PGPASSFILE PGSERVICE PGSERVICEFILE AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_WEB_IDENTITY_TOKEN_FILE AWS_CONTAINER_AUTHORIZATION_TOKEN AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE";

function reject(code, detail = null) {
  throw new Error(detail === null ? code : `${code}:${detail}`);
}

function readUnit(relativePath) {
  const filePath = path.join(ROOT, relativePath);
  const stat = fs.lstatSync(filePath);
  if (
    !stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 ||
    fs.realpathSync(filePath) !== filePath
  ) {
    reject("INTEGRATED_LIVE_DRILL_SYSTEMD_BOUNDARY_REJECTED");
  }
  return fs.readFileSync(filePath, "utf8");
}

function requireMarkers(source, markers) {
  for (const marker of markers) {
    if (!source.includes(marker)) {
      reject("INTEGRATED_LIVE_DRILL_SYSTEMD_BOUNDARY_REJECTED", marker);
    }
  }
}

export function verifyIntegratedLiveDrillSystemdBoundary() {
  const controller = readUnit(CONTROLLER);
  const stageVerify = readUnit(STAGE_VERIFY);
  const resume = readUnit(RESUME);
  const broker = readUnit(BROKER);
  const executor = readUnit(EXECUTOR);
  const providerOperation = readUnit(PROVIDER_OPERATION);
  const providerOperationSocket = readUnit(PROVIDER_OPERATION_SOCKET);
  const providerActivation = readUnit(PROVIDER_ACTIVATION);
  const providerActivationSocket = readUnit(PROVIDER_ACTIVATION_SOCKET);
  const providerCallbackSocket = readUnit(PROVIDER_CALLBACK_SOCKET);
  const providerExchange = readUnit(PROVIDER_EXCHANGE);
  const providerTerminalizer = readUnit(PROVIDER_TERMINALIZER);
  const providerTerminalizerTimer = readUnit(PROVIDER_TERMINALIZER_TIMER);
  const reconcile = readUnit(RECONCILE);
  if (
    !controller.includes(
      "Requires=prooftoact-integrated-live-drill-stage-verify@%i.service"
    ) ||
    [resume, broker, executor, providerOperation, providerOperationSocket,
      reconcile]
      .some((source) => source.includes("stage-verify@%i.service"))
  ) {
    reject("INTEGRATED_LIVE_DRILL_SYSTEMD_BOUNDARY_REJECTED");
  }
  requireMarkers(controller, [
    "User=prooftoact",
    "Environment=LANG=C.UTF-8",
    "Environment=LC_ALL=C.UTF-8",
    "Environment=PATH=/usr/bin:/bin",
    EXACT_UNSET_ENVIRONMENT,
    EXACT_UNSET_CAPABILITIES,
    "Requires=prooftoact-integrated-live-drill-stage-verify@%i.service",
    "After=prooftoact-integrated-live-drill-stage-verify@%i.service",
    "Environment=TIDEPROOF_INTEGRATED_LIVE_DRILL_SYSTEMD_BOUNDARY=prepare-v1",
    "Environment=TIDEPROOF_INTEGRATED_LIVE_DRILL_SYSTEMD_INSTANCE=%i",
    "LoadCredential=orchestrator-input:/etc/prooftoact/runs/%i/preparation-input.json",
    "ExecStart=/usr/bin/perl /opt/prooftoact/runtime/runs/%i/verified-node-bundle-launcher.pl orchestrator",
    "SuccessExitStatus=3",
    "RemainAfterExit=yes",
    "NoNewPrivileges=yes",
    "ProtectSystem=strict",
    "CapabilityBoundingSet=",
    "AmbientCapabilities="
  ]);
  requireMarkers(stageVerify, [
    "User=prooftoact",
    EXACT_UNSET_ENVIRONMENT,
    EXACT_UNSET_CAPABILITIES,
    "LoadCredential=accepted-build-receipt-sha256:/etc/prooftoact/runs/%i/accepted-build-receipt-sha256",
    "ExecStart=/opt/prooftoact/verifiers/%i/node /opt/prooftoact/verifiers/%i/verify-integrated-live-drill-stage.js",
    "--build-root /opt/prooftoact/builds/%i",
    "--build-receipt /opt/prooftoact/builds/%i/gate2-build-receipt.json",
    "--expected-build-receipt-sha256-path ${CREDENTIALS_DIRECTORY}/accepted-build-receipt-sha256",
    "--expected-stage-root /opt/prooftoact/runtime/runs/%i",
    "--unit-root /etc/systemd/system",
    "--verifier-root /opt/prooftoact/verifiers/%i",
    "RestrictAddressFamilies=AF_UNIX",
    "RemainAfterExit=yes",
    "NoNewPrivileges=yes",
    "ProtectSystem=strict",
    "CapabilityBoundingSet=",
    "AmbientCapabilities="
  ]);
  requireMarkers(resume, [
    "User=prooftoact",
    EXACT_UNSET_ENVIRONMENT,
    EXACT_UNSET_CAPABILITIES,
    "Requires=prooftoact-integrated-live-drill@%i.service",
    "After=prooftoact-integrated-live-drill@%i.service",
    "Environment=TIDEPROOF_INTEGRATED_LIVE_DRILL_SYSTEMD_BOUNDARY=resume-v1",
    "Environment=TIDEPROOF_INTEGRATED_LIVE_DRILL_SYSTEMD_INSTANCE=%i",
    "LoadCredential=orchestrator-input:/etc/prooftoact/runs/%i/resume-input.json",
    "ExecStart=/usr/bin/perl /opt/prooftoact/runtime/runs/%i/verified-node-bundle-launcher.pl orchestrator",
    "SuccessExitStatus=3",
    "RemainAfterExit=yes",
    "NoNewPrivileges=yes",
    "ProtectSystem=strict",
    "CapabilityBoundingSet=",
    "AmbientCapabilities="
  ]);
  requireMarkers(broker, [
    "User=prooftoact-broker",
    EXACT_UNSET_ENVIRONMENT,
    EXACT_UNSET_CAPABILITIES,
    "Requires=prooftoact-integrated-live-drill-resume@%i.service",
    "After=prooftoact-integrated-live-drill-resume@%i.service",
    "LoadCredential=dispatch-request:/var/lib/prooftoact/evidence/%i/root/dispatch-request.json",
    "LoadCredential=provider-claim-database-url:/etc/prooftoact/runs/%i/provider-claim-database-url",
    "LoadCredential=provider-begin-database-url:/etc/prooftoact/runs/%i/provider-begin-database-url",
    "Environment=TIDEPROOF_INTEGRATED_LIVE_DRILL_EXECUTION_GRANT_ROOT=/var/lib/prooftoact/executions/%i",
    "Environment=TIDEPROOF_INTEGRATED_LIVE_DRILL_RECONCILIATION_INPUT_ROOT=/var/lib/prooftoact/reconciliation-inputs/%i",
    "ExecStart=/usr/bin/perl /opt/prooftoact/runtime/runs/%i/verified-node-bundle-launcher.pl dispatch-broker",
    "RemainAfterExit=yes",
    "NoNewPrivileges=yes",
    "ProtectSystem=strict",
    "CapabilityBoundingSet=",
    "AmbientCapabilities="
  ]);
  requireMarkers(executor, [
    "User=prooftoact",
    EXACT_UNSET_ENVIRONMENT,
    EXACT_UNSET_CAPABILITIES,
    "Requires=prooftoact-integrated-live-drill-dispatch-broker@%i.service",
    "Requires=prooftoact-integrated-live-drill-provider-operation@%i.socket",
    "LoadCredential=provider-worker-input:/var/lib/prooftoact/executions/%i/provider-worker-input.json",
    "LoadCredential=operation-nonce:/var/lib/prooftoact/dispatch-broker/%i/operation-nonce",
    "LoadCredential=provider-operation-socket:/etc/prooftoact/runs/%i/provider-operation-socket",
    "LoadCredential=recovery-audit-database-url:/etc/prooftoact/runs/%i/recovery-audit-database-url",
    "Environment=TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_ROOT=/var/lib/prooftoact/evidence/%i/root",
    "ExecStart=/usr/bin/perl /opt/prooftoact/runtime/runs/%i/verified-node-bundle-launcher.pl worker",
    "RemainAfterExit=yes",
    "NoNewPrivileges=yes",
    "ProtectSystem=strict",
    "RestrictAddressFamilies=AF_UNIX",
    "CapabilityBoundingSet=",
    "AmbientCapabilities="
  ]);
  requireMarkers(providerOperation, [
    "User=prooftoact-operation",
    EXACT_UNSET_ENVIRONMENT,
    EXACT_UNSET_CAPABILITIES,
    "UnsetEnvironment=NODE_DEBUG NODE_TLS_REJECT_UNAUTHORIZED",
    "Requires=prooftoact-integrated-live-drill-dispatch-broker@%i.service",
    "LoadCredential=execution-capability:/var/lib/prooftoact/dispatch-broker/%i/execution-capability.json",
    "LoadCredential=provider-execution-attempt:/var/lib/prooftoact/evidence/%i/root/provider-execution-attempt.json",
    "LoadCredential=provider-redeem-database-url:/etc/prooftoact/runs/%i/provider-redeem-database-url",
    "LoadCredential=provider-finalize-database-url:/etc/prooftoact/runs/%i/provider-finalize-database-url",
    "InaccessiblePaths=/etc/prooftoact/runs/%i",
    "ExecStart=/usr/bin/perl /opt/prooftoact/runtime/runs/%i/verified-node-bundle-launcher.pl provider-operation",
    "NoNewPrivileges=yes",
    "ProtectSystem=strict",
    "CapabilityBoundingSet=",
    "AmbientCapabilities="
  ]);
  requireMarkers(providerOperationSocket, [
    "ListenStream=/run/prooftoact/%i/provider-operation.sock",
    "SocketUser=prooftoact",
    "SocketGroup=prooftoact",
    "SocketMode=0600",
    "Service=prooftoact-integrated-live-drill-provider-operation@%i.service"
  ]);
  requireMarkers(providerActivation, [
    "User=prooftoact-activate", "RefuseManualStart=yes",
    "OnSuccess=prooftoact-integrated-live-drill-provider-exchange@%i.service",
    "UnsetEnvironment=NODE_DEBUG NODE_TLS_REJECT_UNAUTHORIZED",
    "LoadCredential=provider-activate-database-url:/etc/prooftoact/runs/%i/provider-activate-database-url",
    "LoadCredential=provider-reconciliation-input:/var/lib/prooftoact/reconciliation-inputs/%i/provider-reconciliation-input.json",
    "InaccessiblePaths=/etc/prooftoact/runs/%i",
    "ExecStart=/usr/bin/perl /opt/prooftoact/runtime/runs/%i/verified-node-bundle-launcher.pl provider-activation"
  ]);
  requireMarkers(providerActivationSocket, [
    "ListenStream=/run/prooftoact/%i/provider-activation.sock",
    "FileDescriptorName=activation", "SocketUser=prooftoact-operation",
    "SocketGroup=prooftoact-operation", "SocketMode=0600",
    "Service=prooftoact-integrated-live-drill-provider-activation@%i.service"
  ]);
  requireMarkers(providerCallbackSocket, [
    "ListenStream=/run/prooftoact/%i/provider-callback.sock",
    "FileDescriptorName=provider-callback", "SocketUser=prooftoact-provider",
    "SocketGroup=prooftoact-provider", "SocketMode=0600",
    "Service=prooftoact-integrated-live-drill-provider-operation@%i.service"
  ]);
  requireMarkers(providerExchange, [
    "User=prooftoact-provider", "RefuseManualStart=yes",
    "UnsetEnvironment=NODE_DEBUG NODE_TLS_REJECT_UNAUTHORIZED",
    "LoadCredential=mcp-api-key:/etc/prooftoact/runs/%i/mcp-api-key",
    "LoadCredential=provider-exchange-input:/var/lib/prooftoact/provider-activations/%i/provider-exchange-input.json",
    "Environment=TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_EXCHANGE_ROOT=/var/lib/prooftoact/provider-exchanges/%i",
    "InaccessiblePaths=/etc/prooftoact/runs/%i",
    "ExecStart=/usr/bin/perl /opt/prooftoact/runtime/runs/%i/verified-node-bundle-launcher.pl provider-exchange"
  ]);
  requireMarkers(providerTerminalizer, [
    "User=prooftoact-terminalize", "RefuseManualStart=yes",
    "UnsetEnvironment=NODE_DEBUG NODE_TLS_REJECT_UNAUTHORIZED",
    "LoadCredential=provider-terminalize-database-url:/etc/prooftoact/runs/%i/provider-terminalize-database-url",
    "InaccessiblePaths=/etc/prooftoact/runs/%i",
    "ExecStart=/usr/bin/perl /opt/prooftoact/runtime/runs/%i/verified-node-bundle-launcher.pl provider-terminalizer"
  ]);
  requireMarkers(providerTerminalizerTimer, [
    "OnUnitInactiveSec=60s", "AccuracySec=1s",
    "Unit=prooftoact-integrated-live-drill-provider-terminalizer@%i.service",
    "Persistent=no"
  ]);
  requireMarkers(reconcile, [
    "User=prooftoact-reconcile",
    EXACT_UNSET_ENVIRONMENT,
    EXACT_UNSET_CAPABILITIES,
    "LoadCredential=provider-reconciliation-input:/var/lib/prooftoact/reconciliation-inputs/%i/provider-reconciliation-input.json",
    "LoadCredential=provider-reconcile-database-url:/etc/prooftoact/runs/%i/provider-reconcile-database-url",
    "InaccessiblePaths=/var/lib/prooftoact/evidence /var/lib/prooftoact/executions /var/lib/prooftoact/dispatch-broker /var/lib/prooftoact/provider-operations /var/lib/prooftoact/reconciliation-inputs",
    "ExecStart=/usr/bin/perl /opt/prooftoact/runtime/runs/%i/verified-node-bundle-launcher.pl reconciler",
    "NoNewPrivileges=yes",
    "ProtectSystem=strict",
    "CapabilityBoundingSet=",
    "AmbientCapabilities="
  ]);
  for (const [name, source] of [
    ["stage-verify", stageVerify],
    ["controller", controller],
    ["resume", resume],
    ["broker", broker],
    ["executor", executor],
    ["provider-operation", providerOperation],
    ["provider-operation-socket", providerOperationSocket],
    ["provider-activation", providerActivation],
    ["provider-activation-socket", providerActivationSocket],
    ["provider-callback-socket", providerCallbackSocket],
    ["provider-exchange", providerExchange],
    ["provider-terminalizer", providerTerminalizer],
    ["provider-terminalizer-timer", providerTerminalizerTimer],
    ["reconcile", reconcile]
  ]) {
    for (const forbidden of [
      "EnvironmentFile=",
      "PassEnvironment=",
      "/bin/sh",
      "/usr/bin/env",
      "MCP_API_KEY=",
      "MemoryDenyWriteExecute=yes",
      "ConditionPathExists=",
      "--jitless",
      "PermissionsStartOnly=",
      "User=root"
    ]) {
      if (source.includes(forbidden)) {
        reject(`INTEGRATED_LIVE_DRILL_SYSTEMD_BOUNDARY_REJECTED:${name}`);
      }
    }
  }
  if (
    stageVerify.includes("LoadCredential=mcp-api-key") ||
    controller.includes("PROVIDER_CREDENTIAL_FILE") ||
    resume.includes("mcp-api-key") ||
    broker.includes("mcp-api-key") ||
    broker.includes("LoadCredential=mcp-api-key") ||
    providerOperation.includes("LoadCredential=mcp-api-key") ||
    providerOperation.includes("provider-activate-database-url") ||
    providerOperation.includes("provider-terminalize-database-url") ||
    providerActivation.includes("LoadCredential=mcp-api-key") ||
    providerActivation.includes("provider-redeem-database-url") ||
    providerActivation.includes("provider-finalize-database-url") ||
    providerExchange.includes("database-url") ||
    providerTerminalizer.includes("LoadCredential=mcp-api-key") ||
    providerTerminalizer.includes("provider-activate-database-url") ||
    executor.includes("mcp-api-key") ||
    executor.includes("execution-capability") ||
    executor.includes("provider-finalize-database-url") ||
    reconcile.includes("mcp-api-key") ||
    reconcile.includes("provider-claim-database-url") ||
    reconcile.includes("provider-begin-database-url") ||
    reconcile.includes("provider-redeem-database-url") ||
    reconcile.includes("provider-finalize-database-url") ||
    reconcile.includes("/var/lib/prooftoact/evidence/") ||
    reconcile.includes("execution-grant.json") ||
    reconcile.includes("provider-worker-input.json")
  ) {
    reject("INTEGRATED_LIVE_DRILL_SYSTEMD_BOUNDARY_REJECTED");
  }
  return Object.freeze({
    schemaVersion: "tideproof.integrated-live-drill-systemd-boundary.v1",
    status: "PASS",
    controllerProviderCredentialPresent: false,
    brokerProviderCredentialPresent: false,
    executorCredentialDelivery: "ONE_SHOT_UNIX_SOCKET_NONCE_AFTER_GLOBAL_GRANT",
    livePlatform: "linux-systemd",
    units: Object.freeze([
      STAGE_VERIFY,
      CONTROLLER,
      RESUME,
      BROKER,
      PROVIDER_OPERATION_SOCKET,
      PROVIDER_OPERATION,
      PROVIDER_ACTIVATION_SOCKET,
      PROVIDER_ACTIVATION,
      PROVIDER_CALLBACK_SOCKET,
      PROVIDER_EXCHANGE,
      PROVIDER_TERMINALIZER,
      PROVIDER_TERMINALIZER_TIMER,
      EXECUTOR,
      RECONCILE
    ])
  });
}

const startedDirectly =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (startedDirectly) {
  try {
    if (process.argv.length !== 2) {
      reject("INTEGRATED_LIVE_DRILL_SYSTEMD_BOUNDARY_ARGUMENTS");
    }
    process.stdout.write(
      `${JSON.stringify(verifyIntegratedLiveDrillSystemdBoundary())}\n`
    );
  } catch (error) {
    process.stderr.write(`${String(error?.message ?? error)}\n`);
    process.exitCode = 1;
  }
}
