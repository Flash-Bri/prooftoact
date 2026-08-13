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
const RECONCILE =
  "infra/systemd/prooftoact-integrated-live-drill-reconcile@.service";
const EXACT_UNSET_ENVIRONMENT =
  "UnsetEnvironment=NODE_OPTIONS NODE_PATH NODE_EXTRA_CA_CERTS LD_PRELOAD LD_AUDIT LD_LIBRARY_PATH DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH DYLD_FRAMEWORK_PATH GLIBC_TUNABLES GCONV_PATH PERL5OPT PERL5LIB PERLLIB";
const EXACT_UNSET_CAPABILITIES =
  "UnsetEnvironment=MCP_API_KEY OPENAI_API_KEY DATABASE_URL AUTHORIZER_DATABASE_URL DISPATCH_DATABASE_URL RECOVERY_DATABASE_URL PRIMARY_AUDIT_DATABASE_URL PRIMARY_RECOVERY_SOURCE_DATABASE_URL RECOVERY_PUBLISHER_DATABASE_URL RECOVERY_PUBLISHER_PRIVATE_KEY_PKCS8_BASE64 RECOVERY_PUBLISHER_PASSWORD TIDEPROOF_AUDITOR_DATABASE_URL TIDEPROOF_INTEGRATED_LIVE_DRILL_CHILD_LAUNCH_PRIVATE_KEY_PKCS8_BASE64 PRIMARY_PROVIDER_CLAIM_DATABASE_URL PRIMARY_PROVIDER_BEGIN_DATABASE_URL PRIMARY_PROVIDER_REDEEM_DATABASE_URL PRIMARY_PROVIDER_FINALIZE_DATABASE_URL PRIMARY_PROVIDER_RECONCILE_DATABASE_URL PGPASSWORD PGPASSFILE PGSERVICE PGSERVICEFILE AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_WEB_IDENTITY_TOKEN_FILE AWS_CONTAINER_AUTHORIZATION_TOKEN AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE";

function reject(code) {
  throw new Error(code);
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
      reject("INTEGRATED_LIVE_DRILL_SYSTEMD_BOUNDARY_REJECTED");
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
    "ConditionPathExists=/etc/prooftoact/runs/%i/stage-receipt.json",
    "ConditionPathExists=/opt/prooftoact/builds/%i/gate2-build-receipt.json",
    "ConditionPathExists=/etc/prooftoact/runs/%i/accepted-build-receipt-sha256",
    "LoadCredential=accepted-build-receipt-sha256:/etc/prooftoact/runs/%i/accepted-build-receipt-sha256",
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
    "ConditionPathExists=/var/lib/prooftoact/evidence/%i/%i.provider-orchestration-preparation.json",
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
    "ConditionPathExists=/var/lib/prooftoact/evidence/%i/dispatch-request.json",
    "LoadCredential=dispatch-request:/var/lib/prooftoact/evidence/%i/dispatch-request.json",
    "LoadCredential=provider-claim-database-url:/etc/prooftoact/runs/%i/provider-claim-database-url",
    "LoadCredential=provider-begin-database-url:/etc/prooftoact/runs/%i/provider-begin-database-url",
    "Environment=TIDEPROOF_INTEGRATED_LIVE_DRILL_EXECUTION_GRANT_ROOT=/var/lib/prooftoact/executions/%i",
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
    "ConditionPathExists=/var/lib/prooftoact/executions/%i/execution-grant.json",
    "LoadCredential=provider-worker-input:/var/lib/prooftoact/executions/%i/provider-worker-input.json",
    "LoadCredential=operation-nonce:/var/lib/prooftoact/dispatch-broker/%i/operation-nonce",
    "LoadCredential=provider-operation-socket:/etc/prooftoact/runs/%i/provider-operation-socket",
    "LoadCredential=recovery-audit-database-url:/etc/prooftoact/runs/%i/recovery-audit-database-url",
    "Environment=TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_ROOT=/var/lib/prooftoact/evidence/%i",
    "ExecStart=/usr/bin/perl /opt/prooftoact/runtime/runs/%i/verified-node-bundle-launcher.pl worker",
    "RemainAfterExit=yes",
    "NoNewPrivileges=yes",
    "ProtectSystem=strict",
    "RestrictAddressFamilies=AF_UNIX",
    "CapabilityBoundingSet=",
    "AmbientCapabilities="
  ]);
  requireMarkers(providerOperation, [
    "User=prooftoact-provider",
    EXACT_UNSET_ENVIRONMENT,
    EXACT_UNSET_CAPABILITIES,
    "Requires=prooftoact-integrated-live-drill-dispatch-broker@%i.service",
    "ConditionPathExists=/var/lib/prooftoact/executions/%i/execution-grant.json",
    "LoadCredential=mcp-api-key:/etc/prooftoact/runs/%i/mcp-api-key",
    "LoadCredential=execution-capability:/var/lib/prooftoact/dispatch-broker/%i/execution-capability.json",
    "LoadCredential=provider-execution-attempt:/var/lib/prooftoact/evidence/%i/provider-execution-attempt.json",
    "LoadCredential=provider-redeem-database-url:/etc/prooftoact/runs/%i/provider-redeem-database-url",
    "LoadCredential=provider-finalize-database-url:/etc/prooftoact/runs/%i/provider-finalize-database-url",
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
  requireMarkers(reconcile, [
    "User=prooftoact-reconcile",
    EXACT_UNSET_ENVIRONMENT,
    EXACT_UNSET_CAPABILITIES,
    "ConditionPathExists=/var/lib/prooftoact/executions/%i/execution-grant.json",
    "LoadCredential=provider-reconciliation-input:/var/lib/prooftoact/executions/%i/provider-reconciliation-input.json",
    "LoadCredential=provider-reconcile-database-url:/etc/prooftoact/runs/%i/provider-reconcile-database-url",
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
    ["reconcile", reconcile]
  ]) {
    for (const forbidden of [
      "EnvironmentFile=",
      "PassEnvironment=",
      "/bin/sh",
      "/usr/bin/env",
      "MCP_API_KEY=",
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
    executor.includes("mcp-api-key") ||
    executor.includes("execution-capability") ||
    executor.includes("provider-finalize-database-url") ||
    reconcile.includes("mcp-api-key") ||
    reconcile.includes("provider-claim-database-url") ||
    reconcile.includes("provider-begin-database-url") ||
    reconcile.includes("provider-redeem-database-url") ||
    reconcile.includes("provider-finalize-database-url") ||
    !executor.includes("ConditionPathExists=")
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
