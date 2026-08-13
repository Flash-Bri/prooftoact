import path from "node:path";
import { pathToFileURL } from "node:url";

import {
  runIntegratedLiveDrillProviderOperationBroker,
  serveIntegratedLiveDrillProviderOperationBroker
} from "../src/cloud/integrated-live-drill-provider-operation-broker.js";
import {
  PROVIDER_DISPATCH_HEX_64,
  PROVIDER_DISPATCH_UUID
} from "../src/cloud/provider-dispatch-binding.js";
import {
  integratedLiveDrillProviderAuthorityTimes,
  validateProviderExecutionAttempt
} from "../src/cloud/integrated-live-drill-provider-recovery.js";
import {
  validateIntegratedLiveDrillProviderWorkerInput
} from "../src/cloud/integrated-live-drill-provider-worker.js";
import {
  validateIntegratedLiveDrillProviderDispatchAuthorizationPure
} from "../src/cloud/integrated-live-drill-provider-evidence.js";
import {
  buildProviderDispatchControlBinding
} from "../src/cloud/provider-dispatch-binding.js";
import { ProviderDispatchFinalizeControl } from
  "../src/cloud/provider-dispatch-finalize-control.js";
import { ProviderDispatchRedeemControl } from
  "../src/cloud/provider-dispatch-redeem-control.js";
import {
  readSystemdCredential,
  readSystemdCredentialText
} from "../src/cloud/systemd-credential.js";

function requiredAbsolute(name) {
  const value = process.env[name];
  if (
    typeof value !== "string" || !path.isAbsolute(value) ||
    path.resolve(value) !== value || value.length > 4096
  ) throw new Error("INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_ENVIRONMENT_REJECTED");
  return value;
}

export async function main({ clientFactory = null, fetchImpl = globalThis.fetch } = {}) {
  const credentialsDirectory = requiredAbsolute("CREDENTIALS_DIRECTORY");
  const operationRootPath = requiredAbsolute(
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_ROOT"
  );
  const workerInput = validateIntegratedLiveDrillProviderWorkerInput(JSON.parse(
    readSystemdCredential({
      credentialsDirectory,
      maximumBytes: 8 * 1024 * 1024,
      name: "provider-worker-input"
    }).toString("utf8")
  ));
  const intent = workerInput.context.preCallIntent;
  const dispatch = validateIntegratedLiveDrillProviderDispatchAuthorizationPure(
    workerInput.context.providerDispatchAuthorization,
    {
      childAuthorizationIssuedAt:
        workerInput.context.preCallInputs.consumedChildAuthorization.attestation
          .payload.issuedAt,
      humanAuthorizationTrustRoot:
        workerInput.context.trustedRunContext.humanAuthorizationTrustRoot,
      intent,
      requireCurrent: false
    }
  );
  const authorityTimes = integratedLiveDrillProviderAuthorityTimes(
    workerInput.context,
    intent,
    dispatch,
    Date.parse(
      workerInput.context.preCallInputs.consumedChildAuthorization.attestation
        .payload.issuedAt
    )
  );
  const binding = buildProviderDispatchControlBinding({
    context: workerInput.context,
    dispatchAuthorizationSha256: dispatch.attestationSha256,
    earliestControllingExpiry: authorityTimes.earliestControllingExpiry,
    latestControllingIssuedAt: authorityTimes.latestControllingIssuedAt
  });
  if (
    binding.controlBindingSha256 !==
      workerInput.executionGrant.controlBindingSha256
  ) throw new Error("INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_BINDING_REJECTED");
  let executionAttempt;
  try {
    executionAttempt = JSON.parse(readSystemdCredential({
      credentialsDirectory,
      maximumBytes: 64 * 1024,
      name: "provider-execution-attempt"
    }).toString("utf8"));
    validateProviderExecutionAttempt(executionAttempt, {
      executionGrant: workerInput.executionGrant,
      intent,
      providerControlBinding: binding
    });
  } catch (cause) {
    throw new Error(
      "INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_ATTEMPT_REJECTED",
      { cause }
    );
  }
  let secret;
  try {
    secret = JSON.parse(readSystemdCredential({
      credentialsDirectory,
      maximumBytes: 256,
      name: "execution-capability"
    }).toString("utf8"));
  } catch (cause) {
    throw new Error(
      "INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_BINDING_REJECTED",
      { cause }
    );
  }
  if (
    !secret || typeof secret !== "object" || Array.isArray(secret) ||
    Object.keys(secret).sort().join("\n") !==
      ["executionCapability", "grantId"].sort().join("\n") ||
    !PROVIDER_DISPATCH_HEX_64.test(secret.executionCapability ?? "") ||
    !PROVIDER_DISPATCH_UUID.test(secret.grantId ?? "") ||
    secret.grantId !== workerInput.executionGrant.grantId
  ) {
    throw new Error("INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_BINDING_REJECTED");
  }
  const redeemControl = new ProviderDispatchRedeemControl({
    clientFactory,
    connectionString: readSystemdCredentialText({
      credentialsDirectory,
      name: "provider-redeem-database-url"
    })
  });
  const finalizeControl = new ProviderDispatchFinalizeControl({
    clientFactory,
    connectionString: readSystemdCredentialText({
      credentialsDirectory,
      name: "provider-finalize-database-url"
    })
  });
  const operation = (request) =>
    runIntegratedLiveDrillProviderOperationBroker({
      apiKey: readSystemdCredentialText({
        credentialsDirectory,
        maximumBytes: 8192,
        name: "mcp-api-key"
      }),
      executionCapability: secret.executionCapability,
      fetchImpl,
      finalizeControl,
      grantId: secret.grantId,
      request,
      rootPath: operationRootPath,
      redeemControl
    });
  return serveIntegratedLiveDrillProviderOperationBroker({
    listen: { fd: 3 },
    operation
  });
}

const startedDirectly = process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href;

if (startedDirectly) {
  main().catch((error) => {
    const code = /^INTEGRATED_LIVE_DRILL_[A-Z0-9_]{1,160}$/u.test(
      String(error?.message ?? "")
    ) ? error.message : "INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_UNKNOWN";
    process.stderr.write(`${code}\n`);
    process.exitCode = 1;
  });
}
