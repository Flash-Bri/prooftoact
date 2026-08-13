import {
  PROVIDER_DISPATCH_HEX_64,
  PROVIDER_DISPATCH_UUID,
  validateProviderDispatchControlBinding
} from "./provider-dispatch-binding.js";
import {
  ProviderDispatchDatabaseClient,
  validateProviderDispatchResult
} from "./provider-dispatch-client.js";

const OUTCOMES = Object.freeze([
  "ALREADY_TERMINAL_OR_EXECUTING",
  "AUTHORITY_NOT_CURRENT",
  "DISPATCH_GRANTED"
]);

function reject(code) { throw new Error(code); }

export class ProviderDispatchClaimControl {
  #database;

  constructor(options = {}) {
    this.#database = new ProviderDispatchDatabaseClient({
      ...options,
      applicationName: "tideproof-provider-dispatch-claim"
    });
  }

  async claim(bindingInput, {
    executionCapabilitySha256,
    grantId,
    workerSpecSha256
  }) {
    const binding = validateProviderDispatchControlBinding(bindingInput);
    if (
      !PROVIDER_DISPATCH_UUID.test(grantId ?? "") ||
      !PROVIDER_DISPATCH_HEX_64.test(executionCapabilitySha256 ?? "") ||
      !PROVIDER_DISPATCH_HEX_64.test(workerSpecSha256 ?? "")
    ) reject("INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_CLAIM_REJECTED");
    const result = validateProviderDispatchResult(
      await this.#database.query({
        attempts: 3,
        sql: `
          SELECT *
          FROM tp_api.g1_claim_provider_dispatch_v2(
            $1::UUID, $2::UUID, $3::UUID, $4::UUID, $5::UUID,
            $6, $7, $8, $9, $10, $11, $12,
            $13::TIMESTAMPTZ, $14::TIMESTAMPTZ, $15, $16
          )
        `,
        params: [
          binding.authorizationId,
          grantId,
          binding.tenantId,
          binding.runId,
          binding.interactionId,
          binding.controlBindingSha256,
          binding.logicalMcpRequestSha256,
          binding.providerEffectKeySha256,
          binding.providerDispatchAuthorizationSha256,
          binding.sourceCommit,
          binding.treeDigest,
          binding.sourceBuildIdentity,
          binding.issuedAt,
          binding.expiresAt,
          executionCapabilitySha256,
          workerSpecSha256
        ]
      }),
      binding,
      { outcomes: OUTCOMES }
    );
    if (
      result.transitionOutcome === "DISPATCH_GRANTED" &&
      (result.grantId !== grantId || result.workerSpecSha256 !== workerSpecSha256)
    ) reject("INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_CLAIM_REJECTED");
    return result;
  }
}
