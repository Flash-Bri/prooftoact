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
  "ALREADY_REDEEMED_DO_NOT_DELIVER",
  "ALREADY_TERMINAL_DO_NOT_DELIVER",
  "AUTHORITY_NOT_CURRENT",
  "CREDENTIAL_REDEEMED"
]);

function reject(code) { throw new Error(code); }

export class ProviderDispatchRedeemControl {
  #database;

  constructor(options = {}) {
    this.#database = new ProviderDispatchDatabaseClient({
      ...options,
      applicationName: "tideproof-provider-dispatch-redeem"
    });
  }

  async redeem(bindingInput, {
    completionCapabilitySha256,
    executionCapability,
    grantId,
    workerSpecSha256
  }) {
    const binding = validateProviderDispatchControlBinding(bindingInput);
    if (
      !PROVIDER_DISPATCH_UUID.test(grantId ?? "") ||
      !PROVIDER_DISPATCH_HEX_64.test(executionCapability ?? "") ||
      !PROVIDER_DISPATCH_HEX_64.test(completionCapabilitySha256 ?? "") ||
      !PROVIDER_DISPATCH_HEX_64.test(workerSpecSha256 ?? "")
    ) reject("INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_REDEEM_REJECTED");
    const result = validateProviderDispatchResult(
      await this.#database.query({
        attempts: 1,
        sql: `
          SELECT *
          FROM tp_api.g1_redeem_provider_dispatch_v2(
            $1::UUID, $2::UUID, $3, $4, $5, $6
          )
        `,
        params: [
          binding.authorizationId,
          grantId,
          binding.controlBindingSha256,
          executionCapability,
          completionCapabilitySha256,
          workerSpecSha256
        ]
      }),
      binding,
      { outcomes: OUTCOMES }
    );
    if (result.grantId !== grantId || result.workerSpecSha256 !== workerSpecSha256) {
      reject("INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_REDEEM_REJECTED");
    }
    return result;
  }
}
