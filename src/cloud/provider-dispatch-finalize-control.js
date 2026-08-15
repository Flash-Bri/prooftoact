import {
  PROVIDER_DISPATCH_HEX_64,
  PROVIDER_DISPATCH_UUID,
  validateProviderDispatchControlBinding
} from "./provider-dispatch-binding.js";
import {
  ProviderDispatchDatabaseClient,
  validateProviderDispatchResult
} from "./provider-dispatch-client.js";

function reject(code) { throw new Error(code); }

export class ProviderDispatchFinalizeControl {
  #database;

  constructor(options = {}) {
    this.#database = new ProviderDispatchDatabaseClient({
      ...options,
      applicationName: "tideproof-provider-dispatch-finalize"
    });
  }

  #grant(value) {
    if (
      !PROVIDER_DISPATCH_UUID.test(value?.grantId ?? "") ||
      !PROVIDER_DISPATCH_HEX_64.test(value?.completionCapability ?? "")
    ) reject("INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_FINALIZE_REJECTED");
    return value;
  }

  async complete(bindingInput, grantInput, terminal) {
    const binding = validateProviderDispatchControlBinding(bindingInput);
    const grant = this.#grant(grantInput);
    if (
      !PROVIDER_DISPATCH_HEX_64.test(terminal?.mcpResultSha256 ?? "") ||
      !PROVIDER_DISPATCH_HEX_64.test(terminal?.sessionCloseSha256 ?? "")
    ) reject("INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_FINALIZE_REJECTED");
    const result = validateProviderDispatchResult(
      await this.#database.query({
        attempts: 3,
        sql: `
          SELECT *
          FROM tp_api.g1_complete_provider_dispatch_v2(
            $1::UUID, $2::UUID, $3, $4, $5, $6
          )
        `,
        params: [
          binding.authorizationId,
          grant.grantId,
          binding.controlBindingSha256,
          grant.completionCapability,
          terminal.mcpResultSha256,
          terminal.sessionCloseSha256
        ]
      }),
      binding,
      { outcomes: ["COMPLETED"] }
    );
    if (result.grantId !== grant.grantId) {
      reject("INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_FINALIZE_REJECTED");
    }
    return result;
  }

  async markUnknown(bindingInput, grantInput) {
    const binding = validateProviderDispatchControlBinding(bindingInput);
    const grant = this.#grant(grantInput);
    const result = validateProviderDispatchResult(
      await this.#database.query({
        attempts: 3,
        sql: `
          SELECT *
          FROM tp_api.g1_mark_provider_dispatch_unknown_v2(
            $1::UUID, $2::UUID, $3, $4
          )
        `,
        params: [
          binding.authorizationId,
          grant.grantId,
          binding.controlBindingSha256,
          grant.completionCapability
        ]
      }),
      binding,
      { outcomes: ["UNKNOWN_RECORDED"] }
    );
    if (result.grantId !== grant.grantId) {
      reject("INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_FINALIZE_REJECTED");
    }
    return result;
  }
}
