import { validateProviderDispatchControlBinding } from
  "./provider-dispatch-binding.js";
import {
  ProviderDispatchDatabaseClient,
  validateProviderDispatchResult
} from "./provider-dispatch-client.js";

export class ProviderDispatchResolver {
  #database;

  constructor(options = {}) {
    this.#database = new ProviderDispatchDatabaseClient({
      ...options,
      applicationName: "tideproof-provider-dispatch-resolve"
    });
  }

  async resolve(bindingInput) {
    const binding = validateProviderDispatchControlBinding(bindingInput);
    return validateProviderDispatchResult(
      await this.#database.query({
        attempts: 3,
        sql: `
          SELECT *
          FROM tp_api.g1_resolve_provider_dispatch_v2($1::UUID, $2)
        `,
        params: [binding.authorizationId, binding.controlBindingSha256]
      }),
      binding,
      { outcomes: ["RESOLVED", "RESOLVED_ABSENT"] }
    );
  }
}
