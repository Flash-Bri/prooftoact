import { validateProviderDispatchControlBinding } from
  "./provider-dispatch-binding.js";
import { validateProviderDispatchResult } from "./provider-dispatch-result.js";
import { ProviderDispatchResolveDatabase } from
  "./provider-dispatch-resolve-database.js";

export class ProviderDispatchResolver {
  #database;

  constructor(options = {}) {
    this.#database = new ProviderDispatchResolveDatabase(options);
  }

  async resolve(bindingInput) {
    const binding = validateProviderDispatchControlBinding(bindingInput);
    return validateProviderDispatchResult(
      await this.#database.query({
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
