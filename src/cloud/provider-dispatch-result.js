import {
  PROVIDER_DISPATCH_CONTROL_STATES,
  PROVIDER_DISPATCH_HEX_64,
  PROVIDER_DISPATCH_UUID,
  validateProviderDispatchControlBinding
} from "./provider-dispatch-binding.js";

const RESULT_KEYS = Object.freeze([
  "authorization_id",
  "control_binding_sha256",
  "database_now",
  "expires_at",
  "grant_id",
  "mcp_result_sha256",
  "session_close_sha256",
  "state",
  "transition_outcome",
  "worker_spec_sha256"
]);

function reject(code) {
  throw new Error(code);
}

function exactIso(value) {
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) ? parsed.toISOString() : null;
}

function exactRow(value) {
  return value && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).sort().join("\n") === [...RESULT_KEYS].sort().join("\n");
}

function optionalDigest(value) {
  return value === null || PROVIDER_DISPATCH_HEX_64.test(value ?? "");
}

export function validateProviderDispatchResult(
  result,
  bindingInput,
  { outcomes }
) {
  const binding = validateProviderDispatchControlBinding(bindingInput);
  const row = result?.rows?.[0];
  const databaseNow = exactIso(row?.database_now);
  const absent = row?.state === PROVIDER_DISPATCH_CONTROL_STATES.ABSENT;
  const expiresAt = row?.expires_at === null ? null : exactIso(row?.expires_at);
  const completed = row?.state === PROVIDER_DISPATCH_CONTROL_STATES.COMPLETED;
  if (
    result?.rowCount !== 1 || !exactRow(row) ||
    row.authorization_id !== binding.authorizationId ||
    row.control_binding_sha256 !== binding.controlBindingSha256 ||
    !Object.values(PROVIDER_DISPATCH_CONTROL_STATES).includes(row.state) ||
    !outcomes.includes(row.transition_outcome) || databaseNow === null ||
    !optionalDigest(row.mcp_result_sha256) ||
    !optionalDigest(row.session_close_sha256) ||
    (completed
      ? !PROVIDER_DISPATCH_HEX_64.test(row.mcp_result_sha256 ?? "") ||
        !PROVIDER_DISPATCH_HEX_64.test(row.session_close_sha256 ?? "")
      : row.mcp_result_sha256 !== null || row.session_close_sha256 !== null) ||
    (absent
      ? row.transition_outcome !== "RESOLVED_ABSENT"
      : row.transition_outcome === "RESOLVED_ABSENT") ||
    (absent
      ? row.grant_id !== null || expiresAt !== null ||
        row.worker_spec_sha256 !== null || row.mcp_result_sha256 !== null ||
        row.session_close_sha256 !== null
      : !PROVIDER_DISPATCH_UUID.test(row.grant_id ?? "") ||
        expiresAt !== binding.expiresAt ||
        !PROVIDER_DISPATCH_HEX_64.test(row.worker_spec_sha256 ?? ""))
  ) {
    reject("INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_RESULT_REJECTED");
  }
  return Object.freeze({
    authorizationId: row.authorization_id,
    controlBindingSha256: row.control_binding_sha256,
    databaseNow,
    expiresAt,
    grantId: row.grant_id,
    mcpResultSha256: row.mcp_result_sha256,
    sessionCloseSha256: row.session_close_sha256,
    state: row.state,
    transitionOutcome: row.transition_outcome,
    workerSpecSha256: row.worker_spec_sha256
  });
}
