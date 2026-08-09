#!/usr/bin/env bash

set -euo pipefail
set +x
umask 077

if (( $# != 0 )); then
  printf '%s\n' 'PROOFTOACT_AWS_OIDC_READ_ONLY_PREFLIGHT_FAILED:ARGUMENT' >&2
  exit 1
fi

oidc_response=""
oidc_token=""
oidc_header=""
oidc_payload=""
sts_response=""
region_status=""
quota_status=""
preflight_receipt=""
sanitized_receipt=""
passphrase_file=""
error_file=""
gnupg_home=""
encrypted_receipt="${RUNNER_TEMP:-}/aws-read-only-preflight-receipt.json.gpg"

cleanup_sensitive_files() {
  local original_status=$?
  local cleanup_failed=0
  trap - EXIT
  set +e
  unset \
    AWS_ACCESS_KEY_ID \
    AWS_SECRET_ACCESS_KEY \
    AWS_SESSION_TOKEN \
    AWS_EVIDENCE_EXPECTED_ACCOUNT_ID \
    AWS_EVIDENCE_EXPECTED_PREFLIGHT_PRINCIPAL_ARN \
    AWS_EVIDENCE_EXPECTED_PREFLIGHT_CALLER_ARN \
    AWS_EVIDENCE_EXPECTED_PREFLIGHT_CALLER_USER_ID \
    ACTIONS_ID_TOKEN_REQUEST_TOKEN \
    ACTIONS_ID_TOKEN_REQUEST_URL \
    RECEIPT_ENCRYPTION_PASSPHRASE
  if [[ -n "$gnupg_home" ]]; then
    if [[ "$gnupg_home" == "${RUNNER_TEMP:-}"/receipt-gnupg.?????? &&
          -d "$gnupg_home" && ! -L "$gnupg_home" ]]; then
      /usr/bin/gpgconf --homedir "$gnupg_home" --kill all \
        >/dev/null 2>&1 || cleanup_failed=1
      /usr/bin/rm -rf -- "$gnupg_home" \
        >/dev/null 2>&1 || cleanup_failed=1
      [[ ! -e "$gnupg_home" && ! -L "$gnupg_home" ]] || cleanup_failed=1
    else
      cleanup_failed=1
    fi
  fi
  for file in \
    "$oidc_response" \
    "$oidc_token" \
    "$oidc_header" \
    "$oidc_payload" \
    "$sts_response" \
    "$region_status" \
    "$quota_status" \
    "$preflight_receipt" \
    "$sanitized_receipt" \
    "$passphrase_file" \
    "$error_file"; do
    if [[ -n "$file" ]]; then
      /usr/bin/rm -f -- "$file" \
        >/dev/null 2>&1 || cleanup_failed=1
      [[ ! -e "$file" && ! -L "$file" ]] || cleanup_failed=1
    fi
  done
  if (( cleanup_failed != 0 )); then
    printf '%s\n' '::error::AWS_READ_ONLY_STAGE_SENSITIVE_CLEANUP' >&2
    if (( original_status == 0 )); then
      exit 1
    fi
  fi
  exit "$original_status"
}
trap cleanup_sensitive_files EXIT

fail_closed() {
  printf '%s\n' \
    'PROOFTOACT_AWS_OIDC_READ_ONLY_PREFLIGHT_FAILED:FAIL_CLOSED' >&2
  exit 1
}

fail_closed_stage() {
  local stage="${1:-}"
  case "$stage" in
    AWS_READ_ONLY_STAGE_RUNTIME_CONTEXT | \
      AWS_READ_ONLY_STAGE_INHERITED_ENVIRONMENT | \
      AWS_READ_ONLY_STAGE_ACCOUNT_AUTHORITY | \
      AWS_READ_ONLY_STAGE_OIDC_ENDPOINT | \
      AWS_READ_ONLY_STAGE_SOURCE_BINDING | \
      AWS_READ_ONLY_STAGE_NODE_DISCOVERY | \
      AWS_READ_ONLY_STAGE_NODE_PATH | \
      AWS_READ_ONLY_STAGE_NODE_OWNER | \
      AWS_READ_ONLY_STAGE_NODE_METADATA | \
      AWS_READ_ONLY_STAGE_NODE_INTEGRITY | \
      AWS_READ_ONLY_STAGE_NODE_VERSION | \
      AWS_READ_ONLY_STAGE_AWS_PATH | \
      AWS_READ_ONLY_STAGE_AWS_METADATA | \
      AWS_READ_ONLY_STAGE_GPG_METADATA | \
      AWS_READ_ONLY_STAGE_TEMPORARY_STATE | \
      AWS_READ_ONLY_STAGE_OIDC_REQUEST | \
      AWS_READ_ONLY_STAGE_OIDC_RECEIPT | \
      AWS_READ_ONLY_STAGE_OIDC_CLAIMS | \
      AWS_READ_ONLY_STAGE_STS_ASSUME_REQUEST | \
      AWS_READ_ONLY_STAGE_STS_ASSUME_RECEIPT | \
      AWS_READ_ONLY_STAGE_STS_ASSUME_FIELDS | \
      AWS_READ_ONLY_STAGE_REGION_REQUEST | \
      AWS_READ_ONLY_STAGE_REGION_RECEIPT | \
      AWS_READ_ONLY_STAGE_QUOTA_REQUEST | \
      AWS_READ_ONLY_STAGE_QUOTA_RECEIPT | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_01 | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_02 | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_03 | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_04 | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_05 | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_06 | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_07 | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_08 | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_09 | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_10 | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_11 | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_12 | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_13 | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_14 | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_15 | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_16 | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_17 | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_CHILD_ENVIRONMENT | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_SOURCE_CHECKOUT | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_EXPECTED_IDENTITY | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_CALL_INVENTORY | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_CALLER_RECEIPT | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_BOOTSTRAP_RECEIPT | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_BUDGET_RECEIPT | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_NOTIFICATION_RECEIPT | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_SUBSCRIBER_RECEIPT | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_COST_REQUEST_PREPARE | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_BUCKET_POLICY_RECEIPT | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_STACK_CENSUS_RECEIPT | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_SNAPSHOT_COMPLETE | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_SOURCE_IDENTITY | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_BOOTSTRAP | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_BUDGET | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_NOTIFICATIONS | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_STACK_ABSENCE | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_ARTIFACT_BUCKET | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_COST | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_EXPOSURE | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_MODEL | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_RECEIPT_ASSEMBLY | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_RECEIPT_OUTPUT | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_ARGUMENT | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_UNCLASSIFIED_CAUGHT | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_PROCESS_UNCAUGHT | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_TIMEOUT | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_EXECUTION | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_TERMINATED | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_PROCESS_UNCLASSIFIED | \
      AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_RECEIPT | \
      AWS_READ_ONLY_STAGE_SANITIZED_RECEIPT | \
      AWS_READ_ONLY_STAGE_PRIVACY_REDACTION | \
      AWS_READ_ONLY_STAGE_RECEIPT_ENCRYPTION_PREPARE | \
      AWS_READ_ONLY_STAGE_RECEIPT_ENCRYPTION | \
      AWS_READ_ONLY_STAGE_ENCRYPTED_RECEIPT | \
      AWS_READ_ONLY_STAGE_RECEIPT_ENCRYPTION_CLEANUP | \
      AWS_READ_ONLY_STAGE_SENSITIVE_CLEANUP) ;;
    *) fail_closed ;;
  esac
  printf '%s\n' "::error::${stage}" >&2
  exit 1
}

[[ "$(/usr/bin/id -u)" != "0" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_RUNTIME_CONTEXT
[[ "${GITHUB_ACTIONS:-}" == "true" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_RUNTIME_CONTEXT
[[ "${CI:-}" == "true" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_RUNTIME_CONTEXT
[[ "${RUNNER_OS:-}" == "Linux" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_RUNTIME_CONTEXT
[[ "${RUNNER_ENVIRONMENT:-}" == "github-hosted" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_RUNTIME_CONTEXT
[[ "${GITHUB_SERVER_URL:-}" == "https://github.com" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_RUNTIME_CONTEXT
[[ "${GITHUB_API_URL:-}" == "https://api.github.com" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_RUNTIME_CONTEXT
[[ "${GITHUB_REPOSITORY:-}" == "Flash-Bri/prooftoact" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_RUNTIME_CONTEXT
[[ "${GITHUB_REPOSITORY_ID:-}" == "1317716765" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_RUNTIME_CONTEXT
[[ "${GITHUB_REF:-}" == "refs/heads/main" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_RUNTIME_CONTEXT
[[ "${GITHUB_EVENT_NAME:-}" == "workflow_dispatch" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_RUNTIME_CONTEXT
[[ "${GITHUB_WORKFLOW:-}" == "AWS Read-Only OIDC Preflight" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_RUNTIME_CONTEXT
[[ "${GITHUB_WORKFLOW_REF:-}" == "Flash-Bri/prooftoact/.github/workflows/aws-oidc-read-only-preflight.yml@refs/heads/main" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_RUNTIME_CONTEXT
[[ "${GITHUB_JOB:-}" == "read-only-preflight" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_RUNTIME_CONTEXT
[[ "${EXPECTED_OFFICIAL_MAIN_COMMIT:-}" =~ ^[0-9a-f]{40}$ ]] || fail_closed_stage AWS_READ_ONLY_STAGE_RUNTIME_CONTEXT
[[ "${GITHUB_SHA:-}" == "$EXPECTED_OFFICIAL_MAIN_COMMIT" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_RUNTIME_CONTEXT
[[ "${PREFLIGHT_DIAGNOSTIC_ONLY:-}" == "true" || "${PREFLIGHT_DIAGNOSTIC_ONLY:-}" == "false" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_RUNTIME_CONTEXT
[[ -n "${GITHUB_WORKSPACE:-}" && -d "$GITHUB_WORKSPACE" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_RUNTIME_CONTEXT
[[ "${RUNNER_TEMP:-}" == /* && -d "$RUNNER_TEMP" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_RUNTIME_CONTEXT
for unsafe_name in \
  ALL_PROXY \
  AWS_CA_BUNDLE \
  AWS_CONFIG_FILE \
  AWS_CONTAINER_AUTHORIZATION_TOKEN \
  AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE \
  AWS_CONTAINER_CREDENTIALS_FULL_URI \
  AWS_CONTAINER_CREDENTIALS_RELATIVE_URI \
  AWS_DATA_PATH \
  AWS_DEFAULT_PROFILE \
  AWS_PROFILE \
  AWS_ROLE_ARN \
  AWS_ROLE_SESSION_NAME \
  AWS_SDK_LOAD_CONFIG \
  AWS_SHARED_CREDENTIALS_FILE \
  AWS_USE_DUALSTACK_ENDPOINT \
  AWS_USE_FIPS_ENDPOINT \
  AWS_WEB_IDENTITY_TOKEN_FILE \
  BOTO_CONFIG \
  CURL_CA_BUNDLE \
  GNUPGHOME \
  HTTPS_PROXY \
  HTTP_PROXY \
  NODE_DEBUG \
  NODE_TLS_REJECT_UNAUTHORIZED \
  NODE_V8_COVERAGE \
  NO_PROXY \
  REQUESTS_CA_BUNDLE \
  SSL_CERT_DIR \
  SSL_CERT_FILE; do
  [[ -z "${!unsafe_name:-}" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_INHERITED_ENVIRONMENT
done
while IFS= read -r unsafe_name; do
  [[ -z "${!unsafe_name:-}" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_INHERITED_ENVIRONMENT
done < <(compgen -A variable AWS_ENDPOINT_URL)
unset unsafe_name
[[ "${AWS_ACCOUNT_ID:-}" =~ ^[0-9]{12}$ ]] || fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_AUTHORITY
[[ "${AWS_APPROVED_ACCOUNT_ID_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] || fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_AUTHORITY
account_digest="$(printf '%s' "$AWS_ACCOUNT_ID" | /usr/bin/sha256sum)" || fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_AUTHORITY
account_digest="${account_digest%% *}"
[[ "$account_digest" == "$AWS_APPROVED_ACCOUNT_ID_SHA256" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_AUTHORITY
unset account_digest AWS_APPROVED_ACCOUNT_ID_SHA256
expected_role_arn="arn:aws:iam::${AWS_ACCOUNT_ID}:role/ProofToActReadOnlyPreflight"
[[ "${AWS_READ_ONLY_PREFLIGHT_ROLE_ARN:-}" == "$expected_role_arn" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_AUTHORITY
expected_caller_arn="arn:aws:sts::${AWS_ACCOUNT_ID}:assumed-role/ProofToActReadOnlyPreflight/read-only-preflight"
[[ "${RECEIPT_ENCRYPTION_PASSPHRASE:-}" =~ ^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$ ]] || fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_AUTHORITY
oidc_request_url="${ACTIONS_ID_TOKEN_REQUEST_URL:-}"
(( ${#oidc_request_url} >= 1 && ${#oidc_request_url} <= 2048 )) || fail_closed_stage AWS_READ_ONLY_STAGE_OIDC_ENDPOINT
oidc_request_url_pattern='^https://(pipelines|run-actions-[0-9]+-[a-z0-9]([a-z0-9-]*[a-z0-9])?)\.actions\.githubusercontent\.com/[^[:space:]?#]+\?[^[:space:]#]+$'
[[ "$oidc_request_url" =~ $oidc_request_url_pattern ]] || fail_closed_stage AWS_READ_ONLY_STAGE_OIDC_ENDPOINT
unset oidc_request_url_pattern
[[ -n "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_OIDC_ENDPOINT

git_environment=(
  /usr/bin/env -i
  HOME=/dev/null
  PATH=/usr/bin:/bin
  GIT_ATTR_NOSYSTEM=1
  GIT_CONFIG_GLOBAL=/dev/null
  GIT_CONFIG_NOSYSTEM=1
  GIT_NO_LAZY_FETCH=1
  GIT_NO_REPLACE_OBJECTS=1
  GIT_PAGER=cat
  GIT_TERMINAL_PROMPT=0
)
source_commit="$(
  "${git_environment[@]}" /usr/bin/git \
    -c core.hooksPath=/dev/null \
    -c credential.helper= \
    -c protocol.file.allow=never \
  -C "$GITHUB_WORKSPACE" rev-parse HEAD
)" || fail_closed_stage AWS_READ_ONLY_STAGE_SOURCE_BINDING
tree_digest="$(
  "${git_environment[@]}" /usr/bin/git \
    -c core.hooksPath=/dev/null \
    -c credential.helper= \
    -c protocol.file.allow=never \
  -C "$GITHUB_WORKSPACE" rev-parse 'HEAD^{tree}'
)" || fail_closed_stage AWS_READ_ONLY_STAGE_SOURCE_BINDING
source_status="$(
  "${git_environment[@]}" /usr/bin/git \
    -c core.hooksPath=/dev/null \
    -c credential.helper= \
    -c protocol.file.allow=never \
  -C "$GITHUB_WORKSPACE" status --porcelain=v1 --untracked-files=all
)" || fail_closed_stage AWS_READ_ONLY_STAGE_SOURCE_BINDING
[[ "$source_commit" == "$EXPECTED_OFFICIAL_MAIN_COMMIT" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_SOURCE_BINDING
[[ "$tree_digest" =~ ^[0-9a-f]{40}$ ]] || fail_closed_stage AWS_READ_ONLY_STAGE_SOURCE_BINDING
[[ -z "$source_status" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_SOURCE_BINDING
unset source_status

# GitHub's hosted image intentionally makes /opt writable. Bind Node by exact
# version and official binary digest, then retain the expected ephemeral owner,
# regular-file, numeric-mode, and executable checks without treating write bits
# as an integrity boundary.
node_candidate="$(command -v node)" || fail_closed_stage AWS_READ_ONLY_STAGE_NODE_DISCOVERY
[[ "$node_candidate" == /* && -x "$node_candidate" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_NODE_DISCOVERY
node_cli="$(/usr/bin/readlink -f -- "$node_candidate")" || fail_closed_stage AWS_READ_ONLY_STAGE_NODE_PATH
[[ "$node_cli" == "/opt/hostedtoolcache/node/22.23.1/x64/bin/node" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_NODE_PATH
node_metadata="$(/usr/bin/stat -Lc '%u:%a:%F' -- "$node_cli")" || fail_closed_stage AWS_READ_ONLY_STAGE_NODE_METADATA
IFS=':' read -r node_uid node_mode node_type <<<"$node_metadata"
runner_uid="$(/usr/bin/id -u)" || fail_closed_stage AWS_READ_ONLY_STAGE_NODE_OWNER
node_owner_allowed=false
if [[ "$node_uid" == "0" || "$node_uid" == "$runner_uid" ]]; then
  node_owner_allowed=true
elif [[ "$runner_uid" == "1001" && "$node_uid" == "1000" ]] && \
  ! /usr/bin/getent passwd 1000 >/dev/null; then
  node_owner_allowed=true
fi
[[ "$node_owner_allowed" == "true" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_NODE_OWNER
[[ "$node_mode" =~ ^[0-7]{3,4}$ && "$node_type" == "regular file" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_NODE_METADATA
node_mode_value=$((8#$node_mode))
(( (node_mode_value & 0111) != 0 )) || fail_closed_stage AWS_READ_ONLY_STAGE_NODE_METADATA
node_digest="$(/usr/bin/sha256sum "$node_cli")" || fail_closed_stage AWS_READ_ONLY_STAGE_NODE_INTEGRITY
node_digest="${node_digest%% *}"
[[ "$node_digest" == "93956de2e59480474a7b46571da1651180b1a050cdf32641ebec4ce6e478e068" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_NODE_INTEGRITY
[[ "$("$node_cli" --version)" == "v22.23.1" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_NODE_VERSION
unset node_candidate node_metadata node_uid node_mode node_type node_mode_value runner_uid node_owner_allowed node_digest

aws_candidate="/usr/local/bin/aws"
[[ -L "$aws_candidate" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_AWS_PATH
aws_cli="$(/usr/bin/readlink -f -- "$aws_candidate")" || fail_closed_stage AWS_READ_ONLY_STAGE_AWS_PATH
[[ "$aws_cli" =~ ^/usr/local/aws-cli/v2/[0-9]+\.[0-9]+\.[0-9]+/dist/aws$ ]] || fail_closed_stage AWS_READ_ONLY_STAGE_AWS_PATH
aws_metadata="$(/usr/bin/stat -Lc '%u:%a:%F' -- "$aws_cli")" || fail_closed_stage AWS_READ_ONLY_STAGE_AWS_METADATA
IFS=':' read -r aws_uid aws_mode aws_type <<<"$aws_metadata"
[[ "$aws_uid" == "0" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_AWS_METADATA
[[ "$aws_mode" =~ ^[0-7]{3,4}$ && "$aws_type" == "regular file" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_AWS_METADATA
aws_mode_value=$((8#$aws_mode))
(( (aws_mode_value & 0111) != 0 )) || fail_closed_stage AWS_READ_ONLY_STAGE_AWS_METADATA
(( (aws_mode_value & 0022) == 0 )) || fail_closed_stage AWS_READ_ONLY_STAGE_AWS_METADATA
unset aws_candidate aws_metadata aws_uid aws_mode aws_type aws_mode_value

for crypto_cli in /usr/bin/gpg /usr/bin/gpgconf; do
  crypto_metadata="$(/usr/bin/stat -Lc '%u:%a:%F' -- "$crypto_cli")" || fail_closed_stage AWS_READ_ONLY_STAGE_GPG_METADATA
  IFS=':' read -r crypto_uid crypto_mode crypto_type <<<"$crypto_metadata"
  [[ "$crypto_uid" == "0" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_GPG_METADATA
  [[ "$crypto_mode" =~ ^[0-7]{3,4}$ ]] || fail_closed_stage AWS_READ_ONLY_STAGE_GPG_METADATA
  [[ "$crypto_type" == "regular file" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_GPG_METADATA
  crypto_mode_value=$((8#$crypto_mode))
  (( (crypto_mode_value & 0111) != 0 )) || fail_closed_stage AWS_READ_ONLY_STAGE_GPG_METADATA
  (( (crypto_mode_value & 0022) == 0 )) || fail_closed_stage AWS_READ_ONLY_STAGE_GPG_METADATA
done
unset crypto_cli crypto_metadata crypto_uid crypto_mode crypto_type crypto_mode_value

oidc_response="$(/usr/bin/mktemp "${RUNNER_TEMP}/oidc-response.XXXXXX")" || fail_closed_stage AWS_READ_ONLY_STAGE_TEMPORARY_STATE
oidc_token="$(/usr/bin/mktemp "${RUNNER_TEMP}/oidc-token.XXXXXX")" || fail_closed_stage AWS_READ_ONLY_STAGE_TEMPORARY_STATE
oidc_header="$(/usr/bin/mktemp "${RUNNER_TEMP}/oidc-header.XXXXXX")" || fail_closed_stage AWS_READ_ONLY_STAGE_TEMPORARY_STATE
oidc_payload="$(/usr/bin/mktemp "${RUNNER_TEMP}/oidc-payload.XXXXXX")" || fail_closed_stage AWS_READ_ONLY_STAGE_TEMPORARY_STATE
sts_response="$(/usr/bin/mktemp "${RUNNER_TEMP}/sts-response.XXXXXX")" || fail_closed_stage AWS_READ_ONLY_STAGE_TEMPORARY_STATE
region_status="$(/usr/bin/mktemp "${RUNNER_TEMP}/region-status.XXXXXX")" || fail_closed_stage AWS_READ_ONLY_STAGE_TEMPORARY_STATE
quota_status="$(/usr/bin/mktemp "${RUNNER_TEMP}/quota-status.XXXXXX")" || fail_closed_stage AWS_READ_ONLY_STAGE_TEMPORARY_STATE
preflight_receipt="$(/usr/bin/mktemp "${RUNNER_TEMP}/preflight-receipt.XXXXXX")" || fail_closed_stage AWS_READ_ONLY_STAGE_TEMPORARY_STATE
sanitized_receipt="$(/usr/bin/mktemp "${RUNNER_TEMP}/sanitized-receipt.XXXXXX")" || fail_closed_stage AWS_READ_ONLY_STAGE_TEMPORARY_STATE
passphrase_file="$(/usr/bin/mktemp "${RUNNER_TEMP}/receipt-passphrase.XXXXXX")" || fail_closed_stage AWS_READ_ONLY_STAGE_TEMPORARY_STATE
error_file="$(/usr/bin/mktemp "${RUNNER_TEMP}/preflight-error.XXXXXX")" || fail_closed_stage AWS_READ_ONLY_STAGE_TEMPORARY_STATE
gnupg_home="$(/usr/bin/mktemp -d "${RUNNER_TEMP}/receipt-gnupg.XXXXXX")" || fail_closed_stage AWS_READ_ONLY_STAGE_TEMPORARY_STATE
[[ "$gnupg_home" == "${RUNNER_TEMP}"/receipt-gnupg.?????? ]] || fail_closed_stage AWS_READ_ONLY_STAGE_TEMPORARY_STATE
/usr/bin/chmod 600 \
  "$oidc_response" \
  "$oidc_token" \
  "$oidc_header" \
  "$oidc_payload" \
  "$sts_response" \
  "$region_status" \
  "$quota_status" \
  "$preflight_receipt" \
  "$sanitized_receipt" \
  "$passphrase_file" \
  "$error_file" || fail_closed_stage AWS_READ_ONLY_STAGE_TEMPORARY_STATE
/usr/bin/chmod 700 "$gnupg_home" || fail_closed_stage AWS_READ_ONLY_STAGE_TEMPORARY_STATE
[[ -d "$gnupg_home" && ! -L "$gnupg_home" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_TEMPORARY_STATE
gnupg_metadata="$(/usr/bin/stat -c '%u:%a:%F' -- "$gnupg_home")" || fail_closed_stage AWS_READ_ONLY_STAGE_TEMPORARY_STATE
IFS=':' read -r gnupg_uid gnupg_mode gnupg_type <<<"$gnupg_metadata"
[[ "$gnupg_uid" == "$(/usr/bin/id -u)" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_TEMPORARY_STATE
[[ "$gnupg_mode" == "700" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_TEMPORARY_STATE
[[ "$gnupg_type" == "directory" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_TEMPORARY_STATE
unset gnupg_metadata gnupg_uid gnupg_mode gnupg_type

if [[ "$PREFLIGHT_DIAGNOSTIC_ONLY" == "true" ]]; then
  printf '%s\n' '::notice::AWS_READ_ONLY_DIAGNOSTIC_PASS'
  exit 0
fi

oidc_url="${oidc_request_url}&audience=sts.amazonaws.com"
if ! /usr/bin/timeout --signal=KILL 30s \
  /usr/bin/curl \
    --disable \
    --proto '=https' \
    --tlsv1.2 \
    --connect-timeout 10 \
    --max-time 20 \
    --fail \
    --silent \
    --show-error \
    --header "Authorization: Bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
    "$oidc_url" >"$oidc_response" 2>"$error_file"; then
  fail_closed_stage AWS_READ_ONLY_STAGE_OIDC_REQUEST
fi
if ! /usr/bin/jq -e \
  'type == "object" and
   keys == ["value"] and
   (.value | type == "string" and
    test("^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$"))' \
  "$oidc_response" >/dev/null 2>"$error_file"; then
  fail_closed_stage AWS_READ_ONLY_STAGE_OIDC_RECEIPT
fi
if ! /usr/bin/jq -j '.value' "$oidc_response" \
  >"$oidc_token" 2>"$error_file"; then
  fail_closed_stage AWS_READ_ONLY_STAGE_OIDC_RECEIPT
fi
[[ -s "$oidc_token" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_OIDC_RECEIPT

token_value="$(<"$oidc_token")"
IFS='.' read -r jwt_header jwt_payload jwt_signature jwt_extra <<<"$token_value"
[[ -n "$jwt_header" && -n "$jwt_payload" && -n "$jwt_signature" && -z "$jwt_extra" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_OIDC_CLAIMS
decode_base64url() {
  local encoded="$1"
  local destination="$2"
  local normalized="${encoded//-/+}"
  normalized="${normalized//_/\/}"
  case $(( ${#normalized} % 4 )) in
    0) ;;
    2) normalized="${normalized}==" ;;
    3) normalized="${normalized}=" ;;
    *) return 1 ;;
  esac
  printf '%s' "$normalized" | /usr/bin/base64 --decode \
    >"$destination" 2>"$error_file"
}
decode_base64url "$jwt_header" "$oidc_header" || fail_closed_stage AWS_READ_ONLY_STAGE_OIDC_CLAIMS
decode_base64url "$jwt_payload" "$oidc_payload" || fail_closed_stage AWS_READ_ONLY_STAGE_OIDC_CLAIMS
unset token_value jwt_header jwt_payload jwt_signature jwt_extra
if ! /usr/bin/jq -e \
  'type == "object" and
   .alg == "RS256" and
   .typ == "JWT" and
   (.kid | type == "string" and length > 0)' \
  "$oidc_header" >/dev/null 2>"$error_file"; then
  fail_closed_stage AWS_READ_ONLY_STAGE_OIDC_CLAIMS
fi
oidc_now="$(/usr/bin/date +%s)" || fail_closed_stage AWS_READ_ONLY_STAGE_OIDC_CLAIMS
if ! /usr/bin/jq -e \
  --arg sha "$EXPECTED_OFFICIAL_MAIN_COMMIT" \
  --argjson now "$oidc_now" \
  'type == "object" and
   .iss == "https://token.actions.githubusercontent.com" and
   .aud == "sts.amazonaws.com" and
   .repository == "Flash-Bri/prooftoact" and
   .repository_id == "1317716765" and
   .repository_owner == "Flash-Bri" and
   .repository_owner_id == "252500266" and
   .ref == "refs/heads/main" and
   .ref_type == "branch" and
   .environment == "aws-read-only-preflight" and
   .sub == "repo:Flash-Bri@252500266/prooftoact@1317716765:environment:aws-read-only-preflight" and
   .workflow == "AWS Read-Only OIDC Preflight" and
   .workflow_ref == "Flash-Bri/prooftoact/.github/workflows/aws-oidc-read-only-preflight.yml@refs/heads/main" and
   .workflow_sha == $sha and
   .event_name == "workflow_dispatch" and
   .runner_environment == "github-hosted" and
   .sha == $sha and
   (.jti | type == "string" and length > 0) and
   (.iat | type == "number" and . >= ($now - 600) and . <= ($now + 60)) and
   (.nbf | type == "number" and . <= ($now + 60)) and
   (.exp | type == "number" and . > $now and . <= ($now + 600)) and
   (.exp > .iat)' \
  "$oidc_payload" >/dev/null 2>"$error_file"; then
  fail_closed_stage AWS_READ_ONLY_STAGE_OIDC_CLAIMS
fi
unset oidc_now

unset \
  AWS_ACCESS_KEY_ID \
  AWS_SECRET_ACCESS_KEY \
  AWS_SESSION_TOKEN \
  AWS_PROFILE \
  AWS_DEFAULT_PROFILE \
  AWS_ROLE_ARN \
  AWS_WEB_IDENTITY_TOKEN_FILE \
  NODE_DEBUG \
  NODE_OPTIONS \
  NODE_PATH \
  NODE_REPL_EXTERNAL_MODULE \
  NODE_V8_COVERAGE
export AWS_CONFIG_FILE=/dev/null
export AWS_SHARED_CREDENTIALS_FILE=/dev/null
export AWS_EC2_METADATA_DISABLED=true
export AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true
export AWS_MAX_ATTEMPTS=1
export AWS_PAGER=""
export AWS_REGION=us-east-1
export AWS_DEFAULT_REGION=us-east-1

if ! /usr/bin/timeout --signal=KILL 30s \
  "$aws_cli" sts assume-role-with-web-identity \
    --role-arn "$expected_role_arn" \
    --role-session-name read-only-preflight \
    --duration-seconds 900 \
    --web-identity-token "file://${oidc_token}" \
    --region us-east-1 \
    --output json \
    --cli-connect-timeout 10 \
    --cli-read-timeout 20 \
    --no-cli-pager \
    >"$sts_response" 2>"$error_file"; then
  fail_closed_stage AWS_READ_ONLY_STAGE_STS_ASSUME_REQUEST
fi
if ! /usr/bin/jq -e \
  --arg expected_arn "$expected_caller_arn" \
  'type == "object" and
   (.Credentials | type == "object") and
   (.Credentials.AccessKeyId |
    type == "string" and test("^ASIA[A-Z0-9]{16}$")) and
   (.Credentials.SecretAccessKey | type == "string" and length >= 16) and
   (.Credentials.SessionToken | type == "string" and length >= 16) and
   (.AssumedRoleUser.Arn == $expected_arn) and
   (.AssumedRoleUser.AssumedRoleId |
    type == "string" and
    test("^AROA[A-Z0-9]{12,124}:read-only-preflight$"))' \
  "$sts_response" >/dev/null 2>"$error_file"; then
  fail_closed_stage AWS_READ_ONLY_STAGE_STS_ASSUME_RECEIPT
fi

assumed_role_id="$(/usr/bin/jq -r '.AssumedRoleUser.AssumedRoleId' "$sts_response" 2>"$error_file")" || fail_closed_stage AWS_READ_ONLY_STAGE_STS_ASSUME_FIELDS
AWS_ACCESS_KEY_ID="$(/usr/bin/jq -r '.Credentials.AccessKeyId' "$sts_response" 2>"$error_file")" || fail_closed_stage AWS_READ_ONLY_STAGE_STS_ASSUME_FIELDS
AWS_SECRET_ACCESS_KEY="$(/usr/bin/jq -r '.Credentials.SecretAccessKey' "$sts_response" 2>"$error_file")" || fail_closed_stage AWS_READ_ONLY_STAGE_STS_ASSUME_FIELDS
AWS_SESSION_TOKEN="$(/usr/bin/jq -r '.Credentials.SessionToken' "$sts_response" 2>"$error_file")" || fail_closed_stage AWS_READ_ONLY_STAGE_STS_ASSUME_FIELDS
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
unset ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL oidc_request_url

if ! /usr/bin/timeout --signal=KILL 30s \
  "$aws_cli" account get-region-opt-status \
    --region-name us-east-1 \
    --region us-east-1 \
    --output json \
    --cli-connect-timeout 10 \
    --cli-read-timeout 20 \
    --no-cli-pager \
    >"$region_status" 2>"$error_file"; then
  fail_closed_stage AWS_READ_ONLY_STAGE_REGION_REQUEST
fi
if ! /usr/bin/jq -e \
  'type == "object" and
   (keys | sort) == ["RegionName", "RegionOptStatus"] and
   .RegionName == "us-east-1" and
   .RegionOptStatus == "ENABLED_BY_DEFAULT"' \
  "$region_status" >/dev/null 2>"$error_file"; then
  fail_closed_stage AWS_READ_ONLY_STAGE_REGION_RECEIPT
fi

if ! /usr/bin/timeout --signal=KILL 30s \
  "$aws_cli" service-quotas list-service-quotas \
    --service-code bedrock \
    --max-results 1 \
    --no-paginate \
    --region us-east-1 \
    --output json \
    --cli-connect-timeout 10 \
    --cli-read-timeout 20 \
    --no-cli-pager \
    >"$quota_status" 2>"$error_file"; then
  fail_closed_stage AWS_READ_ONLY_STAGE_QUOTA_REQUEST
fi
if ! /usr/bin/jq -e \
  'type == "object" and
   (.Quotas | type == "array" and length == 1) and
   (.Quotas[0].ServiceCode == "bedrock") and
   (.Quotas[0].QuotaCode |
    type == "string" and test("^L-[A-Z0-9]{8}$")) and
   (.Quotas[0].Value | type == "number" and . > 0)' \
  "$quota_status" >/dev/null 2>"$error_file"; then
  fail_closed_stage AWS_READ_ONLY_STAGE_QUOTA_RECEIPT
fi

export AWS_EVIDENCE_EXPECTED_ACCOUNT_ID="$AWS_ACCOUNT_ID"
export AWS_EVIDENCE_EXPECTED_PREFLIGHT_PRINCIPAL_ARN="$expected_role_arn"
export AWS_EVIDENCE_EXPECTED_PREFLIGHT_CALLER_ARN="$expected_caller_arn"
export AWS_EVIDENCE_EXPECTED_PREFLIGHT_CALLER_USER_ID="$assumed_role_id"

preflight_status=0
if /usr/bin/timeout --signal=KILL --kill-after=5s 180s \
  "$node_cli" "$GITHUB_WORKSPACE/scripts/gate2-aws-preflight.js" \
    >"$preflight_receipt" 2>"$error_file"; then
  :
else
  preflight_status="$?"
fi
case "$preflight_status" in
  0) ;;
  1) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_PROCESS_UNCAUGHT ;;
  40) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_01 ;;
  41) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_02 ;;
  42) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_03 ;;
  43) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_04 ;;
  44) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_05 ;;
  45) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_06 ;;
  46) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_07 ;;
  47) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_08 ;;
  48) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_09 ;;
  49) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_10 ;;
  50) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_11 ;;
  51) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_12 ;;
  52) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_13 ;;
  53) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_14 ;;
  54) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_15 ;;
  55) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_16 ;;
  56) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_17 ;;
  60) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_CHILD_ENVIRONMENT ;;
  61) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_SOURCE_CHECKOUT ;;
  62) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_EXPECTED_IDENTITY ;;
  63) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_CALL_INVENTORY ;;
  64) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_CALLER_RECEIPT ;;
  65) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_BOOTSTRAP_RECEIPT ;;
  66) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_BUDGET_RECEIPT ;;
  67) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_NOTIFICATION_RECEIPT ;;
  68) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_SUBSCRIBER_RECEIPT ;;
  69) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_COST_REQUEST_PREPARE ;;
  70) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_BUCKET_POLICY_RECEIPT ;;
  71) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_STACK_CENSUS_RECEIPT ;;
  72) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_SNAPSHOT_COMPLETE ;;
  73) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_SOURCE_IDENTITY ;;
  74) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_BOOTSTRAP ;;
  75) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_BUDGET ;;
  76) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_NOTIFICATIONS ;;
  77) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_STACK_ABSENCE ;;
  78) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_ARTIFACT_BUCKET ;;
  79) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_COST ;;
  80) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_EXPOSURE ;;
  81) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_MODEL ;;
  82) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_RECEIPT_ASSEMBLY ;;
  83) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_RECEIPT_OUTPUT ;;
  84) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_ARGUMENT ;;
  85) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_UNCLASSIFIED_CAUGHT ;;
  124) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_TIMEOUT ;;
  125 | 126 | 127) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_EXECUTION ;;
  137) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_TERMINATED ;;
  *) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_PROCESS_UNCLASSIFIED ;;
esac
if ! /usr/bin/jq -e \
  --arg source_commit "$source_commit" \
  --arg tree_digest "$tree_digest" \
  'type == "object" and
   .schemaVersion == "tideproof.gate2.aws-preflight.v6" and
   .status == "PASS" and
   .sourceCommit == $source_commit and
   .treeDigest == $tree_digest and
   .region == "us-east-1" and
   .controls.authenticatedAwsCaller == true and
   .controls.projectExposure.approvedPreflightAllowanceUsd == "0.020000" and
   (.controls.projectExposure.conservativeReservedAwsExposureUsd |
    type == "string" and test("^[0-9]+\\.[0-9]{6}$")) and
   (.controls.projectExposure.conservativeReservedTotalExposureUsd |
    type == "string" and test("^[0-9]+\\.[0-9]{6}$")) and
   (.controls.projectExposure.remainingExposureAfterPreflightAllowanceUsd |
    type == "string" and test("^[0-9]+\\.[0-9]{6}$")) and
   .controls.mainGateTwoStack.state == "ABSENT" and
   .controls.mainGateTwoStack.legacyState == "ABSENT" and
   (.privacy | type == "string" and length > 0) and
   (.claimBoundary | type == "string" and length > 0)' \
  "$preflight_receipt" >/dev/null 2>"$error_file"; then
  fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_RECEIPT
fi

if ! /usr/bin/jq -n \
  --slurpfile preflight "$preflight_receipt" \
  --arg source_commit "$source_commit" \
  --arg tree_digest "$tree_digest" \
  '{
    schemaVersion: "prooftoact.aws-oidc-read-only-preflight-receipt.v1",
    status: "PASS",
    sourceCommit: $source_commit,
    treeDigest: $tree_digest,
    repository: "Flash-Bri/prooftoact",
    ref: "refs/heads/main",
    environment: "aws-read-only-preflight",
    region: "us-east-1",
    sessionDurationSeconds: 900,
    checks: {
      exactOfficialMainCommit: true,
      protectedEnvironmentClaim: true,
      accountDigestMatched: true,
      nonRootRunner: true,
      temporaryAssumedRoleCredentials: true,
      regionEnabledByDefault: true,
      bedrockServiceQuotasReadable: true,
      readOnlyAccountSafetyPreflight: true
    },
    preflight: $preflight[0],
    privacy: "The AWS account, role and caller ARNs, STS principal ID, OIDC token, credentials, private bucket name, subscribers, and raw region/quota responses were validated but omitted.",
    claimBoundary: "This encrypted receipt can evidence one source-bound read-only provider observation only after private decryption and review. It cannot authorize or prove upload, mutation, deployment, model invocation, IAM denial, rollback, publication, submission, or final release readiness."
  }' >"$sanitized_receipt" 2>"$error_file"; then
  fail_closed_stage AWS_READ_ONLY_STAGE_SANITIZED_RECEIPT
fi
privacy_match=0
for forbidden_literal in \
  "$AWS_ACCOUNT_ID" \
  "$expected_role_arn" \
  "$expected_caller_arn" \
  "$assumed_role_id"; do
  if /usr/bin/grep -F -q -- "$forbidden_literal" "$sanitized_receipt" \
    2>"$error_file"; then
    privacy_match=1
  else
    grep_status=$?
    (( grep_status == 1 )) || fail_closed_stage AWS_READ_ONLY_STAGE_PRIVACY_REDACTION
  fi
done
if /usr/bin/grep -E -q -- \
  'AKIA[A-Z0-9]{16}|ASIA[A-Z0-9]{16}|arn:aws:(iam|sts|s3)' \
  "$sanitized_receipt" 2>"$error_file"; then
  privacy_match=1
else
  grep_status=$?
  (( grep_status == 1 )) || fail_closed_stage AWS_READ_ONLY_STAGE_PRIVACY_REDACTION
fi
(( privacy_match == 0 )) || fail_closed_stage AWS_READ_ONLY_STAGE_PRIVACY_REDACTION
unset forbidden_literal grep_status privacy_match

unset \
  AWS_ACCESS_KEY_ID \
  AWS_SECRET_ACCESS_KEY \
  AWS_SESSION_TOKEN \
  AWS_EVIDENCE_EXPECTED_ACCOUNT_ID \
  AWS_EVIDENCE_EXPECTED_PREFLIGHT_PRINCIPAL_ARN \
  AWS_EVIDENCE_EXPECTED_PREFLIGHT_CALLER_ARN \
  AWS_EVIDENCE_EXPECTED_PREFLIGHT_CALLER_USER_ID \
  assumed_role_id
printf '%s\n' "$RECEIPT_ENCRYPTION_PASSPHRASE" >"$passphrase_file" 2>"$error_file" || fail_closed_stage AWS_READ_ONLY_STAGE_RECEIPT_ENCRYPTION_PREPARE
unset RECEIPT_ENCRYPTION_PASSPHRASE
/usr/bin/rm -f -- "$encrypted_receipt" \
  2>"$error_file" || fail_closed_stage AWS_READ_ONLY_STAGE_RECEIPT_ENCRYPTION_PREPARE
if ! /usr/bin/timeout --signal=KILL 30s \
  /usr/bin/gpg \
    --no-options \
    --homedir "$gnupg_home" \
    --batch \
    --yes \
    --pinentry-mode loopback \
    --no-symkey-cache \
    --passphrase-file "$passphrase_file" \
    --symmetric \
    --cipher-algo AES256 \
    --output "$encrypted_receipt" \
    "$sanitized_receipt" \
    >/dev/null 2>"$error_file"; then
  fail_closed_stage AWS_READ_ONLY_STAGE_RECEIPT_ENCRYPTION
fi
/usr/bin/chmod 600 "$encrypted_receipt" \
  2>"$error_file" || fail_closed_stage AWS_READ_ONLY_STAGE_ENCRYPTED_RECEIPT
[[ -s "$encrypted_receipt" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_ENCRYPTED_RECEIPT
if ! /usr/bin/gpgconf --homedir "$gnupg_home" --kill all \
  >/dev/null 2>"$error_file"; then
  fail_closed_stage AWS_READ_ONLY_STAGE_RECEIPT_ENCRYPTION_CLEANUP
fi
[[ -d "$gnupg_home" && ! -L "$gnupg_home" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_RECEIPT_ENCRYPTION_CLEANUP
/usr/bin/rm -rf -- "$gnupg_home" \
  2>"$error_file" || fail_closed_stage AWS_READ_ONLY_STAGE_RECEIPT_ENCRYPTION_CLEANUP
[[ ! -e "$gnupg_home" && ! -L "$gnupg_home" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_RECEIPT_ENCRYPTION_CLEANUP
gnupg_home=""
