#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# -ne 3 ]]; then
  printf '%s\n' \
    'HOLD:BOOTSTRAP_READBACK_COLLECTOR_ARGUMENT_REJECTED' >&2
  exit 64
fi

collector_account_id=$1
collector_artifact_bucket=$2
collector_output=$3
collector_region=us-east-1
collector_stack=prooftoact-release-control-bootstrap
collector_table=prooftoact-release-controller
collector_boundary=ProofToActGate2CloudFormationBoundary
collector_parent_input=$(dirname -- "$collector_output")

if [[ ! $collector_account_id =~ ^[0-9]{12}$ ]] ||
  [[ ! $collector_artifact_bucket =~ ^[a-z0-9][a-z0-9.-]*[a-z0-9]$ ]] ||
  [[ ${#collector_artifact_bucket} -lt 3 ]] ||
  [[ ${#collector_artifact_bucket} -gt 63 ]] ||
  [[ $collector_artifact_bucket == *..* ]] ||
  [[ $collector_artifact_bucket == xn--* ]] ||
  [[ $collector_output != /* ]] ||
  [[ -e $collector_output ]] ||
  [[ ! -d $collector_parent_input ]]; then
  printf '%s\n' \
    'HOLD:BOOTSTRAP_READBACK_COLLECTOR_ARGUMENT_REJECTED' >&2
  exit 65
fi

if ! collector_parent_real=$(cd -- "$collector_parent_input" 2>/dev/null &&
  pwd -P); then
  printf '%s\n' \
    'HOLD:BOOTSTRAP_READBACK_COLLECTOR_ARGUMENT_REJECTED' >&2
  exit 65
fi
if [[ $collector_parent_input != "$collector_parent_real" ]]; then
  printf '%s\n' \
    'HOLD:BOOTSTRAP_READBACK_COLLECTOR_ARGUMENT_REJECTED' >&2
  exit 65
fi

collector_aws=$(command -v aws || true)
collector_jq=$(command -v jq || true)
collector_node=$(command -v node || true)
collector_script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
collector_verifier=${collector_script_dir}/release-provider-bootstrap-readback.js

if [[ ! -x $collector_aws ]] || [[ ! -x $collector_jq ]] ||
  [[ ! -x $collector_node ]] || [[ ! -f $collector_verifier ]] ||
  [[ -L $collector_verifier ]]; then
  printf '%s\n' 'HOLD:BOOTSTRAP_READBACK_COLLECTOR_TOOL_REJECTED' >&2
  exit 66
fi

collector_plan=''
collector_simulation_rows=''
collector_input_temporary=''
collector_accepted_temporary=''
collector_cleanup() {
  [[ -z $collector_plan ]] || rm -f -- "$collector_plan"
  [[ -z $collector_simulation_rows ]] ||
    rm -f -- "$collector_simulation_rows"
  [[ -z $collector_input_temporary ]] ||
    rm -f -- "$collector_input_temporary"
  [[ -z $collector_accepted_temporary ]] ||
    rm -f -- "$collector_accepted_temporary"
}
trap collector_cleanup EXIT

mkdir -m 700 -- "$collector_output"

export AWS_DEFAULT_REGION=$collector_region
export AWS_REGION=$collector_region
export AWS_PAGER=''
export AWS_RETRY_MODE=standard
export AWS_MAX_ATTEMPTS=3

collector_run_json() {
  local collector_target=$1
  shift
  local collector_temporary
  collector_temporary=$(mktemp "${collector_output}/.response.XXXXXX")
  if ! "$collector_aws" "$@" --no-cli-pager --output json \
    >"$collector_temporary"; then
    printf '%s\n' 'HOLD:BOOTSTRAP_READBACK_COLLECTOR_AWS_REJECTED' >&2
    exit 67
  fi
  "$collector_jq" -e . "$collector_temporary" >/dev/null
  chmod 600 "$collector_temporary"
  mv -- "$collector_temporary" "${collector_output}/${collector_target}"
}

collector_run_json caller.json sts get-caller-identity
"$collector_jq" -e --arg account "$collector_account_id" \
  '.Account == $account and (.Arn | type == "string") and
   (.UserId | type == "string")' \
  "${collector_output}/caller.json" >/dev/null

collector_run_json stack.json cloudformation describe-stacks \
  --region "$collector_region" --stack-name "$collector_stack"
collector_run_json resources.json cloudformation list-stack-resources \
  --region "$collector_region" --stack-name "$collector_stack"
collector_run_json deployed-template.json cloudformation get-template \
  --region "$collector_region" --stack-name "$collector_stack" \
  --template-stage Original --query TemplateBody
collector_run_json resource-drifts.json \
  cloudformation describe-stack-resource-drifts \
  --region "$collector_region" --stack-name "$collector_stack"

collector_run_json table.json dynamodb describe-table \
  --region "$collector_region" --table-name "$collector_table"
collector_table_arn=$("$collector_jq" -er '.Table.TableArn' \
  "${collector_output}/table.json")
collector_kms_arn=$("$collector_jq" -er '.Table.SSEDescription.KMSMasterKeyArn' \
  "${collector_output}/table.json")
collector_run_json table-tags.json dynamodb list-tags-of-resource \
  --region "$collector_region" --resource-arn "$collector_table_arn"
collector_run_json dynamodb-kms-key.json kms describe-key \
  --region "$collector_region" --key-id "$collector_kms_arn"

collector_boundary_arn="arn:aws:iam::${collector_account_id}:policy/${collector_boundary}"
collector_run_json boundary.json iam get-policy \
  --policy-arn "$collector_boundary_arn"
collector_boundary_version=$("$collector_jq" -er '.Policy.DefaultVersionId' \
  "${collector_output}/boundary.json")
collector_run_json boundary-version.json iam get-policy-version \
  --policy-arn "$collector_boundary_arn" \
  --version-id "$collector_boundary_version"
collector_run_json boundary-versions.json iam list-policy-versions \
  --policy-arn "$collector_boundary_arn"
collector_run_json boundary-entities.json iam list-entities-for-policy \
  --policy-arn "$collector_boundary_arn"

collector_roles=(
  ProofToActGate2CloudFormation
  ProofToActLiveDrillOperator
  ProofToActReleaseCoordinator
  ProofToActReleaseDeployment
  ProofToActReleaseEvidence
  ProofToActReleaseExecution
  ProofToActReleaseTeardown
  ProofToActReleaseTerminalizer
)
declare -A collector_role_policies=(
  [ProofToActGate2CloudFormation]=ProofToActGate2CreateAndRollback
  [ProofToActLiveDrillOperator]=ProofToActAssumeExactDrillAndInnerEvidenceRoles
  [ProofToActReleaseCoordinator]=ProofToActExactReleaseControlAndReadback
  [ProofToActReleaseDeployment]=ProofToActReleaseChangeSetOnly
  [ProofToActReleaseEvidence]=ProofToActReadOnlyReleaseEvidence
  [ProofToActReleaseExecution]=ProofToActExecuteApprovedCreateChangeSetOnly
  [ProofToActReleaseTeardown]=ProofToActExactReleaseTeardown
  [ProofToActReleaseTerminalizer]=ProofToActSafetyReducingTerminalizationOnly
)

for collector_role in "${collector_roles[@]}"; do
  collector_role_dir=${collector_output}/${collector_role}
  mkdir -m 700 -- "$collector_role_dir"
  collector_run_json "${collector_role}/role.json" iam get-role \
    --role-name "$collector_role"
  collector_run_json "${collector_role}/tags.json" iam list-role-tags \
    --role-name "$collector_role"
  collector_run_json "${collector_role}/inline-list.json" \
    iam list-role-policies --role-name "$collector_role"
  collector_run_json "${collector_role}/inline-policy.json" \
    iam get-role-policy --role-name "$collector_role" \
    --policy-name "${collector_role_policies[$collector_role]}"
  collector_run_json "${collector_role}/attached-list.json" \
    iam list-attached-role-policies --role-name "$collector_role"
  collector_run_json "${collector_role}/instance-profiles.json" \
    iam list-instance-profiles-for-role --role-name "$collector_role"
done

collector_plan=$(mktemp \
  "${collector_parent_real}/.prooftoact-bootstrap-simulation-plan.XXXXXX")
"$collector_node" "$collector_verifier" --simulation-plan \
  "$collector_account_id" "$collector_artifact_bucket" >"$collector_plan"
"$collector_jq" -e . "$collector_plan" >/dev/null

collector_simulation_rows=$(mktemp \
  "${collector_parent_real}/.prooftoact-bootstrap-simulation-rows.XXXXXX")
"$collector_jq" -er '
  to_entries[] as $role |
  ["positive", "negative"][] as $kind |
  [$role.key, $kind,
   $role.value[$kind].PolicySourceArn,
   $role.value[$kind].ActionNames[0],
   $role.value[$kind].ResourceArns[0]] | @tsv
' "$collector_plan" >"$collector_simulation_rows"

collector_simulation_count=0
while IFS=$'\t' read -r collector_logical collector_kind \
  collector_role_arn collector_action collector_resource; do
  if [[ -z $collector_logical ]] || [[ -z $collector_kind ]] ||
    [[ -z $collector_role_arn ]] || [[ -z $collector_action ]] ||
    [[ -z $collector_resource ]]; then
    printf '%s\n' \
      'HOLD:BOOTSTRAP_READBACK_COLLECTOR_SIMULATION_PLAN_REJECTED' >&2
    exit 69
  fi
  collector_run_json "${collector_logical}-${collector_kind}.json" \
    iam simulate-principal-policy \
    --policy-source-arn "$collector_role_arn" \
    --action-names "$collector_action" \
    --resource-arns "$collector_resource"
  collector_simulation_count=$((collector_simulation_count + 1))
done <"$collector_simulation_rows"
if [[ $collector_simulation_count -ne 16 ]]; then
  printf '%s\n' \
    'HOLD:BOOTSTRAP_READBACK_COLLECTOR_SIMULATION_PLAN_REJECTED' >&2
  exit 69
fi
rm -f -- "$collector_plan"
collector_plan=''
rm -f -- "$collector_simulation_rows"
collector_simulation_rows=''

collector_observed_at=$("$collector_node" -e \
  'process.stdout.write(new Date().toISOString())')
collector_input_output=${collector_output}.input.json
collector_accepted_output=${collector_output}.accepted.json

if [[ -e $collector_input_output ]] || [[ -e $collector_accepted_output ]]; then
  printf '%s\n' 'HOLD:BOOTSTRAP_READBACK_COLLECTOR_OUTPUT_REJECTED' >&2
  exit 68
fi

collector_input_temporary=$(mktemp \
  "${collector_parent_real}/.prooftoact-bootstrap-input.XXXXXX")
collector_accepted_temporary=$(mktemp \
  "${collector_parent_real}/.prooftoact-bootstrap-accepted.XXXXXX")

"$collector_node" "$collector_verifier" --assemble-directory \
  "$collector_output" "$collector_account_id" \
  "$collector_artifact_bucket" "$collector_observed_at" \
  >"$collector_input_temporary"
"$collector_node" "$collector_verifier" --verify-input \
  "$collector_input_temporary" >"$collector_accepted_temporary"
chmod 600 "$collector_input_temporary" "$collector_accepted_temporary"
mv -- "$collector_input_temporary" "$collector_input_output"
collector_input_temporary=''
mv -- "$collector_accepted_temporary" "$collector_accepted_output"
collector_accepted_temporary=''

printf 'ACCEPTED:%s:%s\n' "$collector_input_output" \
  "$collector_accepted_output"
