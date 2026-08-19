# Release OIDC credential boundary

Status: **SOURCE-BOUND HOLD — NO PROVIDER AUTHORITY ACTIVATED**

The release roles no longer trust a mutable workflow name alone. Every
GitHub OIDC trust statement retains the exact repository, immutable repository
and owner IDs, `main` ref, protected environment, audience, subject, and caller
workflow condition. It also requires one exact `job_workflow_ref` naming a
role-specific reusable workflow at bootstrap commit
`50d0cd261b8597fe74c80b84c49be0adde5bdf6f`.

This uses a deliberate two-commit sequence:

1. Credential-boundary bootstrap commit `50d0cd26…` sealed the final reusable
   workflow bytes. The commit cannot bind its own SHA without changing that
   SHA. Its earlier parent contains untrusted scaffolding and is not named by
   any source IAM trust or caller.
2. Its child binding commit pins caller `uses:` references and the source IAM
   trusts to the now-known bootstrap SHA.

The direct release-candidate workflow has no `id-token: write` permission and
no AWS credential configuration. Checkout, dependency installation, frozen
application build, tests, and seal generation stay in those tokenless jobs.
They receive no protected environment secret or variable. Its bootstrap-pinned
coordinator and PREPARE reusable workflows still decode only two small
canonical Base64 values, verify their hashes and exact schemas, and stop at the
reviewed HOLD boundary.

The source now also contains activation-ready successor coordinator and EXECUTE
reusable-workflow bytes. Those successors check out the exact authority commit
and frozen application separately, bind the signed approval and protected
bootstrap readback before OIDC, install only the two isolated runtime dependency
trees, assume one phase-specific role, and perform reserve, dispatch, or
finalize through capability-separated runtimes. They are not reachable from the
current diagnostic-only top-level EXECUTE workflow, and the live IAM trusts are
not authorized to their as-yet-unbound commit SHA. Activating them requires the
same two-commit sequence: first merge and verify these reusable bytes; then pin
the caller and IAM `job_workflow_ref` conditions to that immutable commit in a
separate reviewed child, apply the exact IAM update, and capture a fresh
provider readback. The drill, evidence, teardown, and terminalizer reusable
workflows remain hard HOLDs.

The same inert successor commit contains a separate fresh-primary reusable
workflow and standalone `infra/aws/fresh-primary-bootstrap-role-stack.json`.
Before that reusable workflow reads a protected secret, checks out
caller-selected bytes, or exchanges a token for AWS credentials, its immutable
YAML requests a memory-only GitHub OIDC token with the fixed
`prooftoact-fresh-primary-source-lock-v1` audience. It accepts only the bounded
GitHub HTTPS token endpoint and requires both `job_workflow_ref` and
`job_workflow_sha` to identify the reusable workflow at the exact requested
authority commit. The token, response, and decoded claims are never placed in
an argument, file, log, output, or artifact. Only after that GitHub-issued
binding passes may checkout occur, and the checkout must reproduce both the
same commit and the caller-supplied exact tree. A later `main` caller therefore
cannot use the immutable reusable workflow to execute later provider code.
GitHub's OIDC reference documents `job_workflow_ref` and `job_workflow_sha` as
standard reusable-workflow claims. A read-only repository OIDC configuration
readback on 2026-08-19 returned `use_default: true`,
`use_immutable_subject: false`, and the immutable subject prefix
`repo:Flash-Bri@252500266/prooftoact@1317716765`. That prefix agrees with the
repository and owner IDs required by the source-lock validator. This readback
proves the configured claim layout only; it is not provider authorization or
an execution receipt.
That standalone stack is the sole source of the
`ProofToActFreshPrimaryBootstrap` role; the retained ten-resource deployment
stack does not duplicate it. The role can read only seven exact-name Secrets
Manager resources: one operation-bound bootstrap-admin target, one distinct
auditor API credential, one creator API credential, one runtime-credential
bundle, the existing Managed MCP and recovery-publisher credentials, and one
operation-bound recovery-signer target. It
strongly reads and conditionally writes only `FRESH_CLUSTER#*` and
`FRESH_PRIMARY#*` items in the retained controller table. The runtime rereads
the three pre-existing immutable credential versions, seals and reads back the
two operation-bound versions, fixes the Cockroach Cloud API endpoint, and
requires the receipt-bound AWS-hosted Basic cluster before the SQL
census/bootstrap. It cannot deploy the application, invoke Lambda, assume
another role, use KMS or S3, mutate IAM or CloudFormation, or delete, scan,
query, batch, transact, or otherwise broaden the controller table.

A second create-only standalone stack,
`infra/aws/fresh-primary-credential-custody-stack.json`, closes the credential
custody boundary without granting root a workload-secret path. A temporary,
operation-bound non-root B0 creator may create and read back exactly seven
empty retained Secrets Manager containers and one chained writer role, but it
has no `GetSecretValue` or `PutSecretValue` permission. The writer trusts only
the immutable B0 principal plus the source/tree/template/operator-bound
external ID and exact session name. A short-lived approval binds the five
expected value digests, exact ARN hashes, deterministic client tokens, the two
zero-version runtime targets, and the human authorization receipt before any
provider call. The writer can seal and read only the auditor, creator,
runtime-credential, Managed MCP, and recovery-publisher versions. It cannot
read or write the bootstrap-admin or recovery-signer values; those two targets
remain empty until the fresh-cluster and fresh-primary runtimes respectively
seal them. Complete paginated readback requires exactly five one-version
containers and two zero-version containers. Deleting B0 leaves the IAM-stored
writer trust as an opaque, unassumable principal ID.

Managed MCP recovery remains a separate controlled Cockroach database and is
never granted or mutated by the fresh-primary workflow. The fresh-primary
command binds the SHA-256 of its separately verified recovery-security receipt.
That recovery receipt must show exactly public recovery-view `SELECT`,
`mcp_private` schema `USAGE`, and `mcp_public` schema `USAGE`, while continuing
to deny private-relation, function, role, system, grant-option, login, and write
capabilities. A digest binding does not replace independent verification of
those provider grants.

The legacy coordinator and PREPARE seals deliberately contain only the fixed
action `HOLD_NO_PROVIDER_EXECUTION`. The successor EXECUTE seals contain only
hash-bound executable coordinates; they contain no credential, approval, role,
provider receipt, or authority by themselves. The source-bound IAM template
has not been advanced to the successor workflow bytes, and no environment,
secret, role, workflow run, AWS resource, database, deployment, publication, or
submission state is implied by this source. Until the child pin, applied IAM
update, fresh bootstrap readback, fresh signed approval, and exact provider
receipts all exist, the only truthful result is `NO PROVIDER MUTATION`.

The reviewed retained deployment IAM template SHA-256 after this source change
is `5f72ab835c93e6c8739405ed953d5c340dd13497a83eb1efff40fd70ba144da9`.
The standalone fresh-primary stack SHA-256 is
`ced2992afdbce22188672235d12c613fbea941d2d502b56ddf00df78a5dbeb06`.
The standalone credential-custody stack SHA-256 is
`0d23509291626d7e3d91d1454e581e36bb6721166e84747791ce5a3c7d6bb474`.
Any bootstrap readback captured against an earlier template is historical
evidence only after this change merges. Applying the IAM update requires a
fresh complete read-only bootstrap readback against these exact template bytes
before any later release phase can rely on the updated roles.
