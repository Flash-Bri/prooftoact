# Release OIDC credential boundary

Status: **IMMUTABLE SOURCE PINS MERGED — LIVE PROVIDER READBACK REQUIRED**

The release roles no longer trust a mutable workflow name alone. Every
GitHub OIDC trust statement retains the exact repository, immutable repository
and owner IDs, `main` ref, protected environment, audience, subject, and caller
workflow condition. Each role-specific caller and IAM template requires one
exact `job_workflow_ref` naming reviewed reusable-workflow bytes. The private
recovery lanes remain bound to bootstrap commit
`caf417dd84d899c7407e5ed12f56b60f1b74d32a`; the fresh-primary lane is bound
to activation-source commit
`b8f993a4a9a898673c89dbd8218ec7eb591f1f10` and tree
`4615e7bea235f1c4ddf7f680d125cad6d355fecf`.

This uses a deliberate immutable-source sequence:

1. Bootstrap commit `caf417dd…` sealed and reviewed the private recovery and
   fresh-primary reusable workflow bytes.
2. Activation-source commit `b8f993a4…` pinned the five private recovery
   callers to `caf417dd…` and separated immutable source identity from the
   GitHub-issued caller workflow SHA for fresh-primary execution.
3. This child binds the fresh-primary caller and standalone IAM template to
   the now-known `b8f993a4…` source. Its own caller SHA remains a separate
   GitHub-issued identity and cannot change the executable source bytes.

The direct release-candidate workflow has no `id-token: write` permission and
no AWS credential configuration. Checkout, dependency installation, frozen
application build, tests, and seal generation stay in those tokenless jobs.
They receive no protected environment secret or variable. Its bootstrap-pinned
coordinator and PREPARE reusable workflows still decode only two small
canonical Base64 values, verify their hashes and exact schemas, and stop at the
reviewed HOLD boundary.

The source now also contains source-pinned successor coordinator and EXECUTE
reusable-workflow bytes. Those successors check out the exact authority commit
and frozen application separately, bind the signed approval and protected
bootstrap readback before OIDC, install only the two isolated runtime dependency
trees, assume one phase-specific role, and perform reserve, dispatch, or
finalize through capability-separated runtimes. They are not reachable from the
current diagnostic-only top-level EXECUTE workflow. The five private recovery
callers now pin their reviewed reusable bytes, but source pinning alone does not
prove that the corresponding live IAM trusts, environment values, or provider
resources have been applied. Those claims require exact provider readback. The
drill and terminalizer reusable workflows remain hard HOLDs.

The same reviewed source contains a separate fresh-primary reusable
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
provider receipt, or authority by themselves. The source-bound IAM templates
and callers now name their reviewed immutable workflow bytes. No environment
value, secret, role, workflow run, AWS resource, database mutation, deployment,
publication, or submission state is implied by source alone. Applied IAM
updates, fresh bootstrap readback, signed approval, and exact provider receipts
remain required before any live execution claim.

The reviewed retained deployment IAM template SHA-256 after this source change
is `5f72ab835c93e6c8739405ed953d5c340dd13497a83eb1efff40fd70ba144da9`.
The standalone fresh-primary stack SHA-256 is
`0ecab5c430720c7ec030dbd49e48abab3b9554cf2820368f17a3a8f89c13d08b`.
The standalone credential-custody stack SHA-256 is
`0d23509291626d7e3d91d1454e581e36bb6721166e84747791ce5a3c7d6bb474`.
Any bootstrap readback captured against an earlier template is historical
evidence only after this change merges. Applying the IAM update requires a
fresh complete read-only bootstrap readback against these exact template bytes
before any later release phase can rely on the updated roles.
