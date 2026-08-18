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
They receive no protected environment secret or variable. The only
token-capable reusable workflows are the
coordinator and PREPARE boundaries. They perform no checkout, setup, package
installation, build, test, repository script, AWS CLI, or caller-controlled
command or third-party action. They receive only two small canonical Base64
values from the tokenless jobs, decode them into an owner-only temporary
directory, require exactly two bounded regular single-link files, verify the
canonical Base64 and both SHA-256 values, parse exact JSON schemas and fixed
values, and then stop with a hard HOLD before AWS credential configuration.
The tokenless jobs separately retain those two files through an exact pinned
artifact-upload action; the token jobs never download or execute that artifact.

The execution, drill, evidence, teardown, and terminalizer reusable workflows
have no OIDC permission at all and hard-fail. Their role trusts are pinned now
so a later mutable caller cannot silently gain authority. Enabling any of them
requires a new reviewed reusable-workflow commit and a separately reviewed IAM
trust update to that new exact SHA.

The current coordinator and PREPARE seals deliberately contain only the fixed
action `HOLD_NO_PROVIDER_EXECUTION`. They are not executable provider payloads.
The source-bound IAM template has not been applied by this change, and no
environment, secret, role, workflow run, AWS resource, database, deployment,
publication, or submission state was changed. Until the exact IAM update is
deployed and a separately reviewed executable design replaces the HOLD, the
only truthful result is `NO PROVIDER MUTATION`.
