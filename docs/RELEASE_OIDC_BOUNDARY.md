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

The legacy coordinator and PREPARE seals deliberately contain only the fixed
action `HOLD_NO_PROVIDER_EXECUTION`. The successor EXECUTE seals contain only
hash-bound executable coordinates; they contain no credential, approval, role,
provider receipt, or authority by themselves. The source-bound IAM template
has not been advanced to the successor workflow bytes, and no environment,
secret, role, workflow run, AWS resource, database, deployment, publication, or
submission state is implied by this source. Until the child pin, applied IAM
update, fresh bootstrap readback, fresh signed approval, and exact provider
receipts all exist, the only truthful result is `NO PROVIDER MUTATION`.

The reviewed IAM template SHA-256 after this source change is
`5f72ab835c93e6c8739405ed953d5c340dd13497a83eb1efff40fd70ba144da9`.
Any bootstrap readback captured against an earlier template is historical
evidence only after this change merges. Applying the IAM update requires a
fresh complete read-only bootstrap readback against these exact template bytes
before any later release phase can rely on the updated roles.
