# Security policy

## Scope

Tideproof is a synthetic competition demonstration. It is not production
security software, emergency-response software, or a service suitable for real
people, incidents, resources, or credentials. The verified and unverified
boundaries for public claims are maintained in [`CLAIMS.md`](CLAIMS.md).

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use the repository's
private **Report a vulnerability** flow under GitHub Security Advisories and
include:

- the affected commit and file;
- the smallest safe reproduction;
- the impact you believe is possible; and
- whether any secret, personal data, or live cloud resource may be involved.

Do not include credentials, personal data, customer data, real emergency data,
or proprietary third-party source in a report. If a report may involve active
credential exposure, revoke or rotate the affected project-only credential
before sharing diagnostic detail.

## Supported version

Only the current `main` branch is maintained during the competition build.
Security fixes are not backported to earlier commits.

## Release privacy gate

`npm run privacy:verify` scans every current tracked file and every size-bounded
blob reachable from the checked-out commit for a bounded set of high-confidence
credential and privacy signatures. Exact reviewed exceptions live in
`RELEASE_PRIVACY_MANIFEST.json`. This automated result is not an exhaustive
secret or personal-data guarantee and does not replace the final private human
review documented in `docs/RELEASE_PRIVACY.md`.

## Current source security gate

`npm run security:verify` binds the reviewed public runtime, live public-demo
verifier, Gate Two template and Lambda boundaries, CockroachDB security
bootstrap, Managed MCP client, and release threat model to exact hashes. It
also parses the generated CloudFormation and rejects drift in routes,
authentication, throttles, concurrency, immutable aliases, versioned code,
Lambda invoke permissions, and role action sets.

Its `CURRENT_SOURCE_SECURITY_PASS` result is a bounded static review, not a
vulnerability-free claim, penetration test, live IAM receipt, or publication
authorization. The exact scope and remaining live/private review requirements
are documented in `docs/RELEASE_SECURITY.md`.

## Repository governance gate

`npm run governance:verify` validates a sanitized historical observation of
repository visibility, branch protection, required CI, vulnerability alerts,
secret scanning, and push protection against exact reviewed source hashes.
The observation records that automated Dependabot security-update pull
requests were deliberately disabled at that checkpoint to preserve the
single-writer release lane; vulnerability alerts and explicit dependency
review remain required.

`CURRENT_REPOSITORY_GOVERNANCE_PASS` does not query GitHub or establish that
settings remain unchanged. Requery and review the complete GitHub settings at
the exact final release commit before publication or submission.

## Safe research boundary

Testing must stay within locally owned fixtures or explicitly authorized
Tideproof resources. Do not probe Cockroach Labs, AWS, TrustAgentic,
Conversate, Northstar, another entrant, or any third-party system without
separate written authorization.
