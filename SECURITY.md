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

## Safe research boundary

Testing must stay within locally owned fixtures or explicitly authorized
Tideproof resources. Do not probe Cockroach Labs, AWS, TrustAgentic,
Conversate, Northstar, another entrant, or any third-party system without
separate written authorization.
