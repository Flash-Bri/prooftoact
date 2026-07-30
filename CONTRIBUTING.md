# Contributing to Tideproof

Tideproof is a clean-room, synthetic competition project. Contributions must
preserve the provenance, security, cost, and claim boundaries documented in
[`CLEAN_ROOM.md`](CLEAN_ROOM.md), [`CLAIMS.md`](CLAIMS.md), and
[`docs/COST_GATES.md`](docs/COST_GATES.md).

## Before proposing a change

- Use only newly authored or license-compatible material.
- Never include secrets, real people or incidents, customer data, proprietary
  TrustAgentic/Conversate/Northstar material, or OpenClaw credentials.
- Keep scenarios and identities clearly synthetic.
- Do not turn an unverified local or cloud behavior into a public claim.
- Do not create or mutate live AWS or CockroachDB resources from a pull
  request.

## Local checks

Use Node.js 22 or newer:

```sh
npm ci
npm test
npm audit --audit-level=high
npm run build:gate2
```

The Gate Two build is credential-free and produces ignored local artifacts.
Live Gate One or AWS evidence commands require separate project-only
authorization and must not run in pull-request automation.

## Change shape

Keep changes bounded, add deterministic tests for behavior, update the claims
ledger when evidence status changes, and identify any new dependency, asset,
model, dataset, or pre-existing component in the provenance documentation.

Report vulnerabilities through the private process in
[`SECURITY.md`](SECURITY.md), not through a public issue.
