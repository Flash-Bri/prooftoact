# Proof manifest baseline — 2026-07-31

## Scope

This receipt records the first machine-checked Tideproof proof manifest. It
binds every row in `CLAIMS.md` to exact public evidence or local-validation
bytes and keeps incomplete release controls fail closed. It does not accept a
live AWS claim, authorize deployment, prove a public demo or video, approve a
submission, or supersede any source evidence receipt.

Baseline input revision: public `main` commit
`79476df122f434d91be9638f07c3800e83384530`. The Git commit containing this
receipt is the controlling source revision for the new manifest and verifier.

## Exact manifest and verifier

| File | SHA-256 |
| --- | --- |
| `PROOF_MANIFEST.json` | `5b20867d2ccf0baed0f9a320371d14b916b9bccef57ab8506bc390ce4fc5ddb4` |
| `scripts/verify-proof-manifest.js` | `bf277ed795a0597d975d3ddd08eb063c14692e9fc92472353feddd35c96ab31c` |
| `test/proof-manifest.test.js` | `5ec5ad13c4c5aaaaa04cfb9c9bca9c09a6c880384dcb5f403292ebf970e7bbc0` |

The manifest status is `INCOMPLETE_LIVE_GATES_PENDING`. Its 11 claim entries
match the claims ledger exactly: seven are evidence-backed `VERIFIED` entries
and four are `PARTIAL` entries with explicit remaining live requirements. The
manifest also binds 20 artifacts and seven release controls.

The verifier rejects noncanonical JSON, an unrecognized schema or state,
changed artifact bytes, unsafe or symbolic paths, missing claim coverage,
stale claims-ledger status, unknown or unused artifact references, duplicate
IDs, and a `VERIFIED` claim without accepted evidence.

## Verification

The following credential-free checks passed against the exact files above:

- `npm run proof:verify`: `PASS`, manifest SHA-256
  `5b20867d2ccf0baed0f9a320371d14b916b9bccef57ab8506bc390ce4fc5ddb4`;
- focused proof-manifest tests: 5/5 passed, including changed-byte,
  path-traversal, symbolic-path, and omitted-claim rejection;
- full deterministic suite: 112/112 passed; and
- `npm audit --audit-level=low`: zero vulnerabilities.

No AWS, CockroachDB, DNS, domain, production, or submission resource was read
or mutated for this receipt. The AWS deployment gate remains closed pending a
clean authenticated readiness `PASS` and current-spend receipt.
