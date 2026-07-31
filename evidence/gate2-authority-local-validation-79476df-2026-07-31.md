# Gate Two authority local validation — `79476df`

## Scope

This receipt binds the current local AWS Authority Lambda candidate, its
two-contender runner, and the tests that exercise its IAM, transaction,
ambiguous-COMMIT, durable-state, and fail-closed boundaries. It is local
candidate evidence only.

It does **not** prove AWS deployment, Lambda concurrency, Secrets Manager or
IAM enforcement, CockroachDB reachability, a live serializable race, public
API traversal, KMS, Bedrock, current spend, or any real-world effect. Those
claims remain blocked until the accepted private live receipts and sanitized
release evidence named in `docs/AWS_GATE2.md` exist.

Source revision:
`79476df122f434d91be9638f07c3800e83384530` on public `main`. The proof
manifest work that adds this receipt does not change the candidate files
listed below.

## Exact local candidate

| File | SHA-256 |
| --- | --- |
| `src/cloud/aws-authority-race.js` | `dadfdd18eee9f11e3be01fc5b35b1803662a14d353fa1081f1e57f75cc420579` |
| `infra/aws/lambda/authority.cjs` | `3a9bc56fb6a083a4d6ce1f1e29955a4f5028be2cfeec90a64744261ba20aa5c7` |
| `scripts/gate2-authority-race.js` | `67701e35a9e01495f2e736f912489ef465c356e45ccdc6a491eb51806cc7c2ac` |
| `test/aws-authority-race.test.js` | `47b38d50487520366b282ecb0b117c294b727a6b046a12cc63114bd360d969a4` |
| `test/aws-authority-lambda.test.js` | `b92a3352dacb2df462a8682f2e6994e2e1dae18ffb6a1ab2d20f90953b0e8c91` |
| `test/aws-gate2.test.js` | `105c16ff3959ad55cb5c88b64420500687ade56616721051aa3c3f930c1188d8` |

## Credential-free acceptance

The focused command below passed 30/30 tests:

```sh
node --test test/aws-authority-lambda.test.js \
  test/aws-authority-race.test.js test/aws-gate2.test.js
```

The accepted local cases include:

- exact two-contender request and capability-field derivation outside the
  model;
- one exact least-privilege secret read and strict database selection;
- `SERIALIZABLE` transaction setup, pre-commit `40001` retry only, and
  ambiguous-COMMIT reconciliation without replaying the spend;
- a later read-only durable observation bound to both terminal receipts, one
  winner, one winner-aware denial, one outbox, the winning holder and fence,
  no pending receipt, and zero protected effects;
- rejection of non-overlap, alias drift, response expansion, model authority,
  durable-proof drift, extra receipts, changed outbox state, effects, and stale
  observation; and
- least-privilege template, Lambda capability, typed observer, generated
  template, and effective-config-digest checks.

The full deterministic suite also passed 112/112 and the locked dependency
audit reported zero vulnerabilities. No credential or cloud call was used.
