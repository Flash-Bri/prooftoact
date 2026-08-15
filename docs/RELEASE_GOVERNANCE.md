# Release governance control

Status: `OBSERVED_POST_RENAME_NONFINAL_GITHUB_GOVERNANCE`

This control binds a sanitized, read-only snapshot of the public GitHub repository's release governance to reviewed local release surfaces. It exists to prevent the project from silently treating a one-time settings check as durable final proof.

## Observed checkpoint

At `2026-08-01T01:45:38Z`, the GitHub API reported the following for public repository `Flash-Bri/tideproof` at commit `68f112f97e7439ac2ab1ecdde4c6379453c825c6`:

That immutable historical snapshot retains status
`OBSERVED_NONFINAL_GITHUB_GOVERNANCE`.

- `main` required a pull request and the strict `verify` status check;
- administrator enforcement and conversation resolution were enabled;
- force pushes and branch deletion were disabled;
- the required approving-review count was zero, so this control does **not** claim that human approval was required;
- vulnerability alerts, secret scanning, and secret-scanning push protection were enabled;
- automated Dependabot security-update pull requests were disabled deliberately to preserve the single-writer release lane; and
- GitHub Actions run `30674588891` completed successfully at that exact commit.

The snapshot contains no credentials, request identifiers, account identities,
email addresses, billing data, or private repository data.

That checkpoint intentionally retains the former repository coordinate. Brian
approved the ProofToAct rename on 2026-08-03, and the same repository was
renamed in place to `Flash-Bri/prooftoact`. The sanitized post-rename snapshot
at `evidence/github-release-governance-rename-2026-08-03.json` records stable
repository ID `1317716765` (`R_kgDOTorDHQ`), the transferred protection and
security settings, and successful pull-request CI run `30827066820` at commit
`df4da95358324ab95b8556650f4c639c7cee21f5`. The historical snapshot remains
immutable. The approved name, current coordinate, preserved identifiers, and
no-touch boundaries are machine-bound by `RENAME_MIGRATION_MANIFEST.json` and
`docs/RENAME_MIGRATION.md`.

## Fail-closed interpretation

`npm run governance:verify` verifies both canonical snapshot structures, exact
reviewed settings, the stable repository identity and current coordinate,
exact surface hashes, the protected `verify` merge/main job, the separate
no-secrets `verify-pr-head-no-secrets` candidate-head job, and the explicit
non-final boundary. A pass means only `CURRENT_REPOSITORY_GOVERNANCE_PASS`.

It does not query GitHub, prove that settings still match, require a human approval, establish vulnerability absence, approve the release, authorize cloud mutation, or authorize submission. Any final release must requery GitHub at the exact final commit and bind the resulting observation to the final hosted CI run.

## Final release requirements

1. Requery repository visibility, security settings, and the complete `main` branch-protection document at the exact final release commit.
2. Before merge, verify `verify-pr-head-no-secrets` succeeds on the exact candidate head while `verify` succeeds on the distinct synthetic merge commit; after merge, verify `verify` succeeds at the exact official-main commit and still belongs to the intended GitHub Actions workflow.
3. Complete signed-out repository, release metadata, and public-link review before publication and submission.
