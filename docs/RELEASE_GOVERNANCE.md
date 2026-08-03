# Release governance control

Status: `OBSERVED_NONFINAL_GITHUB_GOVERNANCE`

This control binds a sanitized, read-only snapshot of the public GitHub repository's release governance to reviewed local release surfaces. It exists to prevent the project from silently treating a one-time settings check as durable final proof.

## Observed checkpoint

At `2026-08-01T01:45:38Z`, the GitHub API reported the following for public repository `Flash-Bri/tideproof` at commit `68f112f97e7439ac2ab1ecdde4c6379453c825c6`:

- `main` required a pull request and the strict `verify` status check;
- administrator enforcement and conversation resolution were enabled;
- force pushes and branch deletion were disabled;
- the required approving-review count was zero, so this control does **not** claim that human approval was required;
- vulnerability alerts, secret scanning, and secret-scanning push protection were enabled;
- automated Dependabot security-update pull requests were disabled deliberately to preserve the single-writer release lane; and
- GitHub Actions run `30674588891` completed successfully at that exact commit.

The snapshot contains no credentials, request identifiers, account identifiers, email addresses, billing data, or private repository data.

This checkpoint intentionally retains the former repository coordinate. Brian
approved the ProofToAct rename on 2026-08-03; the current repository coordinate
is `Flash-Bri/prooftoact`. A new sanitized post-rename observation must bind
that coordinate to the same stable repository identity, current protection,
security settings, and hosted CI. The historical snapshot remains immutable.
The approved name, target coordinate, preserved identifiers, and no-touch
boundaries are machine-bound by `RENAME_MIGRATION_MANIFEST.json` and
`docs/RENAME_MIGRATION.md` while that transition is in progress.

## Fail-closed interpretation

`npm run governance:verify` verifies canonical snapshot and manifest structure, exact reviewed settings, exact surface hashes, the required local CI job identity, the repository's public source coordinates, and the explicit non-final boundary. A pass means only `CURRENT_REPOSITORY_GOVERNANCE_PASS`.

It does not query GitHub, prove that settings still match, require a human approval, establish vulnerability absence, approve the release, authorize cloud mutation, or authorize submission. Any final release must requery GitHub at the exact final commit and bind the resulting observation to the final hosted CI run.

## Final release requirements

1. Requery repository visibility, security settings, and the complete `main` branch-protection document at the exact final release commit.
2. Verify the required `verify` check succeeds at that exact commit and still belongs to the intended GitHub Actions workflow.
3. Complete signed-out repository, release metadata, and public-link review before publication and submission.
