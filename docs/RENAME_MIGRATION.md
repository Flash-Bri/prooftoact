# ProofToAct rename migration

Decision date: 2026-08-03.
Approved public name: **ProofToAct**.
Approved line: **ProofToAct: Admissibility Memory for High-Stakes Agents**.
Intended repository: `https://github.com/Flash-Bri/prooftoact`

## Decision boundary

Brian approved ProofToAct as the replacement name for this hackathon project.
The bounded screening recorded in `docs/PRIOR_ART.md` is an engineering
knockout check, not legal advice or trademark clearance. A close-to-release
confusingly-similar search and qualified review remain appropriate before any
material long-term brand investment.

ProofToAct was formerly developed under the working name **Tideproof**. That
former name is retained only where changing bytes or provider identities would
damage provenance, break compatibility, or falsely rewrite history.

## Current-name mapping

| Surface | Current value |
| --- | --- |
| Product and Devpost name | `ProofToAct` |
| Subtitle | `Admissibility Memory for High-Stakes Agents` |
| GitHub repository | `Flash-Bri/prooftoact` |
| npm-private package name | `prooftoact-admissibility-memory` |
| Future main AWS stack | `prooftoact-gate2` |
| Future disposable probe stack | `prooftoact-gate2-probe` |
| AWS project tag and metric namespace | `ProofToAct` / `ProofToAct/GateTwo` |

## Immutable and compatibility-preserved identifiers

The following remain legacy ProofToAct identifiers until a separately reviewed
migration is justified:

- every pre-rename file under `evidence/`, including its hashes and original
  repository coordinates;
- the CockroachDB databases `tideproof` and `tideproof_recovery`, the `tp_*`
  database principals and schemas, and accepted provider evidence bound to
  those names;
- `tideproof.*` wire-schema identifiers, `TIDEPROOF_*` compatibility
  environment variables, application names, and cryptographic domain
  separators;
- the already-created AWS bootstrap stack `tideproof-gate2-artifacts` and its
  account-safety nested stack, original `Tideproof` description and project
  tag, bucket versions, and historical receipts;
- Git history and third-party references to the unrelated public
  `bigg-kay/TideProof` project.

These retained strings identify the former working-name namespace of this
same hackathon codebase. They do not imply a relationship with any separate
business, domain, or third-party project. New public branding and future main
AWS resources must use ProofToAct identifiers.

## Separate domain boundary

The existing `tideproof.net` registration appears in this repository only as
a historical owner-reported cost input used to enforce the unchanged project
spend ceiling. This rename does not transfer, modify, renew, deploy to, or make
claims about that domain. The domain and any unrelated use are outside this
repository and outside this migration.

## Artifact and release rules

- Never deploy by manually selecting an old file from `dist/aws`.
- Rebuild all six Gate Two bundles from one exact clean ProofToAct commit.
- Accept only hashes emitted by that exact build and the readiness wrapper.
- Regenerate the CloudFormation templates from their source generator.
- Regenerate the architecture PNG directly from the reviewed SVG.
- Update every release manifest hash after its leaf files stabilize;
  `PROOF_MANIFEST.json` is updated last.
- Preserve old receipts as historical evidence and add superseding receipts;
  never edit the old receipt bytes.

The rename itself performs no AWS deployment, CockroachDB mutation, domain or
DNS action, Devpost submission, or live-service claim.
