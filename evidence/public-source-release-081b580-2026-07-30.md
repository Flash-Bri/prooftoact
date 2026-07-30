# Public source release receipt

- Observed: 2026-07-30T22:08:31Z
- Repository: `https://github.com/Flash-Bri/tideproof`
- Released commit: `081b580e4e8d68acf8f6d4dbef0e95928eaf884b`
- Released tree: `8bdd9b4482cbd2fb20eda7bdea952f81b1dc111d`
- Default branch: `main`
- License: MIT

## Publication checks

- An unauthenticated GitHub API request returned HTTP 200 with
  `private: false`, `full_name: Flash-Bri/tideproof`, and default branch
  `main`.
- Local `origin/main` resolved exactly to the released commit.
- GitHub Actions run
  `https://github.com/Flash-Bri/tideproof/actions/runs/30586011228`
  completed successfully for the released commit.
- GitHub secret scanning and push protection reported `enabled`.
- Private vulnerability reporting returned `{"enabled":true}`.

## Pre-publication checks

- `npm test`: 65/65 passed.
- `npm audit --audit-level=high`: zero vulnerabilities.
- A narrow history scan across all 19 published commits found no AWS access key,
  GitHub token, OpenAI-style secret, private-key header, or credentialed
  PostgreSQL URI pattern. This is defense in depth, not proof that arbitrary
  secrets cannot exist.
- `git ls-files -ci --exclude-standard` returned no tracked ignored files.
- The exact released commit produced a `CLEAN_ARTIFACT_BUILD` bound to the
  released tree; all five current ZIPs passed independent `unzip -tq`
  integrity checks.

## Boundaries

This receipt proves public source availability and hosted CI only. It does not
prove a live AWS deployment, public Tideproof application, Bedrock inference,
KMS signature, DNS launch, contest submission, or production suitability. No
AWS, DNS, domain, TrustAgentic, Conversate, Northstar, or submission record was
mutated during publication.
