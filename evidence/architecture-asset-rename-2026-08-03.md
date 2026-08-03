# ProofToAct architecture asset rename receipt — 2026-08-03

## Scope

This receipt supersedes only the current-name and accessible-title binding for
the standalone architecture SVG. It does not alter or rewrite the immutable
2026-07-31 Tideproof working-name receipt, add a logo or marketing asset, or
prove any live AWS or CockroachDB behavior.

## Source-to-output lineage

- Former SVG SHA-256:
  `5e897dbfd926486203362cf517c967e44d799edbf7f56d1d01b16307ec02724c`
- ProofToAct SVG SHA-256:
  `0a35e196d896e932bbadf2afbf5e915c21073c423d9d8ac8a23023ad0887c871`
- ProofToAct PNG SHA-256:
  `6228172f7a5a462940a05543ee455e0de21aa53c805e9466076b9e33fed1f168`
- SVG intrinsic dimensions: `2200 × 720`; view box: `1100 × 360`
- PNG dimensions: `2200 × 720`; RGB PNG
- Renderer: macOS `/usr/bin/sips`, version `sips-316`
- Exact render command:
  `/usr/bin/sips -s format png docs/media/architecture.svg --out docs/media/architecture.png`

The SVG byte change updates only the accessible title and document metadata
from the former working name to ProofToAct. The descriptive content is
unchanged. The rendered pixels are unchanged, so the
PNG digest intentionally remains identical to the 2026-07-31 export. No
external asset, embedded font, script, link, remote request, or generative
media was added.

## Review result

`CLEARED_CURRENT` for the public repository, README, browser demo,
video, and submission, subject to the existing synthetic and non-live claim
boundaries. Any later SVG geometry, palette, copy, or renderer change requires
a new exact-hash rights and accessibility review.
