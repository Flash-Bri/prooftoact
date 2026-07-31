# Architecture asset release receipt — 2026-07-31

## Scope

This receipt clears only Tideproof production asset `V09`: the standalone
trust-boundary diagram and its exact PNG export. It does not clear a wordmark,
logo, ocean image, screenshot, title card, social image, TrustAgentic asset,
or any live-service claim.

## Clean-room lineage

- Source concept: Tideproof-owned inline browser diagram `C02` in
  `web/index.html`.
- Standalone source: `docs/media/architecture.svg`.
- Accessible text counterpart: `docs/ARCHITECTURE.md`.
- Creator and owner: Nunan / Tideproof project.
- Third-party media, logo, webfont, embedded font, script, external link,
  generative image, or remote request: none.
- License: Tideproof repository MIT license.

The diagram was reviewed against the architecture document. It preserves
these claim boundaries:

1. evidence is checked for provenance, validity, scope, and conflict before
   vector ranking;
2. the agent produces a proposal without an operation fence or effect key;
3. deterministic authority commits one serializable fenced receipt; and
4. Managed MCP returns context without inherited authority.

The receipt node is explicitly a synthetic database sink. The diagram is not
evidence of live AWS hosting, Bedrock, KMS, IAM denial, an overlapping Lambda
race, a CockroachDB-to-AWS handoff, or a real-world effect.

## Exact outputs

| File | Dimensions | SHA-256 |
| --- | --- | --- |
| `docs/media/architecture.svg` | intrinsic `2200 × 720`, view box `1100 × 360` | `5e897dbfd926486203362cf517c967e44d799edbf7f56d1d01b16307ec02724c` |
| `docs/media/architecture.png` | `2200 × 720` | `6228172f7a5a462940a05543ee455e0de21aa53c805e9466076b9e33fed1f168` |

The PNG was rendered directly from the SVG with macOS 26.5.2
`/usr/bin/sips`. The renderer uses platform system fonts; no font binary is
redistributed.

## Review result

`CLEARED_CURRENT` for the public repository, README, website, demo video,
social/press packet, and hackathon submission. Any byte change, restyle,
added claim, new embedded asset, or different export requires a new hash and
rights review.
