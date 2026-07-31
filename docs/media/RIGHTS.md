# Media, font, and trademark rights ledger

**Status: ACTIVE BASELINE — NOT RELEASE-COMPLETE**

Ledger origin checkpoint:
`a276dcda0eaf88c8f7862e9a56acd6e1517d0454` on 2026-07-30. Current
distributed surfaces are controlled by the exact file hashes below and the
Git commit containing this ledger.

This is the controlling rights ledger for Tideproof's website, repository,
README, screenshots, video, social preview, press material, and hackathon
submission. A row clears only the exact source hash and use stated here.
Changing a source file, creating a derivative, or adding a channel requires a
new or reviewed row. `PENDING`, `SPEC_ONLY`, and `BLOCKED` never authorize
publication.

The repository's MIT license applies to Tideproof-owned source. It does not
silently relicense third-party trademarks, fonts, reference material, or
future licensed media.

## Status vocabulary

| Status | Meaning |
| --- | --- |
| `CLEARED_CURRENT` | The exact hashed Tideproof-owned source is cleared for its listed current uses. |
| `CLEARED_INTERIM_ONLY` | The exact source may remain in the public clean-room repository and current local or signed-out proof, but it is not an approved final production brand asset. |
| `PLATFORM_ONLY` | No asset file is redistributed; the runtime uses software already licensed on the viewer or capture system. |
| `TEXT_ONLY_REVIEWED` | A third-party name is used factually in plain text; no logo, trade dress, endorsement, or trademark license is claimed. |
| `SPEC_ONLY` | The asset does not exist and cannot be published. |
| `RIGHTS_PENDING` | A candidate or source may exist, but the required grant and hash lineage are incomplete. |
| `BLOCKED` | The asset or derivative must not enter a public deliverable. |

## Current distributed surfaces

| ID | Exact source and SHA-256 | Owner, creator, and provenance | License or grant | Allowed channels, attribution, and modification state | Review |
| --- | --- | --- | --- | --- | --- |
| `C01` | `web/favicon.svg` — `437fc6278bfb358432cf1b30636dc8f0194351e4fb8f4be77c9c67f79ff02a69` | Tideproof project; newly authored by Nunan in clean-room commit `aea4a29` on 2026-07-30 | Repository MIT license | Public source repository plus current local and signed-out proof only; no attribution required; unmodified at this review. It is an interim wave glyph and does **not** satisfy final asset `V02` or authorize a final branded launch. | Nunan, 2026-07-30 — `CLEARED_INTERIM_ONLY` |
| `C02` | Inline trust-boundary SVG in `web/index.html` — containing-file hash `3168686bc8d4491b864895c386af961de31c25e8a872cb45ec6c54776b4f0372` | Tideproof project; newly authored in the clean-room browser proof beginning at commit `aea4a29` | Repository MIT license | Public source repository, current local proof, signed-out AWS proof candidate, and captures of that exact proof; no attribution required. A standalone or restyled derivative requires its own row and does not yet satisfy `V09`. | Nunan, 2026-07-30 — `CLEARED_CURRENT` |
| `C03` | UI layout, palette, and component styling in `web/styles.css` — `f2189c0630bd99533db82ff4781cf2cb9290a9e56453003cf39fb17ca8715124` | Tideproof project; newly authored in the clean-room repository beginning at commit `e198f41` | Repository MIT license | Public source repository, current local proof, signed-out AWS proof candidate, and captures of that exact proof; no attribution required. No external image, font, or stylesheet is imported. | Nunan, 2026-07-30 — `CLEARED_CURRENT` |
| `C04` | Plain-text `Tideproof` name, UI copy, and synthetic Highwater Drill labels in `web/index.html` and `web/app.js`; file hashes `3168686bc8d4491b864895c386af961de31c25e8a872cb45ec6c54776b4f0372` and `a0d5fdc25c580738cd93cbf1b8b83d4cea9f8571ed9266d7cfa452d48760713f` | Tideproof project; newly authored under the clean-room boundary documented in `CLEAN_ROOM.md` | Repository MIT license for source and copy | Public source repository plus local and signed-out AWS proof surfaces; no third-party artwork or wordmark implied; modifications require claim and name review. | Nunan, 2026-07-30 — `CLEARED_CURRENT` |
| `C05` | CSS generic system stacks: `ui-sans-serif`, `system-ui`, `-apple-system`, `BlinkMacSystemFont`, `"Segoe UI"`, `sans-serif`, `ui-monospace`, `SFMono-Regular`, `Menlo`, `Monaco`, `Consolas`, `monospace` | Platform vendors; Tideproof distributes no font binary, webfont, font subset, or font service request | Viewer or capture-platform software license; no separate Tideproof font grant claimed | Runtime rendering only. A final screenshot or video receipt must name its capture platform; no font file may be bundled without a separate row and license. | Nunan, 2026-07-30 — `PLATFORM_ONLY` |
| `C06` | Plain-text references to CockroachDB, CockroachDB Cloud, Distributed Vector Indexing, Managed MCP, AWS, Amazon Bedrock, Lambda, API Gateway, KMS, IAM, GitHub, and Devpost | Marks and names belong to their respective owners; Tideproof uses them only to identify the contest, verified integrations, or source host | Factual nominative text use; no logo, brand artwork, sponsorship, certification, or ownership claimed | Plain text in repository, local and signed-out proof UI, factual submission copy, and evidence only. Preserve official casing, pair every claim with its evidence boundary, and recheck final contest and brand rules. | Nunan, 2026-07-30 — `TEXT_ONLY_REVIEWED` |
| `C07` | Plain-text `A TrustAgentic.ai project` footer in `web/index.html` — containing-file hash `3168686bc8d4491b864895c386af961de31c25e8a872cb45ec6c54776b4f0372` | Relationship wording approved by Brian and recorded in `docs/VISUAL_RELEASE_SYSTEM.md`; no TrustAgentic asset is embedded or derived | Text-only relationship attribution; no trademark asset license or MIT relicensing claimed | Public source repository plus local and signed-out AWS proof surfaces. Exact text only, no hyperlink, logo, redraw, recolor, halo, chrome, sticker, or implied Northstar release. | Nunan, 2026-07-30 — `TEXT_ONLY_REVIEWED` |

Current surface audit:

- the browser proof loads only local HTML, JavaScript, CSS, the local favicon,
  and local synthetic scenario JSON;
- the architecture graphic is inline project-authored SVG;
- there is no `<img>`, `<picture>`, `<video>`, `<audio>`, remote stylesheet,
  webfont, or external media request in the current proof; and
- the CSS `url()` use is the inline SVG arrow marker, not an external asset;
  the one external GitHub anchor is user-initiated navigation to the public
  source, not an embedded media request.

## Planned assets and hard stops

| Production ID | Required source or derivative | Current rights state | Publish rule |
| --- | --- | --- | --- |
| `V01` | Tideproof wordmark master and PNG export | `SPEC_ONLY` | `BLOCKED` until the Tideproof-owned design, exact hashes, and lettering review have rows here. |
| `V02` | Tideproof mark and required icon exports | `SPEC_ONLY` | `BLOCKED`; do not promote interim `C01` or derive the final mark from a generated wave glyph. |
| `V03` | Official TrustAgentic wordmark; current custodian candidate hash `1d1aec3649f161d7e706c941baa763f73ff480b7ef09072a290373ebf2544b44` | `RIGHTS_PENDING`; not stored in Tideproof | `BLOCKED` until an approved source is used byte-for-byte and a written grant covers every intended channel while excluding the mark from MIT relicensing. |
| `V04` | Owned or licensed ocean master at least `4096 × 2304` | `RIGHTS_PENDING`; no source selected | `BLOCKED` until creator, owner, source, acquisition date, unmodified hash, license or grant, attribution, people/property/trademark review, and allowed channels are recorded. |
| `V05` | Responsive public-site derivatives of `V04` | `SPEC_ONLY` | `BLOCKED` until `V04` is cleared and every derivative has a source-to-output hash chain. |
| `V06` | README hero | `SPEC_ONLY` | `BLOCKED` until all inputs are cleared and the exact output hash and claim review are recorded. |
| `V07` | Open Graph and GitHub social images | `SPEC_ONLY` | `BLOCKED` until all inputs, crops, text, and exact output hashes are cleared. |
| `V08` | Demo title and end cards | `SPEC_ONLY` | `BLOCKED` until final URLs, claims, source assets, and exact output hashes are frozen. |
| `V09` | Standalone architecture SVG and PNG export | `SPEC_ONLY`; current inline source is `C02` | `BLOCKED` until the accessible standalone source, output hash, and architecture review are recorded. |
| `V10` | Release screenshots | `SPEC_ONLY` | `BLOCKED` until captured from the exact public-release commit with platform, viewport, zoom, reduced-motion state, and output hashes recorded. |
| `A01` | Music, narration, voice, captions, and sound effects | No source selected | Default is silence. Any audio or voice requires creator/performer consent, license or grant, source and output hashes, attribution, edit state, and channel rights before private review. |
| `T01` | TrustAgentic.ai production homepage link | Text-only Tideproof attribution is reviewed separately as `C07`; final destination and release state are not yet green | The production homepage link is `BLOCKED` until Tideproof's public destination, repository, claims, rights, and release receipts are all verified. No TrustAgentic logo is authorized under this row. |

The Brian-provided TrustAgentic source board and symbol candidate named in
`docs/VISUAL_RELEASE_SYSTEM.md` remain reference-only. They are not cleared
production assets and must not be copied, traced, regenerated, redrawn,
recolored, relit, repaired, or committed here.

## Final rights freeze

Before private review:

1. Enumerate every media request, embedded image, SVG, font, logo, screenshot,
   video frame, audio track, voice, caption file, and third-party mark on every
   release surface.
2. Hash every source and derivative with SHA-256 and reconcile it to one row.
3. Confirm owner, creator, acquisition date, license or written grant,
   channels, attribution, modification state, and reviewer/date.
4. Keep third-party assets outside the repository MIT grant and include any
   required asset-specific notice.
5. Reject reference-only moodboard material, unapproved generative output,
   missing releases, unverifiable licenses, and hashes that do not match.
6. Record a dated private-review receipt against the exact release commit.

Before public release, every planned asset actually used must be
`CLEARED_CURRENT`, every unused planned asset must be omitted, and no
`RIGHTS_PENDING`, `SPEC_ONLY`, or `BLOCKED` item may appear in a deliverable.
