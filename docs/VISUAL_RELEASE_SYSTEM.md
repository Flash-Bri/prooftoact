# ProofToAct visual and release system

Status: CANONICAL DIRECTION — final marketing art has not been produced or
approved.

Originally recorded under the former working name: 2026-07-30.
Amended for the ProofToAct rename and visual separation: 2026-08-03.

This document is the visual source of truth for ProofToAct's website, browser
demo, README, video, wordmark, icons, social preview, and hackathon
submission. It does not override `CLAIMS.md`, `CLEAN_ROOM.md`, the evidence
acceptance rules, or a provider's trademark rules.

## Approved direction

ProofToAct should feel upscale, cohesive, metallic, strong, powerful, premium,
and trustworthy. Its relationship to the parent brand is quiet and exact:

> A TrustAgentic.ai project

ProofToAct's visual language is evidence moving through explicit decision
boundaries: attributed records, admissibility gates, a single committed
authority receipt, and context-only recovery. Prefer owned geometric lines,
ledger grids, proof paths, locks, fences, and exact state transitions. Do not
reuse ocean, tide, wave, shoreline, or beach imagery from the former working
name; that design space is intentionally retired from this project.

TrustAgentic contributes architectural restraint, graphite depth, platinum
materiality, and one warm signal accent. Northstar may inform the sober,
high-trust tone where appropriate, but ProofToAct must not reuse proprietary
Northstar material or imply that it is a Northstar release.

The following are automatic rejects:

- default blue-purple AI gradients;
- glowing brains, robot hands, humanoid agents, or random circuit art;
- stock science-fiction interfaces or decorative fake dashboards;
- pasted-together provider logos or inconsistent illustration styles;
- disaster imagery, frightened people, or emergency voyeurism;
- ocean, tide, wave, shoreline, or beach motifs carried over from the former
  working name;
- unlicensed media, unclear provenance, or a visual that overstates a claim.

## Core visual system

### Color

The existing proof interface establishes the baseline palette. Production
work should refine its material depth without changing the semantic meaning
of evidence states.

| Token | Value | Role |
| --- | --- | --- |
| Ledger black | `#07100c` | Page field and deepest neutral shadow |
| Graphite | `#101a15` | Primary surface |
| Raised graphite | `#17231d` | Raised panels and controls |
| Mineral | `#f5f8f3` | Primary text |
| Brushed silver | `#bdc8c0` | Secondary text and quiet metallic material |
| Verified green | `#9ff0bd` | Verified/pass state only |
| Signal brass | `#ffd28a` | Pending, caution, or constrained proposal |
| Evidence blue | `#9ad7ff` | Recorded evidence and informational links |
| Denial red | `#ffb0b0` | Denial, failure, or invalid state |
| Focus light | `#fff09c` | Keyboard focus only |

TrustAgentic orange remains inside the approved TrustAgentic asset. Do not
sample it into a ProofToAct gradient, recolor the asset, or use it as a broad
ProofToAct theme color.

Metallic character should come from controlled light, fine borders, tonal
depth, and restrained texture on ProofToAct-owned surfaces. Never apply fake
chrome, a black halo, a sticker backing, a glow, or a new gradient to a
TrustAgentic mark.

All final foreground/background pairs must pass WCAG 2.2 AA. Evidence status
must remain legible without color.

### Typography and data

- Keep a precise, contemporary sans-serif for narrative and interface copy.
- Keep a real monospace stack for IDs, hashes, fences, receipts, and states.
- Use weight, spacing, and scale before adding a decorative typeface.
- Do not fetch a new web font until its license, privacy, performance, and
  fallback behavior have passed release review.
- Preserve exact casing for provider names, `TrustAgentic.ai`, receipt states,
  and proof labels.
- A future ProofToAct wordmark must be a reviewed master asset. Do not ask an
  image model to draw lettering or reconstruct a logo from a raster.

### Composition

- Proof remains the foreground; atmosphere remains the background.
- Prefer stable grids, large negative space, strong geometry, and one
  dominant proof transition.
- Use one owned diagrammatic family across website, README, video, and
  submission, derived from the same approved vector master.
- Keep the persistent proof-state ribbon visually stronger than decorative
  media.
- Do not place important text over dense diagrams, animated evidence, or
  high-contrast texture.
- Keep the small parent-brand attribution separate from ProofToAct's own
  wordmark. It must be readable, but never compete with the product name.

### Motion

- Motion should feel deliberate: linear, directional, and commit-like, not
  floaty or frenetic.
- Use motion to reveal hierarchy or a state transition, never to decorate a
  receipt.
- Avoid flashes, rapid zooms, parallax while reading, and perpetual movement
  behind evidence.
- Provide a static first frame and a complete `prefers-reduced-motion`
  experience.
- Pause animation when the document is hidden and keep presenter controls
  keyboard-operable.

## Moodboard acceptance criteria

A reference belongs on the ProofToAct moodboard only when it satisfies every
applicable rule below:

1. It conveys scale, controlled force, resilience, precision, or quiet
   reliability.
2. Its palette can live with Ledger black, Graphite, Mineral, and the semantic
   evidence colors without becoming a blue-purple technology cliché.
3. Its composition leaves usable negative space and remains readable when
   cropped to `16:9`, `1.91:1`, and `4:5`.
4. It communicates evidence, gating, commitment, or recovery without implying
   a capability the product has not proved.
5. It contains no recognizable person, private property, trademark, unsafe
   act, or implied real emergency unless releases and context are explicit.
6. It is either reference-only and labeled as such, or has a documented
   license that covers the public website, repository, video, social preview,
   press, and contest submission.
7. Its creator, source URL or source file, acquisition date, and unmodified
   file SHA-256 can be recorded.
8. It still works without motion and with the proof/safety disclosure present.

Reference-only moodboard images may never leak into a public deliverable.
Before/after treatments must be performed only on owned or licensed masters.

## One system across every surface

| Surface | Required visual behavior |
| --- | --- |
| Website | Proof-first interface, one atmospheric image family at most, persistent safety and evidence state |
| Browser demo | Same palette and typography; state changes, not decoration, carry attention |
| README | One static hero derived from the approved website master, followed immediately by an honest status line |
| Video | Same wordmark, proof labels, type scale, and evidence colors; human-paced cuts follow `DEMO_SCRIPT.md` |
| Social/OG | One thesis, one mark, one restrained image; no unsupported metric or tiny architecture copy |
| Submission | Same cover and naming as the public site; claims copied only from the frozen claims ledger |
| Icons | Derived from one ProofToAct vector master; recognizable at 16 pixels and never confused with TrustAgentic |
| TrustAgentic link | Subtle parent-project attribution; production homepage link is added only after the public destination and repository pass launch review |

The current clean-room browser proof implements the approved relationship as
plain footer text—`A TrustAgentic.ai project`—without a link, logo, recolor, or
derived artwork. That interim text treatment is rights-reviewed in
`docs/media/RIGHTS.md`; it does not clear V03 or authorize the production
TrustAgentic homepage link.

## Exact production asset register

No final marketing asset is authorized merely because it appears in this
register. `SPEC_ONLY` means design work has not begun; `RIGHTS_PENDING` means
the source may not enter the public repository or published media.

| ID and intended path | Exact production specification | Uses | Current state and rights gate |
| --- | --- | --- | --- |
| `V01 web/brand/prooftoact-wordmark.svg` | Transparent SVG master, horizontal `4:1` artboard; outlined or embedded paths only after a lettering review; export `2048 × 512` transparent PNG | Header, README hero, video cards, submission | `SPEC_ONLY`; ProofToAct-owned design and public asset license required |
| `V02 web/brand/prooftoact-mark.svg` | Square SVG master with `1024 × 1024` view box; verified exports at `512`, `192`, `180`, `32`, and `16` px | App icon, favicon, social avatar | `SPEC_ONLY`; deliberately omitted from current release surfaces. Any future mark must derive from V01's system, not from the retired interim wave glyph. |
| `V03 web/brand/trustagentic-wordmark-transparent.png` | Use an approved source asset byte-for-byte; current custodian candidate is `900 × 226`, SHA-256 `1d1aec3649f161d7e706c941baa763f73ff480b7ef09072a290373ebf2544b44` | Small “A TrustAgentic.ai project” attribution and video end card only | `RIGHTS_PENDING`; do not copy into ProofToAct until ProofToAct-specific use and public-repository licensing treatment are recorded |
| `V04 web/media/prooftoact-proof-field.svg` | ProofToAct-owned vector master using only reviewed geometric evidence, gate, fence, receipt, and recovery forms; responsive `16:9` and `4:5` compositions; no provider logos or external media | Website atmosphere, README crop, video establishing frame | `SPEC_ONLY`; must be authored in the clean-room repository and receive exact-hash accessibility, claim, and rights review |
| `V05 web/media/prooftoact-proof-field-*` | V04 deterministic responsive exports; no text baked in; target each raster fallback below `350 KiB` without visible banding | Public website | `SPEC_ONLY`; derivative inherits V04's owned-source hash lineage |
| `V06 docs/media/prooftoact-readme-hero.png` | `1600 × 900`, sRGB, static, with ProofToAct wordmark and short thesis; no metric unless frozen in `CLAIMS.md` | GitHub README and press packet | `SPEC_ONLY`; V01 and V04 must be release-cleared |
| `V07 docs/media/prooftoact-og.png` and `prooftoact-github-social.png` | Open Graph `1200 × 630`; GitHub social preview `1280 × 640`; safe text inset at least `64` px | Link previews and repository social image | `SPEC_ONLY`; V01 and V04 must be release-cleared |
| `V08 docs/media/demo-title.png` and `demo-end.png` | `1920 × 1080`, sRGB, lossless masters; title card identifies a synthetic demo, end card carries verified public URLs and exact evidence state | Demo video | `SPEC_ONLY`; URLs and claims are filled only at release freeze |
| `V09 docs/media/architecture.svg` and `docs/media/architecture.png` | Vector source matching the browser trust-boundary diagram; embedded accessible title and description plus `ARCHITECTURE.md` text counterpart; exact `2200 × 720` PNG export for non-SVG surfaces | Website, README, video | `CLEARED_CURRENT`; SVG SHA-256 `0a35e196d896e932bbadf2afbf5e915c21073c423d9d8ac8a23023ad0887c871`, PNG SHA-256 `6228172f7a5a462940a05543ee455e0de21aa53c805e9466076b9e33fed1f168`; rename/export provenance in `evidence/architecture-asset-rename-2026-08-03.md` and rights in `docs/media/RIGHTS.md` |
| `V10 evidence/release/screenshots/` | Browser captures at `1440 × 900` and mobile `390 × 844`, plus `200%` zoom and reduced-motion states; no browser profile data | README, submission, private review | `SPEC_ONLY`; capture only from the exact public-release commit |
| `V11 docs/media/RIGHTS.md` | One row per public visual with source hash, owner, creator, license/grant, allowed channels, attribution, modification status, and reviewer/date | Release evidence | `ACTIVE BASELINE`; current clean-room surfaces are inventoried, but every pending production asset still fails closed until its row is complete |

The Brian-provided TrustAgentic source board is a reference asset, not a
transparent master: `1448 × 1086`, SHA-256
`fdb14d41236a6eac106887ce05be85bd8cc1da910135d9ffcf2b6f9c80f42c7c`.
The current custodian symbol candidate is `344 × 448`, SHA-256
`e6693445d91e63aa5a84a54d58273a792bdacce88ae8caae15d3872b165c320f`.
Neither file is presently stored in ProofToAct.

If an official vector or layered master supersedes a candidate, record the
new source hash and approval; do not trace, regenerate, redraw, simplify,
recolor, relight, or repair the geometry locally. TrustAgentic assets must
never receive fake chrome, a black halo, or a sticker treatment.

## Rights and provenance gate

Every visual published by ProofToAct must have a row in V11 with:

- final filename and final SHA-256;
- unmodified source filename and SHA-256;
- creator and rights owner;
- license or written grant, including public repository, website, video,
  social, press, and contest-submission use;
- attribution requirement and approved credit line;
- allowed modifications and whether a generative tool was involved;
- source acquisition date and reviewer;
- proof that any people, private property, trademarks, music, voice, fonts,
  and footage are cleared for the intended use.

The repository's MIT license must not silently relicense the TrustAgentic
marks. Before V03 is committed, add an explicit asset notice that keeps those
marks under their owner's terms while preserving the MIT license for
ProofToAct code. Provider logos should be avoided unless official downloads
and current trademark rules make their use necessary and reviewable.

An absent, ambiguous, expired, channel-limited, or non-transferable license is
a release failure. A screenshot of a license page should be retained with the
private release evidence when the terms may change.

## Demo and publish gates

The timed scene map in `DEMO_SCRIPT.md` is required before editing. A video is
not publish-ready until all of the following are true:

1. Every spoken and on-screen claim is backed by the exact release commit and
   frozen claims ledger.
2. Evidence IDs, labels, and diagrams are readable at `1280 × 720` playback
   and remain on screen long enough for a judge to understand them.
3. The pacing is human, captions are corrected manually, and music never
   masks narration or proof.
4. Every image, font, sound, voice, and clip passes the rights gate.
5. A private, unlisted review confirms claim accuracy, accessibility, audio,
   signed-out access, URL correctness, and absence of secrets or personal
   data.
6. Publish readiness is recorded explicitly; private review does not imply
   public approval.

The TrustAgentic.ai homepage link is a launch gate, not a current mutation
task. Do not change the production homepage until ProofToAct is public, the
exact destination and repository are independently verified, all release
gates are green, and rollback ownership is clear.

## Current asset action

No owner asset handoff is required for the rename. Keep the text-only
parent-brand attribution and the current proof-first technical interface.
Any future ProofToAct marketing art must be created from ProofToAct-owned
geometric proof and decision-boundary assets, then pass the exact rights,
accessibility, and claim gates above.
