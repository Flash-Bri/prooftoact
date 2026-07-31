# Local browser accessibility review receipt

- Review date: 2026-07-31
- Command: `npm run accessibility:browser`
- Result: `LOCAL_BROWSER_PASS`
- Browser: `Google Chrome 150.0.7871.187`
- Standard target: `WCAG_2_2_AA`
- Final release ready: `false`
- Static prerequisite: `STATIC_SOURCE_PASS`
- Rights manifest SHA-256:
  `f2499611c166beccbb034e9d8ab98d03484eb665c386ab32756b0e80bf472ae7`

## Exact reviewed source

| Surface | SHA-256 |
| --- | --- |
| `docs/media/architecture.svg` | `5e897dbfd926486203362cf517c967e44d799edbf7f56d1d01b16307ec02724c` |
| `web/app.js` | `f5980c1968417d0c8ebde0256bd56a9f61c6a4c347ccc822839ce8ddb00ecbe2` |
| `web/index.html` | `81b621e6073daa3f465fefe73389719da4c399f1b7a88d5b261cc8fe7a1b07a8` |
| `web/styles.css` | `c33554b39142780f662d9ec5fa8b8c8fd5832eb9c0e4ec5c305ee3a53fd86e9e` |

## Rendered result

- Five required local routes loaded successfully.
- The deliberate favicon omission produced the expected `/favicon.ico` `404`
  and no other browser, runtime, console, or network failure occurred.
- The exact locked `axe-core` 4.12.1 engine ran the selected WCAG 2.0, 2.1,
  and 2.2 A/AA tags at `1440 × 900` and `390 × 844`; it reported 25 and 26
  passed rules respectively, with zero violations and zero unresolved results.
- An earlier same-session scan returned unresolved `aria-prohibited-attr`
  results for the labelled `.hero-facts` and `.presenter-controls` generic
  containers. Both now carry the explicit `group` role, and the final desktop
  and mobile scans report no unresolved results. The verifier now rejects both
  violations and unresolved rule outcomes.
- The exposed accessibility tree contained 303 nodes, nine named headings,
  six named links, and seven exactly named presenter buttons.
- All eight local invariants rendered before playback controls became
  operable.
- The skip link became visible on focus; Arrow Right advanced the proof and
  moved focus to the stage; Home restarted it; act selection and Play/Pause
  kept their labels and `aria-pressed` states synchronized.
- Reduced-motion emulation changed document scrolling to `auto`.
- The `390 × 844` mobile viewport at `2×` device scale produced no page-level
  horizontal overflow, used one act column, and preserved the bounded
  scrollable proof ribbon.

## Acceptance boundary

This receipt proves bounded rendered behavior for the rights-bound current
source in one isolated local headless Chrome run, including a maintained local
rules-engine scan. It is not a WCAG conformance claim, assistive-technology
testing, human usability review, or evidence about the exact deployed public
release. The same automated scan against exact deployed bytes plus
keyboard-only, 200% zoom, mobile, reduced-motion, and screen-reader private
review remain required.
