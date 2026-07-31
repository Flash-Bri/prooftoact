# Local browser accessibility review receipt

- Review date: 2026-07-31
- Command: `npm run accessibility:browser`
- Result: `LOCAL_BROWSER_PASS`
- Browser: `Google Chrome 150.0.7871.187`
- Standard target: `WCAG_2_2_AA`
- Final release ready: `false`
- Static prerequisite: `STATIC_SOURCE_PASS`
- Rights manifest SHA-256:
  `798d5608c456bd13f5ff7a6851f498d6fb999b8b78e1d01f245a848946cf5061`

## Exact reviewed source

| Surface | SHA-256 |
| --- | --- |
| `docs/media/architecture.svg` | `5e897dbfd926486203362cf517c967e44d799edbf7f56d1d01b16307ec02724c` |
| `web/app.js` | `f5980c1968417d0c8ebde0256bd56a9f61c6a4c347ccc822839ce8ddb00ecbe2` |
| `web/index.html` | `88a09d45c3468b0049bee70ef84231554cc88f9e3265b9ed21d7326a9839e25a` |
| `web/styles.css` | `c33554b39142780f662d9ec5fa8b8c8fd5832eb9c0e4ec5c305ee3a53fd86e9e` |

## Rendered result

- Five required local routes loaded successfully.
- The deliberate favicon omission produced the expected `/favicon.ico` `404`
  and no other browser, runtime, console, or network failure occurred.
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
source in one isolated local headless Chrome run. It is not a WCAG conformance
claim, a maintained rules-engine scan, assistive-technology testing, human
usability review, or evidence about the exact deployed public release.
Exact-release automated scanning, keyboard-only, 200% zoom, mobile,
reduced-motion, and screen-reader private review remain required.
