# Static accessibility review receipt

- Review date: 2026-07-31
- Command: `npm run accessibility:verify`
- Result: `STATIC_SOURCE_PASS`
- Standard target: `WCAG_2_2_AA`
- Final release ready: `false`
- Rights manifest SHA-256:
  `798d5608c456bd13f5ff7a6851f498d6fb999b8b78e1d01f245a848946cf5061`

## Exact reviewed files

| Surface | SHA-256 |
| --- | --- |
| `docs/media/architecture.svg` | `5e897dbfd926486203362cf517c967e44d799edbf7f56d1d01b16307ec02724c` |
| `web/app.js` | `f5980c1968417d0c8ebde0256bd56a9f61c6a4c347ccc822839ce8ddb00ecbe2` |
| `web/index.html` | `88a09d45c3468b0049bee70ef84231554cc88f9e3265b9ed21d7326a9839e25a` |
| `web/styles.css` | `c33554b39142780f662d9ec5fa8b8c8fd5832eb9c0e4ec5c305ee3a53fd86e9e` |

## Changes made before the receipt

- All seven static presenter controls now begin disabled and identify the
  proof stage with `aria-controls`. Verified scenario loading is the only path
  that enables them.
- The polite hidden status is atomic so a complete state update is announced.
- User-started autoplay now pauses and announces the pause when the document
  becomes hidden.

The verifier checked nine headings, five labelled sections, seven controls,
one named image, exact ARIA references, keyboard operation, failure-state
control disabling, focus and motion rules, unsafe dynamic HTML absence, and
eleven contrast pairs. All eleven pairs passed; ratios ranged from `6.073:1`
to `18.010:1`.

## Acceptance boundary

This is a deterministic static-source receipt tied to the current rights
manifest. It is not a WCAG conformance claim and does not prove rendered
browser behavior, assistive-technology behavior, or human usability.
A maintained rules-engine scan plus exact-release keyboard, zoom, reflow,
reduced-motion, and screen-reader review remain required.
