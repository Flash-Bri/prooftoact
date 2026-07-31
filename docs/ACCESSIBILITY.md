# Accessibility release control

**Status: STATIC SOURCE PASS — BROWSER AND HUMAN REVIEW PENDING**

Recorded: 2026-07-31
Target: WCAG 2.2 Level AA
Reproduce: `npm run accessibility:verify`

This control reviews the exact browser document, stylesheet, application
script, and architecture SVG already bound to
`docs/media/RIGHTS_MANIFEST.json`. It is deliberately narrower than a WCAG
conformance statement. A static source check cannot prove browser behavior,
assistive-technology output, usable reflow at every zoom level, or the quality
of a human keyboard and screen-reader experience.

## Current deterministic result

The verifier returns `STATIC_SOURCE_PASS` only when all of these checks pass:

- English document language, viewport and description metadata, one main
  landmark, one `h1`, ordered headings, labelled sections, unique IDs, and
  resolvable ARIA references;
- a visible-on-focus skip link, non-positive `tabindex` values, named links,
  named and dimensioned images, and seven native presenter buttons bound to
  the proof stage;
- presenter controls that begin disabled, become operable only after the local
  scenario and every invariant pass, and remain disabled on load or
  verification failure;
- arrow, Space, and Home presenter shortcuts scoped to the focused judge path,
  focus movement without forced scrolling, polite status announcements, and
  autoplay pause when the document becomes hidden;
- a global visible focus treatment, a `44px` equivalent minimum control
  height, reduced-motion removal of smooth scrolling, responsive reflow
  guards, and a horizontally scrollable labelled architecture region;
- absence of unsafe dynamic HTML sinks in the browser script; and
- eleven explicit foreground/background checks using the WCAG relative
  luminance formula. Text pairs require at least `4.5:1`; the focus and
  graphical-boundary pairs require at least `3:1`. The current minimum is
  `6.073:1`.

The architecture SVG also requires an intrinsic `title`, `desc`, `role="img"`,
and exact `aria-labelledby` relationship. The browser image retains a separate
plain-language `alt` value.

## Release boundary

`STATIC_SOURCE_PASS` is a partial release receipt. It does not establish WCAG
conformance and it is not permission to publish. Before final release, bind
all of the following to the exact public-release commit and deployed bytes:

1. an automated browser accessibility scan;
2. keyboard-only, `200%` zoom, mobile reflow, and reduced-motion private
   review; and
3. screen-reader review of navigation, the three-act state changes, status
   announcements, exact evidence payloads, and failure states.

Any final screenshot or video still has its own rights, caption, pacing, and
readability gates in `docs/media/RIGHTS.md` and
`docs/VISUAL_RELEASE_SYSTEM.md`.
