# Local three-act judge-path acceptance — `e2b247a`

## Claim boundary

This receipt validates the local, synthetic Tideproof browser proof at exact
commit `e2b247acbd197b2c2ec3d8dc5bc74d214019c764`, tree
`46c9b4441580cc539b808cb719f4d39078663319`.

It does not prove public hosting, signed-out judge access, live AWS behavior,
real emergency suitability, exactly-once external effects, or independent
provider replay. Recorded Gate One links are repository evidence, not live
results from the displayed session.

## Functional acceptance

- 47 of 47 repository tests passed.
- The deterministic scenario returned 12 events and eight of eight scoped
  local checks.
- The persistent strip showed the synthetic disclosure and all three exact
  proof states.
- The interface exposed three acts, act/step progress, Previous, Play/Pause,
  Next, and Restart controls.
- With the architecture region focused, a real Arrow Right keypress moved the
  diagram 40 pixels and did not change the demonstration step. With the judge
  stage focused, the same key advanced the demonstration.
- Act II preserved both exact local operation IDs and linked the recorded
  authority receipt.
- Act III summarized checkpoint plus
  `PROCESS_TERMINATED_AFTER_CHECKPOINT`, the recovery lineage, original replay
  receipt, and `UNKNOWN_DO_NOT_ACT` outage result. Complete event payloads
  remained available in collapsed disclosures.
- Displayed race and recovery events carried both
  `LOCAL DETERMINISTIC REPLAY` and the separate recorded Gate One backing
  label. The nearby boundary said that the displayed event was local.
- The replay step explicitly described its displayed behavior as local, showed
  the separate recorded Gate One backing label, and linked the recorded
  authority receipt.
- Automatic playback announced the act, step, title, and outcome through the
  concise polite status region on every transition.
- Evidence links served the commit-bound Markdown receipts under the same
  restrictive content-security policy.

## Fail-closed surface

Two deliberate failures were exercised.

First, the scenario request was blocked and the page was reloaded.

- The page displayed `UNKNOWN_DO_NOT_ACT`.
- It displayed zero `CHECK PASSED` labels and removed all invariant rows.
- Act and presenter controls were disabled.
- A `Retry local proof` control was available.
- After the request block was removed, Retry restored eight checks and Act I.

Second, an otherwise valid scenario response was intercepted and
`replayDenied` was changed from `true` to `false`.

- The page displayed `UNKNOWN_DO_NOT_ACT` and “The local proof failed
  verification.”
- It exposed exactly one `CHECK FAILED` row naming the duplicate-operation
  invariant and displayed zero `CHECK PASSED` rows.
- Every act and presenter control was disabled.
- The status region announced that one local check failed.
- Restoring the original response restored all eight checks and the
  presentation.

The restored normal path produced no console or failed-resource errors.

## Responsive and text-resize matrix

Test environment:

- Node.js `v22.23.1`
- Google Chrome `150.0.7871.187`
- local clean-room server at `127.0.0.1`

| Test | Document | Stage | Controls | Overflow |
| --- | ---: | ---: | ---: | --- |
| 1,440px viewport | 1,425 / 1,425px | 1,182 / 1,182px | 1,184 / 1,184px | None |
| 390px viewport | 375 / 375px | 353 / 353px | 355 / 355px | None |
| 320px viewport | 305 / 305px | 283 / 283px | 285 / 285px | None |
| 390px + 200% text | 375 / 375px | 333 / 333px | 335 / 335px | None |
| 320px + 200% text | 305 / 305px | 263 / 263px | 265 / 265px | None |

Each pair is client width / scroll width. No presenter button overflowed at
either text size. At 320px with 200% text, the sticky proof strip remained
bounded to 32% of the viewport height: 287px visible for 515px of
keyboard-scrollable content in the 900px test viewport.

The recovery step fell from the prior 1,779px desktop / approximately 2,900px
mobile stage to 1,012px at 1,440px and 1,463px at 320px, while retaining nine
proof-bearing summary fields and the collapsed exact payload.

## Accessibility and trust checks

- The document exposes skip navigation, banner/main/footer landmarks,
  labelled sections, ordered headings, named presenter controls, a named
  current-step article, and a keyboard-scrollable labelled architecture
  region.
- Presenter shortcuts are scoped to the focused judge path or current stage;
  native keyboard behavior elsewhere is not overridden.
- Activating the skip link moved focus to the judge path. At 320px with 200%
  text, its heading began at y=882 below the 288px sticky proof strip.
- The bounded proof strip is explicitly focusable rather than depending on a
  browser-specific overflow-container tab stop.
- One concise polite status region announces load, completion, and failure;
  result lists are not live regions.
- Exact IDs and status/reason codes remain monospace and are not
  title-cased.
- `CHECK PASSED` is separate from domain outcomes such as `EXCLUDED`,
  `DENIED`, and `CONTEXT_ONLY`.
- Focus-visible styling is explicit, and all important text/background pairs
  retain high contrast in the dark technical theme.
- The protected effect is repeatedly limited to a synthetic database sink.

Actual VoiceOver, Firefox, Safari, a physical mobile device, public hosting,
and a signed-out judge journey remain release gates.
