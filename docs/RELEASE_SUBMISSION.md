# Release submission and eligibility control

**Status: DRAFT SAFELY BLOCKED — FINAL RECEIPTS AND OWNER AUTHORITY PENDING**

This control binds Tideproof's current Devpost draft packet, contest matrix,
release plan, claims boundary, rights ledger, and release-claims inventory to
exact reviewed bytes. It verifies that the public-source draft remains
explicitly incomplete and that every hard publish-gate checkbox remains open.

The control is intentionally non-final. It does not query Devpost, determine
legal eligibility, verify entrant identity or authority, revalidate the
competition pages, prove a live AWS deployment, approve public media, or
authorize publication or submission.

## Current-source contract

`npm run submission:verify` requires all of the following:

- the canonical submission manifest and every listed surface match their
  reviewed SHA-256 digests;
- the draft packet retains its exact `DRAFT — NOT READY TO SUBMIT` status;
- the project name, subtitle, MIT license, and public repository coordinate
  remain exact;
- the official-page check date, official deadline, internal deadline, and
  judge-access horizon remain internally consistent with the contest matrix;
- all 14 hard publish-gate items remain unchecked;
- the exact unresolved stop-token vocabulary is present, with no unknown stop
  token and no missing release dependency;
- live AWS, public demo, public video, final-release commit, final rights,
  post-release roadmap, and owner-confirmation fields remain unresolved;
- the release-claims manifest still binds the exact submission packet and
  remains non-final; and
- the release plan still requires private review, signed-out judge access,
  complete rights, and a timestamped final submission receipt.

The successful current-state receipt is `DRAFT_SAFELY_BLOCKED`. That means the
draft is consistently prevented from becoming a release claim; it is not a
submission-readiness result.

## Final release requirements

Final approval requires a separately reviewed change tied to the exact
official-main commit and deployed artifact hashes. At minimum it must include:

1. accepted live AWS, public-demo, video, and cost receipts;
2. an exact-release private review of claims, privacy, security, accessibility,
   rights, URLs, repository metadata, video, and every submitted field;
3. Brian's or the authorized entrant's explicit eligibility, identity,
   representation, registration, and submission-authority confirmation; and
4. a timestamped receipt of the final Devpost preview, submitted values, public
   URLs, source commit, video, and post-submit signed-out verification.

Any unresolved security, privacy, cost, eligibility, rights, accessibility,
claim, live-evidence, or owner-authority finding keeps publication and
submission blocked.
