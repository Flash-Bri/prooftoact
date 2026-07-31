# Release claim-surface control

**Status: CURRENT PUBLIC CLAIM SURFACES PASS — FINAL LIVE GATES AND PRIVATE REVIEW PENDING**

This control binds the current claim-bearing README, browser, local scenario,
AWS-hosted demo runtime, architecture and AWS boundary ledgers, contest matrix,
video script, and Devpost draft to exact reviewed hashes in
`RELEASE_CLAIMS_MANIFEST.json`.

Run:

```sh
npm run claims:verify
```

The verifier fails closed if a listed surface changes without review, the
claims ledger stops matching `PROOF_MANIFEST.json`, a required synthetic or
local-versus-live boundary disappears, a Devpost stop token is resolved or
removed prematurely, the hard publish checklist is marked complete, or an
unreviewed absolute URL enters the reviewed surfaces.

`CURRENT_PUBLIC_CLAIMS_PASS` is not final publish approval. The current state
deliberately preserves the incomplete live-gate boundary:

- Gate One claims remain limited to their accepted synthetic evidence;
- Gate Two remains a local candidate except for the conditional content-only
  AWS host wording, which proves hosting only when its separate receipt passes;
- no public signed-out demo URL, final video URL, exact release commit, or
  entrant authorization is filled into the Devpost packet;
- the TrustAgentic.ai attribution remains plain text and unlinked until the
  public destination and every release gate are verified.

The control does not prove that a claim is true, discover every possible
overstatement, authorize AWS mutation, establish production suitability, or
replace legal, security, privacy, accessibility, rights, and private human
review. At the final release, every surface and submitted field must be
reviewed again against accepted live receipts and the exact deployed bytes.
