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
claims ledger's claim, current-status, required-artifact, or acceptance-condition
column stops matching its exact `PROOF_MANIFEST.json` row binding, a required
synthetic or local-versus-live boundary disappears, a Devpost stop token is
resolved or removed prematurely, the hard publish checklist is marked complete,
or an unreviewed absolute URL enters the reviewed surfaces.

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

## Complete claims-ledger row binding

- **Root cause:** the proof-manifest verifier parsed all four canonical table
  cells but retained and compared only the claim and current-status columns.
  Required-artifact and acceptance-condition drift could pass after refreshing
  the whole-file claims-ledger artifact hash.
- **Why it was missed:** omission tests proved row cardinality, and exact
  comparisons covered the first two columns. The separately hash-bound ledger
  made that partial semantic mapping look complete.
- **Earliest detection point:** change either the third or fourth cell of one
  ledger row, refresh only the claims-ledger artifact hash, and require proof
  verification to fail before provenance, readiness, publication, or
  submission.
- **Repair:** every proof-manifest claim now stores a SHA-256 binding over the
  canonical JSON array of all four exact trimmed cells. The verifier validates
  the digest shape and recomputes it from `CLAIMS.md` in row order.
- **Regression and preventive control:** focused negatives independently alter
  required-artifact and acceptance-condition cells; the manifest schema
  requires the per-row digest and rejects any mismatch.
- **Verification:** focused proof-manifest tests cover both previously ignored
  columns. Full release verification remains required on the exact merged
  commit.
- **Residual risk:** this control proves exact structural agreement, not claim
  truth, Markdown intent beyond the canonical four-cell grammar, provider
  behavior, or publish readiness.
- **Claim impact:** no claim is promoted and no live gate is closed. The change
  removes an internal ledger-mapping gap while preserving every pending-state
  boundary.
