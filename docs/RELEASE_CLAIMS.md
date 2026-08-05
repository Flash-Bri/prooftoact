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
  the whole-file claims-ledger artifact hash. It also removed the first and last
  row characters without first proving that the last character was the
  canonical terminal pipe, accepted empty cells and duplicate claim text, and
  accepted a second canonical table header that could leave a later table
  unexamined. The authority-race schema-copy census also omitted the proof
  manifest itself.
- **Why it was missed:** omission tests proved row cardinality, and exact
  comparisons covered the first two columns. The separately hash-bound ledger
  made that partial semantic mapping look complete. Happy-path parsing assumed
  well-formed Markdown, while count equality did not prove semantic row
  uniqueness and the copy census did not include its own manifest surface.
- **Earliest detection point:** change either the third or fourth cell of one
  ledger row, refresh only the claims-ledger artifact hash, and require proof
  verification to fail before provenance, readiness, publication, or
  submission. Replacing only the terminal pipe with a non-pipe character must
  fail at the row grammar before cell hashing; duplicate claims and empty cells
  plus duplicate canonical tables must fail before manifest mapping; any stale
  authority-race schema in the proof manifest must fail the shared copy-contract
  test.
- **Repair:** every proof-manifest claim now stores a SHA-256 binding over the
  canonical JSON array of all four exact trimmed cells. The verifier validates
  the digest shape, requires four nonempty cells and the canonical terminal
  pipe, requires exactly one canonical table header, rejects duplicate claim
  text, and recomputes the digest from `CLAIMS.md` in row order. The schema-copy
  census now includes `PROOF_MANIFEST.json`.
- **Regression and preventive control:** focused negatives independently alter
  required-artifact and acceptance-condition cells, and separately replace a
  terminal pipe, duplicate a claim or canonical table, and blank each previously
  unchecked cell; the manifest schema requires the per-row digest and rejects
  any mismatch or malformed or ambiguous row. The existing shared-schema test
  now binds the repaired v6 proof-manifest wording.
- **Verification:** focused proof-manifest tests cover both previously ignored
  columns. Full release verification remains required on the exact merged
  commit.
- **Residual risk:** this control proves exact structural agreement, not claim
  truth, semantic completeness beyond unique claim text, Markdown intent beyond
  the canonical four-cell grammar, provider behavior, or publish readiness.
- **Claim impact:** no claim is promoted and no live gate is closed. The change
  removes an internal ledger-mapping gap while preserving every pending-state
  boundary.
