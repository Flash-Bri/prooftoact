# Release privacy and secret review

**Status: CURRENT PUBLIC HISTORY AUTOMATED PASS — FINAL PRIVATE REVIEW PENDING**

ProofToAct treats repository privacy as a fail-closed release control. The
automated verifier scans every current tracked file and every size-bounded Git
blob reachable from the checked-out commit. It rejects credential-like tracked
paths and checks a bounded set of high-confidence signatures for private keys,
provider tokens, authenticated database URLs, bearer tokens, private home
paths, private IPv4 addresses, email addresses, and AWS account identifiers.

`RELEASE_PRIVACY_MANIFEST.json` contains only exact SHA-256 allowances for the
reviewed upstream attribution and synthetic fixtures that intentionally match
those signatures. It also stores reviewed commit-identity digests rather than
redisplaying identity values. A new finding, identity, path, oversized blob,
shallow checkout, dirty tree, stale allowance, or malformed manifest fails the
gate.

The exact Gate Two v9 build applies a second boundary to generated outputs.
Its receipt enumerates every one of the 21 template, Lambda, evidence-provider,
and live-drill runtime files by path, byte count, and SHA-256. It scans the 20
non-Node outputs with the same bounded signature rules and permits only
already-reviewed public upstream attribution hashes. The remaining file is an
official Node v22.23.1 executable: the build accepts only one of the pinned
nodejs.org release digests for the exact supported platform and records its
byte count as a pinned toolchain exemption, not as scanned content. Readiness
recomputes the inventory, all file digests, the scan result, and the exemption.
An unpinned Node binary, missing output, added output, stale count, changed
byte, or non-attribution finding fails closed.

Run:

```sh
npm run privacy:verify
```

The resulting `CURRENT_PUBLIC_HISTORY_PASS` receipt is deliberately bounded.
It does not prove the absence of every possible secret or personal-data form,
does not inspect unreachable Git objects or external services, and does not
authorize publication. The final release still requires:

1. an exact official-main rerun bound to hosted CI and deployed hashes; and
2. a private human review of repository bytes, metadata, live receipts,
   generated output inventory (including the pinned Node executable),
   screenshots, video, public URLs, and every Devpost field.

If the automated gate finds an actual secret, stop publication, revoke or
rotate the project-only credential before sharing details, remove the exposed
value from every relevant public surface, and preserve a sanitized incident
receipt. Do not weaken a rule or add an allowance merely to make CI pass.
