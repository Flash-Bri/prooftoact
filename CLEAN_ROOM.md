# Clean-room and provenance boundary

Established: 2026-07-29, America/New_York.

## Purpose

This repository is a new work created for the CockroachDB × AWS “Build with
Agentic Memory” competition. Its source and fixtures begin here. The project
must remain technically, legally, and operationally isolated from existing
products.

## Allowed inputs

- public contest rules and product documentation;
- public, generally known distributed-systems techniques such as
  idempotency keys, validity windows, provenance, leases, and fencing tokens;
- newly written code, synthetic fixtures, and original project documentation;
- project-specific AWS and CockroachDB credentials created only after explicit
  authorization.

## Prohibited inputs

- Conversate code, assets, customer information, secrets, or infrastructure;
- any proprietary Northstar engine, policy implementation, prompt, schema, or
  undisclosed design;
- copied implementation from another entrant or non-compatible source;
- OpenClaw OAuth tokens or any credential used as Nunan/OpenClaw's model brain;
- real emergency, patient, victim, responder, or location data.

## Current provenance receipt

- All files in the initial scaffold were newly authored on 2026-07-29.
- The scenario uses invented agencies, resources, evidence, and timestamps.
- Runtime dependencies are pinned: `pg`, role-specific AWS SDK clients, and
  the Smithy Node HTTP handler. `esbuild` is a pinned development dependency
  used only to create deterministic Lambda bundles.
- `THIRD_PARTY_NOTICES.txt` is generated from the exact package union present
  in those bundles, records integrity and license-text provenance, and is
  embedded byte-for-byte in every Gate Two ZIP. Five packages whose published
  tarballs omit a standalone license file use explicit, version-pinned family
  or published-README fallbacks.
- The official-main `release:provenance` control binds the complete,
  non-shallow Git ancestry to the initial clean-room root, rejects replacement
  refs, legacy grafts, alternate object databases, tracked symlinks and
  submodules, verifies Git object integrity, and
  compares the clean installed package identities with the exact lock before
  rechecking the inventory and bundle notices. It is an auditable technical
  boundary, not independent proof of originality or legal clearance; the final
  deployed-bundle and submission-freeze review remains required.
- Two project-only CockroachDB Basic clusters and a cluster-scoped Managed MCP
  identity were created under trial credits with finite monthly caps.
- Project secrets remain in the macOS Keychain and are excluded from source,
  fixtures, evidence, and generated bundles.
- The prerequisite AWS bootstrap stack now exists with an account-wide
  monthly budget and a private, encrypted, versioned artifact bucket. It
  contains historical superseded artifact versions only. The main Gate Two
  stack has not been deployed; the repaired candidate remains local until its
  clean commit, immutable artifact versions, and live capability evidence pass
  review.
- The source repository is published at
  `https://github.com/Flash-Bri/tideproof`; no contest submission has been
  published.

The initial local commit used the working names “Highwater” and “BlackBox.”
Public prior-art research performed immediately afterward found unrelated or
overlapping uses, so those names were retired before registration or
publication. The synthetic exercise may still be called the “Highwater Drill,”
but it is not the product or protocol name.

Every future dependency, generated asset, model, dataset, cloud resource, and
pre-existing component must be added to a provenance inventory before public
submission.
