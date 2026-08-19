# Live AWS → CockroachDB judge receipt — 2026-08-19

## Public judge paths

- Judge experience: <https://flash-bri.github.io/prooftoact/>
- Parameter-free receipt: <https://ug5abyn4lg.execute-api.us-east-1.amazonaws.com/api/judge-proof>
- Merged source: [`e800a8592ad5dbcdfaf280da097e68121a386d1f`](https://github.com/Flash-Bri/prooftoact/tree/e800a8592ad5dbcdfaf280da097e68121a386d1f)
- Backend review: [PR #116](https://github.com/Flash-Bri/prooftoact/pull/116)
- Deployed source commit: `0321d498b645e10a993808c36a920958370348ed`
- Immutable Lambda version: `3`

## What was observed

At `2026-08-19T14:10:26.409Z`, a signed-out request with the exact GitHub
Pages origin returned HTTP 200 and a minimized
`prooftoact.public-judge-proof.v1` receipt. The receipt recorded one complete
Managed MCP exchange:

1. initialize: HTTP 200;
2. initialized notification: HTTP 202;
3. fixed `select_query`: HTTP 200;
4. session close: HTTP 204 with `sessionClosed: true`.

The same response reported `LIVE_MANAGED_MCP_READ`, Lambda version `3`, and a
fresh `observedAt`. Response headers included the exact
`Access-Control-Allow-Origin: https://flash-bri.github.io`,
`Cache-Control: no-store`, `Cross-Origin-Resource-Policy: cross-origin`,
`Referrer-Policy: no-referrer`, and `X-Content-Type-Options: nosniff`.

## Exact read boundary

The public handler accepts only `GET /api/judge-proof` with no body and no
query string. It does not accept a caller-supplied cluster, database, SQL
query, tenant, session, or proof identifier. The deployed Lambda issues one
fixed read of the public recovery view, requires exactly one pinned row, and
verifies its P-256 signature before producing the public projection.

The pinned public digests are:

- bundle: `78ad7269424e13785711b5106083a2aac9fbf9f77996f70db4b9e13df869d991`;
- signature: `86315d12c864c4184176bb1d8a0ce071c80e7e14cdccc021f56d4b39eb178947`.

The returned proof boundary is
`HISTORICAL_SIGNED_RECOVERY_CONTEXT_ONLY`. It reports
`authorityTransferred: false` and `requiresFreshAuthorization: true`. This is
a live transport and signed-context read receipt, not a claim that the
historical recovery context authorizes a present action or that the complete
Gate Two authority race is deployed.

## Availability and cost controls

The public route is throttled to a sustained `0.1` requests per second with a
burst of `1`. The Lambda is 128 MiB with a 28-second timeout, and the page
enforces a ten-second retry cooldown. AWS gross-cost alerts are configured at
well below the owner's $50 judging-period ceiling; alerts provide monitoring,
not an absolute billing stop.

## Reproduction

```sh
curl --fail-with-body \
  -H 'Origin: https://flash-bri.github.io' \
  -H 'Accept: application/json' \
  https://ug5abyn4lg.execute-api.us-east-1.amazonaws.com/api/judge-proof
```

Each successful response has a new observation time and response digest. The
public response intentionally excludes credentials, raw SQL, raw provider
session identifiers, and the full database row.
