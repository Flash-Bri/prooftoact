# Gate One isolated recovery + Managed MCP evidence — 2026-07-29

> Historical receipt. The human-OAuth and v1 bundle work below remains useful
> setup evidence, but it is superseded for deterministic broker and audit
> claims by
> [`gate1-recovery-broker-2026-07-30.md`](gate1-recovery-broker-2026-07-30.md).
> The later receipt uses a machine credential, signed v2 bundle, fixed-query
> broker, and durable pre-read plus terminal audit events.

## Claim boundary

This receipt supports a narrow claim:

> A CockroachDB Managed MCP session authorized with `mcp:read` retrieved one
> digest-bound, sanitized Tideproof recovery bundle from a physically separate
> CockroachDB Basic cluster. The bundle explicitly transferred no authority
> and required fresh authorization. The same MCP `select_query` surface
> rejected a controlled `UPDATE`.

It does **not** prove that raw Managed MCP is table-scoped, that a model-facing
agent can safely choose SQL, that a successor can authorize an operation, or
that a real-world effect is exactly once. The application design therefore
keeps the raw MCP credential and generic tool inside a deterministic recovery
broker. Bedrock receives only a validated bundle, never the MCP tool or token.

## Recovery cluster

- Cluster: `tideproof-recovery`
- Cluster ID: `24f93c44-fa61-467c-bd3f-a1153618c309`
- Plan: CockroachDB Basic
- Cloud/region: AWS `us-east-1`
- Capacity: 20,000,000 RUs/month and 2 GiB/month
- Hard maximum: $5/month
- Due at creation: $0
- Payment method added: no
- Trial credit observed before creation: $399.87, expiring 2026-08-28
- CockroachDB version at first connection: CCL v26.2.1
- Bootstrap credential: macOS Keychain only; never written to this repository

The recovery cluster has only:

```json
[
  {
    "table_schema": "mcp_private",
    "table_name": "recovery_bundles_v1",
    "table_type": "BASE TABLE"
  },
  {
    "table_schema": "mcp_public",
    "table_name": "recovery_bundle_v1",
    "table_type": "VIEW"
  }
]
```

`defaultdb` contained zero user tables or views when checked. The only other
application database is `tideproof_recovery`.

## Sanitized bundle proof

The July 29 receipt used the then-owner primary connection and predates the
runtime credential-isolation control. It is retained as historical evidence,
not final release proof. The current runner command form is:

```sh
PRIMARY_RECOVERY_SOURCE_DATABASE_URL="<tp_recovery_source_user URL>" \
PRIMARY_AUDIT_DATABASE_URL="<tp_recovery_audit_user URL>" \
RECOVERY_DATABASE_URL="<keychain>" \
npm run gate1:recovery
```

Current-source execution must also supply the exact source binding, endpoint,
cluster, publisher-key, and trust-root inputs required by the runner. The
primary administrator URL is forbidden.

Verified result:

```json
{
  "database": "tideproof_recovery",
  "recoverySessionId": "ff401d32-e517-4114-bc12-faf76172d30d",
  "appendOutcome": "bundle_appended",
  "replayOutcome": "bundle_replay",
  "queryTemplateDigest": "ff527aadb340f3e1e80357e3a30a4952dce7da1bf71ead09d8ecfd7f1557ba3a",
  "recoveryStatus": "RECOVERED_CONTEXT_ONLY",
  "sourceDigest": "2c1d950ee22ca0528331dac538ec2594ef96b03661c519e78b09890b248c666d",
  "bundleDigest": "a84dd62c562d64be7d16fa80f497bbbf2798c0064f9d7a8ead952284a34053a8",
  "authorityTransferred": false,
  "requiresFreshAuthorization": true
}
```

The schema fixes `authority_transferred = false` and
`requires_fresh_authorization = true` with database checks. Application
validation also rejects unexpected columns, unsupported schema versions,
expired rows, session mismatch, digest mismatch, authority transfer, and
secret- or capability-shaped summary fields.

## Model Context Protocol configuration

The Codex operator profile was moved from the primary cluster to the isolated
recovery cluster. It has:

- OAuth scope: `mcp:read`
- cluster header: the recovery cluster ID above
- enabled tools: `select_query` only
- disabled tools: schema browsing, cluster/database/table listing, statement
  inspection, query inspection, `create_database`, `create_table`, and
  `insert_rows`
- OAuth credential store: macOS Keychain

Configuration digest after the change:

```text
752b0c7e2c47c6b57b554180e7ea22ecbe05e067bd6c2298c81cd9eb88c330d0
```

The allowlist reduces accidental operator exposure; it is not treated as a
database table boundary. Physical cluster isolation is the confidentiality
boundary.

## Managed MCP fixed-query read

One ephemeral Codex operator run was instructed to call only
`cockroachdb-cloud/select_query` with the fixed recovery query. Managed MCP
returned exactly one row:

```json
{
  "row_count": 1,
  "recovery_session_id": "ff401d32-e517-4114-bc12-faf76172d30d",
  "bundle_digest": "a84dd62c562d64be7d16fa80f497bbbf2798c0064f9d7a8ead952284a34053a8",
  "authority_transferred": false,
  "requires_fresh_authorization": true
}
```

The returned digest matched the direct database read and the local validator.
The exact parameterized-query template has SHA-256:

```text
ff527aadb340f3e1e80357e3a30a4952dce7da1bf71ead09d8ecfd7f1557ba3a
```

The broker accepts only a strict UUID, substitutes it into that fixed template,
and validates the exact result schema and bundle digest before returning
context.

## Managed MCP write-denial probe

The same operator profile submitted this controlled no-op write through the
only enabled tool:

```sql
UPDATE tideproof_recovery.mcp_private.recovery_bundles_v1
SET policy_version = policy_version
WHERE false
RETURNING recovery_session_id
```

Managed MCP rejected it before execution:

```text
only SELECT statements are allowed, got UPDATE
```

A fresh direct database read after the rejection returned:

```json
{
  "row_count": "1",
  "min_digest": "a84dd62c562d64be7d16fa80f497bbbf2798c0064f9d7a8ead952284a34053a8",
  "max_digest": "a84dd62c562d64be7d16fa80f497bbbf2798c0064f9d7a8ead952284a34053a8"
}
```

One attempted post-probe MCP read was not accepted as evidence because the
ephemeral client supplied the wrong argument field and the server returned
`must contain exactly one statement`. It caused no mutation and is recorded
here to keep the trial history complete.

## Remaining work

- Give the deterministic recovery broker its own noninteractive app identity;
  do not reuse the human Codex OAuth session in the deployed application.
- Write a separate append-only recovery-audit receipt through a narrowly
  scoped primary-cluster identity.
- Prove that the broker exposes no generic query input to Bedrock or the
  successor.
- Run cross-tenant, SQL-injection, stale-bundle, unexpected-column, outage,
  digest-tamper, and replay probes against the deployed broker.
- Keep raw authority receipts, fences, credentials, tokens, and primary data
  out of this cluster.
