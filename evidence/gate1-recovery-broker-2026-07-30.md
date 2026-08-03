# Gate One deterministic Managed MCP recovery broker — 2026-07-30

## Claim boundary

This receipt supports the following narrow synthetic claim:

> A deterministic Tideproof broker committed a primary-cluster pre-read audit
> event, made exactly one machine-authenticated CockroachDB Managed MCP
> `select_query` call pinned to a physically separate recovery cluster and an
> exact query template, validated one fresh P-256-signed sanitized bundle, then
> committed a terminal result-bound audit event before releasing context. The
> returned context explicitly transferred no authority and exposed no
> operation ID, effect key, or fencing token. An unbound synthetic principal
> failed closed before MCP.

This does **not** prove production identity verification, KMS-backed publisher
keys, deployed AWS IAM separation, provider-attested service-account scope,
availability, real-world external effects, or suitability for emergency use.
The service-account key remains capable of whatever its Cockroach Cloud IAM
role permits if it is removed from this fixed broker, so physical recovery
cluster isolation remains part of the confidentiality boundary.

## Environment

- Primary cluster ID: `4bd5f0c9-729a-468e-b47c-5c5ed9cd41f9`
- Recovery cluster ID: `24f93c44-fa61-467c-bd3f-a1153618c309`
- Both clusters: CockroachDB Basic, AWS `us-east-1`
- Recovery cluster hard maximum: $5/month
- Managed MCP database: `tideproof_recovery`
- Managed MCP tool: `select_query`
- MCP protocol version: `2025-03-26`
- Authentication: noninteractive Cockroach Cloud service-account API key
- Secret custody during this gate: macOS Keychain; no secret was written to
  the repository or receipt
- Source implementation: Git commit
  `55892bf25a5286af30e30908ab5711e24f106629`
- Synthetic publisher key: ephemeral P-256 gate key, not a durable trust root;
  the exact public-key set is bound by digest in the broker configuration

The primary and recovery connection URLs resolved to distinct expected
hostnames, and the configured cluster IDs were distinct. This is
application-checked endpoint separation, not provider attestation.

## Local hardening checks

Command:

```sh
npm test
```

Result: 31 tests passed, 0 failed.

The suite includes:

- exact MCP protocol-version negotiation;
- JSON-RPC 2.0 response validation;
- redirect rejection;
- exact cluster, database, tool, and query-template binding before network
  access;
- P-256 curve pinning, including rejection of a P-384 key mislabeled as
  P-256;
- signed bundle, digest, freshness, source-cluster, tenant, session, and
  subject binding;
- structured fail-closed handling for invalid principals, resolver failures,
  MCP failures, absent/null broker input, and audit failures;
- pre-read audit-before-MCP ordering;
- context withholding when either the pre-read or terminal audit cannot commit;
- result binding when an observed MCP row fails signature validation.

## Live capability and audit schema gate

Historical July 30 command form (not executable against the current source):

```sh
DATABASE_URL="<primary admin URL from Keychain>" \
TIDEPROOF_TP_INGEST_USER_PASSWORD="<Keychain>" \
TIDEPROOF_TP_AUTHORIZER_USER_PASSWORD="<Keychain>" \
TIDEPROOF_TP_DISPATCH_USER_PASSWORD="<Keychain>" \
TIDEPROOF_TP_RECOVERY_AUDIT_USER_PASSWORD="<Keychain>" \
TIDEPROOF_TP_AUDIT_USER_PASSWORD="<Keychain>" \
npm run gate1:security
```

Exit status: 0.

The current source requires additional split-principal passwords, trust-root
inputs, and exact source bindings enumerated in `docs/FULL_DRILL_EVIDENCE.md`.
Do not reconstruct a current invocation from this historical receipt.

Relevant verified outcomes:

```json
{
  "gate": "primary-capability-boundaries",
  "passed": true,
  "recoveryAudit": {
    "directBaseRead": {
      "denied": true,
      "sqlstate": "42501"
    },
    "directV3Insert": {
      "denied": true,
      "sqlstate": "42501"
    },
    "legacyV1AndV2FunctionsDenied": true,
    "exactEventReplayReturnedOriginalId": true,
    "changedEventReplay": {
      "denied": true,
      "sqlstate": "22000"
    },
    "changedFieldWithOldDigestDenied": true,
    "orphanTerminalDenied": true
  }
}
```

The runtime audit identity has function-shaped append authority but no direct
base-table read or write authority. Audit-v3 identifies one interaction and
permits exactly one `pre_read` and one `terminal` phase. Reusing an event ID or
interaction phase with a different digest or any changed field is rejected.
A terminal event must match an existing pre-read event’s tenant, interaction,
session, subject, tool, cluster, broker configuration, query template, bound
input, and start time. The obsolete v1/v2 audit functions are not executable
by the runtime audit role.

## Live deterministic broker gate

The July 30 receipt predates the source-principal split and is retained as
historical evidence, not final release proof. The historical invocation excerpt
below is intentionally incomplete for the current source; the authoritative
current input contract is `docs/FULL_DRILL_EVIDENCE.md`.

```sh
PRIMARY_RECOVERY_SOURCE_DATABASE_URL="<tp_recovery_source_user URL from Keychain>" \
RECOVERY_PUBLISHER_DATABASE_URL="<recovery publisher URL from Keychain>" \
PRIMARY_AUDIT_DATABASE_URL="<tp_recovery_audit_user URL from Keychain>" \
MCP_API_KEY="<service-account key from Keychain>" \
SOURCE_BUILD_IDENTITY="55892bf25a5286af30e30908ab5711e24f106629" \
PRIMARY_CLUSTER_ID="4bd5f0c9-729a-468e-b47c-5c5ed9cd41f9" \
RECOVERY_CLUSTER_ID="24f93c44-fa61-467c-bd3f-a1153618c309" \
EXPECTED_PRIMARY_HOSTNAME="<expected primary hostname>" \
EXPECTED_RECOVERY_HOSTNAME="<expected recovery hostname>" \
npm run gate1:recovery-broker
```

The primary administrator URL is forbidden. Final provider proof must include
the source and audit credentials' SQLSTATE `42501` results for all six
privilege-pure trust-root write probes and all 18 managed base-table read
probes.

Exit status: 0.

Verified receipt:

```json
{
  "gate": "noninteractive Managed MCP deterministic recovery broker",
  "passed": true,
  "endpointSeparation": {
    "distinctHostnames": true,
    "distinctClusterIds": true
  },
  "recoverySessionId": "df199e9e-ebcd-4eb9-9d71-d2ccb063f94c",
  "tenantId": "886530a3-699c-4a23-90b5-d7a8e17bb422",
  "appendOutcome": "bundle_appended",
  "replayOutcome": "bundle_replay",
  "mcpTool": "select_query",
  "mcpCallCount": 1,
  "queryTemplateDigest": "a2aaf3df68631b734473b4e5085367c2b42a03b0278f17bf590c4eede8f86ab8",
  "brokerConfigDigest": "bd1ae1c147b3bd0ea7b3d551a5a0ec8756825ba0b303014bcf5b934c75829a00",
  "sourceBuildIdentity": "55892bf25a5286af30e30908ab5711e24f106629",
  "publisherKeySetDigest": "2cffc9baa7483aae090ef75242fa65db963ae26aaf78f1522095a63c31e19b3d",
  "recoveryStatus": "RECOVERED_CONTEXT_ONLY",
  "unauthorizedStatus": "UNKNOWN_DO_NOT_ACT",
  "sourceDigest": "6aac30b90f3dd5943f9d09790e9b8ca48d04ce784cd9e4f02d41eb11d8c7b5c4",
  "bundleDigest": "15fdef2ee344791aa28152dc3769b4f978dd3f5e405e7f6e6f2599b338e8c860",
  "auditInteractionId": "e729df46-cda9-4c0d-b71d-f95146b71568",
  "preReadAuditId": "dbb18bcd-34ae-4260-9118-94fe2cf989a4",
  "terminalAuditId": "5ddfbc05-2547-4c31-911a-0c517a5949b2",
  "preReadAuditCommitted": true,
  "terminalAuditCommitted": true,
  "boundInputDigest": "9ba80252936bc5834859e24c7c46fe50ed4f9c9c15b3f27079cc16aa43e1a221",
  "resultDigest": "d33028ed6491f45ad5c3252b9f8d67a36273645a965dd8f553c67fe478712393",
  "authorityTransferred": false,
  "requiresFreshAuthorization": true,
  "operationalCapabilitiesReturned": false
}
```

The gate independently read both primary-cluster audit events and asserted:

- the same interaction, tenant, session, subject hash, recovery cluster,
  broker configuration, query-template digest, and bound-input digest;
- a `pre_read` event with outcome `read_authorized`, no result digest, and no
  source watermark;
- a `terminal` event with the independently recomputed MCP result digest and
  exact source watermark;
- a recomputed event digest matching each stored event;
- a broker-configuration digest binding the exact source commit, MCP protocol,
  audit schema, validator version, query template, clusters, tool, database,
  and ephemeral publisher-key-set digest;
- terminal context was returned only after both append calls succeeded.

The unauthorized synthetic principal returned `UNKNOWN_DO_NOT_ACT`. The total
MCP call count remained one, proving that attempt did not reach MCP in this
run.

## Failed run retained as evidence

The first audit-v3 broker run failed its terminal source-watermark assertion.
The source receipt was a JavaScript `Date`; `Date.parse(dateObject)` coerced it
through a string format that dropped milliseconds. The broker gate stopped
after the terminal audit check and did not accept the run as proof. The
fixture was corrected to use `new Date(value).getTime()`, an explicit
finite-time assertion was added, and a fresh bundle/session produced the
passing receipt above.

## Remaining release gates

- Verify production caller identity from a signed AWS authentication context;
  never accept a model-supplied principal.
- Put publisher, broker, audit, authority, and effect capabilities behind
  separate AWS runtime identities.
- Replace the ephemeral gate signer with a KMS-backed durable publisher key
  and prove rotation/revocation behavior.
- Produce provider-visible IAM evidence for the MCP service account and retain
  physical recovery-cluster isolation.
- Prove Bedrock has no MCP key, database credential, publisher key, or
  authority/effect tool.
- Keep claims limited to synthetic context recovery. No exactly-once
  real-world effect claim is supported.
