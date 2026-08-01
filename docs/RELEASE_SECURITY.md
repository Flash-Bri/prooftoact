# Release security and abuse-boundary control

**Status: CURRENT SOURCE SECURITY PASS — LIVE AND PRIVATE REVIEW PENDING**

Recorded: 2026-08-01
Reproduce: `npm run security:verify`

This control binds the current public runtime, public verifier, AWS template,
proposal/signing/authority runtimes, CockroachDB security bootstrap, Managed
MCP client, local server, and release boundary documents to exact reviewed
hashes in `RELEASE_SECURITY_MANIFEST.json`. It also parses the generated Gate
Two template and rejects drift in the public route set, authentication mode,
throttles, concurrency caps, immutable aliases, versioned artifacts, Lambda
invoke boundaries, and least-privilege role action sets.

`CURRENT_SOURCE_SECURITY_PASS` is a static source and generated-template
receipt. It is not a vulnerability-free claim, a penetration test, proof of
live IAM enforcement, or permission to deploy or publish.

## Protected assets and trust boundaries

| Asset or boundary | Current protection | Remaining release proof |
| --- | --- | --- |
| Signed-out judge surface | Ten enumerated `GET` routes, exact API event validation, no ambient credentials, no CORS, no cookies, strict browser headers, bounded response size, and a logs-only Demo role | Exact deployed-byte, route, header, throttle, IAM, abuse, and signed-out review |
| Advisory proposal | One `AWS_IAM` `POST /advisory` route, one immutable coordinator alias, exact dedicated-role STS principal validation, schema-bound input, one bounded Bedrock model, and an explicitly untrusted proposal | Live dedicated-role allow plus alternate-principal denial receipts, model invocation receipt, and private payload/log review |
| Receipt signing | One P-256 `SIGN_VERIFY` KMS key, digest-only ECDSA signing, one immutable signer alias, and no model, secret, or arbitrary Lambda capability | Live key-policy, public-key, sign/verify, direct-invoke-denial, and teardown receipts |
| Authority spend | One exact project secret ARN and `AWSCURRENT` VersionId, exact Cockroach host/port, `sslmode=verify-full`, bounded database timeouts, derived operation fields, a two-contender typed `SECURITY DEFINER` wrapper, serializable one-winner logic, and no model/signing/arbitrary-Lambda capability. The evidence runner rejects endpoint/profile/proxy/CA and Git-object indirection, resolves the expected caller role from CloudFormation, and binds the observed STS caller triple before invocation. Its validator now requires positive-duration transactions with a positive overlap interval, an initial fence of one, a canonical lease later than the winning commit and still active at the durable observation, and the exact unmodified in-process race observation. | Live secret/version/endpoint/IAM audit, overlapping two-Lambda race, ambiguous-commit behavior, private raw STS receipt, and later read-only durable-state reconciliation |
| CockroachDB memory and recovery | Pre-mutation reused-cluster posture checks reject unsafe role options, external/admin memberships, system grants, and out-of-scope grants; managed privileges are scrubbed and rebuilt through NOLOGIN capability roles. Runtime URLs cannot override the reviewed query/statement/idle timeouts. Managed MCP uses one fixed query bound to the exact tenant, run, incident, evidence, resource, operation, request digest, outcome, and successor principal; it has no recency fallback, rejects redirects, caps streamed responses at 256 KiB, decodes UTF-8 fatally, requires exact-one cardinality, and releases context only after both audits. | Disposable-cluster validation against the exact CockroachDB Cloud version, final grants/options/membership inventory, MCP audit, credential isolation, and private human review |
| Repository and evidence | Exact dependency lock, bundle notices, full-history provenance, bounded privacy scan, claim ledger, and proof manifest | Final official-main rerun plus private review of repository, receipts, screenshots, video, URLs, and submission fields |

## Threat and abuse cases

The current source control checks these bounded cases without claiming live
enforcement:

- **Route expansion or method confusion:** any public route outside the ten
  exact `GET` routes fails; the advisory route remains `AWS_IAM`; public
  handler events must bind API ID, `$default` stage, method, route key, path,
  and an empty body.
- **Browser-origin abuse:** the public runtime returns a self-only CSP, blocks
  framing, objects, forms, ambient CORS, cookies, referrers, powerful browser
  features, and MIME sniffing. The live verifier must repeat both positive and
  negative probes against the final URL.
- **Public cost amplification:** API Gateway and Lambda concurrency are
  bounded, the Demo timeout is five seconds, logs expire after seven days,
  and the demo cannot invoke Bedrock, KMS signing, secrets, other Lambdas, IAM,
  or STS. These controls reduce exposure; they do not promise availability or
  complete denial-of-service protection.
- **Capability crossing:** proposal, coordination, signing, authority, and
  public-demo roles have distinct exact allow sets plus explicit critical
  denials. Published versions and `proof` aliases prevent mutable `$LATEST`
  targets from being the intended path.
- **Secret or transport weakening:** the authority runtime accepts one exact
  secret shape, exact `AWSCURRENT` VersionId, and a
  `tp_gate2_authorizer_user`
  CockroachDB URL with the configured host/port and only
  `sslmode=verify-full`; the Managed MCP client uses the fixed Cockroach Cloud
  endpoint, rejects redirects, bounds requests and streamed response bytes,
  rejects invalid UTF-8, and validates response IDs. Database runtime URLs
  reject timeout/application override parameters and ambient libpq control
  variables; migration clients use a separate, longer bounded profile.
- **Database actor and name resolution:** Gate One and Gate Two use separate
  database users and roles. The Gate Two role can execute only its fixed-two-
  contender wrapper plus the exact read-only resolver/observer, while explicit
  cross-grant and cross-membership revocations deny direct Gate One spend; the
  Gate One role cannot execute the Gate Two wrapper. Both spend contracts use
  `session_user`, not a caller-supplied authenticated-agent duplicate. All
  application relations and nested application functions in primary/recovery
  `SECURITY DEFINER` bodies are schema-qualified. CockroachDB v26.2 has no
  documented function-level `SET search_path`, so each database credential
  remains an authority capability within its grant surface and live
  grant/session review remains required.
- **Dirty or reused database state:** both security bootstraps inventory the
  managed users, roles, memberships, system grants, and object grants before
  changing credentials, ownership, or grants. Unknown options, external or
  admin memberships, system privileges, and out-of-scope grants fail closed.
  Managed-scope grants are broadly revoked from runtime roles and users,
  capability roles are forced to `NOLOGIN`, only exact memberships are
  rebuilt, and a post-attestation digest is returned. Catalog formatting,
  membership propagation, and convergence still require a live disposable-
  cluster test on the exact provider version.
- **Replay, ambiguous commit, and inherited authority:** these are enforced by
  the accepted Gate One transaction/recovery controls and the local Gate Two
  candidate. The static security gate binds those sources but does not upgrade
  them into a live AWS or exactly-once external-effect claim.
- **Evidence or claim substitution:** exact hashes, generated-template
  equality, immutable artifact versions, build bindings, privacy review, and
  the proof manifest make drift visible. A hash is provenance, not proof that
  its contents are safe or true.

The template currently uses one API/stage/method-scoped `GET/*` Lambda
permission for non-root demo paths. That permission is layered behind the
template's exact API Gateway route inventory and the Demo handler's exact
event/path allowlist. The release verifier records this boundary explicitly;
it must not be described as ten path-specific Lambda permission resources.

## Explicit non-proofs

This automated control does not establish:

- absence of vulnerabilities, malicious dependencies, side channels, denial
  of service, or every credential and privacy pattern;
- live AWS IAM, API Gateway, Lambda, KMS, Secrets Manager, Bedrock,
  CloudWatch, or CockroachDB enforcement;
- production security, operational emergency suitability, exactly-once
  real-world effects, or a service-level objective;
- independent penetration testing, legal clearance, WCAG conformance, or
  human review of the final demo, video, and submission; or
- authorization to upload artifacts, create a change set, deploy, publish, or
  submit.

## Final release gate

Before public release, rerun this control on exact official `main`, bind its
receipt to the exact deployed bundle and public URL, and preserve accepted live
receipts for IAM allow/deny behavior, API routes and headers, throttles,
concurrency, KMS, the one bounded model call, the authority race, durable-state
reconciliation, logs, cost controls, and teardown.

Before any release deployment, seed a disposable CockroachDB cluster with a
login-capable owner, stale direct runtime-user grant, unrelated inherited
role, and system privilege. The bootstrap must reject unsafe posture before
credential mutation; after explicit cleanup, an idempotent rerun must attest
the exact options, memberships, grants, timeouts, and private-schema denial.

A separate private human security and abuse review must inspect the deployed
application, repository metadata, CloudFormation change set, IAM policies,
database grants, logs, receipts, screenshots, video, public URLs, and every
Devpost field. Any unresolved security, privacy, cost, eligibility, or claim
finding keeps release and submission blocked.
