import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { buildGate2Template } from "../src/cloud/aws-gate2-template.js";
import { PUBLIC_DEMO_PATHS } from "../src/cloud/public-demo.js";
import { __test as publicDemoVerifierContract } from "../src/cloud/public-demo-verifier.js";

const DEFAULT_ROOT = fileURLToPath(new URL("..", import.meta.url));
const MANIFEST_PATH = "RELEASE_SECURITY_MANIFEST.json";
const MANIFEST_SCHEMA = "tideproof.release-security-manifest.v1";
const MANIFEST_STATUS =
  "CURRENT_SOURCE_SECURITY_REVIEWED_FINAL_LIVE_GATES_PENDING";
const RECEIPT_SCHEMA = "tideproof.release-security-verification.v1";
const HEX_64 = /^[0-9a-f]{64}$/;

const EXPECTED_FINAL_RELEASE_REQUIREMENTS = Object.freeze([
  "Exact-release live receipts for IAM allow and deny behavior, API routes and headers, throttles, concurrency, KMS, the bounded model call, the authority race, durable-state reconciliation, logs, cost controls, and teardown.",
  "Separate private human security and abuse review of the exact deployed application, repository metadata, CloudFormation change set, IAM policies, database grants, logs, receipts, media, public URLs, and submission fields."
]);

const EXPECTED_SURFACES = Object.freeze({
  "admissible-vector-retrieval": Object.freeze({
    path: "src/cloud/admissible-vector-retrieval.js",
    role: "INTEGRATED_ADMISSIBLE_VECTOR_RUNTIME"
  }),
  "admissible-vector-runner": Object.freeze({
    path: "scripts/gate1-admissible-vector.js",
    role: "ADMISSIBLE_VECTOR_EVIDENCE_RUNNER"
  }),
  "authority-identity-contract": Object.freeze({
    path: "src/cloud/authority-identity.js",
    role: "AUTHORITY_IDENTITY_CONTRACT"
  }),
  "authority-identity-ledger": Object.freeze({
    path: "docs/AUTHORITY_IDENTITY.md",
    role: "AUTHORITY_IDENTITY_BOUNDARY"
  }),
  "authority-identity-tests": Object.freeze({
    path: "test/authority-identity.test.js",
    role: "AUTHORITY_IDENTITY_VERIFICATION"
  }),
  "authority-runtime": Object.freeze({
    path: "infra/aws/lambda/authority.cjs",
    role: "AWS_AUTHORITY_RUNTIME"
  }),
  "authority-store": Object.freeze({
    path: "src/cloud/authority-store.js",
    role: "PRIMARY_AUTHORITY_STORE"
  }),
  "aws-authority-race": Object.freeze({
    path: "scripts/gate2-authority-race.js",
    role: "AWS_AUTHORITY_EVIDENCE_RUNNER"
  }),
  "aws-authority-race-validator": Object.freeze({
    path: "src/cloud/aws-authority-race.js",
    role: "AWS_AUTHORITY_EVIDENCE_VALIDATOR"
  }),
  "aws-boundary-ledger": Object.freeze({
    path: "docs/AWS_GATE2.md",
    role: "AWS_SECURITY_BOUNDARY"
  }),
  "aws-evidence-identity": Object.freeze({
    path: "src/cloud/aws-evidence-identity.js",
    role: "AWS_EVIDENCE_IDENTITY_BOUNDARY"
  }),
  "aws-preflight": Object.freeze({
    path: "scripts/gate2-aws-preflight.js",
    role: "READ_ONLY_AWS_PREFLIGHT"
  }),
  "aws-readiness": Object.freeze({
    path: "scripts/gate2-aws-readiness.js",
    role: "EXACT_CHECKOUT_READINESS"
  }),
  "aws-template-generated": Object.freeze({
    path: "infra/aws/gate2-template.json",
    role: "GENERATED_CLOUDFORMATION"
  }),
  "aws-template-source": Object.freeze({
    path: "src/cloud/aws-gate2-template.js",
    role: "CLOUDFORMATION_SOURCE"
  }),
  "boundary-runtime": Object.freeze({
    path: "infra/aws/lambda/boundary.cjs",
    role: "AWS_COORDINATOR_RUNTIME"
  }),
  "database-runtime": Object.freeze({
    path: "src/cloud/database-runtime.js",
    role: "DATABASE_RUNTIME_BOUNDARY"
  }),
  "database-security-posture": Object.freeze({
    path: "src/cloud/database-security-posture.js",
    role: "DATABASE_POSTURE_BOUNDARY"
  }),
  "demo-entry": Object.freeze({
    path: "infra/aws/lambda/demo.js",
    role: "AWS_PUBLIC_ENTRY"
  }),
  "local-server": Object.freeze({
    path: "src/server.js",
    role: "LOOPBACK_DEVELOPMENT_SERVER"
  }),
  "managed-mcp-client": Object.freeze({
    path: "src/cloud/managed-mcp-client.js",
    role: "RECOVERY_MCP_CLIENT"
  }),
  "primary-security-bootstrap": Object.freeze({
    path: "src/cloud/primary-security.js",
    role: "PRIMARY_DATABASE_SECURITY"
  }),
  "protocol-runtime": Object.freeze({
    path: "src/protocol.js",
    role: "LOCAL_PROTOCOL_SPECIFICATION"
  }),
  "proposal-runtime": Object.freeze({
    path: "infra/aws/lambda/agent.cjs",
    role: "AWS_PROPOSAL_RUNTIME"
  }),
  "public-demo-runtime": Object.freeze({
    path: "src/cloud/public-demo.js",
    role: "AWS_PUBLIC_RUNTIME"
  }),
  "public-demo-verifier": Object.freeze({
    path: "src/cloud/public-demo-verifier.js",
    role: "LIVE_PUBLIC_VERIFIER"
  }),
  "recovery-security-bootstrap": Object.freeze({
    path: "src/cloud/recovery-security.js",
    role: "RECOVERY_DATABASE_SECURITY"
  }),
  "recovery-broker": Object.freeze({
    path: "src/cloud/recovery-broker.js",
    role: "RECOVERY_BROKER_RUNTIME"
  }),
  "recovery-broker-runner": Object.freeze({
    path: "scripts/gate1-recovery-broker.js",
    role: "RECOVERY_BROKER_EVIDENCE_RUNNER"
  }),
  "recovery-evidence-runner": Object.freeze({
    path: "scripts/gate1-recovery.js",
    role: "RECOVERY_EVIDENCE_RUNNER"
  }),
  "recovery-store": Object.freeze({
    path: "src/cloud/recovery-store.js",
    role: "RECOVERY_STORE_RUNTIME"
  }),
  "release-security-ledger": Object.freeze({
    path: "docs/RELEASE_SECURITY.md",
    role: "SECURITY_CONTROL_LEDGER"
  }),
  "security-policy": Object.freeze({
    path: "SECURITY.md",
    role: "VULNERABILITY_POLICY"
  }),
  "signed-ingest": Object.freeze({
    path: "src/cloud/signed-ingest.js",
    role: "SIGNED_EVIDENCE_INGEST"
  }),
  "signer-runtime": Object.freeze({
    path: "infra/aws/lambda/signer.cjs",
    role: "AWS_SIGNING_RUNTIME"
  })
});

const EXPECTED_PUBLIC_PATHS = Object.freeze([
  "/",
  "/app.js",
  "/styles.css",
  "/architecture.svg",
  "/api/health",
  "/api/scenario",
  "/evidence/gate1-authority",
  "/evidence/gate1-recovery",
  "/evidence/gate1-ambiguity",
  "/claims"
]);

const EXPECTED_SECURITY_HEADERS = Object.freeze({
  "content-security-policy": [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self'",
    "connect-src 'self'",
    "img-src 'self'",
    "font-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
    "upgrade-insecure-requests"
  ].join("; "),
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
  "permissions-policy":
    "camera=(), geolocation=(), microphone=(), payment=(), usb=()",
  "referrer-policy": "no-referrer",
  "strict-transport-security": "max-age=31536000",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "x-permitted-cross-domain-policies": "none"
});

const EXPECTED_NEGATIVE_PROBES = Object.freeze([
  Object.freeze({ method: "GET", path: "/__tideproof_not_found__" }),
  Object.freeze({ method: "GET", path: "/favicon.svg" }),
  Object.freeze({ method: "HEAD", path: "/" }),
  Object.freeze({ method: "POST", path: "/api/scenario" }),
  Object.freeze({ method: "GET", path: "/advisory" }),
  Object.freeze({ method: "POST", path: "/advisory" })
]);

const EXPECTED_ROLE_ALLOW_ACTIONS = Object.freeze({
  AdvisoryCallerRole: Object.freeze(["execute-api:Invoke"]),
  AgentRole: Object.freeze([
    "bedrock:InvokeModel",
    "logs:CreateLogStream",
    "logs:PutLogEvents"
  ]),
  AuthorityRaceCallerRole: Object.freeze([
    "cloudformation:DescribeStackResource",
    "lambda:InvokeFunction"
  ]),
  AuthorityRole: Object.freeze([
    "logs:CreateLogStream",
    "logs:PutLogEvents",
    "secretsmanager:GetSecretValue"
  ]),
  BoundaryRole: Object.freeze([
    "kms:GetPublicKey",
    "lambda:InvokeFunction",
    "logs:CreateLogStream",
    "logs:PutLogEvents"
  ]),
  DemoRole: Object.freeze([
    "logs:CreateLogStream",
    "logs:PutLogEvents"
  ]),
  SignerRole: Object.freeze([
    "kms:GetPublicKey",
    "kms:Sign",
    "kms:Verify",
    "logs:CreateLogStream",
    "logs:PutLogEvents"
  ])
});

const REQUIRED_DENY_ACTIONS = Object.freeze({
  AdvisoryCallerRole: Object.freeze([
    "bedrock:InvokeModel",
    "iam:*",
    "kms:Sign",
    "lambda:InvokeFunction",
    "secretsmanager:GetSecretValue",
    "sts:AssumeRole"
  ]),
  AgentRole: Object.freeze([
    "iam:*",
    "kms:Sign",
    "lambda:InvokeFunction",
    "secretsmanager:GetSecretValue",
    "sts:AssumeRole"
  ]),
  AuthorityRaceCallerRole: Object.freeze([
    "bedrock:InvokeModel",
    "iam:*",
    "kms:Sign",
    "lambda:InvokeFunction",
    "secretsmanager:GetSecretValue",
    "sts:AssumeRole"
  ]),
  AuthorityRole: Object.freeze([
    "bedrock:InvokeModel",
    "iam:*",
    "kms:Sign",
    "lambda:InvokeFunction",
    "secretsmanager:ListSecrets",
    "sts:AssumeRole"
  ]),
  BoundaryRole: Object.freeze([
    "bedrock:InvokeModel",
    "iam:*",
    "kms:Sign",
    "secretsmanager:GetSecretValue",
    "sts:AssumeRole"
  ]),
  DemoRole: Object.freeze([
    "bedrock:InvokeModel",
    "iam:*",
    "kms:Sign",
    "lambda:InvokeFunction",
    "secretsmanager:GetSecretValue",
    "sts:AssumeRole"
  ]),
  SignerRole: Object.freeze([
    "bedrock:InvokeModel",
    "iam:*",
    "lambda:InvokeFunction",
    "secretsmanager:GetSecretValue",
    "sts:AssumeRole"
  ])
});

const SOURCE_MARKERS = Object.freeze({
  "admissible-vector-retrieval": Object.freeze([
    "connectionStringForDatabase(",
    "\"tideproof\"",
    "FROM tp_api.g1_prepare_vector_set_v1(",
    "FROM tp_api.g1_rank_vector_set_v1(",
    "FROM tp_api.g1_delete_vector_set_v1(",
    "g1_vector_candidates_embedding_idx",
    "crdb_internal.cluster_id()::STRING",
    "nearestExcludedCloserThanRanked: true",
    "tideproof.gate1.admissible-vector-proof.v2",
    "tideproof.gate1.admissible-vector-authority-binding.v1",
    "runId: accepted.runId",
    "authorityEvidenceBindingSha256",
    "rankedSequenceSha256",
    "auditorRankMatchesAuthorizer: true",
    "prepareAttempted = true",
    "authorizationRecheckRequired: true",
    "ADMISSIBLE_VECTOR_PLAN_INDEX_MISSING",
    "ADMISSIBLE_VECTOR_RESULT_ORDER_INVALID"
  ]),
  "admissible-vector-runner": Object.freeze([
    "ADMISSIBLE_VECTOR_WORKTREE_DIRTY",
    "ADMISSIBLE_VECTOR_GIT_REPLACEMENT_REJECTED",
    "ADMISSIBLE_VECTOR_GIT_INDEX_FLAGS_REJECTED",
    "GIT_NO_REPLACE_OBJECTS",
    "core.fsmonitor=false",
    "refs/heads/main:refs/remotes/origin/main",
    "TIDEPROOF_AUDITOR_DATABASE_URL",
    "TIDEPROOF_ADMISSIBLE_VECTOR_PROOF_SPEC",
    "ADMISSIBLE_VECTOR_POOL_CLOSE_FAILED",
    "--proof",
    "not an accepted DVI plan/exclusion receipt"
  ]),
  "authority-identity-contract": Object.freeze([
    "tideproof.authority.identity-contract.v1",
    "tideproof.authority.logical-action.v1",
    "tideproof.authority.dvi-proposal-identity.v1",
    "proposalContextOnlyFields",
    "attemptOnlyFields",
    "databaseOwnedFields",
    "AUTHORITY_DVI_PROPOSAL_TIME",
    "logicalAuthorityKeySha256",
    "authorizationBindingSha256"
  ]),
  "authority-identity-ledger": Object.freeze([
    "FROZEN_CONTRACT_RUNTIME_MIGRATION_PENDING",
    "Only an explicit durable database transition may create a later epoch.",
    "Client input cannot select, increment, or reset the epoch.",
    "must not be treated as satisfying this contract"
  ]),
  "authority-identity-tests": Object.freeze([
    "attempt and proposal context cannot enter logical action identity",
    "only an explicit authorization epoch remints a logical authority key",
    "a new proposal changes authorization binding but not the authority key",
    "identity inputs reject noncanonical text, digests, and timestamps"
  ]),
  "authority-runtime": Object.freeze([
    "parsed.username !== \"tp_gate2_authorizer_user\"",
    "parsed.hostname !== expectedHost",
    "parsed.port !== expectedPort",
    "parsed.searchParams.get(\"sslmode\") !== \"verify-full\"",
    "response.VersionId !== config.secretVersionId",
    "VersionStage: \"AWSCURRENT\"",
    "connectionTimeoutMillis: 2_000",
    "query_timeout: 4_500",
    "statement_timeout: 4_000",
    "idle_in_transaction_session_timeout: 3_000",
    "AUTHORITY_SECRET_REJECTED",
    "BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE READ ONLY",
    "authorityTransferred: false"
  ]),
  "authority-store": Object.freeze([
    "runtimeDatabaseConfig({",
    "bootstrapDatabaseConfig({",
    "tp_private.g1_vector_retrieval_sets",
    "g1_vector_candidates_embedding_idx",
    "CHECK (octet_length(assertion) BETWEEN 1 AND 4096)"
  ]),
  "aws-authority-race": Object.freeze([
    "GIT_NO_REPLACE_OBJECTS: \"1\"",
    "objects/info/alternates",
    "DescribeStackResourceCommand",
    "receipt.treeDigest !== checkout.treeDigest",
    "runId: options.runId",
    "ignoreConfiguredEndpointUrls: true"
  ]),
  "aws-authority-race-validator": Object.freeze([
    "const INITIAL_FENCING_TOKEN = \"1\"",
    "const validatedObservationBindings = new WeakMap()",
    "completedAt <= startedAt",
    "value.fencingToken !== INITIAL_FENCING_TOKEN",
    "leaseExpiresAt <= completedAt",
    "Math.max(...overlapStarts) >= Math.min(...overlapEnds)",
    "observation.runId !== expected.runId",
    "state.activeRunId !== expected.runId",
    "stateObservedAt >= observationBinding.leaseExpiresAt"
  ]),
  "aws-boundary-ledger": Object.freeze([
    "The command is read-only and fail closed.",
    "The evidence runner rejects endpoint, profile, proxy, custom-CA, Git replacement/graft/alternate, shallow-checkout, and tree-digest contamination",
    "`tideproof.aws-authority-race-receipt.v4`",
    "Any wrong-run, sequential, ambiguous, replayed, expanded, stale, extra, or unresolved result is not evidence."
  ]),
  "boundary-runtime": Object.freeze([
    "EXPECTED_ADVISORY_CALLER_ROLE_ARN",
    "assumed-role/${escapedRoleName}",
    "SIGNED_CALLER_REJECTED"
  ]),
  "aws-evidence-identity": Object.freeze([
    "AWS_EVIDENCE_ENDPOINT_OVERRIDE",
    "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS: \"true\"",
    "expectedCallerUserId",
    "bindingDigest"
  ]),
  "aws-preflight": Object.freeze([
    "sts",
    "get-caller-identity",
    "describe-stacks",
    "get-cost-and-usage",
    "get-foundation-model"
  ]),
  "aws-readiness": Object.freeze([
    "LOCAL_ONLY_PASS",
    "awsPreflight: preflight ? \"PASS\" : \"NOT_RUN\"",
    "AWS was not queried or mutated",
    "upload and deployment remain separate reviewed actions"
  ]),
  "aws-template-generated": Object.freeze([
    "\"Type\": \"AWS::KMS::Key\"",
    "\"ReservedConcurrentExecutions\": 2",
    "\"DisableExecuteApiEndpoint\": false",
    "\"EXPECTED_ADVISORY_CALLER_ROLE_ARN\": {",
    "\"AuthorizationType\": \"AWS_IAM\"",
    "\"Type\": \"AWS::Lambda::Permission\""
  ]),
  "aws-template-source": Object.freeze([
    "properties.ReservedConcurrentExecutions = concurrency;",
    "Type: \"AWS::KMS::Key\"",
    "DisableExecuteApiEndpoint: false",
    "EXPECTED_ADVISORY_CALLER_ROLE_ARN: getAtt(",
    "AuthorizationType: \"AWS_IAM\"",
    "ThrottlingBurstLimit: 1",
    "Type: \"AWS::Lambda::Permission\""
  ]),
  "database-runtime": Object.freeze([
    "DATABASE_CONNECTION_RUNTIME_OVERRIDE_REJECTED",
    "statementTimeoutMillis: RUNTIME_STATEMENT_TIMEOUT_MS",
    "idleTransactionTimeoutMillis: RUNTIME_IDLE_TRANSACTION_TIMEOUT_MS",
    "code === \"40003\""
  ]),
  "database-security-posture": Object.freeze([
    "DATABASE_POSTURE_PRINCIPAL_OPTIONS_UNSAFE",
    "DATABASE_POSTURE_EXTERNAL_MEMBERSHIP",
    "DATABASE_POSTURE_SYSTEM_GRANT_UNSAFE",
    "DATABASE_POSTURE_OUT_OF_SCOPE_GRANT",
    "DATABASE_POSTURE_DIRECT_USER_GRANT",
    "FROM [SHOW GRANTS ON ROLE]",
    "FROM [SHOW SYSTEM GRANTS]"
  ]),
  "demo-entry": Object.freeze([
    "createPublicDemoHandler({",
    "expectedApiId: process.env.EXPECTED_API_ID",
    "sourceCommit: process.env.SOURCE_COMMIT",
    "functionVersion: process.env.AWS_LAMBDA_FUNCTION_VERSION",
    "runScenario"
  ]),
  "local-server": Object.freeze([
    "if (request.method !== \"GET\")",
    "frame-ancestors 'none'",
    "server.listen(port, \"127.0.0.1\""
  ]),
  "managed-mcp-client": Object.freeze([
    "https://cockroachlabs.cloud/mcp",
    "redirect: \"error\"",
    "AbortSignal.timeout(30_000)",
    "RECOVERY_MCP_RESPONSE_TOO_LARGE",
    "TextDecoder(\"utf-8\", { fatal: true })",
    "RECOVERY_MCP_RESPONSE_ID_MISMATCH",
    "recoveryQueryBindingsFor(query)"
  ]),
  "primary-security-bootstrap": Object.freeze([
    "REVOKE ALL ON DATABASE tideproof FROM public",
    "REVOKE CREATE ON SCHEMA public FROM public",
    "ALTER DEFAULT PRIVILEGES FOR ROLE",
    "SECURITY DEFINER",
    "session_user <> 'tp_gate2_authorizer_user'",
    "collectValidatedPosture(",
    "ALTER ROLE ${role} WITH NOLOGIN",
    "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA tp_private, tp_ledger, tp_api FROM ${principal}",
    "GRANT USAGE ON SCHEMA tp_api TO ${role}",
    "FROM tp_authorizer_role",
    "FROM tp_gate2_authorizer_role",
    "TO tp_gate2_authorizer_role",
    "p_agent_id NOT IN ('aws-authority-alpha', 'aws-authority-bravo')",
    "tp_api.g2_spend_authority_race_v1"
  ]),
  "protocol-runtime": Object.freeze([
    "receiptOperationId",
    "checkpoint receipt binding is ambiguous",
    "receiptReference",
    "operationalCapabilitiesReturned: false"
  ]),
  "proposal-runtime": Object.freeze([
    "parsed.proposal.action !== \"REQUEST_FRESH_AUTHORIZATION\"",
    "parsed.proposal.resourceId !== \"synthetic-rescue-unit-7\"",
    "It requests deterministic authorization; it never claims permission.",
    "BEDROCK_PROMPT_SIZE_REJECTED",
    "BEDROCK_RESPONSE_SIZE_REJECTED",
    "BEDROCK_TOKEN_TOTAL_REJECTED"
  ]),
  "public-demo-runtime": Object.freeze([
    "event?.requestContext?.apiId !== expectedApiId",
    "event?.requestContext?.stage !== \"$default\"",
    "method !== \"GET\"",
    "!PUBLIC_DEMO_PATHS.includes(path)",
    "authorityCapability: false"
  ]),
  "public-demo-verifier": Object.freeze([
    "PUBLIC_DEMO_VERIFY_SECURITY_HEADERS",
    "PUBLIC_DEMO_VERIFY_AMBIENT_AUTH",
    "set-cookie",
    "access-control-allow-origin",
    "PUBLIC_DEMO_VERIFY_NEGATIVE_PROBE"
  ]),
  "recovery-security-bootstrap": Object.freeze([
    "REVOKE ALL ON DATABASE tideproof_recovery FROM public",
    "REVOKE CREATE ON SCHEMA public FROM public",
    "ALTER DEFAULT PRIVILEGES FOR ROLE",
    "SECURITY DEFINER",
    "collectValidatedRecoveryPosture(",
    "GRANT USAGE ON SCHEMA mcp_api TO ${RECOVERY_PUBLISHER_ROLE}",
    "RECOVERY_PUBLISH_RETRY_DEADLINE_EXCEEDED"
  ]),
  "recovery-broker": Object.freeze([
    "runtimeDatabaseConfig({",
    "RECOVERY_CLUSTER_SEPARATION_REQUIRED",
    "RECOVERY_PRINCIPAL_BINDING_MISMATCH",
    "RECOVERY_MCP_RESULT_CARDINALITY_INVALID"
  ]),
  "recovery-broker-runner": Object.freeze([
    "RECOVERY_SOURCE_OPERATION_ID",
    "RECOVERY_SOURCE_REQUEST_DIGEST",
    "operationalCapabilitiesReturned: false"
  ]),
  "recovery-evidence-runner": Object.freeze([
    "RECOVERY_SOURCE_OPERATION_ID",
    "RECOVERY_SOURCE_REQUEST_DIGEST",
    "publisher unexpectedly read the base recovery table"
  ]),
  "recovery-store": Object.freeze([
    "runtimeDatabaseConfig({",
    "bootstrapDatabaseConfig({",
    "RECOVERY_AUTHORITY_INVARIANT_VIOLATION",
    "RECOVERY_SIGNATURE_INVALID"
  ]),
  "release-security-ledger": Object.freeze([
    "CURRENT SOURCE SECURITY PASS — LIVE AND PRIVATE REVIEW PENDING",
    "not a vulnerability-free claim",
    "The template currently uses one API/stage/method-scoped `GET/*` Lambda permission",
    "Any unresolved security, privacy, cost, eligibility, or claim finding keeps release and submission blocked."
  ]),
  "security-policy": Object.freeze([
    "Do not open a public issue for a suspected vulnerability.",
    "CURRENT_SOURCE_SECURITY_PASS",
    "not a vulnerability-free claim"
  ]),
  "signed-ingest": Object.freeze([
    "runtimeDatabaseConfig({",
    "connectionStringForDatabase(",
    "VERIFICATION_KEY_NOT_ADMISSIBLE",
    "SIGNATURE_INVALID"
  ]),
  "signer-runtime": Object.freeze([
    "SigningAlgorithms.includes(\"ECDSA_SHA_256\")",
    "MessageType: \"DIGEST\"",
    "SigningAlgorithm: \"ECDSA_SHA_256\"",
    "new VerifyCommand({",
    "KMS_SIGNATURE_VERIFICATION_FAILED"
  ])
});

function assert(condition, code) {
  if (!condition) {
    throw new Error(code);
  }
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function sorted(values) {
  return [...values].sort((left, right) => left.localeCompare(right));
}

function sameJson(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function exactKeys(value, keys, code) {
  assert(
    value &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      sameJson(sorted(Object.keys(value)), sorted(keys)),
    code
  );
}

function safeRelativePath(value, code) {
  assert(
    typeof value === "string" &&
      value.length > 0 &&
      value === value.replaceAll("\\", "/") &&
      !path.posix.isAbsolute(value) &&
      value.split("/").every((part) => part !== "" && part !== ".."),
    code
  );
}

function readRegularFile(rootDir, relativePath, code) {
  safeRelativePath(relativePath, code);
  const resolvedRoot = path.resolve(rootDir);
  const resolved = path.resolve(resolvedRoot, relativePath);
  const relative = path.relative(resolvedRoot, resolved);
  assert(
    relative !== "" &&
      relative !== ".." &&
      !relative.startsWith(`..${path.sep}`),
    code
  );
  let current = resolvedRoot;
  let stat;
  for (const segment of relativePath.split("/")) {
    current = path.join(current, segment);
    stat = fs.lstatSync(current);
    assert(!stat.isSymbolicLink(), code);
  }
  assert(stat.isFile(), code);
  return fs.readFileSync(resolved);
}

function actionList(value) {
  return Array.isArray(value) ? value : [value];
}

function roleStatements(role, code) {
  assert(
    role?.Type === "AWS::IAM::Role" &&
      role.Properties?.MaxSessionDuration === 3600 &&
      role.Properties.ManagedPolicyArns === undefined &&
      Array.isArray(role.Properties.Policies) &&
      role.Properties.Policies.length === 1 &&
      Array.isArray(
        role.Properties.Policies[0]?.PolicyDocument?.Statement
      ),
    code
  );
  return role.Properties.Policies[0].PolicyDocument.Statement;
}

function directStatements(statements) {
  return statements.filter((statement) => !Object.hasOwn(statement, "Fn::If"));
}

function allowActions(statements) {
  return sorted(
    directStatements(statements)
      .filter((statement) => statement.Effect === "Allow")
      .flatMap((statement) => actionList(statement.Action))
  );
}

function denyActions(statements) {
  return new Set(
    directStatements(statements)
      .filter((statement) => statement.Effect === "Deny")
      .flatMap((statement) => actionList(statement.Action))
  );
}

function assertConditionalProbeLogs(statements, roleName) {
  const conditional = statements.filter((statement) =>
    Object.hasOwn(statement, "Fn::If")
  );
  if (conditional.length === 0) {
    return;
  }
  assert(conditional.length === 1, `RELEASE_SECURITY_${roleName}_CONDITION`);
  const [condition, enabled, disabled] = conditional[0]["Fn::If"];
  assert(
    condition === "ShouldDeployProbes" &&
      enabled?.Effect === "Allow" &&
      sameJson(sorted(actionList(enabled.Action)), [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]) &&
      enabled.Resource?.["Fn::Sub"]?.endsWith("ProbeLogGroup.Arn}:*") &&
      disabled?.Ref === "AWS::NoValue",
    `RELEASE_SECURITY_${roleName}_CONDITION`
  );
}

function assertTemplateContract(template, builtTemplate = buildGate2Template()) {
  assert(
    sameJson(template, builtTemplate),
    "RELEASE_SECURITY_TEMPLATE_GENERATOR_DRIFT"
  );
  const resources = template.Resources;
  assert(
    resources && typeof resources === "object" && !Array.isArray(resources),
    "RELEASE_SECURITY_TEMPLATE_RESOURCES"
  );

  const publicRoutes = Object.values(resources)
    .filter(
      (resource) =>
        resource.Type === "AWS::ApiGatewayV2::Route" &&
        resource.Properties?.AuthorizationType === "NONE"
    )
    .map((resource) => resource.Properties.RouteKey)
    .sort();
  assert(
    sameJson(
      publicRoutes,
      EXPECTED_PUBLIC_PATHS.map((entry) => `GET ${entry}`).sort()
    ),
    "RELEASE_SECURITY_PUBLIC_ROUTES"
  );
  const allRoutes = Object.values(resources).filter(
    (resource) => resource.Type === "AWS::ApiGatewayV2::Route"
  );
  assert(
    allRoutes.length === EXPECTED_PUBLIC_PATHS.length + 1 &&
      resources.AdvisoryRoute?.Properties?.RouteKey === "POST /advisory" &&
      resources.AdvisoryRoute.Properties.AuthorizationType === "AWS_IAM",
    "RELEASE_SECURITY_ADVISORY_ROUTE"
  );
  assert(
    resources.HttpApi?.Type === "AWS::ApiGatewayV2::Api" &&
      resources.HttpApi.Properties.ProtocolType === "HTTP" &&
      resources.HttpApi.Properties.CorsConfiguration === undefined &&
      !Object.values(resources).some(
        (resource) => resource.Type === "AWS::Lambda::Url"
      ),
    "RELEASE_SECURITY_PUBLIC_API"
  );

  const stage = resources.DefaultStage?.Properties;
  assert(
    stage?.StageName === "$default" &&
      stage.AutoDeploy === true &&
      sameJson(stage.DefaultRouteSettings, {
        ThrottlingBurstLimit: 8,
        ThrottlingRateLimit: 0.05
      }) &&
      sameJson(stage.RouteSettings?.["POST /advisory"], {
        ThrottlingBurstLimit: 1,
        ThrottlingRateLimit: 0.1
      }) &&
      typeof stage.AccessLogSettings?.Format === "string" &&
      stage.AccessLogSettings.Format.includes("requestTimeEpoch") &&
      !/sourceIp|authorization|requestBody/i.test(
        stage.AccessLogSettings.Format
      ),
    "RELEASE_SECURITY_STAGE"
  );

  const functionCaps = {
    AgentFunction: { concurrency: 1, timeout: 15 },
    AuthorityFunction: { concurrency: 2, timeout: 25 },
    BoundaryFunction: { concurrency: 2, timeout: 25 },
    DemoFunction: { concurrency: 8, timeout: 5 },
    SignerFunction: { concurrency: 1, timeout: 8 }
  };
  for (const [name, expected] of Object.entries(functionCaps)) {
    const properties = resources[name]?.Properties;
    assert(
      resources[name]?.Type === "AWS::Lambda::Function" &&
        properties.Runtime === "nodejs22.x" &&
        properties.Handler === "index.handler" &&
        properties.ReservedConcurrentExecutions === expected.concurrency &&
        properties.Timeout === expected.timeout &&
        properties.Code?.S3Bucket &&
        properties.Code.S3Key &&
        properties.Code.S3ObjectVersion &&
        properties.Code.ZipFile === undefined,
      `RELEASE_SECURITY_${name}_BOUNDARY`
    );
  }
  assert(
    template.Parameters?.AuthorityDatabaseSecretVersionId?.MinLength === 32 &&
      template.Parameters.AuthorityDatabaseSecretVersionId.MaxLength === 64 &&
      template.Parameters.AuthorityDatabaseHost?.MaxLength === 253 &&
      template.Parameters.AuthorityDatabasePort?.MaxLength === 5,
    "RELEASE_SECURITY_AUTHORITY_BINDING_PARAMETERS"
  );
  const authorityEnvironment =
    resources.AuthorityFunction.Properties.Environment?.Variables;
  assert(
    authorityEnvironment?.AUTHORITY_DATABASE_SECRET_ARN?.Ref ===
      "AuthorityDatabaseSecretArn" &&
      authorityEnvironment.AUTHORITY_DATABASE_SECRET_VERSION_ID?.Ref ===
        "AuthorityDatabaseSecretVersionId" &&
      authorityEnvironment.AUTHORITY_DATABASE_HOST?.Ref ===
        "AuthorityDatabaseHost" &&
      authorityEnvironment.AUTHORITY_DATABASE_PORT?.Ref ===
        "AuthorityDatabasePort",
    "RELEASE_SECURITY_AUTHORITY_RUNTIME_BINDINGS"
  );
  assert(
    sameJson(
      resources.BoundaryFunction.Properties.Environment?.Variables
        ?.EXPECTED_ADVISORY_CALLER_ROLE_ARN,
      { "Fn::GetAtt": ["AdvisoryCallerRole", "Arn"] }
    ),
    "RELEASE_SECURITY_ADVISORY_CALLER_BINDING"
  );
  for (const name of [
    "AgentAlias",
    "AuthorityAlias",
    "BoundaryAlias",
    "DemoAlias",
    "SignerAlias"
  ]) {
    assert(
      resources[name]?.Type === "AWS::Lambda::Alias" &&
        resources[name].Properties.Name === "proof" &&
        resources[name].Properties.FunctionVersion?.["Fn::GetAtt"]?.[1] ===
          "Version",
      `RELEASE_SECURITY_${name}_IMMUTABLE`
    );
  }

  for (const [roleName, expectedActions] of Object.entries(
    EXPECTED_ROLE_ALLOW_ACTIONS
  )) {
    const statements = roleStatements(
      resources[roleName],
      `RELEASE_SECURITY_${roleName}_ROLE`
    );
    assert(
      sameJson(allowActions(statements), sorted(expectedActions)),
      `RELEASE_SECURITY_${roleName}_ALLOW`
    );
    for (const statement of directStatements(statements).filter(
      (candidate) => candidate.Effect === "Allow"
    )) {
      assert(
        statement.Resource !== "*",
        `RELEASE_SECURITY_${roleName}_WILDCARD_ALLOW`
      );
    }
    const denied = denyActions(statements);
    assert(
      REQUIRED_DENY_ACTIONS[roleName].every((action) => denied.has(action)),
      `RELEASE_SECURITY_${roleName}_DENY`
    );
    assertConditionalProbeLogs(statements, roleName);
  }

  const permissions = {
    BoundaryInvokePermission:
      "arn:${AWS::Partition}:execute-api:${AWS::Region}:${AWS::AccountId}:${HttpApi}/$default/POST/advisory",
    DemoAssetInvokePermission:
      "arn:${AWS::Partition}:execute-api:${AWS::Region}:${AWS::AccountId}:${HttpApi}/$default/GET/*",
    DemoRootInvokePermission:
      "arn:${AWS::Partition}:execute-api:${AWS::Region}:${AWS::AccountId}:${HttpApi}/$default/GET/"
  };
  for (const [name, sourceArn] of Object.entries(permissions)) {
    const permission = resources[name];
    assert(
      permission?.Type === "AWS::Lambda::Permission" &&
        permission.Properties.Action === "lambda:InvokeFunction" &&
        permission.Properties.Principal === "apigateway.amazonaws.com" &&
        permission.Properties.SourceAccount?.Ref === "AWS::AccountId" &&
        permission.Properties.SourceArn?.["Fn::Sub"] === sourceArn &&
        permission.Properties.FunctionName?.["Fn::GetAtt"]?.[1] ===
          "AliasArn",
      `RELEASE_SECURITY_${name}`
    );
  }

  const key = resources.ReceiptSigningKey;
  assert(
    key?.Type === "AWS::KMS::Key" &&
      key.DeletionPolicy === "Delete" &&
      key.UpdateReplacePolicy === "Delete" &&
      key.Properties.Enabled === true &&
      key.Properties.KeySpec === "ECC_NIST_P256" &&
      key.Properties.KeyUsage === "SIGN_VERIFY" &&
      key.Properties.Origin === "AWS_KMS" &&
      key.Properties.MultiRegion === false &&
      key.Properties.PendingWindowInDays === 7,
    "RELEASE_SECURITY_KMS_KEY"
  );
  for (const [name, resource] of Object.entries(resources)) {
    if (resource.Type === "AWS::Logs::LogGroup") {
      assert(
        resource.Properties.RetentionInDays === 7,
        `RELEASE_SECURITY_${name}_RETENTION`
      );
    }
  }
  return {
    publicRouteCount: publicRoutes.length,
    iamRoleCount: Object.keys(EXPECTED_ROLE_ALLOW_ACTIONS).length,
    lambdaPermissionCount: Object.keys(permissions).length,
    boundedFunctionCount: Object.keys(functionCaps).length,
    logGroupCount: Object.values(resources).filter(
      (resource) => resource.Type === "AWS::Logs::LogGroup"
    ).length
  };
}

function assertRuntimeContract() {
  assert(
    sameJson(PUBLIC_DEMO_PATHS, EXPECTED_PUBLIC_PATHS),
    "RELEASE_SECURITY_PUBLIC_PATH_CONTRACT"
  );
  assert(
    sameJson(
      publicDemoVerifierContract.SECURITY_HEADERS,
      EXPECTED_SECURITY_HEADERS
    ),
    "RELEASE_SECURITY_HEADER_CONTRACT"
  );
  assert(
    sameJson(
      publicDemoVerifierContract.NEGATIVE_PROBES.map(({ method, path }) => ({
        method,
        path
      })),
      EXPECTED_NEGATIVE_PROBES
    ),
    "RELEASE_SECURITY_NEGATIVE_PROBES"
  );
  return {
    publicPathCount: PUBLIC_DEMO_PATHS.length,
    securityHeaderCount: Object.keys(EXPECTED_SECURITY_HEADERS).length,
    negativeProbeCount: EXPECTED_NEGATIVE_PROBES.length
  };
}

function assertSourceMarkers(sources) {
  assert(
    sameJson(
      sorted(Object.keys(SOURCE_MARKERS)),
      sorted(Object.keys(EXPECTED_SURFACES))
    ),
    "RELEASE_SECURITY_MARKER_SET"
  );
  for (const [id, markers] of Object.entries(SOURCE_MARKERS)) {
    const source = sources.get(id);
    assert(typeof source === "string", "RELEASE_SECURITY_MARKER_SOURCE");
    const normalizedSource = source.replace(/\s+/g, " ").trim();
    for (const marker of markers) {
      assert(
        normalizedSource.includes(marker.replace(/\s+/g, " ").trim()),
        `RELEASE_SECURITY_MARKER_${id.replaceAll("-", "_").toUpperCase()}`
      );
    }
  }
  return true;
}

export function validateManifest(value) {
  exactKeys(
    value,
    [
      "claimBoundary",
      "finalReleaseReady",
      "finalReleaseRequirements",
      "reviewedOn",
      "schema",
      "status",
      "surfaces"
    ],
    "RELEASE_SECURITY_MANIFEST_SHAPE"
  );
  assert(
    value.schema === MANIFEST_SCHEMA &&
      value.status === MANIFEST_STATUS &&
      /^\d{4}-\d{2}-\d{2}$/.test(value.reviewedOn) &&
      typeof value.claimBoundary === "string" &&
      value.claimBoundary.length > 0 &&
      value.finalReleaseReady === false &&
      sameJson(
        value.finalReleaseRequirements,
        EXPECTED_FINAL_RELEASE_REQUIREMENTS
      ),
    "RELEASE_SECURITY_MANIFEST_BOUNDARY"
  );
  assert(Array.isArray(value.surfaces), "RELEASE_SECURITY_MANIFEST_SURFACES");
  const expectedIds = Object.keys(EXPECTED_SURFACES);
  assert(
    sameJson(
      value.surfaces.map((surface) => surface.id),
      expectedIds
    ),
    "RELEASE_SECURITY_MANIFEST_SURFACE_SET"
  );
  for (const surface of value.surfaces) {
    exactKeys(
      surface,
      ["id", "path", "role", "sha256"],
      "RELEASE_SECURITY_MANIFEST_SURFACE_SHAPE"
    );
    const expected = EXPECTED_SURFACES[surface.id];
    assert(
      expected &&
        surface.path === expected.path &&
        surface.role === expected.role &&
        HEX_64.test(surface.sha256),
      "RELEASE_SECURITY_MANIFEST_SURFACE"
    );
    safeRelativePath(surface.path, "RELEASE_SECURITY_MANIFEST_SURFACE_PATH");
  }
  return value;
}

export function verifyReleaseSecurity({ rootDir = DEFAULT_ROOT } = {}) {
  const manifestBytes = readRegularFile(
    rootDir,
    MANIFEST_PATH,
    "RELEASE_SECURITY_MANIFEST_FILE"
  );
  let manifest;
  try {
    manifest = JSON.parse(manifestBytes.toString("utf8"));
  } catch {
    throw new Error("RELEASE_SECURITY_MANIFEST_JSON");
  }
  assert(
    `${JSON.stringify(manifest, null, 2)}\n` === manifestBytes.toString("utf8"),
    "RELEASE_SECURITY_MANIFEST_CANONICAL"
  );
  validateManifest(manifest);

  const sources = new Map();
  for (const surface of manifest.surfaces) {
    const bytes = readRegularFile(
      rootDir,
      surface.path,
      "RELEASE_SECURITY_SURFACE_FILE"
    );
    assert(
      sha256(bytes) === surface.sha256,
      "RELEASE_SECURITY_SURFACE_DIGEST"
    );
    sources.set(surface.id, bytes.toString("utf8"));
  }
  assertSourceMarkers(sources);

  let generatedTemplate;
  try {
    generatedTemplate = JSON.parse(sources.get("aws-template-generated"));
  } catch {
    throw new Error("RELEASE_SECURITY_TEMPLATE_JSON");
  }
  assert(
    `${JSON.stringify(generatedTemplate, null, 2)}\n` ===
      sources.get("aws-template-generated"),
    "RELEASE_SECURITY_TEMPLATE_CANONICAL"
  );
  const template = assertTemplateContract(generatedTemplate);
  const runtime = assertRuntimeContract();

  return {
    schemaVersion: RECEIPT_SCHEMA,
    status: "CURRENT_SOURCE_SECURITY_PASS",
    finalReleaseReady: false,
    reviewedOn: manifest.reviewedOn,
    manifestPath: MANIFEST_PATH,
    manifestSha256: sha256(manifestBytes),
    surfaceCount: manifest.surfaces.length,
    ...runtime,
    ...template,
    finalReleaseRequirements: manifest.finalReleaseRequirements,
    checks: {
      canonicalManifest: true,
      exactSurfaceHashes: true,
      sourceSecurityMarkersPresent: true,
      generatedTemplateMatchesSource: true,
      exactPublicRouteSet: true,
      advisoryRouteIamAuthenticated: true,
      publicCorsAndLambdaUrlsAbsent: true,
      throttlesAndConcurrencyBounded: true,
      immutableVersionedLambdaTargets: true,
      leastPrivilegeRoleActionsBounded: true,
      criticalRoleDenialsPresent: true,
      apiGatewayInvokePermissionsBounded: true,
      asymmetricSigningKeyBounded: true,
      logsBoundedAndPrivacyMinimized: true,
      publicHeadersAndNegativeProbesBounded: true
    },
    claimBoundary:
      "This receipt proves only that the current hash-bound security surfaces match the reviewed source state and that the generated Gate Two template preserves the enumerated route, authentication, browser-header, negative-probe, throttle, concurrency, immutable-version, IAM-action, Lambda-permission, KMS, log-retention, database-bootstrap, and Managed MCP source contracts checked here. It is not a vulnerability-free claim, penetration test, live AWS or CockroachDB receipt, availability guarantee, production-suitability finding, or authorization to deploy, publish, or submit."
  };
}

async function main() {
  assert(process.argv.length === 2, "RELEASE_SECURITY_ARGUMENT");
  process.stdout.write(`${JSON.stringify(verifyReleaseSecurity(), null, 2)}\n`);
}

const startedDirectly =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (startedDirectly) {
  main().catch((error) => {
    const message = String(error?.message ?? "");
    const code = /^RELEASE_SECURITY_[A-Z0-9_]{1,120}$/.test(message)
      ? message
      : "RELEASE_SECURITY_UNKNOWN";
    process.stderr.write(`TIDEPROOF_RELEASE_SECURITY_FAILED:${code}\n`);
    process.exitCode = 1;
  });
}

export const __test = Object.freeze({
  EXPECTED_FINAL_RELEASE_REQUIREMENTS,
  EXPECTED_NEGATIVE_PROBES,
  EXPECTED_PUBLIC_PATHS,
  EXPECTED_ROLE_ALLOW_ACTIONS,
  EXPECTED_SECURITY_HEADERS,
  EXPECTED_SURFACES,
  MANIFEST_PATH,
  MANIFEST_SCHEMA,
  MANIFEST_STATUS,
  REQUIRED_DENY_ACTIONS,
  SOURCE_MARKERS,
  assertRuntimeContract,
  assertSourceMarkers,
  assertTemplateContract
});
