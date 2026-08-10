import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { buildGate2Template } from "../src/cloud/aws-gate2-template.js";
import { DEPLOYMENT_API_ROUTE_KEYS } from "../src/cloud/aws-deployment-attestation.js";
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
  "actions-checkout-normalizer": Object.freeze({
    path: "scripts/normalize-actions-checkout.js",
    role: "GITHUB_ACTIONS_EXACT_CHECKOUT_NORMALIZATION"
  }),
  "actions-checkout-normalizer-tests": Object.freeze({
    path: "test/release-rights.test.js",
    role: "GITHUB_ACTIONS_CHECKOUT_NORMALIZATION_VERIFICATION"
  }),
  "actions-ci-workflow": Object.freeze({
    path: ".github/workflows/ci.yml",
    role: "GITHUB_ACTIONS_RELEASE_VERIFICATION_WORKFLOW"
  }),
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
  "authority-evidence-runner": Object.freeze({
    path: "scripts/gate1-authority.js",
    role: "AUTHORITY_IDENTITY_EVIDENCE_RUNNER"
  }),
  "authority-capability-race-runner": Object.freeze({
    path: "scripts/gate1-capability-race.js",
    role: "AUTHORITY_CAPABILITY_WAIT_EVIDENCE_RUNNER"
  }),
  "authority-runtime": Object.freeze({
    path: "infra/aws/lambda/authority.cjs",
    role: "AWS_AUTHORITY_RUNTIME"
  }),
  "authority-runtime-identity-tests": Object.freeze({
    path: "test/authority-runtime-identity.test.js",
    role: "AUTHORITY_RUNTIME_IDENTITY_VERIFICATION"
  }),
  "authority-runtime-reconciliation-tests": Object.freeze({
    path: "test/aws-authority-lambda.test.js",
    role: "AUTHORITY_RUNTIME_RECONCILIATION_VERIFICATION"
  }),
  "authority-store": Object.freeze({
    path: "src/cloud/authority-store.js",
    role: "PRIMARY_AUTHORITY_STORE"
  }),
  "aws-alternate-principal-denial-runner": Object.freeze({
    path: "scripts/gate2-evidence-operator-denial.js",
    role: "AWS_EVIDENCE_TRUST_NEGATIVE_CONTROL"
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
  "aws-deployment-attestation": Object.freeze({
    path: "src/cloud/aws-deployment-attestation.js",
    role: "AWS_DEPLOYMENT_ATTESTATION_VALIDATOR"
  }),
  "aws-deployment-attestation-runner": Object.freeze({
    path: "scripts/gate2-aws-attestation.js",
    role: "AWS_DEPLOYMENT_ATTESTATION_RUNNER"
  }),
  "aws-deployment-attestation-tests": Object.freeze({
    path: "test/aws-deployment-attestation.test.js",
    role: "AWS_DEPLOYMENT_ATTESTATION_VERIFICATION"
  }),
  "aws-evidence-identity": Object.freeze({
    path: "src/cloud/aws-evidence-identity.js",
    role: "AWS_EVIDENCE_IDENTITY_BOUNDARY"
  }),
  "aws-evidence-identity-tests": Object.freeze({
    path: "test/aws-evidence-identity.test.js",
    role: "AWS_EVIDENCE_IDENTITY_VERIFICATION"
  }),
  "aws-oidc-identity-bootstrap": Object.freeze({
    path: ".github/workflows/aws-oidc-identity-bootstrap.yml",
    role: "MANUAL_SHORT_LIVED_AWS_IDENTITY_BOOTSTRAP"
  }),
  "aws-oidc-read-only-ledger": Object.freeze({
    path: "docs/AWS_OIDC_PREFLIGHT.md",
    role: "CLOUDSHELL_OPTIONAL_OIDC_AUTHORITY_BOUNDARY"
  }),
  "aws-oidc-read-only-role-template": Object.freeze({
    path: "infra/aws/oidc-read-only-preflight-role-template.json",
    role: "LEAST_PRIVILEGE_READ_ONLY_OIDC_ROLE_SCAFFOLD"
  }),
  "aws-oidc-read-only-runner": Object.freeze({
    path: "scripts/run-aws-oidc-read-only-preflight.sh",
    role: "SOURCE_BOUND_READ_ONLY_OIDC_PREFLIGHT_RUNNER"
  }),
  "aws-oidc-read-only-source-tests": Object.freeze({
    path: "test/aws-oidc-source-lane.test.js",
    role: "OIDC_SOURCE_BOUNDARY_ADVERSARIAL_VERIFICATION"
  }),
  "aws-oidc-read-only-source-verifier": Object.freeze({
    path: "scripts/verify-aws-oidc-preflight-source.js",
    role: "OIDC_SOURCE_BOUNDARY_VERIFIER"
  }),
  "aws-oidc-read-only-workflow": Object.freeze({
    path: ".github/workflows/aws-oidc-read-only-preflight.yml",
    role: "MANUAL_PROTECTED_READ_ONLY_OIDC_PREFLIGHT"
  }),
  "aws-provider-bundle-entry": Object.freeze({
    path: "scripts/lib/aws-provider-bundle-entry.js",
    role: "AWS_ATTESTATION_PROVIDER_BUNDLE_ENTRY"
  }),
  "aws-provider-runtime": Object.freeze({
    path: "scripts/lib/aws-provider-runtime.js",
    role: "AWS_ATTESTATION_PROVIDER_RUNTIME"
  }),
  "aws-provider-runtime-loader": Object.freeze({
    path: "scripts/lib/aws-provider-runtime-loader.js",
    role: "AWS_ATTESTATION_PROVIDER_RUNTIME_LOADER"
  }),
  "aws-provider-clients-tests": Object.freeze({
    path: "test/aws-provider-clients.test.js",
    role: "AWS_ATTESTATION_PROVIDER_CLIENT_VERIFICATION"
  }),
  "exact-build-reproduction": Object.freeze({
    path: "scripts/lib/exact-build-reproduction.js",
    role: "EXACT_BUILD_REPRODUCTION_CONTRACT"
  }),
  "aws-preflight": Object.freeze({
    path: "scripts/gate2-aws-preflight.js",
    role: "READ_ONLY_AWS_PREFLIGHT"
  }),
  "aws-preflight-validator": Object.freeze({
    path: "src/cloud/aws-gate2-preflight.js",
    role: "READ_ONLY_AWS_PREFLIGHT_VALIDATOR"
  }),
  "aws-preflight-tests": Object.freeze({
    path: "test/aws-gate2-preflight.test.js",
    role: "READ_ONLY_AWS_PREFLIGHT_VERIFICATION"
  }),
  "aws-readiness": Object.freeze({
    path: "scripts/gate2-aws-readiness.js",
    role: "EXACT_CHECKOUT_READINESS"
  }),
  "aws-readiness-tests": Object.freeze({
    path: "test/aws-gate2-readiness.test.js",
    role: "EXACT_CHECKOUT_READINESS_VERIFICATION"
  }),
  "aws-security-tests": Object.freeze({
    path: "test/aws-gate2.test.js",
    role: "AWS_GATE2_SECURITY_VERIFICATION"
  }),
  "aws-template-generated": Object.freeze({
    path: "infra/aws/gate2-template.json",
    role: "GENERATED_CLOUDFORMATION"
  }),
  "aws-template-source": Object.freeze({
    path: "src/cloud/aws-gate2-template.js",
    role: "CLOUDFORMATION_SOURCE"
  }),
  "aws-template-security-tests": Object.freeze({
    path: "test/aws-gate2-template-security.test.js",
    role: "AWS_TEMPLATE_LEAST_PRIVILEGE_VERIFICATION"
  }),
  "boundary-runtime": Object.freeze({
    path: "infra/aws/lambda/boundary.cjs",
    role: "AWS_COORDINATOR_RUNTIME"
  }),
  "canonical-json-contract": Object.freeze({
    path: "src/cloud/canonical-json.js",
    role: "CANONICAL_IDENTITY_SERIALIZATION"
  }),
  "commit-reconciliation-contract": Object.freeze({
    path: "src/cloud/database-commit-result.js",
    role: "DATABASE_COMMIT_RESULT_CONTRACT"
  }),
  "commit-reconciliation-ledger": Object.freeze({
    path: "docs/COMMIT_RECONCILIATION.md",
    role: "DATABASE_COMMIT_RECONCILIATION_BOUNDARY"
  }),
  "commit-reconciliation-tests": Object.freeze({
    path: "test/database-commit-result.test.js",
    role: "DATABASE_COMMIT_RECONCILIATION_VERIFICATION"
  }),
  "database-runtime": Object.freeze({
    path: "src/cloud/database-runtime.js",
    role: "DATABASE_RUNTIME_BOUNDARY"
  }),
  "database-security-bootstrap-tests": Object.freeze({
    path: "test/database-security-bootstrap.test.js",
    role: "DATABASE_BOOTSTRAP_SECURITY_VERIFICATION"
  }),
  "database-security-posture": Object.freeze({
    path: "src/cloud/database-security-posture.js",
    role: "DATABASE_POSTURE_BOUNDARY"
  }),
  "database-security-posture-tests": Object.freeze({
    path: "test/database-security-posture.test.js",
    role: "DATABASE_POSTURE_VERIFICATION"
  }),
  "dependency-snapshot": Object.freeze({
    path: "scripts/lib/dependency-snapshot.js",
    role: "IMMUTABLE_DEPENDENCY_AND_TOOLCHAIN_BINDING"
  }),
  "dependency-snapshot-tests": Object.freeze({
    path: "test/dependency-snapshot.test.js",
    role: "DEPENDENCY_SNAPSHOT_TAMPER_VERIFICATION"
  }),
  "demo-entry": Object.freeze({
    path: "infra/aws/lambda/demo.js",
    role: "AWS_PUBLIC_ENTRY"
  }),
  "dvi-proposal-authorization": Object.freeze({
    path: "src/cloud/dvi-proposal-authorization.js",
    role: "DATABASE_OWNED_PROPOSAL_AUTHORIZATION"
  }),
  "dvi-proposal-authorization-tests": Object.freeze({
    path: "test/dvi-proposal-authorization.test.js",
    role: "PROPOSAL_AUTHORIZATION_VERIFICATION"
  }),
  "dvi-selection-contract": Object.freeze({
    path: "src/cloud/dvi-selection.js",
    role: "DURABLE_DVI_SELECTION_IDENTITY"
  }),
  "dvi-reconciliation-tests": Object.freeze({
    path: "test/admissible-vector-retrieval.test.js",
    role: "DVI_PREPARATION_RECONCILIATION_VERIFICATION"
  }),
  "exact-git-source": Object.freeze({
    path: "scripts/lib/exact-git-source.js",
    role: "IMMUTABLE_GIT_BUILD_INPUT"
  }),
  "exact-git-source-tests": Object.freeze({
    path: "test/exact-git-source.test.js",
    role: "IMMUTABLE_GIT_BUILD_VERIFICATION"
  }),
  "gate2-build-runner": Object.freeze({
    path: "scripts/build-gate2-template.js",
    role: "EXACT_GIT_ARTIFACT_BUILDER"
  }),
  "gate2-exact-build-bootstrap": Object.freeze({
    path: "scripts/build-gate2-exact.js",
    role: "ISOLATED_EXACT_GIT_BUILD_BOOTSTRAP"
  }),
  "immutable-deployment-attestation-ledger": Object.freeze({
    path: "docs/IMMUTABLE_DEPLOYMENT_ATTESTATION.md",
    role: "IMMUTABLE_DEPLOYMENT_ATTESTATION_BOUNDARY"
  }),
  "integrated-live-drill-harness": Object.freeze({
    path: "src/cloud/integrated-live-drill.js",
    role: "INTEGRATED_PROVIDER_DRILL_EVIDENCE_CONTRACT"
  }),
  "integrated-live-drill-authorization": Object.freeze({
    path: "src/cloud/integrated-live-drill-authorization.js",
    role: "INTEGRATED_PROVIDER_DRILL_AUTHORIZATION_AND_FINALIZATION_CONTRACT"
  }),
  "integrated-live-drill-authorization-tests": Object.freeze({
    path: "test/integrated-live-drill-authorization.test.js",
    role: "INTEGRATED_PROVIDER_DRILL_SIGNED_CONTRACT_VERIFICATION"
  }),
  "integrated-live-drill-child-authorization": Object.freeze({
    path: "src/cloud/integrated-live-drill-child-authorization.js",
    role: "INTEGRATED_PROVIDER_DRILL_SIGNED_ONE_USE_CHILD_LAUNCH_AUTHORIZATION"
  }),
  "integrated-live-drill-child-authorization-tests": Object.freeze({
    path: "test/integrated-live-drill-child-authorization.test.js",
    role: "INTEGRATED_PROVIDER_DRILL_CHILD_AUTHORIZATION_VERIFICATION"
  }),
  "integrated-live-drill-control-ledger": Object.freeze({
    path: "src/cloud/integrated-live-drill-control-ledger.js",
    role: "INTEGRATED_PROVIDER_DRILL_DURABLE_AUTHORIZATION_AND_SPEND_LEDGER"
  }),
  "integrated-live-drill-control-ledger-tests": Object.freeze({
    path: "test/integrated-live-drill-control-ledger.test.js",
    role: "INTEGRATED_PROVIDER_DRILL_DURABLE_CONTROL_LEDGER_VERIFICATION"
  }),
  "integrated-live-drill-finalizer": Object.freeze({
    path: "src/cloud/integrated-live-drill-finalizer.js",
    role: "INTEGRATED_PROVIDER_DRILL_PACKET_A_FAIL_CLOSED_FINALIZER"
  }),
  "integrated-live-drill-finalizer-runner": Object.freeze({
    path: "scripts/gate2-integrated-live-drill-finalizer.js",
    role: "INTEGRATED_PROVIDER_DRILL_PACKET_A_OFFLINE_FINALIZER_RUNNER"
  }),
  "integrated-live-drill-recovery-continuity": Object.freeze({
    path: "src/cloud/integrated-live-drill-recovery-continuity.js",
    role: "INTEGRATED_PROVIDER_DRILL_LOCAL_RECOVERY_CONTINUITY_SCAFFOLD"
  }),
  "integrated-live-drill-recovery-continuity-tests": Object.freeze({
    path: "test/integrated-live-drill-recovery-continuity.test.js",
    role: "INTEGRATED_PROVIDER_DRILL_LOCAL_RECOVERY_CONTINUITY_VERIFICATION"
  }),
  "integrated-live-drill-recovery-continuity-fixture": Object.freeze({
    path: "test/helpers/integrated-live-drill-recovery-continuity-fixture.js",
    role: "INTEGRATED_PROVIDER_DRILL_TRUSTED_PRE_CALL_TEST_FIXTURE"
  }),
  "integrated-live-drill-recovery-continuity-worker": Object.freeze({
    path: "test/helpers/integrated-live-drill-recovery-continuity-worker.js",
    role: "INTEGRATED_PROVIDER_DRILL_LOCAL_RECOVERY_SUBPROCESS_FIXTURE"
  }),
  "integrated-live-drill-pre-attestation-fixture": Object.freeze({
    path: "test/fixtures/integrated-live-drill-pre-attestation.json",
    role: "INTEGRATED_PROVIDER_DRILL_SIGNED_PRE_ATTESTATION_FIXTURE"
  }),
  "integrated-live-drill-synthetic-test-keys": Object.freeze({
    path: "test/helpers/synthetic-test-signing-keys.js",
    role: "INTEGRATED_PROVIDER_DRILL_SYNTHETIC_TEST_KEY_ISOLATION"
  }),
  "integrated-live-drill-runner": Object.freeze({
    path: "scripts/gate2-integrated-live-drill.js",
    role: "INTEGRATED_PROVIDER_DRILL_EVIDENCE_RUNNER"
  }),
  "integrated-live-drill-tests": Object.freeze({
    path: "test/integrated-live-drill.test.js",
    role: "INTEGRATED_PROVIDER_DRILL_EVIDENCE_VERIFICATION"
  }),
  "recovery-bundle-persistence-tests": Object.freeze({
    path: "test/recovery-bundle-persistence.test.js",
    role: "RESTART_STABLE_SIGNED_BUNDLE_SOURCE_VERIFICATION"
  }),
  "local-full-drill-harness": Object.freeze({
    path: "src/local-full-drill.js",
    role: "LOCAL_FULL_DRILL_EVIDENCE_CONTRACT"
  }),
  "local-full-drill-receipt-verifier": Object.freeze({
    path: "scripts/verify-local-full-drill-receipt.js",
    role: "LOCAL_FULL_DRILL_EVIDENCE_VERIFIER"
  }),
  "local-full-drill-runner": Object.freeze({
    path: "scripts/run-local-full-drills.js",
    role: "LOCAL_FULL_DRILL_EVIDENCE_RUNNER"
  }),
  "local-full-drill-tests": Object.freeze({
    path: "test/local-full-drill.test.js",
    role: "LOCAL_FULL_DRILL_EVIDENCE_VERIFICATION"
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
  "primary-security-runner": Object.freeze({
    path: "scripts/gate1-security.js",
    role: "PRIMARY_DATABASE_SECURITY_EVIDENCE_RUNNER"
  }),
  "proof-manifest-tests": Object.freeze({
    path: "test/proof-manifest.test.js",
    role: "PROOF_MANIFEST_EVIDENCE_VERIFICATION"
  }),
  "proof-manifest-verifier": Object.freeze({
    path: "scripts/verify-proof-manifest.js",
    role: "PROOF_MANIFEST_EVIDENCE_VERIFIER"
  }),
  "probe-runtime": Object.freeze({
    path: "infra/aws/lambda/probe.cjs",
    role: "AWS_CAPABILITY_PROBE_RUNTIME"
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
  "recovery-audit-reconciliation-tests": Object.freeze({
    path: "test/recovery-audit-sink.test.js",
    role: "RECOVERY_AUDIT_RECONCILIATION_VERIFICATION"
  }),
  "recovery-broker": Object.freeze({
    path: "src/cloud/recovery-broker.js",
    role: "RECOVERY_BROKER_RUNTIME"
  }),
  "recovery-bundle-signature": Object.freeze({
    path: "src/cloud/recovery-bundle-signature.js",
    role: "PROVIDER_FREE_STRICT_RECOVERY_BUNDLE_SIGNATURE_VERIFIER"
  }),
  "recovery-continuity-identity": Object.freeze({
    path: "src/cloud/recovery-continuity-identity.js",
    role: "PROVIDER_FREE_RECOVERY_PRE_CALL_IDENTITY_AND_BUNDLE_VERIFICATION"
  }),
  "recovery-security-contract": Object.freeze({
    path: "src/cloud/recovery-security-contract.js",
    role: "PRIMARY_MANAGED_TABLE_AND_RECOVERY_DENIAL_CONTRACT"
  }),
  "recovery-broker-runner": Object.freeze({
    path: "scripts/gate1-recovery-broker.js",
    role: "RECOVERY_BROKER_EVIDENCE_RUNNER"
  }),
  "recovery-evidence-runner": Object.freeze({
    path: "scripts/gate1-recovery.js",
    role: "RECOVERY_EVIDENCE_RUNNER"
  }),
  "recovery-publisher-key": Object.freeze({
    path: "scripts/lib/recovery-publisher-key.js",
    role: "RECOVERY_PUBLISHER_TRUST_ROOT_BOUNDARY"
  }),
  "recovery-publisher-trust": Object.freeze({
    path: "src/cloud/recovery-publisher-trust.js",
    role: "RECOVERY_PUBLISHER_PUBLIC_TRUST_DIGEST_BOUNDARY"
  }),
  "recovery-publisher-key-tests": Object.freeze({
    path: "test/recovery-publisher-key.test.js",
    role: "RECOVERY_PUBLISHER_TRUST_ROOT_VERIFICATION"
  }),
  "recovery-publication-reconciliation-tests": Object.freeze({
    path: "test/recovery-security.test.js",
    role: "RECOVERY_PUBLICATION_RECONCILIATION_VERIFICATION"
  }),
  "recovery-store": Object.freeze({
    path: "src/cloud/recovery-store.js",
    role: "RECOVERY_STORE_RUNTIME"
  }),
  "recovery-store-tests": Object.freeze({
    path: "test/recovery-store.test.js",
    role: "RECOVERY_STORE_BINDING_VERIFICATION"
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
  "signed-ingest-reconciliation-tests": Object.freeze({
    path: "test/signed-ingest.test.js",
    role: "SIGNED_INGEST_RECONCILIATION_VERIFICATION"
  }),
  "signer-runtime": Object.freeze({
    path: "infra/aws/lambda/signer.cjs",
    role: "AWS_SIGNING_RUNTIME"
  }),
  "synthetic-authority-proposal": Object.freeze({
    path: "scripts/lib/synthetic-authority-proposal.js",
    role: "SYNTHETIC_AUTHORITY_PROPOSAL_FIXTURE"
  })
});

export const RELEASE_SECURITY_SURFACE_COUNT =
  Object.keys(EXPECTED_SURFACES).length;

const RELEASE_SECURITY_RECEIPT_KEYS = Object.freeze([
  "boundedFunctionCount",
  "checks",
  "claimBoundary",
  "finalReleaseReady",
  "finalReleaseRequirements",
  "iamRoleCount",
  "lambdaPermissionCount",
  "logGroupCount",
  "manifestPath",
  "manifestSha256",
  "negativeProbeCount",
  "publicPathCount",
  "publicRouteCount",
  "reviewedOn",
  "schemaVersion",
  "securityHeaderCount",
  "status",
  "surfaceCount"
]);

const RELEASE_SECURITY_CHECK_KEYS = Object.freeze([
  "advisoryRouteIamAuthenticated",
  "apiGatewayInvokePermissionsBounded",
  "asymmetricSigningKeyBounded",
  "canonicalManifest",
  "criticalRoleDenialsPresent",
  "deploymentAttestationContractBounded",
  "evidenceOperatorTrustBounded",
  "exactPublicRouteSet",
  "exactGitArtifactInputsBounded",
  "exactSurfaceHashes",
  "generatedTemplateMatchesSource",
  "leastPrivilegeRoleActionsBounded",
  "logsBoundedAndPrivacyMinimized",
  "numericLambdaInvocationTargetsBounded",
  "publicCorsAndLambdaUrlsAbsent",
  "publicHeadersAndNegativeProbesBounded",
  "sourceSecurityMarkersPresent",
  "throttlesAndConcurrencyBounded"
]);

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
  DeploymentEvidenceRole: Object.freeze([
    "apigateway:GET",
    "cloudwatch:DescribeAlarms",
    "cloudformation:BatchDescribeTypeConfigurations",
    "cloudformation:DescribeStackDriftDetectionStatus",
    "cloudformation:DescribeStackResourceDrifts",
    "cloudformation:DescribeStackResources",
    "cloudformation:DescribeStacks",
    "cloudformation:DetectStackDrift",
    "cloudformation:DetectStackResourceDrift",
    "cloudformation:GetTemplate",
    "iam:GetRole",
    "iam:GetRolePolicy",
    "iam:ListAttachedRolePolicies",
    "iam:ListRolePolicies",
    "iam:ListRoleTags",
    "lambda:GetAlias",
    "lambda:GetFunction",
    "lambda:GetFunctionCodeSigningConfig",
    "lambda:GetFunctionConcurrency",
    "lambda:GetFunctionConfiguration",
    "lambda:GetPolicy",
    "lambda:GetFunctionRecursionConfig",
    "lambda:GetRuntimeManagementConfig",
    "lambda:ListAliases",
    "lambda:ListEventSourceMappings",
    "lambda:ListFunctionUrlConfigs",
    "lambda:ListTags",
    "lambda:ListProvisionedConcurrencyConfigs"
  ]),
  DeploymentEvidenceAlternateRole: Object.freeze(["sts:AssumeRole"]),
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
    "bedrock:Invoke*",
    "iam:*",
    "kms:GenerateMac",
    "kms:Sign",
    "lambda:Invoke*",
    "secretsmanager:GetSecretValue",
    "sts:AssumeRole"
  ]),
  AgentRole: Object.freeze([
    "iam:*",
    "kms:GenerateMac",
    "kms:Sign",
    "lambda:Invoke*",
    "secretsmanager:GetSecretValue",
    "sts:AssumeRole"
  ]),
  AuthorityRaceCallerRole: Object.freeze([
    "bedrock:Invoke*",
    "iam:*",
    "kms:GenerateMac",
    "kms:Sign",
    "lambda:InvokeFunction",
    "secretsmanager:GetSecretValue",
    "sts:AssumeRole"
  ]),
  AuthorityRole: Object.freeze([
    "bedrock:Invoke*",
    "iam:*",
    "kms:GenerateMac",
    "kms:Sign",
    "lambda:Invoke*",
    "secretsmanager:ListSecrets",
    "sts:AssumeRole"
  ]),
  BoundaryRole: Object.freeze([
    "bedrock:Invoke*",
    "iam:*",
    "kms:GenerateMac",
    "kms:Sign",
    "secretsmanager:GetSecretValue",
    "sts:AssumeRole"
  ]),
  DemoRole: Object.freeze([
    "bedrock:Invoke*",
    "iam:*",
    "kms:GenerateMac",
    "kms:Sign",
    "lambda:Invoke*",
    "secretsmanager:GetSecretValue",
    "sts:AssumeRole"
  ]),
  DeploymentEvidenceRole: Object.freeze([
    "bedrock:*",
    "kms:*",
    "lambda:Invoke*",
    "secretsmanager:*",
    "sts:AssumeRole"
  ]),
  DeploymentEvidenceAlternateRole: Object.freeze([
    "bedrock:*",
    "iam:*",
    "kms:*",
    "lambda:Invoke*",
    "secretsmanager:*",
    "sts:AssumeRole"
  ]),
  SignerRole: Object.freeze([
    "bedrock:Invoke*",
    "iam:*",
    "lambda:Invoke*",
    "secretsmanager:GetSecretValue",
    "sts:AssumeRole"
  ])
});

const SOURCE_MARKERS = Object.freeze({
  "actions-checkout-normalizer": Object.freeze([
    "const OFFICIAL_REPOSITORY_ID = \"1317716765\"",
    "const CI_WORKFLOW_NAME = \"CI\"",
    "const READ_ONLY_PREFLIGHT_WORKFLOW_NAME =",
    "AWS Read-Only OIDC Preflight",
    ".github/workflows/aws-oidc-read-only-preflight.yml",
    "GIT_OPTIONAL_LOCKS: \"0\"",
    "environment?.GITHUB_JOB === \"verify\"",
    "environment?.GITHUB_JOB === \"read-only-preflight\"",
    "environment?.GITHUB_EVENT_NAME === \"workflow_dispatch\"",
    "environment?.EXPECTED_OFFICIAL_MAIN_COMMIT ===",
    "environment?.GITHUB_SHA",
    "fs.constants.O_NOFOLLOW",
    "descriptorStat.size === EXPECTED_WORKTREE_CONFIG_BYTES.length",
    "[0o600, 0o644].includes(descriptorStat.mode & 0o7777)",
    "process.geteuid()",
    "process.getegid()",
    "allowInactiveActionsWorktreeConfig",
    "sameSnapshot(firstSnapshot, unlinkHandle.snapshot)",
    "decisionState = checkoutState(context, permissiveLayout)",
    "sameRepositoryOwnership(ownershipBefore, decisionOwnership)",
    "fs.fstatSync(unlinkHandle.descriptor).nlink === 0",
    "assertExactGitRepositoryLayout({ rootDir: context.rootDir })",
    "PUBLIC_DIAGNOSTIC_CODES.includes(message)"
  ]),
  "actions-checkout-normalizer-tests": Object.freeze([
    "Actions PR normalization removes only exact inert residue before strict rights verification",
    "Actions main-push normalization is a strict no-op without residue",
    "Actions normalization rejects hostile residue without changing its path identity",
    "Actions normalization rejects wrong context and pathname replacement before unlink",
    "Actions normalization preserves residue when pre-unlink checkout state drifts",
    "protected read-only preflight normalization removes only exact inert residue",
    "protected read-only preflight normalization rejects context drift",
    "CI and read-only preflight order one fail-closed normalizer before strict verification",
    "scripts/normalize-actions-checkout.js"
  ]),
  "actions-ci-workflow": Object.freeze([
    "name: Normalize exact GitHub Actions checkout",
    "GIT_OPTIONAL_LOCKS: \"0\"",
    "NODE_OPTIONS: \"\"",
    "run: node scripts/normalize-actions-checkout.js",
    "name: Install locked dependencies",
    "name: Verify proof manifest"
  ]),
  "admissible-vector-retrieval": Object.freeze([
    "connectionStringForDatabase(",
    "\"tideproof\"",
    "FROM tp_api.g1_prepare_vector_set_v1(",
    "FROM tp_api.g1_observe_vector_exclusion_v1(",
    "FROM tp_api.g1_resolve_vector_set_v1(",
    "FROM tp_api.g1_rank_vector_set_v1(",
    "FROM tp_api.g1_delete_vector_set_v1(",
    "g1_vector_candidates_embedding_idx",
    "crdb_internal.cluster_id()::STRING",
    "nearestExcludedCloserThanRanked: true",
    "requiredExclusionObservationsSha256",
    "requiredExclusionsBoundToSnapshot: true",
    "tideproof.gate1.admissible-vector-proof.v2",
    "FROM tp_api.g1_commit_dvi_selection_v1(",
    "runId: accepted.runId",
    "authorityEvidenceBindingSha256",
    "rankedSequenceSha256",
    "auditorRankMatchesAuthorizer: true",
    "if (prepared)",
    "remainingExclusionCount: 0",
    "executeVectorPreparation(",
    "ADMISSIBLE_VECTOR_PREPARE_COMMIT_UNKNOWN",
    "preparationCommit: preparationCommitFor(",
    "\"read_reconciled\"",
    "authorizationRecheckRequired: true",
    "durableSelectionCommitted: true",
    "ADMISSIBLE_VECTOR_PLAN_INDEX_MISSING",
    "ADMISSIBLE_VECTOR_RESULT_ORDER_INVALID"
  ]),
  "admissible-vector-runner": Object.freeze([
    "ADMISSIBLE_VECTOR_WORKTREE_DIRTY",
    "ADMISSIBLE_VECTOR_GIT_REPLACEMENT_REJECTED",
    "ADMISSIBLE_VECTOR_GIT_INDEX_FLAGS_REJECTED",
    "trustedGitExecutable()",
    "...gitInvariantArguments()",
    "gitEnvironment(",
    "assertExactGitRepositoryLayout",
    "--no-recurse-submodules",
    "refs/heads/main:refs/remotes/origin/main",
    "TIDEPROOF_AUDITOR_DATABASE_URL",
    "TIDEPROOF_ADMISSIBLE_VECTOR_PROOF_SPEC",
    "authorizeIntegratedLiveDrillChildLaunch",
    "assertIntegratedLiveDrillChildAuthorizationCurrent",
    "DVI_PROOF",
    "ADMISSIBLE_VECTOR_POOL_CLOSE_FAILED",
    "--proof",
    "not an accepted DVI plan/exclusion receipt"
  ]),
  "authority-identity-contract": Object.freeze([
    "tideproof.authority.identity-contract.v1",
    "tideproof.authority.logical-action.v1",
    "tideproof.authority.dvi-proposal-identity.v1",
    "selectedEvidenceId",
    "selectedEvidenceDigest",
    "proposalContextOnlyFields",
    "attemptOnlyFields",
    "databaseOwnedFields",
    "AUTHORITY_DVI_PROPOSAL_TIME",
    "logicalAuthorityKeySha256",
    "authorizationBindingSha256"
  ]),
  "authority-identity-ledger": Object.freeze([
    "SOURCE_RUNTIME_BOUND_PROVIDER_VALIDATION_PENDING",
    "tideproof.authority.dvi-selection-receipt.v1",
    "UTF-16 code-unit ordering without Unicode normalization",
    "Only an explicit durable database transition may create a later epoch.",
    "Client input cannot select, increment, or reset the epoch.",
    "CockroachDB v26.2 execution remains pending"
  ]),
  "authority-identity-tests": Object.freeze([
    "attempt and proposal context cannot enter logical action identity",
    "only an explicit authorization epoch remints a logical authority key",
    "a new proposal changes authorization binding but not the authority key",
    "identity inputs reject noncanonical text, digests, and timestamps"
  ]),
  "authority-evidence-runner": Object.freeze([
    "dvi_selection_receipt_mismatch",
    "logical_authority_already_spent",
    "new retrieval reminted an already-spent logical authority",
    "new retrieval changed ${field}"
  ]),
  "authority-capability-race-runner": Object.freeze([
    "class QueryReadyBarrier",
    "query-ready barrier timed out",
    "await pendingResolution.catch(() => {})",
    "runStoredFunctionHeldExpiryProof",
    "runStoredReplayHeldExpiryProof",
    "runReplayClockPairBoundaryControl",
    "temporary-replay-lock-probe",
    "amplified old two-clock replay control did not cross proposal expiry",
    "stored replay currentness and reported database time used different clocks",
    "runStoredProtectedEffectHeldExpiryProof",
    "protected effect did not wait on unique occupancy",
    "runRecoveryResolverHeldExpiryProof",
    "recovery resolver did not wait behind the receipt intent",
    "runRecoveryResolverEvidenceExpiryProof",
    "temporary-recovery-evidence-expiry-lock-probe",
    "runRecoveryResolverConflictActivationProof",
    "temporary-recovery-conflict-activation-lock-probe",
    "PRIMARY_RECOVERY_SOURCE_DATABASE_URL"
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
    "authorityTransferred: false",
    "row.decision_proposal_digest",
    "authorizationBindingSha256",
    "tideproof.database-commit-result.v1",
    "\"read_reconciled\"",
    "requiresFreshAuthorization",
    "logical_authority_replay",
    "row.outbox_request_digest",
    "row.outbox_authorization_binding_sha256",
    "canonicalJson(row.outbox_payload)",
    "sha256Hex(row.outbox_payload)",
    "row.outbox_payload_digest",
    "row.lease_expires_at",
    "normalizeReceiptProposal(row, request)",
    "receipt_proposal_authority_evidence_binding_sha256",
    "receipt_proposal_authorization_binding_sha256",
    "receipt_proposal_selected_evidence_digest",
    "row.observed_holder_operation_id",
    "row.observed_fence",
    "committedProposalDigest",
    "committedSelectedEvidenceId",
    "clientClosed = true",
    "tideproof.aws-semantic-failure.v1",
    "Dimensions: [[\"Deployment\", \"Service\"]]",
    "process.stdout.write(",
    "result.code !== \"STATUS_ONLY_NO_AUTHORIZATION\"",
    "tideproof.aws-authority-boundary.v4",
    "tideproof.aws-authority-changed-input-denial.v2",
    "class OperationDigestMismatchError",
    "probeOriginalRequest !== null",
    "AUTHORITY_PROBE_PRECONDITION_REJECTED",
    "AUTHORITY_PROBE_UNEXPECTED_RETURN",
    "operationDigestMismatch(error)",
    "databaseRejected: true",
    "durableReceiptCreated: false",
    "operation digest mismatch",
    "DENIED_CHANGED_INPUT",
    "AUTHORITY_CHANGED_INPUT_ACCEPTED"
  ]),
  "authority-runtime-identity-tests": Object.freeze([
    "derives all identity digests without a client epoch",
    "transport replacement cannot remint logical action or proposal identity",
    "Unicode-key insertion order",
    "AUTHORITY_DVI_SELECTION_MISMATCH"
  ]),
  "authority-runtime-reconciliation-tests": Object.freeze([
    "authority reconciles an ambiguous COMMIT instead of retrying the spend",
    "authority reconciles an ACK-lost semantic denial through its durable identity",
    "authority reconciles a full transport replacement by one stable logical action",
    "authority reconciliation rejects every drifted outbox binding",
    "authority reconciliation rejects every drifted proposal binding",
    "authority reconciliation binds held-denial observation fields",
    "direct and reconciled denied commits preserve one durable reason",
    "tideproof.database-commit-result.v1",
    "COMMITTED_BUT_NO_LONGER_CURRENT",
    "result.commit.observation, \"read_reconciled\"",
    "result.committedProposalDigest",
    "provider negative probe denies changed input under the committed operation",
    "changed-input probe requires the exact original durable receipt",
    "changed-input probe rejects a drifted original receipt",
    "changed-input denial is emitted only for a mismatch from the spend call",
    "changed-input probe rolls back an unexpected database return before commit",
    "receipt_proposal_payload",
    "destination: \"drifted\""
  ]),
  "authority-store": Object.freeze([
    "runtimeDatabaseConfig({",
    "bootstrapDatabaseConfig({",
    "tp_ledger.g1_dvi_selection_receipts",
    "dvi_selection_receipt_mismatch",
    "logical_authority_already_spent",
    "authorization epoch advancement requires an explicit new-authorization receipt",
    "SELECT statement_timestamp() AS database_now",
    "proposal.expires_at > statement_timestamp()",
    "setProposalExpiryAfterMsForTest",
    "waitForProposalExpiryForTest",
    "unknownDatabaseResult({",
    "requiresFreshAuthorization",
    "payload_canonical STRING NOT NULL",
    "const exactOutbox =",
    "canonicalJson(state.outbox_payload)",
    "canonicalJson(row.receipt_proposal_payload)",
    "sha256(canonicalJson(row.outbox_payload))",
    "dviProposalIdentityDigestFor(proposalInput)",
    "proposalLogicalActionDigest",
    "observed_holder_operation_id",
    "observed_fence",
    "tp_private.g1_vector_retrieval_sets",
    "tp_private.g1_vector_exclusions",
    "g1_vector_candidates_embedding_idx",
    "CHECK (octet_length(assertion) BETWEEN 1 AND 4096)"
  ]),
  "aws-alternate-principal-denial-runner": Object.freeze([
    "AWS_EVIDENCE_EXPECTED_ALTERNATE_PRINCIPAL_ARN",
    "AWS_ATTEST_DENIAL_UNEXPECTEDLY_ALLOWED",
    "expectedPrincipalArn: alternatePrincipalArn",
    "tideproof.gate2.aws-alternate-principal-denial.v3",
    "errorCode: \"AccessDenied\"",
    "reproduceExactBuild({",
    "validateExactBuildReproduction(",
    "AWS_ATTEST_DENIAL_EXACT_BUILD_MISMATCH",
    "validateBuildReceipt(buildReceipt",
    "loadAwsProviderRuntime({",
    "providerRuntime.runtimeSha256",
    "error?.name === \"AccessDenied\"",
    "error.$metadata.attempts === 1"
  ]),
  "aws-authority-race": Object.freeze([
    "trustedGitExecutable()",
    "...gitInvariantArguments()",
    "gitEnvironment(",
    "assertExactGitRepositoryLayout",
    "assertCleanExactGitCheckout",
    "--no-recurse-submodules",
    "DescribeStackResourceCommand",
    "receipt.treeDigest !== checkout.treeDigest",
    "runId: options.runId",
    "authorizeIntegratedLiveDrillChildLaunch",
    "assertIntegratedLiveDrillChildAuthorizationCurrent",
    "AWS_AUTHORITY_RACE",
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
    "stateObservedAt >= observationBinding.leaseExpiresAt",
    "committedProposalDigest",
    "committedAuthorityEvidenceBindingSha256",
    "committedSelectedEvidenceDigest",
    "authorityEvidenceBindingSha256",
    "selectedEvidenceBindingSha256",
    "operation_replay",
    "OPERATION_DIGEST_MISMATCH",
    "AUTHORITY_RACE_CHANGED_INPUT_REJECTED",
    "distinctInvocationDigests",
    "new Set(digests).size === names.length",
    "value.originalRequestDigest !== observation.winner.requestDigest",
    "value.durableReceiptCreated !== false",
    "expectedAuthorizationBindingSha256",
    ":[1-9][0-9]*$/.test("
  ]),
  "aws-boundary-ledger": Object.freeze([
    "The command is read-only and fail closed.",
    "The evidence runner rejects endpoint, profile, proxy, custom-CA, Git replacement/graft/alternate, shallow-checkout, and tree-digest contamination",
    "`tideproof.aws-authority-race-receipt.v7`",
    "Every project input is then read as a regular tracked blob from the exact `HEAD` commit",
    "The `proof` aliases are monitored pointers for inspection and metadata only, not invocation authority.",
    "npm run gate2:aws-attest",
    "Attestation accepts only a never-updated `CREATE_COMPLETE` stack",
    "disposable `prooftoact-gate2-probe` stack",
    "fresh `prooftoact-gate2` main stack",
    "must never be updated",
    "Any wrong-run, cross-DVI,",
    "ambiguous, replay-drifted, changed-input-accepted, expanded, stale, extra,",
    "A missing or drifted original receipt",
    "Require five distinct Lambda request IDs and five distinct AWS Invoke",
    "result is not evidence.",
    "Release Git children inherited caller selection and repository hooks",
    "reference-transaction",
    "exactly two standalone official"
  ]),
  "aws-deployment-attestation": Object.freeze([
    "tideproof.gate2.aws-deployment-expectation.v5",
    "tideproof.gate2.aws-deployment-attestation-snapshot.v6",
    "tideproof.gate2.aws-deployment-attestation.v6",
    "integratedLiveDrillAuthorizationAttestationSha256",
    "signDeploymentAttestationReceipt(",
    "validateDeploymentEvidenceBasis({",
    "validateEvidenceOperatorTrust(",
    "primaryRuntimeRolePolicyCensus: true",
    "primaryRuntimeConfigurationsBound: true",
    "validateStackResourceBindings(",
    "revisionFencedSnapshots: true",
    "apiGatewayActiveDeploymentBound: true",
    "AWS_ATTEST_API_GATEWAY_ACTIVE_DEPLOYMENT",
    "AWS_ATTEST_API_GATEWAY_DEPLOYMENT_CENSUS",
    "AWS_ATTEST_CREATE_ONLY_API_DEPLOYMENT",
    "snapshot.stack.lastUpdatedAt === null",
    "snapshot.stack.stackStatus === \"CREATE_COMPLETE\"",
    "eventSourceMappings",
    "numericVersionArn",
    "attestedResourceDriftInSync: true",
    "alternatePrincipalDenied: true",
    "not administrator exclusion"
  ]),
  "aws-deployment-attestation-runner": Object.freeze([
    "loadAwsProviderRuntime({",
    "providerRuntime.runtimeSha256",
    "provider.detectStackDrift(",
    "AuthoritySemanticFailureAlarm",
    "BoundarySemanticFailureAlarm",
    "provider.describeStackResourceDrifts(",
    "provider.describeStackResources(",
    "provider.getApi(",
    "provider.getDeployment(",
    "provider.getDeployments(",
    "provider.getIntegration(",
    "provider.getRoute(",
    "provider.getStage(",
    "provider.getFunctionConfiguration(",
    "provider.getFunctionConcurrency(",
    "provider.listProvisionedConcurrencyConfigs(",
    "provider.listAliases(",
    "provider.listEventSourceMappings(",
    "provider.listFunctionUrlConfigs(",
    "provider.listRoleTags(",
    "provider.listTags(",
    "provider.getRolePolicy(name, policyName)",
    "provider.listAttachedRolePolicies(name)",
    "provider.listRolePolicies(name)",
    "AWS_ATTEST_COLLECT_PROVISIONED_CONCURRENCY",
    "AWS_ATTEST_COLLECT_REVISION_FENCE",
    "AWS_ATTEST_COLLECT_API_DEPLOYMENT_CENSUS",
    "AWS_ATTEST_COLLECT_STACK_TIME",
    "stack.LastUpdatedTime === undefined",
    "validateBuildReceipt(buildRecord.value",
    "validateExactBuildReproduction(buildRecord, reproducedBuild)",
    "stackResourceBindings(",
    "validateDeploymentAttestationPair({"
  ]),
  "aws-deployment-attestation-tests": Object.freeze([
    "deployment expectation and basis bind exact build and configuration evidence",
    "attestation runners accept only exact private-evidence modes",
    "one signed snapshot binds the five primary runtime functions and roles",
    "an old API deployment cannot be relabeled across a stack update",
    "same-account-shadow-function",
    "API active deployment pending",
    "API newer pending deployment",
    "API permissive CORS",
    "API access log destination",
    "AWS_ATTEST_EXACT_BUILD_MISMATCH",
    "pre/post pair rejects forged evidence, role replacement, and revision drift",
    "snapshot revision fence must bind two identical provider observations"
  ]),
  "aws-provider-bundle-entry": Object.freeze([
    "export { createAwsProviderClients } from \"./aws-provider-runtime.js\";"
  ]),
  "aws-provider-runtime": Object.freeze([
    "createAwsProviderClients({",
    "authSchemePreference: [\"sigv4\"]",
    "ignoreConfiguredEndpointUrls: true",
    "maxAttempts: 1",
    "ListProvisionedConcurrencyConfigsCommand",
    "GetDeploymentCommand",
    "GetDeploymentsCommand",
    "ListEventSourceMappingsCommand",
    "decodePolicyDocument(",
    "RoleSessionName: \"tideproof-evidence-denial\""
  ]),
  "aws-provider-runtime-loader": Object.freeze([
    "RUNTIME_PATH = /^dist\\/aws\\/evidence-provider-",
    "receipt.path === `dist/aws/evidence-provider-${receipt.sha256}.mjs`",
    "assertSafeProjectPath({",
    "stat.isFile() && !stat.isSymbolicLink()",
    "sha256(bytes) === receipt.sha256",
    "data:text/javascript;base64",
    "Object.keys(providerModule).join(\"\\n\") === \"createAwsProviderClients\""
  ]),
  "aws-provider-clients-tests": Object.freeze([
    "AWS provider policy decoding accepts only structured JSON policies",
    "AWS provider clients load only the pinned explicit-credential SDK surface",
    "content-addressed production provider bundle loads every client",
    "AWS evidence runners do not execute a PATH-selected AWS CLI",
    "alternate denial rejects a fabricated provider receipt before runtime load",
    "AWS provider runtime imports the exact receipt-hashed bytes"
  ]),
  "boundary-runtime": Object.freeze([
    "EXPECTED_ADVISORY_CALLER_ROLE_ARN",
    "assumed-role/${escapedRoleName}",
    "SIGNED_CALLER_REJECTED",
    "tideproof.aws-semantic-failure.v1",
    "Dimensions: [[\"Deployment\", \"Service\"]]",
    "process.stdout.write(",
    "result.body?.status === \"UNKNOWN_DO_NOT_ACT\""
  ]),
  "canonical-json-contract": Object.freeze([
    "compareCanonicalKeys(left, right)",
    ".sort(([left], [right]) => compareCanonicalKeys(left, right))",
    "return JSON.stringify(value);"
  ]),
  "commit-reconciliation-contract": Object.freeze([
    "tideproof.database-commit-result.v1",
    "COMMITTED_BUT_NO_LONGER_CURRENT",
    "UNKNOWN_DO_NOT_ACT",
    "direct_ack",
    "read_reconciled",
    "DATABASE_COMMIT_TIME_INVALID",
    "databaseTimestampFromDriver",
    "requiresFreshAuthorization"
  ]),
  "commit-reconciliation-ledger": Object.freeze([
    "SOURCE_RUNTIME_BOUND_PROVIDER_VALIDATION_PENDING",
    "ProofToAct treats a lost database acknowledgement as an unknown observation",
    "Unknown results carry `null`; client time is rejected",
    "Denied receipts and expired or superseded positive receipts are durable history",
    "no live exactly-once or provider-concurrency claim is added",
    "Classifier-dependent rollback after COMMIT dispatch",
    "Direct replay currentness omitted the outbox",
    "Digest label without durable payload verification",
    "Invocation identity projected as committed replay identity"
  ]),
  "commit-reconciliation-tests": Object.freeze([
    "direct ACK and read reconciliation share one exact commit schema",
    "stale or denied durable history requires fresh authorization",
    "unknown reconciliation never invents database time or a commit",
    "commit schema rejects client clocks and contradictory authority state",
    "trusted pg TIMESTAMPTZ values normalize before commit construction"
  ]),
  "aws-evidence-identity": Object.freeze([
    "AWS_EVIDENCE_ENDPOINT_OVERRIDE",
    "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS: \"true\"",
    "expectedCallerUserId",
    "bindingDigest"
  ]),
  "aws-evidence-identity-tests": Object.freeze([
    "caller binding supports an exact IAM user for preflight",
    "AIDATIDEPROOF001"
  ]),
  "aws-oidc-identity-bootstrap": Object.freeze([
    "workflow_dispatch:",
    "official_main_commit:",
    "id-token: write",
    "environment: aws-preflight",
    "shell: /usr/bin/bash --noprofile --norc -euo pipefail {0}",
    "ACTIONS_ID_TOKEN_REQUEST_URL",
    "(pipelines|run-actions-",
    "AWS_APPROVED_ACCOUNT_ID_SHA256",
    "GITHUB_REPOSITORY_ID:-}\" == \"1317716765",
    "GITHUB_SHA:-}\" == \"$EXPECTED_OFFICIAL_MAIN_COMMIT",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "compgen -A variable AWS_ENDPOINT_URL",
    '.repository_owner_id == "252500266"',
    "repo:Flash-Bri@252500266/prooftoact@1317716765:environment:aws-preflight",
    "refs/heads/main",
    "role/ProofToActPreflight",
    "/usr/local/aws-cli/v2/",
    "aws_mode_value & 0022",
    "assume-role-with-web-identity",
    "--role-session-name release-proof",
    "--duration-seconds 900",
    "^ASIA[A-Z0-9]{16}$",
    ".UserId == $assumed_role_id",
    "--cli-connect-timeout 10",
    "--cli-read-timeout 20",
    "--disable",
    "--no-options",
    "^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$",
    "--symmetric",
    "retention-days: 1",
    "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
  ]),
  "aws-oidc-read-only-ledger": Object.freeze([
    "SOURCE AND PROVIDER IDENTITY PATH VERIFIED — ACCEPTED PREFLIGHT RECEIPT PENDING",
    "This lane makes AWS CloudShell optional",
    "ProofToActPreflight/release-proof",
    "ProofToActReadOnlyPreflight/read-only-preflight",
    "external setup gate that source cannot prove",
    "Do not embed an AWS account ID or its digest",
    "canonical unpadded Base64URL for 32 bytes",
    "exactly 20 AWS",
    "17 nested calls",
    "oidc#immutable-subject-claims",
    "created_at` is `2026-07-30T22:07:23Z",
    "use_default: true",
    "repo:Flash-Bri@252500266/prooftoact@1317716765",
    "provider-side gate and residual trust boundary",
    "observed AWS + $0.02 < $13.14",
    "exactly `$13.12` fails",
    "maximum remains `$0.02` for each complete preflight",
    "fixed source-bound failure stages",
    "unclassified fixed stage",
    "Deployment and evidence",
    "Deliberately absent and pending",
    "A source-verifier `PASS` is not a provider receipt"
  ]),
  "aws-oidc-read-only-role-template": Object.freeze([
    "Source-only scaffold",
    "separate human authorization",
    "ProofToActReadOnlyPreflight",
    "repo:Flash-Bri@252500266/prooftoact@1317716765:environment:aws-read-only-preflight",
    "token.actions.githubusercontent.com:repository_id",
    "token.actions.githubusercontent.com:repository_owner_id",
    "token.actions.githubusercontent.com:workflow",
    "token.actions.githubusercontent.com:ref",
    "ProofToActReadOnlyPreflightExactReads",
    "budgets:ViewBudget",
    "ce:GetCostAndUsage",
    "servicequotas:ListServiceQuotas",
    "DenyEverythingExceptExactPreflightReads",
    "NotAction"
  ]),
  "aws-oidc-read-only-runner": Object.freeze([
    "set +x",
    "GITHUB_REPOSITORY_ID:-}\" == \"1317716765",
    "source_commit\" == \"$EXPECTED_OFFICIAL_MAIN_COMMIT",
    "compgen -A variable AWS_ENDPOINT_URL",
    '.repository_owner_id == "252500266"',
    "repo:Flash-Bri@252500266/prooftoact@1317716765:environment:aws-read-only-preflight",
    "--role-session-name read-only-preflight",
    "--duration-seconds 900",
    "^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$",
    "account get-region-opt-status",
    "service-quotas list-service-quotas",
    "scripts/gate2-aws-preflight.js",
    "tideproof.gate2.aws-preflight.v7",
    "approvedPreflightAllowanceUsd",
    "prooftoact.aws-oidc-read-only-preflight-receipt.v1",
    "arn:aws:(iam|sts|s3)",
    "--cipher-algo AES256"
  ]),
  "aws-oidc-read-only-source-tests": Object.freeze([
    "OIDC source receipt remains source-only with provider acceptance pending",
    "read-only role template is exact and rejects expanded trust or authority",
    "identity workflow stays manual, exact-commit-bound, and STS-only",
    "read-only workflow stays separately protected and action-pinned",
    "read-only runner rejects direct mutation calls and shell tracing",
    "receipt secret contract is canonical unpadded Base64URL for 32 bytes",
    "underlying preflight inventory is exact and cannot bypass its reader",
    "preflight identity accepts only the two exact role/session pairings"
  ]),
  "aws-oidc-read-only-source-verifier": Object.freeze([
    "prooftoact.aws-oidc-preflight-source-verification.v2",
    "SOURCE_CONTRACT_PASS_ACCEPTED_PROVIDER_RECEIPT_PENDING",
    "validateReadOnlyRoleTemplate",
    "validateIdentityWorkflow",
    "validateReadOnlyWorkflow",
    "validateReadOnlyRunner",
    "validateUnderlyingPreflight",
    "exactReadOnlyWorkflowAwsCallCount",
    "accountSafetyPreflightCurrentSourceCallsExact",
    "receiptSecretExact32ByteBase64url",
    "providerSetup: \"EXTERNAL_STATE_NOT_ATTESTED\"",
    "providerExecution: \"OUTSIDE_SOURCE_RECEIPT\"",
    "deploymentRoleOrWorkflowAdded: false",
    "providerMutationExplicitlyDenied: true",
    "providerExecutionClaimAbsent: true"
  ]),
  "aws-oidc-read-only-workflow": Object.freeze([
    "workflow_dispatch:",
    "official_main_commit:",
    "id-token: write",
    "environment: aws-read-only-preflight",
    "ref: ${{ github.sha }}",
    "persist-credentials: false",
    "AWS_APPROVED_ACCOUNT_ID_SHA256",
    "LD_PRELOAD: \"\"",
    "/usr/bin/bash scripts/run-aws-oidc-read-only-preflight.sh",
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/setup-node@820762786026740c76f36085b0efc47a31fe5020",
    "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
    "retention-days: 1"
  ]),
  "aws-preflight": Object.freeze([
    "awsPreflightIdentityExpectation(",
    "trustedAwsCliExecutable(",
    "trustedGitExecutable(",
    "trustedGitCheckout(",
    "gitInvariantArguments()",
    "--untracked-files=all",
    "GIT_NO_REPLACE_OBJECTS: \"1\"",
    "--no-paginate",
    "sts",
    "get-caller-identity",
    "validateAwsEvidenceCaller(callerIdentity",
    "readAwsJson(",
    "AWS_GATE2_PREFLIGHT_RUNTIME_CALL_INVENTORY",
    "createAwsPreflightRuntimeCallReader(",
    "runtimeCalls.assertComplete()",
    "timeout: 30_000",
    "killSignal: \"SIGKILL\"",
    "--cli-connect-timeout",
    "--cli-read-timeout",
    "describe-stacks",
    "get-cost-and-usage",
    '"--group-by"',
    '"Type=DIMENSION,Key=RECORD_TYPE"',
    "get-foundation-model"
  ]),
  "aws-preflight-validator": Object.freeze([
    "validateAwsGate2PreflightIdentityExpectation(",
    "ProofToActPreflight",
    "release-proof",
    "ProofToActReadOnlyPreflight",
    "read-only-preflight",
    "APPROVED_PREFLIGHT_IDENTITY_LANES.find(",
    "NextPageToken",
    "MAX_COST_EXPLORER_REQUESTS = 1",
    "APPROVED_PREFLIGHT_METERED_SPEND_CAP_USD = 0.02",
    "USD_MICROS = 1_000_000",
    "PREFLIGHT_ALLOWANCE_AWS_CEILING",
    "PREFLIGHT_ALLOWANCE_TOTAL_EXPOSURE_CEILING",
    "COST_RECORD_TYPES.includes(group.Keys[0])",
    "positiveRecordTypeExposureUsd",
    "negativeOffsetsAppliedToExposure: false",
    "tideproof.gate2.aws-preflight.v7"
  ]),
  "aws-preflight-tests": Object.freeze([
    "AWS preflight rejects every non-lane identity expectation before STS",
    "AWS preflight stops after STS when the caller misses its expectation",
    "AWS Gate Two preflight rejects every Cost Explorer pagination token",
    "AWS preflight runtime reader enforces the exact ordered call cardinality",
    "AWS Gate Two preflight reserves the full allowance below both ceilings",
    "standalone preflight ignores caller Git PATH and configuration",
    "trusted Git rejects unapproved paths, owners, and writable modes"
  ]),
  "aws-readiness": Object.freeze([
    "LOCAL_ONLY_PASS",
    "awsPreflight: preflight ? \"PASS\" : \"NOT_RUN\"",
    "AWS was not queried or mutated",
    "upload and deployment remain separate reviewed actions",
    "tideproof.gate2-build.v6",
    "ISOLATED_EXACT_GIT_CHECKOUT_AND_BLOBS",
    "evidenceProviderRuntime",
    "AWS_READINESS_BUILD_CONTROL_SET",
    "validateDependencySnapshot(",
    "templateReceipt(JSON.parse",
    "gitBlobId(inputBytes)",
    "AWS_READINESS_EXACT_GIT_INPUT_DIGEST",
    "validateOfficialLocalGitConfiguration(",
    "officialFetchArguments()",
    "--readiness-fetched-official-main",
    "READINESS_FETCH_BOUND_PASS",
    "credential.helper=",
    "http.sslVerify=true"
  ]),
  "aws-readiness-tests": Object.freeze([
    "AWS readiness rejects repository-local provenance and transport overrides",
    "AWS readiness fetches only the explicit official URL with sanitized transport",
    "--readiness-fetched-official-main",
    "verifyExactCheckout: fixtureExactCheckout(current.projectRoot)"
  ]),
  "aws-security-tests": Object.freeze([
    "Gate Two template invokes numeric versions and keeps monitored aliases",
    "EvidenceOperatorPrincipalArn",
    "DeploymentEvidenceRole",
    "DeploymentEvidenceAlternateRole",
    "cloudformation:DescribeStackResources",
    "SECURITY DEFINER bodies resolve every application relation by schema",
    "(?:\\bWITH|,)",
    "cteNames.has(match[1].toLowerCase())",
    "generated templates exactly match the reviewed builders",
    "boundary semantic failures emit provider-bound EMF without request data"
  ]),
  "aws-template-generated": Object.freeze([
    "\"Type\": \"AWS::KMS::Key\"",
    "\"ReservedConcurrentExecutions\": 2",
    "\"DisableExecuteApiEndpoint\": false",
    "\"ApiKeySelectionExpression\": \"$request.header.x-api-key\"",
    "\"IpAddressType\": \"ipv4\"",
    "\"IntegrationMethod\": \"POST\"",
    "\"EvidenceOperatorPrincipalArn\": {",
    "\"DeploymentEvidenceRole\": {",
    "\"DeploymentEvidenceAlternateRole\": {",
    "\"ManagedPolicyArns\": []",
    "\"Ref\": \"BoundaryVersion\"",
    "\"AgentVersionArn\": {",
    "\"EXPECTED_ADVISORY_CALLER_ROLE_ARN\": {",
    "\"AuthorizationType\": \"AWS_IAM\"",
    "\"Type\": \"AWS::Lambda::Permission\"",
    "\"Namespace\": \"ProofToAct/GateTwo\"",
    "\"MetricName\": \"SemanticFailures\""
  ]),
  "aws-template-source": Object.freeze([
    "properties.ReservedConcurrentExecutions = concurrency;",
    "Type: \"AWS::KMS::Key\"",
    "DisableExecuteApiEndpoint: false",
    "ApiKeySelectionExpression: \"$request.header.x-api-key\"",
    "IpAddressType: \"ipv4\"",
    "IntegrationMethod: \"POST\"",
    "ReadLambdaEventSourceCensus",
    "ReadSemanticAlarmDrift",
    "cloudwatch:DescribeAlarms",
    "denyAllBedrockCapabilities()",
    "denyAllKmsCapabilities()",
    "EvidenceOperatorPrincipalArn: {",
    "resources.DeploymentEvidenceRole = roleResource({",
    "resources.DeploymentEvidenceAlternateRole = roleResource({",
    "ManagedPolicyArns: []",
    "IntegrationUri: ref(\"BoundaryVersion\")",
    "FunctionName: ref(\"DemoVersion\")",
    "AGENT_FUNCTION_ARN: ref(\"AgentVersion\")",
    "EXPECTED_ADVISORY_CALLER_ROLE_ARN: getAtt(",
    "AuthorizationType: \"AWS_IAM\"",
    "ThrottlingBurstLimit: 1",
    "Type: \"AWS::Lambda::Permission\"",
    "function semanticFailureAlarm(service)",
    "semanticFailureAlarm(\"boundary\")",
    "semanticFailureAlarm(\"authority\")"
  ]),
  "aws-template-security-tests": Object.freeze([
    "deployment evidence role explicitly denies privilege escalation",
    "deployment evidence drift permission is scoped to attested resources",
    "denied.has(\"iam:*\"), false",
    "assert.equal(expected.length, 37)",
    "HTTP API integrations bind numeric versions and explicit POST semantics",
    "expected.includes(\"BoundaryIntegration\"), false",
    "semantic failure alarms bind provider-emitted boundary and authority metrics"
  ]),
  "database-runtime": Object.freeze([
    "DATABASE_CONNECTION_RUNTIME_OVERRIDE_REJECTED",
    "statementTimeoutMillis: RUNTIME_STATEMENT_TIMEOUT_MS",
    "idleTransactionTimeoutMillis: RUNTIME_IDLE_TRANSACTION_TIMEOUT_MS",
    "code === \"40003\""
  ]),
  "database-security-bootstrap-tests": Object.freeze([
    "audits posture before credentials, ownership, or grants",
    "every database SECURITY DEFINER body binds the exact session user",
    "lockInitialPublicCapability(client, bootstrapOwner)",
    "lockInitialRecoveryPublicCapability(client, bootstrapOwner)",
    "expectedPrimaryGuards",
    "sharedAuthorizerGuard",
    "schemaDefaultLock",
    "direct authority replay currentness requires the exact outbox payload",
    "g1_authority_receipt_current_v2",
    "new QueryReadyBarrier",
    "post-COMMIT ambiguity cannot enter a rollback branch",
    "proposal\\.payload = outbox\\.payload"
  ]),
  "database-security-posture": Object.freeze([
    "DATABASE_POSTURE_BOOTSTRAP_SESSION_UNSAFE",
    "DATABASE_POSTURE_BOOTSTRAP_ADMIN_REQUIRED",
    "DATABASE_POSTURE_PRINCIPAL_OPTIONS_UNSAFE",
    "DATABASE_POSTURE_EXTERNAL_PRINCIPAL_CAPABILITY",
    "DATABASE_POSTURE_STALE_PRINCIPAL",
    "DATABASE_POSTURE_EXTERNAL_MEMBERSHIP",
    "DATABASE_POSTURE_SYSTEM_GRANT_UNSAFE",
    "DATABASE_POSTURE_EXTERNAL_OBJECT_GRANT",
    "DATABASE_POSTURE_DEFAULT_GRANT_UNSAFE",
    "DATABASE_POSTURE_MANAGED_GRANT_UNEXPECTED",
    "DATABASE_POSTURE_OUT_OF_SCOPE_GRANT",
    "DATABASE_POSTURE_DIRECT_USER_GRANT",
    "DATABASE_POSTURE_CROSS_BOUNDARY_GRANT",
    "DATABASE_POSTURE_DATABASE_SET_CHANGED",
    "BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE READ ONLY",
    "version() AS database_version",
    "current_database() AS database_name",
    "object_name,",
    "object_type,",
    "FROM [SHOW GRANTS ON ROLE]",
    "FROM [SHOW SYSTEM GRANTS]",
    "WHERE database_name = current_database()",
    "FROM crdb_internal.default_privileges",
    "FROM [SHOW DATABASES]",
    "collectClusterManagedGrantPosture",
    "canonicalRoutineIdentity",
    "synthesizedAllRoleRoutineBaseline",
    "isGrantable: boolean(row?.is_grantable ?? false)"
  ]),
  "database-security-posture-tests": Object.freeze([
    "clean exhaustive database posture validates and binds the census",
    "bootstrap defaults are rejected once a managed principal or surface exists",
    "sibling database principals are recognized but remain capability-free",
    "collector uses one read-only transaction with cache-versioned role introspection",
    "collector rolls back a failed census snapshot",
    "cluster census enforces database isolation with matching barriers",
    "cluster census rejects database-set drift",
    "DATABASE_POSTURE_EXTERNAL_PRINCIPAL_CAPABILITY",
    "DATABASE_POSTURE_EXTERNAL_OBJECT_GRANT",
    "DATABASE_POSTURE_DEFAULT_GRANT_UNSAFE"
  ]),
  "demo-entry": Object.freeze([
    "createPublicDemoHandler({",
    "expectedApiId: process.env.EXPECTED_API_ID",
    "sourceCommit: process.env.SOURCE_COMMIT",
    "functionVersion: process.env.AWS_LAMBDA_FUNCTION_VERSION",
    "runScenario"
  ]),
  "dvi-selection-contract": Object.freeze([
    "tideproof.authority.dvi-selection-receipt.v2",
    "dviSelectionReceiptFor(input)",
    "dviSelectionBindingSha256For(input)",
    "dviRankedSequenceSha256For(rows)",
    "DVI_SELECTION_RECEIPT_RANK"
  ]),
  "dvi-reconciliation-tests": Object.freeze([
    "integrated retrieval reconciles exact DVI preparation after ACK loss",
    "integrated DVI proof reconciles exact preparation after ACK loss",
    "receipt.snapshot.commit.observation, \"read_reconciled\"",
    "pools.authorizerConnections, 2",
    "broken_released",
    "reconciliation_started"
  ]),
  "exact-git-source": Object.freeze([
    "GIT_NO_LAZY_FETCH: \"1\"",
    "GIT_NO_REPLACE_OBJECTS: \"1\"",
    "assertSafeLocalGitConfiguration(",
    "EXACT_GIT_SOURCE_PROMISOR",
    "assertCompleteLocalObjectClosure({",
    "--missing=print",
    "--batch-check=%(objectname) %(objecttype) %(objectsize)",
    "fsck\", \"--strict\", \"--no-dangling",
    "rev-parse\", \"--is-shallow-repository",
    "assertExactGitRepositoryLayout({",
    "rev-parse\", \"--absolute-git-dir",
    "for-each-ref\", \"--format=%(refname)\", \"refs/replace/",
    "ls-tree\", \"-z\", sourceCommit",
    "cat-file\", \"blob\", match[1]",
    "tideproof-exact-git-source",
    "EXACT_GIT_SOURCE_LOADER",
    "assertCleanExactGitCheckout({",
    "trustedGitExecutable()",
    "assertExactWorktreeBytes({",
    "assertSafeProjectPath({",
    "FORBIDDEN_TREE_PATH",
    "gitInvariantArguments()"
  ]),
  "exact-git-source-tests": Object.freeze([
    "Gate Two bundling reads project inputs from immutable Git blobs",
    "committed bytes",
    "dirty bytes",
    "EXACT_GIT_SOURCE_TREE",
    "EXACT_GIT_SOURCE_PATH",
    "exact Git bundling rejects every non-dependency path escape",
    "exact build Git processes reject ambient repository redirection",
    "exact checkout validation rejects hidden index mutations",
    "exact checkout rejects skip-worktree and hidden untracked files",
    "exact checkout rejects linked worktrees and repository object indirection",
    "exact build Git bundle materialization and import are network-free",
    "exact source rejects partial-clone state without transport or hydration",
    "artifact paths reject symlinked parent components",
    "exact build rejects committed checkout transforms",
    "exact build selects one canonical npm CLI and sanitized install environment"
  ]),
  "exact-build-reproduction": Object.freeze([
    "exactBuildRecord(bytes, code)",
    "reproduceExactBuild({",
    "validateExactBuildReproduction(",
    "npm_execpath: npmCli",
    "npm_node_execpath: process.execPath"
  ]),
  "dependency-snapshot": Object.freeze([
    "tideproof.dependency-snapshot.v1",
    "NPM_CI_IGNORE_SCRIPTS_CLEAN_CACHE",
    "DEPENDENCY_SNAPSHOT_SYMLINK",
    "relativeDirectory === \"\" && name === \".bin\"",
    "treeDigest",
    "npmCliSha256",
    "npmPackageTreeDigest"
  ]),
  "dependency-snapshot-tests": Object.freeze([
    "dependency snapshot detects a tampered installed dependency byte",
    "dependency snapshot rejects installed-tree symlinks",
    "dependency snapshot excludes only the sanitized-path root .bin shims",
    "build toolchain receipt requires executable and npm CLI digests",
    "build toolchain binds the complete npm package tree"
  ]),
  "gate2-build-runner": Object.freeze([
    "assertExactGitSourceContext({ rootDir: root, sourceCommit })",
    "exactGitSourcePlugin({",
    "exactGitInputs: exactSource.inputRecords()",
    "ISOLATED_EXACT_GIT_CHECKOUT_AND_BLOBS",
    "tideproof.gate2-build.v6",
    "buildEvidenceProviderRuntime(",
    "evidenceProviderRuntime",
    "TIDEPROOF_EXACT_BUILD_DEPENDENCY_SNAPSHOT",
    "TIDEPROOF_EXACT_BUILD_TOOLCHAIN",
    "GATE2_GENERATED_TEMPLATE_DRIFT_REQUIRES_COMMIT"
  ]),
  "gate2-exact-build-bootstrap": Object.freeze([
    "createStandaloneExactCheckout({",
    "bundle",
    "list-heads",
    "verify",
    "fetch",
    "--no-recurse-submodules",
    "checkout",
    "--detach",
    "ci",
    "--ignore-scripts",
    "createDependencySnapshot({",
    "TIDEPROOF_EXACT_BUILD_SOURCE_COMMIT",
    "TIDEPROOF_EXACT_BUILD_TREE_DIGEST",
    "EXACT_BUILD_POST_DIRTY_TREE",
    "EXACT_BUILD_STANDALONE_ROOT",
    "EXACT_BUILD_SOURCE_CHANGED",
    "GIT_NO_LAZY_FETCH: \"1\"",
    "GIT_NO_REPLACE_OBJECTS: \"1\"",
    "trustedGitExecutable()",
    "trustedTemporaryRoot()",
    "assertCleanExactGitCheckout({"
  ]),
  "immutable-deployment-attestation-ledger": Object.freeze([
    "SOURCE_CLOSED_PROVIDER_VALIDATION_PENDING",
    "Root cause:",
    "Why it was missed:",
    "Earliest detection point:",
    "Preventive controls:",
    "Residual risk:",
    "It must not say that live AWS deployment identity",
    "Accepted standalone exact-build finding",
    "Accepted trusted Git execution finding",
    "reference-transaction",
    "exactly two explicit official-main fetches",
    "network-free claim applies only to Git bundle materialization and import",
    "Accepted semantic-monitoring finding",
    "CloudWatch Embedded Metric Format",
    "alarm state transition"
  ]),
  "integrated-live-drill-harness": Object.freeze([
    "INTEGRATED_LIVE_DRILL_SCHEMA",
    "tideproof.highwater-drill-live.v1",
    "INTEGRATED_LIVE_DRILL_CANDIDATE_SCHEMA",
    "tideproof.highwater-drill-live-candidate.v1",
    "tideproof.highwater-drill-live-candidate.v2",
    "persistIntegratedLiveDrillPrivateEvidence",
    "verifyIntegratedLiveDrillPrivateEvidence",
    "startIntegratedLiveDrillJournal",
    "appendIntegratedLiveDrillJournal",
    "verifyIntegratedLiveDrillJournal",
    "persistOrReuseIntegratedLiveDrillRecoveryBundle",
    "INTEGRATED_LIVE_DRILL_RECOVERY_BUNDLE_RECEIPT_SCHEMA",
    "canonicalJson(parsed.signedBundle) !== canonicalJson(persistedBundle)",
    "creationProtocolObserved",
    "fileDataSynced",
    "PRE_PROVIDER_INTENT",
    "fs.constants.O_NOFOLLOW",
    "fs.linkSync(temporaryPath, destinationPath)",
    "parentDirectoryMode: \"0700\"",
    "fileMode: \"0600\"",
    "INCOMPLETE_LIVE_GATES_PENDING",
    "deploymentAttestationBound: false",
    "preProviderJournalPersisted: false",
    "privateEvidencePersisted: false",
    "preProviderJournalCurrentBytesBound: true",
    "privateEvidenceCurrentBytesBound: true",
    "signedRecoveryBundleCurrentBytesBound: true",
    "crashSafeRecoveryProven: false",
    "restartStableSignedBundleReuseProven: false",
    "RESTART_STABLE_SIGNED_BUNDLE_REUSE_NOT_PROVEN",
    "INTEGRATED_LIVE_DRILL_CROSS_HOST_CLAIM_BLOCKER",
    "exactReplayReturnedOriginalDecision: true",
    "changedInputUnderOperationDenied: true",
    "managedMcpCalledExactlyOnce: true",
    "operationalCapabilityReturned: false",
    "invariantViolations: 0",
    "providerBacked: false",
    "does not independently establish that any component receipt came from a provider"
  ]),
  "integrated-live-drill-runner": Object.freeze([
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_SPEC",
    "TIDEPROOF_GATE2_DEPLOYMENT_EXPECTATION",
    "TIDEPROOF_GATE2_PRE_DEPLOYMENT_ATTESTATION",
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_RUN_AUTHORIZATION",
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_CHILD_LAUNCH_PRIVATE_KEY_PKCS8_BASE64",
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_RUNNER_IDENTITY",
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_PATH",
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_ROOT",
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_JOURNAL_PATH",
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_RECOVERY_BUNDLE_PATH",
    "INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION_ENVIRONMENT",
    "startIntegratedLiveDrillJournal",
    "appendIntegratedLiveDrillJournal",
    "persistIntegratedLiveDrillPrivateEvidence",
    "consumeIntegratedLiveDrillRunAuthorization",
    "reserveIntegratedLiveDrillSpend",
    "integratedLiveDrillChildAuthorizationContext",
    "integratedLiveDrillChildCommittedTrustRoot",
    "finalizeIntegratedLiveDrillControlLedger",
    "gate1-admissible-vector.js",
    "gate2-authority-race.js",
    "gate1-recovery-broker.js",
    "RECOVERY_SOURCE_OPERATION_ID: race.winner?.operationId",
    "RECOVERY_SOURCE_REQUEST_DIGEST: race.winner?.requestDigest",
    "INTEGRATED_LIVE_DRILL_COMPONENT_FAILED"
  ]),
  "integrated-live-drill-authorization": Object.freeze([
    "tideproof.highwater-drill-live-run-authorization.v2",
    "tideproof.highwater-drill-human-authorization-trust-root.v1",
    "tideproof.highwater-drill-spend-authorization.v1",
    "tideproof.highwater-drill-claim-authority.v1",
    "tideproof.highwater-drill-live-finalization-statement.v1",
    "tideproof.highwater-drill-human-authorized-deployment-expectation.v1",
    "DERIVED_FROM_THIS_SIGNED_RUN_AUTHORIZATION_ATTESTATION_SHA256",
    "expectationSha256",
    "validateIntegratedLiveDrillCommittedRecoveryTrustRoot",
    "integratedLiveDrillTypedEvidenceSubjects",
    "CANDIDATE_RECEIPT_BOUND_NOT_ACCEPTED",
    "BILLING_PENDING",
    "RECOVERY_CURRENT_BYTES_BOUND_CRASH_RESTART_PENDING",
    "INTEGRATED_LIVE_DRILL_AUTHORIZATION_KEY_SEPARATION_REJECTED",
    "INTEGRATED_LIVE_DRILL_AUTHORIZATION_CHILD_LAUNCH_KEY_REJECTED",
    "INTEGRATED_LIVE_DRILL_CROSS_HOST_CLAIM_BLOCKER",
    "validateIntegratedLiveDrillPreAuthorizationBinding",
    "validateIntegratedLiveDrillTypedEvidenceAttestations",
    "validateIntegratedLiveDrillEvidenceSet",
    "validateIntegratedLiveDrillFinalizationStatement"
  ]),
  "integrated-live-drill-authorization-tests": Object.freeze([
    "signed integrated-live authorization binds the exact run and separated evidence keys",
    "integrated-live authorization rejects signature mutation, expiry, and key reuse",
    "integrated-live authorization rejects every expectation-to-spec drift",
    "human authorization binds every deployment trust key and configuration",
    "authorized expectation projection rejects marker, extra, and missing-field drift",
    "pre-attestation must start strictly after authorization and finish before expiry",
    "typed evidence binds every signer and uses the latest safe observation",
    "PACKET_B_PROVIDER_ACCEPTANCE_PENDING",
    "signed finalization binds the completed evidence and rejects mutation or premature issue"
  ]),
  "integrated-live-drill-child-authorization": Object.freeze([
    "tideproof.highwater-drill-child-launch-token.v1",
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION",
    "integratedLiveDrillChildAuthorizationContext",
    "parseIntegratedLiveDrillChildAuthorization",
    "authorizeIntegratedLiveDrillChildLaunch",
    "verifyIntegratedLiveDrillConsumedChildLaunch",
    "verifyIntegratedLiveDrillEvidence",
    "consumeIntegratedLiveDrillChildLaunch",
    "validateIntegratedLiveDrillConsumedChildLaunch",
    "assertIntegratedLiveDrillChildAuthorizationCurrent",
    "INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION_TIME_REJECTED"
  ]),
  "integrated-live-drill-child-authorization-tests": Object.freeze([
    "child context binds one reserved provider scope and authorization deadline",
    "child context rejects scope substitution, noncanonical input, and expiry"
  ]),
  "integrated-live-drill-control-ledger": Object.freeze([
    "tideproof.highwater-drill-authorization-claim.v1",
    "tideproof.highwater-drill-spend-reservation.v1",
    "tideproof.highwater-drill-control-ledger-receipt.v1",
    "tideproof.highwater-drill-child-launch-consumption.v1",
    "fs.constants.O_EXCL",
    "fs.fsyncSync",
    "readAndValidateReservationFile",
    "parseCanonicalLedgerRecord",
    "readAndValidateChildLaunchFile",
    "consumeIntegratedLiveDrillRunAuthorization",
    "reserveIntegratedLiveDrillSpend",
    "consumeIntegratedLiveDrillChildLaunch",
    "finalizeIntegratedLiveDrillControlLedger",
    "validateIntegratedLiveDrillConsumedControlLedger",
    "INTEGRATED_LIVE_DRILL_AUTHORIZATION_ALREADY_CONSUMED",
    "INTEGRATED_LIVE_DRILL_SPEND_RESERVATION_ORDER_REJECTED",
    "INTEGRATED_LIVE_DRILL_CHILD_LAUNCH_ALREADY_CONSUMED",
    "INTEGRATED_LIVE_DRILL_CHILD_LAUNCH_ORDER_REJECTED",
    "INTEGRATED_LIVE_DRILL_SPEND_CAP_EXCEEDED"
  ]),
  "integrated-live-drill-control-ledger-tests": Object.freeze([
    "authorization consumption is durable one-use across restart and concurrency",
    "truncated ambiguous claim remains consumed and cannot move spend",
    "same-length noncanonical claim mutation cannot authorize spend",
    "fabricated prior reservation cannot unlock a later provider scope",
    "spend ledger enforces exact order, one reservation, and cumulative cap",
    "child launches reject reserved-but-unlaunched predecessor scopes",
    "concurrent later-scope launches cannot bypass an unlaunched first scope"
  ]),
  "integrated-live-drill-finalizer": Object.freeze([
    "tideproof.highwater-drill-packet-a-finalization-validation.v1",
    "tideproof.highwater-drill-packet-b-finalization-validation.v1",
    "DURABLE_EXACT_ONE_MCP_CRASH_RESTART_AMBIGUOUS_RESULT_RECONCILIATION_NOT_PROVEN",
    "INTEGRATED_LIVE_DRILL_CROSS_HOST_CLAIM_BLOCKER",
    "validateIntegratedLiveDrillEvidenceSet",
    "validateIntegratedLiveDrillFinalizationStatement",
    "validateIntegratedLiveDrillRunAuthorization",
    "validateIntegratedLiveDrillConsumedControlLedger",
    "integratedLiveDrillRunnerIdentityDigest",
    "validateIntegratedLiveDrillPacketAFinalization",
    "PACKET_B_PROVIDER_ACCEPTANCE_PENDING",
    "PACKET_B_LOCAL_SAME_HOST_SCAFFOLD_VALIDATED_NON_ACCEPTING",
    "Local same-host scaffold only; actual provider-bound W1-W5 continuity remains unproven.",
    "liveProviderBoundW1W5ContinuityProven: false",
    "accepted: false",
    "finalReleaseReady: false"
  ]),
  "integrated-live-drill-finalizer-runner": Object.freeze([
    "tideproof.highwater-drill-packet-a-untrusted-finalizer-input.v1",
    "tideproof.highwater-drill-packet-a-trusted-finalizer-context.v1",
    "parseIntegratedLiveDrillPacketAFinalizerInput",
    "parseIntegratedLiveDrillPacketAFinalizerTrustedContext",
    "loadIntegratedLiveDrillPacketAFinalizerTrustedContext",
    "loadCommittedRecoveryPublisherTrustRoot",
    "forbiddenRootPath: MODULE_ROOT",
    "runIntegratedLiveDrillPacketAFinalizer",
    "--packet"
  ]),
  "integrated-live-drill-recovery-continuity": Object.freeze([
    "tideproof.highwater-drill-recovery-continuity-journal-entry.v2",
    "tideproof.highwater-drill-recovery-continuity-journal-receipt.v2",
    "tideproof.highwater-drill-recovery-continuity-pre-call-intent.v1",
    "LOCAL_SAME_HOST_SCAFFOLD_COMPLETED_NO_RETRY",
    "UNKNOWN_DO_NOT_ACT",
    "fs.constants.O_EXCL",
    "randomBytes(32)",
    "attemptOwnershipTokenSha256",
    "acceptExistingArtifact",
    "DURABLE_BEFORE_LOCAL_SCAFFOLD_CALL",
    "topLevelProviderClientOptionReceived: false",
    "providerClientInvoked: false",
    "exactMcpCallClaimCount = claimEntries.length",
    "exactMcpDispatchMarkerCount = dispatchEntries.length",
    "Local same-host scaffold only; actual provider-bound W1-W5 continuity remains unproven.",
    "records truthful post-dispatch evidence after authority expiry",
    "provider-bound persistence and crash reconciliation on the live Managed MCP path remain unproven",
    "not independently anchored against same-owner full-chain rewriting",
    "providerFreeW5ImportGraphProven: false",
    "recoveryBrokerConfiguration",
    "recoveryBrokerConfigDigest",
    "acceptedExpectedSourceClusterId !== acceptedRecoveryClusterId",
    "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_OPTIONS_REJECTED",
    "journalStartedAt",
    "validatePersistedRecoveryBundleForContinuity",
    "validateIntegratedLiveDrillRunAuthorization"
  ]),
  "integrated-live-drill-recovery-continuity-tests": Object.freeze([
    "five subprocess workers resume four failpoints with exactly one fake MCP call",
    "only the O_EXCL claim creator dispatches across synchronized subprocess races",
    "claimed call without durable completion is permanently unknown and never retried",
    "W5 makes no ambient-credential claim, rejects a provider client, and journals reject tampering",
    "public W1-W5 reject caller-controlled journal timestamps",
    "journal rejects future-start and predated first-entry evidence",
    "post-dispatch workers record truthful post-expiry time",
    "production and continuity share strict trusted-bundle validation",
    "liveProviderBoundW1W5ContinuityProven",
    "liveProviderDispatchAuthorizationProven",
    "providerCallCountProven"
  ]),
  "integrated-live-drill-recovery-continuity-fixture": Object.freeze([
    "createRecoveryContinuityFixture",
    "persistOrReuseIntegratedLiveDrillRecoveryBundle",
    "integratedLiveDrillRecoveryContinuityPreCallIntent",
    "recoveryBrokerConfiguration",
    "recoveryBrokerConfigDigest",
    "consumeIntegratedLiveDrillChildLaunch"
  ]),
  "integrated-live-drill-recovery-continuity-worker": Object.freeze([
    "TEST_RECOVERY_CONTINUITY_BARRIER_TIMEOUT",
    "TEST_MCP_CALLED_BEFORE_DURABLE_CLAIM",
    "--barrier-directory",
    "fakeMcpCall",
    "runIntegratedLiveDrillRecoveryContinuityW2"
  ]),
  "integrated-live-drill-pre-attestation-fixture": Object.freeze([
    "tideproof.gate2.aws-deployment-expectation.v5",
    "tideproof.gate2.aws-deployment-attestation-snapshot.v6",
    "BEGIN PRIVATE KEY"
  ]),
  "integrated-live-drill-synthetic-test-keys": Object.freeze([
    "SYNTHETIC TEST-ONLY KEY MATERIAL",
    "generateSyntheticTestOnlyEd25519Key",
    "generateSyntheticTestOnlyP256PublicKey"
  ]),
  "integrated-live-drill-tests": Object.freeze([
    "private evidence source control binds current bytes before candidate composition",
    "private evidence rejects non-canonical or permissive destinations",
    "pre-provider journal is create-only, chained, synced, and tamper evident",
    "unattested provider components remain a non-accepting candidate",
    "integrated receipt fails closed on every cross-act boundary",
    "value.race.invocationRequestDigests.changedInput",
    "value.race.awsInvokeRequestDigests.changedInput",
    "orchestrator executes exactly DVI, race, then exact-winner recovery",
    "Packet B1 continuity is intentionally non-circular",
    "post-call candidate path",
    "packetA.localSameHostScaffoldValidated, false",
    "packetA.recoveryContinuityDisposition",
    "runIntegratedLiveDrillPacketAFinalizer"
  ]),
  "recovery-bundle-persistence-tests": Object.freeze([
    "signed recovery bundle survives restart with the exact first signature bytes",
    "persisted signed recovery bundle rejects tamper and changed canonical input",
    "pre-existing exact bytes attest only current reuse durability",
    "reuse rejects a pathname replaced while its original inode is read"
  ]),
  "local-full-drill-harness": Object.freeze([
    "LOCAL_FULL_DRILL_CLAIM_BOUNDARY",
    "LOCAL_FULL_DRILL_SOURCE_PATHS",
    "MAX_RECEIPT_BYTES",
    "providerBacked: false",
    "liveClaimSatisfied: false",
    "validateLocalFullDrillReceiptBytes"
  ]),
  "local-full-drill-receipt-verifier": Object.freeze([
    "stat.isSymbolicLink()",
    "stat.size > 1024 * 1024",
    "validateLocalFullDrillReceiptBytes",
    "localFullDrillSourceBindings(ROOT)"
  ]),
  "local-full-drill-runner": Object.freeze([
    "buildLocalFullDrillReceipt",
    "localFullDrillSourceBindings(ROOT)",
    "LOCAL_FULL_DRILL_ARGUMENTS_REJECTED"
  ]),
  "local-full-drill-tests": Object.freeze([
    "the validator recomputes through the shared local implementation",
    "the validator rejects count, ordering, digest, source, and claim-boundary drift",
    "the evidence contract preserves generator and validator trust boundaries"
  ]),
  "dvi-proposal-authorization": Object.freeze([
    "FROM tp_api.g1_authorize_dvi_proposal_v1(",
    "normalizedDviAuthorizationFor({",
    "logicalAuthorityKeyFor({",
    "authorizationBindingFor({",
    "DVI_PROPOSAL_DATABASE_IDENTITY_MISMATCH",
    "DVI_PROPOSAL_DATABASE_BINDING_MISMATCH"
  ]),
  "dvi-proposal-authorization-tests": Object.freeze([
    "least-privilege runtime accepts only a database-derived proposal identity",
    "selection mismatch returns no runtime authorization",
    "runtime rejects a database row with a forged logical binding"
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
    "PRIMARY_ROLE_GRANT_POLICIES",
    "lockInitialPublicCapability(client, bootstrapOwner)",
    "clusterPreflightPostureDigest: clusterPreflight.postureDigest",
    "lockPublicRoutineDefaults(client, principals, schemas = [])",
    "ALTER DEFAULT PRIVILEGES ${scope} REVOKE EXECUTE ON FUNCTIONS FROM public",
    "allowMissingExpectedCapabilities: false",
    "session_user = 'tp_ingest_user'",
    "session_user <> 'tp_dispatch_user'",
    "session_user <> 'tp_recovery_audit_user'",
    "session_user <> 'tp_gate2_authorizer_user'",
    "collectValidatedPosture(",
    "ALTER ROLE ${role} WITH NOLOGIN",
    "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA tp_private, tp_ledger, tp_api FROM ${principal}",
    "GRANT USAGE ON SCHEMA tp_api TO ${role}",
    "FROM tp_authorizer_role",
    "FROM tp_gate2_authorizer_role",
    "TO tp_gate2_authorizer_role",
    "p_agent_id NOT IN ('aws-authority-alpha', 'aws-authority-bravo')",
    "tp_api.g1_commit_dvi_selection_v1",
    "tp_api.g1_observe_vector_exclusion_v1",
    "tp_api.g1_resolve_verified_evidence_v1",
    "tp_api.g1_resolve_vector_set_v1",
    "tp_api.g1_resolve_recovery_audit_event_v1",
    "tp_api.g1_resolve_recovery_source_receipt_v2",
    "jsonb_agg(jsonb_build_object(",
    "jsonb_array_elements(v_candidate.conflict_windows)",
    "v_candidate.evidence_valid_until <= v_database_now",
    "tideproof.primary-function-sql-batch.v1",
    "PRIMARY_FUNCTION_SQL_BATCH_UNREVIEWED",
    "primaryFunctionSqlBatchSha256(statements)",
    "validatePrimaryFunctionSqlStatements(statements);",
    "await emitPrimaryFunctionSql({",
    "return executePrimaryFunctionSqlStatements(client, statements);",
    "proposal.authority_evidence_binding_sha256",
    "proposal.selected_evidence_id = receipt.evidence_id",
    "tp_api.g1_resolve_recovery_publisher_trust_root_v1",
    "tp_recovery_source_user",
    "g1_recovery_publisher_trust_roots",
    "ON CONFLICT (trust_root_id) DO NOTHING",
    "tp_api.g1_authorize_dvi_proposal_v1",
    "tp_private.g1_authority_receipt_current_v2",
    "SELECT currentness.authority_current, currentness.database_now",
    "dvi_selection_request_mismatch",
    "IF v_epoch.current_epoch = 1 THEN",
    "'explicit_new_authorization_required'::STRING",
    "v_authorization_epoch := 1",
    "v_expected_payload_digest",
    "v_expected_logical_action_digest",
    "v_expected_request_digest",
    "database-derived authority identity mismatch",
    "tp_api.g2_spend_authority_race_v1",
    "decision_committed_evidence_id UUID",
    "outbox_payload JSONB",
    "receipt_proposal_payload JSONB",
    "receipt_proposal_authority_evidence_binding_sha256 STRING",
    "receipt_proposal_authorization_binding_sha256 STRING",
    "observed_holder_operation_id UUID",
    "observed_fence INT8",
    "proposal.payload = outbox.payload",
    "sha256(proposal.payload_canonical::BYTES)"
  ]),
  "primary-security-runner": Object.freeze([
    "sqlBindingNegatives",
    "TIDEPROOF_RECOVERY_PUBLISHER_KEY_SET_DIGEST",
    "assertRecoveryPublisherTrustRootWriteDeniedWithClient",
    "directTrustRootWrite",
    "recoverySource",
    "sourceResolverDenied",
    "expectPrivilegeDeniedOrUndefined",
    "g1_resolve_recovery_source_receipt_v1",
    "g1_resolve_recovery_source_receipt_v2",
    "g1_resolve_recovery_publisher_trust_root_v1",
    "payloadSubstitutionOutcome",
    "proposalAliasOutcome",
    "DVI selection mismatch mutated authority state",
    "requestDigestRejected?.sqlstate",
    "nullIntentNonceRejected?.sqlstate",
    "tp_authorizer_user"
  ]),
  "proof-manifest-tests": Object.freeze([
    "proof manifest propagates nested local full-drill failure",
    "PROOF_MANIFEST.json distributed-vector-index",
    "AWS(?: authority request| path)? does not yet consume"
  ]),
  "proof-manifest-verifier": Object.freeze([
    "local-full-drill-receipt",
    "validateLocalFullDrillReceiptBytes",
    "proof manifest nested local-full-drill verification failed"
  ]),
  "probe-runtime": Object.freeze([
    "PROBE_REQUEST_REJECTED",
    "tideproof.capability-probe.v1",
    "MessageType: \"RAW\"",
    "functionVersion: process.env.AWS_LAMBDA_FUNCTION_VERSION",
    "probeSourceDigest: process.env.PROBE_SOURCE_DIGEST"
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
    "session_user <> '${RECOVERY_PUBLISHER_USER}'",
    "lockInitialRecoveryPublicCapability(client, bootstrapOwner)",
    "clusterPreflightPostureDigest: clusterPreflight.postureDigest",
    "lockRecoveryPublicRoutineDefaults(",
    "allowMissingExpectedCapabilities: false",
    "collectValidatedRecoveryPosture(",
    "GRANT USAGE ON SCHEMA mcp_api TO ${RECOVERY_PUBLISHER_ROLE}",
    "mcp_api.resolve_recovery_bundle_v1",
    "read_reconciled",
    "RECOVERY_PUBLISH_RETRY_DEADLINE_EXCEEDED",
    "beforeReconcile: closeOriginal",
    "commitDefinitivelyAborted"
  ]),
  "recovery-audit-reconciliation-tests": Object.freeze([
    "recovery audit resolves its exact event after COMMIT ACK loss",
    "g1_resolve_recovery_audit_event_v1",
    "result.commit.observation, \"read_reconciled\"",
    "broken_closed",
    "reconciliation_started",
    "recovery audit reconciles an unclassified post-COMMIT error without rollback"
  ]),
  "recovery-broker": Object.freeze([
    "runtimeDatabaseConfig({",
    "RECOVERY_CLUSTER_SEPARATION_REQUIRED",
    "RECOVERY_PRINCIPAL_BINDING_MISMATCH",
    "RECOVERY_MCP_RESULT_CARDINALITY_INVALID",
    "g1_resolve_recovery_audit_event_v1",
    "g1_resolve_recovery_source_receipt_v2",
    "resolveCommittedRecoverySourceReceipt",
    "RECOVERY_SOURCE_DVI_BINDING_INVALID",
    "selected_evidence_binding_sha256",
    "resolveCommittedRecoveryAuditEvent",
    "assertRecoveryPublisherTrustRootWriteDenied",
    "RECOVERY_TRUST_ROOT_WRITE_PROBE_ROLLBACK_FAILED",
    "databaseClientMustBeDiscarded(error)",
    "read_reconciled",
    "commitDefinitivelyAborted"
  ]),
  "recovery-continuity-identity": Object.freeze([
    "tideproof.highwater-recovery-binding.v3",
    "RECOVERY_DATABASE_FRESHNESS_SQL",
    "RECOVERY_QUERY_TEMPLATE",
    "canonicalRecoveryAttempt",
    "recoveryBrokerConfigDigest",
    "tideproof-managed-mcp-client-v1",
    "tideproof-deterministic-recovery-broker-v3",
    "normalizedRecoverySourceReceiptForContinuity",
    "recoverySourceBindingDigestFor",
    "verifyRecoveryBundleSourceSignature",
    "canonicalJson(signedBundle) !== canonicalJson(envelope.signedBundle)",
    "validatePersistedRecoveryBundleForContinuity",
    "fs.constants.O_NOFOLLOW"
  ]),
  "recovery-bundle-signature": Object.freeze([
    "RECOVERY_MAX_TTL_MS",
    "RECOVERY_SIGNATURE_ALGORITHM",
    "RECOVERY_PUBLISHER_VERSION",
    "checkpointSummary.checkpointVersion",
    "evidenceSummary.admittedCount",
    "conflictSummary.unresolvedCount",
    "receiptSummary.durableIntentPresent",
    "recovery bundle TTL exceeds",
    "bytes.toString(\"base64\") !== text",
    "verifyRecoveryBundleSourceSignature",
    "RECOVERY_SIGNATURE_INVALID"
  ]),
  "recovery-security-contract": Object.freeze([
    "PRIMARY_MANAGED_BASE_TABLES",
    "RECOVERY_TRUST_ROOT_WRITE_PROBES",
    "SET trust_root_commitment =",
    "SET publisher_key_set_digest =",
    "DELETE FROM tp_ledger.g1_recovery_publisher_trust_roots"
  ]),
  "recovery-broker-runner": Object.freeze([
    "RECOVERY_SOURCE_OPERATION_ID",
    "RECOVERY_SOURCE_REQUEST_DIGEST",
    "RECOVERY_SOURCE_AUTHORITY_EVIDENCE_BINDING_SHA256",
    "RECOVERY_SOURCE_SELECTED_EVIDENCE_BINDING_SHA256",
    "loadCommittedRecoveryPublisherSigner()",
    "signer.trustedPublisherKeys",
    "resolveCommittedRecoveryPublisherTrustRoot({",
    "resolveCommittedRecoverySourceReceipt({",
    "resolveCommittedRecoveryAuditEvent",
    "assertRecoveryPublisherTrustRootWriteDenied({",
    "PRIMARY_RECOVERY_SOURCE_DATABASE_URL",
    "PRIMARY_AUDIT_DATABASE_URL",
    "authorizeIntegratedLiveDrillChildLaunch",
    "assertIntegratedLiveDrillChildAuthorizationCurrent",
    "MANAGED_MCP_RECOVERY",
    "publisherTrustRootCommitment",
    "operationalCapabilitiesReturned: false"
  ]),
  "recovery-evidence-runner": Object.freeze([
    "RECOVERY_SOURCE_OPERATION_ID",
    "RECOVERY_SOURCE_REQUEST_DIGEST",
    "RECOVERY_SOURCE_AUTHORITY_EVIDENCE_BINDING_SHA256",
    "RECOVERY_SOURCE_SELECTED_EVIDENCE_BINDING_SHA256",
    "loadCommittedRecoveryPublisherSigner()",
    "signer.trustedPublisherKeys",
    "resolveCommittedRecoveryPublisherTrustRoot({",
    "resolveCommittedRecoverySourceReceipt({",
    "assertRecoveryPublisherTrustRootWriteDenied({",
    "PRIMARY_RECOVERY_SOURCE_DATABASE_URL",
    "PRIMARY_AUDIT_DATABASE_URL",
    "publisherTrustRootCommitment",
    "publisher unexpectedly read the base recovery table"
  ]),
  "recovery-publisher-key": Object.freeze([
    "TIDEPROOF_RECOVERY_PUBLISHER_TRUST_ROOT",
    "TIDEPROOF_RECOVERY_PUBLISHER_TRUST_ROOT_COMMITMENT",
    "RECOVERY_PUBLISHER_PRIVATE_KEY_PKCS8_BASE64",
    "RECOVERY_PUBLISHER_TRUST_ROOT_COMMITMENT_MISMATCH",
    "RECOVERY_PUBLISHER_SIGNING_KEY_MISMATCH",
    "trustedPublisherKeys"
  ]),
  "recovery-publisher-trust": Object.freeze([
    "trustedPublisherKeysDigest",
    "trustedPublisherKeys must not be empty",
    "publicKeyDigest"
  ]),
  "recovery-publisher-key-tests": Object.freeze([
    "recovery publisher requires an independently committed matching trust root",
    "recovery publisher rejects a changed root after commitment",
    "recovery publisher rejects a signing key outside the committed root",
    "recovery publisher environment loader keeps commitment and key separate",
    "recovery publisher rejects noncanonical PKCS8 base64 padding",
    "primary-ledger commitment rejects coordinated root commitment and key replacement"
  ]),
  "recovery-publication-reconciliation-tests": Object.freeze([
    "recovery publisher resolves an exact receipt after COMMIT ACK loss",
    "output.commit.observation, \"read_reconciled\"",
    "sqlState(\"ECONNRESET\")",
    "recovery publisher never rolls back an unclassified post-COMMIT error",
    "ambiguous_closed"
  ]),
  "recovery-store": Object.freeze([
    "runtimeDatabaseConfig({",
    "bootstrapDatabaseConfig({",
    "recoverySourceBindingDigestFor",
    "RECOVERY_AUTHORITY_INVARIANT_VIOLATION",
    "from \"./recovery-bundle-signature.js\"",
    "normalizedRecoveryBundleFor",
    "verifyRecoveryBundleSourceSignature",
    "mcp_private.recovery_bundles_v2",
    "databaseClientMustBeDiscarded(error)",
    "read_reconciled",
    "commitDefinitivelyAborted"
  ]),
  "recovery-store-tests": Object.freeze([
    "cross-act source binding digest changes with every authority identity field",
    "authorityEvidenceBindingSha256",
    "selectedEvidenceBindingSha256"
  ]),
  "release-security-ledger": Object.freeze([
    "CURRENT SOURCE SECURITY PASS — LIVE AND PRIVATE REVIEW PENDING",
    "not a vulnerability-free claim",
    "numeric Lambda invocation targets",
    "standalone closure-complete exact-commit build",
    "suppress repository hooks including `reference-transaction`",
    "Standalone provenance",
    "network-free claim covers only Git bundle materialization and import",
    "administrator exclusion",
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
    "SIGNATURE_INVALID",
    "g1_resolve_verified_evidence_v1",
    "databaseClientMustBeDiscarded(error)",
    "read_reconciled",
    "commitDefinitivelyAborted"
  ]),
  "signed-ingest-reconciliation-tests": Object.freeze([
    "signed ingest resolves its exact receipt after COMMIT ACK loss",
    "result.commit.observation, \"read_reconciled\"",
    "synthetic ACK loss",
    "broken_released",
    "reconciliation_started",
    "signed ingest reconciles an unclassified post-COMMIT error without rollback"
  ]),
  "signer-runtime": Object.freeze([
    "SigningAlgorithms.includes(\"ECDSA_SHA_256\")",
    "MessageType: \"DIGEST\"",
    "SigningAlgorithm: \"ECDSA_SHA_256\"",
    "new VerifyCommand({",
    "KMS_SIGNATURE_VERIFICATION_FAILED"
  ]),
  "synthetic-authority-proposal": Object.freeze([
    "dviSelectionBindingSha256For(selection)",
    "recordDviSelectionReceiptForTest(selection)",
    "SYNTHETIC_PROPOSAL_AUTHORIZATION_FAILED",
    "authorizeSyntheticContenders"
  ])
});

const FORBIDDEN_SOURCE_MARKERS = Object.freeze({
  "aws-oidc-identity-bootstrap": Object.freeze([
    "actions/checkout@",
    "pull_request:",
    "schedule:",
    "set -x"
  ]),
  "aws-oidc-read-only-role-template": Object.freeze([
    "AWS::IAM::OIDCProvider",
    "bedrock:InvokeModel",
    "cloudformation:CreateStack",
    "iam:PassRole",
    "s3:PutObject"
  ]),
  "aws-oidc-read-only-runner": Object.freeze([
    "create-stack",
    "delete-stack",
    "invoke-model",
    "put-object",
    "set -x",
    "tee"
  ]),
  "aws-oidc-read-only-workflow": Object.freeze([
    "AWS_ROLE_ARN:",
    "configure-aws-credentials",
    "pull_request:",
    "schedule:"
  ]),
  "recovery-broker-runner": Object.freeze([
    "createSyntheticRecoverySigner",
    "PRIMARY_DATABASE_URL"
  ]),
  "recovery-evidence-runner": Object.freeze([
    "createSyntheticRecoverySigner",
    "PRIMARY_DATABASE_URL"
  ]),
  "primary-security-bootstrap": Object.freeze([
    "v_authorization_epoch := v_epoch.current_epoch + 1"
  ])
});

const FORBIDDEN_SOURCE_PATTERNS = Object.freeze({
  "gate2-exact-build-bootstrap": Object.freeze([
    /["']worktree["']\s*,\s*["']add["']/u,
    /["']clone["']\s*,/u,
    /--(?:reference|shared|local|hardlinks)\b/u
  ]),
  "recovery-broker": Object.freeze([
    /\bg1_resolve_recovery_source_receipt_v1\s*\(/u
  ])
});

function assert(condition, code) {
  if (!condition) {
    throw new Error(code);
  }
}

function canonicalizeSqlGuardSource(source) {
  assert(typeof source === "string", "RELEASE_SECURITY_PATTERN_SOURCE");
  return source
    .replace(/\/\*[\s\S]*?\*\//gu, " ")
    .replace(/--[^\r\n]*/gu, " ")
    .replace(/"((?:""|[^"])*)"/gu, (_, identifier) =>
      identifier.replaceAll('""', '"'))
    .replace(/['`]/gu, " ")
    .toLowerCase()
    .replace(/\s+/gu, " ")
    .trim();
}

function assertNoForbiddenSourcePatterns(id, source) {
  const patterns = FORBIDDEN_SOURCE_PATTERNS[id];
  assert(Array.isArray(patterns), "RELEASE_SECURITY_PATTERN_SET");
  const canonicalSource = canonicalizeSqlGuardSource(source);
  for (const pattern of patterns) {
    assert(
      !pattern.test(canonicalSource),
      `RELEASE_SECURITY_FORBIDDEN_PATTERN_${id.replaceAll("-", "_").toUpperCase()}`
    );
  }
  return true;
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

export function validateReleaseSecurityReceipt(receipt) {
  exactKeys(
    receipt,
    RELEASE_SECURITY_RECEIPT_KEYS,
    "RELEASE_SECURITY_RECEIPT_CONTRACT"
  );
  exactKeys(
    receipt.checks,
    RELEASE_SECURITY_CHECK_KEYS,
    "RELEASE_SECURITY_RECEIPT_CONTRACT"
  );
  assert(
    receipt.schemaVersion === RECEIPT_SCHEMA &&
      receipt.status === "CURRENT_SOURCE_SECURITY_PASS" &&
      receipt.finalReleaseReady === false &&
      /^\d{4}-\d{2}-\d{2}$/.test(receipt.reviewedOn) &&
      receipt.manifestPath === MANIFEST_PATH &&
      HEX_64.test(receipt.manifestSha256) &&
      receipt.surfaceCount === RELEASE_SECURITY_SURFACE_COUNT &&
      receipt.publicPathCount === 10 &&
      receipt.securityHeaderCount === 9 &&
      receipt.negativeProbeCount === 6 &&
      receipt.publicRouteCount === 10 &&
      receipt.iamRoleCount === 9 &&
      receipt.lambdaPermissionCount === 3 &&
      receipt.boundedFunctionCount === 5 &&
      receipt.logGroupCount === 11 &&
      sameJson(
        receipt.finalReleaseRequirements,
        EXPECTED_FINAL_RELEASE_REQUIREMENTS
      ) &&
      Object.values(receipt.checks).every((value) => value === true) &&
      typeof receipt.claimBoundary === "string" &&
      receipt.claimBoundary.length > 0,
    "RELEASE_SECURITY_RECEIPT_CONTRACT"
  );
  return receipt;
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
      sameJson(role.Properties.ManagedPolicyArns, []) &&
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
      stage.AutoDeploy === false &&
      sameJson(stage.DeploymentId, { Ref: "ApiDeployment" }) &&
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
  const apiDeployment = resources.ApiDeployment;
  assert(
    apiDeployment?.Type === "AWS::ApiGatewayV2::Deployment" &&
      sameJson(apiDeployment.Properties?.ApiId, { Ref: "HttpApi" }) &&
      sameJson(apiDeployment.Properties?.Description, {
        "Fn::Sub":
          "ProofToAct exact API deployment ${SourceCommit} ${ConfigDigest}"
      }) &&
      sameJson(
        apiDeployment.DependsOn,
        [
          "AdvisoryRoute",
          ...Object.keys(DEPLOYMENT_API_ROUTE_KEYS).filter(
            (logicalId) => logicalId !== "AdvisoryRoute"
          )
        ].sort()
      ),
    "RELEASE_SECURITY_API_DEPLOYMENT"
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
  const semanticFailureAlarms = {
    AuthoritySemanticFailureAlarm: "authority",
    BoundarySemanticFailureAlarm: "boundary"
  };
  assert(
    sameJson(authorityEnvironment.SEMANTIC_METRIC_DEPLOYMENT, {
      Ref: "AWS::StackName"
    }) &&
      sameJson(
        resources.BoundaryFunction.Properties.Environment?.Variables
          ?.SEMANTIC_METRIC_DEPLOYMENT,
        { Ref: "AWS::StackName" }
      ) &&
      Object.values(resources).filter(
        (resource) =>
          resource.Type === "AWS::CloudWatch::Alarm" &&
          resource.Properties?.Namespace === "ProofToAct/GateTwo"
      ).length === 2,
    "RELEASE_SECURITY_SEMANTIC_FAILURE_ALARM_SET"
  );
  for (const [logicalId, service] of Object.entries(
    semanticFailureAlarms
  )) {
    const alarm = resources[logicalId];
    assert(
      alarm?.Type === "AWS::CloudWatch::Alarm" &&
        alarm.Properties.AlarmName?.["Fn::Sub"] ===
          `\${AWS::StackName}-${service}-semantic-failures` &&
        alarm.Properties.Namespace === "ProofToAct/GateTwo" &&
        alarm.Properties.MetricName === "SemanticFailures" &&
        alarm.Properties.Statistic === "Sum" &&
        alarm.Properties.Period === 60 &&
        alarm.Properties.EvaluationPeriods === 1 &&
        alarm.Properties.DatapointsToAlarm === 1 &&
        alarm.Properties.Threshold === 1 &&
        alarm.Properties.ComparisonOperator ===
          "GreaterThanOrEqualToThreshold" &&
        alarm.Properties.TreatMissingData === "notBreaching" &&
        sameJson(alarm.Properties.Dimensions, [
          { Name: "Deployment", Value: { Ref: "AWS::StackName" } },
          { Name: "Service", Value: service }
        ]),
      `RELEASE_SECURITY_${logicalId}`
    );
  }
  const functionTitles = [
    "Agent",
    "Authority",
    "Boundary",
    "Demo",
    "Signer"
  ];
  for (const title of functionTitles) {
    const name = `${title}Alias`;
    assert(
      resources[name]?.Type === "AWS::Lambda::Alias" &&
        resources[name].Properties.Name === "proof" &&
        sameJson(resources[name].Properties.FunctionName, {
          Ref: `${title}Function`
        }) &&
        sameJson(resources[name].Properties.FunctionVersion, {
          "Fn::GetAtt": [`${title}Version`, "Version"]
        }),
      `RELEASE_SECURITY_${name}_MONITORED`
    );
  }
  assert(
    sameJson(resources.BoundaryIntegration?.Properties?.IntegrationUri, {
      Ref: "BoundaryVersion"
    }) &&
      sameJson(resources.DemoIntegration?.Properties?.IntegrationUri, {
        Ref: "DemoVersion"
      }) &&
      sameJson(
        resources.BoundaryFunction.Properties.Environment?.Variables
          ?.AGENT_FUNCTION_ARN,
        { Ref: "AgentVersion" }
      ) &&
      sameJson(
        resources.BoundaryFunction.Properties.Environment?.Variables
          ?.SIGNER_FUNCTION_ARN,
        { Ref: "SignerVersion" }
      ),
    "RELEASE_SECURITY_NUMERIC_LAMBDA_TARGETS"
  );
  const probeTargets = {
    PROBE_AGENT_FUNCTION_ARN: "AgentVersion",
    PROBE_AUTHORITY_FUNCTION_ARN: "AuthorityVersion",
    PROBE_BOUNDARY_FUNCTION_ARN: "BoundaryVersion",
    PROBE_SIGNER_FUNCTION_ARN: "SignerVersion"
  };
  for (const title of functionTitles) {
    const environment =
      resources[`${title}ProbeFunction`]?.Properties?.Environment?.Variables;
    assert(
      Object.entries(probeTargets).every(([name, target]) =>
        sameJson(environment?.[name], { Ref: target })
      ),
      `RELEASE_SECURITY_${title}ProbeFunction_NUMERIC_TARGETS`
    );
  }
  for (const title of functionTitles) {
    assert(
      sameJson(template.Outputs?.[`${title}VersionArn`]?.Value, {
        Ref: `${title}Version`
      }),
      `RELEASE_SECURITY_${title}Version_OUTPUT`
    );
  }
  const evidenceTrust =
    resources.DeploymentEvidenceRole?.Properties
      ?.AssumeRolePolicyDocument;
  const alternateTrust =
    resources.DeploymentEvidenceAlternateRole?.Properties
      ?.AssumeRolePolicyDocument;
  assert(
    template.Parameters?.EvidenceOperatorPrincipalArn?.AllowedPattern ===
      "^arn:aws[a-zA-Z-]*:iam::[0-9]{12}:(?:role|user)/[A-Za-z0-9+=,.@_-]{1,64}$" &&
      sameJson(evidenceTrust, {
        Version: "2012-10-17",
        Statement: [
          {
            Effect: "Allow",
            Principal: { AWS: { Ref: "EvidenceOperatorPrincipalArn" } },
            Action: "sts:AssumeRole",
            Condition: {
              StringEquals: {
                "aws:PrincipalArn": {
                  Ref: "EvidenceOperatorPrincipalArn"
                }
              }
            }
          }
        ]
      }) &&
      sameJson(template.Outputs?.DeploymentEvidenceRoleArn?.Value, {
        "Fn::GetAtt": ["DeploymentEvidenceRole", "Arn"]
      }) &&
      sameJson(alternateTrust, {
        Version: "2012-10-17",
        Statement: [
          {
            Effect: "Allow",
            Principal: {
              AWS: {
                "Fn::Sub":
                  "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"
              }
            },
            Action: "sts:AssumeRole"
          }
        ]
      }) &&
      sameJson(
        template.Outputs?.DeploymentEvidenceAlternateRoleArn?.Value,
        {
          "Fn::GetAtt": ["DeploymentEvidenceAlternateRole", "Arn"]
        }
      ) &&
      sameJson(
        resources.DeploymentEvidenceAlternateRole?.Properties?.RoleName,
        { "Fn::Sub": "${AWS::StackName}-evidence-alternate" }
      ),
    "RELEASE_SECURITY_EVIDENCE_OPERATOR_TRUST"
  );

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
    const allowStatements = directStatements(statements).filter(
      (candidate) => candidate.Effect === "Allow"
    );
    for (const statement of allowStatements) {
      const reviewedGlobalDriftRead =
        roleName === "DeploymentEvidenceRole" &&
        statement.Sid === "ReadOwnDriftDetection" &&
        sameJson(actionList(statement.Action), [
          "cloudformation:BatchDescribeTypeConfigurations",
          "cloudformation:DescribeStackDriftDetectionStatus"
        ]);
      const reviewedGlobalEventSourceRead =
        roleName === "DeploymentEvidenceRole" &&
        statement.Sid === "ReadLambdaEventSourceCensus" &&
        sameJson(actionList(statement.Action), [
          "lambda:ListEventSourceMappings"
        ]);
      const reviewedGlobalAlarmRead =
        roleName === "DeploymentEvidenceRole" &&
        statement.Sid === "ReadSemanticAlarmDrift" &&
        sameJson(actionList(statement.Action), [
          "cloudwatch:DescribeAlarms"
        ]);
      assert(
        statement.Resource !== "*" ||
          reviewedGlobalDriftRead ||
          reviewedGlobalEventSourceRead ||
          reviewedGlobalAlarmRead,
        `RELEASE_SECURITY_${roleName}_WILDCARD_ALLOW`
      );
    }
    if (roleName === "DeploymentEvidenceRole") {
      assert(
        allowStatements.filter((statement) => statement.Resource === "*")
          .length === 3,
        "RELEASE_SECURITY_DeploymentEvidenceRole_WILDCARD_ALLOW"
      );
    }
    const denied = denyActions(statements);
    assert(
      REQUIRED_DENY_ACTIONS[roleName].every((action) => denied.has(action)),
      `RELEASE_SECURITY_${roleName}_DENY`
    );
    assertConditionalProbeLogs(statements, roleName);
  }
  const boundaryStatements = roleStatements(
    resources.BoundaryRole,
    "RELEASE_SECURITY_BoundaryRole_ROLE"
  );
  const boundaryInvoke = boundaryStatements.find(
    (statement) => statement.Sid === "InvokeOnlyBoundedChildren"
  );
  const boundaryDenyOther = boundaryStatements.find(
    (statement) => statement.Sid === "DenyOtherLambdaTargets"
  );
  const raceStatements = roleStatements(
    resources.AuthorityRaceCallerRole,
    "RELEASE_SECURITY_AuthorityRaceCallerRole_ROLE"
  );
  const raceInvoke = raceStatements.find(
    (statement) => statement.Sid === "InvokeOnlyAuthorityProof"
  );
  const raceDenyOther = raceStatements.find(
    (statement) => statement.Sid === "DenyOtherLambdaTargets"
  );
  assert(
    sameJson(boundaryInvoke?.Resource, [
      { Ref: "AgentVersion" },
      { Ref: "SignerVersion" }
    ]) &&
      sameJson(boundaryDenyOther?.NotResource, [
        { Ref: "AgentVersion" },
        { Ref: "SignerVersion" }
      ]) &&
      sameJson(raceInvoke?.Resource, { Ref: "AuthorityVersion" }) &&
      sameJson(raceDenyOther?.NotResource, {
        Ref: "AuthorityVersion"
      }),
    "RELEASE_SECURITY_NUMERIC_ROLE_TARGETS"
  );

  const permissions = {
    BoundaryInvokePermission: {
      sourceArn:
        "arn:${AWS::Partition}:execute-api:${AWS::Region}:${AWS::AccountId}:${HttpApi}/$default/POST/advisory",
      version: "BoundaryVersion"
    },
    DemoAssetInvokePermission: {
      sourceArn:
        "arn:${AWS::Partition}:execute-api:${AWS::Region}:${AWS::AccountId}:${HttpApi}/$default/GET/*",
      version: "DemoVersion"
    },
    DemoRootInvokePermission: {
      sourceArn:
        "arn:${AWS::Partition}:execute-api:${AWS::Region}:${AWS::AccountId}:${HttpApi}/$default/GET/",
      version: "DemoVersion"
    }
  };
  for (const [name, expected] of Object.entries(permissions)) {
    const permission = resources[name];
    assert(
      permission?.Type === "AWS::Lambda::Permission" &&
        permission.Properties.Action === "lambda:InvokeFunction" &&
        permission.Properties.Principal === "apigateway.amazonaws.com" &&
        permission.Properties.SourceAccount?.Ref === "AWS::AccountId" &&
        permission.Properties.SourceArn?.["Fn::Sub"] ===
          expected.sourceArn &&
        sameJson(permission.Properties.FunctionName, {
          Ref: expected.version
        }),
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
  for (const [id, markers] of Object.entries(FORBIDDEN_SOURCE_MARKERS)) {
    const source = sources.get(id);
    assert(typeof source === "string", "RELEASE_SECURITY_MARKER_SOURCE");
    const normalizedSource = source.replace(/\s+/g, " ").trim();
    for (const marker of markers) {
      assert(
        !normalizedSource.includes(marker.replace(/\s+/g, " ").trim()),
        `RELEASE_SECURITY_FORBIDDEN_MARKER_${id.replaceAll("-", "_").toUpperCase()}`
      );
    }
  }
  for (const id of Object.keys(FORBIDDEN_SOURCE_PATTERNS)) {
    const source = sources.get(id);
    assertNoForbiddenSourcePatterns(id, source);
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

  const receipt = {
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
      numericLambdaInvocationTargetsBounded: true,
      leastPrivilegeRoleActionsBounded: true,
      criticalRoleDenialsPresent: true,
      evidenceOperatorTrustBounded: true,
      deploymentAttestationContractBounded: true,
      exactGitArtifactInputsBounded: true,
      apiGatewayInvokePermissionsBounded: true,
      asymmetricSigningKeyBounded: true,
      logsBoundedAndPrivacyMinimized: true,
      publicHeadersAndNegativeProbesBounded: true
    },
    claimBoundary:
      "This receipt proves only that the current hash-bound security surfaces match the reviewed source state and that the generated Gate Two template preserves the enumerated route, authentication, browser-header, negative-probe, throttle, concurrency, exact-Git-input, numeric-version, monitored-alias, evidence-operator-trust, deployment-attestation, IAM-action, Lambda-permission, KMS, log-retention, database-bootstrap, and Managed MCP source contracts checked here. It is not a vulnerability-free claim, penetration test, live AWS or CockroachDB receipt, administrator-exclusion finding, availability guarantee, production-suitability finding, or authorization to deploy, publish, or submit."
  };
  return validateReleaseSecurityReceipt(receipt);
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
  RELEASE_SECURITY_CHECK_KEYS,
  RELEASE_SECURITY_RECEIPT_KEYS,
  MANIFEST_PATH,
  MANIFEST_SCHEMA,
  MANIFEST_STATUS,
  FORBIDDEN_SOURCE_MARKERS,
  FORBIDDEN_SOURCE_PATTERNS,
  REQUIRED_DENY_ACTIONS,
  SOURCE_MARKERS,
  assertNoForbiddenSourcePatterns,
  assertRuntimeContract,
  assertSourceMarkers,
  assertTemplateContract,
  canonicalizeSqlGuardSource
});
