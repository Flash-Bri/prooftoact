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

const FRESH_PRIMARY_SURFACES = Object.freeze(Object.fromEntries([
  ["fresh-primary-caller-workflow", ".github/workflows/prooftoact-fresh-primary.yml", "EXACT_MAIN_FRESH_PRIMARY_CALLER"],
  ["fresh-primary-sealed-workflow", ".github/workflows/prooftoact-sealed-fresh-primary.yml", "PROTECTED_FRESH_PRIMARY_PROVIDER_EXECUTION"],
  ["fresh-primary-oidc-boundary", "docs/RELEASE_OIDC_BOUNDARY.md", "FRESH_PRIMARY_OIDC_AND_CREDENTIAL_BOUNDARY"],
  ["fresh-primary-bootstrap-role-template", "infra/aws/fresh-primary-bootstrap-role-stack.json", "FRESH_PRIMARY_EXACT_OIDC_ROLE_TEMPLATE"],
  ["fresh-primary-credential-custody-template", "infra/aws/fresh-primary-credential-custody-stack.json", "CREATE_ONLY_SEVEN_SECRET_CUSTODY_TEMPLATE"],
  ["release-control-aws-runtime", "release-control/src/release-control-aws-runtime.js", "FRESH_PROVIDER_DURABLE_CONTROL_RUNTIME"],
  ["one-time-bootstrap-root-session", "scripts/assume-one-time-bootstrap-root-session.js", "B0_NAMED_ROOT_MFA_SESSION_CUSTODY"],
  ["b0-a1-human-authorization-contract", "scripts/lib/prooftoact-b0-a1-human-authorization.js", "INDEPENDENTLY_SIGNED_B0_A1_HUMAN_AUTHORIZATION"],
  ["b0-a1-human-authorization-materializer", "scripts/materialize-prooftoact-b0-a1-human-authorization.js", "PINNED_IMESSAGE_HUMAN_AUTHORIZATION_MATERIALIZER"],
  ["one-time-bootstrap-authority-plan", "scripts/prepare-one-time-bootstrap-authority.js", "B0_EXACT_AUTHORITY_AND_COST_PLAN"],
  ["one-time-bootstrap-ceremony-launcher", "scripts/launch-one-time-bootstrap-ceremony.js", "SEALED_EXACT_SOURCE_B0_LAUNCHER"],
  ["one-time-bootstrap-ceremony-runner", "scripts/run-one-time-bootstrap-ceremony.js", "B0_CRASH_CONVERGENT_CEREMONY_RUNNER"],
  ["fresh-cluster-provider-key-revocation-finalizer", "scripts/finalize-fresh-cluster-provider-key-revocation.js", "FAIL_CLOSED_SEPARATE_ORG_ADMIN_REVOCATION_GATE"],
  ["fresh-primary-bootstrap", "scripts/bootstrap-fresh-primary.js", "FRESH_PRIMARY_DATABASE_BOOTSTRAP"],
  ["fresh-cluster-aws-provider", "scripts/fresh-cluster-aws-provider.js", "FRESH_CLUSTER_AWS_PROVIDER_CLIENT"],
  ["fresh-cluster-aws-runtime", "scripts/fresh-cluster-aws-runtime.js", "FRESH_CLUSTER_AWS_PROVIDER_RUNTIME"],
  ["fresh-cluster-cloud-controller", "scripts/fresh-cluster-cloud-controller.js", "FRESH_CLUSTER_CLOUD_API_CONTROLLER"],
  ["fresh-cluster-execution-runtime", "scripts/fresh-cluster-execution-runtime.js", "FRESH_CLUSTER_JOINED_EXECUTION_RUNTIME"],
  ["fresh-cluster-provider-controller", "scripts/fresh-cluster-provider-controller.js", "FRESH_CLUSTER_PROVIDER_EFFECT_CONTROLLER"],
  ["fresh-cluster-reconciliation-controller", "scripts/fresh-cluster-reconciliation-controller.js", "FRESH_CLUSTER_READ_ONLY_RECONCILIATION"],
  ["fresh-primary-aws-provider", "scripts/fresh-primary-aws-provider.js", "FRESH_PRIMARY_AWS_PROVIDER_CLIENT"],
  ["fresh-primary-aws-runtime", "scripts/fresh-primary-aws-runtime.js", "FRESH_PRIMARY_AWS_PROVIDER_RUNTIME"],
  ["fresh-primary-bootstrap-role-readback", "scripts/fresh-primary-bootstrap-role-readback.js", "FRESH_PRIMARY_ROLE_PROVIDER_READBACK"],
  ["fresh-primary-credential-custody-readback", "scripts/fresh-primary-credential-custody-readback.js", "SEVEN_SECRET_CUSTODY_PROVIDER_READBACK"],
  ["fresh-primary-credential-sealer-aws-runtime", "scripts/fresh-primary-credential-sealer-aws-runtime.js", "FIVE_VERSION_SECRET_SEAL_AWS_RUNTIME"],
  ["fresh-primary-credential-sealer", "scripts/fresh-primary-credential-sealer.js", "FIVE_VERSION_SECRET_SEAL_CONTROLLER"],
  ["fresh-primary-provider-controller", "scripts/fresh-primary-provider-controller.js", "FRESH_PRIMARY_PROVIDER_CONTROLLER"],
  ["fresh-recovery-publication-execution", "scripts/fresh-recovery-publication-execution.js", "FRESH_RECOVERY_PUBLICATION_EXECUTION"],
  ["fresh-recovery-source-execution", "scripts/fresh-recovery-source-execution.js", "FRESH_RECOVERY_SOURCE_EXECUTION"],
  ["fresh-cluster-provider-launcher", "scripts/launch-fresh-cluster-provider.js", "EXACT_SOURCE_FRESH_PROVIDER_LAUNCHER"],
  ["fresh-bootstrap-collector-binding", "scripts/lib/fresh-bootstrap-collector-binding.js", "EXACT_B0_COLLECTOR_IDENTITY_BINDING"],
  ["fresh-primary-source-lock", "scripts/lib/fresh-primary-source-lock.py", "PRE_CHECKOUT_REUSABLE_OIDC_SOURCE_LOCK"],
  ["fresh-recovery-publisher-key", "scripts/lib/fresh-recovery-publisher-key.js", "FRESH_RECOVERY_SIGNER_KEY_CUSTODY"],
  ["private-recovery-query-binding", "scripts/lib/private-recovery-query-binding.js", "PRIVATE_MANAGED_MCP_QUERY_BINDING"],
  ["fresh-primary-bootstrap-role-plan", "scripts/prepare-fresh-primary-bootstrap-role.js", "FRESH_PRIMARY_ROLE_CREATE_ONLY_PLAN"],
  ["fresh-primary-credential-custody-plan", "scripts/prepare-fresh-primary-credential-custody.js", "SEVEN_SECRET_CUSTODY_CREATE_ONLY_PLAN"],
  ["release-deployment-plan", "scripts/prepare-release-deployment.js", "FRESH_PRIMARY_RELEASE_DEPLOYMENT_PLAN"],
  ["fresh-cluster-provider-runner", "scripts/run-fresh-cluster-provider.js", "FRESH_CLUSTER_PRIVATE_PROVIDER_RUNNER"],
  ["fresh-primary-credential-sealer-runner", "scripts/run-fresh-primary-credential-sealer.js", "PRIVATE_FIVE_VERSION_SEAL_RUNNER"],
  ["fresh-primary-provider-runner", "scripts/run-fresh-primary-provider.js", "FRESH_PRIMARY_PRIVATE_PROVIDER_RUNNER"],
  ["fresh-primary-bootstrap-role-stack-tests", "test/fresh-primary-bootstrap-role-stack.test.js", "FRESH_PRIMARY_ROLE_TEMPLATE_VERIFICATION"],
  ["fresh-primary-bootstrap-tests", "test/fresh-primary-bootstrap.test.js", "FRESH_PRIMARY_BOOTSTRAP_VERIFICATION"],
  ["fresh-primary-provider-controller-tests", "test/fresh-primary-provider-controller.test.js", "FRESH_PRIMARY_CONTROLLER_VERIFICATION"],
  ["release-control-aws-runtime-tests", "test/release-control-aws-runtime.test.js", "FRESH_PROVIDER_CONTROL_RUNTIME_VERIFICATION"],
  ["release-control-runtime-loader-tests", "test/release-control-runtime-loader.test.js", "FRESH_PROVIDER_CONTROL_LOADER_VERIFICATION"],
  ["fresh-cluster-aws-provider-tests", "test/fresh-cluster-aws-provider.test.js", "FRESH_CLUSTER_AWS_PROVIDER_VERIFICATION"],
  ["fresh-cluster-aws-runtime-tests", "test/fresh-cluster-aws-runtime.test.js", "FRESH_CLUSTER_AWS_RUNTIME_VERIFICATION"],
  ["fresh-cluster-cloud-controller-tests", "test/fresh-cluster-cloud-controller.test.js", "FRESH_CLUSTER_CLOUD_CONTROLLER_VERIFICATION"],
  ["fresh-cluster-execution-runtime-tests", "test/fresh-cluster-execution-runtime.test.js", "FRESH_CLUSTER_EXECUTION_VERIFICATION"],
  ["fresh-cluster-provider-controller-tests", "test/fresh-cluster-provider-controller.test.js", "FRESH_CLUSTER_PROVIDER_CONTROLLER_VERIFICATION"],
  ["fresh-cluster-reconciliation-controller-tests", "test/fresh-cluster-reconciliation-controller.test.js", "FRESH_CLUSTER_RECONCILIATION_VERIFICATION"],
  ["fresh-primary-aws-provider-tests", "test/fresh-primary-aws-provider.test.js", "FRESH_PRIMARY_AWS_PROVIDER_VERIFICATION"],
  ["fresh-primary-aws-runtime-tests", "test/fresh-primary-aws-runtime.test.js", "FRESH_PRIMARY_AWS_RUNTIME_VERIFICATION"],
  ["fresh-primary-bootstrap-role-plan-tests", "test/fresh-primary-bootstrap-role-plan.test.js", "FRESH_PRIMARY_ROLE_PLAN_VERIFICATION"],
  ["fresh-primary-bootstrap-role-readback-tests", "test/fresh-primary-bootstrap-role-readback.test.js", "FRESH_PRIMARY_ROLE_READBACK_VERIFICATION"],
  ["fresh-primary-credential-custody-plan-tests", "test/fresh-primary-credential-custody-plan.test.js", "SEVEN_SECRET_CUSTODY_PLAN_VERIFICATION"],
  ["fresh-primary-credential-custody-readback-tests", "test/fresh-primary-credential-custody-readback.test.js", "SEVEN_SECRET_CUSTODY_READBACK_VERIFICATION"],
  ["fresh-primary-credential-sealer-runtime-tests", "test/fresh-primary-credential-sealer-runtime.test.js", "FIVE_VERSION_SEAL_RUNTIME_VERIFICATION"],
  ["fresh-primary-credential-sealer-tests", "test/fresh-primary-credential-sealer.test.js", "FIVE_VERSION_SEAL_CONTROLLER_VERIFICATION"],
  ["fresh-primary-workflow-tests", "test/fresh-primary-workflow.test.js", "FRESH_PRIMARY_WORKFLOW_VERIFICATION"],
  ["fresh-recovery-publication-execution-tests", "test/fresh-recovery-publication-execution.test.js", "FRESH_RECOVERY_PUBLICATION_VERIFICATION"],
  ["fresh-recovery-publisher-key-tests", "test/fresh-recovery-publisher-key.test.js", "FRESH_RECOVERY_SIGNER_VERIFICATION"],
  ["fresh-recovery-source-execution-tests", "test/fresh-recovery-source-execution.test.js", "FRESH_RECOVERY_SOURCE_VERIFICATION"],
  ["fresh-cluster-provider-launcher-tests", "test/launch-fresh-cluster-provider.test.js", "FRESH_PROVIDER_LAUNCHER_VERIFICATION"],
  ["fresh-cluster-provider-runner-tests", "test/run-fresh-cluster-provider.test.js", "FRESH_CLUSTER_RUNNER_VERIFICATION"],
  ["fresh-primary-provider-runner-tests", "test/run-fresh-primary-provider.test.js", "FRESH_PRIMARY_RUNNER_VERIFICATION"],
  ["one-time-bootstrap-authority-tests", "test/one-time-bootstrap-authority.test.js", "B0_AUTHORITY_COST_AND_CREDENTIAL_VERIFICATION"],
  ["one-time-bootstrap-ceremony-launcher-tests", "test/launch-one-time-bootstrap-ceremony.test.js", "SEALED_B0_LAUNCHER_VERIFICATION"],
  ["one-time-bootstrap-ceremony-runner-tests", "test/run-one-time-bootstrap-ceremony.test.js", "B0_CRASH_CONVERGENCE_VERIFICATION"],
  ["b0-a1-human-authorization-tests", "test/prooftoact-b0-a1-human-authorization.test.js", "B0_A1_SIGNED_AUTHORIZATION_CONTRACT_VERIFICATION"],
  ["b0-a1-imessage-authorization-tests", "test/prooftoact-imessage-human-authorization.test.js", "IMESSAGE_IDENTITY_AND_SIGNATURE_VERIFICATION"],
  ["b0-a1-human-authorization-fixture", "test/helpers/prooftoact-human-authorization-fixture.js", "SYNTHETIC_AUTHORIZATION_NEGATIVE_CONTROL_FIXTURE"],
  ["fresh-cluster-provider-key-revocation-tests", "test/finalize-fresh-cluster-provider-key-revocation.test.js", "FAIL_CLOSED_REVOCATION_GATE_VERIFICATION"]
].map(([id, path, role]) => [id, Object.freeze({ path, role })])));

const EXPECTED_SURFACES = Object.freeze({
  ...FRESH_PRIMARY_SURFACES,
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
  "deployment-config-digest": Object.freeze({
    path: "src/cloud/deployment-config-digest.js",
    role: "PROVIDER_FREE_DEPLOYMENT_CONFIGURATION_DIGEST_VALIDATOR"
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
  "gate2-build-contract": Object.freeze({
    path: "scripts/lib/gate2-build-contract.js",
    role: "EXACT_BUILD_RECEIPT_AND_CONTROL_PATH_CONTRACT"
  }),
  "official-node-runtime-contract": Object.freeze({
    path: "src/cloud/official-node-runtime-contract.js",
    role: "PINNED_OFFICIAL_NODE_RUNTIME_METADATA_CONTRACT"
  }),
  "official-node-runtime-loader": Object.freeze({
    path: "scripts/lib/official-node-runtime.js",
    role: "PINNED_OFFICIAL_NODE_RUNTIME_BINARY_VALIDATOR"
  }),
  "official-node-runtime-tests": Object.freeze({
    path: "test/official-node-runtime.test.js",
    role: "PINNED_OFFICIAL_NODE_RUNTIME_VERIFICATION"
  }),
  "pg-native-unavailable": Object.freeze({
    path: "scripts/lib/pg-native-unavailable.cjs",
    role: "OPTIONAL_NATIVE_DATABASE_DEPENDENCY_DENIAL"
  }),
  "release-build-receipt-contract": Object.freeze({
    path: "src/cloud/release-build-receipt-contract.js",
    role: "SHARED_EXACT_BUILD_RECEIPT_SHAPE"
  }),
  "verified-node-bundle-launcher": Object.freeze({
    path: "scripts/lib/verified-node-bundle-launcher.pl",
    role: "CONTENT_ADDRESSED_RUNTIME_EXECUTION_LAUNCHER"
  }),
  "immutable-deployment-attestation-ledger": Object.freeze({
    path: "docs/IMMUTABLE_DEPLOYMENT_ATTESTATION.md",
    role: "IMMUTABLE_DEPLOYMENT_ATTESTATION_BOUNDARY"
  }),
  "atomic-create-only-file": Object.freeze({
    path: "src/cloud/atomic-create-only-file.js",
    role: "OWNER_ONLY_ATOMIC_CREATE_OR_EXACT_REUSE_PRIMITIVE"
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
  "integrated-live-drill-process-boundary-verifier": Object.freeze({
    path: "scripts/verify-integrated-live-drill-process-boundaries.js",
    role: "INTEGRATED_PROVIDER_DRILL_RECURSIVE_PROCESS_IMPORT_GATE"
  }),
  "integrated-live-drill-process-boundary-tests": Object.freeze({
    path: "test/integrated-live-drill-process-boundaries.test.js",
    role: "INTEGRATED_PROVIDER_DRILL_PROCESS_ISOLATION_VERIFICATION"
  }),
  "integrated-live-drill-runtime-contract": Object.freeze({
    path: "src/cloud/integrated-live-drill-runtime.js",
    role: "INTEGRATED_PROVIDER_DRILL_IMMUTABLE_RUNTIME_VALIDATOR"
  }),
  "integrated-live-drill-runtime-spawn": Object.freeze({
    path: "src/cloud/integrated-live-drill-runtime-spawn.js",
    role: "INTEGRATED_PROVIDER_DRILL_SANITIZED_RUNTIME_SPAWN"
  }),
  "integrated-live-drill-runtime-tests": Object.freeze({
    path: "test/integrated-live-drill-runtime.test.js",
    role: "INTEGRATED_PROVIDER_DRILL_RUNTIME_TAMPER_VERIFICATION"
  }),
  "integrated-live-drill-runtime-authority-race-entry": Object.freeze({
    path: "scripts/runtime-entries/integrated-live-drill-authority-race.js",
    role: "CONTENT_ADDRESSED_AUTHORITY_RACE_ENTRY"
  }),
  "integrated-live-drill-runtime-dispatch-broker-entry": Object.freeze({
    path: "scripts/runtime-entries/integrated-live-drill-dispatch-broker.js",
    role: "CONTENT_ADDRESSED_DISPATCH_BROKER_ENTRY"
  }),
  "integrated-live-drill-runtime-provider-activation-entry": Object.freeze({
    path: "scripts/runtime-entries/integrated-live-drill-provider-activation.js",
    role: "CONTENT_ADDRESSED_PROVIDER_ACTIVATION_ENTRY"
  }),
  "integrated-live-drill-runtime-provider-exchange-entry": Object.freeze({
    path: "scripts/runtime-entries/integrated-live-drill-provider-exchange.js",
    role: "CONTENT_ADDRESSED_PROVIDER_EXCHANGE_ENTRY"
  }),
  "integrated-live-drill-runtime-provider-operation-entry": Object.freeze({
    path: "scripts/runtime-entries/integrated-live-drill-provider-operation.js",
    role: "CONTENT_ADDRESSED_PROVIDER_OPERATION_ENTRY"
  }),
  "integrated-live-drill-runtime-provider-terminalizer-entry": Object.freeze({
    path: "scripts/runtime-entries/integrated-live-drill-provider-terminalizer.js",
    role: "CONTENT_ADDRESSED_PROVIDER_TERMINALIZER_ENTRY"
  }),
  "integrated-live-drill-runtime-dvi-entry": Object.freeze({
    path: "scripts/runtime-entries/integrated-live-drill-dvi.js",
    role: "CONTENT_ADDRESSED_DVI_ENTRY"
  }),
  "integrated-live-drill-runtime-finalizer-entry": Object.freeze({
    path: "scripts/runtime-entries/integrated-live-drill-finalizer.js",
    role: "CONTENT_ADDRESSED_FINALIZER_ENTRY"
  }),
  "integrated-live-drill-runtime-orchestrator-entry": Object.freeze({
    path: "scripts/runtime-entries/integrated-live-drill-orchestrator.js",
    role: "CONTENT_ADDRESSED_ORCHESTRATOR_ENTRY"
  }),
  "integrated-live-drill-runtime-reconciler-entry": Object.freeze({
    path: "scripts/runtime-entries/integrated-live-drill-reconciler.js",
    role: "CONTENT_ADDRESSED_PROVIDER_RECONCILER_ENTRY"
  }),
  "integrated-live-drill-runtime-recovery-entry": Object.freeze({
    path: "scripts/runtime-entries/integrated-live-drill-recovery.js",
    role: "CONTENT_ADDRESSED_RECOVERY_ENTRY"
  }),
  "integrated-live-drill-runtime-supervisor-entry": Object.freeze({
    path: "scripts/runtime-entries/integrated-live-drill-supervisor.js",
    role: "CONTENT_ADDRESSED_SUPERVISOR_ENTRY"
  }),
  "integrated-live-drill-runtime-worker-entry": Object.freeze({
    path: "scripts/runtime-entries/integrated-live-drill-worker.js",
    role: "CONTENT_ADDRESSED_WORKER_ENTRY"
  }),
  "integrated-live-drill-stress-runner": Object.freeze({
    path: "scripts/run-integrated-live-drill-stress.js",
    role: "INTEGRATED_PROVIDER_DRILL_COUNT_BOUND_REGRESSION_RUNNER"
  }),
  "integrated-live-drill-stress-tests": Object.freeze({
    path: "test/integrated-live-drill-stress.test.js",
    role: "INTEGRATED_PROVIDER_DRILL_COUNT_BOUND_VERIFICATION"
  }),
  "integrated-live-drill-provider-evidence": Object.freeze({
    path: "src/cloud/integrated-live-drill-provider-evidence.js",
    role: "INTEGRATED_PROVIDER_DRILL_PROVIDER_FREE_EVIDENCE_VALIDATOR"
  }),
  "integrated-live-drill-provider-recovery": Object.freeze({
    path: "src/cloud/integrated-live-drill-provider-recovery.js",
    role:
      "INTEGRATED_PROVIDER_DRILL_B2A_SOURCE_WIRED_NOT_LIVE_PROVIDER_RECOVERY_LIBRARY"
  }),
  "integrated-live-drill-provider-recovery-tests": Object.freeze({
    path: "test/integrated-live-drill-provider-recovery.test.js",
    role:
      "INTEGRATED_PROVIDER_DRILL_B2A_STRICT_LOCAL_FAKE_TRANSPORT_VERIFICATION"
  }),
  "integrated-live-drill-dispatch-broker": Object.freeze({
    path: "src/cloud/integrated-live-drill-dispatch-broker.js",
    role: "PROVIDER_FREE_DATABASE_GLOBAL_DISPATCH_BROKER"
  }),
  "integrated-live-drill-dispatch-broker-runner": Object.freeze({
    path: "scripts/gate1-integrated-live-drill-dispatch-broker.js",
    role: "SYSTEMD_CREDENTIAL_FREE_GLOBAL_DISPATCH_RUNNER"
  }),
  "integrated-live-drill-dispatch-broker-tests": Object.freeze({
    path: "test/integrated-live-drill-dispatch-broker.test.js",
    role: "REAL_PROCESS_GLOBAL_DISPATCH_AND_RETRY_VERIFICATION"
  }),
  "integrated-live-drill-execution-fence-tests": Object.freeze({
    path: "test/integrated-live-drill-provider-execution-fence.test.js",
    role: "REAL_PROCESS_PROVIDER_EXECUTION_FENCE_VERIFICATION"
  }),
  "integrated-live-drill-atomic-publication-crash-fixture": Object.freeze({
    path: "test/fixtures/atomic-publication-crash-child.js",
    role: "ATOMIC_PUBLICATION_CRASH_RECOVERY_SUBPROCESS_FIXTURE"
  }),
  "integrated-live-drill-provider-operation-broker": Object.freeze({
    path: "src/cloud/integrated-live-drill-provider-operation-broker.js",
    role: "ONE_SHOT_PROVIDER_CREDENTIAL_AND_OPERATION_BROKER"
  }),
  "integrated-live-drill-provider-operation-client": Object.freeze({
    path: "src/cloud/brokered-provider-operation-client.js",
    role: "PROVIDER_CREDENTIAL_FREE_EXECUTOR_IPC_CLIENT"
  }),
  "integrated-live-drill-provider-operation-runner": Object.freeze({
    path: "scripts/gate1-integrated-live-drill-provider-operation-broker.js",
    role: "SYSTEMD_PROVIDER_OPERATION_BROKER_RUNNER"
  }),
  "integrated-live-drill-provider-operation-tests": Object.freeze({
    path: "test/provider-operation-broker.test.js",
    role: "ONE_REDEMPTION_AMBIGUITY_AND_NO_REDISPATCH_VERIFICATION"
  }),
  "integrated-live-drill-provider-activation": Object.freeze({
    path: "src/cloud/integrated-live-drill-provider-activation.js",
    role: "DATABASE_ACKNOWLEDGED_PROVIDER_ACTIVATION_CONTRACT"
  }),
  "integrated-live-drill-provider-activation-runner": Object.freeze({
    path: "scripts/gate1-integrated-live-drill-provider-activation.js",
    role: "SYSTEMD_DATABASE_ACTIVATION_RUNNER"
  }),
  "integrated-live-drill-provider-exchange": Object.freeze({
    path: "src/cloud/integrated-live-drill-provider-exchange.js",
    role: "ONE_SHOT_PROVIDER_BEARER_EXCHANGE"
  }),
  "integrated-live-drill-provider-exchange-runner": Object.freeze({
    path: "scripts/gate1-integrated-live-drill-provider-exchange.js",
    role: "SYSTEMD_ONE_SHOT_PROVIDER_EXCHANGE_RUNNER"
  }),
  "integrated-live-drill-provider-terminalization": Object.freeze({
    path: "src/cloud/integrated-live-drill-provider-terminalization.js",
    role: "DATABASE_TIME_PROVIDER_TERMINALIZATION_CONTRACT"
  }),
  "integrated-live-drill-provider-terminalizer-runner": Object.freeze({
    path: "scripts/gate1-integrated-live-drill-provider-terminalizer.js",
    role: "SYSTEMD_DATABASE_TERMINALIZATION_RUNNER"
  }),
  "integrated-live-drill-provider-activation-terminalization-tests": Object.freeze({
    path: "test/provider-dispatch-activation-terminalization.test.js",
    role: "ACTIVATION_TERMINALIZATION_AUTHORITY_AND_RACE_VERIFICATION"
  }),
  "integrated-live-drill-provider-finalization": Object.freeze({
    path: "src/cloud/integrated-live-drill-provider-finalization.js",
    role:
      "INTEGRATED_PROVIDER_DRILL_B2_PROVIDER_FREE_W4_W5_FINALIZATION"
  }),
  "integrated-live-drill-provider-finalizer-runner": Object.freeze({
    path: "scripts/gate2-integrated-live-drill-provider-finalizer.js",
    role:
      "INTEGRATED_PROVIDER_DRILL_B2_PROVIDER_FREE_FINALIZER_RUNNER"
  }),
  "integrated-live-drill-provider-orchestration": Object.freeze({
    path: "src/cloud/integrated-live-drill-provider-orchestration.js",
    role:
      "INTEGRATED_PROVIDER_DRILL_B2_DURABLE_PREPARE_HOLD_RESUME_CONTRACT"
  }),
  "integrated-live-drill-provider-orchestration-tests": Object.freeze({
    path: "test/integrated-live-drill-provider-orchestration.test.js",
    role:
      "INTEGRATED_PROVIDER_DRILL_B2_ORCHESTRATION_FAIL_CLOSED_VERIFICATION"
  }),
  "integrated-live-drill-provider-reconciliation": Object.freeze({
    path: "src/cloud/integrated-live-drill-provider-reconciliation.js",
    role: "INTEGRATED_PROVIDER_DRILL_AUDIT_ONLY_RECONCILIATION"
  }),
  "integrated-live-drill-provider-reconciliation-runner": Object.freeze({
    path: "scripts/gate1-integrated-live-drill-provider-reconciler.js",
    role: "INTEGRATED_PROVIDER_DRILL_AUDIT_ONLY_RECONCILIATION_RUNNER"
  }),
  "integrated-live-drill-provider-reconciliation-tests": Object.freeze({
    path: "test/integrated-live-drill-provider-reconciliation.test.js",
    role: "INTEGRATED_PROVIDER_DRILL_AUDIT_ONLY_RECONCILIATION_VERIFICATION"
  }),
  "integrated-live-drill-provider-supervisor-runner": Object.freeze({
    path: "scripts/gate1-integrated-live-drill-provider-supervisor.js",
    role:
      "INTEGRATED_PROVIDER_DRILL_B2_PREPARE_RESUME_SUPERVISOR"
  }),
  "integrated-live-drill-provider-worker": Object.freeze({
    path: "src/cloud/integrated-live-drill-provider-worker.js",
    role:
      "INTEGRATED_PROVIDER_DRILL_B2_CREDENTIAL_ISOLATED_PROVIDER_WORKER"
  }),
  "integrated-live-drill-provider-worker-runner": Object.freeze({
    path: "scripts/gate1-integrated-live-drill-provider-worker.js",
    role:
      "INTEGRATED_PROVIDER_DRILL_B2_PROVIDER_WORKER_RUNNER"
  }),
  "integrated-live-drill-root-stage-installer": Object.freeze({
    path: "scripts/install-integrated-live-drill-stage.js",
    role: "ROOT_ONLY_ATOMIC_RUNTIME_STAGE_INSTALLER"
  }),
  "integrated-live-drill-root-stage-verifier": Object.freeze({
    path: "scripts/verify-integrated-live-drill-stage.js",
    role: "INDEPENDENT_NON_ROOT_RUNTIME_STAGE_VERIFIER"
  }),
  "integrated-live-drill-root-stage-tests": Object.freeze({
    path: "test/root/integrated-live-drill-stage-root.test.js",
    role: "LINUX_ROOT_STAGE_ADVERSARIAL_VERIFICATION"
  }),
  "integrated-live-drill-systemd-boundary-verifier": Object.freeze({
    path: "scripts/verify-integrated-live-drill-systemd-boundary.js",
    role: "FIRST_EXEC_SYSTEMD_CREDENTIAL_BOUNDARY_VERIFIER"
  }),
  "integrated-live-drill-systemd-stage-verify-unit": Object.freeze({
    path: "infra/systemd/prooftoact-integrated-live-drill-stage-verify@.service",
    role: "ROOT_STAGE_FIRST_EXEC_VERIFICATION_UNIT"
  }),
  "integrated-live-drill-systemd-controller-unit": Object.freeze({
    path: "infra/systemd/prooftoact-integrated-live-drill@.service",
    role: "PROVIDER_FREE_PREPARATION_UNIT"
  }),
  "integrated-live-drill-systemd-resume-unit": Object.freeze({
    path: "infra/systemd/prooftoact-integrated-live-drill-resume@.service",
    role: "PROVIDER_FREE_RESUME_UNIT"
  }),
  "integrated-live-drill-systemd-dispatch-broker-unit": Object.freeze({
    path: "infra/systemd/prooftoact-integrated-live-drill-dispatch-broker@.service",
    role: "CLAIM_AND_BEGIN_ONLY_DISPATCH_UNIT"
  }),
  "integrated-live-drill-systemd-executor-unit": Object.freeze({
    path: "infra/systemd/prooftoact-integrated-live-drill-executor@.service",
    role: "PROVIDER_CREDENTIAL_FREE_EXECUTOR_UNIT"
  }),
  "integrated-live-drill-systemd-provider-operation-unit": Object.freeze({
    path: "infra/systemd/prooftoact-integrated-live-drill-provider-operation@.service",
    role: "ONE_SHOT_PROVIDER_CREDENTIAL_UNIT"
  }),
  "integrated-live-drill-systemd-provider-operation-socket": Object.freeze({
    path: "infra/systemd/prooftoact-integrated-live-drill-provider-operation@.socket",
    role: "ONE_SHOT_PROVIDER_OPERATION_IPC_SOCKET"
  }),
  "integrated-live-drill-systemd-provider-activation-unit": Object.freeze({
    path: "infra/systemd/prooftoact-integrated-live-drill-provider-activation@.service",
    role: "DATABASE_ACTIVATION_SERVICE_UNIT"
  }),
  "integrated-live-drill-systemd-provider-activation-socket": Object.freeze({
    path: "infra/systemd/prooftoact-integrated-live-drill-provider-activation@.socket",
    role: "OPERATION_OWNED_ACTIVATION_SOCKET"
  }),
  "integrated-live-drill-systemd-provider-callback-socket": Object.freeze({
    path: "infra/systemd/prooftoact-integrated-live-drill-provider-callback@.socket",
    role: "PROVIDER_OWNED_CALLBACK_SOCKET"
  }),
  "integrated-live-drill-systemd-provider-exchange-unit": Object.freeze({
    path: "infra/systemd/prooftoact-integrated-live-drill-provider-exchange@.service",
    role: "ONE_SHOT_PROVIDER_BEARER_SERVICE_UNIT"
  }),
  "integrated-live-drill-systemd-provider-terminalizer-unit": Object.freeze({
    path: "infra/systemd/prooftoact-integrated-live-drill-provider-terminalizer@.service",
    role: "DATABASE_TIME_TERMINALIZER_SERVICE_UNIT"
  }),
  "integrated-live-drill-systemd-provider-terminalizer-timer": Object.freeze({
    path: "infra/systemd/prooftoact-integrated-live-drill-provider-terminalizer@.timer",
    role: "DATABASE_TIME_TERMINALIZATION_TIMER"
  }),
  "integrated-live-drill-sysusers": Object.freeze({
    path: "infra/sysusers.d/prooftoact.conf",
    role: "SEVEN_IDENTITY_SYSTEMD_SYSUSERS_CONTROL"
  }),
  "integrated-live-drill-systemd-reconcile-unit": Object.freeze({
    path: "infra/systemd/prooftoact-integrated-live-drill-reconcile@.service",
    role: "RESOLVE_ONLY_RECONCILIATION_UNIT"
  }),
  "integrated-live-drill-systemd-credential-reader": Object.freeze({
    path: "src/cloud/systemd-credential.js",
    role: "NOFOLLOW_SYSTEMD_CREDENTIAL_READER"
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
  "managed-mcp-client-tests": Object.freeze({
    path: "test/managed-mcp-client.test.js",
    role: "RECOVERY_MCP_STRICT_TRANSPORT_VERIFICATION"
  }),
  "judge-proof-lambda": Object.freeze({
    path: "infra/aws/lambda/judge-proof.js",
    role: "AWS_FIXED_PUBLIC_JUDGE_PROOF_RUNTIME"
  }),
  "judge-proof-mcp-tests": Object.freeze({
    path: "test/judge-managed-mcp-client.test.js",
    role: "PUBLIC_JUDGE_MCP_TRANSPORT_VERIFICATION"
  }),
  "judge-proof-query": Object.freeze({
    path: "src/cloud/judge-proof-query.js",
    role: "SIGNED_FIXED_JUDGE_QUERY_CONTRACT"
  }),
  "judge-proof-query-tests": Object.freeze({
    path: "test/judge-proof-query.test.js",
    role: "SIGNED_FIXED_JUDGE_QUERY_VERIFICATION"
  }),
  "public-judge-proof-runtime": Object.freeze({
    path: "src/cloud/public-judge-proof.js",
    role: "SANITIZED_PUBLIC_JUDGE_PROOF_BOUNDARY"
  }),
  "public-judge-proof-tests": Object.freeze({
    path: "test/public-judge-proof.test.js",
    role: "PUBLIC_JUDGE_PROOF_BOUNDARY_VERIFICATION"
  }),
  "managed-mcp-recovery-grant-repair": Object.freeze({
    path: "scripts/repair-managed-mcp-recovery-grants.js",
    role: "MANAGED_MCP_RECOVERY_EXISTING_CLUSTER_REPAIR"
  }),
  "primary-security-bootstrap": Object.freeze({
    path: "src/cloud/primary-security.js",
    role: "PRIMARY_DATABASE_SECURITY"
  }),
  "primary-security-runner": Object.freeze({
    path: "scripts/gate1-security.js",
    role: "PRIMARY_DATABASE_SECURITY_EVIDENCE_RUNNER"
  }),
  "private-recovery-query-approval-generator": Object.freeze({
    path: "scripts/generate-private-recovery-query-approval.js",
    role: "PRIVATE_RECOVERY_QUERY_PROVIDER_BOUND_APPROVAL_GENERATOR"
  }),
  "private-recovery-query-approval-tests": Object.freeze({
    path: "test/private-recovery-query-approval.test.js",
    role: "PRIVATE_RECOVERY_QUERY_APPROVAL_AND_WINDOW_VERIFICATION"
  }),
  "private-recovery-query-aws-runtime": Object.freeze({
    path: "src/cloud/private-recovery-query-aws-runtime.js",
    role: "PRIVATE_RECOVERY_QUERY_AWS_RUNTIME"
  }),
  "private-recovery-query-aws-store": Object.freeze({
    path: "src/cloud/private-recovery-query-aws-store.js",
    role: "PRIVATE_RECOVERY_QUERY_DURABLE_ONE_SHOT_STORE"
  }),
  "private-recovery-query-bootstrap-role-stack": Object.freeze({
    path: "infra/aws/private-recovery-query-bootstrap-role-stack.json",
    role: "PRIVATE_RECOVERY_QUERY_DEDICATED_DEPLOYMENT_BOUNDARY"
  }),
  "private-recovery-query-bootstrap-tests": Object.freeze({
    path: "test/private-recovery-query-bootstrap-role-stack.test.js",
    role: "PRIVATE_RECOVERY_QUERY_BOOTSTRAP_IAM_VERIFICATION"
  }),
  "private-recovery-query-build": Object.freeze({
    path: "scripts/build-private-recovery-query-lambda.js",
    role: "PRIVATE_RECOVERY_QUERY_DETERMINISTIC_BUILD"
  }),
  "private-recovery-query-core": Object.freeze({
    path: "src/cloud/private-recovery-query.js",
    role: "PRIVATE_RECOVERY_QUERY_FIXED_MCP_RUNTIME_CONTRACT"
  }),
  "private-recovery-query-core-tests": Object.freeze({
    path: "test/private-recovery-query.test.js",
    role: "PRIVATE_RECOVERY_QUERY_RUNTIME_VERIFICATION"
  }),
  "private-recovery-query-deploy-caller-workflow": Object.freeze({
    path: ".github/workflows/prooftoact-private-recovery-deploy.yml",
    role: "PRIVATE_RECOVERY_QUERY_DEPLOY_CALLER"
  }),
  "private-recovery-query-deploy-preparer": Object.freeze({
    path: "scripts/prepare-private-recovery-query-deployment.js",
    role: "PRIVATE_RECOVERY_QUERY_CREATE_ONLY_DEPLOYMENT_PREPARER"
  }),
  "private-recovery-query-deploy-runner": Object.freeze({
    path: "scripts/deploy-private-recovery-query.js",
    role: "PRIVATE_RECOVERY_QUERY_RESTART_CONVERGENT_DEPLOYMENT"
  }),
  "private-recovery-query-deploy-sealed-workflow": Object.freeze({
    path: ".github/workflows/prooftoact-sealed-private-recovery-deploy.yml",
    role: "PRIVATE_RECOVERY_QUERY_SEALED_CREATE_ONLY_DEPLOYMENT"
  }),
  "private-recovery-query-evidence": Object.freeze({
    path: "src/cloud/private-recovery-query-evidence.js",
    role: "PRIVATE_RECOVERY_QUERY_SIGNED_EVIDENCE_CONTRACT"
  }),
  "private-recovery-query-evidence-caller-workflow": Object.freeze({
    path: ".github/workflows/prooftoact-private-recovery-evidence.yml",
    role: "PRIVATE_RECOVERY_QUERY_EVIDENCE_CALLER"
  }),
  "private-recovery-query-evidence-readback": Object.freeze({
    path: "scripts/readback-private-recovery-query.js",
    role: "PRIVATE_RECOVERY_QUERY_PROVIDER_READBACK_COLLECTOR"
  }),
  "private-recovery-query-evidence-sealed-workflow": Object.freeze({
    path: ".github/workflows/prooftoact-sealed-private-recovery-evidence.yml",
    role: "PRIVATE_RECOVERY_QUERY_SEALED_SIGNED_EVIDENCE"
  }),
  "private-recovery-query-evidence-tests": Object.freeze({
    path: "test/private-recovery-query-evidence.test.js",
    role: "PRIVATE_RECOVERY_QUERY_SIGNED_EVIDENCE_VERIFICATION"
  }),
  "private-recovery-query-deployment-state-tests": Object.freeze({
    path: "test/private-recovery-query-deployment-state.test.js",
    role: "PRIVATE_RECOVERY_QUERY_DEPLOYMENT_RESTART_VERIFICATION"
  }),
  "private-recovery-query-lambda-entry": Object.freeze({
    path: "infra/aws/lambda/private-recovery-query.js",
    role: "PRIVATE_RECOVERY_QUERY_LAMBDA_ENTRY"
  }),
  "private-recovery-query-operator": Object.freeze({
    path: "src/cloud/private-recovery-query-operator.js",
    role: "PRIVATE_RECOVERY_QUERY_ONE_SHOT_OPERATOR"
  }),
  "private-recovery-query-operator-aws": Object.freeze({
    path: "src/cloud/private-recovery-query-operator-aws.js",
    role: "PRIVATE_RECOVERY_QUERY_AWS_EXACT_VERSION_INVOKER"
  }),
  "private-recovery-query-query-caller-workflow": Object.freeze({
    path: ".github/workflows/prooftoact-private-recovery-query.yml",
    role: "PRIVATE_RECOVERY_QUERY_EXECUTION_CALLER"
  }),
  "private-recovery-query-query-runner": Object.freeze({
    path: "scripts/run-private-recovery-query.js",
    role: "PRIVATE_RECOVERY_QUERY_EXECUTE_OR_RECONCILE_RUNNER"
  }),
  "private-recovery-query-query-sealed-workflow": Object.freeze({
    path: ".github/workflows/prooftoact-sealed-private-recovery-query.yml",
    role: "PRIVATE_RECOVERY_QUERY_SEALED_EXECUTION"
  }),
  "private-recovery-query-secret-seal-caller-workflow": Object.freeze({
    path: ".github/workflows/prooftoact-private-recovery-secret-seal.yml",
    role: "PRIVATE_RECOVERY_QUERY_SECRET_SEAL_CALLER"
  }),
  "private-recovery-query-secret-seal-runner": Object.freeze({
    path: "scripts/seal-private-recovery-query-secret.js",
    role: "PRIVATE_RECOVERY_QUERY_ONE_VERSION_SECRET_SEAL"
  }),
  "private-recovery-query-secret-seal-sealed-workflow": Object.freeze({
    path: ".github/workflows/prooftoact-sealed-private-recovery-secret-seal.yml",
    role: "PRIVATE_RECOVERY_QUERY_SEALED_SECRET_SEAL"
  }),
  "private-recovery-query-secret-seal-tests": Object.freeze({
    path: "test/private-recovery-query-secret-seal.test.js",
    role: "PRIVATE_RECOVERY_QUERY_SECRET_CUSTODY_VERIFICATION"
  }),
  "private-recovery-query-source-lock": Object.freeze({
    path: "scripts/lib/private-recovery-source-lock.py",
    role: "PRIVATE_RECOVERY_QUERY_REUSABLE_WORKFLOW_SOURCE_LOCK"
  }),
  "private-recovery-query-source-lock-tests": Object.freeze({
    path: "test/private-recovery-source-lock.test.js",
    role: "PRIVATE_RECOVERY_QUERY_REUSABLE_SOURCE_LOCK_VERIFICATION"
  }),
  "private-recovery-query-store-tests": Object.freeze({
    path: "test/private-recovery-query-aws-store.test.js",
    role: "PRIVATE_RECOVERY_QUERY_DURABLE_STORE_VERIFICATION"
  }),
  "private-recovery-query-teardown-caller-workflow": Object.freeze({
    path: ".github/workflows/prooftoact-private-recovery-teardown.yml",
    role: "PRIVATE_RECOVERY_QUERY_TEARDOWN_CALLER"
  }),
  "private-recovery-query-teardown-runner": Object.freeze({
    path: "scripts/teardown-private-recovery-query.js",
    role: "PRIVATE_RECOVERY_QUERY_EVIDENCE_GATED_TEARDOWN"
  }),
  "private-recovery-query-teardown-sealed-workflow": Object.freeze({
    path: ".github/workflows/prooftoact-sealed-private-recovery-teardown.yml",
    role: "PRIVATE_RECOVERY_QUERY_SEALED_TEARDOWN"
  }),
  "private-recovery-query-teardown-tests": Object.freeze({
    path: "test/private-recovery-query-teardown.test.js",
    role: "PRIVATE_RECOVERY_QUERY_TEARDOWN_VERIFICATION"
  }),
  "private-recovery-query-template": Object.freeze({
    path: "src/cloud/private-recovery-query-template.js",
    role: "PRIVATE_RECOVERY_QUERY_MINI_STACK_SOURCE"
  }),
  "private-recovery-query-template-tests": Object.freeze({
    path: "test/private-recovery-query-template.test.js",
    role: "PRIVATE_RECOVERY_QUERY_TEMPLATE_AND_WORKFLOW_VERIFICATION"
  }),
  "private-recovery-query-window-check": Object.freeze({
    path: "scripts/check-private-recovery-query-window.js",
    role: "PRIVATE_RECOVERY_QUERY_REMAINING_WINDOW_GATE"
  }),
  "provider-dispatch-control": Object.freeze({
    path: "src/cloud/provider-dispatch-control.js",
    role: "DISABLED_LEGACY_PROVIDER_DISPATCH_INTERFACE"
  }),
  "provider-dispatch-binding": Object.freeze({
    path: "src/cloud/provider-dispatch-binding.js",
    role: "DATABASE_GLOBAL_PROVIDER_DISPATCH_BINDING"
  }),
  "provider-dispatch-client": Object.freeze({
    path: "src/cloud/provider-dispatch-client.js",
    role: "SHARED_PROVIDER_DISPATCH_DATABASE_RESULT_VALIDATOR"
  }),
  "provider-dispatch-claim-control": Object.freeze({
    path: "src/cloud/provider-dispatch-claim-control.js",
    role: "CLAIM_ONLY_PROVIDER_DISPATCH_CLIENT"
  }),
  "provider-dispatch-begin-control": Object.freeze({
    path: "src/cloud/provider-dispatch-begin-control.js",
    role: "BEGIN_ONLY_PROVIDER_DISPATCH_CLIENT"
  }),
  "provider-dispatch-redeem-control": Object.freeze({
    path: "src/cloud/provider-dispatch-redeem-control.js",
    role: "REDEEM_ONLY_PROVIDER_DISPATCH_CLIENT"
  }),
  "provider-dispatch-finalize-control": Object.freeze({
    path: "src/cloud/provider-dispatch-finalize-control.js",
    role: "OWNER_BOUND_PROVIDER_FINALIZATION_CLIENT"
  }),
  "provider-dispatch-activate-control": Object.freeze({
    path: "src/cloud/provider-dispatch-activate-control.js",
    role: "ACTIVATE_ONLY_PROVIDER_DISPATCH_CLIENT"
  }),
  "provider-dispatch-reconciliation-input": Object.freeze({
    path: "src/cloud/provider-dispatch-reconciliation-input.js",
    role: "SHARED_STRICT_PROVIDER_RECONCILIATION_INPUT"
  }),
  "provider-dispatch-resolve-database": Object.freeze({
    path: "src/cloud/provider-dispatch-resolve-database.js",
    role: "RESOLVE_ONLY_DATABASE_CONNECTION_FACTORY"
  }),
  "provider-dispatch-result": Object.freeze({
    path: "src/cloud/provider-dispatch-result.js",
    role: "SHARED_STRICT_PROVIDER_DISPATCH_RESULT_VALIDATOR"
  }),
  "provider-dispatch-terminalize-control": Object.freeze({
    path: "src/cloud/provider-dispatch-terminalize-control.js",
    role: "TERMINALIZE_ONLY_PROVIDER_DISPATCH_CLIENT"
  }),
  "provider-dispatch-resolver": Object.freeze({
    path: "src/cloud/provider-dispatch-resolver.js",
    role: "RESOLVE_ONLY_PROVIDER_DISPATCH_CLIENT"
  }),
  "provider-dispatch-control-tests": Object.freeze({
    path: "test/provider-dispatch-control.test.js",
    role: "DATABASE_GLOBAL_PROVIDER_DISPATCH_VERIFICATION"
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
  "recovery-broker-tests": Object.freeze({
    path: "test/recovery-broker.test.js",
    role: "RECOVERY_BROKER_AMBIGUOUS_RESULT_VERIFICATION"
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
    role: "DIRECT_RECOVERY_ENTRY_FAIL_CLOSED"
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
  "recovery-publisher-schema-repair": Object.freeze({
    path: "scripts/repair-recovery-publisher-private-schema-usage.js",
    role: "RECOVERY_PUBLISHER_EXISTING_CLUSTER_REPAIR"
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
  "strict-json-contract": Object.freeze({
    path: "src/cloud/strict-json.js",
    role: "STRICT_JSON_DUPLICATE_MEMBER_REJECTION"
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
  ...Object.freeze({
    ...Object.fromEntries(Object.keys(FRESH_PRIMARY_SURFACES).map((id) =>
      [id, Object.freeze([])])),
    "fresh-primary-caller-workflow": Object.freeze([
      "name: ProofToAct Fresh Cluster And Primary",
      "github.ref == 'refs/heads/main'",
      "cancel-in-progress: false",
      "id-token: write",
      "b8f993a4a9a898673c89dbd8218ec7eb591f1f10",
      "4615e7bea235f1c4ddf7f680d125cad6d355fecf"
    ]),
    "fresh-primary-sealed-workflow": Object.freeze([
      "name: ProofToAct Sealed Fresh Cluster And Primary",
      "environment: aws-release-database-bootstrap",
      "timeout-minutes: 45",
      "PROOFTOACT_FRESH_CLUSTER_APPROVAL_SHA256",
      "PROOFTOACT_HUMAN_AUTHORIZATION_SIGNER_SHA256",
      "github.workflow_ref",
      "github.workflow_sha",
      "--mode reconcile-only"
    ]),
    "fresh-primary-oidc-boundary": Object.freeze([
      "credential custody boundary",
      "exactly seven empty retained Secrets Manager containers",
      "exactly five one-version containers",
      "b8f993a4a9a898673c89dbd8218ec7eb591f1f10",
      "4615e7bea235f1c4ddf7f680d125cad6d355fecf"
    ]),
    "fresh-primary-bootstrap-role-template": Object.freeze([
      "ProofToActFreshPrimaryBootstrap",
      "token.actions.githubusercontent.com:job_workflow_ref",
      "DenyUnrelatedProviderCapabilities",
      "b8f993a4a9a898673c89dbd8218ec7eb591f1f10"
    ]),
    "fresh-primary-credential-custody-template": Object.freeze([
      "FreshPrimaryCredentialWriterRole",
      "SealAndReadExactFiveCredentialVersions",
      "DenySecretLifecycleMutation"
    ]),
    "release-control-aws-runtime": Object.freeze([
      "putReleaseControlItem",
      "new dynamodb.PutItemCommand",
      "requireExactTable(input, tableName)",
      "maxAttempts: 1"
    ]),
    "one-time-bootstrap-root-session": Object.freeze([
      "createNamedRootProfileStsClient",
      "assumeOneTimeBootstrapRootSession",
      "bytes.fill(0)",
      "ONE_TIME_BOOTSTRAP_ROOT_ASSUME_REJECTED"
    ]),
    "b0-a1-human-authorization-contract": Object.freeze([
      "prooftoact.b0-a1-human-authorization-contract.v4",
      "humanAuthorizationSignerPublicKeySha256",
      "crypto.verify(",
      "awsMonthlyResidualCeilingUsdCents === 350",
      "DELETE_OR_ROTATE_CREATOR_OR_AUDITOR_PROVIDER_KEYS"
    ]),
    "b0-a1-human-authorization-materializer": Object.freeze([
      "AUTHORIZATION_SIGNING_SEED_DOMAIN",
      "authorizationSigner(hmacKey)",
      "crypto.sign(null, signaturePayload.bytes",
      "verifyProofToActB0A1HumanAuthorizationWithImsg",
      "hmacKey.fill(0)"
    ]),
    "one-time-bootstrap-authority-plan": Object.freeze([
      "EXACT_MONTHLY_AUTHORIZATION_USD_CENTS = 350",
      "ITEMIZED_EXACT_RESOURCE_ENVELOPE_REVIEWED",
      "COST_RECONCILIATION_MAXIMUM_AGE_MS",
      "AWS_SECRETS_MANAGER_EIGHT_RETAINED_SECRETS",
      "ONE_TIME_BOOTSTRAP_COST_CEILING_REJECTED"
    ]),
    "one-time-bootstrap-ceremony-launcher": Object.freeze([
      "ONE_TIME_BOOTSTRAP_LAUNCH_IMPORT_GRAPH_REJECTED",
      "createSealedSnapshot",
      "maximumMonthlyUsdCents === 350",
      "authorizationBytes.fill(0)"
    ]),
    "one-time-bootstrap-ceremony-runner": Object.freeze([
      "runCrashConvergentMutation",
      "runCrashConvergentSecretSeal",
      "validateOneTimeBootstrapTimingBudget",
      "verifyProofToActB0A1HumanAuthorizationWithImsg",
      "awsMonthlyResidualCeilingUsdCents"
    ]),
    "fresh-cluster-provider-key-revocation-finalizer": Object.freeze([
      "HOLD_REQUIRES_SEPARATE_SIGNED_ORGANIZATION_ADMIN_AUTHORIZATION",
      "FRESH_CLUSTER_KEY_REVOCATION_INDEPENDENT_ORG_ADMIN_AUTHORIZATION_REQUIRED",
      "void provider"
    ]),
    "fresh-primary-bootstrap": Object.freeze([
      "validateFreshPrimaryCredentialBundle",
      "env.GITHUB_SHA === callerWorkflowSha",
      "runFreshPrimaryProviderControlledBootstrap",
      "freshPrimaryIntent",
      "EXACT_COMPLETE_SHOW_USERS_LOGIN_POSTURE",
      "rootNoLoginProvedFromShowUsers",
      "rootCredentialLifecycle",
      "immutable built-in admin role remains a provider-managed exception"
    ]),
    "fresh-cluster-aws-provider": Object.freeze([
      "createFreshClusterAwsProvider",
      "readFreshClusterSecretMaterial",
      "normalizeFreshClusterAdminSealReadback"
    ]),
    "fresh-cluster-aws-runtime": Object.freeze([
      "createFreshClusterAwsRuntime",
      "FRESH_CLUSTER_AWS_CONFIGURATION_REJECTED",
      "maxAttempts: 1"
    ]),
    "fresh-cluster-cloud-controller": Object.freeze([
      "createFreshClusterCloudRuntime",
      "reconcileFreshClusterInventory",
      "approvalExpiresAt - authorizedAt <= 60 * 60 * 1000",
      "now < Date.parse(accepted.approval.billingAuthorization.retentionDeadline)",
      "humanAuthorizationReceiptSha256",
      "FRESH_CLUSTER_CLOUD_REQUEST_FAILED_NO_RETRY"
    ]),
    "fresh-cluster-execution-runtime": Object.freeze([
      "createFreshClusterExecutionRuntime",
      "createFreshClusterCleanupRuntime",
      "FRESH_CLUSTER_EXECUTION_CONFIGURATION_REJECTED"
    ]),
    "fresh-cluster-provider-controller": Object.freeze([
      "FreshClusterProviderController",
      "UNKNOWN_DO_NOT_RETRY",
      "PROVIDER_KEYS_REVOCATION_PENDING",
      "providerKeyRevocationCeremony",
      "completeShowUsersPrincipalCensusSha256",
      "commitValidatorSequenceMatchedDirectDvi",
      "assertCleanupOpen(clock, command);"
    ]),
    "fresh-cluster-reconciliation-controller": Object.freeze([
      "reconcileFreshClusterProviderAccess",
      "AUTHENTICATED_PROVIDER_READBACK",
      "FRESH_CLUSTER_CLEANUP_PENDING_RETRY_REQUIRED",
      "requireCleanupDispatch();",
      "FRESH_CLUSTER_CLEANUP_APPROVAL_EXPIRED"
    ]),
    "fresh-primary-aws-provider": Object.freeze([
      "createFreshPrimaryAwsProvider",
      "putRecoverySignerSecret",
      "FRESH_PRIMARY_AWS_SIGNER_SECRET_UNKNOWN_DO_NOT_RETRY"
    ]),
    "fresh-primary-aws-runtime": Object.freeze([
      "createFreshPrimaryAwsRuntime",
      "FRESH_PRIMARY_AWS_RUNTIME_CONFIGURATION_REJECTED",
      "maxAttempts: 1"
    ]),
    "fresh-primary-bootstrap-role-readback": Object.freeze([
      "verifyFreshPrimaryBootstrapRoleReadback",
      "permissionsBoundaryArn",
      "validateFreshBootstrapCollectorCaller"
    ]),
    "fresh-primary-credential-custody-readback": Object.freeze([
      "verifyFreshPrimaryCredentialCustodyReadback",
      "freshPrimaryCredentialSecretArnsFromStackOutputs",
      "EXACT_FIVE_SEALED_TWO_EMPTY_CREATOR_LIFECYCLE_ACCEPTED"
    ]),
    "fresh-primary-credential-sealer-aws-runtime": Object.freeze([
      "createFreshPrimaryCredentialSealerAwsRuntime",
      "IncludeDeprecated: true",
      "maxAttempts: 1"
    ]),
    "fresh-primary-credential-sealer": Object.freeze([
      "buildFreshPrimaryCredentialSealApproval",
      "sealFreshPrimaryCredentialCustody",
      "FRESH_CREDENTIAL_VERSION_UNKNOWN_DO_NOT_CHANGE_TOKEN"
    ]),
    "fresh-primary-provider-controller": Object.freeze([
      "FreshPrimaryProviderController",
      "runFreshPrimaryProviderController",
      "FRESH_PRIMARY_PROVIDER_UNKNOWN_DO_NOT_RETRY"
    ]),
    "fresh-recovery-publication-execution": Object.freeze([
      "createFreshRecoveryPublicationExecution",
      "executeFreshPublicationProviderAction",
      "databaseNow",
      "managedMcpLogicalRequest",
      "minimum_residual_ms",
      "sourceAuthorityWindow"
    ]),
    "fresh-recovery-source-execution": Object.freeze([
      "produceFreshRecoverySource",
      "freshRecoverySourceIdentity",
      "authorityEvidenceBindingSha256",
      "proveFreshAdmissibleVectorSnapshot",
      "Promise.allSettled",
      "FROM tp_api.g1_spend_authority_v1(",
      "commitValidatorSequenceMatchedDirectDvi",
      "outboxCount: finalSnapshot.outbox.length"
    ]),
    "fresh-cluster-provider-launcher": Object.freeze([
      "FRESH_CLUSTER_LAUNCH_IMPORT_GRAPH_REJECTED",
      "env.GITHUB_SHA === expectedCallerCommit",
      "controllerImportGraphSha256: graph.graphSha256",
      "--approval-sha256",
      "tideproof.gate2-build.v9",
      "export async function main"
    ]),
    "fresh-bootstrap-collector-binding": Object.freeze([
      "validateFreshBootstrapCollectorBinding",
      "prooftoact-bootstrap-",
      "prooftoact-b0-"
    ]),
    "fresh-primary-source-lock": Object.freeze([
      "prooftoact-fresh-primary-source-lock-v1",
      "caller_sha != expected_caller_sha",
      "job_workflow_ref",
      "job_workflow_sha",
      "FRESH_PRIMARY_SOURCE_LOCK_REJECTED"
    ]),
    "fresh-recovery-publisher-key": Object.freeze([
      "validateFreshRecoveryPublisherSecret",
      "generateFreshRecoveryPublisherSecret",
      "FRESH_RECOVERY_PUBLISHER_SECRET_REJECTED"
    ]),
    "private-recovery-query-binding": Object.freeze([
      "validatePrivateRecoveryQueryBinding",
      "PRIVATE_RECOVERY_QUERY_BINDING_REJECTED"
    ]),
    "fresh-primary-bootstrap-role-plan": Object.freeze([
      "prepareFreshPrimaryBootstrapRole",
      "READY_FOR_EXACT_CREATE_ONLY_APPLY",
      "passRoleExplicitlyAbsent: true",
      "0ecab5c430720c7ec030dbd49e48abab3b9554cf2820368f17a3a8f89c13d08b"
    ]),
    "fresh-primary-credential-custody-plan": Object.freeze([
      "prepareFreshPrimaryCredentialCustody",
      "initialVersionContract",
      "valueActionsExplicitlyAbsent"
    ]),
    "release-deployment-plan": Object.freeze([
      "validateReleaseDeploymentRoleTemplate",
      "ReadOwnCallerIdentity",
      "sts:GetCallerIdentity"
    ]),
    "fresh-cluster-provider-runner": Object.freeze([
      "runFreshClusterProvider",
      "callerWorkflowSha: parsed[\"--caller-workflow-sha\"]",
      "sha256(canonicalBytes(approval)) === authority.approvalSha256",
      "approval.controllerImportGraphSha256",
      "approval.callerWorkflowSha === authority.callerWorkflowSha",
      "authority?.humanAuthorizationSignerSha256",
      "--human-authorization-signer-sha256",
      "--receipt-output",
      "FRESH_CLUSTER_PROVIDER_HOLD_PROVIDER_KEYS_REVOCATION_PENDING"
    ]),
    "fresh-primary-credential-sealer-runner": Object.freeze([
      "runFreshPrimaryCredentialSealer",
      "buffer.fill(0)",
      "--secret-arns-file"
    ]),
    "fresh-primary-provider-runner": Object.freeze([
      "runFreshPrimaryProvider",
      "--caller-workflow-sha",
      "callerWorkflowSha: parsed[\"--caller-workflow-sha\"]",
      "--receipt-output"
    ]),
    "fresh-primary-bootstrap-tests": Object.freeze([
      "fresh source and triggering caller remain independently bound"
    ]),
    "fresh-cluster-provider-launcher-tests": Object.freeze([
      "launcher distinguishes immutable source from the triggering caller"
    ]),
    "fresh-cluster-provider-runner-tests": Object.freeze([
      "combined runner preserves distinct caller SHA for nested primary"
    ]),
    "fresh-primary-provider-runner-tests": Object.freeze([
      "runner accepts one exact coordinate set and rejects duplicates or ID aliasing"
    ]),
    "one-time-bootstrap-authority-tests": Object.freeze([
      "planner rejects 351-cent AWS authority, fabricated cost digests, and inflated item sums",
      "root AssumeRole rechecks the exact execution deadline immediately before dispatch"
    ]),
    "one-time-bootstrap-ceremony-launcher-tests": Object.freeze([
      "B0 launcher statically imports built-ins only and runner is launcher-only",
      "authorization must bind the exact runtime snapshot"
    ]),
    "one-time-bootstrap-ceremony-runner-tests": Object.freeze([
      "mutation classes journal before dispatch and converge ACK loss without redispatch",
      "A1 nested continuation resumes crashes"
    ]),
    "b0-a1-human-authorization-tests": Object.freeze([
      "external evidence finalizes a non-circular receipt",
      "authorizationSignatureBase64"
    ]),
    "b0-a1-imessage-authorization-tests": Object.freeze([
      "live verifier re-materializes the exact two events",
      "event materialization rejects key, identity, body, thread, time, and cardinality drift"
    ]),
    "b0-a1-human-authorization-fixture": Object.freeze([
      "buildSyntheticProofToActHumanAuthorization",
      "humanAuthorizationSignerPublicKeySha256"
    ]),
    "fresh-cluster-provider-key-revocation-tests": Object.freeze([
      "revocation proposal remains fail-closed before any provider access",
      "HOLD_REQUIRES_SEPARATE_SIGNED_ORGANIZATION_ADMIN_AUTHORIZATION"
    ])
  }),
  "actions-checkout-normalizer": Object.freeze([
    "const OFFICIAL_REPOSITORY_ID = \"1317716765\"",
    "const CI_WORKFLOW_NAME = \"CI\"",
    "const READ_ONLY_PREFLIGHT_WORKFLOW_NAME =",
    "AWS Read-Only OIDC Preflight",
    ".github/workflows/aws-oidc-read-only-preflight.yml",
    "GIT_OPTIONAL_LOCKS: \"0\"",
    "environment?.GITHUB_JOB === \"verify\"",
    "environment?.GITHUB_JOB === \"verify-pr-head-no-secrets\"",
    "EXPECTED_PULL_REQUEST_HEAD_REPOSITORY",
    "EXPECTED_PULL_REQUEST_HEAD_SHA",
    "checkoutMode: context.checkoutMode",
    "githubEventSha: context.githubEventSha",
    "normalizePullRequestHeadOrigin(context)",
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
    "Actions exact PR-head normalization binds head separately from merge SHA",
    "Actions fork PR-head normalization validates then removes fork origin",
    "CI head, merge, and read-only lanes normalize before strict verification",
    "scripts/normalize-actions-checkout.js"
  ]),
  "actions-ci-workflow": Object.freeze([
    "verify-pr-head-no-secrets:",
    "if: github.event_name == 'pull_request'",
    "repository: ${{ github.event.pull_request.head.repo.full_name }}",
    "ref: ${{ github.event.pull_request.head.sha }}",
    "EXPECTED_PULL_REQUEST_HEAD_REPOSITORY: ${{ github.event.pull_request.head.repo.full_name }}",
    "EXPECTED_PULL_REQUEST_HEAD_SHA: ${{ github.event.pull_request.head.sha }}",
    "lfs: false",
    "submodules: false",
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
    "directDviQueryForcedIndex: true",
    "directDviResultValidated: true",
    "commitValidatorSequenceMatchedDirectDvi: true",
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
    "dispatchPayloadFor",
    "AUTHORITY_DISPATCH_PAYLOAD_SHAPE",
    "AUTHORITY_DISPATCH_PAYLOAD_TEXT",
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
    "dispatch payload canonicalization accepts only the bounded domain schema",
    "dispatch payload canonicalization rejects ambiguous or unsafe values",
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
    "allowed-key insertion order",
    "rejects fields outside the domain schema",
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
    "dispatchPayloadFor(input.payload)",
    "Object.hasOwn(input, \"payload\")",
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
    "Invocation identity projected as committed replay identity",
    "Recovery publisher schema repair runbook",
    "`CONFIRMED_ABSENT` is a terminal HOLD",
    "no other administrator may alter users, roles, memberships, grants"
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
    "GATE2_BUILD_SCHEMA",
    "ISOLATED_EXACT_GIT_CHECKOUT_AND_BLOBS",
    "evidenceProviderRuntime",
    "liveDrillRuntime",
    "outputPrivacy",
    "AWS_READINESS_BUILD_VALIDATOR",
    "validateLiveDrillRuntime(",
    "validateBuildOutputPrivacy(",
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
    "AWS readiness rejects substituted runtime validators",
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
    "private recovery source snapshot binds identity while separating policy domains",
    "recovery source resolves through a private scalar snapshot and inert public boundary",
    "direct authority replay currentness requires the exact outbox payload",
    "g1_authority_receipt_current_v2",
    "new QueryReadyBarrier",
    "post-COMMIT ambiguity cannot enter a rollback branch",
    "proposal\\.payload = outbox\\.payload",
    "bootstrap fails closed on legacy DVI payload identities before installing functions",
    "DVI proposal payload identity uses one exact compact dispatch schema",
    "protected-effect SQL snapshots one exact authority before a value-only insert",
    "const retainedPostInsertClauses = Object.freeze([",
    "assert.doesNotMatch(insertClause, /\\bSELECT\\b/u)",
    "body.match(/v_database_now := clock_timestamp\\(\\);/gu)?.length",
    "Gate One repeat stability compares equal database timestamps by value",
    "Gate One proves resolver cursor closure inside one transaction",
    "assert.deepEqual(stableColumns, [...stableColumns].sort())",
    "const outputAssignments = Object.freeze([",
    "assert.equal(outputAssignments.length, 24)",
    "minimum_residual_ms := \\(v_snapshot->>'minimum_residual_ms'\\)::INT8; database_now := \\(v_snapshot->>'database_now'\\)::TIMESTAMPTZ; RETURN NEXT; RETURN; END$",
    "assert.doesNotMatch(wrapper, /\\bRETURN QUERY\\b/u)",
    "privateSnapshotGrant",
    "Cockroach schema closure preserves typed public surfaces and direct denials",
    "tp_provider_activate_role",
    "tp_provider_terminalize_role"
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
    "directPrincipalGrantPolicies",
    "policy?.allowAbsent === true",
    "policy?.databaseConnect === false",
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
    "FROM [SHOW DEFAULT PRIVILEGES]",
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
    "recovery publisher requires private-schema usage but rejects table DML",
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
  "deployment-config-digest": Object.freeze([
    "deploymentConfigDigestPure",
    "DEPLOYMENT_CONFIG_SHAPE_REJECTED",
    "functionConfigurationDigests",
    "functionRolePolicyDigests",
    "receiptPublicKeys",
    "crypto.createPublicKey",
    "canonicalJson(configuration)"
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
    "exact build validates every staged output before copying",
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
    "GATE2_BUILD_SCHEMA",
    "buildEvidenceProviderRuntime(",
    "evidenceProviderRuntime",
    "liveDrillRuntime",
    "verifyBuildOutputPrivacy(",
    "TIDEPROOF_EXACT_RUNTIME_NODE_SHA256",
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
    "assertCleanExactGitCheckout({",
    "validateStagedOutputInventory(",
    "EXACT_BUILD_STAGED_OUTPUT_INVENTORY"
  ]),
  "gate2-build-contract": Object.freeze([
    "GATE2_BUILD_CONTROL_INPUT_COUNT",
    "scripts/lib/pg-native-unavailable.cjs",
    "scripts/lib/verified-node-bundle-launcher.pl",
    "src/cloud/release-build-receipt-contract.js",
    "GATE2_BUILD_CONTROL_INPUT_COUNT_DRIFT"
  ]),
  "official-node-runtime-contract": Object.freeze([
    "nodejs.org-release-v22.23.1",
    "2e3f1286a7eb3736346ed1803e458a0ff909e2b2d5bc746144dcb76970e9b99d",
    "93956de2e59480474a7b46571da1651180b1a050cdf32641ebec4ce6e478e068",
    "OFFICIAL_NODE_RUNTIME_METADATA_REJECTED"
  ]),
  "official-node-runtime-loader": Object.freeze([
    "fs.constants.O_NOFOLLOW",
    "before.nlink === 1",
    "digest === expected.sha256",
    "OFFICIAL_NODE_RUNTIME_REJECTED"
  ]),
  "official-node-runtime-tests": Object.freeze([
    "official runtime node reader binds one stable regular executable",
    "official runtime node reader rejects an unpinned platform or digest",
    "node-hardlink"
  ]),
  "pg-native-unavailable": Object.freeze([
    "optional pg-native binding is unavailable",
    "MODULE_NOT_FOUND"
  ]),
  "release-build-receipt-contract": Object.freeze([
    "tideproof.gate2-build.v9",
    "GATE2_BUILD_CONTROL_INPUT_COUNT = 83",
    "GATE2_BUILD_OUTPUT_COUNT = 24"
  ]),
  "verified-node-bundle-launcher": Object.freeze([
    "tideproof.integrated-live-drill-runtime-manifest.v1",
    "O_NOFOLLOW",
    "assert_root_owned_immutable_directory_chain",
    "LD_.*|DYLD_.*|GLIBC_TUNABLES|GCONV_PATH",
    "node-[0-9a-f]{64}",
    "exec {",
    "--disable-proto=throw"
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
  "atomic-create-only-file": Object.freeze([
    "readExactOwnedFile",
    "publishOrReadExactOwnedFile",
    "publishOrReadExactOwnedFile",
    "PUBLICATION_SETTLE_ATTEMPTS",
    "PUBLICATION_ABSENT_CAUSE",
    "PUBLICATION_SETTLE_CAUSE",
    "hasPublishedTemporaryLink",
    "unlinkTemporaryIfPresent",
    "fs.constants.O_NOFOLLOW"
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
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_MODE",
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_SYSTEMD_BOUNDARY",
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_SYSTEMD_INSTANCE",
    "tideproof.integrated-live-drill-systemd-orchestrator-input.v1",
    "systemdIntegratedLiveDrillEnvironment",
    "readSystemdCredential",
    "PROVIDER_CAPABILITY_ENVIRONMENT",
    "sanitizedIntegratedLiveDrillProviderOrchestrationHold",
    "persistIntegratedLiveDrillProviderDispatchRequest",
    "buildProviderDispatchControlBinding",
    "INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION_ENVIRONMENT",
    "startIntegratedLiveDrillJournal",
    "appendIntegratedLiveDrillJournal",
    "consumeIntegratedLiveDrillRunAuthorization",
    "reserveIntegratedLiveDrillSpend",
    "integratedLiveDrillChildAuthorizationContext",
    "integratedLiveDrillChildCommittedTrustRoot",
    "gate1-admissible-vector.js",
    "gate2-authority-race.js",
    "gate1-integrated-live-drill-provider-supervisor.js",
    "providerApiCredentialPresent: false",
    "INTEGRATED_LIVE_DRILL_SYSTEMD_BOUNDARY_REQUIRED",
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
    "authorizeOrVerifyIntegratedLiveDrillChildLaunch",
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
  "integrated-live-drill-process-boundary-verifier": Object.freeze([
    "tideproof.highwater-drill-process-boundary-verification.v5",
    "verifyIntegratedLiveDrillProcessBoundaries",
    "FINALIZER_FORBIDDEN_PATH_PATTERNS",
    "RECONCILER_FORBIDDEN_PATH_PATTERNS",
    "WORKER_FORBIDDEN_PATH_PATTERNS",
    "validateSupervisorSource",
    "providerFinalizerEnvironmentRequired: false",
    "providerWorkerEnvironmentRequired: false",
    "name: \"provider-operation\"",
    "name: \"provider-activation\"",
    "name: \"provider-exchange\"",
    "name: \"provider-terminalizer\"",
    "name: \"reconciler\"",
    "INTEGRATED_LIVE_DRILL_PROCESS_BOUNDARY_BUILTIN_REJECTED",
    "INTEGRATED_LIVE_DRILL_PROCESS_BOUNDARY_PACKAGE_REJECTED",
    "managed-mcp-client\\.js$",
    "recovery-broker\\.js$"
  ]),
  "integrated-live-drill-process-boundary-tests": Object.freeze([
    "provider broker, worker, reconciler, and finalizer preserve authority boundaries",
    "receipt.reconciler.externalPackages, [\"pg\"]",
    "receipt.supervisor.legacyRecoveryEntryPointImported, false",
    "receipt.supervisor.managedMcpClientConstructed, false",
    "node:child_process",
    "src/cloud/integrated-live-drill-provider-evidence.js",
    "src/cloud/integrated-live-drill-provider-recovery.js",
    "src/cloud/brokered-provider-operation-client.js",
    "src/cloud/managed-mcp-client.js",
    "src/cloud/recovery-broker.js"
  ]),
  "integrated-live-drill-runtime-contract": Object.freeze([
    "tideproof.integrated-live-drill-runtime-manifest.v1",
    "INTEGRATED_LIVE_DRILL_RUNTIME_STAGE_REJECTED",
    "INTEGRATED_LIVE_DRILL_RUNTIME_MANIFEST_REJECTED",
    "INTEGRATED_LIVE_DRILL_RUNTIME_REJECTED",
    "assertRootOwnedStagePath"
  ]),
  "integrated-live-drill-runtime-spawn": Object.freeze([
    "PRE_EXECUTION_INJECTION_ENVIRONMENT",
    "assertIntegratedLiveDrillRuntime",
    "spawnSync",
    "/usr/bin/perl"
  ]),
  "integrated-live-drill-runtime-tests": Object.freeze([
    "runtime manifest binds every content-addressed executable component",
    "reviewed runtime makes the optional native Postgres binding unavailable",
    "runtime stage rejects any mutable ancestor in its absolute path",
    "child launch removes every pre-execution injection surface"
  ]),
  "integrated-live-drill-runtime-authority-race-entry": Object.freeze([
    "../gate2-authority-race.js",
    "tideproof.aws-authority-race-error.v1"
  ]),
  "integrated-live-drill-runtime-dispatch-broker-entry": Object.freeze([
    "../gate1-integrated-live-drill-dispatch-broker.js",
    "INTEGRATED_LIVE_DRILL_DISPATCH_BROKER_UNKNOWN"
  ]),
  "integrated-live-drill-runtime-provider-activation-entry": Object.freeze([
    "../gate1-integrated-live-drill-provider-activation.js",
    "INTEGRATED_LIVE_DRILL_PROVIDER_ACTIVATION_UNKNOWN"
  ]),
  "integrated-live-drill-runtime-provider-exchange-entry": Object.freeze([
    "../gate1-integrated-live-drill-provider-exchange.js",
    "INTEGRATED_LIVE_DRILL_PROVIDER_EXCHANGE_UNKNOWN"
  ]),
  "integrated-live-drill-runtime-provider-operation-entry": Object.freeze([
    "../gate1-integrated-live-drill-provider-operation-broker.js",
    "INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_UNKNOWN"
  ]),
  "integrated-live-drill-runtime-provider-terminalizer-entry": Object.freeze([
    "../gate1-integrated-live-drill-provider-terminalizer.js",
    "INTEGRATED_LIVE_DRILL_PROVIDER_TERMINALIZATION_UNKNOWN"
  ]),
  "integrated-live-drill-runtime-dvi-entry": Object.freeze([
    "../gate1-admissible-vector.js",
    "safeAdmissibleVectorFailureCode"
  ]),
  "integrated-live-drill-runtime-finalizer-entry": Object.freeze([
    "../gate2-integrated-live-drill-provider-finalizer.js",
    "INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_UNKNOWN"
  ]),
  "integrated-live-drill-runtime-orchestrator-entry": Object.freeze([
    "../gate2-integrated-live-drill.js",
    "safeIntegratedLiveDrillFailureCode"
  ]),
  "integrated-live-drill-runtime-reconciler-entry": Object.freeze([
    "../gate1-integrated-live-drill-provider-reconciler.js",
    "main().catch((error)",
    "INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_UNKNOWN_DO_NOT_ACT"
  ]),
  "integrated-live-drill-runtime-recovery-entry": Object.freeze([
    "../gate1-recovery-broker.js",
    "noninteractive Managed MCP deterministic recovery broker"
  ]),
  "integrated-live-drill-runtime-supervisor-entry": Object.freeze([
    "../gate1-integrated-live-drill-provider-supervisor.js",
    "INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_UNKNOWN"
  ]),
  "integrated-live-drill-runtime-worker-entry": Object.freeze([
    "../gate1-integrated-live-drill-provider-worker.js",
    "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_UNKNOWN"
  ]),
  "integrated-live-drill-stress-runner": Object.freeze([
    "tideproof.integrated-live-drill-stress-receipt.v1",
    "two real broker processes publish one execution grant after one global begin",
    "test/integrated-live-drill-dispatch-broker.test.js",
    "INTEGRATED_LIVE_DRILL_STRESS_DIRTY_TREE",
    "observedTargetPassCount"
  ]),
  "integrated-live-drill-stress-tests": Object.freeze([
    "stress TAP parser accepts exactly one named pass",
    "stress receipt binds the claimed count to every iteration digest",
    "deliberately makes no provider, deployment, cross-host, hostile-host, or release claim"
  ]),
  "integrated-live-drill-provider-evidence": Object.freeze([
    "tideproof.highwater-drill-provider-recovery-handoff.v1",
    "normalizeIntegratedLiveDrillProviderContext",
    "integratedLiveDrillProviderContextAssertions",
    "FINALIZER_CONTEXT_FORBIDDEN_KEY_CLASSES",
    "exactContextRecord",
    "exactContextRecord(value, HANDOFF_KEYS)",
    "HANDOFF_KEYS.map",
    "HANDOFF_BOOLEAN_KEYS.every",
    "HANDOFF_COUNT_KEYS.every",
    "HANDOFF_STRING_KEYS.every",
    "Object.getOwnPropertyDescriptor(value, key).value",
    "contextKeyAssertions",
    "Object.getPrototypeOf(entry) === Array.prototype",
    "PROVIDER_PRE_CALL_INPUT_KEYS",
    "RECOGNIZABLE_CREDENTIAL_TEXT_PATTERNS",
    "credentialMaterialAbsent",
    "providerCapabilityAbsent",
    "rawProviderResultAbsent",
    "retryNamedKeyAbsent",
    "validateIntegratedLiveDrillProviderDispatchAuthorizationPure",
    "secureIntegratedLiveDrillPrivateRoot",
    "readIntegratedLiveDrillExactPrivateJson",
    "verifyIntegratedLiveDrillProviderEvidenceBundle",
    "INTEGRATED_LIVE_DRILL_PROVIDER_HANDOFF_BINDING_REJECTED",
    "INTEGRATED_LIVE_DRILL_PROVIDER_JOURNAL_BINDING_REJECTED",
    "canonicalJson(recomputed) === canonicalJson(reported)",
    "strictly validated locally recorded transport/session-close evidence",
    "does not establish provider origin",
    "path.dirname(filePath) === secure.rootPath",
    "fs.constants.O_NOFOLLOW",
    "providerBacked: false",
    "accepted: false",
    "finalReleaseReady: false"
  ]),
  "integrated-live-drill-provider-recovery": Object.freeze([
    "tideproof.highwater-drill-provider-dispatch-preparation.v1",
    "tideproof.highwater-drill-provider-expiry-burn.v1",
    "tideproof.highwater-drill-provider-recovery-pre-read-plan.v1",
    "tideproof.highwater-drill-provider-recovery-terminal-plan.v1",
    "AWAITING_AUTHORIZATION",
    "prepareIntegratedLiveDrillProviderRecoveryAuthorization",
    "dedicatedCredentialFieldAcceptedOrPersisted: false",
    "humanPrivateKeyRequired: false",
    "humanSignatureProducedOutsidePreparationApi: true",
    "preparationContextStrictlyAllowlisted: true",
    "normalizeIntegratedLiveDrillProviderContext",
    "MAX_PROVIDER_DISPATCH_AUTHORIZATION_MS",
    "publishOrReadExactOwnedFile",
    "fs.constants.O_NOFOLLOW",
    "after.nlink === 1",
    "named.nlink === 1",
    "named.size === after.size",
    "assertSameRoot(secure);",
    "validateIntegratedLiveDrillProviderDispatchAuthorization",
    "childAuthorizationIssuedAt",
    "providerAuthorityExpiryBurnBody",
    "PROCESS_STICKY_PROVIDER_AUTHORITY_BURNS",
    "clockRollbackCanReactivateAfterDurableBurn: false",
    "failedBurnPersistenceRequiresRunAbandonment: true",
    "processRestartSafetyAfterFailedPersistenceProven: false",
    "processStickyBurnPrecedesPersistenceAttempt: true",
    "retryPermitted: false",
    "maximumManagedMcpToolCallCount: 1",
    "requiredToolsCallCount: 1",
    "requiredSessionCloseCount: 1",
    "beforeProviderDispatch(action)",
    "closePreparedRecoveryProviderSessionAndReadEvidence",
    "validatePreparedRecoveryResume",
    "commitPreparedRecoveryCompletion",
    "resolvePreparedRecoveryAuditEvent",
    "reconcileDurableResult",
    "recoveryWorkerAuthorityIsCurrent",
    "INTEGRATED_LIVE_DRILL_PROVIDER_POST_EXPIRY_AUDIT_AUTHORIZATION_REQUIRED",
    "observedToolsCallCount",
    "observedSessionCloseCount",
    "providerBacked: false",
    "accepted: false",
    "finalReleaseReady: false",
    "Gate1/Gate2 PREPARE/HOLD/RESUME is source-wired and locally tested",
    "cross-host authority",
    "has not been deployed or executed against the live provider"
  ]),
  "integrated-live-drill-provider-recovery-tests": Object.freeze([
    "provider worker input and environment contain no provider or database capability",
    "provider finalizer import surface is provider and credential free",
    "a crash after the durable execution attempt resumes through the one-shot broker fence",
    "actual provider path cross-binds W1-W3, exact tools/call bytes, and private evidence",
    "W1 and W3 audit-commit crashes resume exact persisted event plans without duplicate MCP fetches",
    "provider path rejects semantic or separately signed dispatch substitution",
    "preparation defaults to a bounded lifetime and rejects extra or credential-bearing context",
    "invalid exact dispatch authorization causes zero provider fetches",
    "missing, substituted, or expired dispatch authority never fetches",
    "prepared resume rejects changed cluster, query, intent, ledger, or launch",
    "dispatch authorization is resampled immediately before selectQuery",
    "pre-W2 expiry is durably burned across clock rollback and repeated invocation",
    "signed child issuedAt gates dispatch before and at the exact boundary",
    "failed expiry-burn persistence remains process-sticky after clock rollback",
    "expiry inside audit resolver before actual dispatch stops with zero resolve or MCP action",
    "expiry during initialize response burns W2 without notification, tool call, or retry",
    "post-W2 expiry reconciles audit-only without reactivating provider access",
    "expiry after audit resolution preserves the exact event and completes audit-only",
    "a durable private result reconciles the W2 journal without redispatch",
    "post-expiry wrapper reconciles W2 and terminal audit without provider redispatch",
    "provider artifact read rejects chmod and hardlink mutation after descriptor read",
    "continuity journal read rejects chmod and hardlink mutation after descriptor read",
    "RECOVERY_PREPARED_RESUME_BINDING_MISMATCH",
    "RECOVERY_BUNDLE_EXPIRED",
    "dedicatedCredentialFieldAcceptedOrPersisted",
    "humanSignatureProducedOutsidePreparationApi",
    "transportMutations",
    "provider-worker-outside-link",
    "provider-finalizer-outside-link",
    "FOO_UNEXPECTED",
    "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_ENVIRONMENT_REJECTED",
    "substitutedRootInput",
    "tamperedDispatchContext",
    "rejectedContextMutations",
    "directApiMutations",
    "wrapperDirectApiMutations",
    "handoffDirectApiMutations",
    "nestedHandoffGetterCalls",
    "coercible digest object",
    "workerInputDirectApiMutations",
    "workerEnvironmentDirectApiMutations",
    "finalizerEnvironmentDirectApiMutations",
    "fakeFetchCalls",
    "fakeAuditFactoryCalls",
    "created no W4, W5, or component artifact",
    "nested array prototype",
    "nested array getter",
    "created no finalization artifact",
    "normalizedFinalizationInput",
    "contextExactSchemaValidated",
    "auditResolveAttempts",
    "AWAITING_AUTHORIZATION"
  ]),
  "integrated-live-drill-dispatch-broker": Object.freeze([
    "tideproof.integrated-live-drill-execution-grant.v1",
    "claimWithBoundedPreEffectRetry",
    "INTEGRATED_LIVE_DRILL_DISPATCH_BEGIN_AMBIGUOUS",
    "provider-reconciliation-input.json",
    "providerCredentialPresent: false"
  ]),
  "integrated-live-drill-dispatch-broker-runner": Object.freeze([
    "Object.hasOwn(process.env, \"MCP_API_KEY\")",
    "ProviderDispatchClaimControl",
    "ProviderDispatchBeginControl",
    "readSystemdCredential"
  ]),
  "integrated-live-drill-dispatch-broker-tests": Object.freeze([
    "two real broker processes publish one execution grant after one global begin",
    "claim retries surfaced 40001 before effect, but begin ambiguity is never retried",
    "provider-reconciliation-input.json"
  ]),
  "integrated-live-drill-execution-fence-tests": Object.freeze([
    "atomic publication converges after a hard crash at every fault phase",
    "after-directory-fsync",
    "PUBLICATION_FAULT_PHASE",
    "created: !finalExistsAtCrash.has(phase)",
    "real worker contenders have one create-only execution-attempt winner",
    "created.filter(Boolean).length, 1",
    "published temporary-link cleanup tolerates an exact concurrent unlink",
    "simulated concurrent unlink",
    "exact read settles only a winner linked after cleanup observed absence",
    "simulated pre-publication absence",
    "rootAssertions, 4",
    "exact read settles a two-link descriptor after peer cleanup",
    "peerCleanupSimulated",
    "published temporary-link cleanup rejects every non-ENOENT failure",
    "simulated cleanup I/O failure",
    "exact published-file read does not retry transient I/O failure",
    "simulated exact-read I/O failure",
    "post-open final disappearance is fatal rather than initial absence",
    "simulated post-open disappearance",
    "conflicting two-link file never enters publication settle retry",
    "simulated conflict cleanup absence",
    "exact owned-file primitive rejects an empty expected file",
    "exact read rejects a new matching hardlink after one-link open"
  ]),
  "integrated-live-drill-atomic-publication-crash-fixture": Object.freeze([
    "publishOrReadExactOwnedFile",
    "ATOMIC_PUBLICATION_FIXTURE_PATH_REJECTED",
    "atomic-publication-crash-matrix-v1",
    "PUBLICATION_FAULT_PHASE",
    "if (observed === phase) process.exit(73)",
    "JSON.stringify({ created: result.created })"
  ]),
  "integrated-live-drill-provider-operation-broker": Object.freeze([
    "tideproof.provider-operation-broker-transcript.v1",
    "INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_ALREADY_REDEEMED",
    "CREDENTIAL_REDEEMED",
    "persistTranscript",
    "activateExchange"
  ]),
  "integrated-live-drill-provider-operation-client": Object.freeze([
    "tideproof.provider-operation-broker-request.v1",
    "node:net",
    "async selectQuery",
    "async markUnknown"
  ]),
  "integrated-live-drill-provider-operation-runner": Object.freeze([
    "readSystemdCredential",
    "ProviderDispatchRedeemControl",
    "ProviderDispatchFinalizeControl",
    "name: \"execution-capability\""
  ]),
  "integrated-live-drill-provider-operation-tests": Object.freeze([
    "READY before activation ACK blocks and then exactly one result resolves",
    "result timeout removes pending state and refuses every late result",
    "already redeemed duplicate never terminalizes beneath an activation receipt",
    "PROCEED delayed past activation age creates no fence and makes no provider call",
    "exchange durably publishes one result and create-only fence blocks restart",
    "assert.equal(unknowns, 0)",
    "assert.equal(counter.calls, 0)",
    "assert.equal(counter.calls, calls)"
  ]),
  "integrated-live-drill-provider-activation": Object.freeze([
    "tideproof.provider-activation-request.v1",
    "tideproof.provider-activation-receipt.v1",
    "tideproof.provider-exchange-ready.v1",
    "tideproof.provider-exchange-result.v1",
    "runIntegratedLiveDrillProviderActivation"
  ]),
  "integrated-live-drill-provider-activation-runner": Object.freeze([
    "expectedComponent: \"provider-activation\"",
    "ProviderDispatchActivateControl",
    "name: \"provider-activate-database-url\"",
    "provider-exchange-input.json"
  ]),
  "integrated-live-drill-provider-exchange": Object.freeze([
    "PROVIDER_ACTIVATION_MAX_AGE_MILLISECONDS",
    "PROCEED_ONCE",
    "tideproof.provider-exchange-consumption-fence.v1",
    "publishOrReadExactOwnedFile",
    "RESULT_NAME"
  ]),
  "integrated-live-drill-provider-exchange-runner": Object.freeze([
    "expectedComponent: \"provider-exchange\"",
    "name: \"mcp-api-key\"",
    "provider-exchange-input",
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_CALLBACK_SOCKET"
  ]),
  "integrated-live-drill-provider-terminalization": Object.freeze([
    "tideproof.highwater-drill-provider-terminalization.v1",
    "terminalizeIntegratedLiveDrillProviderDispatch",
    "TERMINAL_EXPIRED",
    "TERMINAL_UNKNOWN_DO_NOT_ACT"
  ]),
  "integrated-live-drill-provider-terminalizer-runner": Object.freeze([
    "expectedComponent: \"provider-terminalizer\"",
    "ProviderDispatchTerminalizeControl",
    "name: \"provider-terminalize-database-url\""
  ]),
  "integrated-live-drill-provider-activation-terminalization-tests": Object.freeze([
    "activation authorizes credential delivery only for one fresh database grant",
    "effect-then-ACK-loss and conflicting activation replay can never deliver",
    "database time exactly at expiry cannot authorize credential delivery",
    "terminalization is exact-idempotent for immutable terminal states",
    "terminalizer retries transient database failure but rejects identity and SQL denials",
    "activation and terminalization transitive import closures exclude provider and raw evidence code"
  ]),
  "integrated-live-drill-provider-finalization": Object.freeze([
    "tideproof.highwater-drill-provider-component-receipt.v2",
    "tideproof.highwater-drill-provider-finalization.v2",
    "tideproof.highwater-drill-provider-finalization-input.v2",
    "DURABLE_SANITIZED_COMPONENT_RECEIPT",
    "LOCAL_FAKE_PRODUCTION_WIRING_VALIDATED",
    "normalizeIntegratedLiveDrillProviderContext",
    "validateIntegratedLiveDrillProviderFinalizationInput",
    "validateIntegratedLiveDrillProviderFinalizationReceipt",
    "INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_CLAIM_BOUNDARY",
    "contextCredentialMaterialAbsent",
    "contextExactSchemaValidated",
    "contextProviderCapabilityAbsent",
    "contextRawProviderResultAbsent",
    "contextRetryNamedKeyAbsent",
    "credentialOptionAccepted:",
    "providerCapabilityAccepted:",
    "rawProviderResultAccepted:",
    "retryNamedKeyAccepted:",
    "!contextAssertions.credentialMaterialAbsent",
    "!contextAssertions.providerCapabilityAbsent",
    "!contextAssertions.rawProviderResultAbsent",
    "!contextAssertions.retryNamedKeyAbsent",
    "runIntegratedLiveDrillRecoveryContinuityW4",
    "runIntegratedLiveDrillRecoveryContinuityW5",
    "verifyIntegratedLiveDrillProviderEvidenceBundle",
    "requireCompleteJournal: false",
    "assertIntegratedLiveDrillProviderFinalizerEnvironment",
    "normalizeFinalizerEnvironment",
    "Reflect.ownKeys(environment)",
    "environment === process.env",
    "FINALIZER_ENVIRONMENT_NAMES",
    "publishOrReadExactOwnedFile",
    "fs.constants.O_NOFOLLOW",
    "fs.fsyncSync",
    "providerBacked: false",
    "accepted: false",
    "finalReleaseReady: false"
  ]),
  "integrated-live-drill-provider-finalizer-runner": Object.freeze([
    "assertIntegratedLiveDrillProviderFinalizerEnvironment",
    "readIntegratedLiveDrillProviderFinalizationInput",
    "finalizeIntegratedLiveDrillProviderRecovery",
    "INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_INPUT_PATH_ENVIRONMENT",
    "INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_ROOT_ENVIRONMENT",
    "INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_FORBIDDEN_ROOT_ENVIRONMENT"
  ]),
  "integrated-live-drill-provider-orchestration": Object.freeze([
    "tideproof.highwater-drill-provider-orchestration-preparation.v2",
    "tideproof.highwater-drill-provider-orchestration-completion.v1",
    "tideproof.highwater-drill-provider-orchestration-decision.v4",
    "HOLD_AWAITING_EXACT_PROVIDER_DISPATCH_AUTHORIZATION",
    "RECOVERY_PREPARED_AWAITING_EXACT_DISPATCH_AUTHORIZATION",
    "UNKNOWN_DO_NOT_ACT",
    "EXPIRED_FRESH_AUDIT_AUTHORITY_REQUIRED",
    "persistIntegratedLiveDrillProviderOrchestrationPreparation",
    "readIntegratedLiveDrillProviderOrchestrationPreparation",
    "persistIntegratedLiveDrillProviderOrchestrationStop",
    "readIntegratedLiveDrillProviderOrchestrationDecisionIfPresent",
    "STOPPED_BEFORE_GLOBAL_EXECUTION",
    "retryPermitted: false",
    "providerBacked: false",
    "accepted: false",
    "finalReleaseReady: false"
  ]),
  "integrated-live-drill-provider-orchestration-tests": Object.freeze([
    "provider orchestration HOLD binds full legacy DVI/race invariants and exact signing payload",
    "checkpoint sidecar binds canonical root and checkpoint file identity across resume",
    "pre-execution UNKNOWN and expired stops are durable and permanently nonretryable",
    "supervisor RESUME is disabled and accessor-bearing options are never read",
    "orchestration boundaries reject accessors, exotic keys, prototypes, and coercible scalars before hashing"
  ]),
  "integrated-live-drill-provider-reconciliation": Object.freeze([
    "tideproof.highwater-drill-provider-reconciliation.v3",
    "providerApiCredentialPresent: false",
    "PRIMARY_PROVIDER_RECONCILE_DATABASE_URL",
    "!Object.hasOwn(environment, \"MCP_API_KEY\")",
    "ProviderDispatchResolver",
    "reconcileIntegratedLiveDrillProviderDispatchControl",
    "return await resolver.resolve(binding)",
    "Object.values(PROVIDER_DISPATCH_CONTROL_STATES).includes(value.state)",
    "AUDIT_ONLY_PROVIDER_RECONCILIATION_NOT_RELEASED"
  ]),
  "integrated-live-drill-provider-reconciliation-runner": Object.freeze([
    "expectedComponent: \"reconciler\"",
    "runIntegratedLiveDrillProviderReconciliation",
    "name: \"provider-reconciliation-input\"",
    "name: \"provider-reconcile-database-url\""
  ]),
  "integrated-live-drill-provider-reconciliation-tests": Object.freeze([
    "reconciliation environment carries only resolve authority",
    "sanitized reconciliation input is canonical, digest-bound, and secret-free",
    "reconciliation receipt accepts every canonical resolver state",
    "audit-only reconciliation exposes no mutation surface",
    "run reconciliation reports only database-observed state and digests"
  ]),
  "integrated-live-drill-provider-supervisor-runner": Object.freeze([
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_MODE",
    "prepareIntegratedLiveDrillProviderSupervisor",
    "resumeIntegratedLiveDrillProviderSupervisor",
    "INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_RESUME_DISABLED",
    "persistIntegratedLiveDrillProviderSupervisorPreparation",
    "assertRecoveryPublisherTrustRootWriteDenied",
    "assertRecoveryRunnerBaseTableReadsDenied",
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_EXPECTED_PREPARATION_CONTEXT_SHA256",
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_EXPECTED_PREPARATION_RECEIPT_SHA256",
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_EXPECTED_SIGNING_PAYLOAD_SHA256",
    "mode === \"PREPARE\"",
    "RECOVERY_PREPARED_AWAITING_EXACT_DISPATCH_AUTHORIZATION",
    "providerBacked: false",
    "accepted: false",
    "finalReleaseReady: false"
  ]),
  "integrated-live-drill-provider-worker": Object.freeze([
    "tideproof.highwater-drill-provider-worker-input.v3",
    "integratedLiveDrillProviderWorkerEnvironment",
    "assertIntegratedLiveDrillProviderWorkerEnvironment",
    "normalizeIntegratedLiveDrillProviderContext",
    "normalizedWorkerEnvironment",
    "Reflect.ownKeys(environment)",
    "environment === process.env",
    "WORKER_ENVIRONMENT_NAMES",
    "MCP_API_KEY",
    "PRIMARY_AUDIT_DATABASE_URL",
    "recoveryAuditTargetIdentity",
    "executionGrant",
    "BrokeredProviderOperationClient",
    "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_AUDIT_TARGET_REJECTED",
    "DeterministicRecoveryBroker",
    "RecoveryAuditSink",
    "runIntegratedLiveDrillProviderRecovery",
    "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_PRINCIPAL_REJECTED",
    "fetchImpl === null"
  ]),
  "integrated-live-drill-provider-worker-runner": Object.freeze([
    "assertIntegratedLiveDrillProviderWorkerEnvironment",
    "name: \"provider-worker-input\"",
    "runIntegratedLiveDrillProviderWorker",
    "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_ROOT_ENVIRONMENT",
    "CREDENTIALS_DIRECTORY"
  ]),
  "integrated-live-drill-root-stage-installer": Object.freeze([
    "tideproof.integrated-live-drill-root-stage.v5",
    "fs.constants.O_NOFOLLOW",
    "fs.constants.O_EXCL",
    "fileSystem.linkSync(temporary, filePath)",
    "unlinkPublishedTemporaryIfPresent",
    "systemdSysusersExecuted: true",
    "daemon-reload"
  ]),
  "integrated-live-drill-root-stage-verifier": Object.freeze([
    "tideproof.integrated-live-drill-root-stage.v5",
    "observedAncestors",
    "validateAccountRecords",
    "observedStateDirectories",
    "receipt.unitFiles.length === expectedUnits.length",
    "receipt.verifierFiles.length === expectedVerifier.length"
  ]),
  "integrated-live-drill-root-stage-tests": Object.freeze([
    "root installer publishes one exact stage and independent non-root verification rejects drift",
    "concurrent-cleanup.json",
    "cleanup-io-error.json",
    "receipt.unitFiles.length, 14",
    "assert.notEqual(wrongMode.status, 0)"
  ]),
  "integrated-live-drill-systemd-boundary-verifier": Object.freeze([
    "EXACT_UNSET_CAPABILITIES",
    "LoadCredential=mcp-api-key",
    "LoadCredential=provider-reconcile-database-url",
    "units: Object.freeze",
    "provider-activation@.service",
    "provider-exchange@.service",
    "provider-terminalizer@.timer"
  ]),
  "integrated-live-drill-systemd-stage-verify-unit": Object.freeze([
    "User=prooftoact",
    "LoadCredential=accepted-build-receipt-sha256",
    "RemainAfterExit=yes"
  ]),
  "integrated-live-drill-systemd-controller-unit": Object.freeze([
    "Requires=prooftoact-integrated-live-drill-stage-verify@%i.service",
    "LoadCredential=orchestrator-input",
    "SuccessExitStatus=3"
  ]),
  "integrated-live-drill-systemd-resume-unit": Object.freeze([
    "Requires=prooftoact-integrated-live-drill@%i.service",
    "LoadCredential=orchestrator-input",
    "SuccessExitStatus=3"
  ]),
  "integrated-live-drill-systemd-dispatch-broker-unit": Object.freeze([
    "User=prooftoact-broker",
    "LoadCredential=provider-claim-database-url",
    "LoadCredential=provider-begin-database-url"
  ]),
  "integrated-live-drill-systemd-executor-unit": Object.freeze([
    "LoadCredential=operation-nonce",
    "LoadCredential=provider-operation-socket",
    "RestrictAddressFamilies=AF_UNIX"
  ]),
  "integrated-live-drill-systemd-provider-operation-unit": Object.freeze([
    "User=prooftoact-operation",
    "LoadCredential=provider-redeem-database-url"
  ]),
  "integrated-live-drill-systemd-provider-operation-socket": Object.freeze([
    "ListenStream=/run/prooftoact/%i/provider-operation.sock",
    "SocketMode=0600"
  ]),
  "integrated-live-drill-systemd-provider-activation-unit": Object.freeze([
    "User=prooftoact-activate",
    "LoadCredential=provider-activate-database-url",
    "provider-activation"
  ]),
  "integrated-live-drill-systemd-provider-activation-socket": Object.freeze([
    "ListenStream=/run/prooftoact/%i/provider-activation.sock",
    "SocketUser=prooftoact-operation",
    "SocketMode=0600"
  ]),
  "integrated-live-drill-systemd-provider-callback-socket": Object.freeze([
    "ListenStream=/run/prooftoact/%i/provider-callback.sock",
    "SocketUser=prooftoact-provider",
    "SocketMode=0600"
  ]),
  "integrated-live-drill-systemd-provider-exchange-unit": Object.freeze([
    "User=prooftoact-provider",
    "LoadCredential=mcp-api-key",
    "provider-exchange"
  ]),
  "integrated-live-drill-systemd-provider-terminalizer-unit": Object.freeze([
    "User=prooftoact-terminalize",
    "LoadCredential=provider-terminalize-database-url",
    "provider-terminalizer"
  ]),
  "integrated-live-drill-systemd-provider-terminalizer-timer": Object.freeze([
    "OnUnitInactiveSec=60s",
    "AccuracySec=1s",
    "Persistent=no"
  ]),
  "integrated-live-drill-sysusers": Object.freeze([
    "u prooftoact-operation",
    "u prooftoact-activate",
    "u prooftoact-provider",
    "u prooftoact-terminalize",
    "u prooftoact-reconcile"
  ]),
  "integrated-live-drill-systemd-reconcile-unit": Object.freeze([
    "User=prooftoact-reconcile",
    "LoadCredential=provider-reconciliation-input",
    "LoadCredential=provider-reconcile-database-url"
  ]),
  "integrated-live-drill-systemd-credential-reader": Object.freeze([
    "fs.constants.O_NOFOLLOW",
    "before.nlink === 1",
    "readSystemdCredentialText"
  ]),
  "integrated-live-drill-recovery-continuity": Object.freeze([
    "tideproof.highwater-drill-recovery-continuity-journal-entry.v2",
    "tideproof.highwater-drill-recovery-continuity-journal-receipt.v2",
    "tideproof.highwater-drill-recovery-continuity-pre-call-intent.v1",
    "LOCAL_SAME_HOST_SCAFFOLD_COMPLETED_NO_RETRY",
    "UNKNOWN_DO_NOT_ACT",
    "fs.constants.O_EXCL",
    "after.nlink === 1",
    "named.nlink === 1",
    "named.size === after.size",
    "randomBytes(32)",
    "attemptOwnershipTokenSha256",
    "acceptExistingArtifact",
    "DURABLE_BEFORE_BOUND_CALL",
    "topLevelProviderClientOptionReceived: false",
    "providerClientInvoked: false",
    "exactMcpCallClaimCount = claimEntries.length",
    "exactMcpDispatchMarkerCount = dispatchEntries.length",
    "Local same-host scaffold only; actual provider-bound W1-W5 continuity remains unproven.",
    "records truthful post-dispatch evidence after authority expiry",
    "provider-bound persistence and crash reconciliation on the live Managed MCP path remain unproven",
    "reconcileDurableResult",
    "reconciledFromDurableResult: true",
    "resumed: true",
    "recoveryAppendReceiptSha256",
    "recoveryReplayReceiptSha256",
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
    "audit target identity binds endpoint and TLS policy without credentials",
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
    "consumeIntegratedLiveDrillChildLaunch",
    "recoveryAppendReceipt",
    "recoveryReplayReceipt"
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
    "systemd orchestrator input admits exact provider-free PREPARE and RESUME payloads",
    "systemd orchestrator input rejects extra, missing, ambient, and substituted capability data",
    "PREPARE executes only DVI, authority race, and provider-free preparation",
    "direct non-systemd launch fails before any component or provider capability use",
    "provider orchestration mode/environment accessors fail before execution",
    "Gate2 refuses mutable source-path child execution",
    "orchestrator rejects authorization expiry between provider components",
    "integrated drill errors disclose only bounded failure codes",
    "Object.hasOwn(prepared, name), false",
    "INTEGRATED_LIVE_DRILL_SYSTEMD_BOUNDARY_REQUIRED",
    "an admitted-but-incomplete CLI result is a nonzero checkpoint"
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
    "dispatchPayloadFor(logicalAction.payload)",
    "normalizedDviAuthorizationFor({",
    "logicalAuthorityKeyFor({",
    "authorizationBindingFor({",
    "DVI_PROPOSAL_DATABASE_IDENTITY_MISMATCH",
    "DVI_PROPOSAL_DATABASE_BINDING_MISMATCH"
  ]),
  "dvi-proposal-authorization-tests": Object.freeze([
    "least-privilege runtime accepts only a database-derived proposal identity",
    "dispatch payload violations fail before any database query",
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
    "signal: this.#signal(30_000)",
    "RECOVERY_MCP_RESPONSE_TOO_LARGE",
    "TextDecoder(\"utf-8\", { fatal: true })",
    "RECOVERY_MCP_RESPONSE_ID_MISMATCH",
    "RECOVERY_MCP_RESPONSE_JSON_DUPLICATE_MEMBER",
    "parseStrictJson(text, {",
    "validateJsonRpcResponse(message, id)",
    "Object.hasOwn(message, \"error\")",
    "message.id !== expectedId",
    "normalizedMcpContentType",
    "RECOVERY_MCP_RESPONSE_SSE_AMBIGUOUS",
    "recoveryQueryBindingsFor(query)",
    "semanticRequestEvidence()",
    "beforeExternalAction",
    "tideproof.managed-mcp-semantic-request-evidence.v1"
  ]),
  "managed-mcp-client-tests": Object.freeze([
    "strict JSON parsing rejects decoded-equivalent and nested duplicate members",
    "Managed MCP response envelopes are exact across JSON and SSE",
    "Managed MCP rejects duplicate decoded members across JSON and SSE",
    "Managed MCP validates every SSE payload before correlation",
    "Managed MCP accepts exact success and error envelopes across JSON and SSE",
    "Managed MCP client rejects non-normalized or ambiguous content types",
    "Managed MCP SSE rejects malformed, duplicate, or uncorrelated response data",
    "RECOVERY_MCP_RESPONSE_SSE_AMBIGUOUS"
  ]),
  "judge-proof-lambda": Object.freeze([
    "GetSecretValueCommand",
    "VersionStage: \"AWSCURRENT\"",
    "AWS_LAMBDA_FUNCTION_VERSION",
    "ignoreConfiguredEndpointUrls: true",
    "maxAttempts: 1"
  ]),
  "judge-proof-mcp-tests": Object.freeze([
    "one no-argument fixed proof operation",
    "closes before rejecting an invalid row",
    "fails closed when session cleanup fails",
    "enforces one total deadline"
  ]),
  "judge-proof-query": Object.freeze([
    "FROM mcp_public.recovery_bundle_v2",
    "verifyRecoveryBundleSourceSignature",
    "HISTORICAL_SIGNED_RECOVERY_CONTEXT_ONLY",
    "AND bundle_digest =",
    "LIMIT 2"
  ]),
  "judge-proof-query-tests": Object.freeze([
    "one no-argument exact recovery-view read",
    "rejects any text substitution",
    "verifies the real pinned P-256 row",
    "rejects ambiguity, drift, and signature tampering"
  ]),
  "public-judge-proof-runtime": Object.freeze([
    "https://flash-bri.github.io",
    "cross-origin-resource-policy\": \"cross-origin",
    "status: JUDGE_PROOF_STATUS",
    "sessionClosed: true",
    "proof_unavailable"
  ]),
  "public-judge-proof-tests": Object.freeze([
    "accepts only exact parameter-free GET",
    "browser CORS permits only the exact GitHub Pages origin",
    "rejects body, query, route, and API substitution before secret read",
    "validates the exact secret and hides failures"
  ]),
  "managed-mcp-recovery-grant-repair": Object.freeze([
    "--preflight",
    "--verify",
    "--apply",
    "--disable",
    "createExclusiveManagedMcpJournal",
    "EXPECTED_MANAGED_MCP_PRE_REPAIR_POSTURE_SHA256",
    "MANAGED_MCP_RECOVERY_GRANT_CONFIRMATION",
    "MANAGED_MCP_RECOVERY_DISABLE_CONFIRMATION",
    "MANAGED_MCP_RECOVERY_TARGET_ALREADY_RESERVED",
    "TARGET_UNIQUE_RESERVED",
    "fs.openSync(target, \"wx\", 0o600)",
    "fs.fsyncSync",
    "uuidgen | tr '[:upper:]' '[:lower:]'"
  ]),
  "primary-security-bootstrap": Object.freeze([
    "REVOKE ALL ON DATABASE tideproof FROM public",
    "REVOKE CREATE ON SCHEMA public FROM public",
    "ALTER DEFAULT PRIVILEGES FOR ROLE",
    "SECURITY DEFINER",
    "PRIMARY_ROLE_GRANT_POLICIES",
    "lockInitialPublicCapability(client, bootstrapOwner)",
    "assertDviProposalPayloadCompatibility(client)",
    "DVI_PROPOSAL_PAYLOAD_CANONICALIZATION_INCOMPATIBLE",
    "clusterPreflightPostureDigest: clusterPreflight.postureDigest",
    "lockPublicRoutineDefaults(client, principals, schemas = [])",
    "ALTER DEFAULT PRIVILEGES ${scope} REVOKE EXECUTE ON FUNCTIONS FROM public",
    "allowMissingExpectedCapabilities: false",
    "session_user = 'tp_ingest_user'",
    "session_user <> 'tp_dispatch_user'",
    "session_user <> 'tp_recovery_audit_user'",
    "session_user <> 'tp_gate2_authorizer_user'",
    "session_user <> 'tp_provider_claim_user'",
    "session_user <> 'tp_provider_begin_user'",
    "session_user <> 'tp_provider_redeem_user'",
    "session_user <> 'tp_provider_finalize_user'",
    "session_user <> 'tp_provider_reconcile_user'",
    "DROP FUNCTION IF EXISTS tp_api.g1_transition_provider_dispatch_v1",
    "tp_api.g1_claim_provider_dispatch_v2",
    "tp_api.g1_begin_provider_dispatch_v2",
    "tp_api.g1_redeem_provider_dispatch_v2",
    "tp_api.g1_complete_provider_dispatch_v2",
    "tp_api.g1_mark_provider_dispatch_unknown_v2",
    "tp_api.g1_resolve_provider_dispatch_v2",
    "collectValidatedPosture(",
    "ALTER ROLE ${role} WITH NOLOGIN",
    "ALTER ROLE root WITH NOLOGIN",
    "FROM [SHOW USERS]",
    "EXACT_COMPLETE_SHOW_USERS_LOGIN_POSTURE",
    "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA tp_private, tp_ledger, tp_api FROM ${principal}",
    "GRANT USAGE ON SCHEMA ${schemaName} TO ${role}",
    "FROM tp_authorizer_role",
    "FROM tp_gate2_authorizer_role",
    "TO tp_gate2_authorizer_role",
    "p_agent_id NOT IN ('aws-authority-alpha', 'aws-authority-bravo')",
    "tp_api.g1_commit_dvi_selection_v1",
    "tp_api.g1_observe_vector_exclusion_v1",
    "tp_api.g1_resolve_verified_evidence_v1",
    "tp_api.g1_resolve_vector_set_v1",
    "tp_api.g1_resolve_recovery_audit_event_v1",
    "tp_private.g1_resolve_recovery_source_snapshot_v1",
    "tp_api.g1_resolve_recovery_source_receipt_v2",
    "tp_api.g1_resolve_recovery_source_receipt_v3",
    "tp_recovery_source_role: ALL_RUNTIME_SCHEMAS,",
    "tp_provider_activate_role: Object.freeze([\"tp_api\", \"tp_ledger\"])",
    "tp_provider_terminalize_role: Object.freeze([\"tp_api\", \"tp_ledger\"])",
    "tp_audit_role: Object.freeze([\"tp_api\", \"tp_ledger\"])",
    "proposal.policy_version = 'g1-admissibility-v2'",
    "receipt.policy_version = 'gate1-policy-v2'",
    "evidence.claim_key AS evidence_claim_key",
    "evidence.claim_value AS evidence_claim_value",
    "IF v_candidate_tenant_id IS NULL OR v_candidate_incident_id IS NULL OR v_candidate_evidence_id IS NULL OR v_candidate_agency IS NULL OR v_candidate_evidence_claim_key IS NULL OR v_candidate_evidence_claim_value IS NULL THEN RETURN NULL; END IF;",
    "v_candidate_conflict_windows := '[]'::JSONB; v_candidate_conflict_count := 0; v_candidate_conflict_snapshot_valid := true; OPEN v_candidate_conflict_cursor NO SCROLL FOR SELECT other.evidence_id, other.observed_at, other.valid_from, other.valid_until FROM tp_private.g1_evidence AS other",
    "other.claim_key = v_candidate_evidence_claim_key",
    "other.claim_value <> v_candidate_evidence_claim_value",
    "other.agency_scope IN (v_candidate_agency, '*')",
    "FETCH v_candidate_conflict_cursor INTO v_candidate_conflict_evidence_id, v_candidate_conflict_observed_at, v_candidate_conflict_valid_from, v_candidate_conflict_valid_until; EXIT WHEN v_candidate_conflict_evidence_id IS NULL;",
    "IF v_candidate_conflict_count > 10000 OR v_candidate_conflict_observed_at IS NULL OR v_candidate_conflict_valid_from IS NULL OR v_candidate_conflict_valid_until IS NULL THEN v_candidate_conflict_snapshot_valid := false; EXIT; END IF;",
    "CLOSE v_candidate_conflict_cursor; IF NOT v_candidate_conflict_snapshot_valid THEN RETURN NULL; END IF; v_database_now := clock_timestamp();",
    "WHILE v_candidate_conflict_index < jsonb_array_length(v_candidate_conflict_windows) LOOP v_candidate_conflict_window := v_candidate_conflict_windows->v_candidate_conflict_index;",
    "v_candidate_evidence_valid_until <= v_database_now",
    "RETURN jsonb_build_object( 'snapshot_schema', 'g1-recovery-source-snapshot-v1', 'tenant_id', v_candidate_tenant_id::STRING",
    "'minimum_residual_ms', v_minimum_residual_ms",
    "v_snapshot := tp_private.g1_resolve_recovery_source_snapshot_v1( p_tenant_id, p_run_id, p_incident_id, p_evidence_id, p_resource_id, p_operation_id, p_request_digest );",
    "v_snapshot IS DISTINCT FROM jsonb_build_object( 'snapshot_schema', v_snapshot->'snapshot_schema'",
    "jsonb_typeof(v_snapshot->'reason') IS DISTINCT FROM 'string' AND jsonb_typeof(v_snapshot->'reason') IS DISTINCT FROM 'null'",
    "minimum_residual_ms := (v_snapshot->>'minimum_residual_ms')::INT8; database_now := (v_snapshot->>'database_now')::TIMESTAMPTZ; RETURN NEXT; RETURN;",
    "tp_private.g1_resolve_recovery_source_snapshot_v1(UUID, UUID, UUID, UUID, STRING, UUID, STRING)",
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
    "IF v_epoch_current_epoch = 1 THEN",
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
    "SELECT count(*)::INT8, min(outbox.proposal_digest), min(outbox.logical_action_digest), min(outbox.authorization_epoch), min(outbox.logical_authority_key_sha256), min(outbox.authorization_binding_sha256), min(receipt.lease_expires_at), min(resource.lease_expires_at), min(proposal.expires_at) INTO v_authority_count, v_proposal_digest, v_logical_action_digest, v_authorization_epoch, v_logical_authority_key_sha256, v_authorization_binding_sha256, v_receipt_lease_expires_at, v_resource_lease_expires_at, v_proposal_expires_at",
    "v_database_now := clock_timestamp(); IF v_authority_count <> 1 OR v_proposal_digest IS NULL OR v_receipt_lease_expires_at <= v_database_now OR v_resource_lease_expires_at <= v_database_now OR v_proposal_expires_at <= v_database_now THEN RETURN; END IF; INSERT INTO tp_ledger.g1_protected_effects AS inserted_effect",
    "VALUES ( p_tenant_id, p_effect_key, p_operation_id, p_request_digest, v_proposal_digest, v_logical_action_digest, v_authorization_epoch, v_logical_authority_key_sha256, v_authorization_binding_sha256, p_run_id, p_incident_id, p_resource_id, p_agent_id, p_fencing_token, p_payload_digest ) ON CONFLICT DO NOTHING",
    "v_database_now := clock_timestamp(); IF v_authority_count <> 1 OR v_receipt_lease_expires_at <= v_database_now OR v_resource_lease_expires_at <= v_database_now OR v_proposal_expires_at <= v_database_now THEN DELETE FROM tp_ledger.g1_protected_effects AS effect WHERE effect.tenant_id = p_tenant_id AND effect.effect_key = v_effect_key AND effect.operation_id = v_operation_id; RETURN; END IF; RETURN QUERY SELECT v_effect_key, v_operation_id;",
    "proposal.payload = outbox.payload",
    "sha256(proposal.payload_canonical::BYTES)"
  ]),
  "primary-security-runner": Object.freeze([
    "sqlBindingNegatives",
    "assertSqlProbeRequestBindings",
    "TIDEPROOF_RECOVERY_PUBLISHER_KEY_SET_DIGEST",
    "assertRecoveryPublisherTrustRootWriteDeniedWithClient",
    "directTrustRootWrite",
    "recoverySource",
    "sourceResolverDenied",
    "expectPrivilegeDeniedOrUndefined",
    "providerMutationDenials",
    "tp_provider_reconcile_user",
    "g1_claim_provider_dispatch_v2",
    "g1_begin_provider_dispatch_v2",
    "g1_redeem_provider_dispatch_v2",
    "g1_complete_provider_dispatch_v2",
    "g1_mark_provider_dispatch_unknown_v2",
    "g1_transition_provider_dispatch_v1",
    "g1_resolve_provider_dispatch_v2",
    "RESOLVED_ABSENT",
    "/nonce|capability/u.test(name)",
    "g1_resolve_recovery_source_receipt_v1",
    "g1_resolve_recovery_source_receipt_v2",
    "privateSnapshotDenied",
    "directPrivateRead",
    "const PROVIDER_RUNTIME_CLOSURE_PROBES = Object.freeze({",
    "async function assertProviderRuntimeClosure(client, probe)",
    "directLedgerRead",
    "directPrivateFunction",
    "publicControlAbsent",
    "provider dispatch control absent",
    "providerActivate",
    "providerTerminalize",
    "tp_private.g1_resolve_recovery_source_snapshot_v1",
    "resolvedAgain = await client.query(",
    "SELECT count(*)::INT8 AS cursor_count FROM pg_catalog.pg_cursors",
    "cursorCountAfterFirst !== 0",
    "cursorCountAfterSecond !== 0",
    "function sameStableDatabaseValue(left, right)",
    "const RECOVERY_SOURCE_STABLE_COLUMNS = Object.freeze([",
    "stable database timestamp invalid",
    "stable database value invalid",
    "new Date(milliseconds).toISOString()",
    "JSON.stringify(RECOVERY_SOURCE_STABLE_COLUMNS)",
    "!sameStableDatabaseValue(",
    "resolverRepeatStable: true",
    "g1_resolve_recovery_publisher_trust_root_v1",
    "payloadSubstitutionOutcome",
    "payloadSubstitutionReason",
    "proposalAliasOutcome",
    "proposalAliasReason",
    "DVI selection mismatch mutated authority state",
    "requestDigestRejected?.sqlstate",
    "requestDigestRejected?.message",
    "nullIntentNonceRejected?.sqlstate",
    "nullIntentNonceRejected?.message",
    "database-derived authority identity mismatch",
    "authority request identity binding mismatch",
    "tp_authorizer_user"
  ]),
  "private-recovery-query-approval-generator": Object.freeze([
    "prooftoact.private-recovery-query-mcp-secret-binding.v1",
    "IMMUTABLE_AWSCURRENT_READBACK_BOUND",
    "validatePrivateRecoveryQueryProviderBinding",
    "providerBindingSha256",
    "expectedSourceCommitTs",
    "PRIVATE_RECOVERY_QUERY_APPROVAL_CLI_HOLD"
  ]),
  "private-recovery-query-approval-tests": Object.freeze([
    "generator copies the exact fresh provider binding with no overrides",
    "generator rejects stale binding and secret readback source drift",
    "deployment window check fails closed before the remaining margin"
  ]),
  "private-recovery-query-aws-runtime": Object.freeze([
    "GetSecretValueCommand",
    "VersionStage: \"AWSCURRENT\"",
    "ignoreConfiguredEndpointUrls: true",
    "maxAttempts: 1"
  ]),
  "private-recovery-query-aws-store": Object.freeze([
    "PRIVATE_RECOVERY_QUERY#${command.globalKeySha256}",
    "ConsistentRead: true",
    "attribute_not_exists(#pk)",
    "PRIVATE_RECOVERY_QUERY_DDB_ACK_UNKNOWN",
    "PRIVATE_RECOVERY_QUERY_DDB_OPERATION_COMMAND_CONFLICT",
    "UNKNOWN_DO_NOT_RETRY"
  ]),
  "private-recovery-query-bootstrap-role-stack": Object.freeze([
    "\"ManagedPolicyName\": \"ProofToActPrivateRecoveryQueryBoundary\"",
    "ProofToActPrivateRecoveryQueryDeployment",
    "DeploymentWorkflowCommit",
    "SecretSealWorkflowCommit",
    "s3:ListBucketVersions",
    "iam:PermissionsBoundary",
    "DenyPublicAndUnrelatedProviders"
  ]),
  "private-recovery-query-bootstrap-tests": Object.freeze([
    "bootstrap stack owns only the isolated boundary, empty secret, and three roles",
    "dispatcher trust is protected, main-only, and parameter-pinned",
    "secret sealer copies one exact source version into only the retained target",
    "service role is exact-resource rollback capable without runtime authority"
  ]),
  "private-recovery-query-build": Object.freeze([
    "entryPoints: [\"infra/aws/lambda/private-recovery-query.js\"]",
    "archiveEntryCount: 2",
    "THIRD_PARTY_NOTICES.txt",
    "packages: \"bundle\"",
    "PRIVATE_RECOVERY_QUERY_BUILD_CLI_HOLD"
  ]),
  "private-recovery-query-core": Object.freeze([
    "PRIVATE_AWS_MANAGED_MCP_RECOVERY_QUERY",
    "semantic.toolName === \"select_query\"",
    "rows.length === 1",
    "rows[0].source_commit_ts === approval.expectedSourceCommitTs",
    "status: dispatched ? \"UNKNOWN_DO_NOT_RETRY\" : \"FAILED_NO_PROVIDER_CALL\"",
    "authorityTransferred: false",
    "exactKeys(secretPayload, [\"apiKey\"])",
    "transport.endpointSha256 === sha256(MANAGED_MCP_ENDPOINT)",
    "transport.protocolVersion === MANAGED_MCP_PROTOCOL_VERSION",
    "PRIVATE_RECOVERY_QUERY_DISPATCH_STATE_REJECTED",
    "domain: OPERATION_KEY_DOMAIN",
    "PRIVATE_RECOVERY_QUERY_EXECUTION_FAILED",
    "SAFE_EXECUTION_FAILURE_CODES.has"
  ]),
  "private-recovery-query-core-tests": Object.freeze([
    "private Lambda performs one fixed Managed MCP query and emits no row",
    "completion timestamp and row freshness use a fresh post-close clock",
    "provider-bound source commit timestamp rejects a different signed row",
    "tool acknowledgement loss becomes durable unknown and never retries",
    "transport evidence is bound to the exact endpoint cluster and protocol",
    "dispatch-store contract drift fails before creating an MCP client",
    "hostile provider errors become fixed durable codes with no secret or identity leakage",
    "top-level Lambda boundary emits only one fixed response code and no log"
  ]),
  "private-recovery-query-deploy-caller-workflow": Object.freeze([
    "name: ProofToAct Private Recovery Deploy",
    "prooftoact-sealed-private-recovery-deploy.yml@caf417dd84d899c7407e5ed12f56b60f1b74d32a",
    "authority_commit: \"caf417dd84d899c7407e5ed12f56b60f1b74d32a\"",
    "authority_tree: \"b01bf525dd47eb7ad6ed412e9557010289c6836b\"",
    "secrets: inherit"
  ]),
  "private-recovery-query-deploy-preparer": Object.freeze([
    "minimumRemainingMilliseconds = 15 * 60 * 1_000",
    "READY_FOR_CREATE_CHANGE_SET",
    "artifactObjectVersionSha256",
    "sealedWorkflowCommit",
    "PRIVATE_RECOVERY_QUERY_DEPLOYMENT_CLI_HOLD"
  ]),
  "private-recovery-query-deploy-runner": Object.freeze([
    "prooftoact-private-recovery-query-create-${sanitizedIntent.intentSha256}",
    "CreateChangeSetCommand",
    "ExecuteChangeSetCommand",
    "REVIEW_IN_PROGRESS",
    "CREATE_IN_PROGRESS",
    "CREATE_COMPLETE",
    "PRIVATE_RECOVERY_QUERY_DEPLOY_EXECUTE_ACK_UNKNOWN",
    "PRIVATE_RECOVERY_QUERY_DEPLOY_PROTECTION_ACK_UNKNOWN",
    "PRIVATE_RECOVERY_QUERY_DEPLOY_CLI_HOLD"
  ]),
  "private-recovery-query-deploy-sealed-workflow": Object.freeze([
    "environment: aws-private-recovery-deploy",
    "Bind immutable reusable source before protected material",
    "SOURCE_LOCK_LANE: deploy",
    "--validate-token",
    "--minimum-remaining-seconds 1500",
    "--minimum-remaining-seconds 900",
    "artifact-version-census.json",
    "lexical minimum is a deterministic version choice across reruns",
    "scripts/deploy-private-recovery-query.js",
    "sanitized-deployment-receipt.json"
  ]),
  "private-recovery-query-evidence": Object.freeze([
    "signatureAlgorithm: \"Ed25519\"",
    "[\"PRE_QUERY\", \"POST_QUERY\"]",
    "value.function.eventSourceCount === 0",
    "value.function.functionUrlCount === 0",
    "value.function.vpcAttached === false",
    "snapshot.workflowCommit === expectation.workflowCommit",
    "stackParametersSha256"
  ]),
  "private-recovery-query-evidence-caller-workflow": Object.freeze([
    "name: ProofToAct Private Recovery Evidence",
    "prooftoact-sealed-private-recovery-evidence.yml@caf417dd84d899c7407e5ed12f56b60f1b74d32a",
    "authority_commit: \"caf417dd84d899c7407e5ed12f56b60f1b74d32a\"",
    "authority_tree: \"b01bf525dd47eb7ad6ed412e9557010289c6836b\"",
    "PRE_QUERY",
    "POST_QUERY"
  ]),
  "private-recovery-query-evidence-readback": Object.freeze([
    "GetCallerIdentityCommand",
    "ListFunctionUrlConfigsCommand",
    "ConsistentRead: true",
    "signPrivateRecoveryDeploymentEvidence",
    "Object.keys(versions).length === 1",
    "canonicalJson([\"AWSCURRENT\"])",
    "decodePolicyDocument",
    "normalizePolicyDocument",
    "PermissionsBoundaryType === \"Policy\"",
    "parameters.SealedWorkflowCommit === expectation.workflowCommit",
    "functionUrlCount: 0",
    "vpcAttached: false",
    "PRIVATE_RECOVERY_QUERY_EVIDENCE_CLI_HOLD"
  ]),
  "private-recovery-query-evidence-sealed-workflow": Object.freeze([
    "environment: aws-private-recovery-evidence",
    "Bind immutable reusable source before protected material",
    "SOURCE_LOCK_LANE: evidence",
    "Collect and sign exact read-only deployment evidence",
    "npm run proof:verify",
    "signed-evidence-receipt.json",
    "role-to-assume: ${{ secrets.PROOFTOACT_PRIVATE_RECOVERY_EVIDENCE_ROLE_ARN }}"
  ]),
  "private-recovery-query-evidence-tests": Object.freeze([
    "signed pre-query deployment evidence binds private exact-version posture",
    "signed post-query evidence requires the exact terminal receipt and pre-link",
    "evidence signature and public-trigger posture fail closed on tampering",
    "deployment evidence accepts only the exact one-version secret posture",
    "deployment role readback decodes exact IAM policy shapes and rejects drift",
    "IAM policy normalization is bounded to documented scalar-list fields"
  ]),
  "private-recovery-query-deployment-state-tests": Object.freeze([
    "fresh deployment uses deterministic intent-bound CREATE and converges",
    "deployment restarts from ${label}",
    "deployment reconciles ${label} acknowledgement loss",
    "completed protected stack returns without another provider mutation",
    "change-set timeout is restartable after exact provider completion",
    "stack timeout is restartable after exact provider completion",
    "deployment holds on provider template, parameter, or service-role drift"
  ]),
  "private-recovery-query-lambda-entry": Object.freeze([
    "prooftoact.private-recovery-query-invocation.v1",
    "privateRecoveryQueryApprovalSha256(event.approval)",
    "${configuration.functionArn}:${context.functionVersion}",
    "firstRuntimeClockRead",
    "runtimePromise ??=",
    "withTopLevelFailureBoundary",
    "PRIVATE_RECOVERY_QUERY_LAMBDA_HOLD"
  ]),
  "private-recovery-query-operator": Object.freeze([
    "reservePrivateRecoveryQuery",
    "invokeExactVersion",
    "reconcilePrivateRecoveryQuery",
    "PRIVATE_RECOVERY_QUERY_INVOCATION_ACK_UNKNOWN"
  ]),
  "private-recovery-query-operator-aws": Object.freeze([
    "InvokeCommand",
    "Qualifier: functionVersion",
    "InvocationType: \"RequestResponse\"",
    "maxAttempts: 1",
    "response.ExecutedVersion === functionVersion"
  ]),
  "private-recovery-query-query-caller-workflow": Object.freeze([
    "name: ProofToAct Private Recovery Query",
    "reconcile-only",
    "authority_commit: \"caf417dd84d899c7407e5ed12f56b60f1b74d32a\"",
    "authority_tree: \"b01bf525dd47eb7ad6ed412e9557010289c6836b\"",
    "prooftoact-sealed-private-recovery-query.yml@caf417dd84d899c7407e5ed12f56b60f1b74d32a"
  ]),
  "private-recovery-query-query-runner": Object.freeze([
    "[\"execute\", \"reconcile-only\"].includes",
    "executePrivateRecoveryQueryOnce",
    "reconcilePrivateRecoveryQuery",
    "PRIVATE_RECOVERY_QUERY_${receipt.status}",
    "PRIVATE_RECOVERY_QUERY_CLI_HOLD"
  ]),
  "private-recovery-query-query-sealed-workflow": Object.freeze([
    "environment: aws-private-recovery-query",
    "Bind immutable reusable source before protected material",
    "SOURCE_LOCK_LANE: query",
    "Execute or reconcile the exact one-shot private query",
    "--function-version \"$FUNCTION_VERSION\"",
    "Publish sanitized receipt only",
    "role-to-assume: ${{ secrets.PROOFTOACT_PRIVATE_RECOVERY_OPERATOR_ROLE_ARN }}"
  ]),
  "private-recovery-query-secret-seal-caller-workflow": Object.freeze([
    "name: ProofToAct Private Recovery Secret Seal",
    "prooftoact-sealed-private-recovery-secret-seal.yml@caf417dd84d899c7407e5ed12f56b60f1b74d32a",
    "authority_commit: \"caf417dd84d899c7407e5ed12f56b60f1b74d32a\"",
    "authority_tree: \"b01bf525dd47eb7ad6ed412e9557010289c6836b\"",
    "secrets: inherit"
  ]),
  "private-recovery-query-secret-seal-runner": Object.freeze([
    "PRIVATE_RECOVERY_QUERY_MCP_SECRET_SEAL",
    "PutSecretValueCommand",
    "canonicalJson({ apiKey: sourceApiKey })",
    "RECONCILED_AFTER_ACK_LOSS",
    "EXACT_VERSION_ALREADY_PRESENT",
    "PRIVATE_RECOVERY_QUERY_SECRET_SEAL_UNKNOWN_DO_NOT_RETRY",
    "PRIVATE_RECOVERY_QUERY_SECRET_SEAL_CLI_HOLD"
  ]),
  "private-recovery-query-secret-seal-sealed-workflow": Object.freeze([
    "environment: aws-private-recovery-deploy",
    "Bind immutable reusable source before protected material",
    "SOURCE_LOCK_LANE: secret-seal",
    "Assume only the one-version private secret sealer",
    "scripts/seal-private-recovery-query-secret.js",
    "mcp-secret-binding.json",
    "role-to-assume: ${{ secrets.PROOFTOACT_PRIVATE_RECOVERY_SECRET_SEALER_ROLE_ARN }}"
  ]),
  "private-recovery-query-secret-seal-tests": Object.freeze([
    "secret sealer copies one exact source key into one canonical target version",
    "secret sealer reconciles PutSecretValue acknowledgement loss without retry",
    "secret sealer rejects any unexpected target version before writing",
    "secret sealer rejects missing operator authorization before provider read"
  ]),
  "private-recovery-query-source-lock": Object.freeze([
    "AUDIENCE = \"prooftoact-private-recovery-source-lock-v1\"",
    "LANES = {",
    "job_workflow_ref",
    "job_workflow_sha",
    "workflow_sha",
    "validate_endpoint",
    "validate_token_response",
    "PRIVATE_RECOVERY_SOURCE_LOCK_REJECTED"
  ]),
  "private-recovery-query-source-lock-tests": Object.freeze([
    "all sealed lanes bind their GitHub-issued reusable identity before secrets",
    "all callers pin one reviewed Commit A and its exact tree",
    "source-lock endpoint accepts only the bounded GitHub HTTPS endpoint",
    "source lock accepts the exact identity of every private recovery lane",
    "source lock rejects identity, time, structure, and coordinate drift",
    "source-lock contract fails closed if dispatch or source guards are removed"
  ]),
  "private-recovery-query-store-tests": Object.freeze([
    "AWS store reserves, dispatches, and finalizes one exact item",
    "conditional write acknowledgement loss converges by strong read only",
    "unknown terminalization preserves no provider retry authority",
    "one operation ID occupies one create-only key across approval drift",
    "one operation ID rejects a different command after restart and final replay",
    "distinct operation IDs reserve distinct keys while concurrent replays converge"
  ]),
  "private-recovery-query-teardown-caller-workflow": Object.freeze([
    "name: ProofToAct Private Recovery Teardown",
    "confirmation: ${{ inputs.confirmation }}",
    "authority_commit: \"caf417dd84d899c7407e5ed12f56b60f1b74d32a\"",
    "authority_tree: \"b01bf525dd47eb7ad6ed412e9557010289c6836b\"",
    "prooftoact-sealed-private-recovery-teardown.yml@caf417dd84d899c7407e5ed12f56b60f1b74d32a"
  ]),
  "private-recovery-query-teardown-runner": Object.freeze([
    "DELETE_PROOFTOACT_PRIVATE_RECOVERY_QUERY_AFTER_POST_EVIDENCE",
    "UpdateTerminationProtectionCommand",
    "DeleteStackCommand",
    "ConsistentRead: true",
    "ClientRequestToken:",
    "DELETE_IN_PROGRESS",
    "DELETE_FAILED",
    "PRIVATE_RECOVERY_QUERY_TEARDOWN_DELETE_FAILED_HOLD",
    "PRIVATE_RECOVERY_QUERY_TEARDOWN_CLI_HOLD"
  ]),
  "private-recovery-query-teardown-sealed-workflow": Object.freeze([
    "environment: aws-private-recovery-teardown",
    "Bind immutable reusable source before protected material",
    "SOURCE_LOCK_LANE: teardown",
    "Verify terminal receipt and delete exactly one stack once",
    "POST_EVIDENCE_RECEIPT_B64",
    "Publish sanitized teardown receipt only",
    "role-to-assume: ${{ secrets.PROOFTOACT_PRIVATE_RECOVERY_TEARDOWN_ROLE_ARN }}"
  ]),
  "private-recovery-query-teardown-tests": Object.freeze([
    "governed teardown verifies POST evidence and deletes one exact stack once",
    "teardown rejects wrong confirmation before any provider read",
    "teardown restarts after protection was already disabled",
    "teardown resumes DELETE_IN_PROGRESS without another mutation",
    "teardown timeout preserves DELETE_IN_PROGRESS for a later successful rerun",
    "DELETE_FAILED is re-protected and held without a delete retry"
  ]),
  "private-recovery-query-template": Object.freeze([
    "ReservedConcurrentExecutions: 1",
    "\"dynamodb:LeadingKeys\": \"false\"",
    "functionUrlCount: 0",
    "publicApiCount: 0",
    "vpcAttached: false",
    "resourceCount: Object.keys(template.Resources).length"
  ]),
  "private-recovery-query-template-tests": Object.freeze([
    "mini-stack owns one private exact-version Lambda with no public trigger",
    "runtime and operator are restricted to one operation key and one secret",
    "OIDC trust pins protected environment and immutable reusable workflow",
    "sealed workflow and caller bind reviewed GitHub authority commit and tree"
  ]),
  "private-recovery-query-window-check": Object.freeze([
    "minimumRemainingSeconds >= 60",
    "remainingMilliseconds >= minimumRemainingSeconds * 1_000",
    "prooftoact.private-recovery-query-window-check.v1",
    "PRIVATE_RECOVERY_QUERY_WINDOW_REJECTED",
    "PRIVATE_RECOVERY_QUERY_WINDOW_CLI_HOLD"
  ]),
  "provider-dispatch-control": Object.freeze([
    "INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_V1_DISABLED",
    "ProviderDispatchControl",
    "providerDispatchEffectKeySha256"
  ]),
  "provider-dispatch-binding": Object.freeze([
    "tideproof.provider-dispatch-control-binding.v2",
    "tideproof.provider-effect-key.v1",
    "CREDENTIAL_REDEEMED",
    "UNKNOWN_DO_NOT_ACT"
  ]),
  "provider-dispatch-client": Object.freeze([
    "ProviderDispatchDatabaseClient",
    "validateProviderDispatchResult",
    "INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_QUERY_REJECTED"
  ]),
  "provider-dispatch-claim-control": Object.freeze([
    "ProviderDispatchClaimControl",
    "g1_claim_provider_dispatch_v2",
    "attempts: 3"
  ]),
  "provider-dispatch-begin-control": Object.freeze([
    "ProviderDispatchBeginControl",
    "g1_begin_provider_dispatch_v2",
    "attempts: 1"
  ]),
  "provider-dispatch-redeem-control": Object.freeze([
    "ProviderDispatchRedeemControl",
    "g1_redeem_provider_dispatch_v2",
    "ALREADY_REDEEMED_DO_NOT_DELIVER"
  ]),
  "provider-dispatch-finalize-control": Object.freeze([
    "ProviderDispatchFinalizeControl",
    "g1_complete_provider_dispatch_v2",
    "g1_mark_provider_dispatch_unknown_v2"
  ]),
  "provider-dispatch-activate-control": Object.freeze([
    "ProviderDispatchActivateControl",
    "tp_api.g1_activate_provider_dispatch_v2",
    "DELIVER_CREDENTIAL_ONCE",
    "ACTIVATION_ALREADY_CONSUMED"
  ]),
  "provider-dispatch-reconciliation-input": Object.freeze([
    "tideproof.highwater-drill-provider-reconciliation-input.v3",
    "validateProviderDispatchReconciliationInput",
    "providerDispatchReconciliationInputBytes"
  ]),
  "provider-dispatch-resolve-database": Object.freeze([
    "tideproof-provider-dispatch-resolve",
    "ProviderDispatchResolveDatabase",
    "INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_DATABASE_REJECTED"
  ]),
  "provider-dispatch-result": Object.freeze([
    "validateProviderDispatchResult",
    "INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_RESULT_REJECTED",
    "mcp_result_sha256",
    "session_close_sha256"
  ]),
  "provider-dispatch-terminalize-control": Object.freeze([
    "ProviderDispatchTerminalizeControl",
    "tp_api.g1_terminalize_provider_dispatch_v2",
    "EXPIRED_RECORDED",
    "ALREADY_TERMINAL"
  ]),
  "provider-dispatch-resolver": Object.freeze([
    "ProviderDispatchResolver",
    "g1_resolve_provider_dispatch_v2",
    "RESOLVED_ABSENT"
  ]),
  "provider-dispatch-control-tests": Object.freeze([
    "claim, begin, redeem, and finalize use distinct least-privilege clients",
    "resolver observes absent and terminal states without a mutation method or secret",
    "wrong execution capability cannot begin or finalize"
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
    "GRANT USAGE ON SCHEMA mcp_api, mcp_private TO ${RECOVERY_PUBLISHER_ROLE}",
    "RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_SQL",
    "MANAGED_MCP_RECOVERY_GRANT_SQL",
    "MANAGED_MCP_RECOVERY_FRESH_BOOTSTRAP_SQL",
    "REVOKE USAGE ON SCHEMA mcp_public FROM \"managed-mcp\"",
    "GRANT USAGE ON SCHEMA mcp_private TO \"managed-mcp\"",
    "GRANT USAGE ON SCHEMA mcp_public TO \"managed-mcp\"",
    "PUBLIC_VIEW_READY",
    "PRIVATE_USAGE_AND_SELECT",
    "tideproof.managed-mcp-recovery-grant-posture.v2",
    "tideproof.managed-mcp-recovery-grant-repair.v2",
    "SCHEMA:mcp_private:USAGE",
    "RELATION:mcp_private:*",
    "preflightManagedMcpRecoveryGrants",
    "reserveManagedMcpRecoveryTarget",
    "baselineRecoveryPostureDigest",
    "MANAGED_MCP_RECOVERY_EMERGENCY_HOLD",
    "MANAGED_MCP_RECOVERY_BASELINE_DRIFT",
    "collectRecoveryPublisherCapabilityPosture",
    "assertCleanExactGitCheckout",
    "RECOVERY_SCHEMA_REPAIR_SOURCE_CHECKOUT_INVALID",
    "crdb_internal.cluster_id()::STRING AS cluster_id",
    "RECOVERY_SCHEMA_REPAIR_CLUSTER_OBSERVATION_MISMATCH",
    "validateRecoveryPublisherFunctionDefinitionBinding",
    "RECOVERY_SCHEMA_REPAIR_FUNCTION_DEFINITION_MISMATCH",
    "RECOVERY_PUBLISHER_DIRECT_${operation}_NOT_DENIED",
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
    "RECOVERY_MCP_RESPONSE_SHAPE_AMBIGUOUS",
    "parseStrictJson(text, {",
    "RECOVERY_MCP_RESPONSE_JSON_DUPLICATE_MEMBER",
    "hasExactKeys(parsed, [\"rows\"])",
    "resolvePreparedRecoveryAuditEvent",
    "beforeExternalAction(\"AUDIT_RESOLVE_CONNECT\")",
    "beforeExternalAction(\"AUDIT_RESOLVE_QUERY\")",
    "g1_resolve_recovery_audit_event_v1",
    "g1_resolve_recovery_source_receipt_v3",
    "resolveCommittedRecoverySourceReceipt",
    "row.policy_version !== \"gate1-policy-v2\"",
    "RECOVERY_SOURCE_DVI_BINDING_INVALID",
    "selected_evidence_binding_sha256",
    "resolveCommittedRecoveryAuditEvent",
    "assertRecoveryPublisherTrustRootWriteDenied",
    "RECOVERY_TRUST_ROOT_WRITE_PROBE_ROLLBACK_FAILED",
    "databaseClientMustBeDiscarded(error)",
    "read_reconciled",
    "commitDefinitivelyAborted",
    "async prepareRecovery(input = {}, options = {})",
    "async planRecovery(input = {}, { auditIdentity = null } = {})",
    "async commitPreparedRecoveryPreRead(",
    "async executePreparedRecovery(",
    "closePreparedRecoveryProviderSessionAndReadEvidence",
    "validatePreparedRecoveryResume",
    "planPreparedRecoveryCompletion",
    "commitPreparedRecoveryCompletion",
    "async completePreparedRecovery(prepared, rawResult)",
    "restorePreparedRecovery(prepared)"
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
    "INTEGRATED_PERSISTENCE_ENVIRONMENT",
    "integratedPersistenceEnvironment",
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_SPEC",
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_RECOVERY_BUNDLE_PATH",
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_ROOT",
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_FORBIDDEN_ROOT",
    "INTEGRATED_LIVE_DRILL_RECOVERY_BROKER_PARTIAL_CONFIG_REJECTED",
    "INTEGRATED_LIVE_DRILL_SYSTEMD_BOUNDARY_REQUIRED"
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
    "primary-ledger commitment rejects coordinated root commitment and key replacement",
    "policy_version: \"g1-admissibility-v2\"",
    "RECOVERY_SOURCE_RECEIPT_INVALID"
  ]),
  "recovery-publisher-schema-repair": Object.freeze([
    "mode === \"--plan\"",
    "--verify-applied",
    "RECOVERY_ADMIN_DATABASE_URL",
    "RECOVERY_PUBLISHER_DATABASE_URL",
    "EXPECTED_RECOVERY_HOSTNAME",
    "EXPECTED_RECOVERY_CLUSTER_ID",
    "EXPECTED_RECOVERY_SQL_CLUSTER_ID",
    "EXPECTED_RECOVERY_PRE_REPAIR_POSTURE_SHA256",
    "EXPECTED_RECOVERY_CLUSTER_PRE_REPAIR_POSTURE_SHA256",
    "EXPECTED_RECOVERY_APPEND_FUNCTION_DEFINITION_SHA256",
    "EXPECTED_RECOVERY_RESOLVE_FUNCTION_DEFINITION_SHA256",
    "RECOVERY_SCHEMA_REPAIR_SOURCE_COMMIT",
    "RECOVERY_SCHEMA_REPAIR_SOURCE_TREE",
    "RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_CONFIRMATION"
  ]),
  "recovery-publication-reconciliation-tests": Object.freeze([
    "recovery publisher resolves an exact receipt after COMMIT ACK loss",
    "output.commit.observation, \"read_reconciled\"",
    "sqlState(\"ECONNRESET\")",
    "recovery publisher never rolls back an unclassified post-COMMIT error",
    "ambiguous_closed",
    "publisher capability collector executes functions only in a rolled-back probe",
    "publisher capability collector rejects any direct private-table operation",
    "publisher capability collector executes functions only in a rolled-back probe without internal cluster metadata",
    "read-only repair verification distinguishes exact absent and present state",
    "repair reconciles COMMIT ACK loss as present without retry",
    "repair reconciles COMMIT ACK loss as absent and never retries",
    "repair marks contradictory ACK-loss readback unresolved",
    "post-COMMIT verification failure is recoverable only by read-only verification",
    "post-COMMIT function or cluster drift remains unresolved without retry",
    "repair stops on rollback failure before dispatching COMMIT",
    "repair requires the executing standalone exact-Git checkout identity",
    "repair CLI gates apply and exposes only a read-only verify mode",
    "Managed MCP preflight discovers the exact posture digest after source binding and needs no prior digest",
    "Managed MCP recovery collector names every exact zero, one, two, and three grant state",
    "Managed MCP repair accepts only the exact live public-view baseline and refuses every other state before mutation",
    "Managed MCP recovery plan deactivates the public view before private schema traversal and reactivates last",
    "Managed MCP repair disables an activated capability when post-activation verification fails",
    "Managed MCP repair disables schema usage observed concurrently after the inert first step",
    "Managed MCP disable proves exact baseline restoration rather than capability removal alone",
    "Managed MCP CLI exposes exact modes and gates apply and disable confirmations",
    "Managed MCP local journal reserves one target durably and excludes other operations",
    "Managed MCP journal durability failure stops before any grant dispatch"
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
  "recovery-broker-tests": Object.freeze([
    "audit resolver resamples authority after connect and before query dispatch",
    "broker rejects an MCP result containing both rows and content",
    "broker rejects nested MCP text containing rows plus another representation",
    "broker rejects duplicate and escaped-equivalent members in nested MCP text",
    "RECOVERY_MCP_RESPONSE_SHAPE_AMBIGUOUS"
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
  "strict-json-contract": Object.freeze([
    "export function parseStrictJson(",
    "STRICT_JSON_DUPLICATE_MEMBER",
    "Number.isFinite(Number(match[0]))",
    "members.has(member)",
    "return JSON.parse(text);"
  ])
});

const FORBIDDEN_SOURCE_MARKERS = Object.freeze({
  "actions-ci-workflow": Object.freeze([
    "pull_request_target:",
    "id-token: write",
    "contents: write",
    "secrets.",
    "environment:"
  ]),
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
    "v_authorization_epoch := v_epoch.current_epoch + 1",
    "CREATE OR REPLACE FUNCTION tp_api.g1_transition_provider_dispatch_v1",
    "proposal.policy_version = receipt.policy_version",
    "COALESCE(( SELECT jsonb_agg(jsonb_build_object(",
    "SELECT COALESCE(jsonb_agg(jsonb_build_object(",
    "FROM pg_catalog.jsonb_array_elements(v_candidate_conflict_windows)",
    "FOR v_candidate_conflict_window IN SELECT",
    "RETURN QUERY SELECT v_candidate_tenant_id, v_candidate_run_id, v_candidate_incident_id, v_candidate_evidence_id, v_candidate_operation_id, v_candidate_recorded_at, v_candidate_request_digest, v_candidate_proposal_digest, v_candidate_logical_action_digest, v_candidate_authorization_epoch, v_candidate_logical_authority_key_sha256, v_candidate_authorization_binding_sha256, v_candidate_policy_version, v_candidate_agent_id, v_candidate_agency, v_candidate_outcome, v_candidate_reason, v_candidate_evidence_digest, v_candidate_authority_evidence_binding_sha256, v_candidate_resource_id, v_candidate_has_durable_intent, v_candidate_admissibility, v_database_now",
    "GRANT EXECUTE ON FUNCTION tp_private.g1_resolve_recovery_source_snapshot_v1",
    "INSERT INTO tp_ledger.g1_protected_effects AS inserted_effect ( tenant_id, effect_key, operation_id, request_digest, proposal_digest, logical_action_digest, authorization_epoch, logical_authority_key_sha256, authorization_binding_sha256, run_id, incident_id, resource_id, agent_id, fencing_token, payload_digest ) SELECT p_tenant_id, p_effect_key, p_operation_id, p_request_digest"
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
  const exactOperatorTrust = {
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
  };
  assert(
    template.Parameters?.EvidenceOperatorPrincipalArn?.AllowedPattern ===
      "^arn:aws[a-zA-Z-]*:iam::[0-9]{12}:(?:role|user)/[A-Za-z0-9+=,.@_-]{1,64}$" &&
      sameJson(evidenceTrust, exactOperatorTrust) &&
      sameJson(
        resources.AdvisoryCallerRole?.Properties?.AssumeRolePolicyDocument,
        exactOperatorTrust
      ) &&
      sameJson(
        resources.AuthorityRaceCallerRole?.Properties
          ?.AssumeRolePolicyDocument,
        exactOperatorTrust
      ) &&
      sameJson(template.Outputs?.DeploymentEvidenceRoleArn?.Value, {
        "Fn::GetAtt": ["DeploymentEvidenceRole", "Arn"]
      }) &&
      sameJson(alternateTrust, exactOperatorTrust) &&
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
