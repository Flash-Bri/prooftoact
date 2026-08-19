import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  APP_SOURCE,
  canonicalDigest
} from "../release-provider/src/release-provider-common.js";
import {
  buildExecutePhaseRuntime,
  releaseExecuteConstants,
  validateExecuteProtectedBootstrapGate,
  validateExecuteWorkflowContext
} from "../scripts/run-release-execute-common.js";
import { __test as phaseTest } from
  "../scripts/run-release-execute-phase.js";
import { __test as preflightTest } from
  "../scripts/run-release-execute-preflight.js";
import { decodePhaseLookup } from
  "../scripts/run-release-prepare-common.js";

const ACCOUNT = "111111111111";
const COMMIT = "1".repeat(40);
const TREE = "2".repeat(40);
const NOW = Date.parse("2026-08-18T15:00:00.000Z");

function temporaryDirectory(prefix) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  fs.chmodSync(root, 0o700);
  return fs.realpathSync(root);
}

function contextFixture(phaseName) {
  const workspace = temporaryDirectory("prooftoact-execute-context-");
  fs.mkdirSync(path.join(workspace, "control-plane"), { mode: 0o700 });
  fs.mkdirSync(path.join(workspace, "frozen-application"), { mode: 0o700 });
  const contract = releaseExecuteConstants.PHASES[phaseName];
  return {
    cleanup: () => fs.rmSync(workspace, { force: true, recursive: true }),
    environment: {
      CI: "true",
      EXPECTED_OFFICIAL_MAIN_COMMIT: COMMIT,
      GITHUB_ACTIONS: "true",
      GITHUB_API_URL: "https://api.github.com",
      GITHUB_EVENT_NAME: "workflow_dispatch",
      GITHUB_GRAPHQL_URL: "https://api.github.com/graphql",
      GITHUB_JOB: contract.job,
      GITHUB_REF: "refs/heads/main",
      GITHUB_REF_NAME: "main",
      GITHUB_REF_TYPE: "branch",
      GITHUB_REPOSITORY: "Flash-Bri/prooftoact",
      GITHUB_REPOSITORY_ID: "1317716765",
      GITHUB_REPOSITORY_OWNER_ID: "252500266",
      GITHUB_RUN_ATTEMPT: "1",
      GITHUB_RUN_ID: "123456789",
      GITHUB_SERVER_URL: "https://github.com",
      GITHUB_SHA: COMMIT,
      GITHUB_WORKFLOW: "ProofToAct Execute Approved Release",
      GITHUB_WORKFLOW_REF:
        "Flash-Bri/prooftoact/.github/workflows/" +
        "prooftoact-execute-approved-release.yml@refs/heads/main",
      GITHUB_WORKFLOW_SHA: COMMIT,
      GITHUB_WORKSPACE: workspace,
      PROOFTOACT_RELEASE_PHASE_ENVIRONMENT: contract.environment,
      RUNNER_ENVIRONMENT: "github-hosted",
      RUNNER_OS: "Linux"
    },
    workspace
  };
}

function sealedContextFixture(phaseName) {
  const fixture = contextFixture(phaseName);
  fixture.environment.GITHUB_JOB = "sealed-credential-boundary";
  fixture.environment.PROOFTOACT_RELEASE_CALLER_JOB =
    releaseExecuteConstants.PHASES[phaseName].job;
  fixture.environment.PROOFTOACT_RELEASE_SEALED_AUTHORITY_COMMIT = COMMIT;
  fixture.environment.PROOFTOACT_RELEASE_SEALED_WORKFLOW =
    phaseName === "dispatch" ? "prooftoact-sealed-execute.yml" :
      "prooftoact-sealed-coordinator.yml";
  return fixture;
}

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function approvalFixture(controlRoot) {
  const release = {
    artifactManifestSha256: "3".repeat(64),
    buildReceiptSha256: "4".repeat(64),
    changeSetArn:
      `arn:aws:cloudformation:us-east-1:${ACCOUNT}:changeSet/` +
      "prooftoact-release-final/123e4567-e89b-42d3-a456-426614174000",
    changeSetSha256: "5".repeat(64),
    changeSetType: "CREATE",
    parameterManifestSha256: "6".repeat(64),
    region: "us-east-1",
    resourceInventorySha256: "7".repeat(64),
    stackId: `arn:aws:cloudformation:us-east-1:${ACCOUNT}:stack/` +
      "prooftoact-gate2/223e4567-e89b-42d3-a456-426614174001",
    stackName: "prooftoact-gate2"
  };
  const teardown = {
    deadline: "2026-08-19T15:00:00.000Z",
    deleteExactStack: "prooftoact-gate2",
    deleteExactStackId: release.stackId,
    environment: "aws-release-teardown",
    expectedResourceInventorySha256: release.resourceInventorySha256,
    originatingChangeSetArn: release.changeSetArn,
    originatingChangeSetSha256: release.changeSetSha256,
    required: true,
    residualCensusRequired: true,
    roleArn: `arn:aws:iam::${ACCOUNT}:role/ProofToActReleaseTeardown`,
    separateApprovalRequired: true,
    workflow: "ProofToAct Approved Teardown"
  };
  return {
    approvalSha256: "8".repeat(64),
    providerAccountId: ACCOUNT,
    claims: {
      appSource: APP_SOURCE,
      authoritySeparation: { exact: true },
      budget: { censusReceiptSha256: "9".repeat(64) },
      controlPlane: {
        brokerArtifactSha256: "a".repeat(64),
        buildSha256: "b".repeat(64),
        commit: COMMIT,
        identitySha256: "c".repeat(64),
        tree: TREE
      },
      database: { freshPrimaryReceiptSha256: "d".repeat(64) },
      globalStore: { tableIdentitySha256: "e".repeat(64) },
      release,
      teardown,
      workspaceRealpathSha256: sha256(Buffer.from(controlRoot, "utf8"))
    }
  };
}

function lookupFixture() {
  return {
    approvalSha256: "1".repeat(64),
    commandSha256: "2".repeat(64),
    globalKeySha256: "3".repeat(64),
    intentSha256: "4".repeat(64),
    lookupSha256: "5".repeat(64),
    namespaceArnSha256: "6".repeat(64),
    schemaVersion: "prooftoact.provider-broker-phase-lookup.v1",
    tableIdentitySha256: "7".repeat(64)
  };
}

test("direct EXECUTE context admits diagnostic only and rejects provider phases", () => {
  const diagnostic = contextFixture("diagnostic");
  try {
    const context = validateExecuteWorkflowContext(
      diagnostic.environment, "diagnostic", "linux");
    assert.equal(context.controlRoot,
      path.join(diagnostic.workspace, "control-plane"));
  } finally {
    diagnostic.cleanup();
  }
  for (const phase of ["reserve", "dispatch", "finalize"]) {
    const fixture = contextFixture(phase);
    try {
      assert.throws(() => validateExecuteWorkflowContext(
        fixture.environment, phase, "linux"),
      /RELEASE_EXECUTE_WORKFLOW_CONTEXT_REJECTED/u);
    } finally {
      fixture.cleanup();
    }
  }
});

test("exact EXECUTE workflow context admits the trust-pinned reusable phase jobs", () => {
  for (const phase of ["reserve", "dispatch", "finalize"]) {
    const fixture = sealedContextFixture(phase);
    try {
      const context = validateExecuteWorkflowContext(
        fixture.environment, phase, "linux");
      assert.equal(context.contract.job,
        releaseExecuteConstants.PHASES[phase].job);
      for (const mutation of [
        { PROOFTOACT_RELEASE_CALLER_JOB: "provider-dispatch" },
        { PROOFTOACT_RELEASE_SEALED_AUTHORITY_COMMIT: "f".repeat(40) },
        { PROOFTOACT_RELEASE_SEALED_WORKFLOW:
          "prooftoact-sealed-teardown.yml" }
      ]) {
        if (phase === "dispatch" && mutation.PROOFTOACT_RELEASE_CALLER_JOB ===
          "provider-dispatch") continue;
        assert.throws(() => validateExecuteWorkflowContext({
          ...fixture.environment, ...mutation
        }, phase, "linux"), /RELEASE_EXECUTE_WORKFLOW_CONTEXT_REJECTED/u);
      }
    } finally {
      fixture.cleanup();
    }
  }
});

test("EXECUTE workflow context rejects job, workflow, ref, and retry drift", () => {
  const fixture = contextFixture("dispatch");
  try {
    for (const mutation of [
      { GITHUB_JOB: "coordinator-reserve" },
      { GITHUB_WORKFLOW: "ProofToAct Release Candidate" },
      { GITHUB_REF: "refs/heads/release" },
      { GITHUB_RUN_ATTEMPT: "2" },
      { PROOFTOACT_RELEASE_PHASE_ENVIRONMENT: "aws-release-deployment" }
    ]) {
      assert.throws(() => validateExecuteWorkflowContext({
        ...fixture.environment, ...mutation
      }, "dispatch", "linux"), /RELEASE_EXECUTE_WORKFLOW_CONTEXT_REJECTED/u);
    }
  } finally {
    fixture.cleanup();
  }
});

test("protected gate binds exact bootstrap template, table, and phase role", () => {
  const root = temporaryDirectory("prooftoact-execute-bootstrap-");
  try {
    const template = path.join(root,
      "infra/aws/release-deployment-roles-template.json");
    fs.mkdirSync(path.dirname(template), { recursive: true, mode: 0o700 });
    fs.writeFileSync(template, "{}\n", { mode: 0o600 });
    const tableId = "323e4567-e89b-42d3-a456-426614174002";
    const approval = { providerAccountId: ACCOUNT,
      claims: { globalStore: { tableId } } };
    const base = {
      PROOFTOACT_RELEASE_BOOTSTRAP_RECEIPT_SHA256: "1".repeat(64),
      PROOFTOACT_RELEASE_BOOTSTRAP_STACK_ID_SHA256: "2".repeat(64),
      PROOFTOACT_RELEASE_BOOTSTRAP_STATUS:
        "EXACT_BOOTSTRAP_PROVIDER_READBACK_ACCEPTED",
      PROOFTOACT_RELEASE_BOOTSTRAP_TEMPLATE_SHA256:
        sha256(Buffer.from("{}\n")),
      PROOFTOACT_RELEASE_CONTROL_TABLE_ID: tableId
    };
    assert.equal(validateExecuteProtectedBootstrapGate({
      approval,
      controlRoot: root,
      environment: { ...base, PROOFTOACT_RELEASE_ROLE_ARN:
        `arn:aws:iam::${ACCOUNT}:role/ProofToActReleaseExecution` },
      phaseName: "dispatch"
    }).tableId, tableId);
    assert.throws(() => validateExecuteProtectedBootstrapGate({
      approval,
      controlRoot: root,
      environment: { ...base, PROOFTOACT_RELEASE_ROLE_ARN:
        `arn:aws:iam::${ACCOUNT}:role/ProofToActReleaseDeployment` },
      phaseName: "dispatch"
    }), /RELEASE_EXECUTE_PROTECTED_BOOTSTRAP_GATE_REJECTED/u);
  } finally {
    fs.rmSync(root, { force: true, recursive: true });
  }
});

test("phase runtime binds EXECUTE workflow, exact role session, source, and receipts", () => {
  const fixture = contextFixture("dispatch");
  try {
    const controlRoot = path.join(fixture.workspace, "control-plane");
    const approval = approvalFixture(controlRoot);
    const sessionName = "pta-123456789-1-provider-dispatch";
    const runtime = buildExecutePhaseRuntime({
      actualControlPlaneBuildSha256: approval.claims.controlPlane.buildSha256,
      approval,
      approvalEnvelope: { expiresAt: new Date(NOW + 20 * 60_000).toISOString() },
      brokerArtifactSha256:
        approval.claims.controlPlane.brokerArtifactSha256,
      callerIdentity: {
        accountId: ACCOUNT,
        assumedRoleArn: `arn:aws:sts::${ACCOUNT}:assumed-role/` +
          `ProofToActReleaseExecution/${sessionName}`,
        roleId: `AROA${"A".repeat(16)}`,
        roleName: "ProofToActReleaseExecution",
        sessionName
      },
      context: {
        controlRoot,
        environment: fixture.environment
      },
      now: NOW,
      phaseName: "dispatch"
    });
    assert.equal(runtime.lane, "EXECUTE");
    assert.equal(runtime.phase, "PROVIDER_DISPATCH");
    assert.equal(runtime.workflow,
      "ProofToAct Execute Approved Release");
    assert.equal(runtime.releaseReadbackSha256,
      canonicalDigest(approval.claims.release));
    assert.equal(runtime.authorityReceipts.providerBacked, true);
    assert.equal(runtime.authorityReceipts.strongRead, true);
  } finally {
    fixture.cleanup();
  }
});

test("finalizer publication is create-only, hash-bound, and idempotent", () => {
  const runnerTemp = temporaryDirectory("prooftoact-execute-receipt-");
  try {
    const runtime = {
      environment: "aws-release-coordination",
      jobName: "coordinator-finalize",
      lane: "EXECUTE",
      phase: "COORDINATOR_FINALIZE",
      principalArn: `arn:aws:sts::${ACCOUNT}:assumed-role/` +
        "ProofToActReleaseCoordinator/pta-123456789-1-coordinator-finalize",
      providerAccountId: ACCOUNT,
      repositoryId: "1317716765",
      repositoryOwnerId: "252500266",
      runAttempt: 1,
      runId: "123456789",
      workflow: "ProofToAct Execute Approved Release",
      workflowRef: releaseExecuteConstants.WORKFLOW_REF,
      workflowSha: COMMIT
    };
    const accepted = { approval: {
      approvalSha256: "1".repeat(64),
      claims: { controlPlane: {
        commit: COMMIT, identitySha256: "2".repeat(64)
      } }
    } };
    const context = { environment: { RUNNER_TEMP: runnerTemp } };
    const result = { receipt: {
      receiptSha256: "3".repeat(64),
      schemaVersion: "prooftoact.provider-broker-phase-receipt.v1",
      status: "CONFIRMED"
    } };
    const first = phaseTest.publishFinalizerReceipt({ accepted, context,
      observedAt: NOW, result, runtime });
    const second = phaseTest.publishFinalizerReceipt({ accepted, context,
      observedAt: NOW, result, runtime });
    assert.equal(first.created, true);
    assert.equal(second.created, false);
    assert.equal(first.filePath, second.filePath);
    const publication = JSON.parse(fs.readFileSync(first.filePath, "utf8"));
    const unsigned = { ...publication };
    delete unsigned.publicationSha256;
    assert.equal(publication.publicationSha256, canonicalDigest(unsigned));
    assert.equal(fs.statSync(first.filePath).mode & 0o777, 0o600);
  } finally {
    fs.rmSync(runnerTemp, { force: true, recursive: true });
  }
});

test("reserve handoff exposes only hash lookup plus a strict replay-fence bit", () => {
  const root = temporaryDirectory("prooftoact-execute-output-");
  try {
    const file = path.join(root, "github-output");
    fs.writeFileSync(file, "", { mode: 0o600 });
    phaseTest.writeLookupOutput({ GITHUB_OUTPUT: file }, lookupFixture(), false);
    const lines = fs.readFileSync(file, "utf8").trim().split("\n");
    assert.equal(lines.length, 2);
    assert.match(lines[0], /^lookup_b64=[A-Za-z0-9+/]+=*$/u);
    assert.equal(lines[1], "dispatch_permitted=false");
    assert.deepEqual(decodePhaseLookup(
      lines[0].slice("lookup_b64=".length)), lookupFixture());
  } finally {
    fs.rmSync(root, { force: true, recursive: true });
  }
});

test("pre-OIDC gate rejects every ambient AWS credential carrier", () => {
  assert.doesNotThrow(() => preflightTest
    .assertBeforeCredentialConfiguration({
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: "github-owned-request-token"
    }));
  for (const name of ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN", "AWS_WEB_IDENTITY_TOKEN_FILE"]) {
    assert.throws(() => preflightTest.assertBeforeCredentialConfiguration({
      [name]: "present"
    }), /RELEASE_EXECUTE_PREFLIGHT_CREDENTIAL_REJECTED/u);
  }
});

test("top-level EXECUTE remains held until the activated reusable workflows receive exact trust pins", () => {
  const workflow = fs.readFileSync(new URL(
    "../.github/workflows/prooftoact-execute-approved-release.yml",
    import.meta.url), "utf8");
  const coordinator = fs.readFileSync(new URL(
    "../.github/workflows/prooftoact-sealed-coordinator.yml",
    import.meta.url), "utf8");
  const execute = fs.readFileSync(new URL(
    "../.github/workflows/prooftoact-sealed-execute.yml",
    import.meta.url), "utf8");
  assert.match(workflow,
    /diagnostic_only:[\s\S]*?default: true[\s\S]*?type: boolean/u);
  assert.match(workflow, /^  controller-diagnostic:$/mu);
  assert.doesNotMatch(workflow, /id-token:\s*write|configure-aws-credentials/u);
  assert.match(workflow,
    /PROVIDER_EXECUTION_DISABLED_RUNTIME_AUTHORITY_RECEIPTS_REQUIRED/u);
  for (const source of [coordinator, execute]) {
    assert.match(source, /id-token: write/u);
    assert.match(source,
      /aws-actions\/configure-aws-credentials@e6de054238d6b7531b4efff3b6587d9aade6a06c/u);
    assert.match(source, /ACTIVATE_SIGNED_EXECUTE_PHASE/u);
    assert.match(source, /HASH_BOUND_EXECUTABLE_COORDINATES/u);
    assert.match(source, /run-release-execute-preflight\.js/u);
    assert.match(source, /run-release-execute-phase\.js/u);
    assert.match(source, /disable-retry: true/u);
  }
  assert.match(coordinator, /outputs:[\s\S]*?lookup_base64:/u);
  assert.match(coordinator, /dispatch_permitted:/u);
  assert.match(execute, /PROOFTOACT_RELEASE_EXECUTE_LOOKUP_B64/u);
});

test("phase source injects signed expiry and never accepts dispatcher output as confirmation", () => {
  const source = fs.readFileSync(new URL(
    "../scripts/run-release-execute-phase.js", import.meta.url), "utf8");
  assert.ok((source.match(/accepted\.boundary\(\)/gu) ?? []).length >= 12);
  assert.match(source,
    /authorityNotAfter:\s*runtime\.authorityReceipts\.expiresAt/u);
  assert.match(source, /dispatcherOutcome:\s*null/u);
  assert.match(source, /capability:\s*"EXECUTE_PERMIT_READER"/u);
  assert.match(source, /capability:\s*"EXECUTE_DISPATCHER"/u);
  assert.match(source, /capability:\s*"EXECUTE_READBACK"/u);
  assert.doesNotMatch(source,
    /(?:reserveProviderOneShotIntent|dispatchReservedProviderOneShotIntent|finalizeProviderOneShotIntent)\(\{[\s\S]{0,500}?\bnow:/u);
});
