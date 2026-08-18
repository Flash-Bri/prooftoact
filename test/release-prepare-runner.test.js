import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import test from "node:test";

import {
  __test as commonTest,
  consumeExplicitTemporaryCredentials,
  consumePrivatePrepareConfiguration,
  createControlPlaneExecutableManifest,
  decodePhaseLookup,
  encodePhaseLookup,
  releasePrepareConstants,
  sanitizedBrokerEnvironment,
  validatePrepareWorkflowContext,
  validateProtectedBootstrapGate,
  verifyControlPlaneExecutableManifest,
  verifyLiveControlCheckout
} from "../scripts/run-release-prepare-common.js";
import { __test as phaseTest } from
  "../scripts/run-release-prepare-phase.js";
import { __test as preflightTest } from
  "../scripts/run-release-prepare-preflight.js";
import {
  gitEnvironment,
  gitInvariantArguments,
  trustedGitExecutable
} from "../scripts/lib/exact-git-source.js";
import { createPrepareReadback } from
  "../release-provider/src/release-provider-prepare-readback.js";

const ACCOUNT_ID = "111111111111";
const COMMIT = "1".repeat(40);
const TREE = "2".repeat(40);
const UUID = "12345678-1234-4234-8234-123456789abc";

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function temporaryDirectory(prefix) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  fs.chmodSync(root, 0o700);
  return fs.realpathSync(root);
}

function contextFixture(phaseName) {
  const workspace = temporaryDirectory("prooftoact-prepare-context-");
  fs.mkdirSync(path.join(workspace, "control-plane"), { mode: 0o700 });
  fs.mkdirSync(path.join(workspace, "frozen-application"), { mode: 0o700 });
  const contract = releasePrepareConstants.PHASES[phaseName];
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
      GITHUB_WORKFLOW: "ProofToAct Release Candidate",
      GITHUB_WORKFLOW_REF:
        "Flash-Bri/prooftoact/.github/workflows/" +
        "prooftoact-release-candidate.yml@refs/heads/main",
      GITHUB_WORKFLOW_SHA: COMMIT,
      GITHUB_WORKSPACE: workspace,
      PROOFTOACT_RELEASE_PHASE_ENVIRONMENT: contract.environment,
      RUNNER_ENVIRONMENT: "github-hosted",
      RUNNER_OS: "Linux"
    },
    workspace
  };
}

function lookup() {
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

function privateConfiguration() {
  return {
    artifactBucket: "prooftoact-private-artifacts",
    authorityDatabaseHost: "cluster.example.cockroachlabs.cloud",
    authorityDatabasePort: "26257",
    authorityDatabaseSecretArn:
      `arn:aws:secretsmanager:us-east-1:${ACCOUNT_ID}:secret:pta/db`,
    authorityDatabaseSecretVersionId: "a".repeat(32),
    authorityIncidentId: UUID,
    authorityResourceId: "highwater-synthetic",
    authorityTenantId: "87654321-4321-4321-8321-cba987654321",
    bedrockModelId: "amazon.nova-micro-v1:0",
    configDigest: "8".repeat(64),
    schemaVersion: "prooftoact.prepare-private-configuration.v1"
  };
}

function writeExecutableFiles(root) {
  for (const relative of releasePrepareConstants.TRACKED_EXECUTABLE_PATHS) {
    const file = path.join(root, relative);
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    fs.writeFileSync(file, `${relative}\n`, { mode: 0o600 });
  }
}

function git(root, ...args) {
  return execFileSync(trustedGitExecutable(),
    [...gitInvariantArguments(), ...args], {
      cwd: root,
      encoding: "utf8",
      env: gitEnvironment(),
      stdio: ["ignore", "pipe", "ignore"]
    }).trim();
}

test("exact workflow context admits only the four phase tuples", () => {
  for (const phase of ["diagnostic", "reserve", "dispatch", "finalize"]) {
    const fixture = contextFixture(phase);
    try {
      const result = validatePrepareWorkflowContext(
        fixture.environment, phase, "linux");
      assert.equal(result.controlRoot,
        path.join(fixture.workspace, "control-plane"));
    } finally {
      fixture.cleanup();
    }
  }
});

test("exact workflow context admits Node's real process environment carrier",
  { concurrency: false }, () => {
    const fixture = contextFixture("diagnostic");
    const previous = new Map(Object.keys(fixture.environment).map((name) =>
      [name, process.env[name]]));
    try {
      Object.assign(process.env, fixture.environment);
      const result = validatePrepareWorkflowContext(
        process.env, "diagnostic", "linux");
      assert.equal(result.controlRoot,
        path.join(fixture.workspace, "control-plane"));
    } finally {
      for (const [name, value] of previous) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
      fixture.cleanup();
    }
  });

test("wrong job, ref, environment, SHA, and run attempt reject", () => {
  const fixture = contextFixture("dispatch");
  try {
    for (const mutation of [
      { GITHUB_JOB: "coordinator-reserve" },
      { GITHUB_REF: "refs/heads/release" },
      { PROOFTOACT_RELEASE_PHASE_ENVIRONMENT: "aws-live-drill" },
      { GITHUB_WORKFLOW_SHA: "f".repeat(40) },
      { GITHUB_RUN_ATTEMPT: "2" }
    ]) {
      assert.throws(() => validatePrepareWorkflowContext({
        ...fixture.environment, ...mutation
      }, "dispatch", "linux"), /RELEASE_PREPARE_WORKFLOW_CONTEXT_REJECTED/u);
    }
  } finally {
    fixture.cleanup();
  }
});

test("explicit temporary credentials are consumed and ambient AWS state rejects", () => {
  const environment = {
    AWS_ACCESS_KEY_ID: `ASIA${"A".repeat(16)}`,
    AWS_DEFAULT_REGION: "us-east-1",
    AWS_REGION: "us-east-1",
    AWS_SECRET_ACCESS_KEY: "s".repeat(40),
    AWS_SESSION_TOKEN: "temporary-session-token"
  };
  const credentials = consumeExplicitTemporaryCredentials(environment);
  assert.equal(credentials.accessKeyId, `ASIA${"A".repeat(16)}`);
  assert.deepEqual(environment, {});
  assert.throws(() => consumeExplicitTemporaryCredentials({
    ...environment,
    AWS_ACCESS_KEY_ID: `ASIA${"A".repeat(16)}`,
    AWS_CONFIG_FILE: "/tmp/ambient",
    AWS_DEFAULT_REGION: "us-east-1",
    AWS_REGION: "us-east-1",
    AWS_SECRET_ACCESS_KEY: "s".repeat(40),
    AWS_SESSION_TOKEN: "temporary-session-token"
  }), /RELEASE_PREPARE_EXPLICIT_CREDENTIALS_REJECTED/u);
  assert.throws(() => sanitizedBrokerEnvironment({ HTTP_PROXY: "http://x" }),
    /RELEASE_PREPARE_HOSTILE_ENVIRONMENT_REJECTED/u);
});

test("pre-OIDC gate rejects any configured provider credential", () => {
  assert.doesNotThrow(() => preflightTest
    .assertBeforeCredentialConfiguration({
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: "github-owned-oidc-request-token"
    }));
  for (const name of ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN", "AWS_WEB_IDENTITY_TOKEN_FILE"]) {
    assert.throws(() => preflightTest.assertBeforeCredentialConfiguration({
      [name]: "present"
    }), /RELEASE_PREPARE_PREFLIGHT_CREDENTIAL_REJECTED/u);
  }
});

test("approval windows use fresh monotonic time and reject exact elapsed boundaries", () => {
  const expiresAt = 1_000_000;
  assert.equal(commonTest.validateApprovalWindow({
    expiresAt,
    now: 400_000,
    phaseName: "dispatch",
    priorNow: 399_999
  }).remainingMs, 600_000);
  assert.throws(() => commonTest.validateApprovalWindow({
    expiresAt,
    now: 400_001,
    phaseName: "dispatch",
    priorNow: 400_000
  }), /RELEASE_PREPARE_APPROVAL_WINDOW_REJECTED/u);
  assert.throws(() => commonTest.validateApprovalWindow({
    expiresAt,
    now: 300_000,
    phaseName: "reserve",
    priorNow: 300_001
  }), /RELEASE_PREPARE_APPROVAL_WINDOW_REJECTED/u);
  assert.throws(() => commonTest.validateApprovalWindow({
    expiresAt,
    now: 700_001,
    phaseName: "finalize",
    priorNow: 700_000
  }), /RELEASE_PREPARE_APPROVAL_WINDOW_REJECTED/u);
});

test("hash-only lookup round trips and malformed handoffs reject", () => {
  const encoded = encodePhaseLookup(lookup());
  assert.deepEqual(decodePhaseLookup(encoded), lookup());
  assert.throws(() => decodePhaseLookup("not-base64"),
    /RELEASE_PREPARE_LOOKUP_REJECTED/u);
  const forged = { ...lookup(), unexpectedProviderResult: "success" };
  assert.throws(() => encodePhaseLookup(forged),
    /RELEASE_PREPARE_LOOKUP_REJECTED/u);
});

test("GitHub handoff publication appends only the encoded hash lookup", () => {
  const root = temporaryDirectory("prooftoact-prepare-output-");
  try {
    const output = path.join(root, "github-output");
    fs.writeFileSync(output, "", { mode: 0o600 });
    phaseTest.writeLookupOutput({ GITHUB_OUTPUT: output }, lookup());
    const line = fs.readFileSync(output, "utf8").trim();
    assert.match(line, /^lookup_b64=[A-Za-z0-9+/]+=*$/u);
    assert.deepEqual(decodePhaseLookup(line.slice("lookup_b64=".length)),
      lookup());
    const alias = path.join(root, "output-alias");
    fs.symlinkSync(output, alias);
    assert.throws(() => phaseTest.writeLookupOutput({ GITHUB_OUTPUT: alias },
      lookup()), /RELEASE_PREPARE_GITHUB_OUTPUT_REJECTED/u);
  } finally {
    fs.rmSync(root, { force: true, recursive: true });
  }
});

test("private configuration is exact, account-bound, and consumed", () => {
  const configuration = privateConfiguration();
  const environment = {
    PROOFTOACT_RELEASE_PREPARE_PRIVATE_CONFIG_B64:
      Buffer.from(JSON.stringify(configuration)).toString("base64")
  };
  assert.deepEqual(consumePrivatePrepareConfiguration(environment, ACCOUNT_ID),
    configuration);
  assert.equal(environment.PROOFTOACT_RELEASE_PREPARE_PRIVATE_CONFIG_B64,
    undefined);
  const wrong = {
    PROOFTOACT_RELEASE_PREPARE_PRIVATE_CONFIG_B64:
      Buffer.from(JSON.stringify({ ...configuration,
        authorityDatabaseSecretArn: configuration.authorityDatabaseSecretArn
          .replace(ACCOUNT_ID, "222222222222") })).toString("base64")
  };
  assert.throws(() => consumePrivatePrepareConfiguration(wrong, ACCOUNT_ID),
    /RELEASE_PREPARE_PRIVATE_CONFIG_REJECTED/u);
});

test("protected bootstrap gate binds receipt, exact template, table, and role", () => {
  const root = temporaryDirectory("prooftoact-bootstrap-gate-");
  try {
    const template = path.join(root,
      "infra/aws/release-deployment-roles-template.json");
    fs.mkdirSync(path.dirname(template), { recursive: true });
    fs.writeFileSync(template, "{}\n");
    const tableId = UUID;
    const approval = {
      providerAccountId: ACCOUNT_ID,
      claims: { globalStore: { tableId } }
    };
    const environment = {
      PROOFTOACT_RELEASE_BOOTSTRAP_RECEIPT_SHA256: "1".repeat(64),
      PROOFTOACT_RELEASE_BOOTSTRAP_STACK_ID_SHA256: "2".repeat(64),
      PROOFTOACT_RELEASE_BOOTSTRAP_STATUS:
        "EXACT_BOOTSTRAP_PROVIDER_READBACK_ACCEPTED",
      PROOFTOACT_RELEASE_BOOTSTRAP_TEMPLATE_SHA256:
        sha256(Buffer.from("{}\n")),
      PROOFTOACT_RELEASE_CONTROL_TABLE_ID: tableId,
      PROOFTOACT_RELEASE_ROLE_ARN:
        `arn:aws:iam::${ACCOUNT_ID}:role/ProofToActReleaseCoordinator`
    };
    assert.equal(validateProtectedBootstrapGate({ approval,
      controlRoot: root, environment, phaseName: "reserve" }).tableId,
    tableId);
    assert.throws(() => validateProtectedBootstrapGate({ approval,
      controlRoot: root, environment, phaseName: "dispatch" }),
    /RELEASE_PREPARE_PROTECTED_BOOTSTRAP_GATE_REJECTED/u);
    for (const mutation of [
      { PROOFTOACT_RELEASE_BOOTSTRAP_RECEIPT_SHA256: "" },
      { PROOFTOACT_RELEASE_BOOTSTRAP_TEMPLATE_SHA256: "f".repeat(64) },
      { PROOFTOACT_RELEASE_CONTROL_TABLE_ID:
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" },
      { PROOFTOACT_RELEASE_ROLE_ARN:
        `arn:aws:iam::${ACCOUNT_ID}:role/Administrator` }
    ]) {
      assert.throws(() => validateProtectedBootstrapGate({ approval,
        controlRoot: root, environment: { ...environment, ...mutation },
        phaseName: "reserve" }),
      /RELEASE_PREPARE_PROTECTED_BOOTSTRAP_GATE_REJECTED/u);
    }
  } finally {
    fs.rmSync(root, { force: true, recursive: true });
  }
});

test("executable manifest binds every named executable surface and signed identity", () => {
  const root = temporaryDirectory("prooftoact-executable-manifest-");
  try {
    writeExecutableFiles(root);
    const { publicKey } = crypto.generateKeyPairSync("ec", {
      namedCurve: "prime256v1"
    });
    const operatorPublicKey = publicKey.export({ format: "pem", type: "spki" });
    const controlReceipt = {
      controlPlaneCommit: COMMIT,
      controlPlaneTree: TREE,
      provenanceSha256: "3".repeat(64),
      sha256: "4".repeat(64)
    };
    const providerReceipt = {
      controlPlaneCommit: COMMIT,
      controlPlaneTree: TREE,
      provenanceSha256: "5".repeat(64),
      runtimeSetSha256: "6".repeat(64)
    };
    const candidate = createControlPlaneExecutableManifest({
      controlPlane: { commit: COMMIT, tree: TREE },
      controlReceipt,
      controlRoot: root,
      operatorPublicKey,
      providerReceipt
    });
    const controlPlane = {
      brokerArtifactSha256: candidate.manifest.brokerSha256,
      buildSha256: candidate.buildSha256,
      commit: COMMIT,
      identitySha256: candidate.identitySha256,
      separation: "SEPARATE_CONTROL_PLANE_FROM_FROZEN_APPLICATION",
      tree: TREE
    };
    assert.equal(verifyControlPlaneExecutableManifest({
      approval: { claims: { controlPlane } },
      controlReceipt,
      controlRoot: root,
      operatorPublicKey,
      providerReceipt
    }).buildSha256, candidate.buildSha256);
    fs.appendFileSync(path.join(root,
      "scripts/run-release-prepare-phase.js"), "drift\n");
    assert.throws(() => verifyControlPlaneExecutableManifest({
      approval: { claims: { controlPlane } },
      controlReceipt,
      controlRoot: root,
      operatorPublicKey,
      providerReceipt
    }), /RELEASE_PREPARE_CONTROL_PLANE_BUILD_REJECTED/u);
  } finally {
    fs.rmSync(root, { force: true, recursive: true });
  }
});

test("live checkout accepts exact detached Actions checkout and rejects drift/tree mismatch", () => {
  const root = temporaryDirectory("prooftoact-live-checkout-");
  try {
    git(root, "init", "--quiet", "--initial-branch=main");
    writeExecutableFiles(root);
    git(root, "add", "--all");
    git(root, "-c", "user.name=Fixture", "-c",
      "user.email=fixture@invalid", "commit", "--quiet", "-m", "fixture");
    git(root, "remote", "add", "origin",
      "https://github.com/Flash-Bri/prooftoact.git");
    const commit = git(root, "rev-parse", "HEAD");
    const tree = git(root, "rev-parse", "HEAD^{tree}");
    git(root, "checkout", "--quiet", "--detach", commit);
    assert.equal(verifyLiveControlCheckout({ controlRoot: root,
      expectedCommit: commit, expectedTree: tree }).tree, tree);
    assert.throws(() => verifyLiveControlCheckout({ controlRoot: root,
      expectedCommit: commit, expectedTree: "f".repeat(40) }),
    /RELEASE_PREPARE_LIVE_CONTROL_CHECKOUT_REJECTED/u);
    fs.appendFileSync(path.join(root,
      "scripts/run-release-prepare-common.js"), "dirty\n");
    assert.throws(() => verifyLiveControlCheckout({ controlRoot: root,
      expectedCommit: commit, expectedTree: tree }),
    /RELEASE_PREPARE_LIVE_CONTROL_CHECKOUT_REJECTED/u);
  } finally {
    fs.rmSync(root, { force: true, recursive: true });
  }
});

test("dispatcher outcome is always ambiguous and never converts dispatch into confirmation", () => {
  const now = Date.parse("2026-08-17T12:00:00.000Z");
  const outcome = phaseTest.dispatcherOutcome({
    providerReceiptSha256: "a".repeat(64),
    providerRequestId: UUID
  }, { operationIdentitySha256: "b".repeat(64) }, now);
  assert.equal(outcome.status, "AMBIGUOUS");
  assert.equal(outcome.possibleMutation, true);
  assert.equal(outcome.observedAt, "2026-08-17T12:00:00.000Z");
});

test("workflow defaults diagnostic, separates OIDC jobs, and passes only hash lookup", () => {
  const workflow = fs.readFileSync(new URL(
    "../.github/workflows/prooftoact-release-candidate.yml",
    import.meta.url), "utf8");
  const diagnostic = workflow.slice(workflow.indexOf("  prepare-diagnostic:"),
    workflow.indexOf("  coordinator-reserve:"));
  assert.match(workflow,
    /diagnostic_only:[\s\S]*?default: true[\s\S]*?type: boolean/u);
  assert.doesNotMatch(diagnostic, /id-token:\s*write/u);
  assert.equal((workflow.match(/id-token:\s*write/gu) ?? []).length, 3);
  assert.equal((workflow.match(/aws-actions\/configure-aws-credentials@e6de054238d6b7531b4efff3b6587d9aade6a06c/gu) ?? []).length, 3);
  assert.equal((workflow.match(/run-release-prepare-preflight\.js (?:reserve|dispatch|finalize)/gu) ?? []).length, 3);
  assert.match(workflow, /environment: aws-release-coordination/u);
  assert.match(workflow, /environment: aws-release-deployment/u);
  assert.match(workflow, /outputs:\n\s+lookup_b64:/u);
  assert.doesNotMatch(workflow, /needs\.provider-dispatch\.outputs/u);
  assert.doesNotMatch(workflow, /actions\/(?:upload-artifact|cache)@/u);
  assert.match(workflow,
    /PROOFTOACT_RELEASE_BOOTSTRAP_RECEIPT_SHA256:\s*\$\{\{ vars\./u);
  assert.match(workflow,
    /coordinator-finalize:[\s\S]*?if: \$\{\{ always\(\)[\s\S]*?!inputs\.diagnostic_only/u);
});

test("phase runner revalidates advancing authority and uses the sealed readback clock", () => {
  const source = fs.readFileSync(new URL(
    "../scripts/run-release-prepare-phase.js", import.meta.url), "utf8");
  assert.ok((source.match(/accepted\.boundary\(\)/gu) ?? []).length >= 10);
  assert.match(source,
    /createPrepareReadback\(\{\s*transport\s*\}\)/gu);
  assert.doesNotMatch(source,
    /createPrepareReadback\(\{\s*clock\s*[,}]/gu);
  assert.doesNotMatch(source, /clock:\s*\(\)\s*=>\s*now/gu);
  assert.match(source,
    /const providerReceipt = await providerDispatcher\.dispatch[\s\S]*?accepted\.boundary\(\)/u);
  assert.match(source,
    /authorityNotAfter:\s*accepted\.envelope\.expiresAt/u);
  assert.doesNotMatch(source,
    /(?:reserveProviderOneShotIntent|dispatchReservedProviderOneShotIntent|finalizeProviderOneShotIntent)\(\{[\s\S]{0,500}?\bnow:/u);
});

test("finalizer constructs the sealed production readback factory without a test clock", () => {
  const transport = Object.freeze(Object.fromEntries([
    "describeChangeSet", "describeStackEvents", "describeStackResources",
    "describeStacks", "getObject", "getTemplate", "headObject"
  ].map((name) => [name, async () => {
    throw new Error(`UNUSED_${name}`);
  }])));
  const reader = phaseTest.createSealedPrepareReader(
    Object.freeze({ createPrepareReadback }), transport);
  assert.equal(typeof reader.readback, "function");
  assert.throws(() => createPrepareReadback({ clock: Date.now, transport }),
    /RELEASE_PROVIDER_READBACK_CONFIGURATION_REJECTED/u);
});
