import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  AWS_GATE2_PREFLIGHT_BUDGET_FAILURES,
  AWS_GATE2_PREFLIGHT_CONTROL_FAILURES,
  AWS_GATE2_PREFLIGHT_COST_FAILURES,
  AWS_GATE2_PREFLIGHT_DEFAULTS,
  AwsGate2PreflightControlFailure,
  awsBudgetDescribeArguments,
  awsCostExplorerPeriod,
  createAwsGate2PreflightDiagnosticContext,
  validateAwsGate2Preflight
} from "../src/cloud/aws-gate2-preflight.js";
import {
  AWS_GATE2_PREFLIGHT_RUNTIME_CALL_INVENTORY,
  AWS_GATE2_PREFLIGHT_RUNTIME_BUDGET_FAILURES,
  AWS_GATE2_PREFLIGHT_RUNTIME_CONTROL_FAILURES,
  AWS_GATE2_PREFLIGHT_RUNTIME_COST_FAILURES,
  AWS_GATE2_PREFLIGHT_RUNTIME_FAILURES,
  AWS_GATE2_PREFLIGHT_RUNTIME_PHASE_FAILURES,
  assertAwsPreflightParentEnvironment,
  awsCostExplorerArguments,
  awsPreflightRuntimeFailureDescriptor,
  awsPreflightAwsEnvironment,
  awsPreflightIdentityExpectation,
  collectSnapshot,
  controlledAwsCliPath,
  controlledGitPath,
  createAwsPreflightRuntimeCallReader,
  gitPreflightEnvironment,
  trustedAwsCliExecutable,
  trustedGitCheckout,
  trustedGitExecutable,
  trustedGitText
} from "../scripts/gate2-aws-preflight.js";

const ACCOUNT_ID = "111111111111";
const BUCKET_NAME = "private-tideproof-artifacts-111111111111";
const BOOTSTRAP_STACK = "tideproof-gate2-artifacts";
const BUDGET_NAME = `${BOOTSTRAP_STACK}-account-safety`;
const OIDC_WORKFLOW = fs.readFileSync(
  new URL(
    "../.github/workflows/aws-oidc-identity-bootstrap.yml",
    import.meta.url
  ),
  "utf8"
);

test("AWS OIDC identity bootstrap is manual, minimal, and encrypted", () => {
  assert.match(
    OIDC_WORKFLOW,
    /\non:\n  workflow_dispatch:\n    inputs:\n      official_main_commit:[\s\S]*?\npermissions:\n  contents: read\n  id-token: write\n/
  );
  assert.doesNotMatch(
    OIDC_WORKFLOW,
    /\n  (?:push|pull_request|schedule):/
  );
  assert.match(OIDC_WORKFLOW, /environment: aws-preflight/);
  assert.match(OIDC_WORKFLOW, /official_main_commit:/);
  assert.match(
    OIDC_WORKFLOW,
    /EXPECTED_OFFICIAL_MAIN_COMMIT: \$\{\{ inputs\.official_main_commit \}\}/
  );
  assert.match(OIDC_WORKFLOW, /GITHUB_REPOSITORY_ID:-\}" == "1317716765/);
  assert.match(
    OIDC_WORKFLOW,
    /GITHUB_SHA:-\}" == "\$EXPECTED_OFFICIAL_MAIN_COMMIT/
  );
  assert.match(OIDC_WORKFLOW, /\$\(\/usr\/bin\/id -u\)" != "0"/);
  assert.doesNotMatch(OIDC_WORKFLOW, /actions\/checkout@/);
  for (const secret of [
    "AWS_ROLE_ARN",
    "AWS_ACCOUNT_ID",
    "RECEIPT_ENCRYPTION_PASSPHRASE"
  ]) {
    assert.match(
      OIDC_WORKFLOW,
      new RegExp(`secrets\\.${secret}`)
    );
  }
  assert.match(OIDC_WORKFLOW, /ACTIONS_ID_TOKEN_REQUEST_URL/);
  assert.match(
    OIDC_WORKFLOW,
    /\(pipelines\|run-actions-/
  );
  assert.doesNotMatch(
    OIDC_WORKFLOW,
    /https:\/\/pipelines\.actions\.githubusercontent\.com\//
  );
  assert.match(OIDC_WORKFLOW, /ACTIONS_ID_TOKEN_REQUEST_TOKEN/);
  assert.match(OIDC_WORKFLOW, /audience=sts\.amazonaws\.com/);
  assert.match(OIDC_WORKFLOW, /Flash-Bri\/prooftoact/);
  assert.match(OIDC_WORKFLOW, /refs\/heads\/main/);
  assert.match(OIDC_WORKFLOW, /\.repository_owner_id == "252500266"/);
  assert.match(
    OIDC_WORKFLOW,
    /repo:Flash-Bri@252500266\/prooftoact@1317716765:environment:aws-preflight/
  );
  assert.match(OIDC_WORKFLOW, /\.environment == "aws-preflight"/);
  assert.match(
    OIDC_WORKFLOW,
    /AWS_APPROVED_ACCOUNT_ID_SHA256: \$\{\{ secrets\.AWS_APPROVED_ACCOUNT_ID_SHA256 \}\}/
  );
  assert.match(
    OIDC_WORKFLOW,
    /expected_role_arn="arn:aws:iam::\$\{AWS_ACCOUNT_ID\}:role\/ProofToActPreflight"/
  );
  assert.doesNotMatch(OIDC_WORKFLOW, /role_prefix|role_resource|role_name=/);
  assert.match(OIDC_WORKFLOW, /assume-role-with-web-identity/);
  assert.match(OIDC_WORKFLOW, /--role-session-name release-proof/);
  assert.match(OIDC_WORKFLOW, /--duration-seconds 900/);
  assert.match(OIDC_WORKFLOW, /\^ASIA\[A-Z0-9\]\{16\}\$/);
  assert.match(OIDC_WORKFLOW, /expected_caller_arn/);
  assert.match(OIDC_WORKFLOW, /\.UserId == \$assumed_role_id/);
  assert.match(OIDC_WORKFLOW, /\/usr\/local\/bin\/aws/);
  assert.match(OIDC_WORKFLOW, /\/usr\/local\/aws-cli\/v2\//);
  assert.match(OIDC_WORKFLOW, /aws_uid" == "0/);
  assert.match(OIDC_WORKFLOW, /aws_mode_value & 0022/);
  assert.match(OIDC_WORKFLOW, /"\$aws_cli" sts/);
  assert.match(OIDC_WORKFLOW, /\.repository == "Flash-Bri\/prooftoact"/);
  assert.match(OIDC_WORKFLOW, /\.workflow_ref ==/);
  assert.match(OIDC_WORKFLOW, /\.workflow_sha == \$sha/);
  assert.match(OIDC_WORKFLOW, /\.sha == \$sha/);
  assert.match(OIDC_WORKFLOW, /\.event_name == "workflow_dispatch"/);
  assert.match(OIDC_WORKFLOW, /--cli-connect-timeout 10/);
  assert.match(OIDC_WORKFLOW, /--cli-read-timeout 20/);
  assert.match(OIDC_WORKFLOW, /\/usr\/bin\/timeout --signal=KILL 30s/);
  assert.match(OIDC_WORKFLOW, /chmod 600/);
  assert.match(OIDC_WORKFLOW, /--symmetric/);
  assert.match(OIDC_WORKFLOW, /--cipher-algo AES256/);
  assert.match(OIDC_WORKFLOW, /retention-days: 1/);

  const actionPins = [
    ...OIDC_WORKFLOW.matchAll(
      /^\s*uses:\s*(\S+)(?:\s+#.*)?$/gmu
    )
  ].map((match) => match[1]);
  assert.deepEqual(actionPins, [
    "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
  ]);
  const awsServices = [
    ...OIDC_WORKFLOW.matchAll(/"\$aws_cli"\s+([a-z0-9-]+)/gu)
  ].map((match) => match[1]);
  assert.deepEqual(awsServices, ["sts", "sts"]);
  assert.doesNotMatch(OIDC_WORKFLOW, /^\s*aws\s+/gmu);
  assert.doesNotMatch(OIDC_WORKFLOW, /\bset\s+-x\b/);
  assert.doesNotMatch(OIDC_WORKFLOW, /\b(?:cat|tee)\b/);
});

test("direct AWS preflight rejects Node and endpoint injection before spawning", () => {
  for (const environment of [
    { NODE_DEBUG: "child_process" },
    { NODE_OPTIONS: "--require=/tmp/inject.js" },
    { NODE_TLS_REJECT_UNAUTHORIZED: "0" },
    { AWS_ENDPOINT_URL_STS: "http://127.0.0.1:9000" }
  ]) {
    assert.throws(
      () => assertAwsPreflightParentEnvironment(environment),
      /AWS_EVIDENCE_(?:SDK_ENVIRONMENT|ENDPOINT_OVERRIDE)/
    );
  }
});

test("direct AWS preflight requires temporary assumed-role credentials", () => {
  assert.doesNotThrow(() =>
    assertAwsPreflightParentEnvironment(
      expectedPreflightEnvironment()
    )
  );
  assert.throws(
    () =>
      assertAwsPreflightParentEnvironment(
        expectedPreflightEnvironment({
          AWS_SESSION_TOKEN: undefined
        })
      ),
    /AWS_EVIDENCE_SESSION_TOKEN/
  );
  assert.throws(
    () =>
      assertAwsPreflightParentEnvironment(
        expectedPreflightEnvironment({
          AWS_ACCESS_KEY_ID: "AKIAEXAMPLE12345678"
        })
      ),
    /AWS_EVIDENCE_TEMPORARY_ACCESS_KEY/
  );
  assert.throws(
    () =>
      assertAwsPreflightParentEnvironment(
        expectedPreflightEnvironment({
          AWS_ACCESS_KEY_ID: "ASIAEXAMPLE12345678"
        })
      ),
    /AWS_EVIDENCE_TEMPORARY_ACCESS_KEY/
  );
});

function expectedPreflightEnvironment(overrides = {}) {
  return {
    PATH: "/usr/bin",
    AWS_ACCESS_KEY_ID: ["ASIAEXAMPLE", "123456789"].join(""),
    AWS_SECRET_ACCESS_KEY: "secret-example-value",
    AWS_SESSION_TOKEN: "session-example-value",
    AWS_EVIDENCE_EXPECTED_ACCOUNT_ID: ACCOUNT_ID,
    AWS_EVIDENCE_EXPECTED_PREFLIGHT_PRINCIPAL_ARN:
      `arn:aws:iam::${ACCOUNT_ID}:role/ProofToActPreflight`,
    AWS_EVIDENCE_EXPECTED_PREFLIGHT_CALLER_ARN:
      `arn:aws:sts::${ACCOUNT_ID}:assumed-role/` +
      "ProofToActPreflight/release-proof",
    AWS_EVIDENCE_EXPECTED_PREFLIGHT_CALLER_USER_ID:
      "AROAPROOFTOACTROLE1:release-proof",
    ...overrides
  };
}

test("standalone preflight replaces caller PATH with a platform allowlist", () => {
  assert.equal(
    controlledAwsCliPath({ platform: "darwin", delimiter: ":" }),
    "/opt/homebrew/bin:/usr/bin:/bin"
  );
  assert.equal(
    controlledAwsCliPath({ platform: "linux", delimiter: ":" }),
    "/usr/local/bin:/usr/bin:/bin"
  );
  assert.equal(
    controlledGitPath({ platform: "darwin", delimiter: ":" }),
    "/usr/bin:/bin"
  );
  const isolated = awsPreflightAwsEnvironment(
    expectedPreflightEnvironment({ PATH: "/tmp/untrusted-bin" }),
    { platform: "darwin", delimiter: ":" }
  );
  assert.equal(isolated.PATH, "/opt/homebrew/bin:/usr/bin:/bin");
  assert.doesNotMatch(isolated.PATH, /untrusted-bin/);
  assert.throws(
    () => controlledAwsCliPath({ platform: "win32" }),
    /AWS_CLI_UNSUPPORTED_PLATFORM/
  );
  assert.throws(
    () => controlledAwsCliPath({ delimiter: "::" }),
    /AWS_CLI_PATH_DELIMITER/
  );
  assert.throws(
    () => controlledGitPath({ platform: "win32" }),
    /GIT_UNSUPPORTED_PLATFORM/
  );
});

test("standalone preflight resolves only an owned immutable packaged AWS CLI", () => {
  const fixtureRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "prooftoact-aws-cli-")
  );
  try {
    const candidateDirectory = path.join(fixtureRoot, "bin");
    const trustedRoot = path.join(fixtureRoot, "trusted-aws-cli");
    const resolvedExecutable = path.join(
      trustedRoot,
      "2.36.16",
      "aws"
    );
    fs.mkdirSync(candidateDirectory, { recursive: true });
    fs.mkdirSync(path.dirname(resolvedExecutable), {
      recursive: true
    });
    fs.writeFileSync(resolvedExecutable, "#!/bin/sh\nexit 0\n", {
      mode: 0o700
    });
    const candidate = path.join(candidateDirectory, "aws");
    fs.symlinkSync(resolvedExecutable, candidate);

    assert.equal(
      trustedAwsCliExecutable({
        platform: "darwin",
        candidatePaths: [candidate],
        packageRoots: [trustedRoot]
      }),
      fs.realpathSync(resolvedExecutable)
    );

    const untrustedExecutable = path.join(
      fixtureRoot,
      "untrusted",
      "aws"
    );
    fs.mkdirSync(path.dirname(untrustedExecutable), {
      recursive: true
    });
    fs.writeFileSync(untrustedExecutable, "#!/bin/sh\nexit 0\n", {
      mode: 0o700
    });
    assert.throws(
      () =>
        trustedAwsCliExecutable({
          platform: "darwin",
          candidatePaths: [untrustedExecutable],
          packageRoots: [trustedRoot]
        }),
      /AWS_CLI_TRUSTED_EXECUTABLE/
    );

    const directWrapper = path.join(candidateDirectory, "direct", "aws");
    fs.mkdirSync(path.dirname(directWrapper), { recursive: true });
    fs.writeFileSync(directWrapper, "#!/bin/sh\nexit 0\n", {
      mode: 0o700
    });
    assert.throws(
      () =>
        trustedAwsCliExecutable({
          platform: "darwin",
          candidatePaths: [directWrapper],
          packageRoots: [path.dirname(directWrapper)]
        }),
      /AWS_CLI_TRUSTED_EXECUTABLE/
    );

    fs.chmodSync(resolvedExecutable, 0o720);
    assert.throws(
      () =>
        trustedAwsCliExecutable({
          platform: "darwin",
          candidatePaths: [candidate],
          packageRoots: [trustedRoot]
        }),
      /AWS_CLI_TRUSTED_EXECUTABLE/
    );

    fs.chmodSync(resolvedExecutable, 0o700);
    assert.throws(
      () =>
        trustedAwsCliExecutable({
          platform: "darwin",
          candidatePaths: [candidate],
          packageRoots: [trustedRoot],
          expectedOwnerUid: process.getuid() + 1
        }),
      /AWS_CLI_TRUSTED_EXECUTABLE/
    );

    fs.chmodSync(resolvedExecutable, 0o600);
    assert.throws(
      () =>
        trustedAwsCliExecutable({
          platform: "darwin",
          candidatePaths: [candidate],
          packageRoots: [trustedRoot]
        }),
      /AWS_CLI_TRUSTED_EXECUTABLE/
    );
  } finally {
    fs.rmSync(fixtureRoot, { force: true, recursive: true });
  }
});

test("standalone preflight ignores caller Git PATH and configuration", () => {
  const fixtureRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "prooftoact-git-wrapper-")
  );
  try {
    const marker = path.join(fixtureRoot, "wrapper-ran");
    const wrapper = path.join(fixtureRoot, "git");
    fs.writeFileSync(
      wrapper,
      `#!/bin/sh\nprintf used >${JSON.stringify(marker)}\nprintf '%040d\\n' 0\n`,
      { mode: 0o700 }
    );
    const sourceEnvironment = {
      PATH: fixtureRoot,
      GIT_CONFIG_GLOBAL: path.join(fixtureRoot, "malicious.gitconfig"),
      GIT_CONFIG_NOSYSTEM: "0",
      GIT_CONFIG_COUNT: "1",
      GIT_CONFIG_KEY_0: "status.showUntrackedFiles",
      GIT_CONFIG_VALUE_0: "no",
      GIT_DIR: fixtureRoot,
      GIT_INDEX_FILE: path.join(fixtureRoot, "index"),
      GIT_ALTERNATE_OBJECT_DIRECTORIES: path.join(
        fixtureRoot,
        "objects"
      ),
      GIT_REPLACE_REF_BASE: "refs/hostile/replace"
    };
    const isolated = gitPreflightEnvironment(sourceEnvironment, {
      platform: "darwin",
      delimiter: ":"
    });
    assert.equal(isolated.PATH, "/usr/bin:/bin");
    assert.equal(isolated.GIT_CONFIG_GLOBAL, "/dev/null");
    assert.equal(isolated.GIT_CONFIG_NOSYSTEM, "1");
    assert.equal(isolated.GIT_CONFIG_COUNT, undefined);
    assert.equal(isolated.GIT_DIR, undefined);
    assert.equal(isolated.GIT_INDEX_FILE, undefined);
    assert.equal(isolated.GIT_ALTERNATE_OBJECT_DIRECTORIES, undefined);
    assert.equal(isolated.GIT_REPLACE_REF_BASE, undefined);
    assert.equal(isolated.GIT_ATTR_NOSYSTEM, "1");
    assert.equal(isolated.GIT_NO_LAZY_FETCH, "1");
    assert.equal(isolated.GIT_NO_REPLACE_OBJECTS, "1");

    const actual = trustedGitText(
      "git",
      ["rev-parse", "HEAD"],
      "GIT_SOURCE_COMMIT",
      { sourceEnvironment }
    );
    assert.match(actual, /^[0-9a-f]{40}$/);
    assert.equal(fs.existsSync(marker), false);
    assert.equal(trustedGitExecutable(), "/usr/bin/git");
    const gitMetadata = fs.statSync(trustedGitExecutable());
    assert.equal(gitMetadata.uid, 0);
    assert.equal((gitMetadata.mode & 0o022), 0);
    assert.notEqual((gitMetadata.mode & 0o111), 0);
    assert.throws(
      () =>
        trustedGitText(
          "git",
          ["config", "--list"],
          "GIT_UNREVIEWED",
          { sourceEnvironment }
        ),
      /GIT_COMMAND_NOT_ALLOWED/
    );
  } finally {
    fs.rmSync(fixtureRoot, { force: true, recursive: true });
  }
});

test("standalone preflight binds an explicit exact Git checkout", () => {
  const requests = [];
  const rootDir = path.resolve("/tmp/prooftoact-preflight-fixture");
  const checkout = trustedGitCheckout({
    rootDir,
    verifyRepositoryLayout: () => ({ rootDir }),
    readCommandText(_command, args) {
      requests.push(args);
      if (args.join(" ") === "rev-parse HEAD") {
        return "a".repeat(40);
      }
      if (args.join(" ") === "rev-parse HEAD^{tree}") {
        return "b".repeat(40);
      }
      if (
        args.join(" ") ===
        "status --porcelain=v1 --untracked-files=all"
      ) {
        return "";
      }
      throw new Error("UNEXPECTED_TEST_COMMAND");
    },
    verifyCheckout(value) {
      assert.deepEqual(value, {
        rootDir,
        sourceCommit: "a".repeat(40),
        treeDigest: "b".repeat(40)
      });
      return value;
    }
  });
  assert.deepEqual(checkout, {
    sourceCommit: "a".repeat(40),
    treeDigest: "b".repeat(40),
    workingTreeClean: true
  });
  assert.deepEqual(requests, [
    ["rev-parse", "HEAD"],
    ["rev-parse", "HEAD^{tree}"],
    ["status", "--porcelain=v1", "--untracked-files=all"]
  ]);
});

test("trusted Git rejects unapproved paths, owners, and writable modes", () => {
  const fixtureRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "prooftoact-trusted-git-")
  );
  try {
    const candidate = path.join(fixtureRoot, "git");
    fs.writeFileSync(candidate, "#!/bin/sh\nexit 0\n", {
      mode: 0o700
    });
    assert.equal(
      trustedGitExecutable({
        platform: "darwin",
        candidatePaths: [candidate],
        resolvedPaths: [candidate],
        expectedOwnerUid: process.getuid()
      }),
      candidate
    );
    assert.throws(
      () =>
        trustedGitExecutable({
          platform: "darwin",
          candidatePaths: [candidate],
          resolvedPaths: [path.join(fixtureRoot, "other", "git")],
          expectedOwnerUid: process.getuid()
        }),
      /GIT_TRUSTED_EXECUTABLE/
    );
    assert.throws(
      () =>
        trustedGitExecutable({
          platform: "darwin",
          candidatePaths: [candidate],
          resolvedPaths: [candidate],
          expectedOwnerUid: process.getuid() + 1
        }),
      /GIT_TRUSTED_EXECUTABLE/
    );
    fs.chmodSync(candidate, 0o722);
    assert.throws(
      () =>
        trustedGitExecutable({
          platform: "darwin",
          candidatePaths: [candidate],
          resolvedPaths: [candidate],
          expectedOwnerUid: process.getuid()
        }),
      /GIT_TRUSTED_EXECUTABLE/
    );
  } finally {
    fs.rmSync(fixtureRoot, { force: true, recursive: true });
  }
});

const PREFLIGHT_BINDING_CONTEXT = Object.freeze({
  purpose: "gate2-read-only-preflight",
  sourceCommit: "a".repeat(40),
  treeDigest: "b".repeat(40)
});

test("AWS preflight validates a self-consistent identity expectation before STS", () => {
  const expectation = awsPreflightIdentityExpectation(
    expectedPreflightEnvironment(),
    PREFLIGHT_BINDING_CONTEXT
  );
  assert.deepEqual(expectation, {
    expectedAccountId: ACCOUNT_ID,
    expectedPrincipalArn:
      `arn:aws:iam::${ACCOUNT_ID}:role/ProofToActPreflight`,
    expectedCallerArn:
      `arn:aws:sts::${ACCOUNT_ID}:assumed-role/` +
      "ProofToActPreflight/release-proof",
    expectedCallerUserId: "AROAPROOFTOACTROLE1:release-proof"
  });

  assert.throws(
    () =>
      awsPreflightIdentityExpectation(
        expectedPreflightEnvironment({
          AWS_EVIDENCE_EXPECTED_PREFLIGHT_PRINCIPAL_ARN:
            "arn:aws:iam::222222222222:role/ProofToActPreflight"
        }),
        PREFLIGHT_BINDING_CONTEXT
      ),
    /AWS_PREFLIGHT_EXPECTED_ROLE/
  );

  for (const [overrides, expectedCode] of [
    [
      {
        AWS_EVIDENCE_EXPECTED_PREFLIGHT_PRINCIPAL_ARN:
          `arn:aws:iam::${ACCOUNT_ID}:role/OtherReadOnlyRole`,
        AWS_EVIDENCE_EXPECTED_PREFLIGHT_CALLER_ARN:
          `arn:aws:sts::${ACCOUNT_ID}:assumed-role/` +
          "OtherReadOnlyRole/release-proof"
      },
      "AWS_PREFLIGHT_EXPECTED_ROLE"
    ],
    [
      {
        AWS_EVIDENCE_EXPECTED_PREFLIGHT_PRINCIPAL_ARN:
          `arn:aws:iam::${ACCOUNT_ID}:role/team/ProofToActPreflight`
      },
      "AWS_PREFLIGHT_EXPECTED_ROLE"
    ],
    [
      {
        AWS_EVIDENCE_EXPECTED_PREFLIGHT_CALLER_ARN:
          `arn:aws:sts::${ACCOUNT_ID}:assumed-role/` +
          "ProofToActPreflight/other-session",
        AWS_EVIDENCE_EXPECTED_PREFLIGHT_CALLER_USER_ID:
          "AROAPROOFTOACTROLE1:other-session"
      },
      "AWS_PREFLIGHT_EXPECTED_CALLER_ARN"
    ],
    [
      {
        AWS_EVIDENCE_EXPECTED_PREFLIGHT_CALLER_USER_ID:
          "AROAPROOFTOACTROLE1:other-session"
      },
      "AWS_PREFLIGHT_EXPECTED_CALLER_USER_ID"
    ]
  ]) {
    assert.throws(
      () =>
        awsPreflightIdentityExpectation(
          expectedPreflightEnvironment(overrides),
          PREFLIGHT_BINDING_CONTEXT
        ),
      new RegExp(expectedCode)
    );
  }
});

function exactCheckout() {
  return {
    sourceCommit: "a".repeat(40),
    treeDigest: "b".repeat(40),
    workingTreeClean: true
  };
}

test("AWS preflight rejects every non-lane identity expectation before STS", () => {
  const validUserArn =
    `arn:aws:iam::${ACCOUNT_ID}:user/prooftoact-preflight`;
  for (const overrides of [
    {
      AWS_EVIDENCE_EXPECTED_PREFLIGHT_PRINCIPAL_ARN: validUserArn,
      AWS_EVIDENCE_EXPECTED_PREFLIGHT_CALLER_ARN: validUserArn,
      AWS_EVIDENCE_EXPECTED_PREFLIGHT_CALLER_USER_ID:
        "AIDAPROOFTOACT001"
    },
    {
      AWS_EVIDENCE_EXPECTED_PREFLIGHT_PRINCIPAL_ARN:
        `arn:aws:iam::${ACCOUNT_ID}:user/release operator`,
      AWS_EVIDENCE_EXPECTED_PREFLIGHT_CALLER_ARN:
        `arn:aws:iam::${ACCOUNT_ID}:user/release operator`,
      AWS_EVIDENCE_EXPECTED_PREFLIGHT_CALLER_USER_ID:
        "AIDAPROOFTOACT001"
    },
    {
      AWS_EVIDENCE_EXPECTED_PREFLIGHT_PRINCIPAL_ARN: validUserArn,
      AWS_EVIDENCE_EXPECTED_PREFLIGHT_CALLER_ARN: validUserArn,
      AWS_EVIDENCE_EXPECTED_PREFLIGHT_CALLER_USER_ID:
        "not an AWS principal id"
    }
  ]) {
    let awsCallCount = 0;
    assert.throws(
      () =>
        collectSnapshot(new Date("2026-08-04T23:08:00.000Z"), {
          environment: expectedPreflightEnvironment(overrides),
          readGitCheckout: exactCheckout,
          readAwsJson() {
            awsCallCount += 1;
            throw new Error("AWS_CALL_MUST_NOT_OCCUR");
          }
        }),
      /(?:AWS_EVIDENCE_(?:EXPECTED_PRINCIPAL|CALLER_USER_ID)|AWS_PREFLIGHT_EXPECTED_(?:ROLE|CALLER_ARN|CALLER_USER_ID))/
    );
    assert.equal(awsCallCount, 0);
  }
});

test("AWS preflight stops after STS when the caller misses its expectation", () => {
  const awsCalls = [];
  const readAwsJson = (_region, service, operation) => {
    awsCalls.push({ service, operation });
    assert.equal(service, "sts");
    assert.equal(operation, "get-caller-identity");
    return {
      Account: "222222222222",
      Arn:
        "arn:aws:sts::222222222222:assumed-role/" +
        "ProofToActPreflight/release-proof",
      UserId: "AROAPROOFTOACTROLE1:release-proof"
    };
  };

  assert.throws(
    () =>
      collectSnapshot(new Date("2026-08-04T23:08:00.000Z"), {
        environment: expectedPreflightEnvironment(),
        readGitCheckout: exactCheckout,
        readAwsJson
      }),
    /AWS_EVIDENCE_CALLER_ACCOUNT/
  );
  assert.deepEqual(awsCalls, [
    { service: "sts", operation: "get-caller-identity" }
  ]);
});

test("AWS preflight runtime reader enforces the exact ordered call cardinality", () => {
  const observed = [];
  const reader = createAwsPreflightRuntimeCallReader(
    (region, service, operation, args) => {
      observed.push({ region, service, operation, args });
      return {};
    }
  );
  for (const [service, operation, cardinality] of
    AWS_GATE2_PREFLIGHT_RUNTIME_CALL_INVENTORY) {
    for (let index = 0; index < cardinality; index += 1) {
      reader.read("us-east-1", service, operation, []);
    }
  }
  assert.equal(reader.assertComplete(), 17);
  assert.equal(observed.length, 17);
  assert.throws(
    () => reader.read("us-east-1", "sts", "get-caller-identity"),
    /AWS_RUNTIME_CALL_INVENTORY/
  );

  const incomplete = createAwsPreflightRuntimeCallReader(() => ({}));
  incomplete.read("us-east-1", "sts", "get-caller-identity");
  assert.throws(
    () => incomplete.assertComplete(),
    /AWS_RUNTIME_CALL_CARDINALITY/
  );

  const wrong = createAwsPreflightRuntimeCallReader(() => ({}));
  assert.throws(
    () => wrong.read("us-west-2", "sts", "get-caller-identity"),
    /AWS_RUNTIME_CALL_INVENTORY/
  );
});

test("AWS preflight reader converts all raw failures to fixed ordinal diagnostics", () => {
  const calls = AWS_GATE2_PREFLIGHT_RUNTIME_CALL_INVENTORY.flatMap(
    ([service, operation, cardinality]) =>
      Array.from({ length: cardinality }, () => [service, operation])
  );
  assert.equal(calls.length, 17);
  assert.deepEqual(
    AWS_GATE2_PREFLIGHT_RUNTIME_FAILURES,
    Array.from({ length: 17 }, (_, index) => ({
      stage: `AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_${String(
        index + 1
      ).padStart(2, "0")}`,
      exitCode: 40 + index
    }))
  );

  for (let target = 0; target < calls.length; target += 1) {
    let callIndex = 0;
    const reader = createAwsPreflightRuntimeCallReader(() => {
      const observed = callIndex;
      callIndex += 1;
      if (observed === target) {
        throw new Error(`SECRET_RAW_PROVIDER_FAILURE_${target}`);
      }
      return {};
    });
    let caught;
    for (let index = 0; index <= target; index += 1) {
      const [service, operation] = calls[index];
      try {
        reader.read("us-east-1", service, operation, []);
      } catch (error) {
        caught = error;
      }
    }
    assert(caught instanceof Error);
    assert.equal(caught.message, "AWS_RUNTIME_READ_FAILURE");
    assert.deepEqual(
      awsPreflightRuntimeFailureDescriptor(caught),
      AWS_GATE2_PREFLIGHT_RUNTIME_FAILURES[target]
    );
    assert.doesNotMatch(
      caught.message,
      /SECRET_RAW_PROVIDER_FAILURE/u
    );
  }

  assert.deepEqual(
    awsPreflightRuntimeFailureDescriptor(
      new Error("SECRET_RAW_PROVIDER_FAILURE")
    ),
    { stage: "UNCLASSIFIED_CAUGHT", exitCode: 85 }
  );
});

test("AWS preflight non-read diagnostics use the exact fixed phase and control maps", () => {
  assert.deepEqual(
    AWS_GATE2_PREFLIGHT_RUNTIME_PHASE_FAILURES,
    [
      ["CHILD_ENVIRONMENT", 60],
      ["SOURCE_CHECKOUT", 61],
      ["EXPECTED_IDENTITY", 62],
      ["CALL_INVENTORY", 63],
      ["CALLER_RECEIPT", 64],
      ["BOOTSTRAP_RECEIPT", 65],
      ["BUDGET_RECEIPT", 66],
      ["NOTIFICATION_RECEIPT", 67],
      ["SUBSCRIBER_RECEIPT", 68],
      ["COST_REQUEST_PREPARE", 69],
      ["BUCKET_POLICY_RECEIPT", 70],
      ["STACK_CENSUS_RECEIPT", 71],
      ["SNAPSHOT_COMPLETE", 72],
      ["RECEIPT_OUTPUT", 83],
      ["ARGUMENT", 84],
      ["UNCLASSIFIED_CAUGHT", 85]
    ].map(([stage, exitCode]) => ({ stage, exitCode }))
  );
  assert.deepEqual(
    AWS_GATE2_PREFLIGHT_RUNTIME_CONTROL_FAILURES,
    AWS_GATE2_PREFLIGHT_CONTROL_FAILURES.map((stage, index) => ({
      stage,
      exitCode: 73 + index
    }))
  );
});

test("AWS preflight phase diagnostics discard raw causes and preserve read ordinals", () => {
  const rawSecret = "SECRET_RAW_CHILD_FAILURE_7f4d";
  let phaseFailure;
  try {
    collectSnapshot(new Date("2026-08-04T23:08:00.000Z"), {
      diagnosticFailureMode: true,
      environment: expectedPreflightEnvironment({
        NODE_OPTIONS: `--require=${rawSecret}`
      }),
      readGitCheckout: exactCheckout,
      readAwsJson() {
        throw new Error("AWS_CALL_MUST_NOT_OCCUR");
      }
    });
  } catch (error) {
    phaseFailure = error;
  }
  assert(phaseFailure instanceof Error);
  assert.equal(phaseFailure.message, "AWS_RUNTIME_PHASE_FAILURE");
  assert.deepEqual(
    awsPreflightRuntimeFailureDescriptor(phaseFailure),
    { stage: "CHILD_ENVIRONMENT", exitCode: 60 }
  );
  assert.doesNotMatch(String(phaseFailure), new RegExp(rawSecret));

  let readFailure;
  try {
    collectSnapshot(new Date("2026-08-04T23:08:00.000Z"), {
      diagnosticFailureMode: true,
      environment: expectedPreflightEnvironment(),
      readGitCheckout: exactCheckout,
      readAwsJson() {
        throw new Error(rawSecret);
      }
    });
  } catch (error) {
    readFailure = error;
  }
  assert(readFailure instanceof Error);
  assert.equal(readFailure.message, "AWS_RUNTIME_READ_FAILURE");
  assert.deepEqual(
    awsPreflightRuntimeFailureDescriptor(readFailure),
    AWS_GATE2_PREFLIGHT_RUNTIME_FAILURES[0]
  );
  assert.doesNotMatch(String(readFailure), new RegExp(rawSecret));
});

function notification(
  notificationType,
  threshold,
  subscribers = [
    {
      SubscriptionType: "EMAIL",
      Address: "private@example.invalid"
    }
  ]
) {
  return {
    notification: {
      NotificationType: notificationType,
      ComparisonOperator: "GREATER_THAN",
      Threshold: threshold,
      ThresholdType: "ABSOLUTE_VALUE"
    },
    subscribers
  };
}

function validSnapshot() {
  return {
    observedAt: "2026-07-30T19:30:00.000Z",
    sourceCommit: "a".repeat(40),
    treeDigest: "b".repeat(40),
    workingTreeClean: true,
    region: "us-east-1",
    expectedAccountId: ACCOUNT_ID,
    expectedPrincipalArn:
      `arn:aws:iam::${ACCOUNT_ID}:role/ProofToActPreflight`,
    expectedCallerArn:
      `arn:aws:sts::${ACCOUNT_ID}:assumed-role/` +
      "ProofToActPreflight/release-proof",
    expectedCallerUserId: "AROAPROOFTOACTROLE1:release-proof",
    callerIdentity: {
      Account: ACCOUNT_ID,
      Arn:
        `arn:aws:sts::${ACCOUNT_ID}:assumed-role/` +
        "ProofToActPreflight/release-proof",
      UserId: "AROAPROOFTOACTROLE1:release-proof"
    },
    bootstrapStackName: BOOTSTRAP_STACK,
    bootstrapStack: {
      StackName: BOOTSTRAP_STACK,
      StackStatus: "UPDATE_COMPLETE",
      Outputs: [
        {
          OutputKey: "AccountBudgetName",
          OutputValue: BUDGET_NAME
        },
        {
          OutputKey: "ArtifactBucketName",
          OutputValue: BUCKET_NAME
        }
      ]
    },
    budget: {
      BudgetName: BUDGET_NAME,
      BudgetType: "COST",
      TimeUnit: "MONTHLY",
      CostTypes: {
        IncludeCredit: true,
        IncludeDiscount: true,
        IncludeOtherSubscription: true,
        IncludeRecurring: true,
        IncludeRefund: true,
        IncludeSubscription: true,
        IncludeSupport: true,
        IncludeTax: true,
        IncludeUpfront: true,
        UseAmortized: false,
        UseBlended: false
      },
      BudgetLimit: { Amount: "15", Unit: "USD" },
      TimePeriod: {
        Start: "2026-07-01T00:00:00.000Z",
        End: "2087-06-15T00:00:00.000Z"
      },
      CalculatedSpend: {
        ActualSpend: { Amount: "0.25", Unit: "USD" }
      }
    },
    notificationSubscribers: [
      notification("ACTUAL", 1),
      notification("ACTUAL", 5),
      notification("ACTUAL", 10),
      notification("FORECASTED", 15)
    ],
    artifactBucket: {
      versioning: { Status: "Enabled" },
      encryption: {
        ServerSideEncryptionConfiguration: {
          Rules: [
            {
              ApplyServerSideEncryptionByDefault: {
                SSEAlgorithm: "AES256"
              }
            }
          ]
        }
      },
      publicAccessBlock: {
        PublicAccessBlockConfiguration: {
          BlockPublicAcls: true,
          BlockPublicPolicy: true,
          IgnorePublicAcls: true,
          RestrictPublicBuckets: true
        }
      },
      ownership: {
        OwnershipControls: {
          Rules: [{ ObjectOwnership: "BucketOwnerEnforced" }]
        }
      },
      policyStatus: { PolicyStatus: { IsPublic: false } },
      policy: {
        Version: "2012-10-17",
        Statement: [
          {
            Sid: "DenyInsecureTransport",
            Effect: "Deny",
            Principal: "*",
            Action: "s3:*",
            Resource: [
              `arn:aws:s3:::${BUCKET_NAME}`,
              `arn:aws:s3:::${BUCKET_NAME}/*`
            ],
            Condition: {
              Bool: { "aws:SecureTransport": "false" }
            }
          }
        ]
      }
    },
    mainStackName: "prooftoact-gate2",
    legacyMainStackName: "tideproof-gate2",
    stackSummaries: [
      {
        StackName: "deleted-unrelated-stack",
        StackStatus: "DELETE_COMPLETE"
      }
    ],
    currentCost: {
      periodStart: "2026-07-01",
      periodEndExclusive: "2026-07-31",
      response: {
        ResultsByTime: [
          {
            TimePeriod: {
              Start: "2026-07-01",
              End: "2026-07-31"
            },
            Estimated: true,
            Total: {
              UnblendedCost: { Amount: "0.20", Unit: "USD" }
            }
          }
        ]
      }
    },
    foundationModel: {
      modelDetails: {
        modelId: "amazon.nova-micro-v1:0",
        modelLifecycle: { status: "ACTIVE" },
        inputModalities: ["TEXT"],
        outputModalities: ["TEXT"],
        inferenceTypesSupported: ["ON_DEMAND"]
      }
    }
  };
}

test("AWS preflight collector completes only the exact 17-call inventory", () => {
  const fixture = validSnapshot();
  const responses = [
    fixture.callerIdentity,
    { Stacks: [fixture.bootstrapStack] },
    { Budget: fixture.budget },
    {
      Notifications: fixture.notificationSubscribers.map(
        ({ notification: entry }) => entry
      )
    },
    ...fixture.notificationSubscribers.map(({ subscribers }) => ({
      Subscribers: subscribers
    })),
    fixture.currentCost.response,
    fixture.artifactBucket.versioning,
    fixture.artifactBucket.encryption,
    fixture.artifactBucket.publicAccessBlock,
    fixture.artifactBucket.ownership,
    fixture.artifactBucket.policyStatus,
    { Policy: JSON.stringify(fixture.artifactBucket.policy) },
    { StackSummaries: fixture.stackSummaries },
    fixture.foundationModel
  ];
  const observedCalls = [];
  const collected = collectSnapshot(
    new Date(fixture.observedAt),
    {
      environment: expectedPreflightEnvironment(),
      readGitCheckout: exactCheckout,
      readAwsJson(region, service, operation, args) {
        observedCalls.push([region, service, operation, args]);
        return responses.shift();
      }
    }
  );
  assert.equal(responses.length, 0);
  assert.equal(observedCalls.length, 17);
  assert.deepEqual(
    observedCalls.map(([, service, operation]) => [service, operation]),
    AWS_GATE2_PREFLIGHT_RUNTIME_CALL_INVENTORY.flatMap(
      ([service, operation, cardinality]) =>
        Array.from({ length: cardinality }, () => [service, operation])
    )
  );
  assert.equal(validateAwsGate2Preflight(collected).status, "PASS");
});

test("AWS preflight validation diagnostics identify every fixed control domain", () => {
  const cases = [
    {
      index: 0,
      rawCode: "AWS_REGION",
      mutate(snapshot) {
        snapshot.region = "us-west-2";
      }
    },
    {
      index: 1,
      rawCode: "BOOTSTRAP_STACK_STATUS",
      mutate(snapshot) {
        snapshot.bootstrapStack.StackStatus = "ROLLBACK_COMPLETE";
      }
    },
    {
      index: 2,
      rawCode: "SECRET_BUDGET_CONTROL_FAILURE",
      mutate(snapshot) {
        Object.defineProperty(snapshot, "budget", {
          configurable: true,
          get() {
            throw new Error("SECRET_BUDGET_CONTROL_FAILURE");
          }
        });
      }
    },
    {
      index: 3,
      rawCode: "BUDGET_NOTIFICATION_CARDINALITY",
      mutate(snapshot) {
        snapshot.notificationSubscribers = [];
      }
    },
    {
      index: 4,
      rawCode: "MAIN_STACK_ALREADY_PRESENT",
      mutate(snapshot) {
        snapshot.stackSummaries.push({
          StackName: snapshot.mainStackName,
          StackStatus: "CREATE_COMPLETE"
        });
      }
    },
    {
      index: 5,
      rawCode: "ARTIFACT_BUCKET_VERSIONING",
      mutate(snapshot) {
        snapshot.artifactBucket.versioning.Status = "Suspended";
      }
    },
    {
      index: 6,
      rawCode: "SECRET_COST_CONTROL_FAILURE",
      mutate(snapshot) {
        Object.defineProperty(snapshot, "currentCost", {
          configurable: true,
          get() {
            throw new Error("SECRET_COST_CONTROL_FAILURE");
          }
        });
      }
    },
    {
      index: 7,
      rawCode: "PREFLIGHT_ALLOWANCE_AWS_CEILING",
      mutate(snapshot) {
        snapshot.budget.CalculatedSpend.ActualSpend.Amount = "13.12";
      }
    },
    {
      index: 8,
      rawCode: "BEDROCK_MODEL_LIFECYCLE",
      mutate(snapshot) {
        snapshot.foundationModel.modelDetails.modelLifecycle.status =
          "LEGACY";
      }
    }
  ];

  for (const { index, rawCode, mutate } of cases) {
    const rawSnapshot = validSnapshot();
    mutate(rawSnapshot);
    assert.throws(
      () => validateAwsGate2Preflight(rawSnapshot),
      new RegExp(rawCode)
    );

    const diagnosticSnapshot = validSnapshot();
    mutate(diagnosticSnapshot);
    const diagnosticContext =
      createAwsGate2PreflightDiagnosticContext();
    let diagnosticFailure;
    try {
      validateAwsGate2Preflight(diagnosticSnapshot, {
        diagnosticFailureMode: true,
        diagnosticContext
      });
    } catch (error) {
      diagnosticFailure = error;
    }
    assert(
      diagnosticFailure instanceof AwsGate2PreflightControlFailure
    );
    assert.equal(
      diagnosticFailure.message,
      "AWS_GATE2_PREFLIGHT_CONTROL_FAILURE"
    );
    assert.deepEqual(
      awsPreflightRuntimeFailureDescriptor(
        diagnosticFailure,
        diagnosticContext
      ),
      AWS_GATE2_PREFLIGHT_RUNTIME_CONTROL_FAILURES[index]
    );
    assert.doesNotMatch(String(diagnosticFailure), new RegExp(rawCode));
  }

  const receiptFailureCode = "SECRET_RECEIPT_ASSEMBLY_FAILURE";
  const receiptFailureSnapshot = validSnapshot();
  const observedAt = receiptFailureSnapshot.observedAt;
  let observedAtReads = 0;
  Object.defineProperty(receiptFailureSnapshot, "observedAt", {
    configurable: true,
    get() {
      observedAtReads += 1;
      if (observedAtReads === 4) {
        throw new Error(receiptFailureCode);
      }
      return observedAt;
    }
  });
  const receiptFailureContext =
    createAwsGate2PreflightDiagnosticContext();
  let receiptFailure;
  try {
    validateAwsGate2Preflight(receiptFailureSnapshot, {
      diagnosticFailureMode: true,
      diagnosticContext: receiptFailureContext
    });
  } catch (error) {
    receiptFailure = error;
  }
  assert(receiptFailure instanceof AwsGate2PreflightControlFailure);
  assert.deepEqual(
    awsPreflightRuntimeFailureDescriptor(
      receiptFailure,
      receiptFailureContext
    ),
    AWS_GATE2_PREFLIGHT_RUNTIME_CONTROL_FAILURES[9]
  );
  assert.doesNotMatch(String(receiptFailure), /SECRET_RECEIPT/u);
});

test("AWS preflight budget diagnostics identify all fixed semantic predicates", () => {
  const cases = [
    ["BUDGET_NAME", (s) => { s.budget.BudgetName = "wrong"; }],
    ["BUDGET_TYPE", (s) => { s.budget.BudgetType = "USAGE"; }],
    ["BUDGET_TIME_UNIT", (s) => { s.budget.TimeUnit = "DAILY"; }],
    ["BUDGET_COST_FILTERS_ACCOUNT_WIDE", (s) => {
      s.budget.CostFilters = { Service: ["private"] };
    }],
    ["BUDGET_FILTER_EXPRESSION_ACCOUNT_WIDE", (s) => {
      s.budget.FilterExpression = { Not: {} };
    }],
    ["BUDGET_BILLING_VIEW_ACCOUNT_WIDE", (s) => {
      s.budget.BillingViewArn = "private";
    }],
    ["BUDGET_AUTO_ADJUST_NOT_FIXED", (s) => {
      s.budget.AutoAdjustData = {};
    }],
    ["BUDGET_PLANNED_LIMITS_NOT_FIXED", (s) => {
      s.budget.PlannedBudgetLimits = { "1": {} };
    }],
    ["BUDGET_METRICS_MODEL", (s) => {
      s.budget.Metrics = ["AmortizedCost"];
    }],
    ["BUDGET_COST_TYPES", (s) => {
      s.budget.CostTypes.UseBlended = true;
    }],
    ["BUDGET_TIME_PERIOD_START", (s) => {
      s.budget.TimePeriod.Start = "invalid";
    }],
    ["BUDGET_TIME_PERIOD_END", (s) => {
      s.budget.TimePeriod.End = "invalid";
    }],
    ["BUDGET_TIME_PERIOD_ORDER", (s) => {
      s.budget.TimePeriod.Start = "2088-01-01T00:00:00.000Z";
    }],
    ["BUDGET_TIME_PERIOD_NOT_STARTED", (s) => {
      s.budget.TimePeriod.Start = "2026-08-01T00:00:00.000Z";
    }],
    ["BUDGET_TIME_PERIOD_EXPIRED", (s) => {
      s.budget.TimePeriod.End = "2026-07-15T00:00:00.000Z";
    }],
    ["BUDGET_TIME_PERIOD_RELEASE_HORIZON", (s) => {
      s.budget.TimePeriod.End = "2026-08-31T00:00:00.000Z";
    }],
    ["BUDGET_LIMIT_UNIT", (s) => {
      s.budget.BudgetLimit.Unit = "EUR";
    }],
    ["BUDGET_LIMIT_AMOUNT", (s) => {
      s.budget.BudgetLimit.Amount = "invalid";
    }],
    ["BUDGET_LIMIT_NEGATIVE", (s) => {
      s.budget.BudgetLimit.Amount = "-1";
    }],
    ["BUDGET_LIMIT_VALUE", (s) => {
      s.budget.BudgetLimit.Amount = "16";
    }],
    ["BUDGET_ACTUAL_UNIT", (s) => {
      s.budget.CalculatedSpend.ActualSpend.Unit = "EUR";
    }],
    ["BUDGET_ACTUAL_AMOUNT", (s) => {
      s.budget.CalculatedSpend.ActualSpend.Amount = "invalid";
    }],
    ["BUDGET_ACTUAL_NEGATIVE", (s) => {
      s.budget.CalculatedSpend.ActualSpend.Amount = "-1";
    }],
    ["BUDGET_ACTUAL_CEILING", (s) => {
      s.budget.CalculatedSpend.ActualSpend.Amount = "13.14";
    }]
  ];

  assert.equal(cases.length, AWS_GATE2_PREFLIGHT_BUDGET_FAILURES.length);
  assert.equal(
    cases.length,
    AWS_GATE2_PREFLIGHT_RUNTIME_BUDGET_FAILURES.length
  );
  for (const [index, [rawCode, mutate]] of cases.entries()) {
    const rawSnapshot = validSnapshot();
    mutate(rawSnapshot);
    let rawFailure;
    try {
      validateAwsGate2Preflight(rawSnapshot);
    } catch (error) {
      rawFailure = error;
    }
    assert(rawFailure instanceof Error);
    assert.equal(rawFailure.name, "Error");
    assert.equal(rawFailure.message, rawCode);

    const diagnosticSnapshot = validSnapshot();
    mutate(diagnosticSnapshot);
    const diagnosticContext =
      createAwsGate2PreflightDiagnosticContext();
    let failure;
    try {
      validateAwsGate2Preflight(diagnosticSnapshot, {
        diagnosticFailureMode: true,
        diagnosticContext
      });
    } catch (error) {
      failure = error;
    }
    assert(failure instanceof Error);
    assert.equal(failure.name, "AwsGate2PreflightBudgetFailure");
    assert.equal(failure.message, "AWS_GATE2_PREFLIGHT_BUDGET_FAILURE");
    assert.equal(Object.isFrozen(failure), true);
    assert.equal(Object.hasOwn(failure, "index"), false);
    assert.equal(
      AWS_GATE2_PREFLIGHT_BUDGET_FAILURES[index],
      AWS_GATE2_PREFLIGHT_RUNTIME_BUDGET_FAILURES[index].stage
    );
    assert.deepEqual(
      awsPreflightRuntimeFailureDescriptor(failure, diagnosticContext),
      AWS_GATE2_PREFLIGHT_RUNTIME_BUDGET_FAILURES[index]
    );
    assert.deepEqual(
      awsPreflightRuntimeFailureDescriptor(failure, diagnosticContext),
      { stage: "UNCLASSIFIED_CAUGHT", exitCode: 85 }
    );
    assert.doesNotMatch(String(failure), new RegExp(rawCode));
    assert.doesNotMatch(
      String(failure),
      /private|AmortizedCost|UnblendedCost|13\.14|2088/u
    );
  }
});

test("AWS preflight cost diagnostics identify all fixed semantic predicates", () => {
  const replaceNumberToFixed = (replacement) => {
    const descriptor = Object.getOwnPropertyDescriptor(
      Number.prototype,
      "toFixed"
    );
    Object.defineProperty(Number.prototype, "toFixed", {
      ...descriptor,
      value() {
        return replacement;
      }
    });
    return () =>
      Object.defineProperty(Number.prototype, "toFixed", descriptor);
  };
  const replaceObservedAtOnThirdRead = (snapshot, replacement) => {
    const observedAt = snapshot.observedAt;
    let reads = 0;
    Object.defineProperty(snapshot, "observedAt", {
      configurable: true,
      get() {
        reads += 1;
        return reads === 3 ? replacement : observedAt;
      }
    });
  };
  const cases = [
    ["CURRENT_COST_OBSERVED_AT", (s) => {
      replaceObservedAtOnThirdRead(s, "invalid");
    }],
    ["CURRENT_COST_OBSERVED_AT_WINDOW", (s) => {
      replaceObservedAtOnThirdRead(s, "2026-06-30T12:00:00.000Z");
    }],
    ["CURRENT_COST_PERIOD_START", (s) => {
      s.currentCost.periodStart = "2026-06-01";
    }],
    ["CURRENT_COST_PERIOD_END", (s) => {
      s.currentCost.periodEndExclusive = "2026-07-30";
    }],
    ["CURRENT_COST_NEXT_PAGE_TOKEN", (s) => {
      s.currentCost.response.NextPageToken = "";
    }],
    ["CURRENT_COST_ROWS", (s) => {
      s.currentCost.response.ResultsByTime = [];
    }],
    ["CURRENT_COST_ROW_PERIOD", (s) => {
      s.currentCost.response.ResultsByTime[0].TimePeriod.End =
        "2026-07-30";
    }],
    ["CURRENT_COST_UNBLENDED_UNIT", (s) => {
      s.currentCost.response.ResultsByTime[0]
        .Total.UnblendedCost.Unit = "EUR";
    }],
    ["CURRENT_COST_UNBLENDED_AMOUNT", (s) => {
      s.currentCost.response.ResultsByTime[0]
        .Total.UnblendedCost.Amount = "invalid";
    }],
    ["CURRENT_COST_UNBLENDED_NEGATIVE", (s) => {
      s.currentCost.response.ResultsByTime[0]
        .Total.UnblendedCost.Amount = "-1";
    }],
    ["CURRENT_COST_UNBLENDED_DECIMAL", (s) => {
      s.currentCost.response.ResultsByTime[0]
        .Total.UnblendedCost.Amount = "1e-7";
    }],
    ["CURRENT_COST_UNBLENDED_RANGE", (s) => {
      s.currentCost.response.ResultsByTime[0]
        .Total.UnblendedCost.Amount = "9007199255";
    }],
    ["CURRENT_COST_UNBLENDED_TOTAL_RANGE", (s) => {
      s.observedAt = "2026-08-31T12:00:00.000Z";
      s.currentCost.periodEndExclusive = "2026-09-01";
      s.currentCost.response.ResultsByTime = [
        {
          TimePeriod: { Start: "2026-07-01", End: "2026-08-01" },
          Estimated: false,
          Total: {
            UnblendedCost: { Amount: "9007199254", Unit: "USD" }
          }
        },
        {
          TimePeriod: { Start: "2026-08-01", End: "2026-09-01" },
          Estimated: true,
          Total: {
            UnblendedCost: { Amount: "9007199254", Unit: "USD" }
          }
        }
      ];
    }],
    ["CURRENT_COST_CEILING_DECIMAL", () =>
      replaceNumberToFixed("invalid")],
    ["CURRENT_COST_CEILING_RANGE", () =>
      replaceNumberToFixed("9007199255")],
    ["CURRENT_COST_CEILING", (s) => {
      s.currentCost.response.ResultsByTime[0]
        .Total.UnblendedCost.Amount = "13.14";
    }]
  ];

  const capture = (mutate, options = undefined) => {
    const snapshot = validSnapshot();
    const cleanup = mutate(snapshot) ?? (() => {});
    try {
      validateAwsGate2Preflight(snapshot, options);
    } catch (error) {
      return error;
    } finally {
      cleanup();
    }
    assert.fail("expected cost validation failure");
  };

  assert.equal(cases.length, AWS_GATE2_PREFLIGHT_COST_FAILURES.length);
  assert.equal(
    cases.length,
    AWS_GATE2_PREFLIGHT_RUNTIME_COST_FAILURES.length
  );
  assert.deepEqual(
    AWS_GATE2_PREFLIGHT_RUNTIME_COST_FAILURES.map(
      ({ exitCode }) => exitCode
    ),
    [57, 58, ...Array.from({ length: 14 }, (_, index) => 110 + index)]
  );
  assert.equal(
    AWS_GATE2_PREFLIGHT_RUNTIME_COST_FAILURES.some(
      ({ exitCode }) => exitCode >= 124
    ),
    false
  );
  for (const [index, [rawCode, mutate]] of cases.entries()) {
    const rawFailure = capture(mutate);
    assert(rawFailure instanceof Error);
    assert.equal(rawFailure.name, "Error");
    assert.equal(rawFailure.message, rawCode);

    const diagnosticContext =
      createAwsGate2PreflightDiagnosticContext();
    const failure = capture(mutate, {
      diagnosticFailureMode: true,
      diagnosticContext
    });
    assert(failure instanceof Error);
    assert.equal(failure.name, "AwsGate2PreflightCostFailure");
    assert.equal(failure.message, "AWS_GATE2_PREFLIGHT_COST_FAILURE");
    assert.equal(Object.isFrozen(failure), true);
    assert.equal(Object.hasOwn(failure, "index"), false);
    assert.equal(
      AWS_GATE2_PREFLIGHT_COST_FAILURES[index],
      AWS_GATE2_PREFLIGHT_RUNTIME_COST_FAILURES[index].stage
    );
    assert.deepEqual(
      awsPreflightRuntimeFailureDescriptor(failure, diagnosticContext),
      AWS_GATE2_PREFLIGHT_RUNTIME_COST_FAILURES[index]
    );
    assert.deepEqual(
      awsPreflightRuntimeFailureDescriptor(failure, diagnosticContext),
      { stage: "UNCLASSIFIED_CAUGHT", exitCode: 85 }
    );
    assert.doesNotMatch(String(failure), new RegExp(rawCode));
    assert.doesNotMatch(
      String(failure),
      /2026|13\.14|9007199255|EUR|invalid|UnblendedCost/u
    );
  }
});

test("AWS preflight cost diagnostics reject forgery, replay, and cross-domain injection", () => {
  const snapshot = validSnapshot();
  snapshot.currentCost.response.ResultsByTime[0]
    .Total.UnblendedCost.Amount = "1e-7";
  const diagnosticContext = createAwsGate2PreflightDiagnosticContext();
  let original;
  try {
    validateAwsGate2Preflight(snapshot, {
      diagnosticFailureMode: true,
      diagnosticContext
    });
  } catch (error) {
    original = error;
  }
  assert(original instanceof Error);
  assert.equal(Object.isFrozen(original), true);
  assert.equal(Object.hasOwn(original, "index"), false);
  assert.throws(
    () => Object.defineProperty(original, "index", { value: 15 }),
    TypeError
  );

  const LeakedErrorConstructor = original.constructor;
  const constructorForgery = new LeakedErrorConstructor(
    "AWS_GATE2_PREFLIGHT_COST_FAILURE"
  );
  if (Object.isExtensible(constructorForgery)) {
    Object.assign(constructorForgery, {
      name: "AwsGate2PreflightCostFailure",
      index: 15
    });
  }
  assert.deepEqual(
    awsPreflightRuntimeFailureDescriptor(
      constructorForgery,
      diagnosticContext
    ),
    { stage: "UNCLASSIFIED_CAUGHT", exitCode: 85 }
  );

  const forged = Object.assign(new Error("PRIVATE_FORGED_FAILURE"), {
    name: "AwsGate2PreflightCostFailure",
    index: 15
  });
  assert.deepEqual(
    awsPreflightRuntimeFailureDescriptor(forged, diagnosticContext),
    { stage: "UNCLASSIFIED_CAUGHT", exitCode: 85 }
  );

  const injectedSnapshot = validSnapshot();
  Object.defineProperty(injectedSnapshot, "currentCost", {
    configurable: true,
    get() {
      throw original;
    }
  });
  const injectedContext = createAwsGate2PreflightDiagnosticContext();
  let injectedFailure;
  try {
    validateAwsGate2Preflight(injectedSnapshot, {
      diagnosticFailureMode: true,
      diagnosticContext: injectedContext
    });
  } catch (error) {
    injectedFailure = error;
  }
  assert(injectedFailure instanceof AwsGate2PreflightControlFailure);
  assert.deepEqual(
    awsPreflightRuntimeFailureDescriptor(
      injectedFailure,
      injectedContext
    ),
    AWS_GATE2_PREFLIGHT_RUNTIME_CONTROL_FAILURES[6]
  );
  assert.deepEqual(
    awsPreflightRuntimeFailureDescriptor(original, injectedContext),
    { stage: "UNCLASSIFIED_CAUGHT", exitCode: 85 }
  );
  assert.deepEqual(
    awsPreflightRuntimeFailureDescriptor(original, diagnosticContext),
    AWS_GATE2_PREFLIGHT_RUNTIME_COST_FAILURES[10]
  );
  assert.deepEqual(
    awsPreflightRuntimeFailureDescriptor(original, diagnosticContext),
    { stage: "UNCLASSIFIED_CAUGHT", exitCode: 85 }
  );

  const wrongDomainSnapshot = validSnapshot();
  Object.defineProperty(wrongDomainSnapshot.budget, "BudgetType", {
    configurable: true,
    get() {
      throw original;
    }
  });
  const wrongDomainContext = createAwsGate2PreflightDiagnosticContext();
  let wrongDomainFailure;
  try {
    validateAwsGate2Preflight(wrongDomainSnapshot, {
      diagnosticFailureMode: true,
      diagnosticContext: wrongDomainContext
    });
  } catch (error) {
    wrongDomainFailure = error;
  }
  assert.deepEqual(
    awsPreflightRuntimeFailureDescriptor(
      wrongDomainFailure,
      wrongDomainContext
    ),
    AWS_GATE2_PREFLIGHT_RUNTIME_BUDGET_FAILURES[1]
  );
});

test("AWS preflight cost diagnostics retain the broad unexpected-error fallback", () => {
  const snapshot = validSnapshot();
  Object.defineProperty(snapshot.currentCost.response, "ResultsByTime", {
    configurable: true,
    get() {
      throw new Error("SECRET_UNEXPECTED_COST_FAILURE");
    }
  });
  const diagnosticContext = createAwsGate2PreflightDiagnosticContext();
  let failure;
  try {
    validateAwsGate2Preflight(snapshot, {
      diagnosticFailureMode: true,
      diagnosticContext
    });
  } catch (error) {
    failure = error;
  }
  assert(failure instanceof AwsGate2PreflightControlFailure);
  assert.deepEqual(
    awsPreflightRuntimeFailureDescriptor(failure, diagnosticContext),
    AWS_GATE2_PREFLIGHT_RUNTIME_CONTROL_FAILURES[6]
  );
  assert.doesNotMatch(String(failure), /SECRET_UNEXPECTED_COST_FAILURE/u);
});

test("AWS preflight budget diagnostics reject forgery, replay, and cross-invocation injection", () => {
  const captureBudgetFailure = (mutate) => {
    const snapshot = validSnapshot();
    mutate(snapshot);
    const diagnosticContext =
      createAwsGate2PreflightDiagnosticContext();
    let error;
    try {
      validateAwsGate2Preflight(snapshot, {
        diagnosticFailureMode: true,
        diagnosticContext
      });
    } catch (caught) {
      error = caught;
    }
    assert(error instanceof Error);
    return { diagnosticContext, error };
  };

  const original = captureBudgetFailure((snapshot) => {
    snapshot.budget.Metrics = ["AmortizedCost"];
  });
  let runtimePhaseFailure;
  try {
    collectSnapshot(new Date("2026-08-04T23:08:00.000Z"), {
      diagnosticFailureMode: true,
      environment: expectedPreflightEnvironment(),
      readGitCheckout() {
        throw original.error;
      },
      readAwsJson() {
        throw new Error("AWS_CALL_MUST_NOT_OCCUR");
      }
    });
  } catch (error) {
    runtimePhaseFailure = error;
  }
  assert.deepEqual(
    awsPreflightRuntimeFailureDescriptor(runtimePhaseFailure),
    { stage: "SOURCE_CHECKOUT", exitCode: 61 }
  );
  assert.equal(Object.isFrozen(original.error), true);
  assert.equal(Object.hasOwn(original.error, "index"), false);
  assert.throws(
    () => Object.defineProperty(original.error, "index", { value: 23 }),
    TypeError
  );
  const LeakedErrorConstructor = original.error.constructor;
  const constructorForgery = new LeakedErrorConstructor(
    23,
    original.diagnosticContext
  );
  if (Object.isExtensible(constructorForgery)) {
    Object.assign(constructorForgery, {
      name: "AwsGate2PreflightBudgetFailure",
      index: 23
    });
  }
  assert.deepEqual(
    awsPreflightRuntimeFailureDescriptor(
      constructorForgery,
      original.diagnosticContext
    ),
    { stage: "UNCLASSIFIED_CAUGHT", exitCode: 85 }
  );

  const forgedContext = createAwsGate2PreflightDiagnosticContext();
  assert.equal(
    validateAwsGate2Preflight(validSnapshot(), {
      diagnosticFailureMode: true,
      diagnosticContext: forgedContext
    }).status,
    "PASS"
  );
  const forged = Object.assign(new Error("PRIVATE_FORGED_FAILURE"), {
    name: "AwsGate2PreflightBudgetFailure",
    index: 23
  });
  assert.deepEqual(
    awsPreflightRuntimeFailureDescriptor(forged, forgedContext),
    { stage: "UNCLASSIFIED_CAUGHT", exitCode: 85 }
  );

  const constructorInjectionContext =
    createAwsGate2PreflightDiagnosticContext();
  const constructorInjectionSnapshot = validSnapshot();
  Object.defineProperty(
    constructorInjectionSnapshot.budget,
    "BudgetType",
    {
      configurable: true,
      get() {
        throw new LeakedErrorConstructor(
          23,
          constructorInjectionContext
        );
      }
    }
  );
  let constructorInjectionFailure;
  try {
    validateAwsGate2Preflight(constructorInjectionSnapshot, {
      diagnosticFailureMode: true,
      diagnosticContext: constructorInjectionContext
    });
  } catch (error) {
    constructorInjectionFailure = error;
  }
  assert.deepEqual(
    awsPreflightRuntimeFailureDescriptor(
      constructorInjectionFailure,
      constructorInjectionContext
    ),
    AWS_GATE2_PREFLIGHT_RUNTIME_BUDGET_FAILURES[1]
  );

  const injectedSnapshot = validSnapshot();
  Object.defineProperty(injectedSnapshot.budget, "BudgetType", {
    configurable: true,
    get() {
      throw original.error;
    }
  });
  const injectedContext = createAwsGate2PreflightDiagnosticContext();
  let injectedFailure;
  try {
    validateAwsGate2Preflight(injectedSnapshot, {
      diagnosticFailureMode: true,
      diagnosticContext: injectedContext
    });
  } catch (error) {
    injectedFailure = error;
  }
  assert(injectedFailure instanceof Error);
  assert.notEqual(injectedFailure, original.error);
  assert.deepEqual(
    awsPreflightRuntimeFailureDescriptor(
      original.error,
      injectedContext
    ),
    { stage: "UNCLASSIFIED_CAUGHT", exitCode: 85 }
  );
  assert.deepEqual(
    awsPreflightRuntimeFailureDescriptor(
      injectedFailure,
      injectedContext
    ),
    AWS_GATE2_PREFLIGHT_RUNTIME_BUDGET_FAILURES[1]
  );
  assert.deepEqual(
    awsPreflightRuntimeFailureDescriptor(
      original.error,
      original.diagnosticContext
    ),
    AWS_GATE2_PREFLIGHT_RUNTIME_BUDGET_FAILURES[8]
  );
  assert.deepEqual(
    awsPreflightRuntimeFailureDescriptor(
      original.error,
      original.diagnosticContext
    ),
    { stage: "UNCLASSIFIED_CAUGHT", exitCode: 85 }
  );

  assert.throws(
    () =>
      validateAwsGate2Preflight(validSnapshot(), {
        diagnosticFailureMode: true,
        diagnosticContext: forgedContext
      }),
    (error) =>
      error instanceof AwsGate2PreflightControlFailure &&
      error.index === 9
  );
  assert.throws(
    () =>
      validateAwsGate2Preflight(validSnapshot(), {
        diagnosticFailureMode: true,
        diagnosticContext: Object.freeze({})
      }),
    (error) =>
      error instanceof AwsGate2PreflightControlFailure &&
      error.index === 9
  );
});

test("AWS preflight diagnostic context preserves the exact valid receipt", () => {
  const legacyReceipt = validateAwsGate2Preflight(validSnapshot());
  const diagnosticContext = createAwsGate2PreflightDiagnosticContext();
  const diagnosticReceipt = validateAwsGate2Preflight(validSnapshot(), {
    diagnosticFailureMode: true,
    diagnosticContext
  });
  assert.equal(
    `${JSON.stringify(diagnosticReceipt, null, 2)}\n`,
    `${JSON.stringify(legacyReceipt, null, 2)}\n`
  );
  assert.throws(
    () =>
      validateAwsGate2Preflight(validSnapshot(), {
        diagnosticFailureMode: true,
        diagnosticContext
      }),
    (error) =>
      error instanceof AwsGate2PreflightControlFailure &&
      error.index === 9
  );
});

test("AWS Gate Two preflight accepts exact read-only safety controls", () => {
  const receipt = validateAwsGate2Preflight(validSnapshot());

  assert.equal(receipt.status, "PASS");
  assert.equal(
    receipt.schemaVersion,
    "tideproof.gate2.aws-preflight.v6"
  );
  assert.equal(
    receipt.controls.budget.conservativeObservedActualUsd,
    "0.250000"
  );
  assert.equal(receipt.controls.mainGateTwoStack.state, "ABSENT");
  assert.match(
    receipt.controls.callerBinding.callerIdentityDigest,
    /^[0-9a-f]{64}$/
  );
  assert.equal(
    receipt.controls.callerBinding.callerIdentityDigest,
    receipt.controls.callerBinding.expectedIdentityDigest
  );
  assert.equal(
    receipt.controls.callerBinding.principalType,
    "assumed-role"
  );
  assert.equal(receipt.controls.bedrock.catalogStatus, "ACTIVE");
  assert.equal(receipt.controls.artifactBucket.tlsOnlyPolicy, true);
  assert.equal(receipt.controls.budget.scope, "ACCOUNT_WIDE");
  assert.equal(
    receipt.controls.budget.costBasis,
    "UnblendedCost"
  );
  assert.equal(receipt.controls.budget.defaultCostTypes, true);
  assert.equal(receipt.controls.budget.fixedLimit, true);
  assert.equal(
    receipt.controls.projectExposure.ceilingUsd,
    "25.000000"
  );
  assert.equal(
    receipt.controls.projectExposure.recordedNonAwsSpendUsd,
    "11.860000"
  );
  assert.equal(
    receipt.controls.projectExposure.effectiveAwsSpendCeilingUsd,
    "13.140000"
  );
  assert.equal(
    receipt.controls.projectExposure.approvedPreflightAllowanceUsd,
    "0.020000"
  );
  assert.equal(
    receipt.controls.projectExposure
      .conservativeReservedAwsExposureUsd,
    "0.270000"
  );
  assert.equal(
    receipt.controls.projectExposure
      .conservativeObservedTotalExposureUsd,
    "12.110000"
  );
  assert.equal(
    receipt.controls.projectExposure.remainingExposureUsd,
    "12.890000"
  );
  assert.equal(
    receipt.controls.projectExposure
      .conservativeReservedTotalExposureUsd,
    "12.130000"
  );
  assert.equal(
    receipt.controls.projectExposure
      .remainingExposureAfterPreflightAllowanceUsd,
    "12.870000"
  );
  assert.equal(
    receipt.controls.projectExposure.registrarReceiptVerified,
    false
  );
  assert.equal(
    AWS_GATE2_PREFLIGHT_DEFAULTS.effectiveAwsSpendCeilingUsd,
    13.14
  );

  const serialized = JSON.stringify(receipt);
  assert.doesNotMatch(serialized, new RegExp(ACCOUNT_ID));
  assert.doesNotMatch(serialized, new RegExp(BUCKET_NAME));
  assert.doesNotMatch(serialized, /private@example\.invalid/);
  assert.doesNotMatch(serialized, /ProofToActPreflight/);
});

test("AWS Gate Two preflight rejects an IAM-user receipt", () => {
  const snapshot = validSnapshot();
  const userArn =
    `arn:aws:iam::${ACCOUNT_ID}:user/prooftoact-preflight`;
  snapshot.expectedPrincipalArn = userArn;
  snapshot.expectedCallerArn = userArn;
  snapshot.expectedCallerUserId = "AIDAPROOFTOACT001";
  snapshot.callerIdentity = {
    Account: ACCOUNT_ID,
    Arn: userArn,
    UserId: "AIDAPROOFTOACT001"
  };
  assert.throws(
    () => validateAwsGate2Preflight(snapshot),
    /AWS_PREFLIGHT_EXPECTED_ROLE/
  );
});

test("AWS Gate Two preflight rejects a different assumed-role lane", () => {
  for (const mutate of [
    (snapshot) => {
      snapshot.expectedPrincipalArn =
        `arn:aws:iam::${ACCOUNT_ID}:role/OtherReadOnlyRole`;
      snapshot.expectedCallerArn =
        `arn:aws:sts::${ACCOUNT_ID}:assumed-role/` +
        "OtherReadOnlyRole/release-proof";
      snapshot.callerIdentity.Arn = snapshot.expectedCallerArn;
    },
    (snapshot) => {
      snapshot.expectedCallerArn =
        `arn:aws:sts::${ACCOUNT_ID}:assumed-role/` +
        "ProofToActPreflight/other-session";
      snapshot.expectedCallerUserId =
        "AROAPROOFTOACTROLE1:other-session";
      snapshot.callerIdentity.Arn = snapshot.expectedCallerArn;
      snapshot.callerIdentity.UserId = snapshot.expectedCallerUserId;
    }
  ]) {
    const snapshot = validSnapshot();
    mutate(snapshot);
    assert.throws(
      () => validateAwsGate2Preflight(snapshot),
      /AWS_PREFLIGHT_EXPECTED_(?:ROLE|CALLER_ARN)/
    );
  }
});

test("AWS Gate Two preflight requests modern filter visibility", () => {
  assert.deepEqual(
    awsBudgetDescribeArguments("111111111111", "account-safety"),
    [
      "--account-id",
      "111111111111",
      "--budget-name",
      "account-safety",
      "--show-filter-expression"
    ]
  );
});

test("AWS Gate Two preflight binds Cost Explorer through today", () => {
  assert.deepEqual(
    awsCostExplorerPeriod("2026-07-30T23:59:59.000Z"),
    {
      periodStart: "2026-07-01",
      periodEndExclusive: "2026-07-31"
    }
  );
  assert.deepEqual(
    awsCostExplorerPeriod("2026-08-31T12:00:00.000Z"),
    {
      periodStart: "2026-07-01",
      periodEndExclusive: "2026-09-01"
    }
  );
  assert.deepEqual(
    awsCostExplorerArguments({
      periodStart: "2026-07-01",
      periodEndExclusive: "2026-09-01"
    }),
    [
      "--time-period",
      "Start=2026-07-01,End=2026-09-01",
      "--granularity",
      "MONTHLY",
      "--metrics",
      "UnblendedCost",
      "--no-paginate"
    ]
  );
  assert.equal(
    AWS_GATE2_PREFLIGHT_DEFAULTS.maxCostExplorerRequests,
    1
  );
  assert.equal(
    AWS_GATE2_PREFLIGHT_DEFAULTS.approvedPreflightMeteredSpendCapUsd,
    0.02
  );
});

test("AWS Gate Two preflight accepts explicit empty filter maps", () => {
  const snapshot = validSnapshot();
  snapshot.budget.CostFilters = {};
  snapshot.budget.FilterExpression = {};
  assert.equal(validateAwsGate2Preflight(snapshot).status, "PASS");

  delete snapshot.budget.CostTypes;
  assert.equal(validateAwsGate2Preflight(snapshot).status, "PASS");
});

test("AWS Gate Two preflight accepts only exact UnblendedCost metric representations", () => {
  const omittedMetricsSnapshot = validSnapshot();
  const omittedMetricsReceipt = validateAwsGate2Preflight(
    omittedMetricsSnapshot
  );
  assert.equal(
    omittedMetricsReceipt.schemaVersion,
    "tideproof.gate2.aws-preflight.v6"
  );
  const assertByteIdenticalReceipt = (snapshot) => {
    const receipt = validateAwsGate2Preflight(snapshot);
    assert.deepEqual(receipt, omittedMetricsReceipt);
    assert.equal(
      JSON.stringify(receipt),
      JSON.stringify(omittedMetricsReceipt)
    );
  };

  const nullMetricsSnapshot = validSnapshot();
  nullMetricsSnapshot.budget.Metrics = null;
  assertByteIdenticalReceipt(nullMetricsSnapshot);

  const explicitMetricsSnapshot = validSnapshot();
  explicitMetricsSnapshot.budget.Metrics = ["UnblendedCost"];
  assertByteIdenticalReceipt(explicitMetricsSnapshot);

  const modernMetricsSnapshot = validSnapshot();
  modernMetricsSnapshot.budget.Metrics = ["UnblendedCost"];
  delete modernMetricsSnapshot.budget.CostTypes;
  assertByteIdenticalReceipt(modernMetricsSnapshot);

  for (const rejectedMetrics of [
    [],
    ["AmortizedCost"],
    ["UnblendedCost", "AmortizedCost"],
    ["UnblendedCost", "UnblendedCost"],
    ["unblendedcost"],
    ["UNBLENDED_COST"],
    [null],
    "UnblendedCost",
    { 0: "UnblendedCost" }
  ]) {
    const snapshot = validSnapshot();
    snapshot.budget.Metrics = rejectedMetrics;
    assert.throws(
      () => validateAwsGate2Preflight(snapshot),
      /BUDGET_METRICS_MODEL/
    );
  }
});

test("explicit budget Metrics cannot bypass scope or CostTypes controls", () => {
  for (const [mutate, expectedCode] of [
    [
      (snapshot) => {
        snapshot.budget.CostFilters = { Service: ["private"] };
      },
      "BUDGET_COST_FILTERS_ACCOUNT_WIDE"
    ],
    [
      (snapshot) => {
        snapshot.budget.FilterExpression = { Not: {} };
      },
      "BUDGET_FILTER_EXPRESSION_ACCOUNT_WIDE"
    ],
    [
      (snapshot) => {
        snapshot.budget.BillingViewArn = "private";
      },
      "BUDGET_BILLING_VIEW_ACCOUNT_WIDE"
    ],
    [
      (snapshot) => {
        snapshot.budget.CostTypes.UseBlended = true;
      },
      "BUDGET_COST_TYPES"
    ]
  ]) {
    const snapshot = validSnapshot();
    snapshot.budget.Metrics = ["UnblendedCost"];
    mutate(snapshot);
    assert.throws(
      () => validateAwsGate2Preflight(snapshot),
      new RegExp(expectedCode)
    );
  }
});

test("AWS Gate Two preflight rejects non-account-wide budgets", () => {
  for (const [mutate, expectedCode] of [
    [
      (snapshot) => {
        snapshot.budget.CostFilters = {
          Service: ["Amazon Simple Storage Service"]
        };
      },
      "BUDGET_COST_FILTERS_ACCOUNT_WIDE"
    ],
    [
      (snapshot) => {
        snapshot.budget.FilterExpression = {
          Dimensions: {
            Key: "SERVICE",
            Values: ["Amazon Simple Storage Service"]
          }
        };
      },
      "BUDGET_FILTER_EXPRESSION_ACCOUNT_WIDE"
    ],
    [
      (snapshot) => {
        snapshot.budget.BillingViewArn =
          "arn:aws:billing::111111111111:billingview/private";
      },
      "BUDGET_BILLING_VIEW_ACCOUNT_WIDE"
    ]
  ]) {
    const snapshot = validSnapshot();
    mutate(snapshot);
    assert.throws(
      () => validateAwsGate2Preflight(snapshot),
      new RegExp(expectedCode)
    );
  }
});

test("AWS Gate Two preflight rejects non-fixed budget models", () => {
  for (const [mutate, expectedCode] of [
    [
      (snapshot) => {
        snapshot.budget.AutoAdjustData = {
          AutoAdjustType: "HISTORICAL"
        };
      },
      "BUDGET_AUTO_ADJUST_NOT_FIXED"
    ],
    [
      (snapshot) => {
        snapshot.budget.PlannedBudgetLimits = {
          "1785542400": { Amount: "15", Unit: "USD" }
        };
      },
      "BUDGET_PLANNED_LIMITS_NOT_FIXED"
    ],
    [
      (snapshot) => {
        snapshot.budget.Metrics = ["AmortizedCost"];
      },
      "BUDGET_METRICS_MODEL"
    ],
    [
      (snapshot) => {
        snapshot.budget.CostTypes.UseBlended = true;
      },
      "BUDGET_COST_TYPES"
    ],
    [
      (snapshot) => {
        delete snapshot.budget.CostTypes.IncludeCredit;
      },
      "BUDGET_COST_TYPES"
    ]
  ]) {
    const snapshot = validSnapshot();
    mutate(snapshot);
    assert.throws(
      () => validateAwsGate2Preflight(snapshot),
      new RegExp(expectedCode)
    );
  }
});

test("AWS Gate Two preflight requires an active release-long budget", () => {
  for (const [mutate, expectedCode] of [
    [
      (snapshot) => {
        snapshot.budget.TimePeriod.Start = "not-a-timestamp";
      },
      "BUDGET_TIME_PERIOD_START"
    ],
    [
      (snapshot) => {
        snapshot.budget.TimePeriod.End = "not-a-timestamp";
      },
      "BUDGET_TIME_PERIOD_END"
    ],
    [
      (snapshot) => {
        snapshot.budget.TimePeriod.Start =
          "2026-09-17T00:00:00.000Z";
        snapshot.budget.TimePeriod.End =
          "2026-09-16T00:00:00.000Z";
      },
      "BUDGET_TIME_PERIOD_ORDER"
    ],
    [
      (snapshot) => {
        snapshot.budget.TimePeriod.Start =
          "2026-08-01T00:00:00.000Z";
      },
      "BUDGET_TIME_PERIOD_NOT_STARTED"
    ],
    [
      (snapshot) => {
        snapshot.budget.TimePeriod.End = snapshot.observedAt;
      },
      "BUDGET_TIME_PERIOD_EXPIRED"
    ],
    [
      (snapshot) => {
        snapshot.budget.TimePeriod.End =
          "2026-09-15T23:59:59.999Z";
      },
      "BUDGET_TIME_PERIOD_RELEASE_HORIZON"
    ]
  ]) {
    const snapshot = validSnapshot();
    mutate(snapshot);
    assert.throws(
      () => validateAwsGate2Preflight(snapshot),
      new RegExp(expectedCode)
    );
  }
});

test("AWS Gate Two preflight rejects a stale Cost Explorer window", () => {
  const snapshot = validSnapshot();
  snapshot.currentCost.periodEndExclusive = "2026-07-30";
  assert.throws(
    () => validateAwsGate2Preflight(snapshot),
    /CURRENT_COST_PERIOD_END/
  );
});

test("AWS Gate Two preflight binds the Cost Explorer response period", () => {
  const snapshot = validSnapshot();
  snapshot.currentCost.response.ResultsByTime[0].TimePeriod.End =
    "2026-07-30";
  assert.throws(
    () => validateAwsGate2Preflight(snapshot),
    /CURRENT_COST_ROW_PERIOD/
  );
});

test("AWS Gate Two preflight rejects every Cost Explorer pagination token", () => {
  for (const token of ["next-page", ""]) {
    const snapshot = validSnapshot();
    snapshot.currentCost.response.NextPageToken = token;
    assert.throws(
      () => validateAwsGate2Preflight(snapshot),
      /CURRENT_COST_NEXT_PAGE_TOKEN/
    );
  }
});

test("AWS Gate Two preflight totals every month in the project window", () => {
  const snapshot = validSnapshot();
  snapshot.observedAt = "2026-08-31T12:00:00.000Z";
  snapshot.currentCost.periodEndExclusive = "2026-09-01";
  snapshot.currentCost.response.ResultsByTime = [
    {
      TimePeriod: {
        Start: "2026-07-01",
        End: "2026-08-01"
      },
      Estimated: false,
      Total: {
        UnblendedCost: { Amount: "0.20", Unit: "USD" }
      }
    },
    {
      TimePeriod: {
        Start: "2026-08-01",
        End: "2026-09-01"
      },
      Estimated: true,
      Total: {
        UnblendedCost: { Amount: "0.30", Unit: "USD" }
      }
    }
  ];

  const receipt = validateAwsGate2Preflight(snapshot);
  assert.equal(receipt.controls.currentCost.amountUsd, "0.500000");
  assert.equal(
    receipt.controls.currentCost.scope,
    "ACCOUNT_WIDE_PROJECT_WINDOW_TO_DATE"
  );
  assert.equal(
    receipt.controls.projectExposure
      .conservativeObservedTotalExposureUsd,
    "12.360000"
  );
});

test("AWS Gate Two preflight rejects a different region", () => {
  const snapshot = validSnapshot();
  snapshot.region = "us-west-2";
  assert.throws(
    () => validateAwsGate2Preflight(snapshot),
    /AWS_REGION/
  );
});

test("AWS Gate Two preflight rejects missing cost alerts", () => {
  const snapshot = validSnapshot();
  snapshot.notificationSubscribers = snapshot.notificationSubscribers.slice(
    0,
    3
  );
  assert.throws(
    () => validateAwsGate2Preflight(snapshot),
    /BUDGET_NOTIFICATION_CARDINALITY/
  );
});

test("AWS Gate Two preflight requires an email subscriber per alert", () => {
  const snapshot = validSnapshot();
  snapshot.notificationSubscribers[0].subscribers = [];
  assert.throws(
    () => validateAwsGate2Preflight(snapshot),
    /BUDGET_SUBSCRIBER_ACTUAL_1/
  );
});

test("AWS Gate Two preflight rejects unsafe artifact-bucket controls", () => {
  for (const mutate of [
    (snapshot) => {
      snapshot.artifactBucket.versioning.Status = "Suspended";
    },
    (snapshot) => {
      snapshot.artifactBucket.publicAccessBlock
        .PublicAccessBlockConfiguration.RestrictPublicBuckets = false;
    },
    (snapshot) => {
      snapshot.artifactBucket.policy.Statement = [];
    },
    (snapshot) => {
      snapshot.artifactBucket.policy.Statement.push({
        Sid: "DelegatePrivateRead",
        Effect: "Allow",
        Principal: {
          AWS: "arn:aws:iam::222222222222:root"
        },
        Action: "s3:GetObject",
        Resource: `arn:aws:s3:::${BUCKET_NAME}/*`
      });
    }
  ]) {
    const snapshot = validSnapshot();
    mutate(snapshot);
    assert.throws(
      () => validateAwsGate2Preflight(snapshot),
      /ARTIFACT_BUCKET/
    );
  }
});

test("AWS Gate Two preflight rejects an existing main stack", () => {
  const snapshot = validSnapshot();
  snapshot.stackSummaries.push({
    StackName: snapshot.mainStackName,
    StackStatus: "CREATE_COMPLETE"
  });
  assert.throws(
    () => validateAwsGate2Preflight(snapshot),
    /MAIN_STACK_ALREADY_PRESENT/
  );
});

test("AWS Gate Two preflight rejects a legacy working-name main stack", () => {
  const snapshot = validSnapshot();
  snapshot.stackSummaries.push({
    StackName: snapshot.legacyMainStackName,
    StackStatus: "CREATE_COMPLETE"
  });
  assert.throws(
    () => validateAwsGate2Preflight(snapshot),
    /LEGACY_MAIN_STACK_ALREADY_PRESENT/
  );
});

test("AWS Gate Two preflight rejects spend at the effective project ceiling", () => {
  const snapshot = validSnapshot();
  snapshot.currentCost.response.ResultsByTime[0]
    .Total.UnblendedCost.Amount = "13.14";
  assert.throws(
    () => validateAwsGate2Preflight(snapshot),
    /CURRENT_COST_CEILING/
  );
});

test("AWS Gate Two preflight reserves the full allowance below both ceilings", () => {
  const justBelow = validSnapshot();
  justBelow.currentCost.response.ResultsByTime[0]
    .Total.UnblendedCost.Amount = "13.119999";
  const receipt = validateAwsGate2Preflight(justBelow);
  assert.equal(
    receipt.controls.projectExposure
      .conservativeReservedAwsExposureUsd,
    "13.139999"
  );
  assert.equal(
    receipt.controls.projectExposure
      .conservativeReservedTotalExposureUsd,
    "24.999999"
  );
  assert.equal(
    receipt.controls.projectExposure
      .remainingExposureAfterPreflightAllowanceUsd,
    "0.000001"
  );

  for (const mutate of [
    (snapshot) => {
      snapshot.currentCost.response.ResultsByTime[0]
        .Total.UnblendedCost.Amount = "13.12";
    },
    (snapshot) => {
      snapshot.budget.CalculatedSpend.ActualSpend.Amount = "13.12";
    },
    (snapshot) => {
      snapshot.currentCost.response.ResultsByTime[0]
        .Total.UnblendedCost.Amount = "13.1199991";
    }
  ]) {
    const atOrAboveReservedBoundary = validSnapshot();
    mutate(atOrAboveReservedBoundary);
    assert.throws(
      () => validateAwsGate2Preflight(atOrAboveReservedBoundary),
      /PREFLIGHT_ALLOWANCE_AWS_CEILING/
    );
  }
});

test("AWS Gate Two preflight rejects extra budget notification reads", () => {
  const snapshot = validSnapshot();
  snapshot.notificationSubscribers.push(notification("ACTUAL", 20));
  assert.throws(
    () => validateAwsGate2Preflight(snapshot),
    /BUDGET_NOTIFICATION_CARDINALITY/
  );
});

test("AWS Gate Two preflight applies the effective ceiling to budget spend", () => {
  const snapshot = validSnapshot();
  snapshot.budget.CalculatedSpend.ActualSpend.Amount = "13.14";
  assert.throws(
    () => validateAwsGate2Preflight(snapshot),
    /BUDGET_ACTUAL_CEILING/
  );
});

test("AWS Gate Two preflight rejects unavailable Nova metadata", () => {
  for (const mutate of [
    (snapshot) => {
      snapshot.foundationModel.modelDetails.modelLifecycle.status =
        "LEGACY";
    },
    (snapshot) => {
      snapshot.foundationModel.modelDetails.inferenceTypesSupported = [];
    }
  ]) {
    const snapshot = validSnapshot();
    mutate(snapshot);
    assert.throws(
      () => validateAwsGate2Preflight(snapshot),
      /BEDROCK_MODEL/
    );
  }
});
