import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { singleFileZip } from "../scripts/lib/deterministic-zip.js";
import {
  __test,
  parseArguments,
  runAwsReadiness,
  validateAuditReport,
  validateBuildReceipt,
  validatePreflightReceipt
} from "../scripts/gate2-aws-readiness.js";

const SOURCE_COMMIT = "a".repeat(40);
const TREE_DIGEST = "b".repeat(40);

function sha256(value, encoding = "hex") {
  return crypto.createHash("sha256").update(value).digest(encoding);
}

function writeFile(root, relativePath, value) {
  const filePath = path.join(root, relativePath);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, value);
  return filePath;
}

function fixture() {
  const projectRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "tideproof-aws-readiness-")
  );
  const packageLock = Buffer.from(
    '{"lockfileVersion":3}\n',
    "utf8"
  );
  const bootstrapTemplate = Buffer.from("{}\n", "utf8");
  const gate2Template = Buffer.from(
    '{"Resources":{}}\n',
    "utf8"
  );
  writeFile(projectRoot, "package-lock.json", packageLock);
  writeFile(
    projectRoot,
    "infra/aws/bootstrap-template.json",
    bootstrapTemplate
  );
  writeFile(
    projectRoot,
    "infra/aws/gate2-template.json",
    gate2Template
  );

  const artifacts = [];
  for (const name of __test.ARTIFACT_NAMES) {
    const extension = name === "demo" ? "js" : "cjs";
    const sourcePath = `infra/aws/lambda/${name}.${extension}`;
    const source = Buffer.from(
      `exports.handler = async () => "${name}";\n`,
      "utf8"
    );
    writeFile(projectRoot, sourcePath, source);
    const archive = singleFileZip("index.js", source);
    const artifactDigest = sha256(archive);
    const artifactFile = `${name}-${artifactDigest}.zip`;
    const artifactPath = `dist/aws/${artifactFile}`;
    writeFile(projectRoot, artifactPath, archive);
    artifacts.push({
      name,
      sourcePath,
      sourceDigest: sha256(source),
      artifactPath,
      artifactFile,
      artifactDigest,
      artifactCodeSha256: sha256(archive, "base64"),
      artifactBytes: archive.length,
      suggestedS3Key:
        `gate2/${SOURCE_COMMIT}/${artifactFile}`
    });
  }

  const buildReceipt = {
    schemaVersion: "tideproof.gate2-build.v2",
    mode: "CLEAN_ARTIFACT_BUILD",
    sourceCommit: SOURCE_COMMIT,
    treeDigest: TREE_DIGEST,
    workingTreeClean: true,
    workingTreeCleanBeforeGeneration: true,
    archiveFormat: "ZIP_STORED_SINGLE_FILE_V1",
    packageLockDigest: sha256(packageLock),
    bootstrapTemplate: {
      path: "infra/aws/bootstrap-template.json",
      templateDigest: sha256(bootstrapTemplate),
      canonicalDigest: "c".repeat(64),
      bytes: bootstrapTemplate.length
    },
    gate2Template: {
      path: "infra/aws/gate2-template.json",
      templateDigest: sha256(gate2Template),
      canonicalDigest: "d".repeat(64),
      bytes: gate2Template.length
    },
    artifacts
  };

  return {
    projectRoot,
    buildReceipt,
    cleanup() {
      fs.rmSync(projectRoot, { recursive: true, force: true });
    }
  };
}

function cleanAuditReport() {
  return {
    metadata: {
      vulnerabilities: {
        info: 0,
        low: 0,
        moderate: 0,
        high: 0,
        critical: 0,
        total: 0
      }
    }
  };
}

function preflightReceipt() {
  return {
    schemaVersion: "tideproof.gate2.aws-preflight.v3",
    status: "PASS",
    observedAt: "2026-07-31T05:30:00.000Z",
    sourceCommit: SOURCE_COMMIT,
    treeDigest: TREE_DIGEST,
    region: "us-east-1",
    controls: {
      authenticatedAwsCaller: true,
      bootstrapStack: {
        name: "tideproof-gate2-artifacts",
        status: "UPDATE_COMPLETE"
      },
      budget: {
        name: "tideproof-gate2-artifacts-account-safety",
        scope: "ACCOUNT_WIDE",
        type: "COST",
        timeUnit: "MONTHLY",
        costBasis: "UnblendedCost",
        defaultCostTypes: true,
        fixedLimit: true,
        limitUsd: 15,
        coverageStart: "2026-07-01T00:00:00.000Z",
        coverageEnd: "2087-06-15T00:00:00.000Z",
        budgetReportedActualUsd: "0.250000",
        conservativeObservedActualUsd: "0.250000",
        notifications: [
          ["ACTUAL", 1],
          ["ACTUAL", 5],
          ["ACTUAL", 10],
          ["FORECASTED", 15]
        ].map(([metric, thresholdUsd]) => ({
          metric,
          comparison: "GREATER_THAN",
          thresholdUsd,
          thresholdType: "ABSOLUTE_VALUE",
          emailRecipientCount: 1
        }))
      },
      currentCost: {
        scope: "ACCOUNT_WIDE_PROJECT_WINDOW_TO_DATE",
        periodStart: "2026-07-01",
        periodEndExclusive: "2026-08-01",
        amountUsd: "0.200000",
        estimated: true
      },
      projectExposure: {
        scope: "TIDEPROOF_TOTAL_APPROVED_EXPOSURE",
        ceilingUsd: "25.000000",
        recordedNonAwsSpendUsd: "11.860000",
        effectiveAwsSpendCeilingUsd: "13.140000",
        conservativeObservedTotalExposureUsd: "12.110000",
        remainingExposureUsd: "12.890000",
        awsCostWindowStart: "2026-07-01",
        recordedSpendBasis:
          "OWNER_REPORTED_TIDEPROOF_NET_REGISTRATION",
        registrarReceiptVerified: false,
        autoRenewReportedEnabled: false
      },
      mainGateTwoStack: {
        name: "tideproof-gate2",
        state: "ABSENT"
      },
      bedrock: {
        modelId: "amazon.nova-micro-v1:0",
        catalogStatus: "ACTIVE",
        textInput: true,
        textOutput: true,
        onDemandListed: true
      },
      artifactBucket: {
        versioningEnabled: true,
        aes256AtRest: true,
        publicAccessBlocked: true,
        bucketOwnerEnforced: true,
        tlsOnlyPolicy: true
      }
    },
    privacy:
      "AWS account, caller ARN, bucket name, and subscriber addresses were validated but omitted.",
    claimBoundary:
      "Read-only preflight fixture; no AWS mutation or live behavior claim."
  };
}

function successfulRunner(buildReceipt, calls) {
  return (command, args, options = {}) => {
    const call = [command, ...args];
    call.options = options;
    calls.push(call);
    const shape = `${command} ${args.join(" ")}`;
    let stdout = "";
    if (shape === "git remote get-url origin") {
      stdout = `${__test.OFFICIAL_REMOTE}\n`;
    } else if (shape === "git symbolic-ref --short HEAD") {
      stdout = "main\n";
    } else if (shape === "git rev-parse HEAD") {
      stdout = `${SOURCE_COMMIT}\n`;
    } else if (
      shape === "git rev-parse refs/remotes/origin/main"
    ) {
      stdout = `${SOURCE_COMMIT}\n`;
    } else if (shape === "git rev-parse HEAD^{tree}") {
      stdout = `${TREE_DIGEST}\n`;
    } else if (
      shape === "npm audit --json --audit-level=low"
    ) {
      stdout = JSON.stringify(cleanAuditReport());
    } else if (
      shape === "npm run --silent build:gate2"
    ) {
      stdout = JSON.stringify(buildReceipt);
    } else if (
      shape === "npm run --silent gate2:aws-preflight"
    ) {
      stdout = JSON.stringify(preflightReceipt());
    }
    return { status: 0, stdout, stderr: "" };
  };
}

test("AWS readiness validates every exact-head artifact byte", () => {
  const current = fixture();
  try {
    const accepted = validateBuildReceipt(
      current.buildReceipt,
      {
        projectRoot: current.projectRoot,
        sourceCommit: SOURCE_COMMIT,
        treeDigest: TREE_DIGEST
      }
    );
    assert.equal(accepted.mode, "CLEAN_ARTIFACT_BUILD");
    assert.deepEqual(
      Object.keys(accepted.artifacts).sort(),
      [...__test.ARTIFACT_NAMES].sort()
    );
    assert.equal(
      accepted.artifacts.demo.artifactDigest,
      current.buildReceipt.artifacts.find(
        (artifact) => artifact.name === "demo"
      ).artifactDigest
    );
  } finally {
    current.cleanup();
  }
});

test("AWS readiness rejects an artifact changed after the build", () => {
  const current = fixture();
  try {
    const artifact =
      current.buildReceipt.artifacts[0];
    fs.appendFileSync(
      path.join(current.projectRoot, artifact.artifactPath),
      "tamper"
    );
    assert.throws(
      () =>
        validateBuildReceipt(current.buildReceipt, {
          projectRoot: current.projectRoot,
          sourceCommit: SOURCE_COMMIT,
          treeDigest: TREE_DIGEST
        }),
      /AWS_READINESS_ARTIFACT_DIGEST/
    );
  } finally {
    current.cleanup();
  }
});

test("AWS readiness requires a zero-vulnerability audit", () => {
  assert.deepEqual(validateAuditReport(cleanAuditReport()), {
    status: "PASS",
    knownVulnerabilities: 0
  });
  const vulnerable = cleanAuditReport();
  vulnerable.metadata.vulnerabilities.high = 1;
  vulnerable.metadata.vulnerabilities.total = 1;
  assert.throws(
    () => validateAuditReport(vulnerable),
    /AWS_READINESS_AUDIT/
  );
});

test("AWS readiness binds the preflight to the exact checkout", () => {
  const receipt = preflightReceipt();
  assert.equal(
    validatePreflightReceipt(receipt, {
      sourceCommit: SOURCE_COMMIT,
      treeDigest: TREE_DIGEST
    }),
    receipt
  );
  assert.throws(
    () =>
      validatePreflightReceipt(receipt, {
        sourceCommit: "e".repeat(40),
        treeDigest: TREE_DIGEST
      }),
    /AWS_READINESS_PREFLIGHT/
  );
});

test("AWS readiness full mode performs only reviewed command families", async () => {
  const current = fixture();
  const calls = [];
  try {
    const receipt = await runAwsReadiness({
      projectRoot: current.projectRoot,
      run: successfulRunner(current.buildReceipt, calls)
    });
    assert.equal(receipt.status, "PASS");
    assert.equal(receipt.checks.awsPreflight, "PASS");
    assert.equal(receipt.source.commit, SOURCE_COMMIT);
    assert.equal(
      calls.some(
        (call) =>
          call[0] === "npm" &&
          call.includes("gate2:aws-preflight")
      ),
      true
    );
    const preflightCall = calls.find(
      (call) =>
        call[0] === "npm" &&
        call.includes("gate2:aws-preflight")
    );
    assert.deepEqual(preflightCall.options, {
      awsAuthenticated: true
    });
    assert.equal(
      calls
        .filter((call) => call !== preflightCall)
        .every(
          (call) =>
            call.options.awsAuthenticated !== true
        ),
      true
    );
    assert.equal(
      calls.some(
        (call) =>
          call[0] === "npm" &&
          call[1] === "ci" &&
          call.includes("--ignore-scripts")
      ),
      true
    );
    assert.equal(
      calls.every(
        (call) =>
          call[0] === "git" || call[0] === "npm"
      ),
      true
    );
    const fetches = calls.filter((call) =>
      call.includes("fetch")
    );
    assert.equal(fetches.length, 2);
    assert.equal(
      fetches.every((call) =>
        call.includes(
          "http.https://github.com/.extraheader="
        )
      ),
      true
    );
  } finally {
    current.cleanup();
  }
});

test("AWS readiness local mode is explicit non-AWS evidence", async () => {
  const current = fixture();
  const calls = [];
  try {
    const receipt = await runAwsReadiness({
      projectRoot: current.projectRoot,
      localOnly: true,
      now: () => new Date("2026-07-31T05:45:00.000Z"),
      run: successfulRunner(current.buildReceipt, calls)
    });
    assert.equal(receipt.status, "LOCAL_ONLY_PASS");
    assert.equal(receipt.awsPreflight, null);
    assert.equal(receipt.checks.awsPreflight, "NOT_RUN");
    assert.equal(
      calls.some((call) => call.includes("gate2:aws-preflight")),
      false
    );
  } finally {
    current.cleanup();
  }
});

test("AWS readiness accepts only full or explicit local mode", () => {
  assert.deepEqual(parseArguments([]), { localOnly: false });
  assert.deepEqual(parseArguments(["--local-only"]), {
    localOnly: true
  });
  assert.throws(
    () => parseArguments(["--execute"]),
    /AWS_READINESS_ARGUMENT/
  );
});

test("AWS readiness accepts only public official remote forms", () => {
  assert.equal(
    __test.isOfficialRemote(
      "https://github.com/Flash-Bri/tideproof.git"
    ),
    true
  );
  assert.equal(
    __test.isOfficialRemote(
      "https://github.com/Flash-Bri/tideproof"
    ),
    true
  );
  assert.equal(
    __test.isOfficialRemote(
      "git@github.com:Flash-Bri/tideproof.git"
    ),
    false
  );
  assert.equal(
    __test.isOfficialRemote(
      "https://github.com/other/tideproof.git"
    ),
    false
  );
});

test("AWS readiness isolates credentials outside the AWS preflight", () => {
  const source = {
    PATH: "/usr/bin",
    AWS_ACCESS_KEY_ID: "temporary-access",
    AWS_SESSION_TOKEN: "temporary-session",
    DATABASE_URL: "postgresql://private",
    OPENAI_API_KEY: "private-model-key",
    SAFE_VALUE: "retained"
  };
  const isolated = __test.childEnvironment(source);
  assert.equal(isolated.PATH, "/usr/bin");
  assert.equal(isolated.SAFE_VALUE, "retained");
  assert.equal(isolated.AWS_ACCESS_KEY_ID, undefined);
  assert.equal(isolated.AWS_SESSION_TOKEN, undefined);
  assert.equal(isolated.DATABASE_URL, undefined);
  assert.equal(isolated.OPENAI_API_KEY, undefined);
  assert.equal(
    isolated.AWS_SHARED_CREDENTIALS_FILE,
    "/dev/null"
  );
  assert.equal(isolated.GIT_TERMINAL_PROMPT, "0");
  assert.equal(isolated.npm_config_userconfig, "/dev/null");

  const authenticated = __test.childEnvironment(source, {
    awsAuthenticated: true
  });
  assert.equal(
    authenticated.AWS_ACCESS_KEY_ID,
    "temporary-access"
  );
  assert.equal(
    authenticated.AWS_SESSION_TOKEN,
    "temporary-session"
  );
  assert.equal(authenticated.DATABASE_URL, undefined);
  assert.equal(authenticated.OPENAI_API_KEY, undefined);
  assert.equal(
    authenticated.AWS_SHARED_CREDENTIALS_FILE,
    undefined
  );
});
